from flask import Blueprint, request, render_template, jsonify, g, make_response, session
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import time
import re
import hashlib
import json
import logging
import ipaddress
import user_agents
import socket
import struct
import traceback
from pymongo import UpdateOne
from mongodb.database import db
from helpers.global_rate_limiter import GlobalRateLimiter
from default_scan_paths import DEFAULT_SCAN_PATHS
from honeypot_routes import register_routes_with_blueprint
from proxy_detector import proxy_detector
from geo_db_updater import download_and_extract_db

# Create honeypot blueprint
honeypot_bp = Blueprint('honeypot', __name__)


ASN_DB_PATH = os.path.join("/path/to/geoip_db")
COUNTRY_DB_PATH = os.path.join("/path/to/geoip_db")

asn_reader = None
country_reader = None

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


HONEYPOT_RATE_LIMIT = 5  # requests per minute
HONEYPOT_RATE_PERIOD = 60  # seconds


def load_geoip_readers():
    """Load or reload the GeoIP database readers"""
    global asn_reader, country_reader
    
    try:
        if os.path.exists(ASN_DB_PATH):
            asn_reader = geoip2.database.Reader(ASN_DB_PATH)
            
        if os.path.exists(COUNTRY_DB_PATH):
            country_reader = geoip2.database.Reader(COUNTRY_DB_PATH)
            
        return True
    except Exception as e:
        logger.error(f"Error loading GeoIP databases: {str(e)}")
        return False

# Load databases on module import
load_geoip_readers()


# List of paths we've seen scanned before (will be populated from DB at startup)
COMMON_SCAN_PATHS = set()

def load_common_scan_paths():
    """Load the most common scan paths from the database"""
    global COMMON_SCAN_PATHS
    
    # Start with the default paths
    COMMON_SCAN_PATHS = DEFAULT_SCAN_PATHS.copy()
    
    try:
        # Get top 500 scanned paths from database
        pipeline = [
            {"$group": {"_id": "$path", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 500}
        ]
        results = list(db.scanAttempts.aggregate(pipeline))
        
        # Add database paths to our set (which already contains the defaults)
        for result in results:
            COMMON_SCAN_PATHS.add(result["_id"])
            
        logger.info(f"Loaded {len(COMMON_SCAN_PATHS)} common scan paths (including defaults) from database")
    except Exception as e:
        logger.error(f"Error loading common scan paths: {str(e)}")


load_common_scan_paths()

def get_client_identifier():
    """
    Generate a comprehensive client identifier using multiple factors.
    This creates a more reliable identifier even if the client is trying to hide.
    """
    factors = []
    
    # Basic identifiers
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:  # Handle proxy chains
        ip = ip.split(',')[0].strip()
    factors.append(ip or "unknown_ip")
    
    # Browser fingerprinting
    user_agent = request.headers.get('User-Agent', '')
    factors.append(user_agent[:100] or "unknown_agent")
    
    # Accept headers can be used for fingerprinting
    accept = request.headers.get('Accept', '')
    accept_lang = request.headers.get('Accept-Language', '')
    accept_encoding = request.headers.get('Accept-Encoding', '')
    factors.append((accept + accept_lang + accept_encoding)[:50])
    
    # Connection-specific headers
    connection = request.headers.get('Connection', '')
    factors.append(connection)
    
    # Additional headers that might be useful for fingerprinting
    additional_headers = [
        # Standard browser headers
        'X-Requested-With', 'DNT', 'Referer', 'Origin',
        'Sec-Fetch-Dest', 'Sec-Fetch-Mode', 'Sec-Fetch-Site', 'Sec-Fetch-User',
        'Cache-Control', 'Pragma', 'If-None-Match', 'If-Modified-Since',
        
        # Common custom headers
        'X-Forwarded-For', 'X-Forwarded-Proto', 'X-Forwarded-Host',
        'X-Real-IP', 'X-Original-URL', 'X-Rewrite-URL',
        
        # API and auth headers
        'Authorization', 'X-API-Key', 'X-Auth-Token', 'API-Key',
        'X-CSRF-Token', 'X-XSRF-Token', 'X-Access-Token',
        
        # Device/client information
        'User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding',
        'Content-Type', 'Content-Length', 'Content-Encoding',
        'Upgrade-Insecure-Requests', 'X-Device-Info',
        
        # Browser fingerprinting
        'Accept-Charset', 'Viewport-Width', 'Width', 
        'Save-Data', 'X-Do-Not-Track', 'X-Screen-Height', 'X-Screen-Width',
        
        # Mobile-specific
        'X-Requested-With', 'X-Wap-Profile', 'X-UIDH', 'X-ATT-DeviceId',
        
        # Unusual headers (often used by bots and tools)
        'Max-Forwards', 'Via', 'From', 'Warning', 'Expect',
        'X-Scanner', 'X-Scan', 'X-Exploit', 'X-Payload'
    ]
    
    for header in additional_headers:
        value = request.headers.get(header, '')
        if value:
            factors.append(f"{header}:{value[:20]}")
    
    # If we have a session, add a fingerprint of session data
    if session:
        try:
            session_data = json.dumps(dict(session))
            factors.append(hashlib.md5(session_data.encode()).hexdigest()[:12])
        except:
            pass
    
    # Build and hash the combined identifier
    identifier = "|".join(factors)
    hashed_id = hashlib.sha256(identifier.encode()).hexdigest()
    
    return hashed_id

def extract_asn_from_ip(ip):
    """
    Get ASN, organization, and country information for an IP address
    using MaxMind GeoLite2 databases
    """
    try:
        # Skip private, local, or invalid IPs
        if not ip or ip == "unknown_ip" or ip == "127.0.0.1":
            return {"asn": "Unknown", "org": "Unknown", "country": "Unknown"}
            
        # Make sure we're working with a valid IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                return {"asn": "Private", "org": "Private Network", "country": "Unknown"}
        except ValueError:
            return {"asn": "Invalid", "org": "Invalid IP", "country": "Unknown"}
            
        # Get ASN information
        asn_info = {"asn": "Unknown", "org": "Unknown", "country": "Unknown"}
        
        # Try to get ASN and organization
        if asn_reader:
            try:
                response = asn_reader.asn(ip)
                asn_info["asn"] = f"AS{response.autonomous_system_number}"
                asn_info["org"] = response.autonomous_system_organization
            except geoip2.errors.AddressNotFoundError:
                # IP not found in ASN database
                pass
                
        # Try to get country
        if country_reader:
            try:
                response = country_reader.country(ip)
                asn_info["country"] = response.country.name or "Unknown"
            except geoip2.errors.AddressNotFoundError:
                # IP not found in Country database
                pass
                
        return asn_info
        
    except Exception as e:
        logger.error(f"Error extracting ASN for IP {ip}: {str(e)}")
        return {"asn": "Error", "org": "Error", "country": "Unknown"}

def detect_tor_or_proxy(ip):
    """
    Check if the IP is likely a Tor exit node or a known proxy service.
    Uses our ProxyDetector class that maintains a list of Tor nodes and proxies.
    """
    if not ip or ip == "unknown_ip":
        return False
        
    # Basic IP validation
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
            return False
    except ValueError:
        return False
        
    # Check against our detector
    return proxy_detector.is_tor_or_proxy(ip)

def detect_bot_patterns(user_agent, request_info):
    """
    Analyze request patterns to determine if it's likely a bot.
    """
    bot_indicators = []
    
    ua_lower = user_agent.lower()
    
    # Check for common bot strings in user agent
    bot_strings = [
        # Common crawlers and bots
        'bot', 'crawl', 'spider', 'scan', 'scrape',
        # Web automation tools
        'wget', 'curl', 'httr', 'httpie', 'requests', 'axios',
        # Programming language HTTP clients
        'python-requests', 'python-urllib', 'go-http', 'java-http-client', 'okhttp',
        'aiohttp', 'httpclient', 'urllib', 'apache-httpclient',
        # Security scanners and testing tools
        'nmap', 'nikto', 'burp', 'zap', 'acunetix', 'qualys', 'nessus', 'sqlmap',
        'masscan', 'dirbuster', 'gobuster', 'dirb', 'wfuzz', 'hydra',
        # Specific bots
        'googlebot', 'bingbot', 'yandex', 'baidu', 'semrush', 'ahref', 'mj12bot',
        'archive.org', 'slurp', 'facebook', 'twitter', 'discord', 'telegram',
        # Common automation frameworks
        'selenium', 'playwright', 'puppeteer', 'webdriver', 'phantomjs', 'headless',
        # Less common identifiers
        'harvester', 'collector', 'fetch', 'checker', 'monitor', 'prober',
        'copier', 'indexer', 'archiver', 'data'
    ]
    for bot_string in bot_strings:
        if bot_string in ua_lower:
            bot_indicators.append(f"UA contains '{bot_string}'")
    
    # Empty or very short user agents are suspicious
    if len(user_agent) < 10:
        bot_indicators.append("Short user agent")
        
    # Check request pattern (timing, multiple requests, etc.)
    # In a real implementation, you would track this across requests
    
    return bot_indicators if bot_indicators else None

def log_scan_attempt(path, method, params=None, data=None):
    """
    Log comprehensive details about the scan attempt to the database.
    """
    try:
        client_id = get_client_identifier()
        
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        
        user_agent = request.headers.get('User-Agent', '')
        
        # 1. Reverse DNS lookup for additional intelligence
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = None
        
        # 2. Check for port scanning attempts
        is_port_scan = any(scan_term in path.lower() for scan_term in [
            'port', 'scan', 'nmap', 'masscan', 'shodan', 'censys'
        ])
        
        # 3. Check for common vulnerability scanners in user agent
        ua_lower = user_agent.lower() if user_agent else ""
        scanner_signs = ['nmap', 'nikto', 'sqlmap', 'acunetix', 'nessus', 
                        'zap', 'burp', 'whatweb', 'qualys', 'openvas']
        is_scanner = any(sign in ua_lower for sign in scanner_signs)
        
        # 4. Check for suspicious request parameters
        suspicious_params = False
        if params and request.args:
            param_checks = ['sleep', 'benchmark', 'exec', 'eval', 'union', 
                          'select', 'update', 'delete', 'insert', 'script']
            for param, value in request.args.items():
                if any(check in value.lower() for check in param_checks):
                    suspicious_params = True
                    break
        
        # Parse the user agent string for more details
        ua_info = {}
        try:
            if user_agent:
                parsed_ua = user_agents.parse(user_agent)
                ua_info = {
                    "browser": {
                        "family": parsed_ua.browser.family,
                        "version": parsed_ua.browser.version_string
                    },
                    "os": {
                        "family": parsed_ua.os.family,
                        "version": parsed_ua.os.version_string
                    },
                    "device": {
                        "family": parsed_ua.device.family,
                        "brand": parsed_ua.device.brand,
                        "model": parsed_ua.device.model
                    },
                    "is_mobile": parsed_ua.is_mobile,
                    "is_tablet": parsed_ua.is_tablet,
                    "is_pc": parsed_ua.is_pc,
                    "is_bot": parsed_ua.is_bot
                }
        except Exception as e:
            ua_info = {"parse_error": str(e)}
        
        # Get ASN info
        asn_info = extract_asn_from_ip(ip)
        
        # Detect if it's a likely bot
        bot_indicators = detect_bot_patterns(user_agent, {
            "path": path,
            "method": method
        })
        
        # Check if using Tor or proxy
        is_tor_or_proxy = detect_tor_or_proxy(ip)
        
        # Extract all headers for analysis
        headers = {key: value for key, value in request.headers.items()}
        
        # Build the scan log document
        scan_log = {
            "clientId": client_id,
            "ip": ip,
            "path": path,
            "method": method,
            "timestamp": datetime.utcnow(),
            "user_agent": user_agent,
            "ua_info": ua_info,
            "asn_info": asn_info,
            "headers": headers,
            "query_params": dict(request.args) if params else None,
            "form_data": dict(request.form) if data else None,
            "json_data": request.get_json(silent=True) if data else None,
            "cookies": {key: value for key, value in request.cookies.items()},
            "is_tor_or_proxy": is_tor_or_proxy,
            "bot_indicators": bot_indicators,
            "hostname": hostname,
            "is_port_scan": is_port_scan,
            "is_scanner": is_scanner,
            "suspicious_params": suspicious_params,
            "notes": []
        }
        
        # Additional security checks
        if "X-Forwarded-For" in headers and ip != request.remote_addr:
            scan_log["notes"].append("Possible IP spoofing attempt")
        
        # Check for suspicious query parameters
        if params:
            suspicious_params = [
                # SQL injection
                'eval', 'exec', 'select', 'union', 'sleep', 'benchmark', 'waitfor', 'delay',
                'from', 'where', 'having', 'group by', 'order by', 'insert', 'update', 'delete',
                '1=1', 'true=true', '1 like 1', 'information_schema', 'sys.tables',
                # Command injection
                'cmd', 'command', 'system', 'shell', 'bash', 'powershell', 'execute',
                '|', '&', ';', '`', '$', '>', '<', 'ping', 'nc', 'ncat', 'telnet',
                # File inclusion/traversal
                'file', 'path', 'include', 'require', 'load', '../', '..\\', '/etc/passwd',
                'c:\\windows', 'boot.ini', 'win.ini', '/var/www',
                # XSS-related
                'script', 'alert', 'onerror', 'onload', 'iframe', 'javascript', 'img',
                '<svg', 'prompt', 'confirm', 'cookie', 'document.location',
                # Serialization attacks
                'object', 'serialize', 'pickle', 'yaml', 'json', 'marshal',
                # NoSQL injection
                '$where', '$gt', '$lt', '$ne', '$exists', '$regex',
                # Other
                'test', 'debug', 'admin', 'root', 'passwd', 'password', 'config', 'secret',
                'token', 'jwt', 'api_key', 'key', 'auth', 'administrator', 'phpinfo'
            ]
            for param, value in request.args.items():
                if any(sus in value.lower() for sus in suspicious_params):
                    scan_log["notes"].append(f"Suspicious parameter: {param}")
        
        # Insert into database
        db.scanAttempts.insert_one(scan_log)
        
        # Update watchlist with this client
        severity = 1  # Base severity level
        
        # Increase severity based on certain factors
        if bot_indicators:
            severity += 1
        if is_tor_or_proxy:
            severity += 1
        if scan_log["notes"]:
            severity += len(scan_log["notes"])
        if is_port_scan:
            severity += 2
        if is_scanner:
            severity += 3
        if suspicious_params:
            severity += 2
        
        # Update the watchlist
        db.watchList.update_one(
            {"clientId": client_id},
            {
                "$set": {
                    "lastSeen": datetime.utcnow(),
                    "lastPath": path,
                    "ip": ip
                },
                "$inc": {"count": 1, "severity": severity}
            },
            upsert=True
        )
        
        # Return the client ID for potential further actions
        return client_id
        
    except Exception as e:
        logger.error(f"Error logging scan attempt: {str(e)}")
        logger.error(traceback.format_exc())
        return None


def is_rate_limited(client_id):
    """
    Check if the client has exceeded the honeypot rate limit.
    Much stricter than normal rate limits.
    """
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=HONEYPOT_RATE_PERIOD)
    
    # Count recent requests from this client to honeypot endpoints
    count = db.scanAttempts.count_documents({
        "clientId": client_id,
        "timestamp": {"$gte": cutoff}
    })
    
    return count >= HONEYPOT_RATE_LIMIT

def render_fake_response(path, method):
    """
    Return a fake but convincing response based on the requested path.
    Routes are checked against categories in the honeypot_routes dictionary.
    """
    # Get routes dictionary
    routes = get_honeypot_routes()
    
    # Check which category the path belongs to
    category = None
    for cat, paths in routes.items():
        if any(path == p for p in paths):
            category = cat
            break
    
    # Return appropriate template based on category
    if category == "wordpress":
        return render_template('honeypot/wp-login.html')
    elif category == "admin_panels":
        return render_template('honeypot/admin-login.html')
    elif category == "e_commerce":
        return render_template('honeypot/ecommerce-login.html')
    elif category == "additional_cms":
        return render_template('honeypot/cms-login.html')
    elif category == "forums_and_boards":
        return render_template('honeypot/forum-login.html')
    elif category == "file_sharing":
        return render_template('honeypot/filesharing-login.html')
    elif category == "database_endpoints":
        return render_template('honeypot/database-login.html')
    elif category == "mail_servers":
        return render_template('honeypot/mail-login.html')
    elif category == "remote_access":
        return render_template('honeypot/remote-access.html')
    elif category == "iot_devices":
        return render_template('honeypot/iot-admin.html')
    elif category == "devops_tools":
        return render_template('honeypot/devops-login.html')
    elif category == "web_frameworks":
        return render_template('honeypot/framework-admin.html')
    elif category == "logs_and_debug":
        return render_template('honeypot/debug-console.html')
    elif category == "backdoors_and_shells":
        return render_template('honeypot/shell.html')
    elif category == "injection_attempts":
        return render_template('honeypot/generic-page.html')
    elif category == "mobile_endpoints":
        return render_template('honeypot/mobile-api.html')
    elif category == "cloud_services":
        return render_template('honeypot/cloud-login.html')
    elif category == "monitoring_tools":
        return render_template('honeypot/monitoring-login.html')
    
    # Fallback for string matching if exact path not found
    if 'wp-login' in path or 'wp-admin' in path:
        return render_template('honeypot/wp-login.html')
    elif 'phpmyadmin' in path or 'pma' in path:
        return render_template('honeypot/phpmyadmin.html')
    elif 'cpanel' in path:
        return render_template('honeypot/cpanel.html')
    elif 'admin' in path:
        return render_template('honeypot/admin-login.html')
    
    # Default - generic login page
    return render_template('honeypot/generic-login.html')

def get_threat_score(client_id):
    """
    Calculate a threat score for this client based on past behavior.
    Higher score = more suspicious.
    """
    # Get client history
    client = db.watchList.find_one({"clientId": client_id})
    if not client:
        return 0
    
    # Base score
    score = 0
    
    # Number of scan attempts
    count = client.get("count", 0)
    if count > 1:
        score += min(count * 5, 50)  # Max 50 points from count
    
    # Severity from past scans
    severity = client.get("severity", 0)
    score += min(severity * 2, 30)  # Max 30 points from severity
    
    # Recent activity (within last hour)
    cutoff = datetime.utcnow() - timedelta(hours=1)
    recent_count = db.scanAttempts.count_documents({
        "clientId": client_id,
        "timestamp": {"$gte": cutoff}
    })
    score += min(recent_count * 2, 20)  # Max 20 points from recent activity
    
    return min(score, 100)  # Cap at 100

def handle_high_threat(client_id, threat_score):
    """
    Take action based on threat score. 
    This could include adding to a block list, triggering alerts, etc.
    """
    if threat_score >= 80:
        # Very high threat - add to blocklist
        db.securityBlocklist.update_one(
            {"clientId": client_id},
            {
                "$set": {
                    "blockUntil": datetime.utcnow() + timedelta(days=7),
                    "reason": "Excessive scanning activity",
                    "threatScore": threat_score,
                    "updatedAt": datetime.utcnow()
                }
            },
            upsert=True
        )
        
        # Could also trigger a notification here
        
    elif threat_score >= 50:
        # Medium-high threat - temporary block
        db.securityBlocklist.update_one(
            {"clientId": client_id},
            {
                "$set": {
                    "blockUntil": datetime.utcnow() + timedelta(hours=24),
                    "reason": "Suspicious scanning activity",
                    "threatScore": threat_score,
                    "updatedAt": datetime.utcnow()
                }
            },
            upsert=True
        )


def honeypot_handler():
    """
    Centralized handler for all honeypot routes. 
    Logs the attempt and returns appropriate fake response.
    """
    path = request.path
    method = request.method
    
    # Log this scan attempt
    client_id = log_scan_attempt(
        path, 
        method, 
        params=(request.method == 'GET'), 
        data=(request.method == 'POST')
    )
    
    # Check if this client is rate limited
    if client_id and is_rate_limited(client_id):
        # Calculate threat score for this client
        threat_score = get_threat_score(client_id)
        
        # Handle high-threat clients
        if threat_score >= 50:
            handle_high_threat(client_id, threat_score)
            
            # For very high threats, we might want to return a different response
            # e.g., a fake error page instead of login
            if threat_score >= 90:
                resp = make_response("403 Forbidden", 403)
                resp.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
                return resp
    
    # Return a fake but convincing response
    resp = make_response(render_fake_response(path, method))
    
    # Add some realistic headers
    resp.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
    resp.headers['X-Powered-By'] = 'PHP/7.4.3'
    
    return resp

# Add scheduled tasks
@honeypot_bp.before_app_first_request
def setup_honeypot_analytics():
    """Setup regular analytics for honeypot data"""
    # This would typically be done with Celery or similar
    # For now, we'll just initialize some data
    
    # Create indexes for better performance
    db.scanAttempts.create_index("timestamp")
    db.scanAttempts.create_index("clientId")
    db.scanAttempts.create_index("path")
    db.watchList.create_index("clientId")
    db.securityBlocklist.create_index("clientId")
    db.securityBlocklist.create_index("blockUntil")


# Default handler for all
def default_honeypot_handler():
    return honeypot_handler()

register_routes_with_blueprint(honeypot_bp, default_honeypot_handler)

# Add a catch-all for all the above routes
for endpoint in honeypot_bp.url_map._rules_by_endpoint:
    if 'honeypot_bp.' in endpoint and not endpoint.endswith('default_honeypot_handler'):
        honeypot_bp.view_functions[endpoint] = default_honeypot_handler

# Analytics route for admin dashboard
@honeypot_bp.route('/analytics', methods=['GET'])
def honeypot_analytics():
    """Return analytics about honeypot activity"""
    if not require_cracked_admin:
        return jsonify({"error": "Not authorized"}), 403
    
    # Get overall statistics
    total_attempts = db.scanAttempts.count_documents({})
    unique_ips = len(db.scanAttempts.distinct("ip"))
    unique_clients = len(db.scanAttempts.distinct("clientId"))
    
    # Most common paths
    top_paths_pipeline = [
        {"$group": {"_id": "$path", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]
    top_paths = list(db.scanAttempts.aggregate(top_paths_pipeline))
    
    # Most common IPs
    top_ips_pipeline = [
        {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]
    top_ips = list(db.scanAttempts.aggregate(top_ips_pipeline))
    
    # Recent activity
    recent_activity = list(db.scanAttempts.find()
                          .sort("timestamp", -1)
                          .limit(20))
    
    # Format for JSON response
    for activity in recent_activity:
        activity["_id"] = str(activity["_id"])
        activity["timestamp"] = activity["timestamp"].isoformat()
    
    return jsonify({
        "total_attempts": total_attempts,
        "unique_ips": unique_ips,
        "unique_clients": unique_clients,
        "top_paths": top_paths,
        "top_ips": top_ips,
        "recent_activity": recent_activity
    })


def ensure_ttl_indexes():
    """Ensure TTL indexes exist on collections that need automatic cleanup"""
    try:
        # Create TTL index on ai_usage_logs
        db.ai_usage_logs.create_index("expiresAt", expireAfterSeconds=0)
        
        # Create TTL index on userQuotas
        db.userQuotas.create_index("expiresAt", expireAfterSeconds=0)
        
        # Create TTL index on anonymousQuotas
        db.anonymousQuotas.create_index("expiresAt", expireAfterSeconds=0)
        
        logger.info("Ensured TTL indexes for AI guardrails collections")
    except Exception as e:
        logger.error(f"Error creating TTL indexes: {str(e)}")


