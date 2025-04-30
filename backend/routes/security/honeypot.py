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
from routes.security.honeypot_routes import register_routes_with_blueprint
from routes.security.proxy_detector import proxy_detector
from routes.security.geo_db_updater import download_and_extract_db
import geoip2.database
import os
from routes.admin.cracked_admin import require_cracked_admin

from dotenv import load_dotenv

load_dotenv()

# Create honeypot blueprint
honeypot_bp = Blueprint('honeypot', __name__)

DEFAULT_SCAN_PATHS = {
    "/admin",
    "/admin/login",
    "/wp-admin",
    "/wp-login.php",
    "/administrator",
    "/login",
    "/administrator/index.php"
}


DB_DIRECTORY = os.environ.get('DB_DIRECTORY')
LICENSE_KEY = os.environ.get('MAXMIND_LICENSE_KEY')
geoip_dir = os.environ.get('DB_DIRECTORY', '/app/geoip_db')

# Complete the paths with proper filenames
ASN_DB_PATH = os.path.join(geoip_dir, 'GeoLite2-ASN.mmdb')
COUNTRY_DB_PATH = os.path.join(geoip_dir, 'GeoLite2-Country.mmdb')
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


@honeypot_bp.route('/analytics', methods=['GET'])
def honeypot_analytics():
    """Return analytics about honeypot activity"""
    if not require_cracked_admin():  
        return jsonify({"error": "Not authorized"}), 403
    
    try:

        total_attempts = db.scanAttempts.count_documents({})
        unique_ips = len(db.scanAttempts.distinct("ip"))
        unique_clients = len(db.scanAttempts.distinct("clientId"))
        

        top_paths_pipeline = [
            {"$group": {"_id": "$path", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        top_paths = list(db.scanAttempts.aggregate(top_paths_pipeline))
        

        top_ips_pipeline = [
            {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        top_ips = list(db.scanAttempts.aggregate(top_ips_pipeline))
        

        recent_activity = list(db.scanAttempts.find()
                              .sort("timestamp", -1)
                              .limit(20))
        

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
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error in honeypot analytics: {str(e)}")
        return jsonify({
            "total_attempts": 0,
            "unique_ips": 0,
            "unique_clients": 0,
            "top_paths": [],
            "top_ips": [],
            "recent_activity": []
        }), 200  

def log_honeypot_interaction(category, action, details=None):
    """Log interactions with honeypot pages
    
    Args:
        category (str): Category of honeypot (wordpress, admin, etc.)
        action (str): Type of interaction (page_view, login_attempt, etc.)
        details (dict, optional): Additional details about the interaction
    """
    from flask import request, current_app
    from datetime import datetime
    from mongodb.database import db
    
    # Create log entry
    log_entry = {
        "category": category,
        "action": action,
        "timestamp": datetime.utcnow(),
        "ip": request.remote_addr,
        "user_agent": request.headers.get('User-Agent', 'Unknown'),
        "path": request.path,
        "method": request.method
    }
    
    # Add additional details if provided
    if details:
        log_entry.update(details)
    
    # Insert into database and get ID
    result = db.honeypotLogs.insert_one(log_entry)
    
    # Log to application logger
    current_app.logger.info(f"Honeypot interaction: {category} - {action} from {request.remote_addr}")   
    return str(result.inserted_id)
    
    
@honeypot_bp.route('/log-interaction', methods=['POST'])
def log_client_side_interaction():
    """Endpoint for logging client-side interactions via AJAX"""
    if not request.is_json:
        return jsonify({"status": "error", "message": "Expected JSON data"}), 400
        
    data = request.get_json()
    page_type = data.get('page_type', 'unknown')
    interaction_type = data.get('interaction_type', 'unknown')
    additional_data = data.get('additional_data', {})
    
    interaction_id = log_honeypot_interaction(page_type, interaction_type, additional_data)
    
    return jsonify({"status": "success", "interaction_id": interaction_id})
    
    
    
@honeypot_bp.route('/detailed-stats', methods=['GET'])
def honeypot_detailed_stats():
    """Return detailed statistics about honeypot activity"""
    from flask import session, jsonify, current_app
    from routes.admin.cracked_admin import require_cracked_admin
    from datetime import datetime, timedelta
    
    # Check admin authentication
    if not require_cracked_admin():
        return jsonify({"error": "Not authorized"}), 403
    
    try:
        # Get time frames for stats
        now = datetime.utcnow()
        yesterday = now - timedelta(days=1)
        last_week = now - timedelta(days=7)
        last_month = now - timedelta(days=30)
        
        # Get threats detected (interactions with certain patterns)
        threats_detected = db.honeypot_interactions.count_documents({
            "$or": [
                {"suspicious_params": True},
                {"is_scanner": True},
                {"is_port_scan": True}
            ]
        })
        
        # Get unique page types and counts
        page_types = db.honeypot_interactions.aggregate([
            {"$group": {"_id": "$page_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ])
        page_type_stats = {doc["_id"]: doc["count"] for doc in page_types if doc["_id"]}
        
        # Get interaction types
        interaction_types = db.honeypot_interactions.aggregate([
            {"$group": {"_id": "$interaction_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ])
        interaction_stats = {doc["_id"]: doc["count"] for doc in interaction_types if doc["_id"]}
        
        # Get time-based stats
        today_count = db.honeypot_interactions.count_documents({
            "timestamp": {"$gte": yesterday}
        })
        
        week_count = db.honeypot_interactions.count_documents({
            "timestamp": {"$gte": last_week}
        })
        
        month_count = db.honeypot_interactions.count_documents({
            "timestamp": {"$gte": last_month}
        })
        
        # Get top interactors (IPs with most interactions)
        top_interactors = list(db.honeypot_interactions.aggregate([
            {"$group": {"_id": "$ip_address", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))
        
        # Get most downloaded payloads
        payload_downloads = list(db.honeypot_interactions.aggregate([
            {"$match": {"interaction_type": "download_attempt"}},
            {"$group": {"_id": "$page_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]))
        
        # Get geographical distribution
        countries = list(db.honeypot_interactions.aggregate([
            {"$match": {"geoInfo.country": {"$exists": True}}},
            {"$group": {"_id": "$geoInfo.country", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))
        
        # Combine all stats
        stats = {
            "threats_detected": threats_detected,
            "unique_page_types": len(page_type_stats),
            "unique_interaction_types": len(interaction_stats),
            "today_interactions": today_count,
            "week_interactions": week_count,
            "month_interactions": month_count,
            "page_type_stats": page_type_stats,
            "interaction_stats": interaction_stats,
            "top_interactors": top_interactors,
            "payload_downloads": payload_downloads,
            "geographic_stats": countries,
            "timestamp": now.isoformat()
        }
        
        return jsonify(stats), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting honeypot stats: {str(e)}")
        return jsonify({
            "error": "Failed to retrieve honeypot statistics",
            "details": str(e)
        }), 500


@honeypot_bp.route('/interactions', methods=['GET'])
def view_honeypot_interactions():
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
        
    try:
        # Get interactions with pagination
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        skip = (page - 1) * limit
        
        # Apply filters if provided
        filter_query = {}
        page_type = request.args.get('page_type')
        if page_type:
            filter_query['page_type'] = page_type
            
        interaction_type = request.args.get('interaction_type')
        if interaction_type:
            filter_query['interaction_type'] = interaction_type
            
        # Get interactions
        interactions = list(db.honeypot_interactions.find(filter_query)
                           .sort("timestamp", -1)
                           .skip(skip)
                           .limit(limit))
                           
        # Format for JSON response
        for interaction in interactions:
            interaction['_id'] = str(interaction['_id'])
            interaction['timestamp'] = interaction['timestamp'].isoformat()
            
        # Get total count
        total_count = db.honeypot_interactions.count_documents(filter_query)
        
        return jsonify({
            "interactions": interactions,
            "total": total_count,
            "page": page,
            "limit": limit
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve user requests: {str(e)}"}), 500
        
        
@honeypot_bp.route('/interactions/<interaction_id>', methods=['GET'])
def get_honeypot_interaction(interaction_id):
    """Get detailed information about a specific honeypot interaction"""
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
        
    try:
        # Find the interaction by ID
        interaction = db.honeypot_interactions.find_one({"_id": ObjectId(interaction_id)})
        
        if not interaction:
            return jsonify({"error": "Interaction not found"}), 404
            
        # Convert ObjectId to string for JSON serialization
        interaction["_id"] = str(interaction["_id"])
        
        # Make timestamp JSON serializable if it's a datetime
        if isinstance(interaction.get("timestamp"), datetime):
            interaction["timestamp"] = interaction["timestamp"].isoformat()
            
        # Add human-readable explanations to the data
        interaction["explanations"] = {
            "summary": "This is a record of when someone interacted with your honeypot system.",
            "interaction_type": get_interaction_type_explanation(interaction.get("interaction_type", "")),
            "page_type": get_page_type_explanation(interaction.get("page_type", "")),
            "suspicious_factors": get_suspicious_factors(interaction),
            "technical_details": "The data shows exactly what the visitor sent to your server, including their browser details, IP address, and what they were trying to access."
        }
        
        return jsonify(interaction), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting honeypot interaction: {str(e)}")
        return jsonify({"error": f"Failed to retrieve interaction details: {str(e)}"}), 500

# Helper functions for human-readable explanations
def get_interaction_type_explanation(interaction_type):
    """Return a human-readable explanation of the interaction type"""
    explanations = {
        "page_view": "Someone visited this page directly, possibly trying to access restricted admin areas.",
        "download_attempt": "Someone tried to download a file from your honeypot, which could indicate they were tricked by the fake system.",
        "form_submission": "Someone submitted login credentials or other data to your honeypot form.",
        "button_click": "Someone clicked on an interactive element in your honeypot.",
        "menu_click": "Someone clicked on a menu item in your honeypot interface."
    }
    return explanations.get(interaction_type, "Unknown interaction type")
    
def get_page_type_explanation(page_type):
    """Return a human-readable explanation of the page type"""
    explanations = {
        "wordpress": "A fake WordPress admin page that attracts attackers looking for vulnerable WordPress sites.",
        "admin_panels": "A fake admin login page designed to attract unauthorized access attempts.",
        "phpmyadmin": "A fake database administration tool page that attracts attackers looking for database access.",
        "cpanel": "A fake hosting control panel that attracts attackers looking for website hosting access."
    }
    return explanations.get(page_type, "Unknown page type")
    
def get_suspicious_factors(interaction):
    """Analyze the interaction for suspicious factors and return human-readable explanations"""
    factors = []
    
    # Check for Tor/proxy usage
    if interaction.get("is_tor_or_proxy"):
        factors.append("This visitor appears to be using Tor or a proxy service, which might indicate they're trying to hide their identity.")
    
    # Check for known bot patterns
    if interaction.get("bot_indicators") and len(interaction.get("bot_indicators", [])) > 0:
        factors.append("This visitor shows signs of being an automated tool or bot rather than a real person.")
    
    # Check for scanner signatures
    if interaction.get("is_scanner"):
        factors.append("This visitor appears to be using a vulnerability scanner tool, which is commonly used by attackers.")
    
    # Check for port scanning
    if interaction.get("is_port_scan"):
        factors.append("This visitor seems to be scanning your server for open ports, which is often a first step in an attack.")
    
    # Check for suspicious query parameters
    if interaction.get("suspicious_params"):
        factors.append("This visitor is using suspicious parameters that might indicate an attempt to exploit vulnerabilities.")
    
    return factors if factors else ["No obviously suspicious behavior detected."]



@honeypot_bp.route('/combined-analytics', methods=['GET'])
def combined_honeypot_analytics():
    """Return combined analytics from both honeypot collections"""
    if not require_cracked_admin():  
        return jsonify({"error": "Not authorized"}), 401
    
    try:
        # Get statistics from both collections
        scan_attempts_count = db.scanAttempts.count_documents({})
        interactions_count = db.honeypot_interactions.count_documents({})
        total_attempts = scan_attempts_count + interactions_count
        
        # Combine unique IPs from both collections
        scan_ips = set(db.scanAttempts.distinct("ip"))
        interaction_ips = set(db.honeypot_interactions.distinct("ip_address"))
        unique_ips = len(scan_ips.union(interaction_ips))
        
        # Combine unique clients
        scan_clients = set(db.scanAttempts.distinct("clientId"))
        interaction_clients = set(db.honeypot_interactions.distinct("interaction_id"))
        unique_clients = len(scan_clients.union(interaction_clients))
        
        # Get top paths from both collections
        paths_data = []
        
        # Get paths from scanAttempts
        if scan_attempts_count > 0:
            scan_paths_pipeline = [
                {"$group": {"_id": "$path", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            scan_paths = list(db.scanAttempts.aggregate(scan_paths_pipeline))
            paths_data.extend(scan_paths)
        
        # Get paths from honeypot_interactions
        if interactions_count > 0:
            interaction_paths_pipeline = [
                {"$group": {"_id": "$path", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            interaction_paths = list(db.honeypot_interactions.aggregate(interaction_paths_pipeline))
            paths_data.extend(interaction_paths)
        
        # Combine and sort paths
        path_counts = {}
        for item in paths_data:
            path = item["_id"]
            count = item["count"]
            if path in path_counts:
                path_counts[path] += count
            else:
                path_counts[path] = count
        
        top_paths = [{"_id": k, "count": v} for k, v in path_counts.items()]
        top_paths.sort(key=lambda x: x["count"], reverse=True)
        top_paths = top_paths[:10]
        
        # Similar approach for IPs
        ips_data = []
        
        # Get IPs from scanAttempts
        if scan_attempts_count > 0:
            scan_ips_pipeline = [
                {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            scan_ips_list = list(db.scanAttempts.aggregate(scan_ips_pipeline))
            ips_data.extend(scan_ips_list)
        
        # Get IPs from honeypot_interactions
        if interactions_count > 0:
            interaction_ips_pipeline = [
                {"$group": {"_id": "$ip_address", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            interaction_ips_list = list(db.honeypot_interactions.aggregate(interaction_ips_pipeline))
            ips_data.extend(interaction_ips_list)
        
        # Combine and sort IPs
        ip_counts = {}
        for item in ips_data:
            ip = item["_id"]
            count = item["count"]
            if ip in ip_counts:
                ip_counts[ip] += count
            else:
                ip_counts[ip] = count
        
        top_ips = [{"_id": k, "count": v} for k, v in ip_counts.items()]
        top_ips.sort(key=lambda x: x["count"], reverse=True)
        top_ips = top_ips[:10]
        
        # Get recent activity (combine both collections)
        recent_scan_attempts = list(db.scanAttempts.find().sort("timestamp", -1).limit(10))
        recent_interactions = list(db.honeypot_interactions.find().sort("timestamp", -1).limit(10))
        
        # Format scan attempts
        for item in recent_scan_attempts:
            item["_id"] = str(item["_id"])
            if isinstance(item.get("timestamp"), datetime):
                item["timestamp"] = item["timestamp"].isoformat()
            # Normalize data structure
            item["ip"] = item.get("ip")
            item["path"] = item.get("path", "")
            item["type"] = item.get("type", "page_view")
        
        # Format interactions
        for item in recent_interactions:
            item["_id"] = str(item["_id"])
            if isinstance(item.get("timestamp"), datetime):
                item["timestamp"] = item["timestamp"].isoformat()
            # Normalize data structure
            item["ip"] = item.get("ip_address")
            item["path"] = item.get("path", "")
            item["type"] = item.get("interaction_type", "page_view")
        
        # Combine, sort by timestamp, and limit to 20
        combined_activity = recent_scan_attempts + recent_interactions
        combined_activity.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        recent_activity = combined_activity[:20]
        
        # Count detected threats
        threats_detected = (
            db.scanAttempts.count_documents({
                "$or": [
                    {"is_scanner": True},
                    {"is_port_scan": True},
                    {"suspicious_params": True},
                    {"bot_indicators": {"$exists": True, "$ne": []}}
                ]
            }) +
            db.honeypot_interactions.count_documents({
                "$or": [
                    {"is_scanner": True},
                    {"is_port_scan": True},
                    {"suspicious_params": True}
                ]
            })
        )
        
        return jsonify({
            "total_attempts": total_attempts,
            "unique_ips": unique_ips,
            "unique_clients": unique_clients,
            "threats_detected": threats_detected,
            "top_paths": top_paths,
            "top_ips": top_ips,
            "recent_activity": recent_activity
        }), 200
    except Exception as e:
        logger.error(f"Error in combined honeypot analytics: {str(e)}")
        # Return empty data with 200 status
        return jsonify({
            "total_attempts": 0,
            "unique_ips": 0,
            "unique_clients": 0,
            "threats_detected": 0,
            "top_paths": [],
            "top_ips": [],
            "recent_activity": []
        }), 200



@honeypot_bp.route('/html-interactions', methods=['GET'])
def get_html_interactions():
    """Get honeypot HTML page interactions with filtering and pagination"""
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
        
    try:
        # Get pagination params
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        skip = (page - 1) * limit
        
        # Get filter params
        page_type = request.args.get('page_type')
        interaction_type = request.args.get('interaction_type')
        ip_filter = request.args.get('ip')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        search_term = request.args.get('search')
        
        # Build query
        query = {}
        
        # Apply filters
        if page_type and page_type != 'all':
            query['page_type'] = page_type
            
        if interaction_type and interaction_type != 'all':
            query['interaction_type'] = interaction_type
            
        if ip_filter:
            query['ip_address'] = {"$regex": ip_filter, "$options": "i"}
            
        # Date range filter
        if date_from or date_to:
            query['timestamp'] = {}
            if date_from:
                try:
                    from_date = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                    query['timestamp']["$gte"] = from_date
                except:
                    pass
                    
            if date_to:
                try:
                    to_date = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                    query['timestamp']["$lte"] = to_date
                except:
                    pass
        
        # Full text search across multiple fields
        if search_term:
            search_regex = {"$regex": search_term, "$options": "i"}
            query["$or"] = [
                {"page_type": search_regex},
                {"interaction_type": search_regex},
                {"ip_address": search_regex},
                {"additional_data.username": search_regex},
                {"additional_data.message": search_regex},
                {"additional_data.input": search_regex},
                {"additional_data.form_data": search_regex}
            ]
        
        # Get total count for pagination
        total_count = db.honeypot_interactions.count_documents(query)
        
        # Get interactions with pagination
        interactions = list(db.honeypot_interactions.find(query)
                          .sort("timestamp", -1)
                          .skip(skip)
                          .limit(limit))
        
        # Format for JSON
        for interaction in interactions:
            interaction['_id'] = str(interaction['_id'])
            if isinstance(interaction.get('timestamp'), datetime):
                interaction['timestamp'] = interaction['timestamp'].isoformat()
            
        # Get unique page types and interaction types for filters
        page_types = db.honeypot_interactions.distinct("page_type")
        interaction_types = db.honeypot_interactions.distinct("interaction_type")
        
        return jsonify({
            "interactions": interactions,
            "total": total_count,
            "page": page,
            "limit": limit,
            "page_types": page_types,
            "interaction_types": interaction_types
        }), 200
        
    except Exception as e:
        print(f"Error getting honeypot interactions: {str(e)}")
        return jsonify({"error": str(e)}), 500

@honeypot_bp.route('/html-interactions/stats', methods=['GET'])
def get_html_interactions_stats():
    """Get statistics about honeypot HTML page interactions"""
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
        
    try:
        # Get time frames for stats
        now = datetime.utcnow()
        yesterday = now - timedelta(days=1)
        last_week = now - timedelta(days=7)
        last_month = now - timedelta(days=30)
        
        # Get count of interactions in various time frames
        total_interactions = db.honeypot_interactions.count_documents({})
        today_interactions = db.honeypot_interactions.count_documents({"timestamp": {"$gte": yesterday}})
        week_interactions = db.honeypot_interactions.count_documents({"timestamp": {"$gte": last_week}})
        month_interactions = db.honeypot_interactions.count_documents({"timestamp": {"$gte": last_month}})
        
        # Get most popular page types
        page_type_pipeline = [
            {"$group": {"_id": "$page_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        page_types = list(db.honeypot_interactions.aggregate(page_type_pipeline))
        
        # Get most common interaction types
        interaction_type_pipeline = [
            {"$group": {"_id": "$interaction_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        interaction_types = list(db.honeypot_interactions.aggregate(interaction_type_pipeline))
        
        # Get top IPs with most interactions
        ip_pipeline = [
            {"$group": {"_id": "$ip_address", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        top_ips = list(db.honeypot_interactions.aggregate(ip_pipeline))
        
        # Get credential harvesting attempts
        credentials_pipeline = [
            {"$match": {"$or": [
                {"interaction_type": "login_attempt"},
                {"interaction_type": "form_submit"},
                {"additional_data.username": {"$exists": true}},
                {"additional_data.password": {"$exists": true}}
            ]}},
            {"$sort": {"timestamp": -1}},
            {"$limit": 20}
        ]
        credential_attempts = list(db.honeypot_interactions.aggregate(credentials_pipeline))
        
        # Format for JSON
        for attempt in credential_attempts:
            attempt['_id'] = str(attempt['_id'])
            if isinstance(attempt.get('timestamp'), datetime):
                attempt['timestamp'] = attempt['timestamp'].isoformat()
        
        # Get interactions over time (for charts)
        time_series_pipeline = [
            {"$match": {"timestamp": {"$gte": last_month}}},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": 1}}
        ]
        time_series = list(db.honeypot_interactions.aggregate(time_series_pipeline))
        
        # Convert time series to chart-friendly format
        chart_data = [{"date": item["_id"], "count": item["count"]} for item in time_series]
        
        return jsonify({
            "total_interactions": total_interactions,
            "today_interactions": today_interactions,
            "week_interactions": week_interactions,
            "month_interactions": month_interactions,
            "page_types": page_types,
            "interaction_types": interaction_types,
            "top_ips": top_ips,
            "credential_attempts": credential_attempts,
            "time_series": chart_data
        }), 200
        
    except Exception as e:
        print(f"Error getting honeypot stats: {str(e)}")
        return jsonify({"error": str(e)}), 500

@honeypot_bp.route('/html-interactions/<interaction_id>', methods=['GET'])
def get_html_interaction_details(interaction_id):
    """Get detailed information about a specific honeypot interaction"""
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
        
    try:
        # Find the interaction by ID
        interaction = db.honeypot_interactions.find_one({"_id": ObjectId(interaction_id)})
        
        if not interaction:
            return jsonify({"error": "Interaction not found"}), 404
            
        # Convert ObjectId to string for JSON serialization
        interaction["_id"] = str(interaction["_id"])
        
        # Make timestamp JSON serializable if it's a datetime
        if isinstance(interaction.get("timestamp"), datetime):
            interaction["timestamp"] = interaction["timestamp"].isoformat()
            
        # Add human-readable explanations
        interaction["explanations"] = {
            "summary": f"This is a record of a user interacting with the {interaction.get('page_type', 'unknown')} honeypot page.",
            "interaction_type": get_interaction_explanation(interaction.get("interaction_type", "")),
            "page_type": get_page_type_explanation(interaction.get("page_type", "")),
            "risk_level": get_risk_level(interaction),
            "technical_details": "The data shows the exact interaction the visitor made with your honeypot system."
        }
        
        # Enrich with GeoIP data if not already present
        if interaction.get('ip_address') and not interaction.get('geoInfo'):
            interaction['geoInfo'] = extract_asn_from_ip(interaction['ip_address'])
        
        return jsonify(interaction), 200
        
    except Exception as e:
        print(f"Error getting interaction details: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Helper functions
def get_interaction_explanation(interaction_type):
    """Return a human-readable explanation of the interaction type"""
    explanations = {
        "page_view": "The visitor viewed this honeypot page, showing interest in this resource.",
        "login_attempt": "The visitor attempted to log in with credentials, trying to gain unauthorized access.",
        "form_submit": "The visitor submitted form data, potentially revealing their intentions.",
        "button_click": "The visitor clicked on a button, showing deeper engagement with the honeypot.",
        "download_attempt": "The visitor tried to download a file, which could indicate data exfiltration intent.",
        "sql_injection_attempt": "The visitor attempted to inject SQL code, a clear attack vector.",
        "captcha_attempt": "The visitor attempted to solve a CAPTCHA challenge.",
        "terminal_command": "The visitor entered commands in a fake terminal, showing technical sophistication.",
        "chat_message": "The visitor sent messages in a fake chat interface."
    }
    
    return explanations.get(interaction_type, f"Unknown interaction type: {interaction_type}")

def get_page_type_explanation(page_type):
    """Return a human-readable explanation of the page type"""
    explanations = {
        "admin_dashboard": "A fake admin dashboard that attracts attackers looking for privileged access.",
        "login_portal": "A fake login page designed to attract unauthorized access attempts.",
        "system_verify": "A fake system verification page that appears to offer privileged access.",
        "synergy_portal_login": "A fake enterprise portal login that attracts credential harvesting attempts.",
        "wp-admin": "A fake WordPress admin page that attracts attackers looking for vulnerable WordPress sites.",
        "phpmyadmin": "A fake database administration tool page that attracts attackers looking for database access.",
        "cpanel": "A fake hosting control panel that attracts attackers looking for website hosting access."
    }
    
    return explanations.get(page_type, f"Honeypot page type: {page_type}")

def get_risk_level(interaction):
    """Determine risk level based on interaction characteristics"""
    risk = "Low"
    reasons = []
    
    # Higher risk interaction types
    high_risk_types = ["sql_injection_attempt", "terminal_command", "download_attempt"]
    medium_risk_types = ["login_attempt", "form_submit"]
    
    interaction_type = interaction.get("interaction_type", "")
    
    if interaction_type in high_risk_types:
        risk = "High"
        reasons.append(f"{interaction_type} is a high-risk interaction type")
    elif interaction_type in medium_risk_types:
        risk = "Medium"
        reasons.append(f"{interaction_type} is a medium-risk interaction type")
    
    # Check additional data for suspicious content
    additional_data = interaction.get("additional_data", {})
    
    # SQL injection patterns
    sql_patterns = ["'", "\"", ";", "--", "/*", "*/", "=", " OR ", " AND ", 
                   "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "UNION "]
    
    for field in ["username", "password", "message", "input", "command"]:
        if field in additional_data:
            value = str(additional_data[field]).lower()
            for pattern in sql_patterns:
                if pattern.lower() in value:
                    risk = "High"
                    reasons.append(f"SQL injection pattern ({pattern}) found in {field}")
                    break
    
    # Check for credential harvesting
    if interaction_type == "login_attempt" and "username" in additional_data and "password" in additional_data:
        risk = max(risk, "Medium")
        reasons.append("Credential harvesting attempt detected")
    
    # Check browser information if present
    browser_info = additional_data.get("browser_info", {})
    user_agent = browser_info.get("userAgent", "").lower()
    
    # Potential automated tool indicators
    tool_patterns = ["curl", "wget", "python", "bot", "spider", "crawl", "scan"]
    for pattern in tool_patterns:
        if pattern in user_agent:
            risk = max(risk, "Medium")
            reasons.append(f"Potential automated tool detected in user agent ({pattern})")
            break
    
    return {"level": risk, "reasons": reasons}

