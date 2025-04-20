import time
import logging
from datetime import datetime, timedelta
from flask import request, jsonify, g
from functools import wraps
from mongodb.database import db
import ipaddress
import hashlib

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class GlobalRateLimiter:
    """
    Global rate limiter to prevent abuse of public API endpoints.
    Tracks usage based on IP address and/or session/user identifiers.
    Implements progressive rate limits (stricter limits after repeated violations).
    """
    
    # Default limits for different categories, AINT NOBODY SPAMMIN MY SHIT IM UNHACKABLE!!!!
    DEFAULT_LIMITS = {
        'auth': {'calls': 150, 'period': 60},         # 10 calls per minute for authentication
        'password_reset': {'calls': 100, 'period': 300},  # 5 calls per 5 minutes for password reset
        'contact': {'calls': 100, 'period': 300},         # 5 calls per 5 minutes for contact form
        'general': {'calls': 150, 'period': 60}          # 30 calls per minute for general endpoints
    }
    
    # Penalty factors for repeated violations
    PENALTY_PERIODS = [1, 5, 15, 30, 60]  # Minutes to block after consecutive violations
    
    def __init__(self, limiter_type=None):
        """
        Initialize the rate limiter with specific type limits.
        
        Args:
            limiter_type: The type of endpoint being rate limited
                         ('auth', 'password_reset', 'contact', 'general')
        """
        self.limiter_type = limiter_type or 'general'
        self.limits = self.DEFAULT_LIMITS.get(self.limiter_type, self.DEFAULT_LIMITS['general'])
    
    def _get_client_identifier(self):
        """
        Get a unique identifier for the client, using multiple factors for reliability.
        Uses a combination of IP, user agent, and session identifier if available.
        
        Returns:
            str: A hashed identifier for the client
        """
        # Get IP address, handling proxies
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:  # Handle multiple IPs in X-Forwarded-For
            ip = ip.split(',')[0].strip()
            
        # Try to get a more precise identifier
        session_id = request.cookies.get('session', '')
        user_agent = request.headers.get('User-Agent', '')
        
        # Create a combined identifier
        identifier_parts = [ip]
        
        # Only include session ID if it exists
        if session_id:
            identifier_parts.append(session_id)
        
        # Build the identifier
        identifier = "_".join(identifier_parts)
        
        # Hash the identifier to protect privacy and handle special characters
        hashed_id = hashlib.md5(identifier.encode()).hexdigest()
        
        return f"{ip}_{hashed_id[:8]}"
    
    def _check_ip_whitelist(self, ip):
        """
        Check if the IP is in the whitelist.
        Allows for both exact IPs and CIDR notation.
        
        Args:
            ip: IP address to check
            
        Returns:
            bool: True if IP is whitelisted
        """
        # Define whitelisted IPs or ranges
        whitelist = [
            '127.0.0.1',        # Localhost
            '192.168.1.0/24',   # Common local network
            '10.0.0.0/8'        # Internal network
        ]
        
        try:
            client_ip = ipaddress.ip_address(ip)
            
            # Check exact IP matches and network ranges
            for item in whitelist:
                if '/' in item:  # CIDR notation
                    if client_ip in ipaddress.ip_network(item):
                        return True
                else:  # Exact IP match
                    if ip == item:
                        return True
            
            return False
        except ValueError:
            return False
    
    def is_rate_limited(self):
        """
        Check if the current client is rate limited for this endpoint.
        
        Returns:
            tuple: (is_limited, remaining_calls, reset_time, retry_after)
        """
        # Get client identifier
        client_id = self._get_client_identifier()
        
        # Extract IP part for whitelist checking
        ip = client_id.split('_')[0] if '_' in client_id else client_id
        
        # Allow whitelisted IPs to bypass rate limiting (TRY TO SPOOF IT I DARE YOU)
        if self._check_ip_whitelist(ip):
            return False, self.limits['calls'], None, 0
        
        # Get current time
        now = datetime.utcnow()
        
        # Find client's usage records for this endpoint
        collection = db.globalRateLimits
        record = collection.find_one({
            "clientId": client_id,
            "endpoint": self.limiter_type
        })
        
        # If no record exists, create one
        if not record:
            record = {
                "clientId": client_id,
                "endpoint": self.limiter_type,
                "calls": [],
                "violations": 0,
                "blockUntil": None,
                "updatedAt": now
            }
            collection.insert_one(record)
            return False, self.limits['calls'], None, 0
        
        # Check if the client is currently blocked
        block_until = record.get('blockUntil')
        if block_until and block_until > now:
            # Calculate time remaining in the block
            retry_after = int((block_until - now).total_seconds())
            return True, 0, block_until, retry_after
        
        # Get the calls within the time period
        period_start = now - timedelta(seconds=self.limits['period'])
        valid_calls = [call for call in record.get('calls', []) if call >= period_start]
        
        # Calculate remaining calls
        used_calls = len(valid_calls)
        remaining_calls = max(0, self.limits['calls'] - used_calls)
        
        # Calculate reset time (when oldest call will expire)
        reset_time = None
        if valid_calls and used_calls >= self.limits['calls']:
            oldest_call = min(valid_calls)
            reset_time = oldest_call + timedelta(seconds=self.limits['period'])
        
        # Check if client has exceeded the limit
        is_limited = used_calls >= self.limits['calls']
        
        # If limited, calculate retry-after header value
        retry_after = 0
        if is_limited and reset_time:
            retry_after = max(0, int((reset_time - now).total_seconds()))
            
            # If this is a violation, update the violation count and potentially block the client
            if is_limited:
                violations = record.get('violations', 0) + 1
                
                # Determine if we need to block the client for a longer period
                if violations > 1:
                    # Get the penalty period (in minutes) based on violation count
                    penalty_index = min(violations - 2, len(self.PENALTY_PERIODS) - 1)
                    penalty_minutes = self.PENALTY_PERIODS[penalty_index]
                    
                    # Set block until time
                    block_until = now + timedelta(minutes=penalty_minutes)
                    
                    # Update the record with the new block time
                    collection.update_one(
                        {"_id": record["_id"]},
                        {"$set": {
                            "violations": violations,
                            "blockUntil": block_until,
                            "updatedAt": now
                        }}
                    )
                    
                    # Update retry_after to reflect the block time
                    retry_after = penalty_minutes * 60
                    reset_time = block_until
                else:
                    # Just update the violation count
                    collection.update_one(
                        {"_id": record["_id"]},
                        {"$set": {
                            "violations": violations,
                            "updatedAt": now
                        }}
                    )
        
        return is_limited, remaining_calls, reset_time, retry_after
    
    def increment_usage(self):
        """
        Record that the client has made another call to this endpoint.
        """
        # Get client identifier
        client_id = self._get_client_identifier()
        
        # Get current time
        now = datetime.utcnow()
        
        # Add call timestamp to the client's record
        db.globalRateLimits.update_one(
            {"clientId": client_id, "endpoint": self.limiter_type},
            {
                "$push": {"calls": now},
                "$set": {"updatedAt": now}
            },
            upsert=True
        )
        
    def reset_violations(self, client_id=None):
        """
        Reset violation count for a client.
        
        Args:
            client_id: Optional client ID to reset. If None, uses current client.
        """
        if client_id is None:
            client_id = self._get_client_identifier()
            
        # Get current time
        now = datetime.utcnow()
        
        # Reset violations and block
        db.globalRateLimits.update_one(
            {"clientId": client_id, "endpoint": self.limiter_type},
            {
                "$set": {
                    "violations": 0,
                    "blockUntil": None,
                    "updatedAt": now
                }
            }
        )

def global_rate_limit(limiter_type):
    """
    Decorator to apply rate limiting to a route.
    
    Args:
        limiter_type: The type of endpoint being rate limited
                    ('auth', 'password_reset', 'contact', 'general')
    
    Returns:
        Function decorator
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Create a rate limiter for this endpoint
            limiter = GlobalRateLimiter(limiter_type)
            
            # Check if rate limited
            is_limited, remaining, reset_time, retry_after = limiter.is_rate_limited()
            
            # If limited, return 429 Too Many Requests
            if is_limited:
                reset_msg = ""
                if reset_time:
                    # Calculate seconds until reset
                    seconds_to_reset = max(1, int((reset_time - datetime.utcnow()).total_seconds()))
                    minutes_to_reset = max(1, seconds_to_reset // 60)
                    reset_msg = f" Try again in {minutes_to_reset} minutes."
                
                response = jsonify({
                    "error": f"Rate limit exceeded for {limiter_type} endpoint.{reset_msg}",
                    "remaining": remaining,
                    "type": "rate_limit_error"
                })
                response.status_code = 429
                
                # Set headers for rate limit info
                response.headers['X-RateLimit-Limit'] = str(limiter.limits['calls'])
                response.headers['X-RateLimit-Remaining'] = str(remaining)
                if reset_time:
                    response.headers['X-RateLimit-Reset'] = str(int(reset_time.timestamp()))
                if retry_after > 0:
                    response.headers['Retry-After'] = str(retry_after)
                
                return response
            
            # Record the usage
            limiter.increment_usage()
            
            # Store rate limit info for setting headers in after_request
            g.rate_limit_info = {
                'limit': limiter.limits['calls'],
                'remaining': remaining - 1
            }
            
            # Continue with the original function
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_limiter_type_for_path(path):
    """
    Determine the limiter type based on the request path.
    
    Args:
        path: The request path
        
    Returns:
        str: The limiter type or None if not a public endpoint
    """
    path = path.lower()
    

    auth_paths = [
        '/test/login',
        '/test/user',  
        '/oauth/login',
        '/oauth/auth',
        '/oauth/verify-google-token',


    ]
    
    password_reset_paths = [
        '/password-reset/request-reset',
        '/password-reset/verify-token',
        '/password-reset/reset-password'
    ]
    
    contact_paths = [
        '/contact-form/submit'
    ]
    

    for auth_path in auth_paths:
        if path.startswith(auth_path):
            return 'auth'
    
    for reset_path in password_reset_paths:
        if path.startswith(reset_path):
            return 'password_reset'
    
    for contact_path in contact_paths:
        if path.startswith(contact_path):
            return 'contact'
    
    # Protected paths that should NOT be rate limited
    protected_paths = [
        '/cracked/',       # Admin routes
        '/api/socket.io',  # WebSocket connections
        '/test/achievements', # Protected
        '/test/shop', # Protected
        '/subscription/', # Protected
        '/analogy/',       # Already rate-limited 
        '/scenario/',      # Already rate-limited 
        '/grc/',           # Already rate-limited 
        '/payload/'        # Already rate-limited 
        '/support/'
        '/subscription/'
    ]
    
    for protected_path in protected_paths:
        if path.startswith(protected_path):
            return None  # Skip rate limiting for these
    

    general_paths = [
        '/test/public-leaderboard',
        '/newsletter/',
    ]
    
    for general_path in general_paths:
        if path.startswith(general_path):
            return 'general'
            
    # For other endpoints, we need to determine if they're public or not
    # For now, let's assume routes not matched above don't need rate limiting
    return None

def apply_global_rate_limiting():
    """
    Function to create a Flask before_request middleware that applies
    rate limiting to all public API endpoints.
    """
    def check_rate_limit():
        # Always skip for health checks, static files, and asset files
        basic_excluded_paths = [
            '/health',
            '/static',
            '/avatars',
            '/.well-known',
            '/favicon.ico'
        ]
        
        path = request.path
        
        # Skip non-API OPTIONS requests (CORS preflight)
        if request.method == 'OPTIONS':
            return
        
        # Skip rate limiting for basic excluded paths
        if any(path.startswith(excluded) for excluded in basic_excluded_paths):
            return
        
        # Determine the limiter type based on the path
        limiter_type = get_limiter_type_for_path(path)
        
        # If limiter_type is None, this is not a public endpoint that needs rate limiting
        if limiter_type is None:
            return
        
        # Create a rate limiter for this endpoint type
        limiter = GlobalRateLimiter(limiter_type)
        
        # Check if rate limited
        is_limited, remaining, reset_time, retry_after = limiter.is_rate_limited()
        
        # If limited, return 429 Too Many Requests
        if is_limited:
            reset_msg = ""
            if reset_time:
                # Calculate seconds until reset
                seconds_to_reset = max(1, int((reset_time - datetime.utcnow()).total_seconds()))
                minutes_to_reset = max(1, seconds_to_reset // 60)
                reset_msg = f" Try again in {minutes_to_reset} minutes."
            
            response = jsonify({
                "error": f"Rate limit exceeded for {limiter_type} endpoint.{reset_msg}",
                "remaining": remaining,
                "type": "rate_limit_error"
            })
            response.status_code = 429
            
            # Set headers for rate limit info
            response.headers['X-RateLimit-Limit'] = str(limiter.limits['calls'])
            response.headers['X-RateLimit-Remaining'] = str(remaining)
            if reset_time:
                response.headers['X-RateLimit-Reset'] = str(int(reset_time.timestamp()))
            if retry_after > 0:
                response.headers['Retry-After'] = str(retry_after)
            
            # Log rate limit events
            logger.warning(f"Rate limit exceeded: {limiter_type} endpoint, path={path}, client={limiter._get_client_identifier()}")
            
            return response
        
        # Record the usage
        limiter.increment_usage()
        
        # Store rate limit info for setting headers in after_request
        g.rate_limit_info = {
            'limit': limiter.limits['calls'],
            'remaining': remaining - 1
        }
            
    return check_rate_limit

def setup_rate_limit_headers(response):
    """
    Function to create a Flask after_request middleware that adds
    rate limit headers to responses.
    """
    if hasattr(g, 'rate_limit_info'):
        response.headers['X-RateLimit-Limit'] = str(g.rate_limit_info['limit'])
        response.headers['X-RateLimit-Remaining'] = str(g.rate_limit_info['remaining'])
    
    return response
