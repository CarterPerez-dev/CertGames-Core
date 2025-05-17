import time
import logging
from datetime import datetime, timedelta
from flask import request, session, jsonify, g
from functools import wraps
from mongodb.database import db

logger = logging.getLogger(__name__)

class RateLimiter:
    """
    Rate limiter class to manage API request rates for AI generators.
    Tracks usage in MongoDB and enforces limits per user per endpoint.
    """
    

    DEFAULT_LIMITS = {
        'analogy': {'calls': 25, 'period': 3600},  # 15 calls per hour
        'scenario': {'calls': 18, 'period': 3600},  # 10 calls per hour
        'grc': {'calls': 30, 'period': 3600},      # 20 calls per hour
        'portfolio': {'calls': 15, 'period': 3600}, # 15 calls per hour
        'fix-error': {'calls': 15, 'period': 3600}, # 15 calls per hour
    }
    
    def __init__(self, limiter_type=None):
        """
        Initialize the rate limiter with specific type limits.
        
        Args:
            limiter_type: The type of generator being rate limited 
                          ('analogy', 'scenario', 'grc')
        """
        self.limiter_type = limiter_type
        self.limits = self.DEFAULT_LIMITS.get(limiter_type, {'calls': 25, 'period': 3600})
    
    def is_rate_limited(self, user_id=None):
        """
        Check if the current user is rate limited for this endpoint.
        
        Args:
            user_id: Optional user ID to check. If None, tries to get from session.
            
        Returns:
            tuple: (is_limited, remaining_calls, reset_time)
        """
        # Get user ID from session if not provided
        if not user_id:
            user_id = session.get('userId')
            
        # If no user ID, use IP address as fallback
        if not user_id:
            user_id = f"ip_{request.remote_addr}"
        
        # Get current time
        now = datetime.utcnow()
        
        # Find user's usage records for this endpoint
        collection = db.rateLimits
        record = collection.find_one({
            "userId": user_id,
            "endpoint": self.limiter_type
        })
        
        # If no record exists, create one
        if not record:
            new_record = {
                "userId": user_id,
                "endpoint": self.limiter_type,
                "calls": [],
                "updatedAt": now
            }
            collection.insert_one(new_record)
            return False, self.limits['calls'], None
        
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
        
        # Check if user has exceeded the limit
        is_limited = used_calls >= self.limits['calls']
        
        return is_limited, remaining_calls, reset_time
    
    def increment_usage(self, user_id=None):
        """
        Record that the user has made another call to this endpoint.
        
        Args:
            user_id: Optional user ID. If None, tries to get from session.
        """
        # Get user ID from session if not provided
        if not user_id:
            user_id = session.get('userId')
            
        # If no user ID, use IP address as fallback
        if not user_id:
            user_id = f"ip_{request.remote_addr}"
        
        now = datetime.utcnow()
        
        # Add call timestamp to the user's record
        db.rateLimits.update_one(
            {"userId": user_id, "endpoint": self.limiter_type},
            {
                "$push": {"calls": now},
                "$set": {"updatedAt": now}
            },
            upsert=True
        )

def rate_limit(limiter_type):
    """
    Decorator to apply rate limiting to a route.
    
    Args:
        limiter_type: The type of generator being rate limited 
                     ('analogy', 'scenario', 'grc')
    
    Returns:
        Function decorator
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):

            limiter = RateLimiter(limiter_type)          

            is_limited, remaining, reset_time = limiter.is_rate_limited()
            
            if is_limited:
                reset_msg = ""
                if reset_time:

                    seconds_to_reset = (reset_time - datetime.utcnow()).total_seconds()
                    minutes_to_reset = max(1, int(seconds_to_reset / 60))
                    reset_msg = f" Try again in {minutes_to_reset} minutes."
                
                response = jsonify({
                    "error": f"Rate limit exceeded for {limiter_type} generation.{reset_msg}",
                    "remaining": remaining,
                    "type": "rate_limit_error"
                })
                response.status_code = 429
                return response
            

            limiter.increment_usage()           

            g.rate_limit_remaining = remaining - 1
            

            return f(*args, **kwargs)
        return decorated_function
    return decorator
