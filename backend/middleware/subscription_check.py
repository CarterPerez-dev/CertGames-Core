from functools import wraps
from flask import session, jsonify, request, redirect, current_app
from mongodb.database import db
from models.test import get_user_by_id
from helpers.jwt_auth import jwt_required_wrapper, jwt_optional_wrapper
from flask_jwt_extended import get_jwt, get_jwt_identity

def subscription_required(f):
    """
    Middleware to check if the user has an active subscription.
    This middleware can be applied to routes that require an active subscription.
    """
    @jwt_optional_wrapper  # Use our custom wrapper that supports both JWT and X-User-Id
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get the user ID from JWT, g (set by wrapper), or request
        user_id = get_jwt_identity()
        
        if not user_id:
            # Check if set by wrapper from X-User-Id header
            user_id = getattr(g, 'user_id', None)
        
        if not user_id:
            # Check if it's in the request
            try:
                data = request.get_json(silent=True) or {}
                user_id = data.get('userId')
            except Exception:
                pass
                
        if not user_id:
            # Check query parameters
            user_id = request.args.get('userId')
            
        if not user_id:
            # No user ID, return error
            return jsonify({"error": "Authentication required", "status": "unauthenticated"}), 401
            
        # Check JWT claims first (fastest method)
        jwt_data = get_jwt()
        if jwt_data:
            subscription_active = jwt_data.get('subscriptionActive', False)
            if not subscription_active:
                return jsonify({
                    "error": "Subscription required", 
                    "status": "subscription_required"
                }), 403
            # If we have valid JWT claims showing active subscription, proceed directly
            return f(*args, **kwargs)
            
        # Otherwise, check database
        user = get_user_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found", "status": "unauthenticated"}), 404
            
        # Check subscription status
        subscription_active = user.get('subscriptionActive', False)
        if not subscription_active:
            return jsonify({
                "error": "Subscription required", 
                "status": "subscription_required"
            }), 403
                
        # User has an active subscription, proceed
        return f(*args, **kwargs)
        
    return decorated_function

def check_subscription_middleware():
    """
    Function to create a Flask before_request middleware
    that checks subscription status for certain routes
    """
    def check_subscription():
        # Routes that require a premium subscription
        premium_required_prefixes = [
            '/payload',  # XploitCraft
            '/scenario', # ScenarioSphere
            '/grc',      # GRC Wizard
            '/test/daily-question/answer',  # Answering daily questions
            '/cipher',
            '/threat-hunter'
        ]
        
        # Routes for limited access (free users with usage tracking)
        limited_access_prefixes = [
            '/test/attempts',  # Practice tests (limited to 100 questions)
            '/analogy',        # AnalogHub (fully accessible to free users)
        ]
        
        # Routes that should always be accessible
        public_prefixes = [
            '/test/user',
            '/test/login',
            '/test/register',
            '/test/public-leaderboard',
            '/password-reset',
            '/oauth',
            '/.well-known',
            '/test/token/refresh',  # Add token refresh endpoint
        ]
        
        # Check if current path requires premium
        if any(request.path.startswith(prefix) for prefix in premium_required_prefixes):
            # First try to get subscription info from JWT
            try:
                # Optional verification - doesn't error if no token
                verify_jwt_in_request(optional=True)
                jwt_data = get_jwt()
                
                # If we have JWT claims with subscription info, use that
                if jwt_data:
                    subscription_active = jwt_data.get('subscriptionActive', False)
                    subscription_type = jwt_data.get('subscriptionType', 'free')
                    
                    # Premium check using JWT claims
                    if not subscription_active or subscription_type == 'free':
                        return jsonify({
                            "error": "Premium subscription required", 
                            "status": "subscription_required",
                            "tier": "premium_required",
                            "feature": "premium_only"
                        }), 403
                    
                    # If subscription is active via JWT, allow access
                    if subscription_active:
                        return None
            except Exception:
                # JWT verification failed, continue with traditional checks
                pass
            
            # Traditional user ID check (fallback)
            user_id = session.get('userId')
            
            if not user_id:
                # Check if it's in the request
                try:
                    data = request.get_json(silent=True) or {}
                    user_id = data.get('userId')
                except Exception:
                    pass
                    
            if not user_id:
                # Check query parameters
                user_id = request.args.get('userId')
                
            if not user_id:
                # Check headers
                user_id = request.headers.get('X-User-Id')
                
            if not user_id:
                # No user ID, return error
                return jsonify({
                    "error": "Authentication required", 
                    "status": "unauthenticated",
                    "tier": "login_required"
                }), 401
                
            # Get the user
            user = get_user_by_id(user_id)
            if not user:
                return jsonify({
                    "error": "User not found", 
                    "status": "unauthenticated",
                    "tier": "login_required"
                }), 404
                
            # Check subscription status
            subscription_active = user.get('subscriptionActive', False)
            subscription_type = user.get('subscriptionType', 'free')
            if not subscription_active and subscription_type != 'free':
                return jsonify({
                    "error": "Premium subscription required", 
                    "status": "subscription_required",
                    "tier": "premium_required",
                    "feature": "premium_only"
                }), 403
    
    return check_subscription
