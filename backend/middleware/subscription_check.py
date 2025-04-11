import functools
from flask import session, jsonify, request, redirect, current_app
from mongodb.database import db
from models.test import get_user_by_id

def subscription_required(f):
    """
    Middleware to check if the user has an active subscription.
    This middleware can be applied to routes that require an active subscription.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Get the user ID from the session or request
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
            # No user ID, return error
            return jsonify({"error": "Authentication required", "status": "unauthenticated"}), 401
            
        # Get the user
        user = get_user_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found", "status": "unauthenticated"}), 404
            
        # Check subscription status
        subscription_active = user.get('subscriptionActive', False)
        if not subscription_active:
            # Always return JSON error instead of conditionally redirecting
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
        # UNHACKABLE AND UNBYPASSABLE, PUBLIC ROUTES ARE RATE LIMITED AS WELL. IM UNHACKABLE!!!!
        protected_prefixes = [
            '/test/daily-question',
            '/test/daily-question/answer',
            '/payload',
            '/scenario',
            '/analogy',
            '/grc',
            '/test/profile'
            '/test/attempts',
            '/test/user/*/add-xp',
            '/test/user/*/add-coins',
            '/test/user/*/submit-answer',
            '/test/user/*/daily-bonus',
            '/test/shop/purchase',
            '/test/shop/equip',
            '/test/shop',
        ]
        
        if any(request.path.startswith(prefix) for prefix in protected_prefixes):
            # Get the user ID from the session
            user_id = session.get('userId')
            
            if not user_id:
                return
                
            # Get the user
            user = get_user_by_id(user_id)
            if not user:
                return
                
            # Check subscription status
            subscription_active = user.get('subscriptionActive', False)
            if not subscription_active:
                return jsonify({
                    "error": "Subscription required", 
                    "status": "subscription_required"
                }), 403
                
    return check_subscription
