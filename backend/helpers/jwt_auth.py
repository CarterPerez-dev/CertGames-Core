# backend/helpers/jwt_auth.py
import os
from datetime import datetime, timedelta, timezone
from flask import current_app, request, jsonify, g
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    get_jwt_identity, get_jwt, verify_jwt_in_request
)
from functools import wraps
from bson.objectid import ObjectId
from mongodb.database import db, mainusers_collection


# Initialize JWT Manager (to be attached to app in app.py)
jwt = JWTManager()

# Settings from environment variables
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 60 * 60 * 24))
JWT_REFRESH_TOKEN_EXPIRES = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', 60 * 60 * 24 * 30))

def init_jwt(app):
    """Initialize JWT settings for the app"""
    app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=JWT_ACCESS_TOKEN_EXPIRES)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(seconds=JWT_REFRESH_TOKEN_EXPIRES)
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
    
    jwt.init_app(app)
    
    # Register JWT callbacks
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        token = db.token_blocklist.find_one({"jti": jti})
        return token is not None
    
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        """Load user from database when JWT is verified"""
        identity = jwt_data["sub"]
        try:
            user = mainusers_collection.find_one({"_id": ObjectId(identity)})
            if user:
                return user
        except Exception as e:
            current_app.logger.error(f"Error looking up user: {str(e)}")
        return None
    
    # Handle JWT errors
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'status': 401,
            'error': 'Token has expired',
            'message': 'The token has expired. Please log in again.'
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'status': 401,
            'error': 'Invalid token',
            'message': 'Signature verification failed.'
        }), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            'status': 401,
            'error': 'Authorization required',
            'message': 'Missing JWT token.'
        }), 401

def generate_tokens(user_id, additional_claims=None):
    """
    Generate access and refresh tokens for a user
    
    Args:
        user_id: User's ID string
        additional_claims: Dictionary of additional claims to include in tokens
        
    Returns:
        Dictionary with access_token and refresh_token
    """
    # Create base claims
    claims = {}
    
    if additional_claims:
        claims.update(additional_claims)
    
    # Generate tokens
    access_token = create_access_token(
        identity=user_id,
        additional_claims=claims
    )
    
    refresh_token = create_refresh_token(
        identity=user_id,
        additional_claims=claims
    )
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'expires_in': JWT_ACCESS_TOKEN_EXPIRES
    }

def revoke_token(jti):
    """Add a JWT ID to the blocklist"""
    now = datetime.now(timezone.utc)
    db.token_blocklist.insert_one({
        "jti": jti,
        "created_at": now
    })

def jwt_optional_wrapper(fn):
    """
    Custom wrapper that extracts user ID from JWT if available,
    but still allows requests without a valid JWT.
    This is perfect for supporting both JWT and your existing auth system.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
 
            verify_jwt_in_request(optional=True)

            identity = get_jwt_identity()
            if identity:
                # If we have a valid JWT, store user ID in g
                g.user_id = identity
        except Exception as e:
            # If JWT verification fails, check for X-User-Id header
            # Maintains backward compatibility iOS app
            user_id = request.headers.get('X-User-Id')
            if user_id:
                g.user_id = user_id
        
        # Either way, continue to the route
        return fn(*args, **kwargs)
    
    return wrapper

def jwt_required_wrapper(fn):
    """
    Custom wrapper that requires a valid JWT *or* a valid X-User-Id header.
    This ensures compatibility with both new JWT auth and your existing auth.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Try to get JWT identity
        jwt_valid = False
        user_id = None
        
        try:
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
            if user_id:
                jwt_valid = True
                g.user_id = user_id
        except Exception:
            pass
        
        # If JWT is not valid, check for X-User-Id header
        if not jwt_valid:
            header_user_id = request.headers.get('X-User-Id')
            if header_user_id:
                # Verify user exists
                try:
                    user = mainusers_collection.find_one({"_id": ObjectId(header_user_id)})
                    if user:
                        g.user_id = header_user_id
                        return fn(*args, **kwargs)
                except Exception:
                    pass
                
                # If we're here, the X-User-Id was invalid
                return jsonify({
                    'status': 401,
                    'error': 'Unauthorized',
                    'message': 'Invalid user ID'
                }), 401
            else:
                # No JWT and no X-User-Id
                return jsonify({
                    'status': 401,
                    'error': 'Authentication required',
                    'message': 'Please log in to access this resource'
                }), 401
        
        # If we're here, JWT was valid
        return fn(*args, **kwargs)
    
    return wrapper
