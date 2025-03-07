# routes/oauth_routes.py
from flask import Blueprint, request, redirect, session, jsonify, current_app, url_for
from bson.objectid import ObjectId
import os
import time
import jwt
import json
import secrets
import requests
from datetime import datetime, timedelta
from authlib.integrations.flask_client import OAuth
from models.test import create_user, get_user_by_id, update_user_fields
from mongodb.database import db, mainusers_collection

oauth_bp = Blueprint('oauth', __name__)

# Initialize OAuth
oauth = OAuth()

# Configure Google OAuth
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    # Skip the need for jwks_uri metadata by disabling JWT validation
    server_metadata_url=None
)

# Function to generate Apple client secret JWT
def generate_apple_client_secret():
    team_id = os.getenv('APPLE_TEAM_ID')
    client_id = os.getenv('APPLE_CLIENT_ID')
    key_id = os.getenv('APPLE_KEY_ID')
    
    # Get private key - check if it's content or path
    private_key_path_or_content = os.getenv('APPLE_PRIVATE_KEY')
    
    # If it looks like key content
    if private_key_path_or_content and private_key_path_or_content.startswith('-----BEGIN PRIVATE KEY-----'):
        private_key = private_key_path_or_content
    else:
        # It's a file path
        try:
            with open(private_key_path_or_content, 'r') as key_file:
                private_key = key_file.read()
        except FileNotFoundError:
            current_app.logger.error(f"Error: Apple private key file not found at {private_key_path_or_content}")
            current_app.logger.error(f"Current working directory: {os.getcwd()}")
            raise
    
    # JWT headers
    headers = {
        'kid': key_id
    }
    
    # JWT payload
    payload = {
        'iss': team_id,
        'iat': int(time.time()),
        'exp': int(time.time() + 86400 * 180),  # 180 days (Apple allows up to 6 months)
        'aud': 'https://appleid.apple.com',
        'sub': client_id
    }
    
    # Create and return the JWT token
    token = jwt.encode(
        payload,
        private_key,
        algorithm='ES256',
        headers=headers
    )
    
    # PyJWT >= 2.0.0 returns string instead of bytes
    if isinstance(token, bytes):
        return token.decode('utf-8')
    return token

# Configure Apple OAuth with dynamic client secret
apple = oauth.register(
    name='apple',
    client_id=os.getenv('APPLE_CLIENT_ID'),
    client_secret=generate_apple_client_secret,  # Pass the function, not the result
    authorize_url='https://appleid.apple.com/auth/authorize',
    access_token_url='https://appleid.apple.com/auth/token',
    api_base_url='https://appleid.apple.com/',
    jwks_uri='https://appleid.apple.com/auth/keys',  # Explicitly set JWKS URI
    client_kwargs={
        'scope': 'name email',
        'response_mode': 'form_post',
        'response_type': 'code id_token'
    },
)

def decode_apple_id_token(id_token):
    """
    Manually decode the id_token without validation for Apple Sign In
    """
    try:
        # Split the token into parts
        parts = id_token.split('.')
        if len(parts) != 3:
            return None
        
        # Decode the payload (middle part)
        payload = parts[1]
        # Add padding if needed
        padding = '=' * (4 - len(payload) % 4)
        payload = payload + padding
        
        # Convert from base64 to JSON
        import base64
        decoded = base64.b64decode(payload)
        user_info = json.loads(decoded)
        
        return user_info
    except Exception as e:
        current_app.logger.error(f"Error decoding Apple ID token: {str(e)}")
        return None

def generate_unique_username(base_name):
    """Generate a unique username based on email or name"""
    username = base_name
    count = 0
    
    # Keep checking until we find a unique username
    while mainusers_collection.find_one({'username': username}):
        count += 1
        username = f"{base_name}{count}"
    
    return username

def process_oauth_user(email, name, oauth_provider, oauth_id):
    """Create or retrieve a user from OAuth data"""
    # Check if user exists with this email
    user = mainusers_collection.find_one({'email': email})
    
    if user:
        # User exists, update their OAuth info if not already set
        oauth_field = f"{oauth_provider}_id"
        if not user.get(oauth_field):
            mainusers_collection.update_one(
                {'_id': user['_id']},
                {'$set': {
                    oauth_field: oauth_id,
                    'oauth_provider': oauth_provider
                }}
            )
        return str(user['_id'])
    
    # Create a new user
    # Generate username from email or name
    base_name = name.split()[0].lower() if name else email.split('@')[0]
    username = generate_unique_username(base_name)
    
    # Prepare user data
    user_data = {
        'username': username,
        'email': email,
        'oauth_provider': oauth_provider,
        f"{oauth_provider}_id": oauth_id,
        'coins': 0,
        'xp': 0,
        'level': 1,
        'achievements': [],
        'xpBoost': 1.0,
        'currentAvatar': None,
        'nameColor': None,
        'purchasedItems': [],
        'subscriptionActive': False,
        'achievement_counters': {
            'total_tests_completed': 0,
            'perfect_tests_count': 0,
            'perfect_tests_by_category': {},
            'highest_score_ever': 0.0,
            'lowest_score_ever': 100.0,
            'total_questions_answered': 0,
        }
    }
    
    # Insert the new user
    user_id = create_user(user_data)
    return str(user_id)

# Google OAuth routes
@oauth_bp.route('/login/google')
def google_login():
    # Generate and store a state parameter
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    
    # Use the external URL with /api prefix for your reverse proxy
    base_url = os.getenv('EXTERNAL_URL', 'https://certgames.com')
    redirect_uri = f"{base_url}/api/oauth/auth/google"
    
    # Manual authorize redirect with state parameter
    params = {
        'client_id': google.client_id,
        'redirect_uri': redirect_uri,
        'scope': 'openid email profile',
        'state': state,
        'response_type': 'code'
    }
    
    auth_url = google.authorize_url
    separator = '?' if '?' not in auth_url else '&'
    
    # Build the query string
    query = '&'.join([f"{key}={value}" for key, value in params.items()])
    
    # Full authorization URL
    full_url = f"{auth_url}{separator}{query}"
    
    return redirect(full_url)

@oauth_bp.route('/auth/google')
def google_auth():
    try:
        # Check state parameter to prevent CSRF
        expected_state = session.pop('oauth_state', None)
        received_state = request.args.get('state')
        
        if not expected_state or expected_state != received_state:
            current_app.logger.error(f"State mismatch: expected={expected_state}, received={received_state}")
            return jsonify({"error": "Invalid state parameter"}), 400
        
        # Use the external URL with /api prefix for your reverse proxy
        base_url = os.getenv('EXTERNAL_URL', 'https://certgames.com')
        redirect_uri = f"{base_url}/api/oauth/auth/google"
        
        # Manual token exchange
        code = request.args.get('code')
        if not code:
            return jsonify({"error": "No authorization code received"}), 400
        
        # Exchange code for token
        token_data = google.fetch_access_token(code=code, redirect_uri=redirect_uri)
        if not token_data or 'access_token' not in token_data:
            return jsonify({"error": "Failed to obtain access token"}), 400
        
        # SIMPLIFIED: Instead of using parse_id_token, just get user info directly
        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v1/userinfo',
            headers={'Authorization': f"Bearer {token_data['access_token']}"}
        )
        
        if not userinfo_response.ok:
            return jsonify({"error": "Failed to get user info from Google"}), 400
            
        user_info = userinfo_response.json()
        
        email = user_info.get('email')
        name = user_info.get('name', '')
        google_id = user_info.get('id')
        
        if not email:
            return jsonify({"error": "Email not provided by Google"}), 400
        
        user_id = process_oauth_user(email, name, 'google', google_id)
        
        # Store in session
        session['userId'] = user_id
        
        # Log the login
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": ObjectId(user_id),
            "ip": request.remote_addr or "unknown",
            "success": True,
            "provider": "google"
        })
        
        # Redirect to frontend with success token
        frontend_url = os.getenv('FRONTEND_URL', 'https://certgames.com')
        return redirect(f"{frontend_url}/oauth/success?provider=google&userId={user_id}")
        
    except Exception as e:
        current_app.logger.error(f"Error in Google auth: {str(e)}")
        return jsonify({"error": f"Authentication error: {str(e)}"}), 500

# Apple OAuth routes
@oauth_bp.route('/login/apple')
def apple_login():
    # Generate and store a state parameter
    state = secrets.token_urlsafe(16)
    session['apple_oauth_state'] = state
    
    # Use the external URL with /api prefix for your reverse proxy
    base_url = os.getenv('EXTERNAL_URL', 'https://certgames.com')
    redirect_uri = f"{base_url}/api/oauth/auth/apple"
    
    # Manual authorize redirect with state parameter
    params = {
        'client_id': apple.client_id,
        'redirect_uri': redirect_uri,
        'scope': 'name email',
        'state': state,
        'response_type': 'code id_token',
        'response_mode': 'form_post'
    }
    
    auth_url = apple.authorize_url
    separator = '?' if '?' not in auth_url else '&'
    
    # Build the query string
    query = '&'.join([f"{key}={value}" for key, value in params.items()])
    
    # Full authorization URL
    full_url = f"{auth_url}{separator}{query}"
    
    return redirect(full_url)

@oauth_bp.route('/auth/apple', methods=['GET', 'POST'])
def apple_auth():
    if request.method == 'GET':
        return redirect(url_for('oauth.apple_login'))
    
    try:
        # Check state parameter
        expected_state = session.pop('apple_oauth_state', None)
        received_state = request.form.get('state') or request.args.get('state')
        
        if not expected_state or expected_state != received_state:
            current_app.logger.error(f"Apple state mismatch: expected={expected_state}, received={received_state}")
            return jsonify({"error": "Invalid state parameter"}), 400
        
        # Use the external URL with /api prefix for your reverse proxy
        base_url = os.getenv('EXTERNAL_URL', 'https://certgames.com')
        redirect_uri = f"{base_url}/api/oauth/auth/apple"
        
        # Get the authorization code
        code = request.form.get('code') or request.args.get('code')
        if not code:
            return jsonify({"error": "No authorization code received from Apple"}), 400
        
        # Get the id_token directly from the form post (if available)
        id_token = request.form.get('id_token') or request.args.get('id_token')
        
        # If no id_token in the request, we'll need to exchange the code
        if not id_token:
            # Manual token exchange
            client_secret = generate_apple_client_secret()
            token_params = {
                'client_id': apple.client_id,
                'client_secret': client_secret,
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri
            }
            
            # Exchange code for token
            token_response = requests.post(
                'https://appleid.apple.com/auth/token',
                data=token_params
            )
            
            if not token_response.ok:
                return jsonify({"error": "Failed to obtain tokens from Apple"}), 400
                
            token_data = token_response.json()
            id_token = token_data.get('id_token')
            
            if not id_token:
                return jsonify({"error": "No ID token in Apple response"}), 400
        
        # Manually decode the ID token
        user_info = decode_apple_id_token(id_token)
        if not user_info:
            return jsonify({"error": "Failed to decode Apple ID token"}), 400
        
        email = user_info.get('email')
        # Apple doesn't always include name in the ID token
        name_data = user_info.get('name', {})
        if isinstance(name_data, dict):
            full_name = f"{name_data.get('firstName', '')} {name_data.get('lastName', '')}".strip()
        else:
            full_name = ""
        apple_id = user_info.get('sub')  # Apple's unique user ID
        
        if not email:
            return jsonify({"error": "Email not provided by Apple"}), 400
        
        user_id = process_oauth_user(email, full_name, 'apple', apple_id)
        
        # Store in session
        session['userId'] = user_id
        
        # Log the login
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": ObjectId(user_id),
            "ip": request.remote_addr or "unknown",
            "success": True,
            "provider": "apple"
        })
        
        # Redirect to frontend with success token
        frontend_url = os.getenv('FRONTEND_URL', 'https://certgames.com')
        return redirect(f"{frontend_url}/oauth/success?provider=apple&userId={user_id}")
    
    except Exception as e:
        current_app.logger.error(f"Error in Apple auth: {str(e)}")
        return jsonify({"error": f"Authentication error: {str(e)}"}), 500
