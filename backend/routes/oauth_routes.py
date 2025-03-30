# routes/oauth_routes.py
from flask import Blueprint, request, redirect, session, jsonify, current_app, url_for
from bson.objectid import ObjectId
import traceback
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
        
        # Return user_id and is_new_user flag
        return str(user['_id']), False
    
    # Create a new user
    # Generate temporary username from email or name (will be changed by user)
    base_name = name.split()[0].lower() if name else email.split('@')[0]
    temp_username = generate_unique_username(base_name)
    
    # Prepare user data
    user_data = {
        'username': temp_username,  # Temporary username
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
        },
        'needs_username': True  # Flag indicating this user needs to set a username
    }
    
    # Insert the new user
    user_id = create_user(user_data)
    
    # Return user_id and is_new_user flag
    return str(user_id), True

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
        
        # Process OAuth user and get user_id and is_new_user flag
        user_id, is_new_user = process_oauth_user(email, name, 'google', google_id)
        
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
        
        # Redirect based on whether this is a new user or existing user
        frontend_url = os.getenv('FRONTEND_URL', 'https://certgames.com')
        
        if is_new_user:
            # New user needs to set a username
            return redirect(f"{frontend_url}/create-username?provider=google&userId={user_id}")
        else:
            # Existing user can go directly to profile or OAuth success page
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
        
        # Process OAuth user and get user_id and is_new_user flag
        user_id, is_new_user = process_oauth_user(email, full_name, 'apple', apple_id)
        
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
        
        # Redirect based on whether this is a new user or existing user
        frontend_url = os.getenv('FRONTEND_URL', 'https://certgames.com')
        
        if is_new_user:
            # New user needs to set a username
            return redirect(f"{frontend_url}/create-username?provider=apple&userId={user_id}")
        else:
            # Existing user can go directly to profile or OAuth success page
            return redirect(f"{frontend_url}/oauth/success?provider=apple&userId={user_id}")
    
    except Exception as e:
        current_app.logger.error(f"Error in Apple auth: {str(e)}")




# Add these routes to your oauth_routes.py file

# In oauth_routes.py - modify the google_login_mobile function
@oauth_bp.route('/login/google/mobile')
def google_login_mobile():
    # Get the state parameter from the request instead of generating a new one
    state = request.args.get('state')
    # If no state is provided, generate one (fallback)
    if not state:
        state = secrets.token_urlsafe(16)
    
    # Store it in session
    session['oauth_state'] = state
    
    # Use the external URL with /api prefix for your reverse proxy
    base_url = os.getenv('EXTERNAL_URL', 'https://certgames.com')
    redirect_uri = request.args.get('redirect_uri')
    platform = request.args.get('platform', 'unknown')
    
    if not redirect_uri:
        return jsonify({"error": "redirect_uri is required"}), 400
    
    # Use iOS client ID when platform is iOS
    if platform.lower() == 'ios':
        client_id = os.getenv('GOOGLE_IOS_CLIENT_ID')
    else:
        client_id = google.client_id  # Fall back to web client ID
    
    # Log the request for debugging
    current_app.logger.info(f"Mobile OAuth request with client state: {state}")
    
    # Manual authorize redirect with state parameter
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': 'openid email profile',
        'state': state,  # Use the client's state
        'response_type': 'code'
    }
    
    auth_url = google.authorize_url
    separator = '?' if '?' not in auth_url else '&'
    
    # Build the query string
    query = '&'.join([f"{key}={value}" for key, value in params.items()])
    
    # Full authorization URL
    full_url = f"{auth_url}{separator}{query}"
    current_app.logger.info(f"Redirecting to Google auth URL with client state: {state}")
    
    return redirect(full_url)
    
    
# Add a modified version of the Google auth endpoint for mobile
@oauth_bp.route('/auth/google/mobile')
def google_auth_mobile():
    try:
        # Check state parameter to prevent CSRF
        expected_state = session.pop('oauth_state', None)
        received_state = request.args.get('state')
        
        # Get the redirect URI that was passed in the initial request
        redirect_uri = request.args.get('redirect_uri')
        if not redirect_uri:
            return jsonify({"error": "Missing redirect_uri"}), 400
        
        # Log detailed info for debugging
        current_app.logger.info(f"Auth mobile callback received: state={received_state}, redirect_uri={redirect_uri}")
        
        if not expected_state or expected_state != received_state:
            current_app.logger.error(f"Mobile OAuth state mismatch: expected={expected_state}, received={received_state}")
            return redirect(f"{redirect_uri}?error=invalid_state")
        
        # Exchange code for token
        code = request.args.get('code')
        if not code:
            current_app.logger.error("No authorization code received")
            return redirect(f"{redirect_uri}?error=no_code")
        
        current_app.logger.info(f"Exchanging code for token with redirect_uri: {redirect_uri}")
        
        try:
            # Add better error handling for token exchange
            token_data = google.fetch_access_token(code=code, redirect_uri=redirect_uri)
            current_app.logger.info("Token exchange successful")
        except Exception as token_error:
            current_app.logger.error(f"Token exchange failed: {str(token_error)}")
            return redirect(f"{redirect_uri}?error=token_exchange_failed")
            
        if not token_data or 'access_token' not in token_data:
            return redirect(f"{redirect_uri}?error=token_exchange_failed")
        
        # Get user info with better error handling
        try:
            userinfo_response = requests.get(
                'https://www.googleapis.com/oauth2/v1/userinfo',
                headers={'Authorization': f"Bearer {token_data['access_token']}"}
            )
            
            if not userinfo_response.ok:
                current_app.logger.error(f"Failed to get user info: {userinfo_response.status_code}")
                return redirect(f"{redirect_uri}?error=failed_to_get_user_info")
                
            user_info = userinfo_response.json()
        except Exception as userinfo_error:
            current_app.logger.error(f"Error fetching user info: {str(userinfo_error)}")
            return redirect(f"{redirect_uri}?error=user_info_error")
        
        email = user_info.get('email')
        name = user_info.get('name', '')
        google_id = user_info.get('id')
        
        if not email:
            return redirect(f"{redirect_uri}?error=email_required")
        
        # Process OAuth user and get user_id and is_new_user flag
        try:
            user_id, is_new_user = process_oauth_user(email, name, 'google', google_id)
            current_app.logger.info(f"Processed OAuth user: user_id={user_id}, is_new_user={is_new_user}")
        except Exception as process_error:
            current_app.logger.error(f"Error processing OAuth user: {str(process_error)}")
            return redirect(f"{redirect_uri}?error=user_processing_error")
        
        # Store in session
        session['userId'] = user_id
        
        # Log the login
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": ObjectId(user_id),
            "ip": request.remote_addr or "unknown",
            "success": True,
            "provider": "google",
            "platform": "mobile"
        })
        
        # Check if the user needs to set a username
        user = get_user_by_id(user_id)
        needs_username = user.get('needs_username', False)
        
        # Check for subscription status
        has_subscription = user.get('subscriptionActive', False)
        
        # Redirect back to app with user data
        redirect_params = {
            'userId': user_id,
            'provider': 'google',
            'needsUsername': 'true' if needs_username else 'false',
            'isNewUser': 'true' if is_new_user else 'false',
            'hasSubscription': 'true' if has_subscription else 'false',
            'state': received_state  # Include state for verification on client side
        }
        
        # Build redirect URL with params - FIXED logic for URI handling
        if '?' in redirect_uri:
            separator = '&'
        else:
            # For custom URI schemes like certgamesapp:// or Google schemes
            separator = '?'
            
        param_string = '&'.join([f"{key}={value}" for key, value in redirect_params.items()])
        final_redirect = f"{redirect_uri}{separator}{param_string}"
        
        current_app.logger.info(f"Final redirect URL: {final_redirect}")
        return redirect(final_redirect)
        
    except Exception as e:
        current_app.logger.error(f"Error in Google mobile auth: {str(e)}")
        current_app.logger.error(f"Error traceback: {traceback.format_exc()}")
        # Make sure we have redirect_uri defined before using it in the exception handler
        try:
            if redirect_uri:
                return redirect(f"{redirect_uri}?error={str(e)}")
            else:
                return jsonify({"error": f"Authentication error: {str(e)}"}), 500
        except:
            return jsonify({"error": f"Authentication error: {str(e)}"}), 500
            
# Add a route to handle Apple authentication from mobile
@oauth_bp.route('/login/apple/mobile', methods=['POST'])
def apple_auth_mobile():
    try:
        data = request.json
        identity_token = data.get('identityToken')
        full_name = data.get('fullName')
        email = data.get('email')
        platform = data.get('platform', 'ios')
        
        if not identity_token:
            return jsonify({"error": "identityToken is required"}), 400
        
        # Validate the token
        user_info = decode_apple_id_token(identity_token)
        if not user_info:
            return jsonify({"error": "Invalid Apple identity token"}), 400
        
        # Use email from token if not provided directly
        if not email and 'email' in user_info:
            email = user_info.get('email')
            
        if not email:
            return jsonify({"error": "Email is required"}), 400
            
        # Get name from parameters or construct from components
        name = ""
        if full_name:
            if isinstance(full_name, dict):
                first_name = full_name.get('givenName', '')
                last_name = full_name.get('familyName', '')
                name = f"{first_name} {last_name}".strip()
            else:
                name = full_name
        
        apple_id = user_info.get('sub')  # Apple's unique user ID
        
        # Process OAuth user
        user_id, is_new_user = process_oauth_user(email, name, 'apple', apple_id)
        
        # Get user info
        user = get_user_by_id(user_id)
        needs_username = user.get('needs_username', False)
        has_subscription = user.get('subscriptionActive', False)
        
        # Log the login
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": ObjectId(user_id),
            "ip": request.remote_addr or "unknown",
            "success": True,
            "provider": "apple",
            "platform": platform
        })
        
        return jsonify({
            "success": True,
            "userId": user_id,
            "needsUsername": needs_username,
            "isNewUser": is_new_user,
            "hasSubscription": has_subscription
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in Apple mobile auth: {str(e)}")
        return jsonify({"error": str(e)}), 500
        return jsonify({"error": f"Authentication error: {str(e)}"}), 500




@oauth_bp.route('/exchange-code', methods=['POST'])
def exchange_oauth_code():
    """
    Exchange an OAuth authorization code for user data
    This endpoint is used by the mobile app to complete the OAuth flow
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        code = data.get('code')
        redirect_uri = data.get('redirect_uri')
        state = data.get('state')
        platform = data.get('platform', 'unknown')
        
        if not code or not redirect_uri:
            return jsonify({"error": "Missing required parameters"}), 400
            
        current_app.logger.info(f"Exchanging code for user data: code={code[:10]}..., redirect_uri={redirect_uri}")
        
        # For Google OAuth
        try:
            # Exchange code for token
            token_data = google.fetch_access_token(code=code, redirect_uri=redirect_uri)
            
            if not token_data or 'access_token' not in token_data:
                return jsonify({"error": "Failed to exchange code for token"}), 400
                
            # Get user info
            userinfo_response = requests.get(
                'https://www.googleapis.com/oauth2/v1/userinfo',
                headers={'Authorization': f"Bearer {token_data['access_token']}"}
            )
            
            if not userinfo_response.ok:
                return jsonify({"error": f"Failed to get user info: {userinfo_response.status_code}"}), 400
                
            user_info = userinfo_response.json()
            
            email = user_info.get('email')
            name = user_info.get('name', '')
            google_id = user_info.get('id')
            
            if not email:
                return jsonify({"error": "Email not provided by Google"}), 400
            
            # Process OAuth user
            user_id, is_new_user = process_oauth_user(email, name, 'google', google_id)
            
            # Store in session
            session['userId'] = user_id
            
            # Get user details
            user = get_user_by_id(user_id)
            needs_username = user.get('needs_username', False)
            has_subscription = user.get('subscriptionActive', False)
            
            # Log the login
            db.auditLogs.insert_one({
                "timestamp": datetime.utcnow(),
                "userId": ObjectId(user_id),
                "ip": request.remote_addr or "unknown",
                "success": True,
                "provider": "google",
                "platform": platform
            })
            
            # Return user data
            return jsonify({
                "userId": user_id,
                "isNewUser": is_new_user,
                "needsUsername": needs_username,
                "hasSubscription": has_subscription
            })
            
        except Exception as e:
            current_app.logger.error(f"Error exchanging code: {str(e)}")
            current_app.logger.error(traceback.format_exc())
            return jsonify({"error": f"Code exchange error: {str(e)}"}), 500
    
    except Exception as e:
        current_app.logger.error(f"General error in exchange-code: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500



@oauth_bp.route('/google-callback-mobile', methods=['POST'])
def google_callback_mobile():
    """Mobile Google OAuth callback that handles token exchange manually"""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        code = data.get('code')
        redirect_uri = data.get('redirect_uri')
        
        if not code or not redirect_uri:
            return jsonify({"error": "Missing required parameters"}), 400
            
        current_app.logger.info(f"Processing mobile callback with code")
        
        # IMPORTANT FIX: Always use iOS client ID for this mobile-specific endpoint
        client_id = os.getenv('GOOGLE_IOS_CLIENT_ID')
        current_app.logger.info(f"Using iOS client ID for token exchange: {client_id}")
        
        # Get credentials from environment
        client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        
        # First, exchange the code for a token using requests library
        token_url = 'https://oauth2.googleapis.com/token'
        payload = {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        
        current_app.logger.info(f"Token exchange payload client_id: {client_id}")
        token_response = requests.post(token_url, data=payload)
        
        if not token_response.ok:
            current_app.logger.error(f"Token exchange failed: {token_response.text}")
            return jsonify({"error": f"Token exchange failed: {token_response.text}"}), 400
            
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            return jsonify({"error": "No access token in response"}), 400
            
        # Then use the access token to get user info directly
        userinfo_url = 'https://www.googleapis.com/oauth2/v3/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}
        
        userinfo_response = requests.get(userinfo_url, headers=headers)
        
        if not userinfo_response.ok:
            current_app.logger.error(f"Failed to get user info: {userinfo_response.text}")
            return jsonify({"error": f"Failed to get user info: {userinfo_response.text}"}), 400
            
        userinfo = userinfo_response.json()
        
        # Extract user data
        email = userinfo.get('email')
        name = userinfo.get('name', '')
        google_id = userinfo.get('sub')  # Note: Google uses 'sub' for the user ID
        
        if not email:
            return jsonify({"error": "Email not provided by Google"}), 400
            
        # Process user
        current_app.logger.info(f"Processing user with email: {email}")
        user_id, is_new_user = process_oauth_user(email, name, 'google', google_id)
        
        # Get user details
        user = get_user_by_id(user_id)
        needs_username = user.get('needs_username', False)
        has_subscription = user.get('subscriptionActive', False)
        
        # Log success
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": ObjectId(user_id),
            "ip": request.remote_addr or "unknown",
            "success": True,
            "provider": "google",
            "platform": "mobile"
        })
        
        # Return user data
        return jsonify({
            "success": True,
            "userId": user_id,
            "isNewUser": is_new_user,
            "needsUsername": needs_username,
            "hasSubscription": has_subscription
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in mobile callback: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500



@oauth_bp.route('/verify-google-token', methods=['POST'])
def verify_google_token():
    """
    Verify a Google access token directly.
    This endpoint is used by the mobile app when using @react-native-google-signin/google-signin
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        token = data.get('token')
        user_data = data.get('userData', {})
        
        if not token:
            return jsonify({"error": "No token provided"}), 400
            
        # Log information for debugging
        current_app.logger.info(f"Verifying Google token for user email: {user_data.get('email')}")
        
        # Verify token with Google's userinfo endpoint
        response = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {token}'}
        )
        
        if not response.ok:
            current_app.logger.error(f"Token verification failed: {response.text}")
            return jsonify({"error": f"Invalid token: {response.text}"}), 400
            
        google_user_info = response.json()
        
        # Extract user info from Google's response
        email = google_user_info.get('email')
        name = google_user_info.get('name', '')
        google_id = google_user_info.get('sub')  # Google's unique user ID
        
        if not email:
            return jsonify({"error": "Email not provided by Google"}), 400
            
        # Process user to create or get existing user
        user_id, is_new_user = process_oauth_user(email, name, 'google', google_id)
        
        # Get user details
        user = get_user_by_id(user_id)
        needs_username = user.get('needs_username', False)
        has_subscription = user.get('subscriptionActive', False)
        
        # Log success
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": ObjectId(user_id),
            "ip": request.remote_addr or "unknown",
            "success": True,
            "provider": "google",
            "platform": data.get('platform', 'unknown')
        })
        
        # Return user data
        return jsonify({
            "success": True,
            "userId": user_id,
            "isNewUser": is_new_user,
            "needsUsername": needs_username,
            "hasSubscription": has_subscription
        })
        
    except Exception as e:
        current_app.logger.error(f"Error verifying Google token: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500
