# routes/oauth_routes.py
from flask import Blueprint, request, redirect, session, jsonify, current_app, url_for
from bson.objectid import ObjectId
import os
import time
from datetime import datetime
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
)

# Configure Apple OAuth
apple = oauth.register(
    name='apple',
    client_id=os.getenv('APPLE_CLIENT_ID'),
    client_secret=os.getenv('APPLE_CLIENT_SECRET'),
    authorize_url='https://appleid.apple.com/auth/authorize',
    access_token_url='https://appleid.apple.com/auth/token',
    api_base_url='https://appleid.apple.com/',
    client_kwargs={
        'scope': 'name email',
        'response_mode': 'form_post',
        'response_type': 'code id_token'
    },
)

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
    redirect_uri = url_for('oauth.google_auth', _external=True)
    return google.authorize_redirect(redirect_uri)

@oauth_bp.route('/auth/google')
def google_auth():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    
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
    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
    return redirect(f"{frontend_url}/oauth/success?provider=google&userId={user_id}")

# Apple OAuth routes
@oauth_bp.route('/login/apple')
def apple_login():
    redirect_uri = url_for('oauth.apple_auth', _external=True)
    return apple.authorize_redirect(redirect_uri)

@oauth_bp.route('/auth/apple', methods=['GET', 'POST'])
def apple_auth():
    if request.method == 'GET':
        return redirect(url_for('oauth.apple_login'))
    
    # Handle POST from Apple
    token = apple.authorize_access_token()
    user_info = apple.parse_id_token(token)
    
    email = user_info.get('email')
    name = user_info.get('name', {})
    full_name = f"{name.get('firstName', '')} {name.get('lastName', '')}".strip()
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
    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
    return redirect(f"{frontend_url}/oauth/success?provider=apple&userId={user_id}")
