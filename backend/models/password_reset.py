from datetime import datetime, timedelta
from bson.objectid import ObjectId
import secrets
import string
import time
from flask import g, current_app
from mongodb.database import mainusers_collection, db
from utils.email_sender import email_sender
from dotenv import load_dotenv
import os

# Create a new collection for password reset tokens
password_resets_collection = db.passwordResets

load_dotenv()

def generate_reset_token(length=64):
    """Generate a secure random token for password reset."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def create_password_reset_token(user_id):
    """
    Create a password reset token for the given user_id.
    Returns the token string or None if user not found.
    """
    try:
        user_oid = ObjectId(user_id)
    except:
        return None
    
    # Get the user to verify they exist
    start_db = time.time()
    user = mainusers_collection.find_one({"_id": user_oid})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    if not user:
        return None
    
    # Generate a token and create an expiration date (24 hours from now)
    token = generate_reset_token()
    expires_at = datetime.utcnow() + timedelta(hours=24)
    
    # Store the token in the database, overwriting any existing token for this user
    start_db = time.time()
    password_resets_collection.update_one(
        {"userId": user_oid},
        {
            "$set": {
                "userId": user_oid,
                "token": token,
                "expiresAt": expires_at,
                "createdAt": datetime.utcnow(),
                "email": user.get("email"),
                "used": False
            }
        },
        upsert=True
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return token

def create_reset_token_by_email(email):
    """
    Find a user by email and create a password reset token.
    Returns a tuple of (user_id, token) or (None, None) if user not found.
    """
    if not email:
        return None, None
    
    start_db = time.time()
    user = mainusers_collection.find_one({"email": email})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    if not user:
        return None, None
    
    # Create a token for this user
    token = create_password_reset_token(str(user["_id"]))
    return str(user["_id"]), token

def verify_reset_token(token):
    """
    Verify if a password reset token is valid.
    Returns the user_id if valid, None otherwise.
    """
    if not token:
        return None
    
    start_db = time.time()
    reset_doc = password_resets_collection.find_one({
        "token": token,
        "expiresAt": {"$gt": datetime.utcnow()},
        "used": False
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    if not reset_doc:
        return None
    
    return str(reset_doc["userId"])

def mark_token_as_used(token):
    """
    Mark a token as used so it can't be used again.
    Returns True if successful, False if token not found.
    """
    start_db = time.time()
    result = password_resets_collection.update_one(
        {"token": token},
        {"$set": {"used": True}}
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return result.modified_count > 0

def reset_password_with_token(token, new_password):
    """
    Reset a user's password using a valid token.
    Returns True if successful, False otherwise.
    """
    # First verify the token is valid
    user_id = verify_reset_token(token)
    if not user_id:
        return False, "Invalid or expired token"
    
    try:
        user_oid = ObjectId(user_id)
    except:
        return False, "Invalid user ID"
    
    # Get the user to validate their existence
    start_db = time.time()
    user = mainusers_collection.find_one({"_id": user_oid})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    if not user:
        return False, "User not found"
    
    # Update the password
    start_db = time.time()
    mainusers_collection.update_one(
        {"_id": user_oid},
        {"$set": {"password": new_password}}
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    # Mark the token as used
    mark_token_as_used(token)
    
    return True, "Password updated successfully"

def send_password_reset_email(email, reset_token, frontend_url=None):
    """
    Send a password reset email using SendGrid.
    Returns True if email was sent, False otherwise.
    """
    if not email or not reset_token:
        return False
    
    # Use the email_sender utility to send the password reset email
    return email_sender.send_password_reset_email(email, reset_token)
