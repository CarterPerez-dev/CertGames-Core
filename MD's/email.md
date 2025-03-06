# First make a utils dirsctoyr and put this in it

```python
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask import current_app
import os
from dotenv import load_dotenv

load_dotenv()

class EmailSender:
    """
    A utility class for sending emails through SendGrid with different sender addresses
    and templates.
    """
    
    def __init__(self):
        self.api_key = os.getenv('SENDGRID_API_KEY')
        # Default sender addresses
        self.default_addresses = {
            'password_reset': os.getenv('SENDGRID_PASSWORD_RESET_EMAIL', 'passwordreset@yourdomain.com'),
            'newsletter': os.getenv('SENDGRID_NEWSLETTER_EMAIL', 'newsletter@yourdomain.com'),
            'support': os.getenv('SENDGRID_SUPPORT_EMAIL', 'support@yourdomain.com'),
            # Add more as needed
        }
        # Default frontend URL for links in emails
        self.frontend_url = os.getenv('FRONTEND_URL', 'https://yourdomain.com')
    
    def send_email(self, to_email, subject, html_content, email_type='password_reset', from_email=None):
        """
        Send an email using SendGrid.
        
        Args:
            to_email (str): Recipient email address
            subject (str): Email subject
            html_content (str): HTML content of the email
            email_type (str): Type of email (password_reset, newsletter, etc.)
            from_email (str): Optional override for the sender email
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        # Determine the sender email
        sender = from_email or self.default_addresses.get(email_type)
        if not sender:
            sender = self.default_addresses.get('password_reset')  # Fallback
        
        # Create the email message
        message = Mail(
            from_email=sender,
            to_emails=to_email,
            subject=subject,
            html_content=html_content
        )
        
        try:
            sg = SendGridAPIClient(self.api_key)
            response = sg.send(message)
            success = response.status_code >= 200 and response.status_code < 300
            
            if success:
                current_app.logger.info(f"Email sent to {to_email} (type: {email_type})")
            else:
                current_app.logger.error(f"Failed to send email: {response.status_code}")
            
            return success
        except Exception as e:
            current_app.logger.error(f"Error sending email: {str(e)}")
            return False
    
    def send_password_reset_email(self, to_email, reset_token):
        """
        Send a password reset email with a reset link.
        
        Args:
            to_email (str): Recipient email address
            reset_token (str): Password reset token
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        reset_link = f"{self.frontend_url}/reset-password/{reset_token}"
        
        subject = 'Password Reset Request'
        html_content = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
            <h2 style="color: #333;">Password Reset Request</h2>
            <p>You recently requested to reset your password. Click the button below to reset it:</p>
            <p style="text-align: center;">
                <a href="{reset_link}" style="display: inline-block; padding: 10px 20px; background-color: #4a90e2; color: white; text-decoration: none; border-radius: 4px; font-weight: bold;">Reset Your Password</a>
            </p>
            <p>If you didn't request a password reset, you can safely ignore this email.</p>
            <p>This link will expire in 24 hours.</p>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
            <p style="font-size: 12px; color: #999;">This is an automated email. Please do not reply to this message.</p>
        </div>
        '''
        
        return self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            email_type='password_reset'
        )
    
    def send_newsletter(self, to_email, subject, content, preview_text=None):
        """
        Send a newsletter email.
        
        Args:
            to_email (str): Recipient email address or list of addresses
            subject (str): Newsletter subject
            content (str): Newsletter HTML content
            preview_text (str): Optional preview text for email clients
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        # Create a basic template if detailed HTML isn't provided
        preview = preview_text or subject
        
        html_content = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <!-- Preview text -->
            <div style="display:none;font-size:1px;color:#333333;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
                {preview}
            </div>
            
            <!-- Header -->
            <div style="background-color: #4a90e2; padding: 20px; text-align: center; color: white; border-radius: 5px 5px 0 0;">
                <h1 style="margin: 0;">{subject}</h1>
            </div>
            
            <!-- Content -->
            <div style="padding: 20px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 5px 5px;">
                {content}
                
                <div style="margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 20px; text-align: center; color: #666;">
                    <p>To unsubscribe from these emails, <a href="{self.frontend_url}/unsubscribe" style="color: #4a90e2;">click here</a>.</p>
                </div>
            </div>
        </div>
        '''
        
        return self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            email_type='newsletter'
        )

# Create a singleton instance for easy import
email_sender = EmailSender()
```
----
# Then fix the password_reset.py with this
```python
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
```
# replace newsletter models with 
```python
from datetime import datetime
from bson.objectid import ObjectId
import time
from flask import g
from utils.email_sender import email_sender
from mongodb.database import db

# Newsletter collections
newsletter_collection = db.newsletters
subscribers_collection = db.subscribers

def save_newsletter(title, content, preview_text=None, scheduled_date=None, status="draft", author_id=None):
    """
    Create or update a newsletter
    """
    now = datetime.utcnow()
    newsletter_data = {
        "title": title,
        "content": content,
        "preview_text": preview_text,
        "created_at": now,
        "updated_at": now,
        "scheduled_date": scheduled_date,
        "status": status,  # draft, scheduled, sent
        "author_id": author_id
    }
    
    start_db = time.time()
    result = newsletter_collection.insert_one(newsletter_data)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return str(result.inserted_id)

def get_newsletter(newsletter_id):
    """
    Get a newsletter by ID
    """
    try:
        oid = ObjectId(newsletter_id)
    except:
        return None
    
    start_db = time.time()
    newsletter = newsletter_collection.find_one({"_id": oid})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return newsletter

def add_subscriber(email, name=None, source="website"):
    """
    Add a new newsletter subscriber
    """
    # Check if already subscribed
    start_db = time.time()
    existing = subscribers_collection.find_one({"email": email})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    if existing:
        # Already subscribed
        return False, "Email already subscribed"
    
    subscriber_data = {
        "email": email,
        "name": name,
        "subscribed_at": datetime.utcnow(),
        "source": source,
        "active": True
    }
    
    start_db = time.time()
    result = subscribers_collection.insert_one(subscriber_data)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return True, "Successfully subscribed"

def get_all_active_subscribers():
    """
    Get all active newsletter subscribers
    """
    start_db = time.time()
    subscribers = list(subscribers_collection.find({"active": True}))
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return subscribers

def send_newsletter_to_all(newsletter_id):
    """
    Send a newsletter to all active subscribers
    """
    newsletter = get_newsletter(newsletter_id)
    if not newsletter:
        return False, "Newsletter not found"
    
    subscribers = get_all_active_subscribers()
    if not subscribers:
        return False, "No active subscribers found"
    
    success_count = 0
    fail_count = 0
    
    for subscriber in subscribers:
        email = subscriber.get("email")
        if not email:
            continue
        
        # Send the newsletter
        success = email_sender.send_newsletter(
            to_email=email,
            subject=newsletter["title"],
            content=newsletter["content"],
            preview_text=newsletter.get("preview_text")
        )
        
        if success:
            success_count += 1
        else:
            fail_count += 1
    
    # Update newsletter status to sent
    start_db = time.time()
    newsletter_collection.update_one(
        {"_id": newsletter["_id"]},
        {"$set": {
            "status": "sent",
            "sent_at": datetime.utcnow(),
            "sent_count": success_count,
            "fail_count": fail_count
        }}
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return True, f"Newsletter sent to {success_count} subscribers ({fail_count} failed)"
```
---
# update .env file
```bash
# SendGrid Configuration
SENDGRID_API_KEY=your_sendgrid_api_key
SENDGRID_PASSWORD_RESET_EMAIL=passwordreset@yourdomain.com
SENDGRID_NEWSLETTER_EMAIL=newsletter@yourdomain.com
SENDGRID_SUPPORT_EMAIL=support@yourdomain.com
FRONTEND_URL=https://yourdomain.com
```

