from datetime import datetime
import os
import re
import random
import string
import time
from bson.objectid import ObjectId
from flask import g, current_app
from utils.email_sender import email_sender
from mongodb.database import db

# Newsletter collections
newsletter_subscribers_collection = db.newsletterSubscribers
newsletter_campaigns_collection = db.newsletterCampaigns

def _generate_unsubscribe_token(length=32):
    """
    Generates a random token for unsubscribing.
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def subscribe_email(email: str):
    """
    Subscribe an email to the newsletter.
    Returns a dict {"success": bool, "message": str}
    """
    email = email.strip().lower()
    if not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return {"success": False, "message": "Invalid email format."}

    start_db = time.time()
    existing = newsletter_subscribers_collection.find_one({"email": email})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if existing:
        if existing.get("unsubscribed", False) is True:
            # Mark them re-subscribed
            start_db = time.time()
            newsletter_subscribers_collection.update_one(
                {"_id": existing["_id"]},
                {
                    "$set": {
                        "unsubscribed": False,
                        "resubscribedAt": datetime.utcnow()
                    },
                    # Ensure they have a token
                    "$setOnInsert": {
                        "unsubscribeToken": _generate_unsubscribe_token()
                    }
                },
                upsert=True
            )
            duration = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration
            return {"success": True, "message": "You have been re-subscribed."}
        else:
            return {"success": False, "message": "Already subscribed."}
    else:
        doc = {
            "email": email,
            "subscribedAt": datetime.utcnow(),
            "unsubscribed": False,
            "unsubscribeToken": _generate_unsubscribe_token()
        }
        start_db = time.time()
        newsletter_subscribers_collection.insert_one(doc)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        return {"success": True, "message": "Subscription successful."}

def unsubscribe_email(email: str):
    """
    Unsubscribe an email from the newsletter using the email address.
    Returns a dict {"success": bool, "message": str}
    """
    email = email.strip().lower()
    
    start_db = time.time()
    subscriber = newsletter_subscribers_collection.find_one({"email": email})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    if not subscriber:
        return {"success": False, "message": "Email not found in subscriber list."}

    if subscriber.get("unsubscribed", False) is True:
        return {"success": False, "message": "Already unsubscribed."}

    start_db = time.time()
    newsletter_subscribers_collection.update_one(
        {"_id": subscriber["_id"]},
        {"$set": {"unsubscribed": True, "unsubscribedAt": datetime.utcnow()}}
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return {"success": True, "message": "You have been unsubscribed."}

def unsubscribe_by_token(token: str):
    """
    Finds the subscriber by their token and unsubscribes them if possible.
    Returns a dict { success: bool, message: str }.
    """
    start_db = time.time()
    subscriber = newsletter_subscribers_collection.find_one({"unsubscribeToken": token})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    if not subscriber:
        return {"success": False, "message": "Invalid unsubscribe token."}
    
    if subscriber.get("unsubscribed", False):
        return {"success": False, "message": "You have already unsubscribed."}

    start_db = time.time()
    newsletter_subscribers_collection.update_one(
        {"_id": subscriber["_id"]},
        {"$set": {"unsubscribed": True, "unsubscribedAt": datetime.utcnow()}}
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return {"success": True, "message": "You have been unsubscribed."}

def get_all_active_subscribers():
    """
    Get all active (not unsubscribed) newsletter subscribers
    """
    start_db = time.time()
    subscribers = newsletter_subscribers_collection.find({"unsubscribed": False})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return subscribers

########################################
# Newsletter Campaign Management
########################################

def create_campaign(title: str, content_html: str):
    """
    Create a new newsletter campaign
    """
    doc = {
        "title": title,
        "contentHtml": content_html,
        "createdAt": datetime.utcnow(),
        "sentAt": None,
        "status": "draft"
    }
    
    start_db = time.time()
    result = newsletter_campaigns_collection.insert_one(doc)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return str(result.inserted_id)

def get_campaign_by_id(campaign_id: str):
    """
    Get a newsletter campaign by ID
    """
    try:
        oid = ObjectId(campaign_id)
    except:
        return None
    
    start_db = time.time()
    campaign = newsletter_campaigns_collection.find_one({"_id": oid})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration
    
    return campaign

def mark_campaign_sent(campaign_id: str):
    """
    Mark a newsletter campaign as sent
    """
    try:
        oid = ObjectId(campaign_id)
    except:
        return
    
    start_db = time.time()
    newsletter_campaigns_collection.update_one(
        {"_id": oid},
        {"$set": {
            "sentAt": datetime.utcnow(),
            "status": "sent"
        }}
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

def send_campaign_to_subscriber(campaign, subscriber):
    """
    Send a campaign to a specific subscriber with personalized unsubscribe link
    """
    if not campaign or not subscriber:
        return False
    
    try:
        recipient_email = subscriber["email"]
        
        # Get the user's unsubscribe token (or generate if missing)
        token = subscriber.get("unsubscribeToken")
        if not token:
            token = _generate_unsubscribe_token()
            start_db = time.time()
            newsletter_subscribers_collection.update_one(
                {"_id": subscriber["_id"]},
                {"$set": {"unsubscribeToken": token}}
            )
            duration = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration
        
        # Get the frontend URL from environment variable or use a default
        frontend_url = os.getenv('FRONTEND_URL', 'https://certgames.com')
        unsubscribe_link = f"{frontend_url}/newsletter/unsubscribe/{token}"
        
        # Get the campaign content and title
        subject_line = campaign["title"]
        body_html_from_campaign = campaign["contentHtml"]
        
        # Create simple HTML that includes campaign content + unsubscribe link
        personal_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{subject_line}</title>
        </head>
        <body style="font-family: Arial, sans-serif; color: #333333; line-height: 1.6; margin: 0; padding: 0;">
            {body_html_from_campaign}
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
            <p style="font-size: 12px; color: #999;">
                To unsubscribe, click here: <a href="{unsubscribe_link}">Unsubscribe</a>
            </p>
        </body>
        </html>
        """
        
        # Log for debugging
        if hasattr(current_app, 'logger'):
            current_app.logger.info(f"Sending campaign to: {recipient_email}")
        
        # Send the email using SendGrid
        return email_sender.send_email(
            to_email=recipient_email,
            subject=subject_line,
            html_content=personal_html,
            email_type='newsletter'
        )
    except Exception as e:
        if hasattr(current_app, 'logger'):
            current_app.logger.exception(f"Error sending to subscriber: {str(e)}")
        return False

def send_campaign_to_all(campaign_id):
    """
    Send a campaign to all active subscribers
    """
    campaign = get_campaign_by_id(campaign_id)
    if not campaign:
        if hasattr(current_app, 'logger'):
            current_app.logger.error(f"Campaign not found with ID: {campaign_id}")
        return {"success": False, "message": "Campaign not found"}
    
    if campaign.get("status") == "sent":
        return {"success": False, "message": "Campaign already sent"}
    
    try:
        # Get all active subscribers
        subscribers_cursor = get_all_active_subscribers()
        subscribers_list = list(subscribers_cursor)
        
        if hasattr(current_app, 'logger'):
            current_app.logger.info(f"Found {len(subscribers_list)} active subscribers")
        
        if not subscribers_list:
            if hasattr(current_app, 'logger'):
                current_app.logger.warning("No active subscribers found when sending campaign")
            return {"success": False, "message": "No active subscribers found"}
        
        success_count = 0
        fail_count = 0
        
        for subscriber in subscribers_list:
            # Log subscriber info for debugging
            if hasattr(current_app, 'logger'):
                current_app.logger.info(f"Attempting to send to subscriber: {subscriber.get('email')}")
            
            # Send the campaign to this subscriber
            sent = send_campaign_to_subscriber(campaign, subscriber)
            
            if sent:
                success_count += 1
                if hasattr(current_app, 'logger'):
                    current_app.logger.info(f"Successfully sent to {subscriber.get('email')}")
            else:
                fail_count += 1
                if hasattr(current_app, 'logger'):
                    current_app.logger.error(f"Failed to send to {subscriber.get('email')}")
        
        # Mark the campaign as sent
        mark_campaign_sent(campaign_id)
        
        return {
            "success": True, 
            "message": f"Newsletter sent to {success_count} subscribers ({fail_count} failed)"
        }
    except Exception as e:
        if hasattr(current_app, 'logger'):
            current_app.logger.exception(f"Error sending campaign: {str(e)}")
        return {"success": False, "message": f"Error sending campaign: {str(e)}"}
