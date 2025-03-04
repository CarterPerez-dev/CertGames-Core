#######################################
# models/newsletter.py
#######################################
import os
import re
import random
import string
from datetime import datetime
from bson.objectid import ObjectId
from mongodb.database import db

newsletter_subscribers_collection = db.newsletterSubscribers
newsletter_campaigns_collection = db.newsletterCampaigns

def _generate_unsubscribe_token(length=32):
    """
    Generates a random token for unsubscribing.
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def subscribe_email(email: str):
    email = email.strip().lower()
    if not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return {"success": False, "message": "Invalid email format."}

    existing = newsletter_subscribers_collection.find_one({"email": email})
    if existing:
        if existing.get("unsubscribed", False) is True:
            # Mark them re-subscribed
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
        newsletter_subscribers_collection.insert_one(doc)
        return {"success": True, "message": "Subscription successful."}


def unsubscribe_email(email: str):
    """
    If you still want to let them unsubscribe by email
    (POST /newsletter/unsubscribe with JSON),
    keep this approach for backwards compatibility.
    """
    email = email.strip().lower()
    subscriber = newsletter_subscribers_collection.find_one({"email": email})
    if not subscriber:
        return {"success": False, "message": "Email not found in subscriber list."}

    if subscriber.get("unsubscribed", False) is True:
        return {"success": False, "message": "Already unsubscribed."}

    newsletter_subscribers_collection.update_one(
        {"_id": subscriber["_id"]},
        {"$set": {"unsubscribed": True, "unsubscribedAt": datetime.utcnow()}}
    )
    return {"success": True, "message": "You have been unsubscribed."}


def unsubscribe_by_token(token: str):
    """
    Finds the subscriber by their token and unsubscribes them if possible.
    Returns a dict { success: bool, message: str }.
    """
    subscriber = newsletter_subscribers_collection.find_one({"unsubscribeToken": token})
    if not subscriber:
        return {"success": False, "message": "Invalid unsubscribe token."}
    if subscriber.get("unsubscribed", False):
        return {"success": False, "message": "You have already unsubscribed."}

    newsletter_subscribers_collection.update_one(
        {"_id": subscriber["_id"]},
        {"$set": {"unsubscribed": True, "unsubscribedAt": datetime.utcnow()}}
    )
    return {"success": True, "message": "You have been unsubscribed."}


def get_all_active_subscribers():
    return newsletter_subscribers_collection.find({"unsubscribed": False})


########################################
# Newsletter Campaign Management
########################################

def create_campaign(title: str, content_html: str):
    doc = {
        "title": title,
        "contentHtml": content_html,
        "createdAt": datetime.utcnow(),
        "sentAt": None,
        "status": "draft"
    }
    result = newsletter_campaigns_collection.insert_one(doc)
    return str(result.inserted_id)

def get_campaign_by_id(campaign_id: str):
    try:
        oid = ObjectId(campaign_id)
    except:
        return None
    return newsletter_campaigns_collection.find_one({"_id": oid})

def mark_campaign_sent(campaign_id: str):
    try:
        oid = ObjectId(campaign_id)
    except:
        return
    newsletter_campaigns_collection.update_one(
        {"_id": oid},
        {"$set": {
            "sentAt": datetime.utcnow(),
            "status": "sent"
        }}
    )

