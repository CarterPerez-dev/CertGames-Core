from pymongo import MongoClient
import os
import logging
from helpers.celery_app import app

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI)
db = client['xploitcraft']
subscriptions_collection = db['user_subscriptions']

def add_subscription(email, cert_category, frequency, time_slots, task_ids=None):
    """
    Add a subscription to the database.
    """
    subscription_data = {
        "email": email,
        "cert_category": cert_category,
        "frequency": frequency,
        "time_slots": time_slots,
        "task_ids": task_ids or []
    }
    subscriptions_collection.insert_one(subscription_data)

def remove_subscription(email):
    """
    Remove a subscription from the database by email.
    """
    subscriptions_collection.delete_one({"email": email})

def find_subscription(email):
    """
    Find a subscription by email.
    """
    return subscriptions_collection.find_one({"email": email})

def update_subscription(email, updated_data):
    """
    Update a subscription in the database.
    """
    subscriptions_collection.update_one(
        {"email": email},
        {"$set": updated_data}
    )

def add_task_id(email, task_id):
    """
    Add a Celery task ID to a user's subscription.
    """
    subscriptions_collection.update_one(
        {"email": email},
        {"$push": {"task_ids": task_id}}
    )

def get_task_ids(email):
    """
    Retrieve all Celery task IDs for a user's subscription.
    """
    subscription = find_subscription(email)
    return subscription.get("task_ids", []) if subscription else []

def clear_task_ids(email):
    """
    Clear all Celery task IDs from a user's subscription.
    """
    subscriptions_collection.update_one(
        {"email": email},
        {"$set": {"task_ids": []}}
    )



def cancel_all_scheduled_tasks(email):
    task_ids = get_task_ids(email)
    for task_id in task_ids:
        app.control.revoke(task_id, terminate=True)
    clear_task_ids(email)
