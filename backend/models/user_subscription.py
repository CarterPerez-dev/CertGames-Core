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

def add_subscription(email, cert_category, frequency, time_slots):
    """
    Add a subscription to the database.
    Store task_ids as an empty dict initially.
    """
    subscription_data = {
        "email": email,
        "cert_category": cert_category,
        "frequency": frequency,
        "time_slots": time_slots,
        "task_ids": {}  # <-- a dictionary keyed by slot
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

def set_task_id_for_slot(email, slot, task_id):
    """
    Store/Update a Celery task ID for a specific time slot in the subscription's dictionary.
    """
    subscriptions_collection.update_one(
        {"email": email},
        {"$set": {f"task_ids.{slot}": task_id}}
    )

def remove_task_id_for_slot(email, slot):
    """
    Remove a Celery task ID for a specific time slot from the subscription.
    """
    subscriptions_collection.update_one(
        {"email": email},
        {"$unset": {f"task_ids.{slot}": ""}}
    )

def get_task_id_for_slot(email, slot):
    """
    Retrieve the Celery task ID for a specific time slot, if any.
    """
    subscription = find_subscription(email)
    if not subscription:
        return None
    return subscription.get("task_ids", {}).get(slot)

def get_all_task_ids(email):
    """
    Return entire dictionary of slot -> task_id.
    """
    subscription = find_subscription(email)
    if not subscription:
        return {}
    return subscription.get("task_ids", {})

def cancel_all_scheduled_tasks(email):
    """
    Revoke all scheduled tasks (by slot) and clear the dictionary of task_ids.
    """
    task_ids_dict = get_all_task_ids(email)
    for slot, task_id in task_ids_dict.items():
        if task_id:
            app.control.revoke(task_id, terminate=True)
    # Clear the entire dictionary
    subscriptions_collection.update_one(
        {"email": email},
        {"$set": {"task_ids": {}}}
    )

