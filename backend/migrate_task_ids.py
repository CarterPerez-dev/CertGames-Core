from pymongo import MongoClient
import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file if you use one
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variable for MongoDB URI
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/xploitcraft")

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client['xploitcraft']
subscriptions_collection = db['user_subscriptions']

def migrate_task_ids():
    cursor = subscriptions_collection.find({"task_ids": {"$exists": True}})
    total_migrated = 0

    for subscription in cursor:
        email = subscription.get('email')
        time_slots = subscription.get('time_slots', [])
        old_task_ids = subscription.get('task_ids', [])

        # Ensure task_ids is a list
        if isinstance(old_task_ids, list):
            if len(old_task_ids) != len(time_slots):
                logger.warning(f"Mismatch in number of task_ids and time_slots for {email}. Skipping.")
                continue

            # Create a new dictionary mapping time_slot to task_id
            new_task_ids = {slot: task_id for slot, task_id in zip(time_slots, old_task_ids)}

            # Update the document with the new task_ids dictionary
            result = subscriptions_collection.update_one(
                {"_id": subscription["_id"]},
                {"$set": {"task_ids": new_task_ids}}
            )

            if result.modified_count:
                logger.info(f"Migrated task_ids for {email}.")
                total_migrated += 1
            else:
                logger.error(f"Failed to migrate task_ids for {email}.")

    logger.info(f"Migration completed. Total subscriptions migrated: {total_migrated}")

if __name__ == "__main__":
    migrate_task_ids()

