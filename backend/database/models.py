from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

# Set up MongoDB Client
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client.get_database()

# Define collection
users_collection = db["users"]

def create_user(user_data):
    """
    Create a new user in the users collection.
    :param user_data: Dictionary containing user details (e.g., {"name": "Alice", "email": "alice@example.com"})
    """
    result = users_collection.insert_one(user_data)
    return result.inserted_id

def get_user(email):
    """
    Get a user by email.
    :param email: The email of the user to retrieve.
    """
    return users_collection.find_one({"email": email})

def update_user(email, updates):
    """
    Update a user's information.
    :param email: The email of the user to update.
    :param updates: Dictionary of fields to update (e.g., {"name": "Alice Updated"}).
    """
    return users_collection.update_one({"email": email}, {"$set": updates})

def delete_user(email):
    """
    Delete a user by email.
    :param email: The email of the user to delete.
    """
    return users_collection.delete_one({"email": email})

