# models/newsletter_content.py

from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client.get_database()

newsletter_collection = db["newsletter"]  # or db["newsletter_content"]

def get_current_newsletter_db():
    """
    Returns the single doc that stores the current newsletter content.
    """
    return newsletter_collection.find_one({})

def set_current_newsletter_db(content):
    """
    Overwrite the single doc with new content.
    """
    # Option: remove all existing docs
    newsletter_collection.delete_many({})
    # Insert new doc
    newsletter_collection.insert_one({"content": content})

