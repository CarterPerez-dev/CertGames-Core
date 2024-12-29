# helpers/daily_newsletter_helper.py

import logging
from models.newsletter_content import (
    get_current_newsletter_db,
    set_current_newsletter_db
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def get_newsletter_content():
    """
    Retrieve the latest daily newsletter content from the DB.
    """
    doc = get_current_newsletter_db()
    if doc:
        return doc.get("content", "")
    return ""  # If none found

def set_newsletter_content(new_content):
    """
    Store or overwrite the daily newsletter content in the DB.
    """
    set_current_newsletter_db(new_content)
    logger.info("Daily newsletter content updated successfully.")

