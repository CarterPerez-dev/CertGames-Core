# backend/tasks/cleanup_tokens.py
from datetime import datetime, timedelta, timezone
from mongodb.database import db

def cleanup_expired_token_blocklist():
    """Remove expired entries from token blocklist to prevent it from growing too large"""
    # Tokens older than 30 days can be safely removed
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    
    result = db.token_blocklist.delete_many({
        "created_at": {"$lt": cutoff}
    })
    
    return result.deleted_count
