# backend/routes/cracked_admin.py

import os
from flask import Blueprint, request, session, jsonify
from datetime import datetime
from bson import ObjectId

from ..mongodb.database import db  # db holds our collections (e.g. mainusers, testAttempts, statsCache, supportThreads)

# Read the admin password from the environment variable "AUTHKEY"
ADMIN_PASS = os.getenv('AUTHKEY', 'DEFAULT_ADMIN_KEY')

cracked_bp = Blueprint('cracked', __name__)  # all routes here will be under /cracked

# Helper function to require admin login
def require_cracked_admin():
    if not session.get('cracked_admin_logged_in'):
        return False
    return True

@cracked_bp.route('/login', methods=['POST'])
def cracked_admin_login():
    """
    Admin login for the admin interface.
    Expects JSON: { "adminKey": "your_long_authkey_here" }
    """
    data = request.json
    if not data or 'adminKey' not in data:
        return jsonify({"error": "Missing adminKey"}), 400
    
    adminKey = data['adminKey']
    if adminKey == ADMIN_PASS:
        session['cracked_admin_logged_in'] = True
        return jsonify({"message": "Cracked admin login successful"}), 200
    else:
        return jsonify({"error": "Invalid admin password"}), 403

@cracked_bp.route('/logout', methods=['POST'])
def cracked_admin_logout():
    """
    Admin logout endpoint.
    """
    session.pop('cracked_admin_logged_in', None)
    return jsonify({"message": "Cracked admin logged out"}), 200

# --------------------------------------
# Aggregated Analytics via statsCache
# --------------------------------------
@cracked_bp.route('/stats', methods=['GET'])
def admin_aggregated_stats():
    """
    Returns aggregated analytics from the database.
    The stats are cached in a 'statsCache' collection with a short TTL (e.g., 60 seconds)
    to improve performance on repeated requests.
    """
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated as admin"}), 401

    now = datetime.utcnow()
    # Check for existing cached stats document (with _id: "aggregated_stats")
    cache_doc = db.statsCache.find_one({"_id": "aggregated_stats"})
    if cache_doc:
        last_updated = cache_doc.get("updatedAt", now)
        # If the cached stats are fresh (less than 60 seconds old), return them
        if (now - last_updated).total_seconds() < 60:
            return jsonify(cache_doc.get("stats", {})), 200

    # Otherwise, perform aggregation from raw collections
    try:
        user_count = db.mainusers.count_documents({})
        test_attempts_count = db.testAttempts.count_documents({})
        # Assume that each user document has a 'lastDailyClaim' field.
        # We'll count those users who claimed their daily bonus today.
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        daily_bonus_claims = db.mainusers.count_documents({
            "lastDailyClaim": {"$gte": start_of_day}
        })

        # Build the aggregated stats dictionary.
        stats = {
            "user_count": user_count,
            "test_attempts_count": test_attempts_count,
            "daily_bonus_claims": daily_bonus_claims,
            "timestamp": now.isoformat()
        }

        # Upsert the cache document.
        db.statsCache.replace_one(
            {"_id": "aggregated_stats"},
            {"stats": stats, "updatedAt": now},
            upsert=True
        )
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --------------------------------------
# Example: User Management Routes
# --------------------------------------
@cracked_bp.route('/users', methods=['GET'])
def admin_list_users():
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
    
    all_users = list(db.mainusers.find({}, {
        "_id": 1, "username": 1, "email": 1, "coins": 1, "xp": 1, "level": 1, "achievements": 1
    }))
    for user in all_users:
        user['_id'] = str(user['_id'])
    return jsonify(all_users), 200

@cracked_bp.route('/users/<user_id>', methods=['PUT'])
def admin_update_user(user_id):
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.json
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user id"}), 400

    update_fields = {}
    for field in ["username", "coins", "xp", "level", "subscriptionActive"]:
        if field in data:
            update_fields[field] = data[field]
    
    if update_fields:
        db.mainusers.update_one({"_id": obj_id}, {"$set": update_fields})
        return jsonify({"message": "User updated"}), 200
    else:
        return jsonify({"message": "No valid fields to update"}), 200

@cracked_bp.route('/users/<user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    try:
        obj_id = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user id"}), 400

    db.mainusers.delete_one({"_id": obj_id})
    return jsonify({"message": "User deleted"}), 200

# --------------------------------------
# Support / Chat Endpoints (Admin Side)
# --------------------------------------
@cracked_bp.route('/supportThreads', methods=['GET'])
def admin_list_support_threads():
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    threads = list(db.supportThreads.find({}))
    for t in threads:
        t['_id'] = str(t['_id'])
        t['userId'] = str(t['userId'])
    return jsonify(threads), 200

@cracked_bp.route('/supportThreads/<thread_id>', methods=['GET'])
def admin_get_support_thread(thread_id):
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    try:
        obj_id = ObjectId(thread_id)
    except Exception:
        return jsonify({"error": "Invalid thread id"}), 400

    thread = db.supportThreads.find_one({"_id": obj_id})
    if not thread:
        return jsonify({"error": "Thread not found"}), 404

    thread['_id'] = str(thread['_id'])
    thread['userId'] = str(thread['userId'])
    return jsonify(thread), 200

@cracked_bp.route('/supportThreads/<thread_id>/reply', methods=['POST'])
def admin_reply_to_thread(thread_id):
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    try:
        obj_id = ObjectId(thread_id)
    except Exception:
        return jsonify({"error": "Invalid thread id"}), 400
    
    data = request.json or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({"error": "No content provided"}), 400
    
    now = datetime.utcnow()
    update_result = db.supportThreads.update_one(
        {"_id": obj_id},
        {
            "$push": {"messages": {
                "sender": "admin",
                "content": content,
                "timestamp": now
            }},
            "$set": {"updatedAt": now}
        }
    )
    if update_result.matched_count == 0:
        return jsonify({"error": "Thread not found"}), 404
    return jsonify({"message": "Reply sent"}), 200
