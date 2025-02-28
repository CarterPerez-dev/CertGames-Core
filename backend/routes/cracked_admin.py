# backend/routes/cracked_admin.py

import os
from flask import Blueprint, request, session, jsonify, make_response
from datetime import datetime
from bson import ObjectId

from ..mongodb.database import db
# db = PyMongo client, e.g. db.mainusers, db.supportThreads, etc.

cracked_bp = Blueprint('cracked', __name__)  # distinct name from normal user blueprint

ADMIN_PASS = os.getenv('CRACKED_ADMIN_PASSWORD', 'authkey')  # must match .env

# Helper function to verify if admin is logged in
def require_cracked_admin():
    if not session.get('cracked_admin_logged_in'):
        # Or you can do token-based checks, whichever method is chosen
        return False
    return True

@cracked_bp.route('/login', methods=['POST'])
def cracked_admin_login():
    """
    Admin logs in with the CRACKED_ADMIN_PASSWORD from .env
    JSON body: { "adminKey": "the superLongRandomAdminKey345!!!JustForCracked" }
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
    Admin logs out
    """
    session.pop('cracked_admin_logged_in', None)
    return jsonify({"message": "Cracked admin logged out"}), 200


# -----------------------------
# Example: Dashboard Stats
# -----------------------------
@cracked_bp.route('/dashboard', methods=['GET'])
def admin_dashboard():
    """
    Summaries of user count, test attempts, daily bonus claims, etc.
    Requires admin to be logged in.
    """
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated as admin"}), 401

    # Example queries:
    user_count = db.mainusers.count_documents({})
    test_attempts_count = db.testAttempts.count_documents({})
    # daily claims, etc. can vary
    daily_bonus_claims = 0  # if we store them in an external collection or check user docs
    # ...

    # Return these stats in a JSON
    return jsonify({
        "user_count": user_count,
        "test_attempts_count": test_attempts_count,
        "daily_bonus_claims": daily_bonus_claims
    }), 200


# -----------------------------
# Example: User Listing
# -----------------------------
@cracked_bp.route('/users', methods=['GET'])
def admin_list_users():
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
    
    # optional: parse pagination from request.args
    # let’s just do a quick no-limit example:
    all_users = list(db.mainusers.find({}, {
        "_id": 1, "username": 1, "email": 1, "coins": 1, "xp": 1, "level": 1, "achievements": 1
    }))
    # Convert ObjectId to string
    for user in all_users:
        user['_id'] = str(user['_id'])
    return jsonify(all_users), 200


# -----------------------------
# Example: Update a user
# -----------------------------
@cracked_bp.route('/users/<user_id>', methods=['PUT'])
def admin_update_user(user_id):
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.json
    # data might contain { "coins": 9999, "xp": 10000, ... } etc.
    
    # Convert user_id from string to ObjectId
    try:
        obj_id = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user id"}), 400

    # Perform update
    update_fields = {}
    # Whitelist possible fields
    for field in ["username", "coins", "xp", "level", "subscriptionActive"]:
        if field in data:
            update_fields[field] = data[field]
    
    if update_fields:
        db.mainusers.update_one({"_id": obj_id}, {"$set": update_fields})
        return jsonify({"message": "User updated"}), 200
    else:
        return jsonify({"message": "No valid fields to update"}), 200


# -----------------------------
# Example: Delete/Suspend user
# -----------------------------
@cracked_bp.route('/users/<user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    try:
        obj_id = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user id"}), 400

    # Actually delete or mark as suspended
    db.mainusers.delete_one({"_id": obj_id})
    return jsonify({"message": "User deleted"}), 200


# =======================
# SUPPORT / CHAT MESSAGES
# =======================
@cracked_bp.route('/supportThreads', methods=['GET'])
def admin_list_support_threads():
    """
    List all open support threads from users.
    Possibly filter by 'open' status or let the admin see everything.
    """
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    threads = db.supportThreads.find({})
    results = []
    for t in threads:
        t['_id'] = str(t['_id'])
        t['userId'] = str(t['userId'])
        results.append(t)
    return jsonify(results), 200


@cracked_bp.route('/supportThreads/<thread_id>', methods=['GET'])
def admin_get_support_thread(thread_id):
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread id"}), 400

    thread = db.supportThreads.find_one({"_id": obj_id})
    if not thread:
        return jsonify({"error": "Thread not found"}), 404

    thread['_id'] = str(thread['_id'])
    thread['userId'] = str(thread['userId'])
    return jsonify(thread), 200


@cracked_bp.route('/supportThreads/<thread_id>/reply', methods=['POST'])
def admin_reply_to_thread(thread_id):
    """
    Admin sends a reply message to a user's support thread
    Body: { "content": "some text" }
    """
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread id"}), 400
    
    data = request.json or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({"error": "No content provided"}), 400
    
    # Insert new message in the messages array
    now = datetime.utcnow()
    update_result = db.supportThreads.update_one(
        {"_id": obj_id},
        {
            "$push": {
                "messages": {
                    "sender": "admin",
                    "content": content,
                    "timestamp": now
                }
            },
            "$set": {"updatedAt": now}
        }
    )
    if update_result.matched_count == 0:
        return jsonify({"error": "Thread not found"}), 404
    return jsonify({"message": "Reply sent"}), 200

