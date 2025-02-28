# backend/routes/cracked_admin.py

import os
import csv
import io
from flask import Blueprint, request, session, jsonify, make_response
from datetime import datetime, timedelta
from bson import ObjectId
from ..mongodb.database import db

cracked_bp = Blueprint('cracked', __name__, url_prefix='/cracked')

ADMIN_PASS = os.getenv('CRACKED_ADMIN_PASSWORD', 'authkey')

# ---------------------------
# Helper: Check Admin Session
# ---------------------------
def require_cracked_admin(required_role=None):
    """
    If required_role is given, we also check session['cracked_admin_role'] >= required_role 
    in a naive role system, or we compare roles in some custom logic.
    """
    if not session.get('cracked_admin_logged_in'):
        return False
    
    # Example naive role check (optional).
    if required_role:
        current_role = session.get('cracked_admin_role', 'basic')
        # If we had a role priority system, e.g. "basic" < "supervisor" < "superadmin"
        priority_map = {
            "basic": 1,
            "supervisor": 2,
            "superadmin": 3
        }
        needed = priority_map.get(required_role, 1)
        have = priority_map.get(current_role, 1)
        if have < needed:
            return False
    
    return True


# ---------------------------
# Admin Login / Logout
# ---------------------------
@cracked_bp.route('/login', methods=['POST'])
def cracked_admin_login():
    """
    JSON body: { "adminKey": "...", "role": "superadmin" }
    """
    data = request.json or {}
    adminKey = data.get('adminKey', '')
    input_role = data.get('role', 'basic')  # optional
    
    if adminKey == ADMIN_PASS:
        # Mark session
        session['cracked_admin_logged_in'] = True
        # Example: store the role
        session['cracked_admin_role'] = input_role
        
        return jsonify({"message": "Cracked admin login successful"}), 200
    else:
        return jsonify({"error": "Invalid admin password"}), 403


@cracked_bp.route('/logout', methods=['POST'])
def cracked_admin_logout():
    """
    Clears admin session state
    """
    session.pop('cracked_admin_logged_in', None)
    session.pop('cracked_admin_role', None)
    return jsonify({"message": "Cracked admin logged out"}), 200


# -------------------------------------------------------
# Dashboard / Aggregated Stats (Cached in statsCache)
# -------------------------------------------------------
@cracked_bp.route('/dashboard', methods=['GET'])
def admin_dashboard():
    """
    Summaries of user count, test attempts, daily bonus claims, etc.
    Aggregates and caches them in statsCache for 60s.
    """
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated as admin"}), 401

    # Check cache
    now = datetime.utcnow()
    cached_doc = db.statsCache.find_one({"_id": "admin_dashboard"})
    if cached_doc:
        last_updated = cached_doc.get("updatedAt", now)
        if (now - last_updated) < timedelta(seconds=60):
            return jsonify(cached_doc["data"]), 200
    
    # Recompute
    try:
        user_count = db.mainusers.count_documents({})
        test_attempts_count = db.testAttempts.count_documents({})
        
        # Example: daily bonus claims since midnight
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        daily_bonus_claims = db.mainusers.count_documents({
            "lastDailyClaim": {"$gte": start_of_day}
        })
        
        # Example: average test score if testAttempts store 'score' and 'totalQuestions'
        pipeline = [
            {"$match": {"finished": True}},
            {"$group": {
                "_id": None,
                "avgScorePercent": {
                    "$avg": {
                        "$multiply": [
                            {"$divide": ["$score", "$totalQuestions"]},
                            100
                        ]
                    }
                }
            }}
        ]
        result = list(db.testAttempts.aggregate(pipeline))
        avg_score = result[0]["avgScorePercent"] if result else 0.0
        
        data = {
            "user_count": user_count,
            "test_attempts_count": test_attempts_count,
            "daily_bonus_claims": daily_bonus_claims,
            "average_test_score_percent": round(avg_score, 2),
            "timestamp": now.isoformat()
        }
        
        # upsert into statsCache
        db.statsCache.replace_one(
            {"_id": "admin_dashboard"},
            {"data": data, "updatedAt": now},
            upsert=True
        )
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------------------------------------------
# 1) USER MANAGEMENT
# -------------------------------------------------------
@cracked_bp.route('/users', methods=['GET'])
def admin_list_users():
    """
    GET /cracked/users?search=...&page=1&limit=20
    Returns a paginated, searchable list of users.
    """
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
    
    search = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 20))
    
    query = {}
    if search:
        # Example: search in username or email (case-insensitive)
        query = {
            "$or": [
                {"username": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}}
            ]
        }
    
    skip_count = (page - 1) * limit
    
    users_cursor = db.mainusers.find(query, {
        "_id": 1, "username": 1, "email": 1, "coins": 1, "xp": 1, "level": 1,
        "achievements": 1, "subscriptionActive": 1, "suspended": 1
    }).skip(skip_count).limit(limit)
    
    results = []
    for u in users_cursor:
        u['_id'] = str(u['_id'])
        results.append(u)
    
    total_count = db.mainusers.count_documents(query)
    
    return jsonify({
        "users": results,
        "total": total_count,
        "page": page,
        "limit": limit
    }), 200


@cracked_bp.route('/users/export', methods=['GET'])
def admin_export_users_csv():
    """
    Export all users in CSV format.
    Only superadmin role can do this, for example.
    """
    if not require_cracked_admin(required_role="superadmin"):
        return jsonify({"error": "Insufficient admin privileges"}), 403
    
    users = db.mainusers.find({}, {
        "username": 1, "email": 1, "coins": 1, "xp": 1, "level": 1
    })
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["username", "email", "coins", "xp", "level"])
    for u in users:
        writer.writerow([
            u.get("username", ""),
            u.get("email", ""),
            u.get("coins", 0),
            u.get("xp", 0),
            u.get("level", 1)
        ])
    output.seek(0)
    
    response = make_response(output.read())
    response.headers["Content-Disposition"] = "attachment; filename=users_export.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


@cracked_bp.route('/users/<user_id>', methods=['PUT'])
def admin_update_user(user_id):
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.json or {}
    try:
        obj_id = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user id"}), 400

    # Whitelist
    update_fields = {}
    for field in ["username", "coins", "xp", "level", "subscriptionActive", "suspended"]:
        if field in data:
            update_fields[field] = data[field]
    
    if update_fields:
        db.mainusers.update_one({"_id": obj_id}, {"$set": update_fields})
        return jsonify({"message": "User updated"}), 200
    else:
        return jsonify({"message": "No valid fields to update"}), 200


@cracked_bp.route('/users/<user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    """
    Actually deletes the user from DB (super dangerous).
    Alternatively, you might want to just 'suspend' them instead.
    """
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    try:
        obj_id = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user id"}), 400

    db.mainusers.delete_one({"_id": obj_id})
    return jsonify({"message": "User deleted"}), 200


# -------------------------------------------------------
# 2) TEST MANAGEMENT
# -------------------------------------------------------
@cracked_bp.route('/tests', methods=['GET'])
def admin_list_tests():
    """
    GET /cracked/tests?category=aplus
    Returns a list of tests for a specific category or all if no category param.
    """
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401
    
    category = request.args.get('category', '').strip()
    query = {}
    if category:
        query["category"] = category
    
    tests_cursor = db.tests.find(query)
    results = []
    for t in tests_cursor:
        t['_id'] = str(t['_id'])
        results.append(t)
    
    return jsonify(results), 200


@cracked_bp.route('/tests', methods=['POST'])
def admin_create_test():
    """
    Creates a new test with a given category, testName, questions, etc.
    Example JSON:
    {
      "category": "aplus",
      "testId": 11,
      "testName": "Custom A+ Test 11",
      "questions": [
        {
          "id": 101,
          "question": "What is RAM?",
          "options": [...],
          "correctAnswerIndex": 0,
          "explanation": "Random Access Memory..."
        }
      ]
    }
    """
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    data = request.json or {}
    if "category" not in data or "testId" not in data or "questions" not in data:
        return jsonify({"error": "Missing required fields"}), 400
    
    # Insert
    result = db.tests.insert_one(data)
    return jsonify({"message": "Test created", "insertedId": str(result.inserted_id)}), 201


@cracked_bp.route('/tests/<test_id>', methods=['PUT'])
def admin_update_test(test_id):
    """
    Update an existing test's metadata or questions.
    """
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403
    
    data = request.json or {}
    try:
        obj_id = ObjectId(test_id)
    except:
        return jsonify({"error": "Invalid test id"}), 400
    
    update_result = db.tests.update_one({"_id": obj_id}, {"$set": data})
    if update_result.matched_count == 0:
        return jsonify({"error": "Test not found"}), 404
    return jsonify({"message": "Test updated"}), 200


@cracked_bp.route('/tests/<test_id>', methods=['DELETE'])
def admin_delete_test(test_id):
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    try:
        obj_id = ObjectId(test_id)
    except:
        return jsonify({"error": "Invalid test id"}), 400

    delete_result = db.tests.delete_one({"_id": obj_id})
    if delete_result.deleted_count == 0:
        return jsonify({"error": "Test not found"}), 404
    return jsonify({"message": "Test deleted"}), 200


# -------------------------------------------------------
# 3) DAILY PBQ MANAGEMENT
# -------------------------------------------------------
@cracked_bp.route('/daily', methods=['GET'])
def admin_list_daily_questions():
    """
    List daily PBQ (Performance-Based Question) docs or random daily question docs
    """
    if not require_cracked_admin(required_role="basic"):
        return jsonify({"error": "Not authenticated"}), 401

    docs = list(db.dailyQuestions.find({}))
    for d in docs:
        d['_id'] = str(d['_id'])
    return jsonify(docs), 200


@cracked_bp.route('/daily', methods=['POST'])
def admin_create_daily_question():
    """
    JSON: {
      "dayIndex": 50,
      "prompt": "What is the best method to do X?",
      "options": [...],
      "correctIndex": 2,
      "explanation": "...",
      "activeDate": "2025-03-01"
    }
    """
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    data = request.json or {}
    if "prompt" not in data:
        return jsonify({"error": "Missing prompt"}), 400

    data["createdAt"] = datetime.utcnow()
    db.dailyQuestions.insert_one(data)
    return jsonify({"message": "Daily PBQ created"}), 201


@cracked_bp.route('/daily/<obj_id>', methods=['PUT'])
def admin_update_daily_question(obj_id):
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    data = request.json or {}
    try:
        doc_id = ObjectId(obj_id)
    except:
        return jsonify({"error": "Invalid daily PBQ id"}), 400
    
    update_result = db.dailyQuestions.update_one({"_id": doc_id}, {"$set": data})
    if update_result.matched_count == 0:
        return jsonify({"error": "Daily PBQ not found"}), 404
    return jsonify({"message": "Daily PBQ updated"}), 200


@cracked_bp.route('/daily/<obj_id>', methods=['DELETE'])
def admin_delete_daily_question(obj_id):
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    try:
        doc_id = ObjectId(obj_id)
    except:
        return jsonify({"error": "Invalid daily PBQ id"}), 400

    delete_result = db.dailyQuestions.delete_one({"_id": doc_id})
    if delete_result.deleted_count == 0:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"message": "Daily PBQ deleted"}), 200


# -------------------------------------------------------
# 4) SUPPORT CHAT (Admin Side)
# -------------------------------------------------------
@cracked_bp.route('/supportThreads', methods=['GET'])
def admin_list_support_threads():
    """
    Admin sees all or only open threads.
    /cracked/supportThreads?status=open
    """
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    status_filter = request.args.get('status', '')
    query = {}
    if status_filter:
        query["status"] = status_filter
    
    threads = db.supportThreads.find(query).sort("updatedAt", -1)
    results = []
    for t in threads:
        t['_id'] = str(t['_id'])
        t['userId'] = str(t['userId'])
        # Convert each message's timestamp to string if you want
        for m in t['messages']:
            m['timestamp'] = m['timestamp'].isoformat()
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
    for m in thread['messages']:
        m['timestamp'] = m['timestamp'].isoformat()
    return jsonify(thread), 200


@cracked_bp.route('/supportThreads/<thread_id>/reply', methods=['POST'])
def admin_reply_to_thread(thread_id):
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


@cracked_bp.route('/supportThreads/<thread_id>/close', methods=['POST'])
def admin_close_thread(thread_id):
    """
    Admin can close a support thread.
    Body can optionally provide a 'resolution' message or code.
    """
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread id"}), 400
    
    data = request.json or {}
    resolution = data.get('resolution', 'closed by admin')
    now = datetime.utcnow()

    update_result = db.supportThreads.update_one(
        {"_id": obj_id},
        {
            "$push": {"messages": {
                "sender": "admin",
                "content": f"Thread closed. Reason: {resolution}",
                "timestamp": now
            }},
            "$set": {
                "status": "closed",
                "updatedAt": now
            }
        }
    )
    if update_result.matched_count == 0:
        return jsonify({"error": "Thread not found"}), 404
    
    return jsonify({"message": "Thread closed"}), 200
