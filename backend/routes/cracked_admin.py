import csv
import io
import random
import string
import pytz
from datetime import datetime, timedelta
from bson import ObjectId
from flask import Blueprint, request, session, jsonify, make_response, current_app
from pymongo import ReturnDocument
import redis
import os
import time
import pickle
from dotenv import load_dotenv

from mongodb.database import db

cracked_bp = Blueprint('cracked', __name__, url_prefix='/cracked')
ADMIN_PASS = os.getenv('CRACKED_ADMIN_PASSWORD', 'authkey')

load_dotenv()

REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
cache_conn = redis.StrictRedis(host='redis', port=6379, db=1, password=REDIS_PASSWORD)

def cache_set(key, value, ttl=60):
    try:
        serialized = pickle.dumps(value)
        cache_conn.setex(key, ttl, serialized)
    except:
        pass

def cache_get(key):
    try:
        data = cache_conn.get(key)
        if data:
            return pickle.loads(data)
        return None
    except:
        return None

def require_cracked_admin(required_role=None):
    """
    Checks if session['cracked_admin_logged_in'] is True.
    Optionally enforces roles: basic=1, supervisor=2, superadmin=3.
    """
    if not session.get('cracked_admin_logged_in'):
        return False
    if required_role:
        current_role = session.get('cracked_admin_role', 'basic')
        priority_map = {"basic": 1, "supervisor": 2, "superadmin": 3}
        needed = priority_map.get(required_role, 1)
        have = priority_map.get(current_role, 1)
        return have >= needed
    return True


##################################################################
# ADMIN LOGIN / LOGOUT
##################################################################
@cracked_bp.route('/login', methods=['POST'])
def cracked_admin_login():
    data = request.json or {}
    adminKey = data.get('adminKey', '')
    input_role = data.get('role', 'basic')
    if adminKey == ADMIN_PASS:
        session['cracked_admin_logged_in'] = True
        session['cracked_admin_role'] = input_role
        return jsonify({"message": "Authorization successful"}), 200
    else:
        return jsonify({"error": "Invalid admin password"}), 403

@cracked_bp.route('/logout', methods=['POST'])
def cracked_admin_logout():
    session.pop('cracked_admin_logged_in', None)
    session.pop('cracked_admin_role', None)
    return jsonify({"message": "admin logged out"}), 200


##################################################################
# ADMIN DASHBOARD
##################################################################
@cracked_bp.route('/dashboard', methods=['GET'])
def admin_dashboard():
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated as admin"}), 401

    cache_key = 'admin_dashboard_data'
    cached_data = cache_get(cache_key)
    now_utc = datetime.utcnow()

    if cached_data:
        return jsonify(cached_data), 200

    try:
        # 1) Basic counts & stats
        user_count = db.mainusers.count_documents({})
        test_attempts_count = db.testAttempts.count_documents({})

        start_of_day = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
        daily_bonus_claims = db.mainusers.count_documents({
            "lastDailyClaim": {"$gte": start_of_day}
        })

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

        # 2) Performance metrics (the latest doc)
        perf_metrics = db.performanceMetrics.find_one({}, sort=[("timestamp", -1)])
        if not perf_metrics:
            # Provide a fallback doc if none exist
            perf_metrics = {
                "avg_request_time": 0.123,
                "avg_db_query_time_ms": 45.0,
                "data_transfer_rate": "1.2MB/s",
                "throughput": 50,
                "error_rate": 0.02,
                "timestamp": now_utc
            }
        else:
            # Convert _id => str
            if '_id' in perf_metrics:
                perf_metrics['_id'] = str(perf_metrics['_id'])

            # If there's a numeric 'avg_db_query_time', convert to ms
            if 'avg_db_query_time' in perf_metrics:
                ms_val = round(perf_metrics['avg_db_query_time'] * 1000, 2)
                perf_metrics['avg_db_query_time_ms'] = ms_val
                del perf_metrics['avg_db_query_time']

            # Convert timestamp to EST
            if 'timestamp' in perf_metrics and isinstance(perf_metrics['timestamp'], datetime):
                import pytz
                est_tz = pytz.timezone('America/New_York')
                perf_metrics['timestamp'] = perf_metrics['timestamp'].astimezone(est_tz).isoformat()

        # 3) Build "recentStats" for the last 7 days
        import pytz
        est_tz = pytz.timezone('America/New_York')
        recentStats = []
        for i in range(7):
            day_start = start_of_day - timedelta(days=i)
            day_end = day_start + timedelta(days=1)
            label_str = day_start.strftime("%Y-%m-%d")

            day_bonus_count = db.mainusers.count_documents({
                "lastDailyClaim": {"$gte": day_start, "$lt": day_end}
            })
            day_test_attempts = db.testAttempts.count_documents({
                "finished": True,
                "finishedAt": {"$gte": day_start, "$lt": day_end}
            })
            recentStats.append({
                "label": label_str,
                "dailyBonus": day_bonus_count,
                "testAttempts": day_test_attempts
            })
        # Reverse so oldest is first
        recentStats.reverse()

        now_est = now_utc.astimezone(est_tz).isoformat()

        dashboard_data = {
            "user_count": user_count,
            "test_attempts_count": test_attempts_count,
            "daily_bonus_claims": daily_bonus_claims,
            "average_test_score_percent": round(avg_score, 2),
            "timestamp_est": now_est,
            "performance_metrics": perf_metrics,
            "recentStats": recentStats
        }

        cache_set(cache_key, dashboard_data, ttl=60)
        return jsonify(dashboard_data), 200

    except Exception as e:
        return jsonify({"error": "Failed to retrieve dashboard metrics", "details": str(e)}), 500

##################################################################
# USERS
##################################################################
@cracked_bp.route('/users', methods=['GET'])
def admin_list_users():
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    search = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 20))

    # Optional: Cache page1 limit20 w/no search
    if not search and page == 1 and limit == 20:
        cache_key = "admin_users_list_page1_limit20"
        cached_data = cache_get(cache_key)
        if cached_data:
            return jsonify(cached_data), 200

    query = {}
    if search:
        query = {
            "$or": [
                {"username": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}}
            ]
        }
    skip_count = (page - 1) * limit

    projection = {
        "_id": 1,
        "username": 1,
        "email": 1,
        "coins": 1,
        "xp": 1,
        "level": 1,
        "achievements": 1,
        "subscriptionActive": 1,
        "suspended": 1,
        "achievement_counters": 1,
        "currentAvatar": 1
    }

    cursor = db.mainusers.find(query, projection).skip(skip_count).limit(limit)
    results = []
    for u in cursor:
        u['_id'] = str(u['_id'])
        if 'currentAvatar' in u and isinstance(u['currentAvatar'], ObjectId):
            u['currentAvatar'] = str(u['currentAvatar'])
        if 'achievements' in u and isinstance(u['achievements'], list):
            u['achievements'] = [str(a) for a in u['achievements']]

        counters = u.get('achievement_counters', {})
        u['totalQuestionsAnswered'] = counters.get('total_questions_answered', 0)
        u['perfectTestsCount'] = counters.get('perfect_tests_count', 0)
        results.append(u)

    total_count = db.mainusers.count_documents(query)
    resp_data = {
        "users": results,
        "total": total_count,
        "page": page,
        "limit": limit
    }

    if not search and page == 1 and limit == 20:
        cache_set("admin_users_list_page1_limit20", resp_data, 60)

    return jsonify(resp_data), 200

@cracked_bp.route('/users/export', methods=['GET'])
def admin_export_users_csv():
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

    # We only allow editing certain fields
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
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    try:
        obj_id = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user id"}), 400

    db.mainusers.delete_one({"_id": obj_id})
    return jsonify({"message": "User deleted"}), 200

@cracked_bp.route('/users/<user_id>/reset-password', methods=['POST'])
def admin_reset_password(user_id):
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    try:
        obj_id = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user id"}), 400

    import string, random
    new_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    result = db.mainusers.find_one_and_update(
        {"_id": obj_id},
        {"$set": {"password": new_pass}},
        return_document=ReturnDocument.AFTER
    )
    if not result:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"message": "Password reset", "newPassword": new_pass}), 200


##################################################################
# SUPPORT THREADS (Admin)
##################################################################
@cracked_bp.route('/supportThreads', methods=['GET'])
def admin_list_support_threads():
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
        for m in t.get('messages', []):
            if isinstance(m.get('timestamp'), datetime):
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
    for m in thread.get('messages', []):
        if isinstance(m.get('timestamp'), datetime):
            m['timestamp'] = m['timestamp'].isoformat()

    return jsonify(thread), 200

@cracked_bp.route('/supportThreads/<thread_id>/reply', methods=['POST'])
def admin_reply_to_thread(thread_id):
    """
    Admin replies to an existing thread. 
    Emits 'new_message' to that thread's room => room = thread_id
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

    socketio = current_app.extensions['socketio']
    thread_id_str = str(thread_id)

    socketio.emit('new_message', {
        "threadId": thread_id_str,
        "message": {
            "sender": "admin",
            "content": content,
            "timestamp": now.isoformat()
        }
    }, room=thread_id_str)

    return jsonify({"message": "Reply sent"}), 200

@cracked_bp.route('/supportThreads/<thread_id>/close', methods=['POST'])
def admin_close_thread(thread_id):
    """
    Admin closes a thread. Also pushes a "Thread closed" message
    into 'messages' array and emits 'new_message'
    so the user sees it in real time.
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

    # Update DB: set status to 'closed', push a closure message
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

    # Emit a 'new_message' event so the user sees
    # "Thread closed..." message in real time
    from flask import current_app
    socketio = current_app.extensions['socketio']
    socketio.emit(
        'new_message',
        {
            "threadId": str(obj_id),
            "message": {
                "sender": "admin",
                "content": f"Thread closed. Reason: {resolution}",
                "timestamp": now.isoformat()
            }
        },
        room=str(obj_id)  # The Socket.IO room is the thread's string ID
    )

    return jsonify({"message": "Thread closed"}), 200


@cracked_bp.route('/supportThreads/clear-closed', methods=['DELETE'])
def admin_clear_closed_threads():
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    result = db.supportThreads.delete_many({"status": "closed"})
    return jsonify({"message": f"Deleted {result.deleted_count} closed threads"}), 200

@cracked_bp.route('/supportThreads/createFromAdmin', methods=['POST'])
def admin_create_thread_for_user():
    """
    JSON: { "userId": "...", "initialMessage": "Hello from admin" }
    Creates a new support thread for the user with an admin-sent message.
    Emits 'new_thread' to the user's personal room => "user_<userId>"
    Returns the thread data in the response.
    """
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    data = request.json or {}
    user_id = data.get("userId")
    initial_message = data.get("initialMessage", "").strip()
    if not user_id:
        return jsonify({"error": "Missing userId"}), 400

    try:
        user_oid = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid userId"}), 400

    now = datetime.utcnow()
    thread_doc = {
        "userId": user_oid,
        "subject": "Admin-initiated conversation",
        "messages": [],
        "status": "open",
        "createdAt": now,
        "updatedAt": now
    }
    if initial_message:
        thread_doc["messages"].append({
            "sender": "admin",
            "content": initial_message,
            "timestamp": now
        })

    insert_result = db.supportThreads.insert_one(thread_doc)
    if insert_result.inserted_id:
        socketio = current_app.extensions['socketio']

        thread_data = {
            "_id": str(insert_result.inserted_id),
            "userId": user_id,
            "subject": "Admin-initiated conversation",
            "status": "open",
            "createdAt": now.isoformat(),
            "updatedAt": now.isoformat(),
            "messages": ([
                {
                    "sender": "admin",
                    "content": initial_message,
                    "timestamp": now.isoformat()
                }
            ] if initial_message else [])
        }

        # Emit to just that user's room => "user_<userId>"
        socketio.emit('new_thread', thread_data, room=f"user_{user_id}")

        return jsonify({"message": "Thread created", "thread": thread_data}), 201
    else:
        return jsonify({"error": "Failed to create thread"}), 500


##################################################################
# TESTS
##################################################################
@cracked_bp.route('/tests', methods=['GET'])
def admin_list_tests():
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
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    data = request.json or {}
    # Must have "category", "testId", "questions"
    if "category" not in data or "testId" not in data or "questions" not in data:
        return jsonify({"error": "Missing required fields"}), 400

    result = db.tests.insert_one(data)
    return jsonify({"message": "Test created", "insertedId": str(result.inserted_id)}), 201


@cracked_bp.route('/tests/<test_id>', methods=['PUT'])
def admin_update_test(test_id):
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


##################################################################
# DAILY PBQs
##################################################################
@cracked_bp.route('/daily', methods=['GET'])
def admin_list_daily_questions():
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    docs = list(db.dailyQuestions.find({}))
    for d in docs:
        d['_id'] = str(d['_id'])
    return jsonify(docs), 200

@cracked_bp.route('/daily', methods=['POST'])
def admin_create_daily_question():
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





##################################################################
# PERFORMANCE
##################################################################
@cracked_bp.route('/performance', methods=['GET'])
def admin_performance_metrics():
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    try:
        perf_metrics = db.performanceMetrics.find_one({}, sort=[("timestamp", -1)])
        if not perf_metrics:
            # Return a dummy doc so front end won't break
            perf_metrics = {
                "_id": None,
                "avg_request_time": 0.123,
                "avg_db_query_time_ms": 45.0,
                "data_transfer_rate": "1.2MB/s",
                "throughput": 50,
                "error_rate": 0.02,
                "timestamp": datetime.utcnow()
            }
        else:
            perf_metrics['_id'] = str(perf_metrics.get('_id', ''))

            # Convert any 'avg_db_query_time' => ms
            if 'avg_db_query_time' in perf_metrics:
                ms_val = round(perf_metrics['avg_db_query_time'] * 1000, 2)
                perf_metrics['avg_db_query_time_ms'] = ms_val
                del perf_metrics['avg_db_query_time']

        # Convert timestamp to EST
        if 'timestamp' in perf_metrics and isinstance(perf_metrics['timestamp'], datetime):
            est_tz = pytz.timezone('America/New_York')
            perf_metrics['timestamp'] = perf_metrics['timestamp'].astimezone(est_tz).isoformat()

        # Example: If you want a history array for charting:
        # (pull last 10 performanceMetrics docs and transform them)
        history_cursor = db.performanceMetrics.find().sort("timestamp", -1).limit(10)
        history_list = []
        est_tz = pytz.timezone('America/New_York')
        for doc in history_cursor:
            doc_id = str(doc['_id'])
            doc_time = doc['timestamp'].astimezone(est_tz).isoformat() if isinstance(doc['timestamp'], datetime) else None
            # convert numeric to ms
            if 'avg_db_query_time' in doc:
                doc['avg_db_query_time_ms'] = round(doc['avg_db_query_time'] * 1000, 2)
                del doc['avg_db_query_time']

            history_list.append({
                "_id": doc_id,
                "timestamp": doc_time,
                "requestTime": doc.get("avg_request_time", 0),
                "dbTime": doc.get("avg_db_query_time_ms", 0.0)
            })
        # Attach the reversed list so it's earliest to latest if you want:
        perf_metrics['history'] = list(reversed(history_list))

        return jsonify(perf_metrics), 200

    except Exception as e:
        return jsonify({"error": "Failed to retrieve performance metrics", "details": str(e)}), 500


##################################################################
# ACTIVITY / AUDIT LOGS
##################################################################
@cracked_bp.route('/activity-logs', methods=['GET'])
def admin_activity_logs():
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    logs = db.auditLogs.find().sort("timestamp", -1).limit(200)
    results = []
    est_tz = pytz.timezone('America/New_York')

    for l in logs:
        # Convert _id => str
        l['_id'] = str(l['_id'])

        # Also convert userId => str if it's an ObjectId
        if 'userId' in l and isinstance(l['userId'], ObjectId):
            l['userId'] = str(l['userId'])

        # Convert timestamp => EST ISO
        if isinstance(l.get('timestamp'), datetime):
            l['timestamp'] = l['timestamp'].astimezone(est_tz).isoformat()

        # The rest is unchanged
        ip = l.get('ip', 'unknown')
        success = l.get('success', True)

        results.append(l)

    # You already do suspicious IP checks if you want…
    # (the main cause was the leftover ObjectId in userId)

    return jsonify({"logs": results}), 200
    
##################################################################
# DB QUERY LOGS (Reading perfSamples)
##################################################################
@cracked_bp.route('/db-logs', methods=['GET'])
def admin_db_logs():
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    limit = int(request.args.get("limit", 100))
    try:
        samples = db.perfSamples.find().sort("timestamp", -1).limit(limit)
        data = []
        est_tz = pytz.timezone('America/New_York')

        for s in samples:
            s['_id'] = str(s['_id'])
            # convert db_time_sec -> ms
            if 'db_time_sec' in s:
                s['db_time_ms'] = round(s['db_time_sec'] * 1000.0, 2)
                del s['db_time_sec']

            # convert duration_sec -> ms
            if 'duration_sec' in s:
                s['duration_ms'] = round(s['duration_sec'] * 1000.0, 2)
                del s['duration_sec']

            if isinstance(s.get('timestamp'), datetime):
                s['timestamp'] = s['timestamp'].astimezone(est_tz).isoformat()

            data.append(s)

        return jsonify(data), 200

    except Exception as e:
        return jsonify({"error": "Error retrieving DB logs", "details": str(e)}), 500


##################################################################
# READ-ONLY DB SHELL
##################################################################
@cracked_bp.route('/db-shell/read', methods=['POST'])
def admin_db_shell_read():
    """
    Body: { "collection": "mainusers", "filter": {}, "limit": 5 }
    Only performs a find() with a limit, returns JSON docs.
    """
    if not require_cracked_admin(required_role="superadmin"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    body = request.json or {}
    coll_name = body.get("collection")
    if not coll_name:
        return jsonify({"error": "No collection specified"}), 400

    if coll_name not in db.list_collection_names():
        return jsonify({"error": f"Invalid or unknown collection: {coll_name}"}), 400

    filt = body.get("filter", {})
    limit_val = int(body.get("limit", 10))

    try:
        cursor = db[coll_name].find(filt).limit(limit_val)
        results = []
        for c in cursor:
            c['_id'] = str(c['_id'])
            results.append(c)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400
        
        
@cracked_bp.route('/health-checks', methods=['GET'])
def admin_health_checks():
    """
    Returns the last ~50 health checks from the 'apiHealth' collection.
    Celery 'check_api_endpoints' task inserts these docs:
        { checkedAt: <datetime>, results: [ { endpoint, status, ok, ... } ] }
    """
    if not require_cracked_admin():
        return jsonify({"error": "Not authenticated"}), 401

    try:
        docs = db.apiHealth.find().sort("checkedAt", -1).limit(50)
        results = []
        est_tz = pytz.timezone('America/New_York')

        for d in docs:
            # Convert _id => str
            d['_id'] = str(d['_id'])
            # Convert checkedAt => EST
            if 'checkedAt' in d and isinstance(d['checkedAt'], datetime):
                d['checkedAt'] = d['checkedAt'].astimezone(est_tz).isoformat()
            # d['results'] is typically an array of endpoint checks
            # Each item is {endpoint, status, ok, error?}
            # No special serialization is needed if they’re just strings/integers.
            results.append(d)

        return jsonify(results), 200
    except Exception as e:
        return jsonify({"error": "Error retrieving health checks", "details": str(e)}), 500
        

