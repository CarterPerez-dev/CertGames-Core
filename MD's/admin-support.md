ok so everything works amazing in this page, howwever whne clsing a thread on teh suers end (liek in the users support page) it says Unexpected token '<', "<!doctype "... is not valid JSON


here are some docker debug logs aswell
 | 2025-03-03 17:02:49,895 - pymongo.connection - DEBUG - {"clientId": {"$oid": "67c5cea8ce87034b66ca328d"}, "message": "Connection checked in", "serverHost": "ac-75jlsm4-lb.nmo0cjq.mongodb.net", "serverPort": 27017, "driverConnectionId": 2}         backend_service      | 2025-03-03 17:02:49,895 - app - ERROR - Exception on /support/my-chat/67c5e0b1ce87034b66ca3315/close [POST]     backend_service      | Traceback (most recent call last):                                                                              backend_service      |   File "/venv/lib/python3.11/site-packages/flask/app.py", line 1473, in wsgi_app                                backend_service      |     response = self.full_dispatch_request()                                                                     backend_service      |                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^                                                                     backend_service      |   File "/venv/lib/python3.11/site-packages/flask/app.py", line 882, in full_dispatch_request                    backend_service      |     rv = self.handle_user_exception(e)                                                                          backend_service      |          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^                                                                          backend_service      |   File "/venv/lib/python3.11/site-packages/flask_cors/extension.py", line 165, in wrapped_function              backend_service      |     return cors_after_request(app.make_response(f(*args, **kwargs)))                                            backend_service      |                                                 ^^^^^^^^^^^^^^^^^^                                              backend_service      |   File "/venv/lib/python3.11/site-packages/flask/app.py", line 880, in full_dispatch_request                    backend_service      |     rv = self.dispatch_request()                                                                                backend_service      |          ^^^^^^^^^^^^^^^^^^^^^^^                                                                                backend_service      |   File "/venv/lib/python3.11/site-packages/flask/app.py", line 865, in dispatch_request                         backend_service      |     return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]     backend_service      |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^                                    backend_service      |   File "/app/routes/support_routes.py", line 252, in user_close_specific_thread                                 backend_service      |     socketio.emit('new_message', {                                                                              backend_service      |     ^^^^^^^^                                                                                                    backend_service      | NameError: name 'socketio' is not defined        
----

additonally- i need the create button for the create a thread (on tehusers edn) needs to be ina differetn spot of something becasue if you look at this image
![image](https://github.com/user-attachments/assets/b53bc453-c708-4004-bb0b-73a8581c1c6c)

it its cutt off/ half hidden- so we need to find an alternaive palce to put it and it can be smaller aswell idk- dont chnag any ofther part of teh disgn- and also the error sesm to be backend wise so we just need to sllighly fix teh backedn BUT DO NOT EDIT ANY PART OF TEH FRONTNEND FUCNTION WISE- WE STRICTLY JUST NEED TO REARANGE/EDIT THE CREATE THREAD BUTTON WHICH IS A DESIGN THING NOT FUCNTIONLITY SO DONT EDIT ANY ACTUAL FUCNTIONLITY PLEASE.




here is some context

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
        

from flask import Blueprint, request, session, jsonify, g, current_app
from datetime import datetime
import time
from bson import ObjectId
from mongodb.database import db

support_bp = Blueprint('support', __name__, url_prefix='/support')

def require_user_logged_in():
    return bool(session.get('userId'))

@support_bp.route('/my-chat', methods=['GET'])
def list_user_threads():
    if not require_user_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session['userId']
    user_obj_id = ObjectId(user_id)

    start_db = time.time()
    # Return newest first
    threads_cursor = db.supportThreads.find({"userId": user_obj_id}).sort("updatedAt", -1)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    threads = []
    for t in threads_cursor:
        t_id = str(t['_id'])
        subject = t.get("subject", "")
        status = t.get("status", "open")
        updated_at = t.get("updatedAt")
        threads.append({
            "_id": t_id,
            "subject": subject if subject else "Untitled Thread",
            "status": status,
            "lastUpdated": updated_at.isoformat() if updated_at else None
        })
    return jsonify(threads), 200

@support_bp.route('/my-chat', methods=['POST'])
def create_user_thread():
    """
    User creates a new support thread.
    Must return the FULL THREAD object to avoid parse errors on front end.
    Emits 'new_thread' to admin room only.
    """
    if not require_user_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    data = request.json or {}
    subject = data.get('subject', '').strip()
    if not subject:
        subject = "Untitled Thread"

    user_id = session['userId']
    user_obj_id = ObjectId(user_id)
    now = datetime.utcnow()

    new_thread = {
        "userId": user_obj_id,
        "subject": subject,
        "messages": [],
        "status": "open",
        "createdAt": now,
        "updatedAt": now
    }

    start_db = time.time()
    result = db.supportThreads.insert_one(new_thread)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if result.inserted_id:
        socketio = current_app.extensions['socketio']

        thread_data = {
            "_id": str(result.inserted_id),
            "userId": str(user_obj_id),
            "subject": subject,
            "status": "open",
            "createdAt": now.isoformat(),
            "updatedAt": now.isoformat(),
            "messages": []
        }

        # Only emit to "admin" room so admins see new threads
        socketio.emit('new_thread', thread_data, room='admin')

        # Return full thread data to user
        return jsonify(thread_data), 201
    else:
        return jsonify({"error": "Failed to create thread"}), 500

@support_bp.route('/my-chat/<thread_id>', methods=['GET'])
def get_single_thread(thread_id):
    if not require_user_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session['userId']
    user_obj_id = ObjectId(user_id)
    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread ID"}), 400

    start_db = time.time()
    thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not thread:
        return jsonify({"error": "Thread not found"}), 404

    thread['_id'] = str(thread['_id'])
    thread['userId'] = str(thread['userId'])
    for m in thread.get("messages", []):
        if "timestamp" in m and isinstance(m["timestamp"], datetime):
            m["timestamp"] = m["timestamp"].isoformat()
    return jsonify(thread), 200

@support_bp.route('/my-chat/<thread_id>', methods=['POST'])
def post_message_to_thread(thread_id):
    if not require_user_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    data = request.json or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({"error": "No content"}), 400

    user_id = session['userId']
    user_obj_id = ObjectId(user_id)
    now = datetime.utcnow()

    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread ID"}), 400

    start_db = time.time()
    thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not thread:
        return jsonify({"error": "Thread not found"}), 404

    updated_status = thread.get("status", "open")
    if updated_status == "closed":
        # Re-open if user posts again
        db.supportThreads.update_one(
            {"_id": thread["_id"]},
            {
                "$push": {
                    "messages": {
                        "sender": "user",
                        "content": content,
                        "timestamp": now
                    }
                },
                "$set": {
                    "status": "open",
                    "updatedAt": now
                }
            }
        )
        msg_response = "Thread was closed. Reopened with new message"
    else:
        db.supportThreads.update_one(
            {"_id": thread["_id"]},
            {
                "$push": {
                    "messages": {
                        "sender": "user",
                        "content": content,
                        "timestamp": now
                    }
                },
                "$set": {"updatedAt": now}
            }
        )
        msg_response = "Message posted"

    # Emit to the thread's room only
    socketio = current_app.extensions['socketio']
    socketio.emit('new_message', {
        "threadId": str(thread["_id"]),
        "message": {
            "sender": "user",
            "content": content,
            "timestamp": now.isoformat()
        }
    }, room=str(thread["_id"]))

    return jsonify({"message": msg_response}), 200

@support_bp.route('/my-chat/<thread_id>/close', methods=['POST'])
def user_close_specific_thread(thread_id):
    if not require_user_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    data = request.json or {}
    content = data.get("content", "User closed the thread")
    now = datetime.utcnow()
    user_id = session['userId']
    user_obj_id = ObjectId(user_id)

    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread ID"}), 400

    start_db = time.time()
    thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not thread:
        return jsonify({"error": "Thread not found"}), 404

    if thread.get("status") == "closed":
        return jsonify({"message": "Thread is already closed"}), 200

    db.supportThreads.update_one(
        {"_id": thread["_id"]},
        {
            "$push": {
                "messages": {
                    "sender": "user",
                    "content": content,
                    "timestamp": now
                }
            },
            "$set": {
                "status": "closed",
                "updatedAt": now
            }
        }
    )

    # Let admin know user closed
    socketio.emit('new_message', {
        "threadId": str(thread["_id"]),
        "message": {
            "sender": "system",
            "content": "Thread closed by user",
            "timestamp": now.isoformat()
        }
    }, room=str(thread["_id"]))

    return jsonify({"message": "Thread closed"}), 200

import React, { useEffect, useState, useRef, useCallback } from 'react';
import { useSelector } from 'react-redux';
import { io } from 'socket.io-client';
import './SupportAskAnythingPage.css';
import { 
  FaPaperPlane, 
  FaPlus, 
  FaSync, 
  FaTimes, 
  FaInfoCircle,
  FaRegSmile,
  FaEnvelope,
  FaHourglassHalf,
  FaCommentDots,
  FaCheck,
  FaComments,
  FaCircleNotch,
  FaExclamationTriangle,
  FaCircle,
  FaArrowLeft,
  FaEllipsisH,
  FaUser,
  FaHeadset,
  FaRobot,
  FaCrown,
  FaSignal,
  FaLock,
  FaBolt
} from 'react-icons/fa';

// Keep a single socket instance at module level
let socket = null;

function SupportAskAnythingPage() {
  // Get user ID from Redux
  const userIdFromRedux = useSelector((state) => state.user.userId);
  
  // Thread and message states
  const [threads, setThreads] = useState([]);
  const [selectedThreadId, setSelectedThreadId] = useState(null);
  const [messages, setMessages] = useState([]);
  
  // UI states
  const [newThreadSubject, setNewThreadSubject] = useState('');
  const [userMessage, setUserMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [adminIsTyping, setAdminIsTyping] = useState(false);
  const [showSupportInfoPopup, setShowSupportInfoPopup] = useState(true);
  const [mobileThreadsVisible, setMobileThreadsVisible] = useState(true);
  
  // Loading and error states
  const [loadingThreads, setLoadingThreads] = useState(false);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [error, setError] = useState(null);
  const [socketStatus, setSocketStatus] = useState('disconnected');
  
  // Refs
  const chatEndRef = useRef(null);
  const messageInputRef = useRef(null);
  const processedMessagesRef = useRef(new Set()); // Track processed messages
  
  // Format timestamps
  const formatTimestamp = (ts) => {
    if (!ts) return '';
    const date = new Date(ts);
    
    // If it's today, just show the time
    const today = new Date();
    if (date.toDateString() === today.toDateString()) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    // Otherwise show date and time
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };
  
  // Get thread status icon and color
  const getStatusInfo = (status = 'open') => {
    const s = status.toLowerCase();
    
    if (s.includes('open')) {
      return { icon: <FaCircle />, label: 'Open', className: 'status-open' };
    }
    if (s.includes('pending')) {
      return { icon: <FaHourglassHalf />, label: 'Pending', className: 'status-pending' };
    }
    if (s.includes('resolved')) {
      return { icon: <FaCheck />, label: 'Resolved', className: 'status-resolved' };
    }
    if (s.includes('closed')) {
      return { icon: <FaLock />, label: 'Closed', className: 'status-closed' };
    }
    
    return { icon: <FaCircle />, label: 'Open', className: 'status-open' };
  };
  
  // Scroll to bottom of messages
  const scrollToBottom = useCallback(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, []);
  
  // Helper function to create a message signature for duplicate detection
  const createMessageSignature = (message) => {
    return `${message.sender}:${message.content}:${message.timestamp}`;
  };
  
  //////////////////////////////////////////////////////////////////////////
  // SOCKET SETUP - Initialize once and handle real-time events
  //////////////////////////////////////////////////////////////////////////
  useEffect(() => {
    // Initialize socket if not already done
    if (!socket) {
      console.log('Initializing Socket.IO for support chat...');
      socket = io(window.location.origin, {
        path: '/api/socket.io',
        transports: ['websocket'],
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000
      });
    }
    
    // Socket connection event handlers
    const handleConnect = () => {
      console.log('Support socket connected:', socket.id);
      setSocketStatus('connected');
      
      // Join user's personal room for notifications
      const userId = userIdFromRedux || localStorage.getItem('userId');
      if (userId) {
        socket.emit('join_user_room', { userId });
        console.log(`Joined user room: user_${userId}`);
      }
      
      // Re-join current thread room if there is one
      if (selectedThreadId) {
        socket.emit('join_thread', { threadId: selectedThreadId });
        console.log(`Rejoined thread room on connect: ${selectedThreadId}`);
      }
    };
    
    const handleDisconnect = () => {
      console.log('Support socket disconnected');
      setSocketStatus('disconnected');
    };
    
    const handleConnectError = (err) => {
      console.error('Socket connection error:', err);
      setSocketStatus('error');
    };
    
    const handleNewMessage = (payload) => {
      console.log('Received new_message event:', payload);
      const { threadId, message } = payload;
      
      // Add message to current thread if it's selected
      if (threadId === selectedThreadId) {
        const messageSignature = createMessageSignature(message);
        
        // Only add the message if we haven't processed it before
        if (!processedMessagesRef.current.has(messageSignature)) {
          processedMessagesRef.current.add(messageSignature);
          
          setMessages((prev) => [...prev, message]);
          scrollToBottom();
        } else {
          console.log('Duplicate message detected and ignored:', messageSignature);
        }
      }
      
      // Update thread's lastUpdated time
      setThreads((prev) =>
        prev.map((t) => {
          if (t._id === threadId) {
            return { ...t, lastUpdated: message.timestamp };
          }
          return t;
        })
      );
    };
    
    const handleNewThread = (threadData) => {
      console.log('Received new_thread event:', threadData);
      
      // Add to threads list if not already there
      setThreads((prev) => {
        if (prev.some((t) => t._id === threadData._id)) {
          return prev;
        }
        return [threadData, ...prev];
      });
      
      // Join the thread room
      socket.emit('join_thread', { threadId: threadData._id });
      console.log(`Joined new thread room: ${threadData._id}`);
    };
    
    const handleAdminTyping = (data) => {
      if (data.threadId === selectedThreadId) {
        setAdminIsTyping(true);
      }
    };
    
    const handleAdminStopTyping = (data) => {
      if (data.threadId === selectedThreadId) {
        setAdminIsTyping(false);
      }
    };
    
    // Register socket event listeners
    socket.on('connect', handleConnect);
    socket.on('disconnect', handleDisconnect);
    socket.on('connect_error', handleConnectError);
    socket.on('new_message', handleNewMessage);
    socket.on('new_thread', handleNewThread);
    socket.on('admin_typing', handleAdminTyping);
    socket.on('admin_stop_typing', handleAdminStopTyping);
    
    // If socket is already connected, manually trigger the connect handler
    if (socket.connected) {
      handleConnect();
    }
    
    // Cleanup function to remove event listeners
    return () => {
      socket.off('connect', handleConnect);
      socket.off('disconnect', handleDisconnect);
      socket.off('connect_error', handleConnectError);
      socket.off('new_message', handleNewMessage);
      socket.off('new_thread', handleNewThread);
      socket.off('admin_typing', handleAdminTyping);
      socket.off('admin_stop_typing', handleAdminStopTyping);
    };
  }, [selectedThreadId, userIdFromRedux, scrollToBottom]);
  
  //////////////////////////////////////////////////////////////////////////
  // FETCH THREADS - Get user's support threads on mount
  //////////////////////////////////////////////////////////////////////////
  const fetchUserThreads = useCallback(async () => {
    setLoadingThreads(true);
    setError(null);
    
    try {
      const res = await fetch('/api/support/my-chat', {
        method: 'GET',
        credentials: 'include'
      });
      
      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Failed to load threads');
        }
        
        const threadList = Array.isArray(data) ? data : [];
        setThreads(threadList);
        
        // Join all thread rooms if socket is connected
        if (socket && socket.connected) {
          threadList.forEach((t) => {
            socket.emit('join_thread', { threadId: t._id });
            console.log(`Joined thread room on load: ${t._id}`);
          });
        }
      } else {
        throw new Error('Server returned unexpected response format');
      }
    } catch (err) {
      setError(err.message);
      console.error('Error fetching threads:', err);
    } finally {
      setLoadingThreads(false);
    }
  }, []);
  
  useEffect(() => {
    fetchUserThreads();
  }, [fetchUserThreads]);
  
  //////////////////////////////////////////////////////////////////////////
  // CREATE THREAD - Start a new support thread
  //////////////////////////////////////////////////////////////////////////
  const createNewThread = async () => {
    if (!newThreadSubject.trim()) {
      setError('Please enter a subject for your thread');
      return;
    }
    
    setError(null);
    
    try {
      const res = await fetch('/api/support/my-chat', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject: newThreadSubject.trim() })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to create thread');
      }
      
      // Add new thread to state
      setThreads((prev) => [data, ...prev]);
      setNewThreadSubject('');
      
      // Select the newly created thread
      setSelectedThreadId(data._id);
      setMessages([]);
      
      // On mobile, show the messages panel after creating a thread
      setMobileThreadsVisible(false);
      
      // Join the thread room
      if (socket && socket.connected) {
        socket.emit('join_thread', { threadId: data._id });
        console.log(`Joined new thread: ${data._id}`);
      }
    } catch (err) {
      setError(err.message);
      console.error('Error creating thread:', err);
    }
  };
  
  //////////////////////////////////////////////////////////////////////////
  // SELECT THREAD - Load messages for a thread
  //////////////////////////////////////////////////////////////////////////
  const selectThread = async (threadId) => {
    // Skip if already selected
    if (threadId === selectedThreadId) {
      // On mobile, just toggle to messages view
      setMobileThreadsVisible(false);
      return;
    }
    
    // Leave current thread room if any
    if (selectedThreadId && socket && socket.connected) {
      socket.emit('leave_thread', { threadId: selectedThreadId });
      console.log(`Left thread room: ${selectedThreadId}`);
    }
    
    setSelectedThreadId(threadId);
    setMessages([]);
    setLoadingMessages(true);
    setError(null);
    
    // On mobile, show the messages panel
    setMobileThreadsVisible(false);
    
    // Clear the processed messages set when switching threads
    processedMessagesRef.current.clear();
    
    // Join new thread room
    if (socket && socket.connected) {
      socket.emit('join_thread', { threadId });
      console.log(`Joined thread room: ${threadId}`);
    }
    
    try {
      const res = await fetch(`/api/support/my-chat/${threadId}`, {
        method: 'GET',
        credentials: 'include'
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to load messages');
      }
      
      // Add all loaded messages to the processed messages set
      const loadedMessages = data.messages || [];
      loadedMessages.forEach(msg => {
        processedMessagesRef.current.add(createMessageSignature(msg));
      });
      
      setMessages(loadedMessages);
      scrollToBottom();
      
      // Focus on message input
      if (messageInputRef.current) {
        messageInputRef.current.focus();
      }
    } catch (err) {
      setError(err.message);
      console.error('Error loading thread messages:', err);
    } finally {
      setLoadingMessages(false);
    }
  };
  
  //////////////////////////////////////////////////////////////////////////
  // SEND MESSAGE - Send a message in the current thread
  //////////////////////////////////////////////////////////////////////////
  const sendMessage = async () => {
    if (!selectedThreadId) {
      setError('Please select a thread first');
      return;
    }
    
    if (!userMessage.trim()) {
      return;
    }
    
    setError(null);
    const messageToSend = userMessage.trim();
    
    // Optimistic update for better UX
    const optimisticMessage = {
      sender: 'user',
      content: messageToSend,
      timestamp: new Date().toISOString(),
      optimistic: true
    };
    
    setMessages((prev) => [...prev, optimisticMessage]);
    setUserMessage('');
    scrollToBottom();
    
    // Stop typing indicator
    if (socket && socket.connected && selectedThreadId) {
      socket.emit('user_stop_typing', { threadId: selectedThreadId });
    }
    setIsTyping(false);
    
    try {
      const res = await fetch(`/api/support/my-chat/${selectedThreadId}`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: messageToSend })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to send message');
      }
      
      // Update the thread's last updated time
      setThreads((prev) =>
        prev.map((t) => {
          if (t._id === selectedThreadId) {
            return { ...t, lastUpdated: new Date().toISOString() };
          }
          return t;
        })
      );
      
      // Replace optimistic message with confirmed one by refetching
      loadMessagesForThread(selectedThreadId);
    } catch (err) {
      setError(err.message);
      console.error('Error sending message:', err);
      
      // Remove optimistic message on error
      setMessages((prev) => prev.filter((msg) => !msg.optimistic));
    }
  };
  
  // Load messages for a thread
  const loadMessagesForThread = async (threadId) => {
    try {
      const res = await fetch(`/api/support/my-chat/${threadId}`, {
        credentials: 'include'
      });
      
      const data = await res.json();
      if (res.ok && data.messages) {
        // Clear previous processed messages when explicitly reloading
        processedMessagesRef.current.clear();
        
        // Add all loaded messages to the processed messages set
        data.messages.forEach(msg => {
          processedMessagesRef.current.add(createMessageSignature(msg));
        });
        
        setMessages(data.messages);
        scrollToBottom();
      }
    } catch (err) {
      console.error('Error reloading messages:', err);
    }
  };
  
  //////////////////////////////////////////////////////////////////////////
  // TYPING HANDLERS - Handle user typing events
  //////////////////////////////////////////////////////////////////////////
  const handleTyping = (e) => {
    const val = e.target.value;
    setUserMessage(val);
    
    // Emit typing events
    if (socket && socket.connected && selectedThreadId) {
      if (!isTyping && val.trim().length > 0) {
        socket.emit('user_typing', { threadId: selectedThreadId });
        setIsTyping(true);
      } else if (isTyping && val.trim().length === 0) {
        socket.emit('user_stop_typing', { threadId: selectedThreadId });
        setIsTyping(false);
      }
    }
  };
  
  // Handle message input keydown (for Enter key)
  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };
  
  // Close thread (user-initiated)
  const closeThread = async () => {
    if (!selectedThreadId) return;
    
    if (!window.confirm('Are you sure you want to close this thread?')) {
      return;
    }
    
    try {
      const res = await fetch(`/api/support/my-chat/${selectedThreadId}/close`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: 'Thread closed by user' })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to close thread');
      }
      
      // Update thread status in the list
      setThreads((prev) =>
        prev.map((t) => {
          if (t._id === selectedThreadId) {
            return { ...t, status: 'closed' };
          }
          return t;
        })
      );
      
      // Reload messages to show closure message
      loadMessagesForThread(selectedThreadId);
    } catch (err) {
      setError(err.message);
      console.error('Error closing thread:', err);
    }
  };
  
  // Get selected thread data
  const selectedThread = threads.find(t => t._id === selectedThreadId);
  const isThreadClosed = selectedThread?.status?.toLowerCase() === 'closed';
  
  // Handle back button on mobile
  const handleBackToThreads = () => {
    setMobileThreadsVisible(true);
  };
  
  return (
    <div className="support-container">
      <div className="support-header">
        <h1 className="support-title">
          <FaHeadset className="support-title-icon" />
          Support / Ask Anything
        </h1>
        
        {showSupportInfoPopup && (
          <div className="support-info-banner">
            <div className="support-info-content">
              <FaBolt className="support-info-icon" />
              <span>We typically respond within 1-24 hours (average ~3 hours)</span>
            </div>
            <button 
              className="support-info-close" 
              onClick={() => setShowSupportInfoPopup(false)}
              aria-label="Close information banner"
            >
              <FaTimes />
            </button>
          </div>
        )}
        
        <p className="support-subtitle">
          Ask us anything about exams, this website, or technical issues. We're here to help!
        </p>
      </div>
      
      {error && (
        <div className="support-error-alert">
          <FaExclamationTriangle className="support-error-icon" />
          <span>{error}</span>
          <button 
            onClick={() => setError(null)}
            aria-label="Dismiss error"
            className="support-error-close"
          >
            <FaTimes />
          </button>
        </div>
      )}
      
      <div className="support-connection-status">
        <span className={`status-indicator status-${socketStatus}`}></span>
        <span className="status-text">
          {socketStatus === 'connected' 
            ? 'Real-time connection active' 
            : socketStatus === 'disconnected'
              ? 'Connecting to real-time service...'
              : 'Connection error - messages may be delayed'}
        </span>
      </div>
      
      <div className={`support-layout ${mobileThreadsVisible ? 'show-threads-mobile' : 'show-messages-mobile'}`}>
        {/* THREADS PANEL */}
        <div className="support-threads-panel">
          <div className="threads-header">
            <h2><FaComments className="threads-header-icon" /> Your Conversations</h2>
            <button 
              className="refresh-button" 
              onClick={fetchUserThreads} 
              title="Refresh threads"
              aria-label="Refresh conversations"
            >
              <FaSync />
            </button>
          </div>
          
          <div className="create-thread-form">
            <input
              type="text"
              placeholder="New conversation subject..."
              value={newThreadSubject}
              onChange={(e) => setNewThreadSubject(e.target.value)}
              className="create-thread-input"
              aria-label="New conversation subject"
            />
            <button 
              className="create-thread-button" 
              onClick={createNewThread}
              disabled={!newThreadSubject.trim()}
              aria-label="Create new conversation"
            >
              <FaPlus />
              <span>Create</span>
            </button>
          </div>
          
          <div className="threads-list-container">
            {loadingThreads ? (
              <div className="threads-loading">
                <FaCircleNotch className="loading-icon spin" />
                <span>Loading conversations...</span>
              </div>
            ) : threads.length === 0 ? (
              <div className="threads-empty">
                <FaRegSmile className="empty-icon" />
                <p>No conversations yet</p>
                <p className="empty-hint">Create one to get started</p>
              </div>
            ) : (
              <ul className="threads-list">
                {threads.map((thread) => {
                  const statusInfo = getStatusInfo(thread.status);
                  
                  return (
                    <li 
                      key={thread._id}
                      className={`thread-item ${selectedThreadId === thread._id ? 'thread-item-active' : ''} ${thread.status?.toLowerCase() === 'closed' ? 'thread-item-closed' : ''}`}
                      onClick={() => selectThread(thread._id)}
                    >
                      <div className="thread-item-header">
                        <span className={`thread-status-indicator ${statusInfo.className}`}>
                          {statusInfo.icon}
                        </span>
                        <h3 className="thread-subject">{thread.subject}</h3>
                      </div>
                      <div className="thread-item-footer">
                        <span className={`thread-status ${statusInfo.className}`}>
                          {statusInfo.label}
                        </span>
                        <span className="thread-timestamp">
                          {thread.lastUpdated ? formatTimestamp(thread.lastUpdated) : 'New'}
                        </span>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
        
        {/* MESSAGES PANEL */}
        <div className="support-messages-panel">
          {!selectedThreadId ? (
            <div className="no-thread-selected">
              <FaEnvelope className="no-thread-icon" />
              <h3>No conversation selected</h3>
              <p>Choose a conversation from the list or create a new one</p>
            </div>
          ) : (
            <>
              <div className="messages-header">
                <button 
                  className="messages-back-button"
                  onClick={handleBackToThreads}
                  aria-label="Back to conversations"
                >
                  <FaArrowLeft />
                </button>
                
                <div className="selected-thread-info">
                  {selectedThread && (
                    <>
                      <span className={`selected-thread-status ${getStatusInfo(selectedThread.status).className}`}>
                        {getStatusInfo(selectedThread.status).icon}
                      </span>
                      <h2>{selectedThread.subject}</h2>
                    </>
                  )}
                </div>
                
                <div className="messages-actions">
                  {!isThreadClosed && selectedThread && (
                    <button 
                      className="close-thread-button" 
                      onClick={closeThread}
                      title="Close conversation"
                      aria-label="Close conversation"
                    >
                      <FaLock />
                      <span>Close</span>
                    </button>
                  )}
                </div>
              </div>
              
              <div className="messages-container">
                {loadingMessages ? (
                  <div className="messages-loading">
                    <FaCircleNotch className="loading-icon spin" />
                    <span>Loading messages...</span>
                  </div>
                ) : messages.length === 0 ? (
                  <div className="messages-empty">
                    <FaCommentDots className="empty-messages-icon" />
                    <p>No messages in this conversation yet</p>
                    <p className="empty-hint">Start the conversation by sending a message</p>
                  </div>
                ) : (
                  <div className="messages-list">
                    {messages.map((message, index) => {
                      const isUser = message.sender === 'user';
                      const isSystem = message.sender === 'system';
                      
                      return (
                        <div 
                          key={index}
                          className={`message ${isUser ? 'message-user' : isSystem ? 'message-system' : 'message-admin'}`}
                        >
                          <div className="message-avatar">
                            {isUser ? (
                              <FaUser className="avatar-icon user" />
                            ) : isSystem ? (
                              <FaRobot className="avatar-icon system" />
                            ) : (
                              <FaCrown className="avatar-icon admin" />
                            )}
                          </div>
                          
                          <div className="message-bubble">
                            {!isSystem && (
                              <div className="message-sender">
                                {isUser ? 'You' : 'Support Team'}
                              </div>
                            )}
                            
                            <div className="message-content">
                              {message.content}
                            </div>
                            
                            <div className="message-timestamp">
                              {formatTimestamp(message.timestamp)}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    
                    {adminIsTyping && (
                      <div className="admin-typing-indicator">
                        <FaCrown className="avatar-icon admin" />
                        <div className="typing-bubble">
                          <div className="typing-dots">
                            <span></span>
                            <span></span>
                            <span></span>
                          </div>
                          <span className="typing-text">Support Team is typing...</span>
                        </div>
                      </div>
                    )}
                    
                    <div ref={chatEndRef} />
                  </div>
                )}
              </div>
              
              <div className="message-input-container">
                {isThreadClosed ? (
                  <div className="thread-closed-notice">
                    <FaLock className="thread-closed-icon" />
                    <span>This conversation is closed. You can create a new one if needed.</span>
                  </div>
                ) : (
                  <>
                    <textarea
                      ref={messageInputRef}
                      className="message-input"
                      placeholder="Type your message here..."
                      value={userMessage}
                      onChange={handleTyping}
                      onKeyDown={handleKeyDown}
                      disabled={isThreadClosed}
                      aria-label="Message input"
                      rows={3}
                    />
                    
                    <button 
                      className="send-message-button" 
                      onClick={sendMessage}
                      disabled={!userMessage.trim() || isThreadClosed}
                      aria-label="Send message"
                    >
                      <FaPaperPlane />
                    </button>
                  </>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default SupportAskAnythingPage;

/* SupportAskAnythingPage.css - Gamified Support Chat Interface */

:root {
  --support-bg-dark: #0b0c15;
  --support-bg-card: #171a23;
  --support-accent: #6543cc;
  --support-accent-hover: #7a58e6;
  --support-accent-glow: #8a58fc;
  --support-accent-secondary: #ff4c8b;
  --support-success: #2ebb77;
  --support-error: #ff4e4e;
  --support-warning: #ffc107;
  --support-info: #3498db;
  --support-text: #e2e2e2;
  --support-text-muted: #9da8b9;
  --support-border: #2a2c3d;
  --support-input-bg: rgba(0, 0, 0, 0.2);
  --support-gradient-primary: linear-gradient(135deg, #6543cc, #8a58fc);
  --support-gradient-secondary: linear-gradient(135deg, #ff4c8b, #ff7950);
  --support-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  --support-glow: 0 0 15px rgba(134, 88, 252, 0.5);
  
  /* Status Colors */
  --status-open: #2ebb77;
  --status-pending: #ffc107;
  --status-resolved: #3498db;
  --status-closed: #9da8b9;
}

/* Main Container */
.support-container {
  font-family: 'Orbitron', 'Roboto', sans-serif;
  color: var(--support-text);
  background-color: var(--support-bg-dark);
  background-image: 
    radial-gradient(circle at 15% 25%, rgba(26, 20, 64, 0.4) 0%, transparent 45%),
    radial-gradient(circle at 75% 65%, rgba(42, 26, 89, 0.3) 0%, transparent 40%),
    repeating-linear-gradient(rgba(0, 0, 0, 0.05) 0px, rgba(0, 0, 0, 0.05) 1px, transparent 1px, transparent 10px);
  min-height: 100vh;
  width: 100%;
  padding: 20px;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
}

/* Header Section */
.support-header {
  background: var(--support-bg-card);
  border-radius: 15px;
  margin-bottom: 20px;
  padding: 25px;
  box-shadow: var(--support-shadow);
  border: 1px solid var(--support-border);
  position: relative;
  overflow: hidden;
}

.support-header::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 4px;
  background: var(--support-gradient-primary);
}

.support-title {
  display: flex;
  align-items: center;
  font-size: 28px;
  margin: 0 0 15px 0;
  background: var(--support-gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-shadow: 0 0 2px rgba(0, 0, 0, 0.5);
  font-weight: 700;
  line-height: 1.2;
}

.support-title-icon {
  margin-right: 12px;
  font-size: 1.2em;
  -webkit-text-fill-color: initial;
  background: var(--support-gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.support-subtitle {
  color: var(--support-text-muted);
  margin: 10px 0 0 0;
  font-size: 15px;
  max-width: 700px;
}

/* Information Banner */
.support-info-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: rgba(134, 88, 252, 0.1);
  border: 1px solid rgba(134, 88, 252, 0.3);
  border-radius: 10px;
  padding: 12px 20px;
  margin-top: 15px;
  animation: slideDown 0.5s ease forwards;
}

@keyframes slideDown {
  from {
    opacity: 0;
    transform: translateY(-10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.support-info-content {
  display: flex;
  align-items: center;
  gap: 12px;
}

.support-info-icon {
  color: var(--support-accent);
  font-size: 20px;
  flex-shrink: 0;
}

.support-info-close {
  background: none;
  border: none;
  color: var(--support-text-muted);
  cursor: pointer;
  font-size: 16px;
  padding: 5px;
  transition: color 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.support-info-close:hover {
  color: var(--support-text);
}

/* Error Alert */
.support-error-alert {
  background: rgba(255, 78, 78, 0.1);
  border: 1px solid rgba(255, 78, 78, 0.3);
  border-radius: 10px;
  padding: 12px 20px;
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 12px;
  animation: fadeIn 0.3s ease forwards;
}

.support-error-icon {
  color: var(--support-error);
  font-size: 18px;
  flex-shrink: 0;
}

.support-error-close {
  background: none;
  border: none;
  color: var(--support-text-muted);
  cursor: pointer;
  font-size: 16px;
  padding: 5px;
  margin-left: auto;
  transition: color 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.support-error-close:hover {
  color: var(--support-error);
}

/* Connection Status */
.support-connection-status {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 20px;
  font-size: 14px;
  color: var(--support-text-muted);
}

.status-indicator {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
}

.status-indicator.status-connected {
  background-color: var(--support-success);
  box-shadow: 0 0 8px var(--support-success);
}

.status-indicator.status-disconnected {
  background-color: var(--support-warning);
  box-shadow: 0 0 8px var(--support-warning);
  animation: pulse 1.5s infinite;
}

.status-indicator.status-error {
  background-color: var(--support-error);
  box-shadow: 0 0 8px var(--support-error);
}

@keyframes pulse {
  0% { opacity: 0.5; }
  50% { opacity: 1; }
  100% { opacity: 0.5; }
}

/* Layout */
.support-layout {
  display: grid;
  grid-template-columns: 300px 1fr;
  gap: 20px;
  flex: 1;
  height: calc(100vh - 220px);
  min-height: 400px;
}

/* Threads Panel */
.support-threads-panel {
  background: var(--support-bg-card);
  border-radius: 15px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--support-border);
  box-shadow: var(--support-shadow);
}

.threads-header {
  padding: 15px 20px;
  border-bottom: 1px solid var(--support-border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: rgba(0, 0, 0, 0.2);
}

.threads-header h2 {
  font-size: 18px;
  margin: 0;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 8px;
}

.threads-header-icon {
  color: var(--support-accent);
}

.refresh-button {
  background: none;
  border: none;
  color: var(--support-text-muted);
  cursor: pointer;
  font-size: 16px;
  width: 36px;
  height: 36px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.refresh-button:hover {
  background: rgba(255, 255, 255, 0.05);
  color: var(--support-text);
}

.create-thread-form {
  padding: 15px;
  border-bottom: 1px solid var(--support-border);
  display: flex;
  gap: 10px;
}

.create-thread-input {
  flex: 1;
  background: var(--support-input-bg);
  border: 1px solid var(--support-border);
  border-radius: 8px;
  padding: 12px 15px;
  color: var(--support-text);
  font-family: inherit;
  font-size: 14px;
  transition: border-color 0.2s;
}

.create-thread-input:focus {
  outline: none;
  border-color: var(--support-accent);
  box-shadow: var(--support-glow);
}

.create-thread-button {
  background: var(--support-gradient-primary);
  color: white;
  border: none;
  border-radius: 8px;
  padding: 0 15px;
  font-family: inherit;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 85px;
  justify-content: center;
}

.create-thread-button:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 15px rgba(134, 88, 252, 0.4);
}

.create-thread-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.threads-list-container {
  flex: 1;
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: var(--support-accent) var(--support-bg-dark);
}

.threads-list-container::-webkit-scrollbar {
  width: 6px;
}

.threads-list-container::-webkit-scrollbar-track {
  background: var(--support-bg-dark);
}

.threads-list-container::-webkit-scrollbar-thumb {
  background: var(--support-accent);
  border-radius: 10px;
}

.threads-list {
  list-style: none;
  margin: 0;
  padding: 10px;
}

.thread-item {
  padding: 15px;
  border-radius: 10px;
  margin-bottom: 8px;
  cursor: pointer;
  transition: all 0.3s;
  border: 1px solid transparent;
  background: rgba(255, 255, 255, 0.03);
}

.thread-item:hover {
  background: rgba(255, 255, 255, 0.05);
  transform: translateX(5px);
}

.thread-item-active {
  background: rgba(134, 88, 252, 0.1);
  border-color: var(--support-accent);
}

.thread-item-closed {
  opacity: 0.7;
}

.thread-item-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}

.thread-status-indicator {
  font-size: 12px;
  color: var(--status-open);
  display: flex;
  align-items: center;
  justify-content: center;
}

.thread-status-indicator.status-pending {
  color: var(--status-pending);
}

.thread-status-indicator.status-resolved {
  color: var(--status-resolved);
}

.thread-status-indicator.status-closed {
  color: var(--status-closed);
}

.thread-subject {
  font-size: 15px;
  margin: 0;
  font-weight: 500;
  flex: 1;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.thread-item-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 12px;
  color: var(--support-text-muted);
}

.thread-status {
  padding: 2px 8px;
  border-radius: 10px;
  background: rgba(46, 187, 119, 0.1);
  color: var(--status-open);
  font-weight: 500;
  text-transform: capitalize;
}

.thread-status.status-pending {
  background: rgba(255, 193, 7, 0.1);
  color: var(--status-pending);
}

.thread-status.status-resolved {
  background: rgba(52, 152, 219, 0.1);
  color: var(--status-resolved);
}

.thread-status.status-closed {
  background: rgba(157, 168, 185, 0.1);
  color: var(--status-closed);
}

.thread-timestamp {
  font-size: 11px;
}

.threads-loading,
.threads-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  text-align: center;
  height: 100%;
}

.loading-icon {
  font-size: 24px;
  color: var(--support-accent);
  margin-bottom: 15px;
}

.loading-icon.spin {
  animation: spin 1.2s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.empty-icon {
  font-size: 40px;
  color: var(--support-text-muted);
  margin-bottom: 15px;
  opacity: 0.5;
}

.threads-empty p {
  margin: 0 0 5px 0;
  font-size: 16px;
}

.empty-hint {
  color: var(--support-text-muted);
  font-size: 14px !important;
}

/* Messages Panel */
.support-messages-panel {
  background: var(--support-bg-card);
  border-radius: 15px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--support-border);
  box-shadow: var(--support-shadow);
}

.messages-header {
  padding: 15px 20px;
  border-bottom: 1px solid var(--support-border);
  display: flex;
  align-items: center;
  gap: 15px;
  background: rgba(0, 0, 0, 0.2);
}

.messages-back-button {
  display: none;
  background: none;
  border: none;
  color: var(--support-text-muted);
  cursor: pointer;
  font-size: 18px;
  width: 36px;
  height: 36px;
  border-radius: 50%;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.messages-back-button:hover {
  background: rgba(255, 255, 255, 0.05);
  color: var(--support-text);
}

.selected-thread-info {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
}

.selected-thread-status {
  font-size: 14px;
  color: var(--status-open);
  display: flex;
  align-items: center;
  justify-content: center;
}

.selected-thread-info h2 {
  font-size: 18px;
  margin: 0;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.messages-actions {
  display: flex;
  gap: 10px;
}

.close-thread-button {
  background: rgba(157, 168, 185, 0.1);
  color: var(--support-text);
  border: 1px solid var(--support-border);
  border-radius: 8px;
  padding: 8px 15px;
  font-family: inherit;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 8px;
}

.close-thread-button:hover {
  background: rgba(157, 168, 185, 0.2);
}

.messages-container {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
  scrollbar-width: thin;
  scrollbar-color: var(--support-accent) var(--support-bg-dark);
}

.messages-container::-webkit-scrollbar {
  width: 6px;
}

.messages-container::-webkit-scrollbar-track {
  background: var(--support-bg-dark);
}

.messages-container::-webkit-scrollbar-thumb {
  background: var(--support-accent);
  border-radius: 10px;
}

.no-thread-selected,
.messages-loading,
.messages-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  height: 100%;
  padding: 20px;
}

.no-thread-icon,
.empty-messages-icon {
  font-size: 48px;
  color: var(--support-text-muted);
  margin-bottom: 20px;
  opacity: 0.5;
}

.no-thread-selected h3,
.messages-empty h3 {
  font-size: 20px;
  margin: 0 0 10px 0;
}

.no-thread-selected p,
.messages-empty p {
  margin: 0 0 5px 0;
  color: var(--support-text-muted);
  font-size: 16px;
}

.messages-list {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.message {
  display: flex;
  gap: 12px;
  max-width: 85%;
  animation: fadeIn 0.3s ease;
}

.message-user {
  align-self: flex-end;
  flex-direction: row-reverse;
}

.message-admin {
  align-self: flex-start;
}

.message-system {
  align-self: center;
  max-width: 90%;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

.message-avatar {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--support-input-bg);
  flex-shrink: 0;
}

.avatar-icon {
  font-size: 18px;
}

.avatar-icon.user {
  color: var(--support-accent-secondary);
}

.avatar-icon.admin {
  color: var(--support-accent);
}

.avatar-icon.system {
  color: var(--support-info);
}

.message-bubble {
  background: var(--support-input-bg);
  border-radius: 18px;
  padding: 12px 16px;
  position: relative;
  border: 1px solid var(--support-border);
}

.message-user .message-bubble {
  background: rgba(255, 76, 139, 0.1);
  border-color: rgba(255, 76, 139, 0.3);
  border-bottom-right-radius: 4px;
}

.message-admin .message-bubble {
  background: rgba(134, 88, 252, 0.1);
  border-color: rgba(134, 88, 252, 0.3);
  border-bottom-left-radius: 4px;
}

.message-system .message-bubble {
  background: rgba(52, 152, 219, 0.1);
  border-color: rgba(52, 152, 219, 0.3);
  text-align: center;
}

.message-sender {
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 5px;
}

.message-user .message-sender {
  color: var(--support-accent-secondary);
}

.message-admin .message-sender {
  color: var(--support-accent);
}

.message-content {
  word-break: break-word;
  font-size: 15px;
  line-height: 1.5;
  white-space: pre-wrap;
  margin-bottom: 5px;
}

.message-timestamp {
  font-size: 11px;
  color: var(--support-text-muted);
  text-align: right;
}

.admin-typing-indicator {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  margin-top: 5px;
}

.typing-bubble {
  background: rgba(134, 88, 252, 0.05);
  border: 1px solid rgba(134, 88, 252, 0.2);
  border-radius: 18px;
  padding: 8px 16px;
  display: flex;
  align-items: center;
  gap: 8px;
  border-bottom-left-radius: 4px;
}

.typing-dots {
  display: flex;
  align-items: center;
  gap: 4px;
}

.typing-dots span {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--support-accent);
  animation: typingAnimation 1.4s infinite;
  opacity: 0.5;
}

.typing-dots span:nth-child(1) {
  animation-delay: 0s;
}

.typing-dots span:nth-child(2) {
  animation-delay: 0.2s;
}

.typing-dots span:nth-child(3) {
  animation-delay: 0.4s;
}

@keyframes typingAnimation {
  0%, 60%, 100% { transform: translateY(0); opacity: 0.5; }
  30% { transform: translateY(-5px); opacity: 1; }
}

.typing-text {
  font-size: 13px;
  color: var(--support-text-muted);
}

.message-input-container {
  padding: 15px;
  border-top: 1px solid var(--support-border);
  display: flex;
  gap: 12px;
  background: rgba(0, 0, 0, 0.1);
}

.message-input {
  flex: 1;
  background: var(--support-input-bg);
  border: 1px solid var(--support-border);
  border-radius: 12px;
  padding: 12px 15px;
  color: var(--support-text);
  font-family: inherit;
  font-size: 14px;
  resize: none;
  min-height: 24px;
  max-height: 120px;
  transition: border-color 0.2s;
}

.message-input:focus {
  outline: none;
  border-color: var(--support-accent);
  box-shadow: var(--support-glow);
}

.send-message-button {
  background: var(--support-gradient-primary);
  color: white;
  border: none;
  border-radius: 50%;
  width: 46px;
  height: 46px;
  font-size: 18px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.3s;
  align-self: flex-end;
  flex-shrink: 0;
  box-shadow: 0 4px 10px rgba(134, 88, 252, 0.3);
}

.send-message-button:hover:not(:disabled) {
  transform: scale(1.1);
  box-shadow: 0 6px 15px rgba(134, 88, 252, 0.4);
}

.send-message-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.thread-closed-notice {
  background: rgba(157, 168, 185, 0.1);
  color: var(--support-text-muted);
  border: 1px solid rgba(157, 168, 185, 0.3);
  border-radius: 10px;
  padding: 12px 20px;
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
  box-sizing: border-box;
}

.thread-closed-icon {
  color: var(--status-closed);
  font-size: 18px;
}

/* Responsive Styles */
@media (max-width: 992px) {
  .support-container {
    padding: 15px;
  }
  
  .support-header {
    padding: 20px;
  }
  
  .support-title {
    font-size: 24px;
  }
  
  .support-layout {
    gap: 15px;
    grid-template-columns: 250px 1fr;
  }
}

@media (max-width: 768px) {
  .support-container {
    padding: 10px;
  }
  
  .support-title {
    font-size: 22px;
  }
  
  .support-subtitle {
    font-size: 14px;
  }
  
  .support-header {
    padding: 15px;
    margin-bottom: 15px;
  }
  
  .support-info-banner {
    padding: 10px 15px;
  }
  
  .support-layout {
    display: flex;
    height: calc(100vh - 200px);
  }
  
  .support-threads-panel,
  .support-messages-panel {
    width: 100%;
    position: absolute;
    left: 0;
    right: 0;
    top: 200px;
    bottom: 10px;
    transition: transform 0.3s ease, opacity 0.3s ease;
  }
  
  .show-threads-mobile .support-threads-panel {
    transform: translateX(0);
    opacity: 1;
    z-index: 2;
  }
  
  .show-messages-mobile .support-threads-panel {
    transform: translateX(-100%);
    opacity: 0;
    z-index: 1;
  }
  
  .show-threads-mobile .support-messages-panel {
    transform: translateX(100%);
    opacity: 0;
    z-index: 1;
  }
  
  .show-messages-mobile .support-messages-panel {
    transform: translateX(0);
    opacity: 1;
    z-index: 2;
  }
  
  .messages-back-button {
    display: flex;
  }
  
  .threads-header h2,
  .selected-thread-info h2 {
    font-size: 16px;
  }
  
  .thread-item {
    padding: 12px;
  }
  
  .thread-subject {
    font-size: 14px;
  }
  
  .message-content {
    font-size: 14px;
  }
}

@media (max-width: 480px) {
  .support-title {
    font-size: 20px;
  }
  
  .support-title-icon {
    margin-right: 8px;
  }
  
  .support-subtitle {
    font-size: 13px;
  }
  
  .support-info-content {
    gap: 8px;
  }
  
  .support-info-icon {
    font-size: 16px;
  }
  
  .support-info-content span {
    font-size: 13px;
  }
  
  .create-thread-form {
    padding: 10px;
  }
  
  .create-thread-input {
    padding: 10px 12px;
    font-size: 13px;
  }
  
  .create-thread-button {
    font-size: 13px;
    padding: 0 10px;
  }
  
  .thread-item {
    padding: 10px;
  }
  
  .message {
    max-width: 90%;
  }
  
  .message-avatar {
    width: 34px;
    height: 34px;
  }
  
  .avatar-icon {
    font-size: 16px;
  }
  
  .message-bubble {
    padding: 10px 12px;
  }
  
  .message-sender {
    font-size: 13px;
  }
  
  .message-content {
    font-size: 13px;
  }
  
  .message-input {
    padding: 10px 12px;
    font-size: 13px;
  }
  
  .send-message-button {
    width: 40px;
    height: 40px;
    font-size: 16px;
  }
  
  .close-thread-button {
    padding: 6px 10px;
    font-size: 13px;
  }
  
  .close-thread-button span {
    display: none;
  }
}

/* iPhone SE and other small devices */
@media (max-width: 375px) {
  .support-title {
    font-size: 18px;
  }
  
  .support-info-content span {
    font-size: 12px;
  }
  
  .support-info-content {
    flex: 1;
  }
  
  .thread-item-header {
    margin-bottom: 6px;
  }
  
  .thread-subject {
    font-size: 13px;
  }
  
  .message-bubble {
    padding: 8px 10px;
  }
  
  .message-content {
    font-size: 12px;
  }
  
  .message-timestamp {
    font-size: 10px;
  }
}



