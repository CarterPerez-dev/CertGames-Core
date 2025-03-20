# backend/routes/support_routes.py
from flask import Blueprint, request, session, jsonify, g, current_app
from datetime import datetime
import time
from bson import ObjectId
from mongodb.database import db

support_bp = Blueprint('support', __name__, url_prefix='/support')

def get_user_id():
    """Helper to get userId from session or request headers/body"""
    # Try to get userId from session first
    user_id = session.get('userId')
    
    # If no userId in session, try from headers or request body
    if not user_id:
        user_id = request.headers.get('X-User-Id') or (request.json or {}).get('userId')
        
    return user_id

@support_bp.route('/my-chat', methods=['GET'])
def list_user_threads():
    # Get user_id using the helper function
    user_id = get_user_id()
    
    if not user_id:
        return jsonify([]), 200  # Return empty list for non-logged in users
    
    try:
        user_obj_id = ObjectId(user_id)
    except:
        return jsonify([]), 200

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
    
    For non-logged in users, we'll create anonymous threads.
    """
    # Get user_id from session or fallback
    user_id = get_user_id()
    user_obj_id = ObjectId(user_id) if user_id else None
    
    data = request.json or {}
    subject = data.get('subject', '').strip()
    if not subject:
        subject = "Untitled Thread"

    now = datetime.utcnow()

    new_thread = {
        "userId": user_obj_id,  # Will be None for anonymous users
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
            "userId": str(user_obj_id) if user_obj_id else None,
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
    user_id = get_user_id()
    
    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread ID"}), 400

    start_db = time.time()
    # If user is logged in, only show their threads
    if user_id:
        user_obj_id = ObjectId(user_id)
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
    else:
        # For non-logged in users, check if it's an anonymous thread
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": None})
        
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not thread:
        return jsonify({"error": "Thread not found"}), 404

    thread['_id'] = str(thread['_id'])
    if thread.get('userId'):
        thread['userId'] = str(thread['userId'])
    for m in thread.get("messages", []):
        if "timestamp" in m and isinstance(m["timestamp"], datetime):
            m["timestamp"] = m["timestamp"].isoformat()
    return jsonify(thread), 200

@support_bp.route('/my-chat/<thread_id>', methods=['POST'])
def post_message_to_thread(thread_id):
    user_id = get_user_id()
    
    data = request.json or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({"error": "No content"}), 400

    now = datetime.utcnow()

    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread ID"}), 400

    start_db = time.time()
    # Query based on whether user is logged in
    if user_id:
        user_obj_id = ObjectId(user_id)
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
    else:
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": None})
        
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
    user_id = get_user_id()
    
    data = request.json or {}
    content = data.get("content", "User closed the thread")
    now = datetime.utcnow()

    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread ID"}), 400

    start_db = time.time()
    # Query based on whether user is logged in
    if user_id:
        user_obj_id = ObjectId(user_id)
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
    else:
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": None})
        
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

    # Get socketio from the current app's extensions
    socketio = current_app.extensions['socketio']

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
