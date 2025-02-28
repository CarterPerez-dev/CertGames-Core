# backend/routes/support_routes.py

from flask import Blueprint, request, session, jsonify
from datetime import datetime
from bson import ObjectId
from mongodb.database import db

support_bp = Blueprint('support', __name__, url_prefix='/support')

def require_user_logged_in():
    """
    Example helper to confirm normal user is logged in (not admin).
    Adjust based on your own session logic or token-based logic.
    """
    return bool(session.get('userId'))

@support_bp.route('/my-chat', methods=['GET'])
def list_user_threads():
    """
    GET /support/my-chat
    Return an array of all threads belonging to the logged-in user.
    Each thread includes: _id, subject, status, updatedAt (optional), 
    but NOT the messages. The React code wants an array, not just one thread.
    """
    if not require_user_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session['userId']
    user_obj_id = ObjectId(user_id)

    threads_cursor = db.supportThreads.find({"userId": user_obj_id})
    threads = []
    for t in threads_cursor:
        t['_id'] = str(t['_id'])
        # Provide subject, status, etc. If there's no stored "subject," use a default
        subject = t.get("subject", "")
        status = t.get("status", "open")
        updated_at = t.get("updatedAt")
        # Return a minimal doc. The React code shows 'thread-subject' and 'thread-status'
        threads.append({
            "_id": t['_id'],
            "subject": subject if subject else "Untitled Thread",
            "status": status,
            "updatedAt": updated_at.isoformat() if updated_at else None
        })

    return jsonify(threads), 200

@support_bp.route('/my-chat', methods=['POST'])
def create_user_thread():
    """
    POST /support/my-chat
    Body: { "subject": "My new support topic" }
    Creates a brand-new thread with empty messages[].
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
        "messages": [],        # no messages until the user posts
        "status": "open",
        "createdAt": now,
        "updatedAt": now
    }
    result = db.supportThreads.insert_one(new_thread)
    if result.inserted_id:
        return jsonify({"message": "Support thread created"}), 201
    else:
        return jsonify({"error": "Failed to create thread"}), 500

@support_bp.route('/my-chat/<thread_id>', methods=['GET'])
def get_single_thread(thread_id):
    """
    GET /support/my-chat/<thread_id>
    Return the full thread doc (including messages) for the given thread.
    The React code calls this to show the conversation in the right panel.
    """
    if not require_user_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session['userId']
    user_obj_id = ObjectId(user_id)

    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread ID"}), 400

    thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
    if not thread:
        return jsonify({"error": "Thread not found"}), 404

    # Convert
    thread['_id'] = str(thread['_id'])
    thread['userId'] = str(thread['userId'])
    messages = thread.get("messages", [])
    for m in messages:
        if "timestamp" in m and isinstance(m["timestamp"], datetime):
            m["timestamp"] = m["timestamp"].isoformat()

    # Return entire doc, including messages
    return jsonify(thread), 200

@support_bp.route('/my-chat/<thread_id>', methods=['POST'])
def post_message_to_thread(thread_id):
    """
    POST /support/my-chat/<thread_id>
    Body: { "content": "Hello, I need help" }
    Appends a new message to the given thread. If the thread is closed,
    optionally re-open it.
    """
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

    thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
    if not thread:
        return jsonify({"error": "Thread not found"}), 404

    if thread.get("status") == "closed":
        # For demonstration, let's reopen if closed
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
        return jsonify({"message": "Thread was closed. Reopened with new message"}), 200
    else:
        # Just append message
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
                    "updatedAt": now
                }
            }
        )
        return jsonify({"message": "Message posted"}), 200

@support_bp.route('/my-chat/<thread_id>/close', methods=['POST'])
def user_close_specific_thread(thread_id):
    """
    POST /support/my-chat/<thread_id>/close
    Body can have: { "content": "Thanks, solved" } for a final user message
    Closes that specific thread. 
    """
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

    thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
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
    return jsonify({"message": "Thread closed"}), 200
