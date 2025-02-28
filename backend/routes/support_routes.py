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
def get_my_support_thread():
    """
    GET /support/my-chat
    Fetch the user's chat thread. Returns messages or empty if none.
    """
    if not require_user_logged_in():
        return jsonify({"error": "Not logged in"}), 401
    
    user_id = session['userId']  # guaranteed by above
    user_obj_id = ObjectId(user_id)
    
    thread = db.supportThreads.find_one({"userId": user_obj_id})
    if not thread:
        return jsonify({"messages": [], "status": "not_found"}), 200
    
    # Convert
    thread['_id'] = str(thread['_id'])
    thread['userId'] = str(thread['userId'])
    for m in thread['messages']:
        m['timestamp'] = m['timestamp'].isoformat()
    return jsonify(thread), 200


@support_bp.route('/my-chat', methods=['POST'])
def post_my_message():
    """
    POST /support/my-chat
    Body: { "content": "Hello, I need help" }
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
    
    thread = db.supportThreads.find_one({"userId": user_obj_id})
    if not thread:
        # create new
        new_thread = {
            "userId": user_obj_id,
            "messages": [
                {
                    "sender": "user",
                    "content": content,
                    "timestamp": now
                }
            ],
            "status": "open",
            "createdAt": now,
            "updatedAt": now
        }
        db.supportThreads.insert_one(new_thread)
        return jsonify({"message": "Support thread created"}), 201
    else:
        if thread.get("status") == "closed":
            # If it's closed, optionally create a brand-new one or reopen it
            # For demonstration, let's reopen:
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
                    "$set": {"updatedAt": now}
                }
            )
            return jsonify({"message": "Message posted"}), 200


@support_bp.route('/close', methods=['POST'])
def user_close_thread():
    """
    Allow user to close their own thread if they consider it resolved.
    Body can contain an optional reason or final message: { "content": "Thanks, solved" }
    """
    if not require_user_logged_in():
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.json or {}
    content = data.get("content", "User closed the thread")
    now = datetime.utcnow()
    
    user_id = session['userId']
    user_obj_id = ObjectId(user_id)
    
    thread = db.supportThreads.find_one({"userId": user_obj_id})
    if not thread:
        return jsonify({"error": "No thread found"}), 404
    
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
