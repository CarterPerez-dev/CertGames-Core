# backend/routes/support_routes.py

from flask import Blueprint, request, session, jsonify
from datetime import datetime
from bson import ObjectId

from ..mongodb.database import db
from .auth_helpers import require_user_logged_in  # hypothetical helper for normal user

support_bp = Blueprint('support', __name__)

# "GET /api/test/support" => fetch user’s chat thread
@support_bp.route('/my-chat', methods=['GET'])
def get_my_support_thread():
    user_id = session.get('userId')  # however you store it
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    user_obj_id = ObjectId(user_id)
    thread = db.supportThreads.find_one({"userId": user_obj_id})
    if not thread:
        # Return empty if user has no thread
        return jsonify({"messages": []}), 200

    # Convert for JSON
    thread['_id'] = str(thread['_id'])
    thread['userId'] = str(thread['userId'])
    return jsonify(thread), 200


# "POST /api/test/support" => user sends a new message
@support_bp.route('/my-chat', methods=['POST'])
def post_my_message():
    user_id = session.get('userId')
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.json or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({"error": "No content"}), 400
    
    user_obj_id = ObjectId(user_id)
    now = datetime.utcnow()

    # 1) Try to find existing thread, else create new
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
    else:
        # push a new message
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

