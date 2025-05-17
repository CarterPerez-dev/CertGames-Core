# backend/routes/main/flashcard_routes.py
from flask import request, jsonify, g, Blueprint
from mongodb.database import db, mainusers_collection
from models.test import update_user_xp, update_user_coins, get_user_by_id
from bson.objectid import ObjectId
from datetime import datetime
import time
from .utils import check_and_unlock_achievements
from .blueprint import api_bp

# Collection references
flashcard_categories_collection = db.flashcardCategories
flashcards_collection = db.flashcards
saved_flashcards_collection = db.savedFlashcards
flashcard_progress_collection = db.flashcardProgress

flashcard_bp = Blueprint('flashcard', __name__)

@api_bp.route('/flashcards/categories', methods=['GET'])
def get_flashcard_categories():
    """Get all flashcard categories (certification vaults)"""
    start_db = time.time()
    categories = list(flashcard_categories_collection.find({}))
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    # Convert ObjectId to string for JSON serialization
    for category in categories:
        category['_id'] = str(category['_id'])
    
    return jsonify(categories), 200

@api_bp.route('/flashcards/category/<category_id>', methods=['GET'])
def get_flashcards_by_category(category_id):
    """Get all flashcards for a specific category"""
    # Optional query parameters for pagination
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 50))
    skip = (page - 1) * limit
    
    try:
        # Handle both string IDs and ObjectId
        if ObjectId.is_valid(category_id):
            query = {"categoryId": ObjectId(category_id)}
        else:
            query = {"categoryCode": category_id}
        
        start_db = time.time()
        flashcards = list(flashcards_collection.find(query).skip(skip).limit(limit))
        total_count = flashcards_collection.count_documents(query)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        # Convert ObjectId to string for JSON serialization
        for card in flashcards:
            card['_id'] = str(card['_id'])
            if 'categoryId' in card and isinstance(card['categoryId'], ObjectId):
                card['categoryId'] = str(card['categoryId'])
        
        return jsonify({
            'flashcards': flashcards,
            'total': total_count,
            'page': page,
            'limit': limit,
            'total_pages': (total_count + limit - 1) // limit
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/flashcards/save', methods=['POST'])
def save_flashcard():
    """Save a flashcard to user's favorites"""
    data = request.json
    user_id = data.get('userId')
    flashcard_id = data.get('flashcardId')
    
    if not user_id or not flashcard_id:
        return jsonify({"error": "userId and flashcardId are required"}), 400
    
    try:
        user_oid = ObjectId(user_id)
        flashcard_oid = ObjectId(flashcard_id)
        
        # Check if already saved
        start_db = time.time()
        existing = saved_flashcards_collection.find_one({
            "userId": user_oid,
            "flashcardId": flashcard_oid
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        
        if existing:
            # If already saved, remove it (toggle functionality)
            start_db = time.time()
            saved_flashcards_collection.delete_one({"_id": existing["_id"]})
            duration = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration
            
            return jsonify({"success": True, "saved": False, "message": "Flashcard removed from saved"}), 200
        else:
            # Save the flashcard
            start_db = time.time()
            saved_flashcards_collection.insert_one({
                "userId": user_oid,
                "flashcardId": flashcard_oid,
                "savedAt": datetime.utcnow()
            })
            duration = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration
            
            return jsonify({"success": True, "saved": True, "message": "Flashcard saved successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/flashcards/saved/<user_id>', methods=['GET'])
def get_saved_flashcards(user_id):
    """Get user's saved flashcards"""
    try:
        user_oid = ObjectId(user_id)
        
        start_db = time.time()
        # Get all saved flashcard IDs for the user
        saved_records = list(saved_flashcards_collection.find({"userId": user_oid}))
        
        # Extract flashcard IDs
        flashcard_ids = [record["flashcardId"] for record in saved_records]
        
        # Get the actual flashcards
        flashcards = list(flashcards_collection.find({"_id": {"$in": flashcard_ids}}))
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        # Convert ObjectId to string for JSON serialization
        for card in flashcards:
            card['_id'] = str(card['_id'])
            if 'categoryId' in card and isinstance(card['categoryId'], ObjectId):
                card['categoryId'] = str(card['categoryId'])
        
        return jsonify(flashcards), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/flashcards/record-progress', methods=['POST'])
def record_flashcard_progress():
    """Record flashcard interaction and award XP/coins"""
    data = request.json
    user_id = data.get('userId')
    category_id = data.get('categoryId')
    interaction_type = data.get('interactionType')  # 'viewed', 'answered', 'completed', etc.
    
    if not user_id or not category_id or not interaction_type:
        return jsonify({"error": "userId, categoryId and interactionType are required"}), 400
    
    try:
        user_oid = ObjectId(user_id)
        
        # Record this interaction
        start_db = time.time()
        progress_record = {
            "userId": user_oid,
            "categoryId": category_id,
            "interactionType": interaction_type,
            "timestamp": datetime.utcnow()
        }
        
        flashcard_progress_collection.insert_one(progress_record)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        
        # Award XP and coins based on interaction type
        xp_award = 0
        coins_award = 0
        
        if interaction_type == 'viewed':
            xp_award = 2
            coins_award = 1
        elif interaction_type == 'answered':
            xp_award = 5
            coins_award = 2
        elif interaction_type == 'completed':
            xp_award = 10
            coins_award = 5
        elif interaction_type == 'streak':
            xp_award = 15
            coins_award = 8
        
        if xp_award > 0:
            update_user_xp(user_id, xp_award)
        
        if coins_award > 0:
            update_user_coins(user_id, coins_award)
            
        # Check for new achievements
        start_db = time.time()
        newly_unlocked = check_and_unlock_achievements(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        
        # Get updated user data
        start_db = time.time()
        updated_user = get_user_by_id(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        
        return jsonify({
            "success": True,
            "xpAwarded": xp_award,
            "coinsAwarded": coins_award,
            "newXP": updated_user.get("xp", 0),
            "newCoins": updated_user.get("coins", 0),
            "newlyUnlocked": newly_unlocked
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/flashcards/stats/<user_id>', methods=['GET'])
def get_flashcard_stats(user_id):
    """Get flashcard usage statistics for a user"""
    try:
        user_oid = ObjectId(user_id)
        
        start_db = time.time()
        # Count interactions by category and type
        pipeline = [
            {"$match": {"userId": user_oid}},
            {"$group": {
                "_id": {
                    "categoryId": "$categoryId",
                    "interactionType": "$interactionType"
                },
                "count": {"$sum": 1}
            }}
        ]
        
        stats = list(flashcard_progress_collection.aggregate(pipeline))
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        
        # Format results in a more usable structure
        formatted_stats = {}
        for stat in stats:
            category_id = stat["_id"]["categoryId"]
            interaction_type = stat["_id"]["interactionType"]
            count = stat["count"]
            
            if category_id not in formatted_stats:
                formatted_stats[category_id] = {}
            
            formatted_stats[category_id][interaction_type] = count
        
        return jsonify(formatted_stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
