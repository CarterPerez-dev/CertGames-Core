# backend/routes/main/flashcard_routes.py
from flask import request, jsonify, g, Blueprint
from mongodb.database import db, mainusers_collection
from models.test import update_user_xp, update_user_coins, get_user_by_id
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import time
from .utils import check_and_unlock_achievements
from .blueprint import api_bp

# Collection references
flashcard_categories_collection = db.flashcardCategories
flashcards_collection = db.flashcards
saved_flashcards_collection = db.savedFlashcards
flashcard_progress_collection = db.flashcardProgress
flashcard_difficulty_collection = db.flashcardDifficulty

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
    limit = int(request.args.get('limit', 100))  # Increased limit for better user experience
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
            # Get the flashcard details for more context
            flashcard = flashcards_collection.find_one({"_id": flashcard_oid})
            
            # Create a more detailed saved record
            saved_record = {
                "userId": user_oid,
                "flashcardId": flashcard_oid,
                "savedAt": datetime.utcnow(),
                "categoryId": flashcard.get("categoryId") if flashcard else None,
                "categoryCode": flashcard.get("categoryCode") if flashcard else None,
                "categoryName": flashcard.get("categoryName") if flashcard else None
            }
            
            saved_flashcards_collection.insert_one(saved_record)
            duration = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration
            
            # Add small reward for saving a card
            update_user_xp(user_id, 2)
            update_user_coins(user_id, 1)
            
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
            
            # Add savedAt timestamp
            for record in saved_records:
                if record["flashcardId"] == card["_id"]:
                    card['savedAt'] = record.get("savedAt")
                    break
        
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
    session_stats = data.get('sessionStats', {})  # Optional detailed session stats
    
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
        
        # Add session stats if provided
        if session_stats:
            progress_record["sessionStats"] = session_stats
        
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
            xp_award = 20
            coins_award = 10
            
            # Bonus for longer sessions
            if session_stats.get('duration', 0) > 300:  # 5+ minutes
                xp_award += 10
                coins_award += 5
                
            # Bonus for more cards reviewed
            if session_stats.get('cardsReviewed', 0) > 10:
                xp_award += 15
                coins_award += 8
                
            # Bonus for good performance in quiz modes
            if session_stats.get('correct', 0) > 0:
                correct = session_stats.get('correct', 0)
                incorrect = session_stats.get('incorrect', 0)
                total = correct + incorrect
                
                if total > 0:
                    correct_ratio = correct / total
                    if correct_ratio >= 0.8:  # 80%+ success rate
                        xp_award += 25
                        coins_award += 15
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
        # Get progress data with more sophisticated aggregation
        pipeline = [
            {"$match": {"userId": user_oid}},
            {"$sort": {"timestamp": -1}}, # Sort by most recent first
            {"$group": {
                "_id": "$categoryId",
                "lastViewed": {"$first": "$timestamp"},
                "viewed": {"$sum": {"$cond": [{"$eq": ["$interactionType", "viewed"]}, 1, 0]}},
                "answered": {"$sum": {"$cond": [{"$eq": ["$interactionType", "answered"]}, 1, 0]}},
                "completed": {"$sum": {"$cond": [{"$eq": ["$interactionType", "completed"]}, 1, 0]}},
                "streak": {"$sum": {"$cond": [{"$eq": ["$interactionType", "streak"]}, 1, 0]}},
                "interactions": {"$push": {
                    "type": "$interactionType",
                    "timestamp": "$timestamp"
                }}
            }}
        ]
        
        stats = list(flashcard_progress_collection.aggregate(pipeline))
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        
        # Get difficulty ratings
        start_db = time.time()
        difficulty_pipeline = [
            {"$match": {"userId": user_oid}},
            {"$group": {
                "_id": "$categoryId",
                "easyCount": {"$sum": {"$cond": [{"$eq": ["$difficulty", "easy"]}, 1, 0]}},
                "mediumCount": {"$sum": {"$cond": [{"$eq": ["$difficulty", "medium"]}, 1, 0]}},
                "hardCount": {"$sum": {"$cond": [{"$eq": ["$difficulty", "hard"]}, 1, 0]}}
            }}
        ]
        
        difficulty_stats = list(flashcard_difficulty_collection.aggregate(difficulty_pipeline))
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        
        # Format results in a more comprehensive structure
        formatted_stats = {}
        
        for stat in stats:
            category_id = stat["_id"]
            if category_id not in formatted_stats:
                formatted_stats[category_id] = {}
                
            formatted_stats[category_id].update({
                "viewed": stat.get("viewed", 0),
                "answered": stat.get("answered", 0),
                "completed": stat.get("completed", 0),
                "streak": stat.get("streak", 0),
                "lastViewed": stat.get("lastViewed", None)
            })
            
            # Get recent interaction history (last 5)
            recent_interactions = stat.get("interactions", [])[:5]
            formatted_stats[category_id]["recentInteractions"] = recent_interactions
        
        # Add difficulty data
        for diff_stat in difficulty_stats:
            category_id = diff_stat["_id"]
            if category_id not in formatted_stats:
                formatted_stats[category_id] = {}
                
            formatted_stats[category_id].update({
                "difficulty": {
                    "easy": diff_stat.get("easyCount", 0),
                    "medium": diff_stat.get("mediumCount", 0),
                    "hard": diff_stat.get("hardCount", 0)
                }
            })
        
        # Calculate overall stats
        total_viewed = sum(cat.get("viewed", 0) for cat in formatted_stats.values())
        total_answered = sum(cat.get("answered", 0) for cat in formatted_stats.values())
        total_completed = sum(cat.get("completed", 0) for cat in formatted_stats.values())
        
        response = {
            "categories": formatted_stats,
            "totals": {
                "viewed": total_viewed,
                "answered": total_answered,
                "completed": total_completed
            }
        }
        
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/flashcards/difficulty', methods=['POST'])
def set_flashcard_difficulty():
    """Set difficulty rating for a flashcard"""
    data = request.json
    user_id = data.get('userId')
    flashcard_id = data.get('flashcardId')
    difficulty = data.get('difficulty')  # 'easy', 'medium', 'hard'
    category_id = data.get('categoryId')
    
    if not user_id or not flashcard_id or not difficulty or not category_id:
        return jsonify({"error": "userId, flashcardId, categoryId and difficulty are required"}), 400
        
    if difficulty not in ['easy', 'medium', 'hard']:
        return jsonify({"error": "Difficulty must be 'easy', 'medium', or 'hard'"}), 400
    
    try:
        user_oid = ObjectId(user_id)
        flashcard_oid = ObjectId(flashcard_id)
        
        start_db = time.time()
        # Check if rating exists
        existing = flashcard_difficulty_collection.find_one({
            "userId": user_oid,
            "flashcardId": flashcard_oid
        })
        
        if existing:
            # Update existing
            flashcard_difficulty_collection.update_one(
                {"_id": existing["_id"]},
                {"$set": {
                    "difficulty": difficulty,
                    "updatedAt": datetime.utcnow()
                }}
            )
        else:
            # Create new rating
            flashcard_difficulty_collection.insert_one({
                "userId": user_oid,
                "flashcardId": flashcard_oid,
                "categoryId": category_id,
                "difficulty": difficulty,
                "createdAt": datetime.utcnow(),
                "updatedAt": datetime.utcnow()
            })
            
            # Small reward for first-time rating
            update_user_xp(user_id, 1)
        
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        
        return jsonify({
            "success": True,
            "message": "Difficulty rating saved"
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/flashcards/difficulty/<user_id>', methods=['GET'])
def get_flashcard_difficulties(user_id):
    """Get all difficulty ratings for a user"""
    try:
        user_oid = ObjectId(user_id)
        category_id = request.args.get('categoryId')
        
        start_db = time.time()
        # Build query
        query = {"userId": user_oid}
        if category_id:
            query["categoryId"] = category_id
            
        # Get ratings
        ratings = list(flashcard_difficulty_collection.find(query))
        
        # Format for easier client use
        formatted_ratings = {}
        for rating in ratings:
            flashcard_id = str(rating["flashcardId"])
            formatted_ratings[flashcard_id] = rating["difficulty"]
            
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        
        return jsonify(formatted_ratings), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/flashcards/progress/<user_id>', methods=['POST'])
def save_flashcard_progress(user_id):
    """Save current progress position for a category"""
    data = request.json
    category_id = data.get('categoryId')
    current_index = data.get('currentIndex', 0)
    progress_percent = data.get('progressPercent', 0)
    
    if not category_id:
        return jsonify({"error": "categoryId is required"}), 400
    
    try:
        user_oid = ObjectId(user_id)
        
        start_db = time.time()
        # Check if progress exists
        existing = db.flashcardUserProgress.find_one({
            "userId": user_oid,
            "categoryId": category_id
        })
        
        if existing:
            # Update existing
            db.flashcardUserProgress.update_one(
                {"_id": existing["_id"]},
                {"$set": {
                    "currentIndex": current_index,
                    "progressPercent": progress_percent,
                    "updatedAt": datetime.utcnow()
                }}
            )
        else:
            # Create new progress
            db.flashcardUserProgress.insert_one({
                "userId": user_oid,
                "categoryId": category_id,
                "currentIndex": current_index,
                "progressPercent": progress_percent,
                "createdAt": datetime.utcnow(),
                "updatedAt": datetime.utcnow()
            })
        
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        
        return jsonify({
            "success": True,
            "message": "Progress saved"
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/flashcards/progress/<user_id>', methods=['GET'])
def get_flashcard_progress(user_id):
    """Get saved progress for a user"""
    try:
        user_oid = ObjectId(user_id)
        category_id = request.args.get('categoryId')
        
        start_db = time.time()
        # Build query
        query = {"userId": user_oid}
        if category_id:
            query["categoryId"] = category_id
            
        # Get progress
        if category_id:
            # Single category
            progress = db.flashcardUserProgress.find_one(query)
            result = {
                "currentIndex": progress.get("currentIndex", 0),
                "progressPercent": progress.get("progressPercent", 0)
            } if progress else {
                "currentIndex": 0,
                "progressPercent": 0
            }
        else:
            # All categories
            all_progress = list(db.flashcardUserProgress.find(query))
            result = {}
            for progress in all_progress:
                cat_id = progress["categoryId"]
                result[cat_id] = {
                    "currentIndex": progress.get("currentIndex", 0),
                    "progressPercent": progress.get("progressPercent", 0)
                }
            
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
