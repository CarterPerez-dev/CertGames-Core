# test_routes.py

from flask import Blueprint, request, jsonify
from models.database import mainusers_collection
from models.test import (
    get_user_by_username,
    get_user_by_identifier,
    create_user,
    get_user_by_id,
    update_user_coins,
    update_user_xp,
    apply_daily_bonus,
    get_shop_items,
    purchase_item,
    get_achievements,
    get_test_by_id,
    check_and_unlock_achievements
)

api_bp = Blueprint('test', __name__)

# -----------------------------
# USER ROUTES
# -----------------------------

@api_bp.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user["_id"] = str(user["_id"])
    return jsonify(user), 200

@api_bp.route('/user', methods=['POST'])
def register_user():
    user_data = request.json
    try:
        user_id = create_user(user_data)
        return jsonify({"message": "User created", "user_id": str(user_id)}), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@api_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    identifier = data.get("usernameOrEmail")
    password = data.get("password")
    if not identifier or not password:
        return jsonify({"error": "Username (or Email) and password are required"}), 400

    user = get_user_by_identifier(identifier)
    if not user or user.get("password") != password:
        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({
        "user_id": str(user["_id"]),
        "username": user["username"],
        "coins": user.get("coins", 0),
        "xp": user.get("xp", 0),
        "level": user.get("level", 1),
        "achievements": user.get("achievements", []),
        # Optional shop fields:
        "xpBoost": user.get("xpBoost", 1.0),
        "currentAvatar": str(user.get("currentAvatar")) if user.get("currentAvatar") else None,
        "nameColor": user.get("nameColor")
    }), 200

@api_bp.route('/user/<user_id>/daily-bonus', methods=['POST'])
def daily_bonus(user_id):
    result = apply_daily_bonus(user_id)
    if not result:
        return jsonify({"error": "User not found"}), 404
    return jsonify(result), 200

@api_bp.route('/user/<user_id>/add-xp', methods=['POST'])
def add_xp_route(user_id):
    data = request.json
    xp_to_add = data.get("xp", 0)
    updated = update_user_xp(user_id, xp_to_add)
    if not updated:
        return jsonify({"error": "User not found"}), 404
    new_achievements = check_and_unlock_achievements(user_id)
    updated["newAchievements"] = new_achievements
    return jsonify(updated), 200

@api_bp.route('/user/<user_id>/add-coins', methods=['POST'])
def add_coins_route(user_id):
    data = request.json
    coins_to_add = data.get("coins", 0)
    update_user_coins(user_id, coins_to_add)
    return jsonify({"message": "Coins updated"}), 200

# -----------------------------
# SHOP ROUTES
# -----------------------------

@api_bp.route('/shop', methods=['GET'])
def fetch_shop():
    """
    Returns all shop items.
    Each shop item document should include:
      - _id, type, title, description, cost, imageUrl, effectValue, unlockLevel (optional)
    """
    items = get_shop_items()
    for item in items:
        item["_id"] = str(item["_id"])
    return jsonify(items), 200

@api_bp.route('/shop/purchase/<item_id>', methods=['POST'])
def purchase_item_route(item_id):
    """
    Expects JSON: { "userId": "<>" }
    Deducts coins, adds item to purchasedItems, and updates user fields based on item type.
    """
    data = request.json or {}
    user_id = data.get("userId")
    if not user_id:
        return jsonify({"success": False, "message": "userId is required"}), 400

    result = purchase_item(user_id, item_id)
    if result["success"]:
        return jsonify(result), 200
    else:
        return jsonify(result), 400

@api_bp.route('/shop/equip', methods=['POST'])
def equip_item_route():
    """
    Allows the user to equip an avatar (or other equippable item).
    Expects JSON: { "userId": "...", "itemId": "..." }
    """
    data = request.json or {}
    user_id = data.get("userId")
    item_id = data.get("itemId")

    if not user_id or not item_id:
        return jsonify({"success": False, "message": "userId and itemId are required"}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    try:
        oid = ObjectId(item_id)
    except Exception:
        return jsonify({"success": False, "message": "Invalid item ID"}), 400

    if oid not in user.get("purchasedItems", []):
        return jsonify({"success": False, "message": "Item not purchased"}), 400

    # Optionally verify that the item is an avatar
    from models.test import shop_collection
    item_doc = shop_collection.find_one({"_id": oid})
    if not item_doc:
        return jsonify({"success": False, "message": "Item not found in shop"}), 404
    if item_doc.get("type") != "avatar":
        return jsonify({"success": False, "message": "Item is not an avatar"}), 400

    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"currentAvatar": oid}}
    )
    return jsonify({"success": True, "message": "Avatar equipped"}), 200

# -----------------------------
# ACHIEVEMENTS ROUTES
# -----------------------------

@api_bp.route('/achievements', methods=['GET'])
def fetch_achievements():
    ach_list = get_achievements()
    for ach in ach_list:
        ach["_id"] = str(ach["_id"])
    return jsonify(ach_list), 200

# -----------------------------
# TESTS ROUTES
# -----------------------------

@api_bp.route('/tests/<test_id>', methods=['GET'])
def fetch_test_by_id_route(test_id):
    test_doc = get_test_by_id(test_id)
    if not test_doc:
        return jsonify({"error": "Test not found"}), 404
    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200

# -----------------------------
# PROGRESS ROUTES
# -----------------------------

@api_bp.route('/user/<user_id>/test-progress/<test_id>', methods=['POST'])
def update_test_progress(user_id, test_id):
    """
    Expects JSON with test progress data:
      {
        "currentQuestionIndex": <int>,
        "answers": <list>,
        "score": <int>,
        "finished": <bool>,
        "totalQuestions": <int>,
        ...
      }
    Appends or updates the user's testsProgress for the given test.
    Keeps only the last 5 attempts.
    If finished==true, triggers achievement checks.
    """
    data = request.json
    if not data:
        return jsonify({"error": "No progress data provided"}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    tests_progress = user.get("testsProgress", {})
    attempts = tests_progress.get(test_id, [])
    if not isinstance(attempts, list):
        attempts = [attempts]

    attempts.append(data)
    if len(attempts) > 5:
        attempts = attempts[-5:]
    tests_progress[test_id] = attempts

    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"testsProgress": tests_progress}}
    )

    if data.get("finished"):
        newly_unlocked = check_and_unlock_achievements(user_id)
        return jsonify({
            "message": "Test progress updated, achievements checked",
            "newlyUnlocked": newly_unlocked
        }), 200

    return jsonify({"message": "Test progress updated"}), 200


@api_bp.route('/user/<user_id>/submit-answer', methods=['POST'])
def submit_answer(user_id):
    """
    Expects JSON:
      {
        "testId": <str or int>,
        "questionId": <str>,
        "correctAnswerIndex": <int>,
        "selectedIndex": <int>,
        "xpPerCorrect": <int>,
        "coinsPerCorrect": <int>
      }
    Checks if the question was already answered correctly in previous attempts.
    If not, awards XP and coins and records the question as correctly answered.
    Returns new total XP and coins.
    """
    data = request.json or {}
    test_id = str(data.get("testId"))
    question_id = data.get("questionId")
    selected_index = data.get("selectedIndex")
    correct_index = data.get("correctAnswerIndex")
    xp_per_correct = data.get("xpPerCorrect", 10)
    coins_per_correct = data.get("coinsPerCorrect", 5)

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    per_test_correct = user.get("perTestCorrect", {})
    if not isinstance(per_test_correct, dict):
        per_test_correct = {}

    if test_id not in per_test_correct:
        per_test_correct[test_id] = []

    existing_correct_set = set(per_test_correct[test_id])
    is_correct = (selected_index == correct_index)
    already_correct = question_id in existing_correct_set

    awarded_xp = 0
    awarded_coins = 0

    if is_correct and not already_correct:
        update_user_xp(user_id, xp_per_correct)
        update_user_coins(user_id, coins_per_correct)
        existing_correct_set.add(question_id)
        awarded_xp = xp_per_correct
        awarded_coins = coins_per_correct

    per_test_correct[test_id] = list(existing_correct_set)
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"perTestCorrect": per_test_correct}}
    )

    # Fetch updated user to return new totals
    updated_user = get_user_by_id(user_id)
    new_xp = updated_user.get("xp", 0)
    new_coins = updated_user.get("coins", 0)

    return jsonify({
        "isCorrect": is_correct,
        "alreadyCorrect": already_correct,
        "awardedXP": awarded_xp,
        "awardedCoins": awarded_coins,
        "newXP": new_xp,
        "newCoins": new_coins
    }), 200
