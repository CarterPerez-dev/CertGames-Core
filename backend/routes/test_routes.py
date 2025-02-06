# test_routes.py
from flask import Blueprint, request, jsonify
from models.database import mainusers_collection
from models.test import (
    get_user_by_username,        # For login by username
    get_user_by_identifier,      # For login by username or email
    create_user,
    get_user_by_id,
    update_user_coins,
    update_user_xp,
    apply_daily_bonus,
    get_shop_items,
    purchase_item,
    get_achievements,
    get_test_by_id,
    check_and_unlock_achievements  # New achievement checking function
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

    # Use field 'usernameOrEmail' for login
    identifier = data.get("usernameOrEmail")
    password = data.get("password")

    if not identifier or not password:
        return jsonify({"error": "Username (or Email) and password are required"}), 400

    user = get_user_by_identifier(identifier)
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401

    if user.get("password") != password:
        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({
        "user_id": str(user["_id"]),
        "username": user["username"],
        "coins": user.get("coins", 0),
        "xp": user.get("xp", 0),
        "level": user.get("level", 1),
        "achievements": user.get("achievements", [])
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
    # Check for achievements after updating XP/level.
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
    items = get_shop_items()
    for item in items:
        item["_id"] = str(item["_id"])
    return jsonify(items), 200

@api_bp.route('/shop/purchase/<item_id>', methods=['POST'])
def purchase_item_route(item_id):
    data = request.json or {}
    user_id = data.get("userId")
    if not user_id:
        return jsonify({"success": False, "message": "userId is required"}), 400
    result = purchase_item(user_id, item_id)
    if result["success"]:
        return jsonify(result), 200
    return jsonify(result), 400

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



# test_routes.py
@api_bp.route('/user/<user_id>/test-progress/<test_id>', methods=['POST'])
def update_test_progress(user_id, test_id):
    """
    POST /api/test/user/<user_id>/test-progress/<test_id>
    Expects JSON with test progress data:
      {
        "currentQuestionIndex": <int>,
        "answers": <list>,
        "score": <int>,
        "finished": <bool>,
        "totalQuestions": <int>
      }
    Appends this attempt into the user's testsProgress for the given test.
    """
    data = request.json
    if not data:
        return jsonify({"error": "No progress data provided"}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    tests_progress = user.get("testsProgress", {})

    # Use a list to store multiple attempts.
    if test_id in tests_progress and isinstance(tests_progress[test_id], list):
        tests_progress[test_id].append(data)
    else:
        tests_progress[test_id] = [data]

    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"testsProgress": tests_progress}}
    )
    return jsonify({"message": "Test progress updated"}), 200

@api_bp.route('/user/<user_id>/submit-answer', methods=['POST'])
def submit_answer(user_id):
    """
    Called from the frontend whenever the user answers a question.
    The frontend sends:
      {
        "testId": <str or int>,
        "questionId": <str>,
        "correctAnswerIndex": <int>,
        "selectedIndex": <int>,
        "xpPerCorrect": <int>    # e.g. 10
        "coinsPerCorrect": <int> # e.g. 5
      }
    We'll check if 'questionId' is already recorded as correct for this test
    in user's testsProgress. If not, award XP/coins, then store it.
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

    # Make sure testsProgress structure exists
    tests_progress = user.get("testsProgress", {})
    if test_id not in tests_progress:
        tests_progress[test_id] = []
    elif not isinstance(tests_progress[test_id], list):
        tests_progress[test_id] = [tests_progress[test_id]]

    # We'll look for a 'globalCorrectQuestions' set for the user for this test
    # to track which questionIds they've previously gotten correct. We'll store
    # it in the newest attempt or create a small helper function to unify them.
    # For simplicity, let's unify it in "perTestCorrect" at the user root:
    per_test_correct = user.get("perTestCorrect", {})
    if test_id not in per_test_correct:
        per_test_correct[test_id] = set()

    # Check if user is correct
    is_correct = (selected_index == correct_index)
    # Check if they've already gotten it correct in a prior attempt
    already_correct = question_id in per_test_correct[test_id]

    awarded_xp = 0
    awarded_coins = 0

    if is_correct and not already_correct:
        # Award XP and coins
        update_user_xp(user_id, xp_per_correct)
        update_user_coins(user_id, coins_per_correct)
        # Mark question as correct
        per_test_correct[test_id].add(question_id)
        awarded_xp = xp_per_correct
        awarded_coins = coins_per_correct

    # Update the user doc
    user_updates = {"perTestCorrect": {k: list(v) for k, v in per_test_correct.items()}}
    mainusers_collection.update_one({"_id": user["_id"]}, {"$set": user_updates})

    return jsonify({
        "isCorrect": is_correct,
        "alreadyCorrect": already_correct,
        "awardedXP": awarded_xp,
        "awardedCoins": awarded_coins
    }), 200
