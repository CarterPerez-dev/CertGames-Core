# src/routes/test_routes.py

from flask import Blueprint, request, jsonify
from bson.objectid import ObjectId
from datetime import datetime

# Mongo collections
from mongodb.database import (
    mainusers_collection,
    shop_collection,
    achievements_collection,
    tests_collection,
    testAttempts_collection,
    correctAnswers_collection
)

# Models
from models.test import (
    get_user_by_identifier,
    create_user,
    get_user_by_id,
    update_user_coins,
    update_user_xp,
    apply_daily_bonus,
    get_shop_items,
    purchase_item,
    get_achievements,
    get_test_by_id_and_category,
    check_and_unlock_achievements,
    validate_username,
    validate_email,
    validate_password,
    update_user_fields,
    get_user_by_id
)

api_bp = Blueprint('test', __name__)

def serialize_user(user):
    """Helper to convert _id, etc. to strings if needed."""
    if not user:
        return None
    user['_id'] = str(user['_id'])
    if 'currentAvatar' in user and user['currentAvatar']:
        user['currentAvatar'] = str(user['currentAvatar'])
    if 'purchasedItems' in user and isinstance(user['purchasedItems'], list):
        user['purchasedItems'] = [str(item) for item in user['purchasedItems']]
    return user

# -------------------------------------------------------------------
# USER ROUTES
# -------------------------------------------------------------------

@api_bp.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user = serialize_user(user)
    # Make sure password is included in the response, if that's desired
    if "password" not in user:
        user["password"] = user.get("password")
    return jsonify(user), 200


@api_bp.route('/user', methods=['POST'])
def register_user():
    """
    Registration: /api/user
    Expects {username, email, password, confirmPassword} in JSON
    Calls create_user, returns {message, user_id} or error.
    """
    user_data = request.json or {}
    try:
        user_id = create_user(user_data)
        return jsonify({"message": "User created", "user_id": str(user_id)}), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@api_bp.route('/login', methods=['POST'])
def login():
    """
    Login: /api/login
    Expects { usernameOrEmail, password } in JSON
    If success => return user doc in JSON (serialized)
    """
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

    user = serialize_user(user)
    return jsonify({
        "user_id": user["_id"],
        "username": user["username"],
        "email": user.get("email", ""),
        "coins": user.get("coins", 0),
        "xp": user.get("xp", 0),
        "level": user.get("level", 1),
        "achievements": user.get("achievements", []),
        "xpBoost": user.get("xpBoost", 1.0),
        "currentAvatar": user.get("currentAvatar"),
        "nameColor": user.get("nameColor"),
        "purchasedItems": user.get("purchasedItems", []),
        "subscriptionActive": user.get("subscriptionActive", False),
        "password": user.get("password")
    }), 200


@api_bp.route('/user/<user_id>/daily-bonus', methods=['POST'])
def daily_bonus(user_id):
    result = apply_daily_bonus(user_id)
    if not result:
        return jsonify({"error": "User not found"}), 404
    return jsonify(result), 200


@api_bp.route('/user/<user_id>/add-xp', methods=['POST'])
def add_xp_route(user_id):
    data = request.json or {}
    xp_to_add = data.get("xp", 0)
    updated = update_user_xp(user_id, xp_to_add)
    if not updated:
        return jsonify({"error": "User not found"}), 404
    new_achievements = check_and_unlock_achievements(user_id)
    updated["newAchievements"] = new_achievements
    return jsonify(updated), 200


@api_bp.route('/user/<user_id>/add-coins', methods=['POST'])
def add_coins_route(user_id):
    data = request.json or {}
    coins_to_add = data.get("coins", 0)
    update_user_coins(user_id, coins_to_add)
    return jsonify({"message": "Coins updated"}), 200


# -------------------------------------------------------------------
# SHOP ROUTES
# -------------------------------------------------------------------

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
    else:
        return jsonify(result), 400


@api_bp.route('/shop/equip', methods=['POST'])
def equip_item_route():
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

    item_doc = shop_collection.find_one({"_id": oid})
    if not item_doc:
        return jsonify({"success": False, "message": "Item not found in shop"}), 404

    # If user hasn't purchased it, check level-based unlock
    if oid not in user.get("purchasedItems", []):
        if user.get("level", 1) < item_doc.get("unlockLevel", 1):
            return jsonify({"success": False, "message": "Item not unlocked"}), 400

    # Equip the avatar
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"currentAvatar": oid}}
    )
    return jsonify({"success": True, "message": "Avatar equipped"}), 200


# -------------------------------------------------------------------
# TESTS ROUTES
# -------------------------------------------------------------------

@api_bp.route('/tests/<test_id>', methods=['GET'])
def fetch_test_by_id_route(test_id):
    # This is your original single-parameter route
    test_doc = get_test_by_id_and_category(test_id, None)  # or your old get_test_by_id
    if not test_doc:
        return jsonify({"error": "Test not found"}), 404
    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200


@api_bp.route('/tests/<category>/<test_id>', methods=['GET'])
def fetch_test_by_category_and_id(category, test_id):
    """
    NEW route that fetches a test doc by both category and testId
    e.g. /tests/aplus/1
    """
    try:
        test_id_int = int(test_id)
    except Exception:
        return jsonify({"error": "Invalid test ID"}), 400

    test_doc = tests_collection.find_one({
        "testId": test_id_int,
        "category": category
    })
    if not test_doc:
        return jsonify({"error": "Test not found"}), 404

    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200


# -------------------------------------------------------------------
# PROGRESS / ATTEMPTS ROUTES
# -------------------------------------------------------------------

@api_bp.route('/attempts/<user_id>/<test_id>', methods=['GET'])
def get_test_attempt(user_id, test_id):
    """
    Returns either an unfinished attempt if it exists;
    otherwise returns the most recently finished attempt for that user/test.
    This version searches for testId as either an integer or a string.
    """
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = None
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    # Build query with $or for testId
    query = {"userId": user_oid, "finished": False}
    if test_id_int is not None:
        query["$or"] = [{"testId": test_id_int}, {"testId": test_id}]
    else:
        query["testId"] = test_id

    attempt = testAttempts_collection.find_one(query)

    # If no unfinished attempt, check the most recent finished one
    if not attempt:
        query_finished = {"userId": user_oid, "finished": True}
        if test_id_int is not None:
            query_finished["$or"] = [{"testId": test_id_int}, {"testId": test_id}]
        else:
            query_finished["testId"] = test_id
        attempt = testAttempts_collection.find_one(query_finished, sort=[("finishedAt", -1)])

    if not attempt:
        return jsonify({"attempt": None}), 200

    attempt["_id"] = str(attempt["_id"])
    attempt["userId"] = str(attempt["userId"])
    return jsonify({"attempt": attempt}), 200


@api_bp.route('/attempts/<user_id>/<test_id>', methods=['POST'])
def update_test_attempt(user_id, test_id):
    data = request.json or {}
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    filter_ = {"userId": user_oid, "finished": False, "$or": [{"testId": test_id_int}, {"testId": test_id}]}
    update_doc = {
        "$set": {
            "userId": user_oid,
            "testId": test_id_int if isinstance(test_id_int, int) else test_id,
            "category": data.get("category", "global"),
            "answers": data.get("answers", []),
            "score": data.get("score", 0),
            "totalQuestions": data.get("totalQuestions", 0),
            "currentQuestionIndex": data.get("currentQuestionIndex", 0),
            "shuffleOrder": data.get("shuffleOrder", []),
            "answerOrder": data.get("answerOrder", []),
            "finished": data.get("finished", False)
        }
    }
    testAttempts_collection.update_one(filter_, update_doc, upsert=True)
    return jsonify({"message": "Progress updated"}), 200


@api_bp.route('/attempts/<user_id>/<test_id>/finish', methods=['POST'])
def finish_test_attempt(user_id, test_id):
    data = request.json or {}
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    filter_ = {"userId": user_oid, "finished": False, "$or": [{"testId": test_id_int}, {"testId": test_id}]}
    update_doc = {
        "$set": {
            "finished": True,
            "finishedAt": datetime.utcnow(),
            "score": data.get("score", 0),
            "totalQuestions": data.get("totalQuestions", 0),
        }
    }
    testAttempts_collection.update_one(filter_, update_doc)

    newly_unlocked = check_and_unlock_achievements(user_id)
    return jsonify({
        "message": "Test attempt finished",
        "newlyUnlocked": newly_unlocked
    }), 200


@api_bp.route('/attempts/<user_id>/list', methods=['GET'])
def list_test_attempts(user_id):
    try:
        user_oid = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user ID"}), 400

    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=50, type=int)
    skip_count = (page - 1) * page_size

    cursor = testAttempts_collection.find(
        {"userId": user_oid}
    ).sort("finishedAt", -1).skip(skip_count).limit(page_size)

    attempts = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        doc["userId"] = str(doc["userId"])
        attempts.append(doc)

    return jsonify({
        "page": page,
        "page_size": page_size,
        "attempts": attempts
    }), 200


# -------------------------------------------------------------------
# FIRST-TIME-CORRECT ANSWERS
# -------------------------------------------------------------------
@api_bp.route('/user/<user_id>/submit-answer', methods=['POST'])
def submit_answer(user_id):
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

    is_correct = (selected_index == correct_index)
    already_correct = correctAnswers_collection.find_one({
        "userId": user["_id"],
        "testId": test_id,
        "questionId": question_id
    })

    awarded_xp = 0
    awarded_coins = 0
    if is_correct and not already_correct:
        correctAnswers_collection.insert_one({
            "userId": user["_id"],
            "testId": test_id,
            "questionId": question_id
        })
        update_user_xp(user_id, xp_per_correct)
        update_user_coins(user_id, coins_per_correct)
        awarded_xp = xp_per_correct
        awarded_coins = coins_per_correct

    updated_user = get_user_by_id(user_id)
    new_xp = updated_user.get("xp", 0)
    new_coins = updated_user.get("coins", 0)

    return jsonify({
        "isCorrect": is_correct,
        "alreadyCorrect": True if already_correct else False,
        "awardedXP": awarded_xp,
        "awardedCoins": awarded_coins,
        "newXP": new_xp,
        "newCoins": new_coins
    }), 200


# -------------------------------------------------------------------
# ACHIEVEMENTS
# -------------------------------------------------------------------
@api_bp.route('/achievements', methods=['GET'])
def fetch_achievements_route():
    ach_list = get_achievements()
    for ach in ach_list:
        ach["_id"] = str(ach["_id"])
    return jsonify(ach_list), 200


# -------------------------------------------------------------------
# Leaderboard Route
# -------------------------------------------------------------------
@api_bp.route('/leaderboard', methods=['GET'])
def get_leaderboard():
    top_users_cursor = mainusers_collection.find(
        {},
        {"username": 1, "level": 1, "xp": 1, "currentAvatar": 1}
    ).sort("level", -1).limit(100)

    results = []
    rank = 1
    for user in top_users_cursor:
        user_data = {
            "username": user.get("username", "unknown"),
            "level": user.get("level", 1),
            "xp": user.get("xp", 0),
            "rank": rank,
            "avatarUrl": None
        }
        if user.get("currentAvatar"):
            avatar_item = shop_collection.find_one({"_id": user["currentAvatar"]})
            if avatar_item and "imageUrl" in avatar_item:
                user_data["avatarUrl"] = avatar_item["imageUrl"]

        results.append(user_data)
        rank += 1

    return jsonify(results), 200


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# USERNAME/EMAIL/PASSWORD CHANGES
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
@api_bp.route('/user/change-username', methods=['POST'])
def change_username():
    data = request.json or {}
    user_id = data.get("userId")
    new_username = data.get("newUsername")
    if not user_id or not new_username:
        return jsonify({"error": "Missing userId or newUsername"}), 400

    # Validate new username using the new rules.
    valid, errors = validate_username(new_username)
    if not valid:
        return jsonify({"error": "Invalid new username", "details": errors}), 400

    # Check if username is already taken.
    if mainusers_collection.find_one({"username": new_username}):
        return jsonify({"error": "Username already taken"}), 400

    doc = get_user_by_id(user_id)
    if not doc:
        return jsonify({"error": "User not found"}), 404

    update_user_fields(user_id, {"username": new_username})
    return jsonify({"message": "Username updated"}), 200


@api_bp.route('/user/change-email', methods=['POST'])
def change_email():
    data = request.json or {}
    user_id = data.get("userId")
    new_email = data.get("newEmail")
    if not user_id or not new_email:
        return jsonify({"error": "Missing userId or newEmail"}), 400

    # Validate new email using the new rules.
    valid, errors = validate_email(new_email)
    if not valid:
        return jsonify({"error": "Invalid email", "details": errors}), 400

    if mainusers_collection.find_one({"email": new_email}):
        return jsonify({"error": "Email already in use"}), 400

    doc = get_user_by_id(user_id)
    if not doc:
        return jsonify({"error": "User not found"}), 404

    update_user_fields(user_id, {"email": new_email})
    return jsonify({"message": "Email updated"}), 200


@api_bp.route('/user/change-password', methods=['POST'])
def change_password():
    data = request.json or {}
    user_id = data.get("userId")
    old_password = data.get("oldPassword")
    new_password = data.get("newPassword")
    confirm = data.get("confirmPassword")

    if not user_id or not old_password or not new_password or not confirm:
        return jsonify({"error": "All fields are required"}), 400
    if new_password != confirm:
        return jsonify({"error": "New passwords do not match"}), 400

    # Validate the new password using the new rules.
    valid, errors = validate_password(new_password)
    if not valid:
        return jsonify({"error": "Invalid new password", "details": errors}), 400

    user_doc = get_user_by_id(user_id)
    if not user_doc:
        return jsonify({"error": "User not found"}), 404

    # NOTE: This example compares plain-text passwords.
    # In production, ensure you hash passwords and use a proper verification method.
    if user_doc.get("password") != old_password:
        return jsonify({"error": "Old password is incorrect"}), 401

    update_user_fields(user_id, {"password": new_password})
    return jsonify({"message": "Password updated"}), 200


@api_bp.route('/subscription/cancel', methods=['POST'])
def cancel_subscription():
    """
    Placeholder. Possibly set subscriptionActive=False
    """
    return jsonify({"message": "Cancel subscription placeholder"}), 200



# For single answer updates
@api_bp.route('/attempts/<user_id>/<test_id>/answer', methods=['POST'])
def update_single_answer(user_id, test_id):
    data = request.json or {}
    question_id = data.get("questionId")
    user_answer_index = data.get("userAnswerIndex")
    correct_answer_index = data.get("correctAnswerIndex")
    
    try:
        user_oid = ObjectId(user_id)
        test_id_int = int(test_id) if test_id.isdigit() else test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400
    
    # Find the attempt
    attempt = testAttempts_collection.find_one({
        "userId": user_oid, 
        "finished": False,
        "$or": [{"testId": test_id_int}, {"testId": test_id}]
    })
    
    if not attempt:
        return jsonify({"error": "Attempt not found"}), 404
    
    # Check if the answer already exists
    existing_answer_index = None
    for i, ans in enumerate(attempt.get("answers", [])):
        if ans.get("questionId") == question_id:
            existing_answer_index = i
            break
    
    if existing_answer_index is not None:
        # Update existing answer using $ positional operator
        testAttempts_collection.update_one(
            {
                "userId": user_oid,
                "finished": False,
                "$or": [{"testId": test_id_int}, {"testId": test_id}],
                "answers.questionId": question_id
            },
            {"$set": {
                "answers.$.userAnswerIndex": user_answer_index,
                "answers.$.correctAnswerIndex": correct_answer_index,
                "score": data.get("score", 0)
            }}
        )
    else:
        # Add new answer to array
        testAttempts_collection.update_one(
            {
                "userId": user_oid,
                "finished": False,
                "$or": [{"testId": test_id_int}, {"testId": test_id}]
            },
            {
                "$push": {
                    "answers": {
                        "questionId": question_id,
                        "userAnswerIndex": user_answer_index,
                        "correctAnswerIndex": correct_answer_index
                    }
                },
                "$set": {"score": data.get("score", 0)}
            }
        )
    
    return jsonify({"message": "Answer updated"}), 200

# For updating the current question position only
@api_bp.route('/attempts/<user_id>/<test_id>/position', methods=['POST'])
def update_position(user_id, test_id):
    data = request.json or {}
    current_index = data.get("currentQuestionIndex", 0)
    
    try:
        user_oid = ObjectId(user_id)
        test_id_int = int(test_id) if test_id.isdigit() else test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400
    
    testAttempts_collection.update_one(
        {
            "userId": user_oid,
            "finished": False,
            "$or": [{"testId": test_id_int}, {"testId": test_id}]
        },
        {"$set": {
            "currentQuestionIndex": current_index,
            "finished": data.get("finished", False)
        }}
    )
    
    return jsonify({"message": "Position updated"}), 200
