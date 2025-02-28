# ================================
# test_routes.py (UPDATED, STEP 1)
# ================================
# Removes "absolute_perfectionist", "exam_conqueror", and "memory_master" achievements;
# Optimizes achievement checks via counters; ensures we skip scanning large collections repeatedly.
# Also includes minor improvements and references to test-length selection (25,50,75,100).
# Achievements for percentage-based criteria will only apply if selectedLength == 100 (enforced in code).
# Everything else remains functionally the same.

from flask import Blueprint, request, jsonify, session
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import pytz
import time

# Mongo collections
from mongodb.database import (
    mainusers_collection,
    shop_collection,
    achievements_collection,
    tests_collection,
    testAttempts_collection,
    correctAnswers_collection,
    dailyQuestions_collection,
    dailyAnswers_collection
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
    # We will replace the old check_and_unlock_achievements with the new version below
    validate_username,
    validate_email,
    validate_password,
    update_user_fields,
    get_user_by_id,
    award_correct_answers_in_bulk
)

api_bp = Blueprint('test', __name__)

#############################################
# Leaderboard Caching Setup (15-second TTL)
#############################################
leaderboard_cache = []
leaderboard_cache_timestamp = 0
LEADERBOARD_CACHE_DURATION_MS = 15000  # 15 seconds

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

def serialize_datetime(dt):
    """Helper: convert a datetime to an ISO string (or return None)."""
    return dt.isoformat() if dt else None


# ==================================================
# NEW: Updated check_and_unlock_achievements (STEP 1)
# We rely on user["achievement_counters"] instead of scanning testAttempts.
# Also remove references to achievements we are dropping:
#   - "absolute_perfectionist"
#   - "exam_conqueror"
#   - "memory_master" (consecutive perfects)
# 
# For achievements that require "score >= X%", we only check if selectedLength == 100.
# For totalQuestions, testCount, perfectTests, etc., we use counters directly.
# ==================================================
def check_and_unlock_achievements(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return []
    # Retrieve the user's counters:
    counters = user.get("achievement_counters", {})
    unlocked = set(user.get("achievements", []))
    newly_unlocked = []

    all_ach = list(achievements_collection.find({}))  # or get_achievements()

    for ach in all_ach:
        aid = ach["achievementId"]
        # If already unlocked, skip
        if aid in unlocked:
            continue
        
        crit = ach.get("criteria", {})
        # We'll check each criterion in the simplest way possible:

        # 1) testCount => total_tests_completed
        test_count_req = crit.get("testCount")
        if test_count_req is not None:
            if counters.get("total_tests_completed", 0) >= test_count_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 2) minScore => e.g. "accuracy_king" with 90
        #    We do not have the exact per-test high score for each test in counters.
        #    We'll do a simple approach:
        #    If we want "score >= X%" once on a 100-question test, we track "highest_score_ever".
        #    If highest_score_ever >= minScore
        min_score_req = crit.get("minScore")
        if min_score_req is not None:
            # For these "score >= 90%" type achievements, only count if they took a 100 Q test
            # AND their highest_score_ever is >= that threshold
            if counters.get("highest_score_ever", 0) >= min_score_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 3) perfectTests => e.g. "perfectionist_1", "double_trouble_2", etc.
        perfect_req = crit.get("perfectTests")
        if perfect_req is not None:
            # This is the total number of perfect tests across all categories
            if counters.get("perfect_tests_count", 0) >= perfect_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 4) coins => coin achievements
        coin_req = crit.get("coins")
        if coin_req is not None:
            if user.get("coins", 0) >= coin_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 5) level => e.g. "level_up_5", "mid_tier_grinder_25", etc.
        level_req = crit.get("level")
        if level_req is not None:
            if user.get("level", 1) >= level_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 6) totalQuestions => e.g. "answer_machine_1000"
        total_q_req = crit.get("totalQuestions")
        if total_q_req is not None:
            if counters.get("total_questions_answered", 0) >= total_q_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 7) perfectTestsInCategory => "category_perfectionist"
        #    We only consider 100-question tests for "perfect" status, which we've already
        #    accounted for in the counters. So if counters says we have X perfect tests in that cat, that's all 100-length.
        perfect_in_cat_req = crit.get("perfectTestsInCategory")
        if perfect_in_cat_req is not None:
            perfect_by_cat = counters.get("perfect_tests_by_category", {})
            # If ANY category has >= needed perfect tests
            for cat_name, cat_count in perfect_by_cat.items():
                if cat_count >= perfect_in_cat_req:
                    unlocked.add(aid)
                    newly_unlocked.append(aid)
                    break
            continue

        # 8) redemption_arc => minScoreBefore + minScoreAfter
        #    If the user’s lowest_score_ever <= 40, and highest_score_ever >= 90 => this qualifies
        #    (We assume user chooses 100 Q test for these. In practice, you might check each attempt, but let's keep counters.)
        min_before = crit.get("minScoreBefore")
        min_after = crit.get("minScoreAfter")
        if min_before is not None and min_after is not None:
            # if user once had a test <= min_before and a test >= min_after
            # (both presumably on 100-length attempts)
            if (counters.get("lowest_score_ever", 100) <= min_before and
                counters.get("highest_score_ever", 0) >= min_after):
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 9) testsCompletedInCategory => "subject_finisher"
        #    "Complete all 10 tests in a category at least once, regardless of score."
        #    We can track a set or dict on user doc: counters["tests_completed_by_category"] = {cat: set([testIds])}
        #    Then if length of that set is >= 10 => done
        cat_required = crit.get("testsCompletedInCategory")
        if cat_required is not None:
            tcbc = counters.get("tests_completed_by_category", {})
            for cat_name, test_set in tcbc.items():
                if len(test_set) >= cat_required:
                    unlocked.add(aid)
                    newly_unlocked.append(aid)
                    break
            continue

        # 10) allTestsCompleted => "test_finisher"
        #     If user has counters["tests_completed_set"] size == total tests in the DB,
        #     we need to get that # from config or store it in counters, e.g. counters.get("total_tests_in_db") etc.
        if crit.get("allTestsCompleted"):
            # Possibly check:
            #   if len(user["achievement_counters"]["tests_completed_set"]) >= (some global #)
            # For now, we skip or handle if you store "all tests" = 130 or something
            # Example:
            user_completed_tests = counters.get("tests_completed_set", set())
            # If your DB says total tests is 130:
            TOTAL_TESTS = 130
            if len(user_completed_tests) >= TOTAL_TESTS:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

    # If we unlocked anything new, store in DB:
    if newly_unlocked:
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"achievements": list(unlocked)}}
        )

    return newly_unlocked


# -------------------------------------------------------------------
# USER ROUTES
# -------------------------------------------------------------------
@api_bp.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user = serialize_user(user)
    # Optionally show or hide password in response
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
        # Before creating, ensure we set up the new "achievement_counters"
        # (You can do it in create_user as well, but here's a fallback.)
        user_data.setdefault("achievement_counters", {
            "total_tests_completed": 0,
            "perfect_tests_count": 0,
            "perfect_tests_by_category": {},
            # We remove consecutive perfect logic:
            # "consecutive_perfect_streak": 0,
            "highest_score_ever": 0.0,
            "lowest_score_ever": 100.0,
            "total_questions_answered": 0,
            # optionally track tests_completed_by_category or tests_completed_set:
            # "tests_completed_by_category": {},
            # "tests_completed_set": set()
        })

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
    If success => store session['userId'] and return user doc in JSON
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

    # Store this user's ID in session so require_user_logged_in() sees them as logged in
    session['userId'] = str(user["_id"])

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

    newly_unlocked = check_and_unlock_achievements(user_id)
    return jsonify({
        "message": "Coins updated",
        "newlyUnlocked": newly_unlocked
    }), 200

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
        newly_unlocked = check_and_unlock_achievements(user_id)
        result["newly_unlocked"] = newly_unlocked
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

    # If user hasn't purchased it, check if it's level-based unlock
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
    test_doc = get_test_by_id_and_category(test_id, None)
    if not test_doc:
        return jsonify({"error": "Test not found"}), 404
    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200

@api_bp.route('/tests/<category>/<test_id>', methods=['GET'])
def fetch_test_by_category_and_id(category, test_id):
    """
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
    Returns either an unfinished attempt if it exists,
    otherwise the most recent finished attempt.
    """
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = None
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    query = {"userId": user_oid, "finished": False}
    if test_id_int is not None:
        query["$or"] = [{"testId": test_id_int}, {"testId": test_id}]
    else:
        query["testId"] = test_id

    attempt = testAttempts_collection.find_one(query)
    if not attempt:
        # If no unfinished, grab the most recent finished
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
    """
    Upserts (creates or updates) a user's test attempt document.
    Now supports 'examMode' and 'selectedLength'.
    Expects JSON with:
      {
        "category": <string>,
        "answers": [],
        "score": 0,
        "totalQuestions": <int>,
        "selectedLength": <int>,
        "currentQuestionIndex": <int>,
        "shuffleOrder": [],
        "answerOrder": [],
        "finished": <bool>,
        "examMode": <bool>
      }
    """
    data = request.json or {}
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    exam_mode_val = data.get("examMode", False)
    selected_length = data.get("selectedLength", data.get("totalQuestions", 0))

    filter_ = {
        "userId": user_oid,
        "$or": [{"testId": test_id_int}, {"testId": test_id}]
    }
    update_doc = {
        "$set": {
            "userId": user_oid,
            "testId": test_id_int if isinstance(test_id_int, int) else test_id,
            "category": data.get("category", "global"),
            "answers": data.get("answers", []),
            "score": data.get("score", 0),
            "totalQuestions": data.get("totalQuestions", 0),
            "selectedLength": selected_length,
            "currentQuestionIndex": data.get("currentQuestionIndex", 0),
            "shuffleOrder": data.get("shuffleOrder", []),
            "answerOrder": data.get("answerOrder", []),
            "finished": data.get("finished", False),
            "examMode": exam_mode_val
        }
    }
    if update_doc["$set"]["finished"] is True:
        update_doc["$set"]["finishedAt"] = datetime.utcnow()

    testAttempts_collection.update_one(filter_, update_doc, upsert=True)
    return jsonify({
        "message": "Progress updated (examMode=%s, selectedLength=%s)" % (exam_mode_val, selected_length)
    }), 200

@api_bp.route('/attempts/<user_id>/<test_id>/finish', methods=['POST'])
def finish_test_attempt(user_id, test_id):
    """
    Called when the user finishes a test attempt.
    If examMode == true => we do a bulk awarding of XP/coins for first-time correct answers.
    If examMode == false => awarding is immediate per question (already done).
    Also we do an update to user’s achievement counters here.
    """
    data = request.json or {}
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    filter_ = {
        "userId": user_oid,
        "finished": False,
        "$or": [{"testId": test_id_int}, {"testId": test_id}]
    }
    update_doc = {
        "$set": {
            "finished": True,
            "finishedAt": datetime.utcnow(),
            "score": data.get("score", 0),
            "totalQuestions": data.get("totalQuestions", 0)
        }
    }
    testAttempts_collection.update_one(filter_, update_doc)

    # Retrieve the now-finished attempt doc
    attempt_doc = testAttempts_collection.find_one({
        "userId": user_oid,
        "$or": [{"testId": test_id_int}, {"testId": test_id}],
        "finished": True
    })
    if not attempt_doc:
        return jsonify({"error": "Attempt not found after finishing."}), 404

    exam_mode = attempt_doc.get("examMode", False)
    selected_length = attempt_doc.get("selectedLength", attempt_doc.get("totalQuestions", 0))
    score = attempt_doc.get("score", 0)
    total_questions = attempt_doc.get("totalQuestions", 0)
    category = attempt_doc.get("category", "global")

    # If exam_mode => do awarding for first-time correct answers
    if exam_mode:
        award_correct_answers_in_bulk(
            user_id=user_id,
            attempt_doc=attempt_doc,
            xp_per_correct=10,
            coins_per_correct=5
        )

    # Now update user’s achievement counters in one pass:
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    counters = user.get("achievement_counters", {})
    percentage = 0
    if total_questions > 0:
        percentage = (score / total_questions) * 100

    update_ops = {"$inc": {"achievement_counters.total_tests_completed": 1}}

    # If this user is tracking "tests_completed_by_category":
    # Let's add the testId to that category's set. We can store sets in Python,
    # but in Mongo we store as an array, or we do an $addToSet operation
    # Example, if you want "subject_finisher" to track sets of test IDs:
    #     update_ops.setdefault("$addToSet", {})
    #     catField = f"achievement_counters.tests_completed_by_category.{category}"
    #     update_ops["$addToSet"][catField] = attempt_doc["testId"]
    #
    # For demonstration, we do it only if you truly want that approach:
    # cat_field = f"achievement_counters.tests_completed_by_category.{category}"
    # update_ops.setdefault("$addToSet", {})
    # update_ops["$addToSet"][cat_field] = attempt_doc["testId"]

    # If perfect test (and selectedLength == 100 to be recognized as "perfect" for achievements):
    if score == total_questions and total_questions > 0 and selected_length == 100:
        update_ops["$inc"]["achievement_counters.perfect_tests_count"] = 1
        catKey = f"achievement_counters.perfect_tests_by_category.{category}"
        update_ops["$inc"][catKey] = 1
    # We do not track consecutive streaks anymore, as memory_master is removed.

    # Highest / lowest test score if selectedLength == 100
    if selected_length == 100:
        highest_so_far = counters.get("highest_score_ever", 0.0)
        lowest_so_far = counters.get("lowest_score_ever", 100.0)
        set_ops = {}
        if percentage > highest_so_far:
            set_ops["achievement_counters.highest_score_ever"] = percentage
        if percentage < lowest_so_far:
            set_ops["achievement_counters.lowest_score_ever"] = percentage
        if set_ops:
            update_ops.setdefault("$set", {}).update(set_ops)

    # total_questions_answered => always increment by selectedLength (no matter exam mode or not)
    update_ops["$inc"]["achievement_counters.total_questions_answered"] = selected_length

    mainusers_collection.update_one({"_id": user_oid}, update_ops)

    newly_unlocked = check_and_unlock_achievements(user_id)
    updated_user = get_user_by_id(user_id)
    return jsonify({
        "message": "Test attempt finished",
        "examMode": exam_mode,
        "selectedLength": selected_length,
        "newlyUnlocked": newly_unlocked,
        "newXP": updated_user.get("xp", 0),
        "newCoins": updated_user.get("coins", 0)
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
    """
    Accepts a single answer for the current question.
    If examMode == false => immediate awarding if first-time correct.
    If examMode == true => awarding on /finish.
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

    attempt_doc = testAttempts_collection.find_one({
        "userId": user["_id"],
        "finished": False,
        "$or": [
            {"testId": int(test_id)} if test_id.isdigit() else {"testId": test_id},
            {"testId": test_id}
        ]
    })
    if not attempt_doc:
        return jsonify({"error": "No unfinished attempt doc found"}), 404

    exam_mode = attempt_doc.get("examMode", False)
    is_correct = (selected_index == correct_index)

    # Update the attempt "answers" array
    existing_answer_index = None
    for i, ans in enumerate(attempt_doc.get("answers", [])):
        if ans.get("questionId") == question_id:
            existing_answer_index = i
            break

    new_score = attempt_doc.get("score", 0)
    if existing_answer_index is not None:
        update_payload = {
            "answers.$.userAnswerIndex": selected_index,
            "answers.$.correctAnswerIndex": correct_index
        }
        if exam_mode is False and is_correct:
            new_score += 1
            update_payload["score"] = new_score

        testAttempts_collection.update_one(
            {
                "_id": attempt_doc["_id"],
                "answers.questionId": question_id
            },
            {"$set": update_payload}
        )
    else:
        new_answer_doc = {
            "questionId": question_id,
            "userAnswerIndex": selected_index,
            "correctAnswerIndex": correct_index
        }
        if exam_mode is False and is_correct:
            new_score += 1
        push_update = {"$push": {"answers": new_answer_doc}}
        if exam_mode is False and is_correct:
            push_update["$set"] = {"score": new_score}

        testAttempts_collection.update_one(
            {"_id": attempt_doc["_id"]},
            push_update
        )

    awarded_xp = 0
    awarded_coins = 0
    if exam_mode is False:
        # Check if user answered it for the first time
        already_correct = correctAnswers_collection.find_one({
            "userId": user["_id"],
            "testId": test_id,
            "questionId": question_id
        })
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
        return jsonify({
            "examMode": False,
            "isCorrect": is_correct,
            "alreadyCorrect": bool(already_correct),
            "awardedXP": awarded_xp,
            "awardedCoins": awarded_coins,
            "newXP": updated_user.get("xp", 0),
            "newCoins": updated_user.get("coins", 0)
        }), 200
    else:
        # examMode == true => store only
        return jsonify({
            "examMode": True,
            "message": "Answer stored. No immediate feedback in exam mode."
        }), 200

# -------------------------------------------------------------------
# ACHIEVEMENTS
# -------------------------------------------------------------------
@api_bp.route('/achievements', methods=['GET'])
def fetch_achievements_route():
    ach_list = list(achievements_collection.find({}))
    for ach in ach_list:
        ach["_id"] = str(ach["_id"])
    return jsonify(ach_list), 200

# -------------------------------------------------------------------
# Leaderboard Route with Lazy Loading & Pagination
# -------------------------------------------------------------------
@api_bp.route('/leaderboard', methods=['GET'])
def get_leaderboard():
    global leaderboard_cache
    global leaderboard_cache_timestamp

    now_ms = int(time.time() * 1000)
    if now_ms - leaderboard_cache_timestamp > LEADERBOARD_CACHE_DURATION_MS:
        # Re-fetch top 1000 from DB
        cursor = mainusers_collection.find(
            {},
            {"username": 1, "level": 1, "xp": 1, "currentAvatar": 1}
        ).sort("level", -1).limit(1000)

        new_results = []
        rank = 1
        for user in cursor:
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
            new_results.append(user_data)
            rank += 1

        leaderboard_cache = new_results
        leaderboard_cache_timestamp = now_ms

    try:
        skip = int(request.args.get("skip", 0))
        limit = int(request.args.get("limit", 50))
    except:
        skip, limit = 0, 50

    total_entries = len(leaderboard_cache)
    end_index = skip + limit
    if skip > total_entries:
        sliced_data = []
    else:
        sliced_data = leaderboard_cache[skip:end_index]

    return jsonify({
        "data": sliced_data,
        "total": total_entries
    }), 200

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

    valid, errors = validate_username(new_username)
    if not valid:
        return jsonify({"error": "Invalid new username", "details": errors}), 400

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

    valid, errors = validate_password(new_password)
    if not valid:
        return jsonify({"error": "Invalid new password", "details": errors}), 400

    user_doc = get_user_by_id(user_id)
    if not user_doc:
        return jsonify({"error": "User not found"}), 404

    if user_doc.get("password") != old_password:
        return jsonify({"error": "Old password is incorrect"}), 401

    update_user_fields(user_id, {"password": new_password})
    return jsonify({"message": "Password updated"}), 200

@api_bp.route('/subscription/cancel', methods=['POST'])
def cancel_subscription():
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
    
    attempt = testAttempts_collection.find_one({
        "userId": user_oid, 
        "finished": False,
        "$or": [{"testId": test_id_int}, {"testId": test_id}]
    })
    if not attempt:
        return jsonify({"error": "Attempt not found"}), 404
    
    existing_answer_index = None
    for i, ans in enumerate(attempt.get("answers", [])):
        if ans.get("questionId") == question_id:
            existing_answer_index = i
            break
    
    if existing_answer_index is not None:
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

##############################################
# DAILY QUESTION ENDPOINTS
##############################################
@api_bp.route('/user/<user_id>/daily-bonus', methods=['POST'])
def daily_bonus(user_id):
    """
    Award a daily bonus if 24 hours have passed.
    """
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    now = datetime.utcnow()
    last_claim = user.get("lastDailyClaim")
    if last_claim and (now - last_claim) < timedelta(hours=24):
        seconds_left = int(24 * 3600 - (now - last_claim).total_seconds())
        return jsonify({
            "success": False,
            "message": f"Already claimed. Next bonus in: {seconds_left} seconds",
            "newCoins": user.get("coins", 0),
            "newXP": user.get("xp", 0),
            "newLastDailyClaim": serialize_datetime(last_claim)
        }), 200
    else:
        update_user_coins(user_id, 1000)
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"lastDailyClaim": now}}
        )
        updated_user = get_user_by_id(user_id)
        newly_unlocked = check_and_unlock_achievements(user_id)
        return jsonify({
            "success": True,
            "message": "Daily bonus applied",
            "newCoins": updated_user.get("coins", 0),
            "newXP": updated_user.get("xp", 0),
            "newLastDailyClaim": serialize_datetime(updated_user.get("lastDailyClaim")),
            "newlyUnlocked": newly_unlocked
        }), 200

@api_bp.route('/daily-question', methods=['GET'])
def get_daily_question():
    user_id = request.args.get("userId")
    if not user_id:
        return jsonify({"error": "No userId provided"}), 400

    try:
        user_oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    # Example dayIndex=0
    day_index = 0

    daily_doc = dailyQuestions_collection.find_one({"dayIndex": day_index})
    if not daily_doc:
        return jsonify({"error": f"No daily question for dayIndex={day_index}"}), 404

    existing_answer = dailyAnswers_collection.find_one({
        "userId": user_oid,
        "dayIndex": day_index
    })

    response = {
        "dayIndex": day_index,
        "prompt": daily_doc.get("prompt"),
        "options": daily_doc.get("options"),
        "alreadyAnswered": bool(existing_answer)
    }
    return jsonify(response), 200

@api_bp.route('/daily-question/answer', methods=['POST'])
def submit_daily_question():
    data = request.json or {}
    user_id = data.get("userId")
    day_index = data.get("dayIndex")
    selected_index = data.get("selectedIndex")

    if not user_id or day_index is None or selected_index is None:
        return jsonify({"error": "Missing userId, dayIndex, or selectedIndex"}), 400

    try:
        user_oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    daily_doc = dailyQuestions_collection.find_one({"dayIndex": day_index})
    if not daily_doc:
        return jsonify({"error": f"No daily question for dayIndex={day_index}"}), 404

    existing = dailyAnswers_collection.find_one({
        "userId": user_oid,
        "dayIndex": day_index
    })
    if existing:
        return jsonify({"error": "You already answered today's question"}), 400

    correct_index = daily_doc.get("correctIndex", 0)
    is_correct = (selected_index == correct_index)
    awarded_coins = 250 if is_correct else 50

    dailyAnswers_collection.insert_one({
        "userId": user_oid,
        "dayIndex": day_index,
        "answeredAt": datetime.utcnow(),
        "userAnswerIndex": selected_index,
        "isCorrect": is_correct
    })

    update_user_coins(user_id, awarded_coins)
    updated_user = get_user_by_id(user_id)
    newly_unlocked = check_and_unlock_achievements(user_id)

    return jsonify({
        "message": "Answer submitted",
        "correct": is_correct,
        "awardedCoins": awarded_coins,
        "newCoins": updated_user.get("coins", 0),
        "newXP": updated_user.get("xp", 0),
        "newLastDailyClaim": serialize_datetime(updated_user.get("lastDailyClaim")),
        "newlyUnlocked": newly_unlocked
    }), 200

