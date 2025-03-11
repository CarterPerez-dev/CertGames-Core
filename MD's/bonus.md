SO i have a page in my webpage/app where you claim a bonus of coins every 24 hours, so it works perfect adn everything right now- but there is one small detail i wanna fix, so when teh bonus is claimed and you click teh button- teh button stays there and does nothing- like you get the bonus and evythting but then if you clcik it again itTHEN show the real tiem countdown of when you rnext bonus is. so i want it so teh FIRST time you click the button the button dissapears and you see teh 24 hour real time coutdown- so yu dont hawv to clcik it twice to actually see teh coudnown. so rigth now it is kinda acting as a like "you already claimed teh bonus today" no so instead you log on- go to the bonus page and click the claim bonus and get he 100 coins and it immediadly shows the real time 24 coudtdowna and just says soemhting liek "time utnil next bonus" or soemthing. cool?

so ill provide you my backend files for context and teh frontnend js and css file

perferably id liek to just have to edit the frontend to fix this issue

please output whatver file you edit in FULL, in its ENTIRITY
DO NOT ALTER/CHNAGE OR REMOVE OR BREAK ANYTHIG ELSE IN MY bonus page and strcitly only fix the claim button havibg to click twice issue

cool?

ok her ei steh backend files

# ================================
# test_routes.py
# ================================

from flask import Blueprint, request, jsonify, session, g  # <-- Added g here for DB time measurement
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import pytz
import time
from mongodb.database import db

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
    validate_username,
    validate_email,
    validate_password,
    update_user_fields,
    get_user_by_id,
    award_correct_answers_in_bulk
)

api_bp = Blueprint('test', __name__)
public_leaderboard_bp = Blueprint('public_leaderboard', __name__)
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



def check_and_unlock_achievements(user_id):
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return []

    counters = user.get("achievement_counters", {})
    unlocked = set(user.get("achievements", []))
    newly_unlocked = []

    start_db = time.time()
    all_ach = list(achievements_collection.find({}))  # or get_achievements()
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    for ach in all_ach:
        aid = ach["achievementId"]
        # If already unlocked, skip
        if aid in unlocked:
            continue

        crit = ach.get("criteria", {})

        # 1) testCount => total_tests_completed
        test_count_req = crit.get("testCount")
        if test_count_req is not None:
            if counters.get("total_tests_completed", 0) >= test_count_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 2) minScore => e.g. "accuracy_king" with 90
        min_score_req = crit.get("minScore")
        if min_score_req is not None:
            if counters.get("highest_score_ever", 0) >= min_score_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 3) perfectTests => e.g. "perfectionist_1", "double_trouble_2", etc.
        perfect_req = crit.get("perfectTests")
        if perfect_req is not None:
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
        perfect_in_cat_req = crit.get("perfectTestsInCategory")
        if perfect_in_cat_req is not None:
            perfect_by_cat = counters.get("perfect_tests_by_category", {})
            for cat_name, cat_count in perfect_by_cat.items():
                if cat_count >= perfect_in_cat_req:
                    unlocked.add(aid)
                    newly_unlocked.append(aid)
                    break
            continue

        # 8) redemption_arc => minScoreBefore + minScoreAfter
        min_before = crit.get("minScoreBefore")
        min_after = crit.get("minScoreAfter")
        if min_before is not None and min_after is not None:
            if (counters.get("lowest_score_ever", 100) <= min_before and
                counters.get("highest_score_ever", 0) >= min_after):
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 9) testsCompletedInCategory => "subject_finisher"
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
        if crit.get("allTestsCompleted"):
            user_completed_tests = counters.get("tests_completed_set", set())
            TOTAL_TESTS = 130
            if len(user_completed_tests) >= TOTAL_TESTS:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

    if newly_unlocked:
        start_db = time.time()
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"achievements": list(unlocked)}}
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    return newly_unlocked


# -------------------------------------------------------------------
# USER ROUTES
# -------------------------------------------------------------------
@api_bp.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404
    user = serialize_user(user)
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
        user_data.setdefault("achievement_counters", {
            "total_tests_completed": 0,
            "perfect_tests_count": 0,
            "perfect_tests_by_category": {},
            "highest_score_ever": 0.0,
            "lowest_score_ever": 100.0,
            "total_questions_answered": 0,
        })

        start_db = time.time()
        user_id = create_user(user_data)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"message": "User created", "user_id": str(user_id)}), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@api_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        start_db = time.time()
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": None,
            "ip": request.remote_addr or "unknown",
            "success": False,
            "reason": "No JSON data provided"
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"error": "No JSON data provided"}), 400

    identifier = data.get("usernameOrEmail")
    password = data.get("password")
    if not identifier or not password:
        start_db = time.time()
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": None,
            "ip": request.remote_addr or "unknown",
            "success": False,
            "reason": "Missing username/password"
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"error": "Username (or Email) and password are required"}), 400

    start_db = time.time()
    user = get_user_by_identifier(identifier)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user or user.get("password") != password:
        start_db = time.time()
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": None,
            "ip": request.remote_addr or "unknown",
            "success": False,
            "reason": "Invalid username or password"
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"error": "Invalid username or password"}), 401

    session['userId'] = str(user["_id"])

    start_db = time.time()
    db.auditLogs.insert_one({
        "timestamp": datetime.utcnow(),
        "userId": user["_id"],
        "ip": request.remote_addr or "unknown",
        "success": True
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

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

    start_db = time.time()
    updated = update_user_xp(user_id, xp_to_add)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not updated:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    new_achievements = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    updated["newAchievements"] = new_achievements
    return jsonify(updated), 200

@api_bp.route('/user/<user_id>/add-coins', methods=['POST'])
def add_coins_route(user_id):
    data = request.json or {}
    coins_to_add = data.get("coins", 0)

    start_db = time.time()
    update_user_coins(user_id, coins_to_add)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    newly_unlocked = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({
        "message": "Coins updated",
        "newlyUnlocked": newly_unlocked
    }), 200

# -------------------------------------------------------------------
# SHOP ROUTES
# -------------------------------------------------------------------
@api_bp.route('/shop', methods=['GET'])
def fetch_shop():
    start_db = time.time()
    items = get_shop_items()
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    for item in items:
        item["_id"] = str(item["_id"])
    return jsonify(items), 200

@api_bp.route('/shop/purchase/<item_id>', methods=['POST'])
def purchase_item_route(item_id):
    data = request.json or {}
    user_id = data.get("userId")
    if not user_id:
        return jsonify({"success": False, "message": "userId is required"}), 400

    start_db = time.time()
    result = purchase_item(user_id, item_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if result["success"]:
        start_db = time.time()
        newly_unlocked = check_and_unlock_achievements(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

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

    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    try:
        oid = ObjectId(item_id)
    except Exception:
        return jsonify({"success": False, "message": "Invalid item ID"}), 400

    start_db = time.time()
    item_doc = shop_collection.find_one({"_id": oid})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not item_doc:
        return jsonify({"success": False, "message": "Item not found in shop"}), 404

    if oid not in user.get("purchasedItems", []):
        if user.get("level", 1) < item_doc.get("unlockLevel", 1):
            return jsonify({"success": False, "message": "Item not unlocked"}), 400

    start_db = time.time()
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"currentAvatar": oid}}
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"success": True, "message": "Avatar equipped"}), 200

# -------------------------------------------------------------------
# TESTS ROUTES
# -------------------------------------------------------------------
@api_bp.route('/tests/<test_id>', methods=['GET'])
def fetch_test_by_id_route(test_id):
    start_db = time.time()
    test_doc = get_test_by_id_and_category(test_id, None)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not test_doc:
        return jsonify({"error": "Test not found"}), 404
    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200

@api_bp.route('/tests/<category>/<test_id>', methods=['GET'])
def fetch_test_by_category_and_id(category, test_id):
    try:
        test_id_int = int(test_id)
    except Exception:
        return jsonify({"error": "Invalid test ID"}), 400

    start_db = time.time()
    test_doc = tests_collection.find_one({
        "testId": test_id_int,
        "category": category
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not test_doc:
        return jsonify({"error": "Test not found"}), 404

    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200

# -------------------------------------------------------------------
# PROGRESS / ATTEMPTS ROUTES
# -------------------------------------------------------------------
@api_bp.route('/attempts/<user_id>/<test_id>', methods=['GET'])
def get_test_attempt(user_id, test_id):
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

    start_db = time.time()
    attempt = testAttempts_collection.find_one(query)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt:
        query_finished = {"userId": user_oid, "finished": True}
        if test_id_int is not None:
            query_finished["$or"] = [{"testId": test_id_int}, {"testId": test_id}]
        else:
            query_finished["testId"] = test_id

        start_db = time.time()
        attempt = testAttempts_collection.find_one(query_finished, sort=[("finishedAt", -1)])
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

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

    start_db = time.time()
    testAttempts_collection.update_one(filter_, update_doc, upsert=True)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({
        "message": "Progress updated (examMode=%s, selectedLength=%s)" % (exam_mode_val, selected_length)
    }), 200

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

    start_db = time.time()
    testAttempts_collection.update_one(filter_, update_doc)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    attempt_doc = testAttempts_collection.find_one({
        "userId": user_oid,
        "$or": [{"testId": test_id_int}, {"testId": test_id}],
        "finished": True
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt_doc:
        return jsonify({"error": "Attempt not found after finishing."}), 404

    exam_mode = attempt_doc.get("examMode", False)
    selected_length = attempt_doc.get("selectedLength", attempt_doc.get("totalQuestions", 0))
    score = attempt_doc.get("score", 0)
    total_questions = attempt_doc.get("totalQuestions", 0)
    category = attempt_doc.get("category", "global")

    if exam_mode:
        start_db = time.time()
        award_correct_answers_in_bulk(
            user_id=user_id,
            attempt_doc=attempt_doc,
            xp_per_correct=10,
            coins_per_correct=5
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404

    counters = user.get("achievement_counters", {})
    percentage = 0
    if total_questions > 0:
        percentage = (score / total_questions) * 100

    update_ops = {"$inc": {"achievement_counters.total_tests_completed": 1}}

    if score == total_questions and total_questions > 0 and selected_length == 100:
        update_ops["$inc"]["achievement_counters.perfect_tests_count"] = 1
        catKey = f"achievement_counters.perfect_tests_by_category.{category}"
        update_ops["$inc"][catKey] = 1

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

    update_ops["$inc"]["achievement_counters.total_questions_answered"] = selected_length

    start_db = time.time()
    mainusers_collection.update_one({"_id": user_oid}, update_ops)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    newly_unlocked = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    updated_user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

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

    start_db = time.time()
    cursor = testAttempts_collection.find(
        {"userId": user_oid}
    ).sort("finishedAt", -1).skip(skip_count).limit(page_size)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

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

    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    attempt_doc = testAttempts_collection.find_one({
        "userId": user["_id"],
        "finished": False,
        "$or": [
            {"testId": int(test_id)} if test_id.isdigit() else {"testId": test_id},
            {"testId": test_id}
        ]
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt_doc:
        return jsonify({"error": "No unfinished attempt doc found"}), 404

    exam_mode = attempt_doc.get("examMode", False)
    is_correct = (selected_index == correct_index)

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

        start_db = time.time()
        testAttempts_collection.update_one(
            {
                "_id": attempt_doc["_id"],
                "answers.questionId": question_id
            },
            {"$set": update_payload}
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

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

        start_db = time.time()
        testAttempts_collection.update_one(
            {"_id": attempt_doc["_id"]},
            push_update
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    awarded_xp = 0
    awarded_coins = 0
    if exam_mode is False:
        start_db = time.time()
        already_correct = correctAnswers_collection.find_one({
            "userId": user["_id"],
            "testId": test_id,
            "questionId": question_id
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        if is_correct and not already_correct:
            start_db = time.time()
            correctAnswers_collection.insert_one({
                "userId": user["_id"],
                "testId": test_id,
                "questionId": question_id
            })
            duration = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration

            start_db = time.time()
            update_user_xp(user_id, xp_per_correct)
            duration2 = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration2

            start_db = time.time()
            update_user_coins(user_id, coins_per_correct)
            duration3 = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration3

            awarded_xp = xp_per_correct
            awarded_coins = coins_per_correct

        start_db = time.time()
        updated_user = get_user_by_id(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

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
        return jsonify({
            "examMode": True,
            "message": "Answer stored. No immediate feedback in exam mode."
        }), 200

# -------------------------------------------------------------------
# ACHIEVEMENTS
# -------------------------------------------------------------------
@api_bp.route('/achievements', methods=['GET'])
def fetch_achievements_route():
    start_db = time.time()
    ach_list = list(achievements_collection.find({}))
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

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
        start_db = time.time()
        cursor = mainusers_collection.find(
            {},
            {"username": 1, "level": 1, "xp": 1, "currentAvatar": 1}
        ).sort("level", -1).limit(1000)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

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
                start_db = time.time()
                avatar_item = shop_collection.find_one({"_id": user["currentAvatar"]})
                duration = time.time() - start_db
                if not hasattr(g, 'db_time_accumulator'):
                    g.db_time_accumulator = 0.0
                g.db_time_accumulator += duration

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

    start_db = time.time()
    existing = mainusers_collection.find_one({"username": new_username})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if existing:
        return jsonify({"error": "Username already taken"}), 400

    start_db = time.time()
    doc = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not doc:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    update_user_fields(user_id, {"username": new_username})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

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

    start_db = time.time()
    existing = mainusers_collection.find_one({"email": new_email})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if existing:
        return jsonify({"error": "Email already in use"}), 400

    start_db = time.time()
    doc = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not doc:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    update_user_fields(user_id, {"email": new_email})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

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

    start_db = time.time()
    user_doc = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user_doc:
        return jsonify({"error": "User not found"}), 404

    if user_doc.get("password") != old_password:
        return jsonify({"error": "Old password is incorrect"}), 401

    start_db = time.time()
    update_user_fields(user_id, {"password": new_password})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

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

    start_db = time.time()
    attempt = testAttempts_collection.find_one({
        "userId": user_oid,
        "finished": False,
        "$or": [{"testId": test_id_int}, {"testId": test_id}]
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt:
        return jsonify({"error": "Attempt not found"}), 404

    existing_answer_index = None
    for i, ans in enumerate(attempt.get("answers", [])):
        if ans.get("questionId") == question_id:
            existing_answer_index = i
            break

    if existing_answer_index is not None:
        start_db = time.time()
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
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    else:
        start_db = time.time()
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
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

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

    start_db = time.time()
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
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"message": "Position updated"}), 200

##############################################
# DAILY QUESTION ENDPOINTS
##############################################
@api_bp.route('/user/<user_id>/daily-bonus', methods=['POST'])
def daily_bonus(user_id):
    user = None
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

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
        start_db = time.time()
        update_user_coins(user_id, 1000)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        start_db = time.time()
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"lastDailyClaim": now}}
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        start_db = time.time()
        updated_user = get_user_by_id(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        start_db = time.time()
        newly_unlocked = check_and_unlock_achievements(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

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

    day_index = 0

    start_db = time.time()
    daily_doc = dailyQuestions_collection.find_one({"dayIndex": day_index})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not daily_doc:
        return jsonify({"error": f"No daily question for dayIndex={day_index}"}), 404

    start_db = time.time()
    existing_answer = dailyAnswers_collection.find_one({
        "userId": user_oid,
        "dayIndex": day_index
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

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

    start_db = time.time()
    daily_doc = dailyQuestions_collection.find_one({"dayIndex": day_index})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not daily_doc:
        return jsonify({"error": f"No daily question for dayIndex={day_index}"}), 404

    start_db = time.time()
    existing = dailyAnswers_collection.find_one({
        "userId": user_oid,
        "dayIndex": day_index
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if existing:
        return jsonify({"error": "You already answered today's question"}), 400

    correct_index = daily_doc.get("correctIndex", 0)
    is_correct = (selected_index == correct_index)
    awarded_coins = 250 if is_correct else 50

    start_db = time.time()
    dailyAnswers_collection.insert_one({
        "userId": user_oid,
        "dayIndex": day_index,
        "answeredAt": datetime.utcnow(),
        "userAnswerIndex": selected_index,
        "isCorrect": is_correct
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    update_user_coins(str(user_oid), awarded_coins)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    updated_user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    newly_unlocked = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({
        "message": "Answer submitted",
        "correct": is_correct,
        "awardedCoins": awarded_coins,
        "newCoins": updated_user.get("coins", 0),
        "newXP": updated_user.get("xp", 0),
        "newLastDailyClaim": serialize_datetime(updated_user.get("lastDailyClaim")),
        "newlyUnlocked": newly_unlocked
    }), 200


#############################################
# Public Leaderboard Caching (30-minute TTL)
#############################################
public_leaderboard_cache = []
public_leaderboard_cache_timestamp = 0
PUBLIC_LEADERBOARD_CACHE_DURATION_MS = 1800000  # 30 minutes (1800 seconds)

@public_leaderboard_bp.route('/board', methods=['GET'])
def get_public_leaderboard():
    """
    Public leaderboard with a longer cache duration (30 minutes)
    This is for the marketing site, separate from the logged-in user leaderboard
    """
    global public_leaderboard_cache
    global public_leaderboard_cache_timestamp

    now_ms = int(time.time() * 1000)
    if now_ms - public_leaderboard_cache_timestamp > PUBLIC_LEADERBOARD_CACHE_DURATION_MS:
        start_db = time.time()
        cursor = mainusers_collection.find(
            {},
            {"username": 1, "level": 1, "xp": 1, "currentAvatar": 1}
        ).sort("level", -1).limit(1000)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

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
                start_db = time.time()
                avatar_item = shop_collection.find_one({"_id": user["currentAvatar"]})
                duration = time.time() - start_db
                if not hasattr(g, 'db_time_accumulator'):
                    g.db_time_accumulator = 0.0
                g.db_time_accumulator += duration

                if avatar_item and "imageUrl" in avatar_item:
                    user_data["avatarUrl"] = avatar_item["imageUrl"]
            new_results.append(user_data)
            rank += 1

        public_leaderboard_cache = new_results
        public_leaderboard_cache_timestamp = now_ms

    try:
        skip = int(request.args.get("skip", 0))
        limit = int(request.args.get("limit", 50))
        cache_param = request.args.get("cache", "1800")  # Default 30 minutes
    except:
        skip, limit = 0, 50

    total_entries = len(public_leaderboard_cache)
    end_index = skip + limit
    if skip > total_entries:
        sliced_data = []
    else:
        sliced_data = public_leaderboard_cache[skip:end_index]

    return jsonify({
        "data": sliced_data,
        "total": total_entries,
        "cached_at": public_leaderboard_cache_timestamp,
        "cache_duration_ms": PUBLIC_LEADERBOARD_CACHE_DURATION_MS
    }), 200



here is the frontend files


userslcie fro context

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { showAchievementToast } from './AchievementToast';
import {
  FaTrophy, FaMedal, FaStar, FaCrown, FaBolt, FaBook, FaBrain,
  FaCheckCircle, FaRegSmile, FaMagic
} from 'react-icons/fa';

// Import the thunks to fetch achievements and shop items
import { fetchAchievements } from './achievementsSlice';
import { fetchShopItems } from './shopSlice';

// Updated icon mapping: removed memory_master, category_perfectionist, subject_specialist,
// subject_finisher, absolute_perfectionist, exam_conqueror. Keep only those we still have:
const iconMapping = {
  test_rookie: FaTrophy,
  accuracy_king: FaMedal,
  bronze_grinder: FaBook,
  silver_scholar: FaStar,
  gold_god: FaCrown,
  platinum_pro: FaMagic,
  walking_encyclopedia: FaBrain,
  redemption_arc: FaBolt,
  coin_collector_5000: FaBook,
  coin_hoarder_10000: FaBook,
  coin_tycoon_50000: FaBook,
  perfectionist_1: FaCheckCircle,
  double_trouble_2: FaCheckCircle,
  error404_failure_not_found: FaCheckCircle,
  level_up_5: FaTrophy,
  mid_tier_grinder_25: FaMedal,
  elite_scholar_50: FaStar,
  ultimate_master_100: FaCrown,
  answer_machine_1000: FaBook,
  knowledge_beast_5000: FaBrain,
  question_terminator: FaBrain,
  test_finisher: FaCheckCircle
};

// Matching color mapping (remove same IDs):
const colorMapping = {
  test_rookie: "#ff5555",
  accuracy_king: "#ffa500",
  bronze_grinder: "#cd7f32",
  silver_scholar: "#c0c0c0",
  gold_god: "#ffd700",
  platinum_pro: "#e5e4e2",
  walking_encyclopedia: "#00fa9a",
  redemption_arc: "#ff4500",
  coin_collector_5000: "#ff69b4",
  coin_hoarder_10000: "#ff1493",
  coin_tycoon_50000: "#ff0000",
  perfectionist_1: "#adff2f",
  double_trouble_2: "#7fff00",
  error404_failure_not_found: "#00ffff",
  level_up_5: "#f08080",
  mid_tier_grinder_25: "#ff8c00",
  elite_scholar_50: "#ffd700",
  ultimate_master_100: "#ff4500",
  answer_machine_1000: "#ff69b4",
  knowledge_beast_5000: "#00fa9a",
  question_terminator: "#ff1493",
  test_finisher: "#adff2f"
};

// Utility function to show toast for newlyUnlocked achievements:
function showNewlyUnlockedAchievements(newlyUnlocked, allAchievements) {
  if (!newlyUnlocked || newlyUnlocked.length === 0) return;
  newlyUnlocked.forEach((achId) => {
    const Icon = iconMapping[achId] ? iconMapping[achId] : FaTrophy;
    const color = colorMapping[achId] || "#fff";

    const foundAch = allAchievements?.find(a => a.achievementId === achId);
    const title = foundAch?.title || `Unlocked ${achId}`;
    const desc = foundAch?.description || 'Achievement Unlocked!';

    showAchievementToast({
      title,
      description: desc,
      icon: Icon ? <Icon /> : null,
      color
    });
  });
}

const initialUserId = localStorage.getItem('userId');

const initialState = {
  userId: initialUserId ? initialUserId : null,
  username: '',
  email: '',
  xp: 0,
  level: 1,
  coins: 0,
  achievements: [],
  xpBoost: 1.0,
  currentAvatar: null,
  nameColor: null,
  purchasedItems: [],
  subscriptionActive: false,
  oauth_provider: null,

  status: 'idle',
  loading: false,
  error: null,
};

// REGISTER
export const registerUser = createAsyncThunk(
  'user/registerUser',
  async (formData, { rejectWithValue, dispatch, getState }) => {
    try {
      const response = await fetch('/api/test/user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Registration failed');
      }
      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// LOGIN
export const loginUser = createAsyncThunk(
  'user/loginUser',
  async (credentials, { rejectWithValue, dispatch, getState }) => {
    try {
      const response = await fetch('/api/test/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }
      // Immediately fetch achievements + shop data after successful login
      dispatch(fetchAchievements());
      dispatch(fetchShopItems());

      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// FETCH USER DATA
export const fetchUserData = createAsyncThunk(
  'user/fetchUserData',
  async (userId, { rejectWithValue, dispatch }) => {
    try {
      const response = await fetch(`/api/test/user/${userId}`);
      if (!response.ok) {
        throw new Error('Failed to fetch user data');
      }
      const data = await response.json();

      // Also fetch achievements + shop items to ensure they're loaded
      dispatch(fetchAchievements());
      dispatch(fetchShopItems());

      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Example of a daily bonus thunk:
export const claimDailyBonus = createAsyncThunk(
  'user/claimDailyBonus',
  async (userId, { rejectWithValue, dispatch, getState }) => {
    try {
      const response = await fetch(`/api/test/user/${userId}/daily-bonus`, {
        method: 'POST'
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || data.error || 'Daily bonus error');
      }
      // If new achievements came back, display them
      if (data.newlyUnlocked && data.newlyUnlocked.length > 0) {
        const allAchs = getState().achievements.all;
        showNewlyUnlockedAchievements(data.newlyUnlocked, allAchs);
      }
      return data; 
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// If you have an "addCoins" route, likewise
export const addCoins = createAsyncThunk(
  'user/addCoins',
  async ({ userId, amount }, { rejectWithValue, dispatch, getState }) => {
    try {
      const res = await fetch(`/api/test/user/${userId}/add-coins`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ coins: amount })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to add coins');
      }
      // Show newly unlocked achievements
      if (data.newlyUnlocked && data.newlyUnlocked.length > 0) {
        const allAchs = getState().achievements.all;
        showNewlyUnlockedAchievements(data.newlyUnlocked, allAchs);
      }
      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

const userSlice = createSlice({
  name: 'user',
  initialState,
  reducers: {
    setCurrentUserId(state, action) {
      state.userId = action.payload;
    },
    logout(state) {
      state.userId = null;
      state.username = '';
      state.email = '';
      state.xp = 0;
      state.level = 1;
      state.coins = 0;
      state.achievements = [];
      state.xpBoost = 1.0;
      state.currentAvatar = null;
      state.nameColor = null;
      state.purchasedItems = [];
      state.subscriptionActive = false;
      state.status = 'idle';
      localStorage.removeItem('userId');
    },
    setXPAndCoins(state, action) {
      const { xp, coins } = action.payload;
      state.xp = xp;
      state.coins = coins;
    },
    // Add this new action:
    clearAuthErrors(state) {
      state.error = null;
    }
  },
  extraReducers: (builder) => {
    builder
      // REGISTER
      .addCase(registerUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(registerUser.fulfilled, (state) => {
        state.loading = false;
        state.error = null;
      })
      .addCase(registerUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // LOGIN
      .addCase(loginUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loginUser.fulfilled, (state, action) => {
        state.loading = false;
        state.error = null;

        const {
          user_id,
          username,
          email,
          coins,
          xp,
          level,
          achievements,
          xpBoost,
          currentAvatar,
          nameColor,
          purchasedItems,
          subscriptionActive,
          password,
          oauth_provider
        } = action.payload;

        state.userId = user_id;
        state.username = username;
        state.email = email || '';
        state.coins = coins || 0;
        state.xp = xp || 0;
        state.level = level || 1;
        state.achievements = achievements || [];
        state.xpBoost = xpBoost !== undefined ? xpBoost : 1.0;
        state.currentAvatar = currentAvatar || null;
        state.nameColor = nameColor || null;
        state.purchasedItems = purchasedItems || [];
        state.subscriptionActive = subscriptionActive || false;
        state.oauth_provider = oauth_provider || null;

        localStorage.setItem('userId', user_id);
      })
      .addCase(loginUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // FETCH USER DATA
      .addCase(fetchUserData.pending, (state) => {
        state.status = 'loading';
      })
      .addCase(fetchUserData.fulfilled, (state, action) => {
        state.status = 'succeeded';
        state.error = null;
        const userDoc = action.payload;

        state.userId = userDoc._id;
        state.username = userDoc.username;
        state.email = userDoc.email || '';
        state.xp = userDoc.xp || 0;
        state.level = userDoc.level || 1;
        state.coins = userDoc.coins || 0;
        state.achievements = userDoc.achievements || [];
        state.xpBoost = userDoc.xpBoost !== undefined ? userDoc.xpBoost : 1.0;
        state.currentAvatar = userDoc.currentAvatar || null;
        state.nameColor = userDoc.nameColor || null;
        state.purchasedItems = userDoc.purchasedItems || [];
        state.subscriptionActive = userDoc.subscriptionActive || false;
        state.oauth_provider = userDoc.oauth_provider || null;
      })
      .addCase(fetchUserData.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      })

      // DAILY BONUS
      .addCase(claimDailyBonus.pending, (state) => {
        state.loading = true;
      })
      .addCase(claimDailyBonus.fulfilled, (state, action) => {
        state.loading = false;
        // Update local user coins/xp if success
        if (action.payload.success) {
          state.coins = action.payload.newCoins;
          state.xp = action.payload.newXP;
        }
      })
      .addCase(claimDailyBonus.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // ADD COINS
      .addCase(addCoins.fulfilled, (state, action) => {
        // If route succeeded, you could do local updates here or re-fetch user
        // For example:
        // state.coins += ...
      });
  },
});

export const { setCurrentUserId, logout, setXPAndCoins, clearAuthErrors } = userSlice.actions;
export default userSlice.reducer;



now teh actual js and css files for this page

/* DailyStation.css - Gamified Daily Station with rewards and challenges */

:root {
  --daily-bg-dark: #0b0c15;
  --daily-bg-card: #171a23;
  --daily-accent: #6543cc;
  --daily-accent-glow: #8a58fc;
  --daily-accent-secondary: #ff4c8b;
  --daily-success: #2ebb77;
  --daily-error: #ff4e4e;
  --daily-warning: #ffc107;
  --daily-text: #e2e2e2;
  --daily-text-secondary: #9da8b9;
  --daily-border: #2a2c3d;
  --daily-input-bg: rgba(0, 0, 0, 0.2);
  --daily-gradient-primary: linear-gradient(135deg, #6543cc, #8a58fc);
  --daily-gradient-secondary: linear-gradient(135deg, #ff4c8b, #ff7950);
  --daily-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  --daily-glow: 0 0 15px rgba(134, 88, 252, 0.5);
  --daily-coin-gold: #ffd700;
  --daily-xp-blue: #0095ff;
}

/* Main Container */
.daily-station-container {
  font-family: 'Orbitron', 'Roboto', sans-serif;
  color: var(--daily-text);
  margin: 0;
  padding: 0;
  min-height: 100vh;
  width: 100%;
  background-color: var(--daily-bg-dark);
  background-image: 
    radial-gradient(circle at 15% 25%, rgba(26, 20, 64, 0.4) 0%, transparent 45%),
    radial-gradient(circle at 75% 65%, rgba(42, 26, 89, 0.3) 0%, transparent 40%),
    repeating-linear-gradient(rgba(0, 0, 0, 0.05) 0px, rgba(0, 0, 0, 0.05) 1px, transparent 1px, transparent 10px);
  position: relative;
  display: flex;
  flex-direction: column;
  padding: 20px;
  box-sizing: border-box;
}

/* =================== */
/* HEADER SECTION      */
/* =================== */

.daily-station-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  margin-bottom: 30px;
  flex-wrap: wrap;
  background: var(--daily-bg-card);
  border-radius: 15px;
  border: 1px solid var(--daily-border);
  box-shadow: var(--daily-shadow);
  position: relative;
  overflow: hidden;
}

.daily-station-header::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 4px;
  background: var(--daily-gradient-primary);
}

.daily-station-title h1 {
  font-size: 28px;
  margin: 0 0 5px 0;
  background: var(--daily-gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-shadow: 0 0 2px rgba(0, 0, 0, 0.5);
  font-weight: 700;
}

.daily-station-title p {
  margin: 0;
  font-size: 14px;
  color: var(--daily-text-secondary);
}

.daily-station-user-stats {
  display: flex;
  gap: 20px;
}

.daily-station-stat {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--daily-input-bg);
  padding: 6px 12px;
  border-radius: 20px;
  border: 1px solid var(--daily-border);
}

.daily-station-stat-icon {
  font-size: 18px;
}

.daily-station-stat-icon.coins {
  color: var(--daily-coin-gold);
}

.daily-station-stat-icon.xp {
  color: var(--daily-xp-blue);
}

.daily-station-stat-value {
  font-size: 16px;
  font-weight: 600;
}

/* =================== */
/* MAIN CONTENT        */
/* =================== */

.daily-station-content {
  display: flex;
  flex-direction: column;
  gap: 30px;
}

/* Login Required */
.daily-station-login-required {
  background: var(--daily-bg-card);
  border-radius: 15px;
  padding: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--daily-border);
  box-shadow: var(--daily-shadow);
}

.daily-station-login-message {
  text-align: center;
  max-width: 500px;
}

.daily-station-login-icon {
  font-size: 48px;
  color: var(--daily-accent);
  margin-bottom: 20px;
}

.daily-station-login-message h2 {
  font-size: 24px;
  margin: 0 0 15px 0;
}

.daily-station-login-message p {
  color: var(--daily-text-secondary);
  font-size: 16px;
  margin: 0;
}

/* Cards (Bonus & Question) */
.daily-station-card {
  background: var(--daily-bg-card);
  border-radius: 15px;
  border: 1px solid var(--daily-border);
  box-shadow: var(--daily-shadow);
  overflow: hidden;
}

.daily-station-card.bonus-card {
  position: relative;
}

.daily-station-card.bonus-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 4px;
  background: var(--daily-gradient-secondary);
}

.daily-station-card.question-card {
  position: relative;
}

.daily-station-card.question-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 4px;
  background: var(--daily-gradient-primary);
}

.daily-station-card-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 20px;
  border-bottom: 1px solid var(--daily-border);
}

.daily-station-card-icon {
  font-size: 24px;
  color: var(--daily-accent);
}

.daily-station-card-header h2 {
  font-size: 20px;
  margin: 0;
}

.daily-station-card-content {
  padding: 20px;
  font-family: 'Trebuchet MS';
}

/* =================== */
/* DAILY BONUS SECTION */
/* =================== */

.daily-station-bonus-info {
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-bottom: 20px;
  text-align: center;
}

.daily-station-bonus-value {
  display: flex;
  align-items: center;
  gap: 10px;
  background: var(--daily-input-bg);
  padding: 12px 24px;
  border-radius: 30px;
  margin-bottom: 15px;
  font-size: 24px;
  font-weight: 700;
  border: 1px solid rgba(255, 215, 0, 0.3);
}

.daily-station-bonus-coin-icon {
  color: var(--daily-coin-gold);
  font-size: 28px;
}

.daily-station-bonus-info p {
  margin: 0;
  color: var(--daily-text-secondary);
}

.daily-station-bonus-action {
  display: flex;
  justify-content: center;
}

.daily-station-claim-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  background: var(--daily-gradient-secondary);
  color: #ffffff;
  border: none;
  border-radius: 30px;
  padding: 12px 30px;
  font-size: 16px;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: 0 4px 15px rgba(255, 76, 139, 0.3);
  min-width: 200px;
}

.daily-station-claim-btn:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(255, 76, 139, 0.4);
}

.daily-station-claim-btn:active:not(:disabled) {
  transform: translateY(1px);
}

.daily-station-claim-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.loading-icon {
  animation: spin 1.5s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.daily-station-countdown {
  display: flex;
  align-items: center;
  gap: 15px;
  background: var(--daily-input-bg);
  padding: 12px 20px;
  border-radius: 30px;
  border: 1px solid var(--daily-border);
}

.daily-station-countdown-icon {
  color: var(--daily-accent);
  font-size: 18px;
}

.daily-station-countdown-info {
  display: flex;
  flex-direction: column;
}

.daily-station-countdown-label {
  font-size: 12px;
  color: var(--daily-text-secondary);
}

.daily-station-countdown-time {
  font-size: 18px;
  font-weight: 700;
  font-family: monospace;
  letter-spacing: 1px;
}

.daily-station-error {
  background: rgba(255, 78, 78, 0.1);
  border: 1px solid rgba(255, 78, 78, 0.3);
  border-radius: 8px;
  padding: 10px 15px;
  margin-bottom: 20px;
  color: var(--daily-error);
  text-align: center;
}

/* =================== */
/* QUESTION SECTION    */
/* =================== */

.daily-station-loading,
.daily-station-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 15px;
  padding: 30px;
  text-align: center;
  color: var(--daily-text-secondary);
}

.daily-station-loading .loading-icon {
  font-size: 32px;
  color: var(--daily-accent);
}

.daily-station-question {
  display: flex;
  flex-direction: column;
  gap: 25px;
  position: relative;
}

.daily-station-question-prompt {
  background: var(--daily-input-bg);
  border-radius: 12px;
  padding: 20px;
  border: 1px solid var(--daily-border);
}

.daily-station-question-prompt p {
  margin: 0;
  font-size: 16px;
  line-height: 1.5;
}

.daily-station-question-options {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.daily-station-options-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.daily-station-option {
  display: flex;
  align-items: center;
  cursor: pointer;
  background: var(--daily-input-bg);
  border: 1px solid var(--daily-border);
  border-radius: 8px;
  padding: 12px 15px;
  transition: all 0.2s;
  position: relative;
}

.daily-station-option:hover {
  background: rgba(255, 255, 255, 0.05);
}

.daily-station-option.selected {
  background: rgba(101, 67, 204, 0.15);
  border-color: var(--daily-accent);
}

.daily-station-option-input {
  position: absolute;
  opacity: 0;
  width: 0;
  height: 0;
}

.daily-station-option-text {
  font-size: 14px;
  flex-grow: 1;
  margin-left: 10px;
}

.daily-station-option-indicator {
  color: var(--daily-accent);
  margin-left: 10px;
}

.daily-station-submit-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--daily-gradient-primary);
  color: #ffffff;
  border: none;
  border-radius: 30px;
  padding: 12px 30px;
  font-size: 16px;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: 0 4px 15px rgba(101, 67, 204, 0.3);
  align-self: center;
  min-width: 200px;
}

.daily-station-submit-btn:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(101, 67, 204, 0.4);
}

.daily-station-submit-btn:active:not(:disabled) {
  transform: translateY(1px);
}

.daily-station-submit-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.daily-station-next-question {
  display: flex;
  justify-content: center;
  margin-top: 20px;
}

/* Answered Results */
.daily-station-question-answered {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.daily-station-result {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 15px;
  padding: 20px;
  border-radius: 12px;
  text-align: center;
}

.daily-station-result.correct {
  background: rgba(46, 187, 119, 0.1);
  border: 1px solid rgba(46, 187, 119, 0.3);
}

.daily-station-result.incorrect {
  background: rgba(255, 78, 78, 0.1);
  border: 1px solid rgba(255, 78, 78, 0.3);
}

.daily-station-result-icon {
  font-size: 24px;
}

.daily-station-result.correct .daily-station-result-icon {
  color: var(--daily-success);
}

.daily-station-result.incorrect .daily-station-result-icon {
  color: var(--daily-error);
}

.daily-station-result p {
  margin: 0;
  font-size: 16px;
  font-weight: 500;
}

/* Animation States */
.daily-station-question.correct-animation {
  animation: correct-pulse 1s ease;
}

.daily-station-question.wrong-animation {
  animation: wrong-pulse 1s ease;
}

@keyframes correct-pulse {
  0%, 100% {
    box-shadow: none;
  }
  50% {
    box-shadow: 0 0 30px rgba(46, 187, 119, 0.5);
  }
}

@keyframes wrong-pulse {
  0%, 100% {
    box-shadow: none;
  }
  50% {
    box-shadow: 0 0 30px rgba(255, 78, 78, 0.5);
  }
}

/* =================== */
/* OVERLAY ANIMATIONS  */
/* =================== */

.daily-station-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  animation: fade-in 0.3s ease;
}

@keyframes fade-in {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}

.daily-station-bonus-animation {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background: var(--daily-bg-card);
  border-radius: 15px;
  padding: 30px;
  border: 1px solid var(--daily-accent-glow);
  box-shadow: var(--daily-glow), var(--daily-shadow);
  animation: bonus-animation 2s ease;
  max-width: 90%;
  text-align: center;
}

@keyframes bonus-animation {
  0% {
    transform: scale(0.5);
    opacity: 0;
  }
  20% {
    transform: scale(1.1);
    opacity: 1;
  }
  30% {
    transform: scale(1);
  }
  70% {
    transform: scale(1);
  }
  100% {
    transform: scale(1);
  }
}

.daily-station-bonus-icon {
  font-size: 64px;
  color: var(--daily-coin-gold);
  margin-bottom: 20px;
  animation: coin-spin 1.5s ease;
}

@keyframes coin-spin {
  0% {
    transform: rotateY(0deg) scale(0.5);
  }
  40% {
    transform: rotateY(1080deg) scale(1.2);
  }
  60% {
    transform: rotateY(1080deg) scale(1.2);
  }
  100% {
    transform: rotateY(1080deg) scale(1);
  }
}

.daily-station-bonus-text h3 {
  font-size: 24px;
  margin: 0 0 10px 0;
  color: var(--daily-accent-glow);
}

.daily-station-bonus-text p {
  margin: 0;
  font-size: 18px;
  color: var(--daily-text);
}

/* =================== */
/* RESPONSIVE STYLES   */
/* =================== */

/* Tablet Styles */
@media (max-width: 992px) {
  .daily-station-container {
    padding: 15px;
  }
  
  .daily-station-header {
    padding: 15px;
    margin-bottom: 20px;
  }
  
  .daily-station-title h1 {
    font-size: 24px;
  }
  
  .daily-station-title p {
    font-size: 13px;
  }
  
  .daily-station-card-header {
    padding: 15px;
  }
  
  .daily-station-card-content {
    padding: 15px;
  }
  
  .daily-station-bonus-value {
    font-size: 22px;
    padding: 10px 20px;
  }
  
  .daily-station-bonus-coin-icon {
    font-size: 24px;
  }
  
  .daily-station-claim-btn,
  .daily-station-submit-btn {
    font-size: 15px;
    padding: 10px 25px;
  }
}

/* Mobile Styles */
@media (max-width: 768px) {
  .daily-station-container {
    padding: 10px;
  }
  
  .daily-station-header {
    flex-direction: column;
    align-items: stretch;
    gap: 15px;
    padding: 15px;
  }
  
  .daily-station-title {
    text-align: center;
  }
  
  .daily-station-title h1 {
    font-size: 22px;
  }
  
  .daily-station-user-stats {
    justify-content: center;
  }
  
  .daily-station-content {
    gap: 20px;
  }
  
  .daily-station-login-message h2 {
    font-size: 20px;
  }
  
  .daily-station-login-message p {
    font-size: 14px;
  }
  
  .daily-station-card-header h2 {
    font-size: 18px;
  }
  
  .daily-station-bonus-value {
    font-size: 20px;
  }
  
  .daily-station-countdown {
    padding: 10px 15px;
  }
  
  .daily-station-countdown-time {
    font-size: 16px;
  }
  
  .daily-station-question-prompt {
    padding: 15px;
  }
  
  .daily-station-option {
    padding: 10px 12px;
  }
  
  .daily-station-bonus-animation {
    padding: 20px;
  }
  
  .daily-station-bonus-icon {
    font-size: 56px;
  }
  
  .daily-station-bonus-text h3 {
    font-size: 20px;
  }
  
  .daily-station-bonus-text p {
    font-size: 16px;
  }
}

/* Small Mobile Styles */
@media (max-width: 480px) {
  .daily-station-title h1 {
    font-size: 20px;
  }
  
  .daily-station-title p {
    font-size: 12px;
  }
  
  .daily-station-stat {
    padding: 5px 10px;
  }
  
  .daily-station-stat-icon {
    font-size: 16px;
  }
  
  .daily-station-stat-value {
    font-size: 14px;
  }
  
  .daily-station-card-icon {
    font-size: 20px;
  }
  
  .daily-station-card-header h2 {
    font-size: 16px;
  }
  
  .daily-station-bonus-value {
    font-size: 18px;
    padding: 8px 16px;
  }
  
  .daily-station-bonus-coin-icon {
    font-size: 20px;
  }
  
  .daily-station-bonus-info p {
    font-size: 13px;
  }
  
  .daily-station-claim-btn,
  .daily-station-submit-btn {
    font-size: 14px;
    padding: 8px 20px;
    min-width: auto;
    width: 100%;
  }
  
  .daily-station-countdown-label {
    font-size: 11px;
  }
  
  .daily-station-countdown-time {
    font-size: 14px;
  }
  
  .daily-station-question-prompt p {
    font-size: 14px;
  }
  
  .daily-station-option-text {
    font-size: 13px;
  }
  
  .daily-station-result p {
    font-size: 14px;
  }
  
  .daily-station-bonus-icon {
    font-size: 48px;
  }
  
  .daily-station-bonus-text h3 {
    font-size: 18px;
  }
  
  .daily-station-bonus-text p {
    font-size: 14px;
  }
}

/* iPhone SE and other small devices */
@media (max-width: 375px) {
  .daily-station-title h1 {
    font-size: 18px;
  }
  
  .daily-station-bonus-value {
    font-size: 16px;
  }
  
  .daily-station-countdown-time {
    font-size: 13px;
  }
  
  .daily-station-option {
    padding: 8px 10px;
  }
  
  .daily-station-bonus-animation {
    padding: 15px;
  }
  
  .daily-station-bonus-icon {
    font-size: 40px;
  }
  
  .daily-station-bonus-text h3 {
    font-size: 16px;
  }
  
  .daily-station-bonus-text p {
    font-size: 13px;
  }
}

// src/components/pages/store/DailyStationPage.js
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { claimDailyBonus, setXPAndCoins, fetchUserData } from './userSlice';
import './DailyStation.css';

// Icon imports
import {
  FaCoins,
  FaStar,
  FaTrophy,
  FaCalendarCheck,
  FaHourglassHalf,
  FaCheckCircle,
  FaTimesCircle,
  FaLightbulb,
  FaChevronRight,
  FaSyncAlt,
  FaGift
} from 'react-icons/fa';

// Helper to format seconds as HH:MM:SS
function formatCountdown(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return [h, m, s].map((x) => String(x).padStart(2, '0')).join(':');
}

const DailyStationPage = () => {
  const dispatch = useDispatch();
  const { userId, username, coins, xp, lastDailyClaim, loading: userLoading } = useSelector((state) => state.user);

  // Local states
  const [bonusError, setBonusError] = useState(null);
  const [bonusSuccess, setBonusSuccess] = useState(false);
  const [loadingBonus, setLoadingBonus] = useState(false);
  const [canClaim, setCanClaim] = useState(false);
  const [bonusCountdown, setBonusCountdown] = useState(0);
  const [localLastDailyClaim, setLocalLastDailyClaim] = useState(lastDailyClaim);

  const [loadingQ, setLoadingQ] = useState(true);
  const [qError, setQError] = useState(null);
  const [questionData, setQuestionData] = useState(null);
  const [selectedAnswer, setSelectedAnswer] = useState(null);
  const [submitResult, setSubmitResult] = useState(null);

  const [questionCountdown, setQuestionCountdown] = useState(0);

  // Animations
  const [showBonusAnimation, setShowBonusAnimation] = useState(false);
  const [showCorrectAnimation, setShowCorrectAnimation] = useState(false);
  const [showWrongAnimation, setShowWrongAnimation] = useState(false);

  // Sync local lastDailyClaim whenever Redux store changes
  useEffect(() => {
    if (lastDailyClaim) {
      setLocalLastDailyClaim(lastDailyClaim);
    }
  }, [lastDailyClaim]);

  // Check if user can claim bonus on initial load
  useEffect(() => {
    if (!localLastDailyClaim) {
      setCanClaim(true);
    } else {
      const lastClaimTime = new Date(localLastDailyClaim).getTime();
      const now = Date.now();
      const diff = lastClaimTime + 24 * 3600 * 1000 - now; // 24h window
      if (diff <= 0) {
        setCanClaim(true);
      } else {
        setCanClaim(false);
        setBonusCountdown(Math.floor(diff / 1000));
      }
    }
  }, [localLastDailyClaim]);

  // Bonus countdown logic (runs every second)
  useEffect(() => {
    if (!localLastDailyClaim) {
      // If we have no known claim, show "canClaim" right away
      setBonusCountdown(0);
      setCanClaim(true);
      return;
    }

    const lastClaimTime = new Date(localLastDailyClaim).getTime();
    
    function tickBonus() {
      const now = Date.now();
      const diff = lastClaimTime + 24 * 3600 * 1000 - now; // 24h window
      if (diff <= 0) {
        setBonusCountdown(0);
        setCanClaim(true);
      } else {
        setBonusCountdown(Math.floor(diff / 1000));
        setCanClaim(false);
      }
    }
    
    tickBonus(); // Run immediately
    const bonusInterval = setInterval(tickBonus, 1000);
    return () => clearInterval(bonusInterval);
  }, [localLastDailyClaim]);

  // Daily question refresh countdown logic (resets at midnight UTC)
  useEffect(() => {
    function tickQuestion() {
      const now = new Date();
      const nextMidnightUTC = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
      const diff = Math.floor((nextMidnightUTC - now) / 1000);
      setQuestionCountdown(diff);
    }
    
    tickQuestion(); // Run immediately
    const questionInterval = setInterval(tickQuestion, 1000);
    return () => clearInterval(questionInterval);
  }, []);

  // Fetch daily question if user is logged in
  useEffect(() => {
    if (userId) {
      fetchDailyQuestion();
    } else {
      setLoadingQ(false);
    }
  }, [userId]);

  // Claim daily bonus
  const handleClaimDailyBonus = async () => {
    if (!userId) {
      setBonusError('Please log in first.');
      return;
    }
    
    setLoadingBonus(true);
    setBonusError(null);
    
    try {
      const res = await fetch(`/api/test/user/${userId}/daily-bonus`, {
        method: 'POST'
      });
      const data = await res.json();
      
      if (!res.ok) {
        // Hard error, e.g. 404 user not found
        setBonusError(data.error || 'Error claiming daily bonus');
        setLoadingBonus(false);
        return;
      }
      
      if (data.success) {
        // Claimed successfully
        setShowBonusAnimation(true);
        setTimeout(() => setShowBonusAnimation(false), 3000);
        setBonusSuccess(true);
        
        // Update state immediately to show countdown
        setLocalLastDailyClaim(new Date().toISOString());
        setCanClaim(false);
        
        // Refresh user data to update coins/xp
        dispatch(fetchUserData(userId));
      } else {
        // Already claimed case
        setBonusError(data.message);
        
        // Parse seconds left from message if available
        const match = data.message && data.message.match(/(\d+)/);
        if (match) {
          const secondsLeft = parseInt(match[1], 10);
          if (!isNaN(secondsLeft) && secondsLeft > 0) {
            // Calculate the last claim time based on seconds left
            const nowMs = Date.now();
            const msLeft = secondsLeft * 1000;
            const lastClaimTime = nowMs - (86400000 - msLeft);
            setLocalLastDailyClaim(new Date(lastClaimTime).toISOString());
            setCanClaim(false);
          }
        }
      }
      
      setLoadingBonus(false);
    } catch (err) {
      setBonusError('Error: ' + err.message);
      setLoadingBonus(false);
    }
  };

  // Fetch daily question
  const fetchDailyQuestion = async () => {
    setLoadingQ(true);
    setQError(null);
    
    try {
      const res = await fetch(`/api/test/daily-question?userId=${userId}`);
      const data = await res.json();
      
      if (!res.ok) {
        setQError(data.error || 'Failed to fetch daily question');
      } else {
        setQuestionData(data);
      }
      
      setLoadingQ(false);
    } catch (err) {
      setQError('Error fetching daily question: ' + err.message);
      setLoadingQ(false);
    }
  };

  // Submit daily answer
  const submitDailyAnswer = async () => {
    if (!questionData || questionData.alreadyAnswered) {
      setQError("You've already answered today's question!");
      return;
    }
    
    if (selectedAnswer === null) {
      setQError('Please select an answer first.');
      return;
    }
    
    setQError(null);
    
    try {
      const body = {
        userId,
        dayIndex: questionData.dayIndex,
        selectedIndex: selectedAnswer
      };
      
      const res = await fetch('/api/test/daily-question/answer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      
      const ansData = await res.json();
      
      if (!res.ok) {
        setQError(ansData.error || 'Error submitting answer.');
      } else {
        setSubmitResult(ansData);
        
        dispatch(
          setXPAndCoins({
            xp: ansData.newXP || xp,
            coins: ansData.newCoins || coins
          })
        );
        
        setQuestionData((prev) => ({
          ...prev,
          alreadyAnswered: true
        }));

        if (ansData.correct) {
          setShowCorrectAnimation(true);
          setTimeout(() => setShowCorrectAnimation(false), 2000);
        } else {
          setShowWrongAnimation(true);
          setTimeout(() => setShowWrongAnimation(false), 2000);
        }
      }
    } catch (err) {
      setQError('Error: ' + err.message);
    }
  };

  return (
    <div className="daily-station-container">
      {/* HEADER SECTION */}
      <div className="daily-station-header">
        <div className="daily-station-title">
          <h1>Daily Station</h1>
          <p>Claim your daily rewards and answer the challenge</p>
        </div>
        
        {userId && (
          <div className="daily-station-user-stats">
            <div className="daily-station-stat">
              <FaCoins className="daily-station-stat-icon coins" />
              <span className="daily-station-stat-value">{coins}</span>
            </div>
            <div className="daily-station-stat">
              <FaStar className="daily-station-stat-icon xp" />
              <span className="daily-station-stat-value">{xp}</span>
            </div>
          </div>
        )}
      </div>

      {/* MAIN CONTENT */}
      <div className="daily-station-content">
        {!userId ? (
          <div className="daily-station-login-required">
            <div className="daily-station-login-message">
              <FaLightbulb className="daily-station-login-icon" />
              <h2>Login Required</h2>
              <p>Please log in to claim daily rewards and participate in daily challenges.</p>
            </div>
          </div>
        ) : (
          <>
            {/* DAILY BONUS SECTION */}
            <div className="daily-station-card bonus-card">
              <div className="daily-station-card-header">
                <FaGift className="daily-station-card-icon" />
                <h2>Daily Bonus</h2>
              </div>
              
              <div className="daily-station-card-content">
                <div className="daily-station-bonus-info">
                  <div className="daily-station-bonus-value">
                    <FaCoins className="daily-station-bonus-coin-icon" />
                    <span>1000</span>
                  </div>
                  <p>Claim your free coins every 24 hours!</p>
                </div>
                
                {/* Show error if any */}
                {bonusError && !bonusError.includes("Next bonus in") && (
                  <div className="daily-station-error">
                    <p>{bonusError}</p>
                  </div>
                )}
                
                {/* Claim Button or Countdown */}
                <div className="daily-station-bonus-action">
                  {canClaim ? (
                    <button 
                      className="daily-station-claim-btn"
                      onClick={handleClaimDailyBonus}
                      disabled={loadingBonus}
                    >
                      {loadingBonus ? (
                        <>
                          <FaSyncAlt className="loading-icon" />
                          <span>Claiming...</span>
                        </>
                      ) : (
                        <>
                          <FaCoins />
                          <span>Claim Bonus</span>
                        </>
                      )}
                    </button>
                  ) : (
                    <div className="daily-station-countdown">
                      <FaHourglassHalf className="daily-station-countdown-icon" />
                      <div className="daily-station-countdown-info">
                        <span className="daily-station-countdown-label">Next bonus in:</span>
                        <span className="daily-station-countdown-time">{formatCountdown(bonusCountdown)}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
            
            {/* DAILY QUESTION SECTION */}
            <div className="daily-station-card question-card">
              <div className="daily-station-card-header">
                <FaLightbulb className="daily-station-card-icon" />
                <h2>Daily Challenge</h2>
              </div>
              
              <div className="daily-station-card-content">
                {loadingQ ? (
                  <div className="daily-station-loading">
                    <FaSyncAlt className="loading-icon" />
                    <p>Loading challenge...</p>
                  </div>
                ) : qError ? (
                  <div className="daily-station-error">
                    <p>{qError}</p>
                  </div>
                ) : !questionData ? (
                  <div className="daily-station-empty">
                    <p>No challenges available today. Check back tomorrow!</p>
                  </div>
                ) : (
                  <div className={`daily-station-question ${showCorrectAnimation ? 'correct-animation' : ''} ${showWrongAnimation ? 'wrong-animation' : ''}`}>
                    <div className="daily-station-question-prompt">
                      <p>{questionData.prompt}</p>
                    </div>
                    
                    {questionData.alreadyAnswered ? (
                      <div className="daily-station-question-answered">
                        {submitResult && (
                          <div className={`daily-station-result ${submitResult.correct ? 'correct' : 'incorrect'}`}>
                            {submitResult.correct ? (
                              <>
                                <FaCheckCircle className="daily-station-result-icon" />
                                <p>Correct! You earned {submitResult.awardedCoins} coins.</p>
                              </>
                            ) : (
                              <>
                                <FaTimesCircle className="daily-station-result-icon" />
                                <p>Not quite, but you still got {submitResult.awardedCoins} coins.</p>
                              </>
                            )}
                          </div>
                        )}
                        
                        <div className="daily-station-next-question">
                          <div className="daily-station-countdown">
                            <FaCalendarCheck className="daily-station-countdown-icon" />
                            <div className="daily-station-countdown-info">
                              <span className="daily-station-countdown-label">Next challenge in:</span>
                              <span className="daily-station-countdown-time">{formatCountdown(questionCountdown)}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="daily-station-question-options">
                        <div className="daily-station-options-list">
                          {questionData.options.map((option, index) => (
                            <label 
                              key={index} 
                              className={`daily-station-option ${selectedAnswer === index ? 'selected' : ''}`}
                            >
                              <input
                                type="radio"
                                name="dailyQuestion"
                                value={index}
                                checked={selectedAnswer === index}
                                onChange={() => setSelectedAnswer(index)}
                                className="daily-station-option-input"
                              />
                              <span className="daily-station-option-text">{option}</span>
                              {selectedAnswer === index && (
                                <FaChevronRight className="daily-station-option-indicator" />
                              )}
                            </label>
                          ))}
                        </div>
                        
                        <button 
                          className="daily-station-submit-btn"
                          onClick={submitDailyAnswer}
                          disabled={selectedAnswer === null}
                        >
                          Submit Answer
                        </button>
                        
                        <div className="daily-station-next-question">
                          <div className="daily-station-countdown">
                            <FaCalendarCheck className="daily-station-countdown-icon" />
                            <div className="daily-station-countdown-info">
                              <span className="daily-station-countdown-label">Challenge refreshes in:</span>
                              <span className="daily-station-countdown-time">{formatCountdown(questionCountdown)}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>
      
      {/* BONUS CLAIM ANIMATION OVERLAY */}
      {showBonusAnimation && (
        <div className="daily-station-overlay">
          <div className="daily-station-bonus-animation">
            <FaCoins className="daily-station-bonus-icon" />
            <div className="daily-station-bonus-text">
              <h3>Daily Bonus Claimed!</h3>
              <p>+1000 coins added to your account</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DailyStationPage;


ok please output whatver ifle you fix in full but DO NOT CHNAEG ANYTHING ELSE. go
