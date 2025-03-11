ok so i have achievemnts i do, i think all my other ones work excpt thes eones- which are the single question achivemnts liek answer 1000 questions and so on. because in my test pages i have fucnionality to finish teh test early. so im assumig the backend is assuming the tests are alwasy finished after answering all teh uqstions and not consiering the fact that a user can finsih a test ealy- so in other words i think the backedn is counting based on finish tests and toatlinh teh amoutn o fquetsions in a test? well i assume the abckedn for these achivements (anser xyz amount of questions) needs ot count the users qustion count right?? i undertsnd that might be databse intesive or could eb ineeficeint so how can i do two thing: 1) fix teh achiveemnt to make it actually be based on how many questions teh user answers rather than i think test question count after finish? and 2) make it efficent so wher eim not stoirng so much data becasue i have to store evry quetsiosn from the suer- howver.... arent i already coutning every users first time ocrrect answers efficently? so im assuming we can make thia achuvemtn counting method efficent aswell.


here are what i input into mongo for teh achivemnts
// FINAL Achievements to insert (no category-based achievements)
db.achievements.insertMany([
  {
    // 1) test_rookie
    achievementId: "test_rookie",
    title: "🏆 Test Rookie",
    description: "Complete your first test. (Welcome to the grind!)",
    category: "global",
    criteria: { testCount: 1 }
  },
  {
    // 2) accuracy_king
    achievementId: "accuracy_king",
    title: "🎯 Accuracy King",
    description: "Score 90% or higher on any test. (Are you even human?!)",
    category: "global",
    criteria: { minScore: 90 }
  },
  {
    // 3) bronze_grinder
    achievementId: "bronze_grinder",
    title: "🏅 Bronze Grinder",
    description: "Complete 10 tests. (You’re putting in the work!)",
    category: "global",
    criteria: { testCount: 10 }
  },
  {
    // 4) silver_scholar
    achievementId: "silver_scholar",
    title: "🥈 Silver Scholar",
    description: "Complete 25 tests. (Starting to look like a pro!)",
    category: "global",
    criteria: { testCount: 25 }
  },
  {
    // 5) gold_god
    achievementId: "gold_god",
    title: "🥇 Gold God",
    description: "Complete 50 tests. (Unstoppable!)",
    category: "global",
    criteria: { testCount: 50 }
  },
  {
    // 6) platinum_pro
    achievementId: "platinum_pro",
    title: "💎 Platinum Pro",
    description: "Complete 80 tests. (No life, just tests!)",
    category: "global",
    criteria: { testCount: 80 }
  },
  {
    // 7) walking_encyclopedia
    achievementId: "walking_encyclopedia",
    title: "📚 Walking Encyclopedia",
    description: "Complete 8,000 questions. (You literally KNOW EVERYTHING.)",
    category: "global",
    criteria: { totalQuestions: 8000 }
  },
  {
    // 8) redemption_arc
    achievementId: "redemption_arc",
    title: "🔄 Redemption Arc",
    description: "Score 40% or lower on a test, then retake and score 90%+. (A true comeback story!)",
    category: "global",
    criteria: { minScoreBefore: 40, minScoreAfter: 90 }
  },
  {
    // 9) coin_collector_5000
    achievementId: "coin_collector_5000",
    title: "💰 Coin Collector (5,000 Coins)",
    description: "Earn 5,000 coins from correct answers. (Keep stacking!)",
    category: "global",
    criteria: { coins: 5000 }
  },
  {
    // 10) coin_hoarder_10000
    achievementId: "coin_hoarder_10000",
    title: "💰 Coin Hoarder (10,000 Coins)",
    description: "Earn 10,000 coins from correct answers. (You're practically printing money.)",
    category: "global",
    criteria: { coins: 10000 }
  },
  {
    // 11) coin_tycoon_50000
    achievementId: "coin_tycoon_50000",
    title: "💰 Coin Tycoon (50,000 Coins)",
    description: "Earn 50,000 coins from correct answers. (You own the leaderboard now!)",
    category: "global",
    criteria: { coins: 50000 }
  },
  {
    // 12) perfectionist_1
    achievementId: "perfectionist_1",
    title: "✅ Perfection (1 Test)",
    description: "Score 100% on a test. (One down, many to go!)",
    category: "global",
    criteria: { perfectTests: 1 }
  },
  {
    // 13) double_trouble_2
    achievementId: "double_trouble_2",
    title: "✅ Double Trouble (2 Tests)",
    description: "Score 100% on two different tests. (You're on a roll!)",
    category: "global",
    criteria: { perfectTests: 2 }
  },
  {
    // 14) error404_failure_not_found
    achievementId: "error404_failure_not_found",
    title: "✅ Error 404 - Failure Not Found (3 Tests)",
    description: "Score 100% on three different tests. (Perfection is your middle name!)",
    category: "global",
    criteria: { perfectTests: 3 }
  },
  {
    // 15) level_up_5
    achievementId: "level_up_5",
    title: "🎚 Level Up! (Level 5)",
    description: "Reach Level 5. (Just getting started!)",
    category: "global",
    criteria: { level: 5 }
  },
  {
    // 16) mid_tier_grinder_25
    achievementId: "mid_tier_grinder_25",
    title: "⚡ Mid-Tier Grinder (Level 25)",
    description: "Reach Level 25. (You're in deep now!)",
    category: "global",
    criteria: { level: 25 }
  },
  {
    // 17) elite_scholar_50
    achievementId: "elite_scholar_50",
    title: "🔥 Elite Scholar (Level 50)",
    description: "Reach Level 50. (You're a force to be reckoned with!)",
    category: "global",
    criteria: { level: 50 }
  },
  {
    // 18) ultimate_master_100
    achievementId: "ultimate_master_100",
    title: "👑 The Ultimate Master (Level 100)",
    description: "Reach Level 100. (You have ascended beyond mere mortals!)",
    category: "global",
    criteria: { level: 100 }
  },
  {
    // 19) answer_machine_1000
    achievementId: "answer_machine_1000",
    title: "📝 Answer Machine (1,000 Questions)",
    description: "Answer 1,000 questions in total. (No stopping now!)",
    category: "global",
    criteria: { totalQuestions: 1000 }
  },
  {
    // 20) knowledge_beast_5000
    achievementId: "knowledge_beast_5000",
    title: "📝 Knowledge Beast (5,000 Questions)",
    description: "Answer 5,000 questions in total. (You're built different.)",
    category: "global",
    criteria: { totalQuestions: 5000 }
  },
  {
    // 21) question_terminator
    achievementId: "question_terminator",
    title: "📝 Question Terminator (10,000 Questions)",
    description: "Answer 10,000 questions in total. (Achievement unlocked: Cyber Overlord.)",
    category: "global",
    criteria: { totalQuestions: 10000 }
  },
  {
    // 22) test_finisher
    achievementId: "test_finisher",
    title: "✅ Test Finisher",
    description: "Complete all tests at least once, regardless of score. (Completionist vibes!)",
    category: "global",
    criteria: { allTestsCompleted: true }
  }
])


starting with backend

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


from bson.objectid import ObjectId
from datetime import datetime, timedelta
from collections import defaultdict
import math
import re
import unicodedata
import time
from flask import g
from functools import wraps

# Import the new collections from database
from mongodb.database import (
    mainusers_collection,
    shop_collection,
    achievements_collection,
    tests_collection,
    testAttempts_collection,
    correctAnswers_collection
)

##############################################
# very complex Input Sanitization Helpers
##############################################

import re
import unicodedata

# Example small dictionary of very common passwords
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "letmein", "welcome"
}

def has_forbidden_unicode_scripts(s):
    """
    Disallow characters from certain Unicode blocks 
    (private use areas, surrogates, etc.).
    """
    private_use_ranges = [
        (0xE000, 0xF8FF),
        (0xF0000, 0xFFFFD),
        (0x100000, 0x10FFFD)
    ]
    surrogates_range = (0xD800, 0xDFFF)

    for ch in s:
        code_point = ord(ch)
        # Surrogates
        if surrogates_range[0] <= code_point <= surrogates_range[1]:
            return True
        # Private use ranges
        for start, end in private_use_ranges:
            if start <= code_point <= end:
                return True
    return False

def disallow_mixed_scripts(s):
    """
    Example check for mixing major scripts (Latin + Cyrillic, etc.).
    Returns True if it detects more than one script in the string.
    """
    script_sets = set()

    for ch in s:
        cp = ord(ch)
        # Basic Latin and extended ranges:
        if 0x0041 <= cp <= 0x024F:
            script_sets.add("Latin")
        # Greek
        elif 0x0370 <= cp <= 0x03FF:
            script_sets.add("Greek")
        # Cyrillic
        elif 0x0400 <= cp <= 0x04FF:
            script_sets.add("Cyrillic")

        # If more than one distinct script is found
        if len(script_sets) > 1:
            return True

    return False

def validate_username(username):
    """
    Validates a username with very strict rules:
      1. Normalize (NFC).
      2. Length 3..30.
      3. No control chars, no private-use/surrogates, no mixing scripts.
      4. Only [A-Za-z0-9._-], no triple repeats, no leading/trailing punctuation.
    Returns: (True, []) if valid, else (False, [list of error messages]).
    """
    errors = []
    username_nfc = unicodedata.normalize("NFC", username)

    # 1) Check length
    if not (3 <= len(username_nfc) <= 30):
        errors.append("Username must be between 3 and 30 characters long.")

    # 2) Forbidden Unicode script checks
    if has_forbidden_unicode_scripts(username_nfc):
        errors.append("Username contains forbidden Unicode blocks (private use or surrogates).")

    # 3) Disallow mixing multiple major scripts
    if disallow_mixed_scripts(username_nfc):
        errors.append("Username cannot mix multiple Unicode scripts (e.g., Latin & Cyrillic).")

    # 4) Forbid control chars [0..31, 127] + suspicious punctuation
    forbidden_ranges = [(0, 31), (127, 127)]
    forbidden_chars = set(['<', '>', '\\', '/', '"', "'", ';', '`',
                           ' ', '\t', '\r', '\n'])
    for ch in username_nfc:
        cp = ord(ch)
        if any(start <= cp <= end for (start, end) in forbidden_ranges):
            errors.append("Username contains forbidden control characters (ASCII 0-31 or 127).")
            break
        if ch in forbidden_chars:
            errors.append("Username contains forbidden characters like <, >, or whitespace.")
            break

    # 5) Strict allowlist pattern
    pattern = r'^[A-Za-z0-9._-]+$'
    if not re.match(pattern, username_nfc):
        errors.append("Username can only contain letters, digits, underscores, dashes, or dots.")

    # 6) Disallow triple identical consecutive characters
    if re.search(r'(.)\1{2,}', username_nfc):
        errors.append("Username cannot contain three identical consecutive characters.")

    # 7) Disallow leading or trailing punctuation
    if re.match(r'^[._-]|[._-]$', username_nfc):
        errors.append("Username cannot start or end with . - or _.")

    if errors:
        return False, errors
    return True, []

def validate_password(password, username=None, email=None):
    """
    Validates a password with very strict rules:
      1. 12..128 length.
      2. Disallow whitespace, <, >.
      3. Require uppercase, lowercase, digit, special char.
      4. Disallow triple repeats.
      5. Check common/breached password list.
      6. Disallow 'password', 'qwerty', etc.
      7. Disallow if username or email local part is in the password.
    Returns: (True, []) if valid, else (False, [list of error messages]).
    """
    errors = []
    length = len(password)

    # 1) Length
    if not (6 <= length <= 69):
        errors.append("Password must be between 6 and 69 characters long.")

    # 2) Disallowed whitespace or < >
    if any(ch in password for ch in [' ', '<', '>', '\t', '\r', '\n']):
        errors.append("Password cannot contain whitespace or < or > characters.")

    # 3) Complexity checks
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit.")

    # We define a broad set of allowed special chars
    special_pattern = r'[!@#$%^&*()\-_=+\[\]{}|;:\'",<.>/?`~\\]'
    if not re.search(special_pattern, password):
        errors.append("Password must contain at least one special character.")

    # 4) Disallow triple identical consecutive characters
    if re.search(r'(.)\1{2,}', password):
        errors.append("Password must not contain three identical consecutive characters.")

    # 5) Convert to lowercase for simplified checks
    password_lower = password.lower()

    # Check against common password list
    if password_lower in COMMON_PASSWORDS:
        errors.append("Password is too common. Please choose a stronger password.")

    # 6) Disallow certain dictionary words
    dictionary_patterns = ['password', 'qwerty', 'abcdef', 'letmein', 'welcome', 'admin']
    for pat in dictionary_patterns:
        if pat in password_lower:
            errors.append(f"Password must not contain the word '{pat}'.")

    # 7) Disallow if password contains username or email local-part
    if username:
        if username.lower() in password_lower:
            errors.append("Password must not contain your username.")

    if email:
        email_local_part = email.split('@')[0].lower()
        if email_local_part in password_lower:
            errors.append("Password must not contain the local part of your email address.")

    if errors:
        return False, errors
    return True, []

def validate_email(email):
    """
    Validates an email with strict rules:
      1. Normalize (NFC), strip whitespace.
      2. 5..69 length.
      3. No control chars, <, >, etc.
      4. Exactly one @.
    Returns: (True, []) if valid, else (False, [list of error messages]).
    """
    errors = []
    email_nfc = unicodedata.normalize("NFC", email.strip())

    # 1) Length check
    if not (5 <= len(email_nfc) <= 69):
        errors.append("Email length must be between 6 and 69 characters.")

    # 3) Forbid suspicious ASCII
    forbidden_ascii = set(['<','>','`',';',' ', '\t','\r','\n','"',"'", '\\'])
    for ch in email_nfc:
        if ch in forbidden_ascii:
            errors.append("Email contains forbidden characters like <, >, or whitespace.")
            break

    # 4) Must have exactly one @
    if email_nfc.count('@') != 1:
        errors.append("Email must contain exactly one '@' symbol.")

    if errors:
        return False, errors
    return True, []

##############################################
# User Retrieval Helpers
##############################################

def get_user_by_username(username):
    return mainusers_collection.find_one({"username": username})

def get_user_by_identifier(identifier):
    if "@" in identifier:
        return mainusers_collection.find_one({"email": identifier})
    else:
        return get_user_by_username(identifier)

def get_user_by_id(user_id):
    """
    Retrieves a user by ID. Returns None if invalid or not found.
    """
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    return mainusers_collection.find_one({"_id": oid})

##############################################
# Create User
##############################################

def create_user(user_data):
    existing_user = mainusers_collection.find_one({
        "$or": [
            {"username": user_data["username"]},
            {"email": user_data["email"]}
        ]
    })
    if existing_user:
        raise ValueError("Username or email is already taken")

    # Default fields
    user_data.setdefault("coins", 0)
    user_data.setdefault("xp", 0)
    user_data.setdefault("level", 1)
    user_data.setdefault("achievements", [])
    user_data.setdefault("subscriptionActive", False)
    user_data.setdefault("subscriptionPlan", None)
    user_data.setdefault("lastDailyClaim", None)
    user_data.setdefault("purchasedItems", [])
    user_data.setdefault("xpBoost", 1.0)
    user_data.setdefault("currentAvatar", None)
    user_data.setdefault("nameColor", None)

    # If you want to ensure new users have the 'achievement_counters'
    # from Day 1, do it here:
    user_data.setdefault("achievement_counters", {
        "total_tests_completed": 0,
        "perfect_tests_count": 0,
        "perfect_tests_by_category": {},
        # "consecutive_perfect_streak": 0, # removing memory_master
        "highest_score_ever": 0.0,
        "lowest_score_ever": 100.0,
        "total_questions_answered": 0,
        # "tests_completed_by_category": {}, # optional
        # "tests_completed_set": set()       # optional
    })

    # Auto-equip default avatar if cost=None
    default_avatar = shop_collection.find_one({"type": "avatar", "cost": None})
    if default_avatar:
        user_data["currentAvatar"] = default_avatar["_id"]
        if default_avatar["_id"] not in user_data["purchasedItems"]:
            user_data["purchasedItems"].append(default_avatar["_id"])

    result = mainusers_collection.insert_one(user_data)
    return result.inserted_id

##############################################
# Update User Fields (CRITICAL)
##############################################

def update_user_fields(user_id, fields):
    """
    Generic helper to update given `fields` (dict) in mainusers_collection.
    """
    try:
        oid = ObjectId(user_id)
    except:
        return None
    mainusers_collection.update_one(
        {"_id": oid},
        {"$set": fields}
    )
    return True

##############################################
# Update User Coins
##############################################

def update_user_coins(user_id, amount):
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    mainusers_collection.update_one({"_id": oid}, {"$inc": {"coins": amount}})

##############################################
# Leveling System
##############################################
# Levels 2–30: +500 XP each
# Levels 31–60: +750 XP each
# Levels 61–100: +1000 XP each
# Above 100: +1500 XP each

def xp_required_for_level(level):
    """
    Returns total XP required to be at `level`.
    Level 1 starts at 0 XP.
    """
    if level < 1:
        return 0
    if level == 1:
        return 0
    if level <= 30:
        return 500 * (level - 1)
    elif level <= 60:
        base = 500 * 29  # up to level 30
        return base + 750 * (level - 30)
    elif level <= 100:
        base = 500 * 29 + 750 * 30  # up to level 60
        return base + 1000 * (level - 60)
    else:
        base = 500 * 29 + 750 * 30 + 1000 * 40  # up to level 100
        return base + 1500 * (level - 100)

def update_user_xp(user_id, xp_to_add):
    """
    Adds xp_to_add to the user's XP. Then, while the new XP total
    is >= XP required for the next level, increments the level.
    """
    user = get_user_by_id(user_id)
    if not user:
        return None

    old_xp = user.get("xp", 0)
    old_level = user.get("level", 1)
    new_xp = old_xp + xp_to_add
    new_level = old_level

    while new_xp >= xp_required_for_level(new_level + 1):
        new_level += 1

    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"xp": new_xp, "level": new_level}}
    )
    return {"xp": new_xp, "level": new_level}



##############################################
# Shop Logic
##############################################

def get_shop_items():
    """
    Returns all shop items from shop_collection,
    in ascending order by title (or another field),
    to ensure stable ordering.
    """
    return list(shop_collection.find({}).sort("title", 1))

def purchase_item(user_id, item_id):
    """
    Purchase an item from the shop:
      1) Check user has enough coins
      2) Ensure item not already purchased
      3) Deduct cost, add to purchasedItems
      4) If xpBoost, set user's xpBoost
      5) If avatar or nameColor, optionally set that field
    """
    user = get_user_by_id(user_id)
    if not user:
        return {"success": False, "message": "User not found"}

    try:
        oid = ObjectId(item_id)
    except Exception:
        return {"success": False, "message": "Invalid item ID"}

    item = shop_collection.find_one({"_id": oid})
    if not item:
        return {"success": False, "message": "Item not found"}

    user_coins = user.get("coins", 0)
    cost = item.get("cost", 0) if item.get("cost") is not None else 0
    if user_coins < cost:
        return {"success": False, "message": "Not enough coins"}

    purchased = user.get("purchasedItems", [])
    if oid in purchased:
        return {"success": False, "message": "Item already purchased"}

    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$inc": {"coins": -cost}}
    )
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$addToSet": {"purchasedItems": oid}}
    )

    item_type = item.get("type")
    if item_type == "xpBoost":
        new_boost = item.get("effectValue", 1.0)
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"xpBoost": new_boost}}
        )
    elif item_type == "avatar":
        pass
    elif item_type == "nameColor":
        new_color = item.get("effectValue", None)
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"nameColor": new_color}}
        )

    return {"success": True, "message": "Purchase successful"}

##############################################
# Achievements
##############################################

def get_achievements():
    return list(achievements_collection.find({}))
    

    
    

def get_test_by_id_and_category(test_id, category):
    """
    Fetch a single test doc by integer testId field and category field.
    """
    try:
        test_id_int = int(test_id)
    except:
        return None
    return tests_collection.find_one({
        "testId": test_id_int,
        "category": category
    })


    
   

def apply_daily_bonus(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return None

    now = datetime.utcnow()
    last_claim = user.get("lastDailyClaim")
    if not last_claim or (now - last_claim) > timedelta(hours=24):
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {
                "$inc": {"coins": 1000},
                "$set": {"lastDailyClaim": now}
            }
        )
        return {"success": True, "message": "Daily bonus applied"}
    else:
        return {"success": False, "message": "Already claimed daily bonus."}

def award_correct_answers_in_bulk(user_id, attempt_doc, xp_per_correct=10, coins_per_correct=5):
    """
    For examMode attempts, no XP was awarded during question-by-question.
    So at 'finish', we do the awarding for each newly-correct question that
    the user has never gotten correct before (per correctAnswers_collection).
    """
    user = get_user_by_id(user_id)
    if not user:
        return

    test_id = attempt_doc.get("testId")
    answers = attempt_doc.get("answers", [])

    # Tally how many new first-time correct answers the user got in this attempt
    newly_correct_count = 0
    for ans in answers:
        if ans.get("userAnswerIndex") == ans.get("correctAnswerIndex"):
            # it's correct
            qid = ans.get("questionId")
            already_correct = correctAnswers_collection.find_one({
                "userId": user["_id"],
                "testId": str(test_id),
                "questionId": qid
            })
            if not already_correct:
                # Insert it and increment counters
                correctAnswers_collection.insert_one({
                    "userId": user["_id"],
                    "testId": str(test_id),
                    "questionId": qid
                })
                newly_correct_count += 1

    if newly_correct_count > 0:
        # apply xp, coins
        total_xp = xp_per_correct * newly_correct_count
        total_coins = coins_per_correct * newly_correct_count
        update_user_xp(user_id, total_xp)
        update_user_coins(user_id, total_coins)    




# helpers/db_timing.py


def measure_db_operation(func):
    """
    Decorator to measure time of a single DB operation.
    Usage: decorate your typical DB calls or your function that does the operation.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start

        # If we have a 'db_time_accumulator' in Flask g, accumulate:
        if not hasattr(g, "db_time_accumulator"):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return result
    return wrapper


##################################
# mongodb/database.py (mostly same)
##################################
from flask import Flask
from flask_pymongo import PyMongo
import os

app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)
db = mongo.db

mainusers_collection = db.mainusers
shop_collection = db.shopItems
achievements_collection = db.achievements
tests_collection = db.tests
testAttempts_collection = db.testAttempts
correctAnswers_collection = db.correctAnswers
dailyQuestions_collection = db.dailyQuestions
dailyAnswers_collection = db.dailyAnswers
supportThreads_collection = db.supportThreads
# For suspicious activity
auditLogs_collection = db.auditLogs
# For caching if needed, but we used Redis above



now frotnend

// src/components/pages/store/AchievementPage.js
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { fetchAchievements } from '../store/achievementsSlice';
import { 
  FaTrophy, 
  FaMedal, 
  FaStar, 
  FaCrown, 
  FaBolt, 
  FaBook, 
  FaBrain, 
  FaCheckCircle, 
  FaMagic,
  FaFilter,
  FaTimes,
  FaCoins,
  FaLevelUpAlt,
  FaCheck,
  FaLock,
  FaInfoCircle,
  FaChevronDown,
  FaChevronUp,
  FaSearch,
  FaSyncAlt
} from 'react-icons/fa';
import { showAchievementToast } from './AchievementToast';
import './AchievementPage.css';

// Mapping achievement IDs to icon components.
const iconMapping = {
  "test_rookie": FaTrophy,
  "accuracy_king": FaMedal,
  "bronze_grinder": FaBook,
  "silver_scholar": FaStar,
  "gold_god": FaCrown,
  "platinum_pro": FaMagic,
  "walking_encyclopedia": FaBrain,
  "redemption_arc": FaBolt,
  "coin_collector_5000": FaBook,
  "coin_hoarder_10000": FaBook,
  "coin_tycoon_50000": FaBook,
  "perfectionist_1": FaCheckCircle,
  "double_trouble_2": FaCheckCircle,
  "error404_failure_not_found": FaCheckCircle,
  "level_up_5": FaTrophy,
  "mid_tier_grinder_25": FaMedal,
  "elite_scholar_50": FaStar,
  "ultimate_master_100": FaCrown,
  "answer_machine_1000": FaBook,
  "knowledge_beast_5000": FaBrain,
  "question_terminator": FaBrain,
  "test_finisher": FaCheckCircle,
};

// Mapping achievement IDs to colors.
const colorMapping = {
  "test_rookie": "#ff5555",
  "accuracy_king": "#ffa500",
  "bronze_grinder": "#cd7f32",
  "silver_scholar": "#c0c0c0",
  "gold_god": "#ffd700",
  "platinum_pro": "#e5e4e2",
  "walking_encyclopedia": "#00fa9a",
  "redemption_arc": "#ff4500",
  "coin_collector_5000": "#ff69b4",
  "coin_hoarder_10000": "#ff1493",
  "coin_tycoon_50000": "#ff0000",
  "perfectionist_1": "#adff2f",
  "double_trouble_2": "#7fff00",
  "error404_failure_not_found": "#00ffff",
  "level_up_5": "#f08080",
  "mid_tier_grinder_25": "#ff8c00",
  "elite_scholar_50": "#ffd700",
  "ultimate_master_100": "#ff4500",
  "answer_machine_1000": "#ff69b4",
  "knowledge_beast_5000": "#00fa9a",
  "question_terminator": "#ff1493",
  "test_finisher": "#adff2f",
};

// Achievement categories
const categories = {
  "test": "Test Completion",
  "score": "Score & Accuracy",
  "coins": "Coin Collection",
  "level": "Leveling Up",
  "questions": "Question Mastery",
  "all": "All Achievements"
};

// Function to determine the category of an achievement
const getAchievementCategory = (achievementId) => {
  if (achievementId.includes('level') || achievementId.includes('grinder') || 
      achievementId.includes('scholar') || achievementId.includes('master')) {
    return "level";
  } else if (achievementId.includes('coin')) {
    return "coins";
  } else if (achievementId.includes('accuracy') || achievementId.includes('perfectionist') || 
             achievementId.includes('redemption')) {
    return "score";
  } else if (achievementId.includes('answer') || achievementId.includes('question') || 
             achievementId.includes('encyclopedia')) {
    return "questions";
  } else if (achievementId.includes('rookie') || achievementId.includes('test') || 
             achievementId.includes('trouble')) {
    return "test";
  }
  return "all";
};

const AchievementPage = () => {
  const dispatch = useDispatch();
  const achievements = useSelector((state) => state.achievements.all);
  const userAchievements = useSelector((state) => state.user.achievements) || [];
  const { username, level, xp } = useSelector((state) => state.user);
  const loadingStatus = useSelector((state) => state.achievements.status);

  // State for filtering and sorting
  const [activeCategory, setActiveCategory] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [showOnlyUnlocked, setShowOnlyUnlocked] = useState(false);
  const [showOnlyLocked, setShowOnlyLocked] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState({});
  const [sortBy, setSortBy] = useState('default'); // default, name, unlocked
  
  // State for tracking achievement stats
  const [totalAchievements, setTotalAchievements] = useState(0);
  const [unlockedAchievements, setUnlockedAchievements] = useState(0);
  const [percentComplete, setPercentComplete] = useState(0);

  useEffect(() => {
    if (!achievements || achievements.length === 0) {
      dispatch(fetchAchievements());
    }
  }, [dispatch, achievements]);

  useEffect(() => {
    if (achievements && achievements.length > 0) {
      setTotalAchievements(achievements.length);
      setUnlockedAchievements(userAchievements.length);
      setPercentComplete((userAchievements.length / achievements.length) * 100);
    }
  }, [achievements, userAchievements]);

  // Filter achievements based on selected criteria
  const filteredAchievements = achievements.filter(achievement => {
    // Category filter
    const categoryMatch = activeCategory === 'all' || 
                        getAchievementCategory(achievement.achievementId) === activeCategory;
    
    // Unlock status filter
    const isUnlocked = userAchievements.includes(achievement.achievementId);
    const statusMatch = (showOnlyUnlocked && isUnlocked) || 
                      (showOnlyLocked && !isUnlocked) || 
                      (!showOnlyUnlocked && !showOnlyLocked);
    
    // Search filter
    const searchMatch = !searchTerm || 
                      achievement.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
                      achievement.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    return categoryMatch && statusMatch && searchMatch;
  });

  // Sort achievements
  const sortedAchievements = [...filteredAchievements].sort((a, b) => {
    const aUnlocked = userAchievements.includes(a.achievementId);
    const bUnlocked = userAchievements.includes(b.achievementId);
    
    if (sortBy === 'name') {
      return a.title.localeCompare(b.title);
    } else if (sortBy === 'unlocked') {
      return bUnlocked - aUnlocked; // Show unlocked first
    } else if (sortBy === 'locked') {
      return aUnlocked - bUnlocked; // Show locked first
    }
    
    // Default sorting
    return 0;
  });

  const toggleDetails = (achievementId) => {
    setDetailsOpen(prev => ({
      ...prev,
      [achievementId]: !prev[achievementId]
    }));
  };

  // Reset all filters
  const resetFilters = () => {
    setActiveCategory('all');
    setSearchTerm('');
    setShowOnlyUnlocked(false);
    setShowOnlyLocked(false);
    setSortBy('default');
  };

  // This function remains if you ever want to trigger a test popup programmatically
  const testPopup = (achievementId) => {
    const achievement = achievements.find((ach) => ach.achievementId === achievementId);
    if (achievement) {
      const IconComponent = iconMapping[achievement.achievementId] || null;
      const color = colorMapping[achievement.achievementId] || "#fff";
      showAchievementToast({
        title: achievement.title,
        description: achievement.description,
        icon: IconComponent ? <IconComponent /> : null,
        color: color
      });
    }
  };

  return (
    <div className="achievement-page-container">
      {/* Header Section with Stats */}
      <div className="achievement-header">
        <div className="achievement-header-content">
          <div className="achievement-header-titles">
            <h1>Achievement Gallery</h1>
            <p>Track your progress and unlock achievements as you master the platform!</p>
          </div>
          
          {username && (
            <div className="achievement-player-stats">
              <div className="achievement-player-name">
                <span>{username}'s Progress</span>
              </div>
              <div className="achievement-progress-container">
                <div className="achievement-progress-stats">
                  <div className="achievement-stat">
                    <FaTrophy className="achievement-stat-icon" />
                    <div className="achievement-stat-numbers">
                      <span className="achievement-stat-value">{unlockedAchievements} / {totalAchievements}</span>
                      <span className="achievement-stat-label">Achievements</span>
                    </div>
                  </div>
                  <div className="achievement-stat">
                    <FaLevelUpAlt className="achievement-stat-icon" />
                    <div className="achievement-stat-numbers">
                      <span className="achievement-stat-value">{level}</span>
                      <span className="achievement-stat-label">Level</span>
                    </div>
                  </div>
                </div>
                <div className="achievement-progress-bar-container">
                  <div className="achievement-progress-bar">
                    <div 
                      className="achievement-progress-fill" 
                      style={{ width: `${percentComplete}%` }}
                    ></div>
                  </div>
                  <span className="achievement-progress-percent">{Math.round(percentComplete)}% Complete</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Filter and Search Section */}
      <div className="achievement-controls">
        <div className="achievement-categories">
          {Object.entries(categories).map(([key, value]) => (
            <button
              key={key}
              className={`achievement-category-btn ${activeCategory === key ? 'active' : ''}`}
              onClick={() => setActiveCategory(key)}
            >
              {value}
            </button>
          ))}
        </div>
        
        <div className="achievement-filters">
          <div className="achievement-search">
            <FaSearch className="achievement-search-icon" />
            <input
              type="text"
              placeholder="Search achievements..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="achievement-search-input"
            />
            {searchTerm && (
              <button 
                className="achievement-search-clear" 
                onClick={() => setSearchTerm('')}
              >
                <FaTimes />
              </button>
            )}
          </div>
          
          <div className="achievement-filter-options">
            <button 
              className={`achievement-filter-btn ${showOnlyUnlocked ? 'active' : ''}`}
              onClick={() => {
                setShowOnlyUnlocked(!showOnlyUnlocked);
                setShowOnlyLocked(false);
              }}
            >
              <FaCheck />
              <span>Unlocked</span>
            </button>
            
            <button 
              className={`achievement-filter-btn ${showOnlyLocked ? 'active' : ''}`}
              onClick={() => {
                setShowOnlyLocked(!showOnlyLocked);
                setShowOnlyUnlocked(false);
              }}
            >
              <FaLock />
              <span>Locked</span>
            </button>
            
            <div className="achievement-sort-dropdown">
              <select 
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="achievement-sort-select"
              >
                <option value="default">Default Sort</option>
                <option value="name">Sort by Name</option>
                <option value="unlocked">Unlocked First</option>
                <option value="locked">Locked First</option>
              </select>
            </div>
            
            <button 
              className="achievement-filter-reset" 
              onClick={resetFilters}
              title="Reset all filters"
            >
              <FaSyncAlt />
            </button>
          </div>
        </div>
      </div>

      {/* Main Achievement Grid */}
      {loadingStatus === 'loading' ? (
        <div className="achievement-loading">
          <FaSyncAlt className="achievement-loading-icon" />
          <p>Loading achievements...</p>
        </div>
      ) : sortedAchievements.length > 0 ? (
        <div className="achievement-grid">
          {sortedAchievements.map((ach) => {
            const isUnlocked = userAchievements.includes(ach.achievementId);
            const IconComponent = iconMapping[ach.achievementId] || FaTrophy;
            const iconColor = colorMapping[ach.achievementId] || "#ffffff";
            const isDetailsOpen = detailsOpen[ach.achievementId] || false;
            
            return (
              <div
                key={ach.achievementId}
                className={`achievement-card ${isUnlocked ? 'unlocked' : 'locked'}`}
                onClick={() => toggleDetails(ach.achievementId)}
              >
                <div className="achievement-card-content">
                  <div className="achievement-icon-container">
                    <div className="achievement-icon" style={{ color: iconColor }}>
                      <IconComponent />
                    </div>
                    {isUnlocked && <div className="achievement-completed-badge"><FaCheck /></div>}
                  </div>
                  
                  <div className="achievement-info">
                    <h3 className="achievement-title">{ach.title}</h3>
                    <p className="achievement-description">{ach.description}</p>
                  </div>
                  
                  <button 
                    className="achievement-details-toggle"
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleDetails(ach.achievementId);
                    }}
                  >
                    {isDetailsOpen ? <FaChevronUp /> : <FaChevronDown />}
                  </button>
                </div>
                
                {isDetailsOpen && (
                  <div className="achievement-details">
                    <div className="achievement-details-content">
                      <div className="achievement-details-header">
                        <FaInfoCircle className="achievement-details-icon" />
                        <h4>Achievement Details</h4>
                      </div>
                      
                      <div className="achievement-details-info">
                        <div className="achievement-details-item">
                          <span className="achievement-details-label">Category:</span>
                          <span className="achievement-details-value">
                            {categories[getAchievementCategory(ach.achievementId)]}
                          </span>
                        </div>
                        
                        <div className="achievement-details-item">
                          <span className="achievement-details-label">Status:</span>
                          <span className={`achievement-details-value ${isUnlocked ? 'unlocked' : 'locked'}`}>
                            {isUnlocked ? 'Unlocked' : 'Locked'}
                          </span>
                        </div>
                        
                        {/* Add more achievement details as needed */}
                      </div>
                    </div>
                  </div>
                )}
                
                {!isUnlocked && (
                  <div className="achievement-locked-overlay">
                    <FaLock className="achievement-locked-icon" />
                    <span>Locked</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="achievement-empty">
          <FaFilter className="achievement-empty-icon" />
          <p>No achievements match your current filters.</p>
          <button className="achievement-reset-btn" onClick={resetFilters}>
            Reset Filters
          </button>
        </div>
      )}
    </div>
  );
};

export default AchievementPage;

// src/store/achievementsSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { registerUser, loginUser, dailyLoginBonus, addXP, addCoins, fetchUserData, logout, setCurrentUserId } from '../store/userSlice';


export const fetchAchievements = createAsyncThunk(
  'achievements/fetchAchievements',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/test/achievements');
      if (!response.ok) throw new Error('Failed to fetch achievements');
      return await response.json();
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

const achievementsSlice = createSlice({
  name: 'achievements',
  initialState: {
    all: [],
    status: 'idle',
    error: null,
    popups: []  // This can be used for temporary popup notifications
  },
  reducers: {
    // If you want to push a new achievement popup (for example, after unlocking an achievement)
    addPopup: (state, action) => {
      state.popups.push(action.payload);
    },
    removePopup: (state) => {
      state.popups.shift();
    }
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchAchievements.pending, (state) => {
        state.status = 'loading';
      })
      .addCase(fetchAchievements.fulfilled, (state, action) => {
        state.all = action.payload;
        state.status = 'succeeded';
      })
      .addCase(fetchAchievements.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      });
  }
});

export const { addPopup, removePopup } = achievementsSlice.actions;
export default achievementsSlice.reducer;


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
          password
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

export const { setCurrentUserId, logout, setXPAndCoins } = userSlice.actions;
export default userSlice.reducer;


import React, { useEffect, useState } from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import "../../test.css";
import {
  FaPlay,
  FaPause,
  FaRedo,
  FaEye,
  FaInfoCircle,
  FaChevronRight,
  FaLock,
  FaTrophy,
  FaCog,
  FaCheck,
  FaTimes,
  FaExclamationTriangle
} from "react-icons/fa";

const APlusTestList = () => {
  const navigate = useNavigate();
  const { userId } = useSelector((state) => state.user);
  const totalQuestionsPerTest = 100;
  const category = "aplus";

  const [attemptData, setAttemptData] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Persist examMode in localStorage
  const [examMode, setExamMode] = useState(() => {
    const stored = localStorage.getItem("examMode");
    return stored === "true";
  });

  // Show/hide tooltip for the info icon
  const [showExamInfo, setShowExamInfo] = useState(false);

  // Restart popup on the test list page (holds test number)
  const [restartPopupTest, setRestartPopupTest] = useState(null);

  // Choose test length
  const allowedTestLengths = [25, 50, 75, 100];
  const [selectedLengths, setSelectedLengths] = useState({});

  useEffect(() => {
    if (!userId) return;
    setLoading(true);

    const fetchAttempts = async () => {
      try {
        const res = await fetch(`/api/test/attempts/${userId}/list`);
        if (!res.ok) {
          throw new Error("Failed to fetch attempts for user");
        }
        const data = await res.json();
        const attemptList = data.attempts || [];

        // Filter attempts for this category
        const relevant = attemptList.filter((a) => a.category === category);

        // For each testId, pick the best attempt doc:
        const bestAttempts = {};
        for (let att of relevant) {
          const testKey = att.testId;
          if (!bestAttempts[testKey]) {
            bestAttempts[testKey] = att;
          } else {
            const existing = bestAttempts[testKey];
            // Prefer an unfinished attempt if it exists; otherwise latest finished
            if (!existing.finished && att.finished) {
              // Keep existing
            } else if (existing.finished && !att.finished) {
              bestAttempts[testKey] = att;
            } else {
              // Both finished or both unfinished => pick newest
              const existingTime = new Date(existing.finishedAt || 0).getTime();
              const newTime = new Date(att.finishedAt || 0).getTime();
              if (newTime > existingTime) {
                bestAttempts[testKey] = att;
              }
            }
          }
        }

        setAttemptData(bestAttempts);
        setLoading(false);
      } catch (err) {
        console.error(err);
        setError(err.message);
        setLoading(false);
      }
    };

    fetchAttempts();
  }, [userId, category]);

  // Save examMode to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem("examMode", examMode ? "true" : "false");
  }, [examMode]);

  if (!userId) {
    return (
      <div className="testlist-container">
        <div className="testlist-auth-message">
          <FaLock className="testlist-auth-icon" />
          <h2>Please log in to access the practice tests</h2>
          <button 
            className="testlist-login-button"
            onClick={() => navigate('/login')}
          >
            Go to Login
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="testlist-container">
        <div className="testlist-loading">
          <div className="testlist-loading-spinner"></div>
          <p>Loading your test progress...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="testlist-container">
        <div className="testlist-error">
          <FaExclamationTriangle className="testlist-error-icon" />
          <h2>Error Loading Tests</h2>
          <p>{error}</p>
          <button 
            className="testlist-retry-button"
            onClick={() => window.location.reload()}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const getAttemptDoc = (testNumber) => {
    return attemptData[testNumber] || null;
  };

  const getProgressDisplay = (attemptDoc) => {
    if (!attemptDoc) return { text: "Not started", percentage: 0 };
    
    const { finished, score, totalQuestions, currentQuestionIndex } = attemptDoc;
    
    if (finished) {
      const pct = Math.round((score / (totalQuestions || totalQuestionsPerTest)) * 100);
      return { 
        text: `Score: ${score}/${totalQuestions || totalQuestionsPerTest} (${pct}%)`, 
        percentage: pct,
        isFinished: true
      };
    } else {
      if (typeof currentQuestionIndex === "number") {
        const progressPct = Math.round(((currentQuestionIndex + 1) / (totalQuestions || totalQuestionsPerTest)) * 100);
        return { 
          text: `Progress: ${currentQuestionIndex + 1}/${totalQuestions || totalQuestionsPerTest}`, 
          percentage: progressPct,
          isFinished: false
        };
      }
      return { text: "Not started", percentage: 0 };
    }
  };

  const difficultyCategories = [
    { label: "Training Wheels", color: "#90ee90", textColor: "#1a1a1a" }, // Light green
    { label: "Easy Going", color: "#3cb371", textColor: "#ffffff" }, // Medium green
    { label: "Balanced", color: "#6543cc", textColor: "#ffffff" }, // Purple
    { label: "Challenging", color: "#ff7950", textColor: "#ffffff" }, // Orange
    { label: "Hard Core", color: "#cc4343", textColor: "#ffffff" }, // Red
    { label: "Very Hard", color: "#990000", textColor: "#ffffff" }, // Dark red
    { label: "Extreme", color: "#7a0099", textColor: "#ffffff" }, // Dark purple
    { label: "Nightmare", color: "#4a0072", textColor: "#ffffff" }, // Deep purple
    { label: "Insanity", color: "#2e004d", textColor: "#ffffff" }, // Very dark purple
    { label: "Ultra Level", color: "#000000", textColor: "#ff3366" }  // Black with neon text
  ];

  const startTest = (testNumber, doRestart = false, existingAttempt = null) => {
    if (existingAttempt && !doRestart) {
      // Resume test
      navigate(`/practice-tests/a-plus/${testNumber}`);
    } else {
      // New or forced restart
      const lengthToUse = selectedLengths[testNumber] || totalQuestionsPerTest;
      fetch(`/api/test/attempts/${userId}/${testNumber}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          category,
          answers: [],
          score: 0,
          totalQuestions: totalQuestionsPerTest,
          selectedLength: lengthToUse,
          currentQuestionIndex: 0,
          shuffleOrder: [],
          answerOrder: [],
          finished: false,
          examMode
        })
      })
        .then(() => {
          navigate(`/practice-tests/a-plus/${testNumber}`, {
            state: { examMode }
          });
        })
        .catch((err) => {
          console.error("Failed to create new attempt doc:", err);
        });
    }
  };

  const examInfoText = "Exam Mode simulates a real certification exam environment by hiding answer feedback and explanations until after you complete the entire test. This helps you prepare for the pressure and pace of an actual exam.";

  return (
    <div className="testlist-container">
      <div className="testlist-header">
        <div className="testlist-title-section">
          <h1 className="testlist-title">CompTIA A+ Core 1</h1>
          <p className="testlist-subtitle">Practice Test Collection</p>
        </div>
        
        <div className="testlist-mode-toggle">
          <div className="testlist-mode-label">
            <FaCog className="testlist-mode-icon" />
            <span>Exam Mode</span>
            
            <div className="testlist-info-container">
              <FaInfoCircle 
                className="testlist-info-icon"
                onMouseEnter={() => setShowExamInfo(true)}
                onMouseLeave={() => setShowExamInfo(false)}
                onClick={() => setShowExamInfo(!showExamInfo)}
              />
              
              {showExamInfo && (
                <div className="testlist-info-tooltip">
                  {examInfoText}
                </div>
              )}
            </div>
          </div>
          
          <label className="testlist-toggle">
            <input
              type="checkbox"
              checked={examMode}
              onChange={(e) => setExamMode(e.target.checked)}
            />
            <span className="testlist-toggle-slider">
              <span className="testlist-toggle-text">
                {examMode ? "ON" : "OFF"}
              </span>
            </span>
          </label>
        </div>
      </div>

      <div className="testlist-grid">
        {Array.from({ length: 10 }, (_, i) => {
          const testNumber = i + 1;
          const attemptDoc = getAttemptDoc(testNumber);
          const progress = getProgressDisplay(attemptDoc);
          const difficulty = difficultyCategories[i] || difficultyCategories[0];

          const isFinished = attemptDoc?.finished;
          const noAttempt = !attemptDoc;
          const inProgress = attemptDoc && !isFinished;

          return (
            <div key={testNumber} className={`testlist-card ${isFinished ? 'testlist-card-completed' : inProgress ? 'testlist-card-progress' : ''}`}>
              <div className="testlist-card-header">
                <div className="testlist-card-number">Test {testNumber}</div>
                <div 
                  className="testlist-difficulty" 
                  style={{ backgroundColor: difficulty.color, color: difficulty.textColor }}
                >
                  {difficulty.label}
                </div>
              </div>
              
              <div className="testlist-card-content">
                <div className="testlist-progress-section">
                  <div className="testlist-progress-text">{progress.text}</div>
                  <div className="testlist-progress-bar-container">
                    <div 
                      className={`testlist-progress-bar ${isFinished ? 'testlist-progress-complete' : ''}`}
                      style={{ width: `${progress.percentage}%` }}
                    ></div>
                  </div>
                </div>
                
                {/* Length Selector */}
                {(noAttempt || isFinished) && (
                  <div className="testlist-length-selector">
                    <div className="testlist-length-label">Select question count:</div>
                    <div className="testlist-length-options">
                      {allowedTestLengths.map((length) => (
                        <label 
                          key={length} 
                          className={`testlist-length-option ${(selectedLengths[testNumber] || totalQuestionsPerTest) === length ? 'selected' : ''}`}
                        >
                          <input
                            type="radio"
                            name={`testLength-${testNumber}`}
                            value={length}
                            checked={(selectedLengths[testNumber] || totalQuestionsPerTest) === length}
                            onChange={(e) => 
                              setSelectedLengths((prev) => ({
                                ...prev,
                                [testNumber]: Number(e.target.value)
                              }))
                            }
                          />
                          <span>{length}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* Action Buttons */}
                <div className={`testlist-card-actions ${inProgress ? 'two-buttons' : ''}`}>
                  {noAttempt && (
                    <button
                      className="testlist-action-button testlist-start-button"
                      onClick={() => startTest(testNumber, false, null)}
                    >
                      <FaPlay className="testlist-action-icon" />
                      <span>Start Test</span>
                    </button>
                  )}
                  
                  {inProgress && (
                    <>
                      <button
                        className="testlist-action-button testlist-resume-button"
                        onClick={() => startTest(testNumber, false, attemptDoc)}
                      >
                        <FaPlay className="testlist-action-icon" />
                        <span>Resume</span>
                      </button>
                      
                      <button
                        className="testlist-action-button testlist-restart-button"
                        onClick={() => setRestartPopupTest(testNumber)}
                      >
                        <FaRedo className="testlist-action-icon" />
                        <span>Restart</span>
                      </button>
                    </>
                  )}
                  
                  {isFinished && (
                    <>
                      <button
                        className="testlist-action-button testlist-review-button"
                        onClick={() => 
                          navigate(`/practice-tests/a-plus/${testNumber}`, {
                            state: { review: true }
                          })
                        }
                      >
                        <FaEye className="testlist-action-icon" />
                        <span>View Results</span>
                      </button>
                      
                      <button
                        className="testlist-action-button testlist-restart-button"
                        onClick={() => startTest(testNumber, true, attemptDoc)}
                      >
                        <FaRedo className="testlist-action-icon" />
                        <span>Restart</span>
                      </button>
                    </>
                  )}
                </div>
              </div>
              
              {isFinished && progress.percentage >= 80 && (
                <div className="testlist-achievement-badge">
                  <FaTrophy className="testlist-achievement-icon" />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Restart Confirmation Popup */}
      {restartPopupTest !== null && (
        <div className="testlist-popup-overlay">
          <div className="testlist-popup">
            <div className="testlist-popup-header">
              <FaExclamationTriangle className="testlist-popup-icon" />
              <h3>Confirm Restart</h3>
            </div>
            
            <div className="testlist-popup-content">
              <p>You're currently in progress on Test {restartPopupTest}. Are you sure you want to restart?</p>
              <p>All current progress will be lost, and your test will begin with your selected length.</p>
            </div>
            
            <div className="testlist-popup-actions">
              <button
                className="testlist-popup-button testlist-popup-confirm"
                onClick={() => {
                  const attemptDoc = getAttemptDoc(restartPopupTest);
                  startTest(restartPopupTest, true, attemptDoc);
                  setRestartPopupTest(null);
                }}
              >
                <FaCheck className="testlist-popup-button-icon" />
                <span>Yes, Restart</span>
              </button>
              
              <button 
                className="testlist-popup-button testlist-popup-cancel"
                onClick={() => setRestartPopupTest(null)}
              >
                <FaTimes className="testlist-popup-button-icon" />
                <span>Cancel</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default APlusTestList;

import React, {
  useState,
  useEffect,
  useCallback,
  useMemo,
  useRef
} from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useSelector, useDispatch } from "react-redux";
import { setXPAndCoins } from "./pages/store/userSlice";
import { fetchShopItems } from "./pages/store/shopSlice";
import ConfettiAnimation from "./ConfettiAnimation";
import { showAchievementToast } from "./pages/store/AchievementToast";
import "./test.css";
import iconMapping from "./iconMapping";
import colorMapping from "./colorMapping";
import {
  FaTrophy,
  FaMedal,
  FaStar,
  FaCrown,
  FaBolt,
  FaBook,
  FaBrain,
  FaCheckCircle,
  FaCoins,
  FaFlagCheckered,
  FaArrowLeft,
  FaArrowRight,
  FaRedoAlt,
  FaStepForward,
  FaExclamationTriangle,
  FaPlay,
  FaEye,
  FaChevronLeft,
  FaChevronRight,
  FaTimes,
  FaCheck,
  FaFlag,
  FaLevelUpAlt,
  FaSpinner,
  FaList,
  FaClipboardList,
  FaFilter,
  FaAngleDoubleRight,
  FaAngleDoubleLeft,
  FaUser
} from "react-icons/fa";

// Helper functions
function shuffleArray(arr) {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

function shuffleIndices(length) {
  const indices = Array.from({ length }, (_, i) => i);
  return shuffleArray(indices);
}

// Reusable QuestionDropdown component
const QuestionDropdown = ({
  totalQuestions,
  currentQuestionIndex,
  onQuestionSelect,
  answers,
  flaggedQuestions,
  testData,
  shuffleOrder,
  examMode
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const getQuestionStatus = (index) => {
    const realIndex = shuffleOrder[index];
    const question = testData.questions[realIndex];
    const answer = answers.find((a) => a.questionId === question.id);
    const isFlagged = flaggedQuestions.includes(question.id);
    const isAnswered = answer?.userAnswerIndex !== undefined;
    const isSkipped = answer?.userAnswerIndex === null;
    const isCorrect =
      answer && answer.userAnswerIndex === question.correctAnswerIndex;
    return { isAnswered, isSkipped, isCorrect, isFlagged };
  };

  return (
    <div className="question-dropdown" ref={dropdownRef}>
      <button onClick={() => setIsOpen(!isOpen)} className="dropdown-button">
        <FaList className="dropdown-icon" />
        <span>Question {currentQuestionIndex + 1} of {totalQuestions}</span>
      </button>
      {isOpen && (
        <div className="dropdown-content">
          {Array.from({ length: totalQuestions }, (_, i) => {
            const status = getQuestionStatus(i);
            let statusClass = "";
            if (status.isAnswered && !status.isSkipped) {
              statusClass = status.isCorrect ? "correct" : "incorrect";
            } else if (status.isSkipped) {
              statusClass = "skipped";
            }
            
            return (
              <button
                key={i}
                onClick={() => {
                  onQuestionSelect(i);
                  setIsOpen(false);
                }}
                className={`dropdown-item ${i === currentQuestionIndex ? 'active' : ''} ${statusClass}`}
              >
                <span>Question {i + 1}</span>
                <div className="status-indicators">
                  {status.isSkipped && <span className="skip-indicator">⏭️</span>}
                  {status.isFlagged && <span className="flag-indicator">🚩</span>}
                  {!examMode && status.isAnswered && !status.isSkipped && (
                    <span
                      className={
                        status.isCorrect
                          ? "answer-indicator correct"
                          : "answer-indicator incorrect"
                      }
                    >
                      {status.isCorrect ? "✓" : "✗"}
                    </span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};

const GlobalTestPage = ({
  testId,
  category,
  backToListPath
}) => {
  const location = useLocation();
  const navigate = useNavigate();
  const dispatch = useDispatch();

  // Redux user data
  const { xp, level, coins, userId, xpBoost, currentAvatar } = useSelector(
    (state) => state.user
  );
  const achievements = useSelector((state) => state.achievements.all);
  const { items: shopItems, status: shopStatus } = useSelector(
    (state) => state.shop
  );

  // Local states for test logic
  const [testData, setTestData] = useState(null);
  const [shuffleOrder, setShuffleOrder] = useState([]);
  const [answerOrder, setAnswerOrder] = useState([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [answers, setAnswers] = useState([]);
  const [score, setScore] = useState(0);
  const [loadingTest, setLoadingTest] = useState(true);
  const [error, setError] = useState(null);
  const [isAnswered, setIsAnswered] = useState(false);
  const [selectedOptionIndex, setSelectedOptionIndex] = useState(null);
  const [isFinished, setIsFinished] = useState(false);

  // Overlays
  const [showScoreOverlay, setShowScoreOverlay] = useState(false);
  const [showReviewMode, setShowReviewMode] = useState(false);

  // Confetti on level-up
  const [localLevel, setLocalLevel] = useState(level);
  const [showLevelUpOverlay, setShowLevelUpOverlay] = useState(false);

  // Flags
  const [flaggedQuestions, setFlaggedQuestions] = useState([]);

  // Confirmation popups
  const [showRestartPopup, setShowRestartPopup] = useState(false);
  const [showFinishPopup, setShowFinishPopup] = useState(false);
  const [showNextPopup, setShowNextPopup] = useState(false);

  // Exam mode
  const [examMode, setExamMode] = useState(false);

  // Test length selection state
  const allowedTestLengths = [25, 50, 75, 100];
  const [selectedLength, setSelectedLength] = useState(100);
  const [activeTestLength, setActiveTestLength] = useState(null);
  const [showTestLengthSelector, setShowTestLengthSelector] = useState(false);

  useEffect(() => {
    if (shopStatus === "idle") {
      dispatch(fetchShopItems());
    }
  }, [shopStatus, dispatch]);

  const fetchTestAndAttempt = async () => {
    setLoadingTest(true);
    try {
      let attemptDoc = null;
      if (userId) {
        const attemptRes = await fetch(`/api/test/attempts/${userId}/${testId}`);
        const attemptData = await attemptRes.json();
        attemptDoc = attemptData.attempt || null;
      }
      const testRes = await fetch(`/api/test/tests/${category}/${testId}`);
      if (!testRes.ok) {
        const errData = await testRes.json().catch(() => ({}));
        throw new Error(errData.error || "Failed to fetch test data");
      }
      const testDoc = await testRes.json();
      setTestData(testDoc);

      const totalQ = testDoc.questions.length;

      // Check if attempt exists
      if (attemptDoc) {
        // If the test is already finished, we keep the data but also mark isFinished
        setAnswers(attemptDoc.answers || []);
        setScore(attemptDoc.score || 0);
        setIsFinished(attemptDoc.finished === true);

        const attemptExam = attemptDoc.examMode || false;
        setExamMode(attemptExam);

        // Use the chosen length if available
        const chosenLength = attemptDoc.selectedLength || totalQ;

        if (
          attemptDoc.shuffleOrder &&
          attemptDoc.shuffleOrder.length === chosenLength
        ) {
          setShuffleOrder(attemptDoc.shuffleOrder);
        } else {
          const newQOrder = shuffleIndices(chosenLength);
          setShuffleOrder(newQOrder);
        }

        if (
          attemptDoc.answerOrder &&
          attemptDoc.answerOrder.length === chosenLength
        ) {
          setAnswerOrder(attemptDoc.answerOrder);
        } else {
          const generatedAnswerOrder = testDoc.questions
            .slice(0, chosenLength)
            .map((q) => {
              const numOptions = q.options.length;
              return shuffleArray([...Array(numOptions).keys()]);
            });
          setAnswerOrder(generatedAnswerOrder);
        }

        setCurrentQuestionIndex(attemptDoc.currentQuestionIndex || 0);
        setActiveTestLength(chosenLength);
      } else {
        // No attempt doc exists: show the test length selector UI
        setActiveTestLength(null);
        setShowTestLengthSelector(true);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingTest(false);
    }
  };

  useEffect(() => {
    fetchTestAndAttempt();
  }, [testId, userId]);

  useEffect(() => {
    if (level > localLevel) {
      setLocalLevel(level);
      setShowLevelUpOverlay(true);
      const t = setTimeout(() => setShowLevelUpOverlay(false), 3000);
      return () => clearTimeout(t);
    }
  }, [level, localLevel]);

  useEffect(() => {
    if (location.state?.review && isFinished) {
      setShowReviewMode(true);
    }
  }, [location.state, isFinished]);

  const getShuffledIndex = useCallback(
    (i) => {
      if (!shuffleOrder || shuffleOrder.length === 0) return i;
      return shuffleOrder[i];
    },
    [shuffleOrder]
  );

  const effectiveTotal =
    activeTestLength || (testData ? testData.questions.length : 0);

  const realIndex = getShuffledIndex(currentQuestionIndex);
  const questionObject =
    testData && testData.questions && testData.questions.length > 0
      ? testData.questions[realIndex]
      : null;

  useEffect(() => {
    if (!questionObject) return;
    const existing = answers.find((a) => a.questionId === questionObject.id);
    if (existing) {
      setSelectedOptionIndex(null);
      if (
        existing.userAnswerIndex !== null &&
        existing.userAnswerIndex !== undefined
      ) {
        const displayIndex = answerOrder[realIndex].indexOf(
          existing.userAnswerIndex
        );
        if (displayIndex >= 0) {
          setSelectedOptionIndex(displayIndex);
          setIsAnswered(true);
        } else {
          setIsAnswered(false);
        }
      } else {
        setIsAnswered(false);
      }
    } else {
      setSelectedOptionIndex(null);
      setIsAnswered(false);
    }
  }, [questionObject, answers, realIndex, answerOrder]);

  const updateServerProgress = useCallback(
    async (updatedAnswers, updatedScore, finished = false, singleAnswer = null) => {
      if (!userId) return;
      try {
        if (singleAnswer) {
          const res = await fetch(`/api/test/user/${userId}/submit-answer`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              testId,
              questionId: singleAnswer.questionId,
              correctAnswerIndex: singleAnswer.correctAnswerIndex,
              selectedIndex: singleAnswer.userAnswerIndex,
              xpPerCorrect: (testData?.xpPerCorrect || 10) * xpBoost,
              coinsPerCorrect: 5
            })
          });
          const data = await res.json();
          return data;
        }
        await fetch(`/api/test/attempts/${userId}/${testId}/position`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            currentQuestionIndex,
            finished
          })
        });
      } catch (err) {
        console.error("Failed to update test attempt on backend", err);
      }
    },
    [userId, testId, testData, xpBoost, currentQuestionIndex]
  );

  // In exam mode, allow answer switching; in non–exam mode, lock answer selection once chosen.
  const handleOptionClick = useCallback(
    async (displayOptionIndex) => {
      if (!questionObject) return;
      if (!examMode && isAnswered) return; // Only block if exam mode is off.
      const actualAnswerIndex = answerOrder[realIndex][displayOptionIndex];
      setSelectedOptionIndex(displayOptionIndex);

      // For non–exam mode, lock the answer; for exam mode, allow changes.
      if (!examMode) {
        setIsAnswered(true);
      }
      try {
        const newAnswerObj = {
          questionId: questionObject.id,
          userAnswerIndex: actualAnswerIndex,
          correctAnswerIndex: questionObject.correctAnswerIndex
        };
        const updatedAnswers = [...answers];
        const idx = updatedAnswers.findIndex(
          (a) => a.questionId === questionObject.id
        );
        if (idx >= 0) {
          updatedAnswers[idx] = newAnswerObj;
        } else {
          updatedAnswers.push(newAnswerObj);
        }
        setAnswers(updatedAnswers);

        const awardData = await updateServerProgress(
          updatedAnswers,
          score,
          false,
          newAnswerObj
        );
        if (!examMode && awardData && awardData.examMode === false) {
          if (awardData.isCorrect) {
            setScore((prev) => prev + 1);
          }
          if (awardData.isCorrect && !awardData.alreadyCorrect && awardData.awardedXP) {
            dispatch(
              setXPAndCoins({
                xp: awardData.newXP,
                coins: awardData.newCoins
              })
            );
          }
        }
      } catch (err) {
        console.error("Failed to submit answer to backend", err);
      }
    },
    [
      isAnswered,
      questionObject,
      examMode,
      testData,
      xpBoost,
      userId,
      testId,
      dispatch,
      score,
      answers,
      updateServerProgress,
      realIndex,
      answerOrder
    ]
  );

  const finishTestProcess = useCallback(async () => {
    let finalScore = 0;
    answers.forEach((ans) => {
      if (ans.userAnswerIndex === ans.correctAnswerIndex) {
        finalScore++;
      }
    });
    setScore(finalScore);
    try {
      const res = await fetch(`/api/test/attempts/${userId}/${testId}/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          score: finalScore,
          totalQuestions: effectiveTotal
        })
      });
      const finishData = await res.json();

      if (finishData.newlyUnlocked && finishData.newlyUnlocked.length > 0) {
        finishData.newlyUnlocked.forEach((achievementId) => {
          const achievement = achievements.find(
            (a) => a.achievementId === achievementId
          );
          if (achievement) {
            const IconComp = iconMapping[achievement.achievementId] || null;
            const color = colorMapping[achievement.achievementId] || "#fff";
            showAchievementToast({
              title: achievement.title,
              description: achievement.description,
              icon: IconComp ? <IconComp /> : null,
              color
            });
          }
        });
      }

      if (
        typeof finishData.newXP !== "undefined" &&
        typeof finishData.newCoins !== "undefined"
      ) {
        dispatch(
          setXPAndCoins({
            xp: finishData.newXP,
            coins: finishData.newCoins
          })
        );
      }
    } catch (err) {
      console.error("Failed to finish test attempt:", err);
    }
    setIsFinished(true);
    setShowScoreOverlay(true);
    setShowReviewMode(false);
  }, [answers, userId, testId, effectiveTotal, achievements, dispatch]);

  const handleNextQuestion = useCallback(() => {
    if (!isAnswered && !examMode) {
      setShowNextPopup(true);
      return;
    }
    if (currentQuestionIndex === effectiveTotal - 1) {
      finishTestProcess();
      return;
    }
    const nextIndex = currentQuestionIndex + 1;
    setCurrentQuestionIndex(nextIndex);
    updateServerProgress(answers, score, false);
  }, [
    isAnswered,
    examMode,
    currentQuestionIndex,
    effectiveTotal,
    finishTestProcess,
    updateServerProgress,
    answers,
    score
  ]);

  const handlePreviousQuestion = useCallback(() => {
    if (currentQuestionIndex > 0) {
      const prevIndex = currentQuestionIndex - 1;
      setCurrentQuestionIndex(prevIndex);
      updateServerProgress(answers, score, false);
    }
  }, [currentQuestionIndex, updateServerProgress, answers, score]);

  const handleSkipQuestion = () => {
    if (!questionObject) return;
    const updatedAnswers = [...answers];
    const idx = updatedAnswers.findIndex(
      (a) => a.questionId === questionObject.id
    );
    const skipObj = {
      questionId: questionObject.id,
      userAnswerIndex: null,
      correctAnswerIndex: questionObject.correctAnswerIndex
    };
    if (idx >= 0) {
      updatedAnswers[idx] = skipObj;
    } else {
      updatedAnswers.push(skipObj);
    }
    setAnswers(updatedAnswers);
    setIsAnswered(false);
    setSelectedOptionIndex(null);
    updateServerProgress(updatedAnswers, score, false, skipObj);
    if (currentQuestionIndex === effectiveTotal - 1) {
      finishTestProcess();
      return;
    }
    setCurrentQuestionIndex(currentQuestionIndex + 1);
  };

  const handleFlagQuestion = () => {
    if (!questionObject) return;
    const qId = questionObject.id;
    if (flaggedQuestions.includes(qId)) {
      setFlaggedQuestions(flaggedQuestions.filter((x) => x !== qId));
    } else {
      setFlaggedQuestions([...flaggedQuestions, qId]);
    }
  };

  const handleRestartTest = useCallback(async () => {
    setCurrentQuestionIndex(0);
    setSelectedOptionIndex(null);
    setIsAnswered(false);
    setScore(0);
    setAnswers([]);
    setFlaggedQuestions([]);
    setIsFinished(false);
    setShowReviewMode(false);
    setShowScoreOverlay(false);

    if (testData?.questions?.length && activeTestLength) {
      const newQOrder = shuffleIndices(activeTestLength);
      setShuffleOrder(newQOrder);
      const newAnswerOrder = testData.questions
        .slice(0, activeTestLength)
        .map((q) => {
          const numOpts = q.options.length;
          return shuffleArray([...Array(numOpts).keys()]);
        });
      setAnswerOrder(newAnswerOrder);

      if (userId && testId) {
        await fetch(`/api/test/attempts/${userId}/${testId}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            answers: [],
            score: 0,
            totalQuestions: testData.questions.length,
            selectedLength: activeTestLength,
            category: testData.category || category,
            currentQuestionIndex: 0,
            shuffleOrder: newQOrder,
            answerOrder: newAnswerOrder,
            finished: false,
            examMode
          })
        });
      }
    }
  }, [
    testData,
    userId,
    testId,
    category,
    examMode,
    activeTestLength
  ]);

  const handleFinishTest = () => {
    finishTestProcess();
  };

  const [reviewFilter, setReviewFilter] = useState("all");
  const handleReviewAnswers = () => {
    setShowReviewMode(true);
    setReviewFilter("all");
  };
  const handleCloseReview = () => {
    if (!isFinished) setShowReviewMode(false);
  };

  const filteredQuestions = useMemo(() => {
    if (!testData || !testData.questions) return [];
    return testData.questions.slice(0, effectiveTotal).filter((q) => {
      const userAns = answers.find((a) => a.questionId === q.id);
      const isFlagged = flaggedQuestions.includes(q.id);

      if (!userAns) {
        // Not answered => count it as "skipped" or "all"
        return reviewFilter === "skipped" || reviewFilter === "all";
      }

      const isSkipped = userAns.userAnswerIndex === null;
      const isCorrect = userAns.userAnswerIndex === q.correctAnswerIndex;

      if (reviewFilter === "all") return true;
      if (reviewFilter === "skipped" && isSkipped) return true;
      if (reviewFilter === "flagged" && isFlagged) return true;
      if (reviewFilter === "incorrect" && !isCorrect && !isSkipped) return true;
      if (reviewFilter === "correct" && isCorrect && !isSkipped) return true;

      return false;
    });
  }, [testData, answers, flaggedQuestions, reviewFilter, effectiveTotal]);

  const NextQuestionAlert = ({ message, onOk }) => (
    <div className="confirm-popup-overlay">
      <div className="confirm-popup-content">
        <div className="alert-header">
          <FaExclamationTriangle className="alert-icon" />
          <h3>Attention</h3>
        </div>
        <p>{message}</p>
        <div className="confirm-popup-buttons">
          <button className="confirm-popup-ok" onClick={onOk}>
            <FaCheck className="button-icon" />
            <span>OK</span>
          </button>
        </div>
      </div>
    </div>
  );

  const renderNextPopup = () => {
    if (!showNextPopup) return null;
    return (
      <NextQuestionAlert
        message="You haven't answered this question yet. Please select an answer or skip the question."
        onOk={() => {
          setShowNextPopup(false);
        }}
      />
    );
  };

  const ConfirmPopup = ({ message, onConfirm, onCancel }) => (
    <div className="confirm-popup-overlay">
      <div className="confirm-popup-content">
        <div className="alert-header">
          <FaExclamationTriangle className="alert-icon" />
          <h3>Confirm Action</h3>
        </div>
        <p>{message}</p>
        <div className="confirm-popup-buttons">
          <button className="confirm-popup-yes" onClick={onConfirm}>
            <FaCheck className="button-icon" />
            <span>Yes</span>
          </button>
          <button className="confirm-popup-no" onClick={onCancel}>
            <FaTimes className="button-icon" />
            <span>No</span>
          </button>
        </div>
      </div>
    </div>
  );

  const renderRestartPopup = () => {
    if (!showRestartPopup) return null;
    return (
      <ConfirmPopup
        message="Are you sure you want to restart the test? All progress will be lost and you'll start from the beginning."
        onConfirm={() => {
          handleRestartTest();
          setShowRestartPopup(false);
        }}
        onCancel={() => setShowRestartPopup(false)}
      />
    );
  };

  const renderFinishPopup = () => {
    if (!showFinishPopup) return null;
    return (
      <ConfirmPopup
        message="Are you sure you want to finish the test now? Any unanswered questions will be marked as skipped."
        onConfirm={() => {
          handleFinishTest();
          setShowFinishPopup(false);
        }}
        onCancel={() => setShowFinishPopup(false)}
      />
    );
  };

  const renderScoreOverlay = () => {
    if (!showScoreOverlay) return null;
    const percentage = effectiveTotal
      ? Math.round((score / effectiveTotal) * 100)
      : 0;
      
    // Determine grade based on percentage
    let grade = "";
    let gradeClass = "";
    
    if (percentage >= 90) {
      grade = "Outstanding!";
      gradeClass = "grade-a-plus";
    } else if (percentage >= 80) {
      grade = "Excellent!";
      gradeClass = "grade-a";
    } else if (percentage >= 70) {
      grade = "Great Job!";
      gradeClass = "grade-b";
    } else if (percentage >= 60) {
      grade = "Good Effort!";
      gradeClass = "grade-c";
    } else {
      grade = "Keep Practicing!";
      gradeClass = "grade-d";
    }
    
    return (
      <div className="score-overlay">
        <div className="score-content">
          <h2 className="score-title">Test Complete!</h2>
          
          <div className="score-grade-container">
            <div className={`score-grade ${gradeClass}`}>
              <div className="percentage-display">{percentage}%</div>
              <div className="grade-label">{grade}</div>
            </div>
            
            <div className="score-details-container">
              <p className="score-details">
                You answered <strong>{score}</strong> out of <strong>{effectiveTotal}</strong> questions correctly.
              </p>
              
              {examMode && (
                <div className="exam-mode-note">
                  <FaTrophy className="exam-icon" />
                  <p>You completed this test in exam mode!</p>
                </div>
              )}
            </div>
          </div>

          {/* Test Length selection after finishing */}
          <div className="length-selection">
            <p>Select Length for Next Attempt:</p>
            <div className="length-selector-options">
              {allowedTestLengths.map((length) => (
                <label
                  key={length}
                  className={`length-option ${selectedLength === length ? 'selected' : ''}`}
                >
                  <input
                    type="radio"
                    name="finishedTestLength"
                    value={length}
                    checked={selectedLength === length}
                    onChange={(e) => {
                      const newLen = Number(e.target.value);
                      setSelectedLength(newLen);
                      setActiveTestLength(newLen);
                    }}
                  />
                  <span>{length}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="overlay-buttons">
            <button
              className="restart-button"
              onClick={() => setShowRestartPopup(true)}
            >
              <FaRedoAlt className="button-icon" />
              <span>Restart Test</span>
            </button>
            
            <button 
              className="review-button" 
              onClick={handleReviewAnswers}
            >
              <FaEye className="button-icon" />
              <span>Review Answers</span>
            </button>
            
            <button 
              className="back-btn" 
              onClick={() => navigate(backToListPath)}
            >
              <FaArrowLeft className="button-icon" />
              <span>Back to List</span>
            </button>
            
            {Number(testId) < 9999 && (
              <button
                className="next-test-button"
                onClick={() => navigate(`${backToListPath}/${Number(testId) + 1}`)}
              >
                <FaArrowRight className="button-icon" />
                <span>Next Test</span>
              </button>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderReviewMode = () => {
    if (!showReviewMode) return null;
    return (
      <div className="score-overlay review-overlay">
        <div className="score-content review-content">
          {isFinished ? (
            <button
              className="back-to-list-btn"
              onClick={() => navigate(backToListPath)}
            >
              <FaArrowLeft className="button-icon" />
              <span>Back to Test List</span>
            </button>
          ) : (
            <button className="close-review-x" onClick={handleCloseReview}>
              <FaTimes />
            </button>
          )}
          <h2 className="score-title">Review Mode</h2>
          {isFinished && (
            <p className="review-score-line">
              Your final score: {score}/{effectiveTotal} (
              {effectiveTotal ? Math.round((score / effectiveTotal) * 100) : 0}
              %)
            </p>
          )}
          <div className="review-filter-buttons">
            <button
              className={reviewFilter === "all" ? "active-filter" : ""}
              onClick={() => setReviewFilter("all")}
            >
              <FaClipboardList className="filter-icon" />
              <span>All</span>
            </button>
            <button
              className={reviewFilter === "skipped" ? "active-filter" : ""}
              onClick={() => setReviewFilter("skipped")}
            >
              <FaStepForward className="filter-icon" />
              <span>Skipped</span>
            </button>
            <button
              className={reviewFilter === "flagged" ? "active-filter" : ""}
              onClick={() => setReviewFilter("flagged")}
            >
              <FaFlag className="filter-icon" />
              <span>Flagged</span>
            </button>
            <button
              className={reviewFilter === "incorrect" ? "active-filter" : ""}
              onClick={() => setReviewFilter("incorrect")}
            >
              <FaTimes className="filter-icon" />
              <span>Incorrect</span>
            </button>
            <button
              className={reviewFilter === "correct" ? "active-filter" : ""}
              onClick={() => setReviewFilter("correct")}
            >
              <FaCheck className="filter-icon" />
              <span>Correct</span>
            </button>
          </div>
          <p className="review-filter-count">
            Showing {filteredQuestions.length} questions
          </p>
          <div className="review-mode-container">
            {filteredQuestions.map((q, idx) => {
              const userAns = answers.find((a) => a.questionId === q.id);
              const isFlagged = flaggedQuestions.includes(q.id);

              if (!userAns) {
                return (
                  <div key={q.id} className="review-question-card">
                    <div className="review-question-header">
                      <span className="question-number">Question {idx + 1}</span>
                      {isFlagged && <span className="flagged-icon">🚩</span>}
                    </div>
                    <h3>{q.question}</h3>
                    <div className="review-answer-section unanswered">
                      <p className="review-status-label">
                        <FaExclamationTriangle className="status-icon warning" />
                        <span>Not Answered</span>
                      </p>
                      <p className="correct-answer">
                        <strong>Correct Answer:</strong>{" "}
                        {q.options[q.correctAnswerIndex]}
                      </p>
                    </div>
                    <div className="review-explanation">
                      <p>{q.explanation}</p>
                    </div>
                  </div>
                );
              }

              const isSkipped = userAns.userAnswerIndex === null;
              const isCorrect = userAns.userAnswerIndex === q.correctAnswerIndex;

              return (
                <div key={q.id} className={`review-question-card ${isSkipped ? 'skipped' : isCorrect ? 'correct' : 'incorrect'}`}>
                  <div className="review-question-header">
                    <span className="question-number">Question {idx + 1}</span>
                    {isFlagged && <span className="flagged-icon">🚩</span>}
                  </div>
                  <h3>{q.question}</h3>
                  <div className={`review-answer-section ${isSkipped ? 'skipped' : isCorrect ? 'correct' : 'incorrect'}`}>
                    <p className="review-status-label">
                      {isSkipped ? (
                        <>
                          <FaStepForward className="status-icon skipped" />
                          <span>Skipped</span>
                        </>
                      ) : isCorrect ? (
                        <>
                          <FaCheck className="status-icon correct" />
                          <span>Correct!</span>
                        </>
                      ) : (
                        <>
                          <FaTimes className="status-icon incorrect" />
                          <span>Incorrect</span>
                        </>
                      )}
                    </p>
                    
                    {!isSkipped && (
                      <p className="your-answer">
                        <strong>Your Answer:</strong>{" "}
                        {q.options[userAns.userAnswerIndex]}
                      </p>
                    )}
                    
                    <p className="correct-answer">
                      <strong>Correct Answer:</strong>{" "}
                      {q.options[q.correctAnswerIndex]}
                    </p>
                  </div>
                  <div className="review-explanation">
                    <p>{q.explanation}</p>
                  </div>
                </div>
              );
            })}
          </div>
          {!isFinished && (
            <button
              className="review-button close-review-btn"
              onClick={handleCloseReview}
            >
              <FaTimes className="button-icon" />
              <span>Close Review</span>
            </button>
          )}
        </div>
      </div>
    );
  };

  const handleNextQuestionButtonClick = () => {
    if (!isAnswered && !examMode) {
      setShowNextPopup(true);
    } else {
      handleNextQuestion();
    }
  };

  // If no attempt doc was found (on first load), show test length UI:
  if (showTestLengthSelector) {
    return (
      <div className="aplus-test-container">
        <div className="test-length-selector">
          <h2>Select Test Length</h2>
          <div className="test-mode-indicator">
            <span className={examMode ? 'exam-on' : 'exam-off'}>
              {examMode ? 'Exam Mode: ON' : 'Practice Mode'}
            </span>
          </div>
          <p>How many questions would you like to answer?</p>
          <div className="test-length-options">
            {allowedTestLengths.map((length) => (
              <label 
                key={length}
                className={selectedLength === length ? 'selected' : ''}
              >
                <input
                  type="radio"
                  name="testLength"
                  value={length}
                  checked={selectedLength === length}
                  onChange={(e) => setSelectedLength(Number(e.target.value))}
                />
                <span>{length}</span>
              </label>
            ))}
          </div>
          <button
            onClick={async () => {
              setActiveTestLength(selectedLength);
              if (testData) {
                const totalQ = testData.questions.length;
                const newQOrder = shuffleIndices(selectedLength);
                setShuffleOrder(newQOrder);
                const newAnswerOrder = testData.questions
                  .slice(0, selectedLength)
                  .map((q) => {
                    const numOpts = q.options.length;
                    return shuffleArray([...Array(numOpts).keys()]);
                  });
                setAnswerOrder(newAnswerOrder);
                try {
                  await fetch(`/api/test/attempts/${userId}/${testId}`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      answers: [],
                      score: 0,
                      totalQuestions: totalQ,
                      selectedLength: selectedLength,
                      category: testData.category || category,
                      currentQuestionIndex: 0,
                      shuffleOrder: newQOrder,
                      answerOrder: newAnswerOrder,
                      finished: false,
                      examMode: location.state?.examMode || false
                    })
                  });
                  setShowTestLengthSelector(false);
                  fetchTestAndAttempt();
                } catch (err) {
                  console.error("Failed to start new attempt", err);
                }
              }
            }}
          >
            <FaPlay className="button-icon" />
            <span>Start Test</span>
          </button>
          <button 
            className="back-to-list-btn"
            onClick={() => navigate(backToListPath)}
          >
            <FaArrowLeft className="button-icon" />
            <span>Back to Test List</span>
          </button>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="aplus-test-container">
        <div className="test-error-container">
          <FaExclamationTriangle className="test-error-icon" />
          <h2>Error Loading Test</h2>
          <p>{error}</p>
          <div className="test-error-actions">
            <button onClick={() => window.location.reload()}>
              <FaRedoAlt className="button-icon" />
              <span>Try Again</span>
            </button>
            <button onClick={() => navigate(backToListPath)}>
              <FaArrowLeft className="button-icon" />
              <span>Back to Test List</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (loadingTest) {
    return (
      <div className="aplus-test-container">
        <div className="test-loading-container">
          <div className="test-loading-spinner">
            <FaSpinner className="spinner-icon" />
          </div>
          <p>Loading test data...</p>
        </div>
      </div>
    );
  }

  if (!testData || !testData.questions || testData.questions.length === 0) {
    return (
      <div className="aplus-test-container">
        <div className="test-error-container">
          <FaExclamationTriangle className="test-error-icon" />
          <h2>No Questions Found</h2>
          <p>This test doesn't have any questions yet.</p>
          <button onClick={() => navigate(backToListPath)}>
            <FaArrowLeft className="button-icon" />
            <span>Back to Test List</span>
          </button>
        </div>
      </div>
    );
  }

  let avatarUrl = "https://via.placeholder.com/60";
  if (currentAvatar && shopItems && shopItems.length > 0) {
    const avatarItem = shopItems.find((item) => item._id === currentAvatar);
    if (avatarItem && avatarItem.imageUrl) {
      avatarUrl = avatarItem.imageUrl;
    }
  }

  const progressPercentage = effectiveTotal
    ? Math.round(((currentQuestionIndex + 1) / effectiveTotal) * 100)
    : 0;
  const progressColorHue = (progressPercentage * 120) / 100; // from red to green
  const progressColor = `hsl(${progressColorHue}, 100%, 50%)`;

  let displayedOptions = [];
  if (questionObject && answerOrder[realIndex]) {
    displayedOptions = answerOrder[realIndex].map(
      (optionIdx) => questionObject.options[optionIdx]
    );
  }

  return (
    <div className="aplus-test-container">
      <ConfettiAnimation trigger={showLevelUpOverlay} level={level} />

      {renderRestartPopup()}
      {renderFinishPopup()}
      {renderNextPopup()}
      {renderScoreOverlay()}
      {renderReviewMode()}

      <div className="top-control-bar">
        <button 
          className={`flag-btn ${questionObject && flaggedQuestions.includes(questionObject.id) ? 'active' : ''}`} 
          onClick={handleFlagQuestion}
          disabled={!questionObject}
        >
          <FaFlag className="button-icon" />
          <span>{questionObject && flaggedQuestions.includes(questionObject.id) ? "Unflag" : "Flag"}</span>
        </button>
        
        <QuestionDropdown
          totalQuestions={effectiveTotal}
          currentQuestionIndex={currentQuestionIndex}
          onQuestionSelect={(index) => {
            setCurrentQuestionIndex(index);
            updateServerProgress(answers, score, false);
          }}
          answers={answers}
          flaggedQuestions={flaggedQuestions}
          testData={testData}
          shuffleOrder={shuffleOrder}
          examMode={examMode}
        />
        
        <button
          className="finish-test-btn"
          onClick={() => setShowFinishPopup(true)}
        >
          <FaFlagCheckered className="button-icon" />
          <span>Finish Test</span>
        </button>
      </div>

      <div className="upper-control-bar">
        <button
          className="restart-test-btn"
          onClick={() => setShowRestartPopup(true)}
        >
          <FaRedoAlt className="button-icon" />
          <span>Restart</span>
        </button>
        
        <h1 className="aplus-title">{testData.testName}</h1>
        
        <button 
          className="back-btn" 
          onClick={() => navigate(backToListPath)}
        >
          <FaArrowLeft className="button-icon" />
          <span>Back to List</span>
        </button>
      </div>

      <div className="top-bar">
        <div className="avatar-section-test">
          <div
            className="avatar-image"
            style={{ backgroundImage: `url(${avatarUrl})` }}
          />
          <div className="avatar-level">
            <FaLevelUpAlt className="level-icon" />
            <span>{level}</span>
          </div>
        </div>
        <div className="xp-level-display">
          <FaStar className="xp-icon" />
          <span>{xp} XP</span>
        </div>
        <div className="coins-display">
          <FaCoins className="coins-icon" />
          <span>{coins}</span>
        </div>
      </div>

      <div className="exam-mode-indicator">
        {examMode ? (
          <div className="exam-badge">
            <FaTrophy className="exam-icon" />
            <span>EXAM MODE</span>
          </div>
        ) : null}
      </div>

      <div className="progress-container">
        <div
          className="progress-fill"
          style={{ width: `${progressPercentage}%`, background: progressColor }}
        >
          {currentQuestionIndex + 1} / {effectiveTotal} ({progressPercentage}%)
        </div>
      </div>

      {!showScoreOverlay && !showReviewMode && !isFinished && (
        <div className="question-card">
          <div className="question-text">
            {questionObject && questionObject.question}
          </div>

          <ul className="options-list">
            {displayedOptions.map((option, displayIdx) => {
              let optionClass = "option-button";

              if (!examMode) {
                if (isAnswered && questionObject) {
                  const correctIndex = questionObject.correctAnswerIndex;
                  const actualIndex = answerOrder[realIndex][displayIdx];

                  if (actualIndex === correctIndex) {
                    optionClass += " correct-option";
                  } else if (
                    displayIdx === selectedOptionIndex &&
                    actualIndex !== correctIndex
                  ) {
                    optionClass += " incorrect-option";
                  }
                }
              } else {
                if (isAnswered && displayIdx === selectedOptionIndex) {
                  optionClass += " chosen-option";
                }
              }

              return (
                <li className="option-item" key={displayIdx}>
                  <button
                    className={optionClass}
                    onClick={() => handleOptionClick(displayIdx)}
                    disabled={examMode ? false : isAnswered}
                  >
                    <div className="option-letter">{String.fromCharCode(65 + displayIdx)}</div>
                    <div className="option-text">{option}</div>
                  </button>
                </li>
              );
            })}
          </ul>

          {isAnswered && questionObject && !examMode && (
            <div className={`explanation ${selectedOptionIndex !== null &&
              answerOrder[realIndex][selectedOptionIndex] ===
                questionObject.correctAnswerIndex
                ? "correct-explanation"
                : "incorrect-explanation"}`}>
              <strong>
                {selectedOptionIndex !== null &&
                answerOrder[realIndex][selectedOptionIndex] ===
                  questionObject.correctAnswerIndex
                  ? (
                    <>
                      <FaCheck className="explanation-icon" />
                      <span>Correct!</span>
                    </>
                  ) : (
                    <>
                      <FaTimes className="explanation-icon" />
                      <span>Incorrect!</span>
                    </>
                  )}
              </strong>
              <p>{questionObject.explanation}</p>
            </div>
          )}

          <div className="bottom-control-bar">
            <div className="bottom-control-row">
              <button
                className="prev-question-btn"
                onClick={handlePreviousQuestion}
                disabled={currentQuestionIndex === 0}
              >
                <FaChevronLeft className="button-icon" />
                <span>Previous</span>
              </button>
              
              {currentQuestionIndex === effectiveTotal - 1 ? (
                <button
                  className="next-question-btn finish-btn"
                  onClick={handleNextQuestionButtonClick}
                >
                  <FaFlagCheckered className="button-icon" />
                  <span>Finish Test</span>
                </button>
              ) : (
                <button
                  className="next-question-btn"
                  onClick={handleNextQuestionButtonClick}
                >
                  <span>Next</span>
                  <FaChevronRight className="button-icon" />
                </button>
              )}
            </div>

            <div className="bottom-control-row skip-row">
              <button 
                className="skip-question-btn" 
                onClick={handleSkipQuestion}
              >
                <FaStepForward className="button-icon" />
                <span>Skip Question</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default GlobalTestPage;




ok so that is definly enough context fro you to determine teh fix for teh questions ansered achiveents and fix it (onlu fix those achivements and make it efficnetly count for each user but then- also beriefly look for any otehr achivemnt that might calculate worng and do not fix it btu isntead just let mem now and explain why- also id rather just have to tweak the backend if possible- if its impossible to fix eith just tweaking the backend asnd we need to edit frontend just a little thats fine but just fwi

ok go
