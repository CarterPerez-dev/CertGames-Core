# models.py

from bson.objectid import ObjectId
from datetime import datetime, timedelta
from collections import defaultdict
from models.database import mainusers_collection, shop_collection, achievements_collection, tests_collection

def get_user_by_username(username):
    return mainusers_collection.find_one({"username": username})

def get_user_by_identifier(identifier):
    if "@" in identifier:
        return mainusers_collection.find_one({"email": identifier})
    else:
        return get_user_by_username(identifier)

def create_user(user_data):
    existing_user = mainusers_collection.find_one({
        "$or": [
            {"username": user_data["username"]},
            {"email": user_data["email"]}
        ]
    })
    if existing_user:
        raise ValueError("Username or email is already taken")

    # Set defaults for new user:
    user_data.setdefault("coins", 0)
    user_data.setdefault("xp", 0)
    user_data.setdefault("level", 1)
    user_data.setdefault("achievements", [])
    user_data.setdefault("subscriptionActive", False)
    user_data.setdefault("subscriptionPlan", None)
    user_data.setdefault("lastDailyClaim", None)
    user_data.setdefault("purchasedItems", [])
    user_data.setdefault("testsProgress", {})
    # NEW: For the new /submit-answer logic
    user_data.setdefault("perTestCorrect", {})  # dict { testId: [questionIds] }

    result = mainusers_collection.insert_one(user_data)
    return result.inserted_id

def get_user_by_id(user_id):
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    return mainusers_collection.find_one({"_id": oid})

def update_user_coins(user_id, amount):
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    mainusers_collection.update_one({"_id": oid}, {"$inc": {"coins": amount}})

def update_user_xp(user_id, xp_to_add):
    user = get_user_by_id(user_id)
    if not user:
        return None

    new_xp = user.get("xp", 0) + xp_to_add
    new_level = user.get("level", 1)
    # Simple leveling logic:
    while new_xp >= 100 * new_level:
        new_level += 1

    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"xp": new_xp, "level": new_level}}
    )
    return {"xp": new_xp, "level": new_level}

def apply_daily_bonus(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return None

    now = datetime.utcnow()
    last_claimed = user.get("lastDailyClaim")
    if not last_claimed or (now - last_claimed) > timedelta(hours=24):
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$inc": {"coins": 50}, "$set": {"lastDailyClaim": now}}
        )
        return {"success": True, "message": "Daily bonus applied"}
    else:
        return {"success": False, "message": "Already claimed daily bonus"}

def get_shop_items():
    return list(shop_collection.find({}))

def purchase_item(user_id, item_id):
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
    cost = item.get("cost", 0)
    if user_coins < cost:
        return {"success": False, "message": "Not enough coins"}

    mainusers_collection.update_one({"_id": user["_id"]}, {"$inc": {"coins": -cost}})
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$addToSet": {"purchasedItems": item["_id"]}}
    )
    return {"success": True, "message": "Purchase successful"}

def get_achievements():
    return list(achievements_collection.find({}))

def get_test_by_id(test_id):
    try:
        test_id_int = int(test_id)
    except Exception:
        return None
    return tests_collection.find_one({"testId": test_id_int})

def check_and_unlock_achievements(user_id):
    """
    Checks the user's progress and unlocks achievements accordingly.
    Expects that each test progress saved for a user includes:
      - finished: bool
      - totalQuestions: int
      - score: int
      - category: string
      - finishedAt: string (ISO timestamp)
    """
    user = get_user_by_id(user_id)
    if not user:
        return []
    
    tests_progress = user.get("testsProgress", {})
    finished_tests = []

    # Flatten the progress: if multiple attempts, consider only finished ones
    for tid, progress_entry in tests_progress.items():
        attempts = progress_entry if isinstance(progress_entry, list) else [progress_entry]
        for attempt in attempts:
            if attempt.get("finished"):
                tq = attempt.get("totalQuestions", 100)
                score = attempt.get("score", 0)
                percentage = (score / tq) * 100 if tq else 0
                finished_tests.append({
                    "test_id": tid,
                    "percentage": percentage,
                    "category": attempt.get("category", "aplus"),
                    "finishedAt": attempt.get("finishedAt")
                })
    
    total_finished = len(finished_tests)
    # Perfect tests
    perfect_tests = sum(1 for ft in finished_tests if ft["percentage"] == 100)
    
    # Consecutive perfect tests (Memory Master)
    perfect_tests_list = [ft for ft in finished_tests if ft["percentage"] == 100]
    try:
        perfect_tests_list.sort(key=lambda x: int(x["test_id"]))
    except Exception:
        perfect_tests_list.sort(key=lambda x: x["test_id"])
    max_consecutive = 0
    current_streak = 0
    previous_test_id = None
    for ft in perfect_tests_list:
        try:
            current_id = int(ft["test_id"])
        except Exception:
            current_id = None
        if previous_test_id is None or current_id is None:
            current_streak = 1
        else:
            if current_id == previous_test_id + 1:
                current_streak += 1
            else:
                current_streak = 1
        max_consecutive = max(max_consecutive, current_streak)
        previous_test_id = current_id

    # Category grouping
    from collections import defaultdict
    category_groups = defaultdict(list)
    for ft in finished_tests:
        cat = ft.get("category", "aplus")
        category_groups[cat].append(ft)
    
    # Assume total # of tests = 80 for some achievements
    TOTAL_TESTS = 80

    unlocked = user.get("achievements", [])
    newly_unlocked = []
    all_achievements = get_achievements()
    
    for ach in all_achievements:
        aid = ach["achievementId"]
        criteria = ach.get("criteria", {})

        # 1. Test Count
        if "testCount" in criteria:
            if total_finished >= criteria["testCount"] and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 2. Coins
        if "coins" in criteria:
            if user.get("coins", 0) >= criteria["coins"] and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 3. Level
        if "level" in criteria:
            if user.get("level", 1) >= criteria["level"] and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 4. Accuracy King
        if "minScore" in criteria:
            if any(ft["percentage"] >= criteria["minScore"] for ft in finished_tests) and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 5. Exam Conqueror
        if "minScoreGlobal" in criteria:
            if finished_tests and all(ft["percentage"] >= criteria["minScoreGlobal"] for ft in finished_tests) and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 6. Subject Specialist
        if "minScoreInCategory" in criteria:
            for cat, tests in category_groups.items():
                if tests and all(t["percentage"] >= criteria["minScoreInCategory"] for t in tests):
                    if aid not in unlocked:
                        unlocked.append(aid)
                        newly_unlocked.append(aid)
                    break
        # 7. Perfect Tests (count)
        if "perfectTests" in criteria:
            if perfect_tests >= criteria["perfectTests"] and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 8. Memory Master (consecutive perfects)
        if "consecutivePerfects" in criteria:
            if max_consecutive >= criteria["consecutivePerfects"] and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 9. Test Finisher
        if "allTestsCompleted" in criteria and criteria["allTestsCompleted"] is True:
            if total_finished >= TOTAL_TESTS and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 10. Subject Finisher
        if "testsCompletedInCategory" in criteria:
            for cat, ccount in {cat: len(tests) for cat, tests in category_groups.items()}.items():
                if ccount >= criteria["testsCompletedInCategory"] and aid not in unlocked:
                    unlocked.append(aid)
                    newly_unlocked.append(aid)
                    break
        # 11. Redemption Arc
        if "minScoreBefore" in criteria and "minScoreAfter" in criteria:
            if (any(ft["percentage"] <= criteria["minScoreBefore"] for ft in finished_tests)
                and any(ft["percentage"] >= criteria["minScoreAfter"] for ft in finished_tests)
                and aid not in unlocked):
                unlocked.append(aid)
                newly_unlocked.append(aid)

    if newly_unlocked:
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"achievements": unlocked}}
        )
    return newly_unlocked
