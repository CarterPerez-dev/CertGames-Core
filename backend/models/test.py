# models.py

from bson.objectid import ObjectId
from datetime import datetime, timedelta
from collections import defaultdict
from models.database import mainusers_collection, shop_collection, achievements_collection, tests_collection
import math


def get_user_by_username(username):
    return mainusers_collection.find_one({"username": username})


def get_user_by_identifier(identifier):
    if "@" in identifier:
        return mainusers_collection.find_one({"email": identifier})
    else:
        return get_user_by_username(identifier)


def create_user(user_data):
    """
    Creates a new user document, setting default fields including coins, xp, level,
    purchasedItems, xpBoost, etc.
    """
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
    user_data.setdefault("perTestCorrect", {})  # for /submit-answer logic

    # NEW FIELDS FOR SHOP + XP INTEGRATION:
    user_data.setdefault("xpBoost", 1.0)         # User’s current XP multiplier (default: 1.0)
    user_data.setdefault("currentAvatar", None)  # Stores an ObjectId from shopItems if an avatar is equipped
    user_data.setdefault("nameColor", None)      # For example: "blue" or "#ff0000"

    result = mainusers_collection.insert_one(user_data)
    return result.inserted_id


def get_user_by_id(user_id):
    """
    Retrieves a user by ID. Returns None if invalid or not found.
    """
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    return mainusers_collection.find_one({"_id": oid})


def update_user_coins(user_id, amount):
    """
    Increments (or decrements) the user's coins by the specified amount.
    """
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    mainusers_collection.update_one({"_id": oid}, {"$inc": {"coins": amount}})


##############################################
# Leveling System
##############################################
# New leveling progression:
#   - Level 1: 0 XP.
#   - Levels 2–30: Each level-up requires 500 XP.
#       XP required for level L (2 ≤ L ≤ 30) = 500 * (L - 1)
#   - Levels 31–60: Each level-up requires 750 XP.
#       XP required for level L (31 ≤ L ≤ 60) = (500 * 29) + 750 * (L - 30)
#   - Levels 61–100: Each level-up requires 1000 XP.
#       XP required for level L (61 ≤ L ≤ 100) = (500 * 29) + (750 * 30) + 1000 * (L - 60)
#   - Levels above 100: Each level-up requires 1500 XP.
#       XP required for level L (> 100) = (500*29) + (750*30) + (1000*40) + 1500 * (L - 100)

def xp_required_for_level(level):
    """
    Returns the total XP required to reach a given level.
    Level 1 starts at 0 XP.
    For levels 2-30, each level-up requires 500 XP.
    For levels 31-60, each level-up requires 750 XP.
    For levels 61-100, each level-up requires 1000 XP.
    For levels beyond 100, each level-up requires 1500 XP.
    """
    if level < 1:
        return 0
    if level == 1:
        return 0
    if level <= 30:
        # Levels 2 to 30: (L - 1) increments at 500 XP each.
        return 500 * (level - 1)
    elif level <= 60:
        # Total XP at level 30: 500 * 29 = 14500
        base = 500 * 29
        # Levels 31 to L: (L - 30) increments at 750 XP each.
        return base + 750 * (level - 30)
    elif level <= 100:
        # Total XP at level 60: 500*29 + 750*30
        base = 500 * 29 + 750 * 30  # 14500 + 22500 = 37000
        # Levels 61 to L: (L - 60) increments at 1000 XP each.
        return base + 1000 * (level - 60)
    else:
        # For levels > 100, total XP at level 100:
        base = 500 * 29 + 750 * 30 + 1000 * 40  # 37000 + 40000 = 77000
        # Each level-up beyond 100 requires 1500 XP.
        return base + 1500 * (level - 100)


def update_user_xp(user_id, xp_to_add):
    """
    Adds xp_to_add to the user's XP. Then, while the new XP total is greater than or
    equal to the requirement for the next level, increments the level.
    There is no maximum level; beyond level 100, each level-up costs 1500 XP.
    """
    user = get_user_by_id(user_id)
    if not user:
        return None

    old_xp = user.get("xp", 0)
    old_level = user.get("level", 1)

    new_xp = old_xp + xp_to_add
    new_level = old_level

    # Loop to update level until the new XP total is insufficient for the next level.
    while new_xp >= xp_required_for_level(new_level + 1):
        new_level += 1

    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"xp": new_xp, "level": new_level}}
    )
    return {"xp": new_xp, "level": new_level}


##############################################
# Daily Bonus
##############################################

def apply_daily_bonus(user_id):
    """
    If the user has not claimed the daily bonus within the last 24 hours,
    adds 50 coins and updates lastDailyClaim.
    """
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


##############################################
# Shop Logic
##############################################

def get_shop_items():
    """
    Returns all shop items from the shop_collection.
    Each shop item document might include:
      - _id, type ("xpBoost", "avatar", "nameColor"), title, cost,
        description, imageUrl, effectValue, unlockLevel (optional)
    """
    return list(shop_collection.find({}))


def purchase_item(user_id, item_id):
    """
    Attempts to purchase an item from the shop:
      - Checks if the user has enough coins.
      - Ensures the item has not already been purchased.
      - Deducts the cost and adds the item to purchasedItems.
      - For xpBoost items, sets the user's xpBoost.
      - For avatar items, optionally auto-equip (or leave for a separate equip action).
      - For nameColor items, sets the user's nameColor.
    Returns a dictionary: { "success": bool, "message": str }
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
    cost = item.get("cost", 0)
    if user_coins < cost:
        return {"success": False, "message": "Not enough coins"}

    purchased = user.get("purchasedItems", [])
    if oid in purchased:
        return {"success": False, "message": "Item already purchased"}

    # Deduct cost
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$inc": {"coins": -cost}}
    )
    # Add to purchasedItems
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$addToSet": {"purchasedItems": oid}}
    )

    # Handle item types
    item_type = item.get("type")
    if item_type == "xpBoost":
        new_boost = item.get("effectValue", 1.0)
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"xpBoost": new_boost}}
        )
    elif item_type == "avatar":
        # Optionally, you might auto-equip here:
        # mainusers_collection.update_one(
        #     {"_id": user["_id"]},
        #     {"$set": {"currentAvatar": oid}}
        # )
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


def get_test_by_id(test_id):
    try:
        test_id_int = int(test_id)
    except Exception:
        return None
    return tests_collection.find_one({"testId": test_id_int})


def check_and_unlock_achievements(user_id):
    """
    Checks the user's progress and unlocks achievements accordingly.
    Each finished test attempt should include:
      - finished: bool
      - totalQuestions: int
      - score: int
      - category: str
      - finishedAt: ISO timestamp string
    """
    user = get_user_by_id(user_id)
    if not user:
        return []

    tests_progress = user.get("testsProgress", {})
    finished_tests = []

    # Flatten the progress
    for tid, progress_entry in tests_progress.items():
        attempts = progress_entry if isinstance(progress_entry, list) else [progress_entry]
        for attempt in attempts:
            if attempt.get("finished"):
                tq = attempt.get("totalQuestions", 100)
                sc = attempt.get("score", 0)
                pct = (sc / tq) * 100 if tq else 0
                finished_tests.append({
                    "test_id": tid,
                    "percentage": pct,
                    "category": attempt.get("category", "aplus"),
                    "finishedAt": attempt.get("finishedAt")
                })

    total_finished = len(finished_tests)
    perfect_tests = sum(1 for ft in finished_tests if ft["percentage"] == 100)

    # Consecutive perfect tests
    perfect_list = [ft for ft in finished_tests if ft["percentage"] == 100]
    try:
        perfect_list.sort(key=lambda x: int(x["test_id"]))
    except Exception:
        perfect_list.sort(key=lambda x: x["test_id"])
    max_consecutive = 0
    current_streak = 0
    previous_test_id = None
    for ft in perfect_list:
        try:
            cid = int(ft["test_id"])
        except Exception:
            cid = None
        if previous_test_id is None or cid is None:
            current_streak = 1
        else:
            if cid == previous_test_id + 1:
                current_streak += 1
            else:
                current_streak = 1
        max_consecutive = max(max_consecutive, current_streak)
        previous_test_id = cid

    from collections import defaultdict
    category_groups = defaultdict(list)
    for ft in finished_tests:
        cat = ft.get("category", "aplus")
        category_groups[cat].append(ft)

    # Assume 80 total tests for certain achievement criteria
    TOTAL_TESTS = 80

    unlocked = user.get("achievements", [])
    newly_unlocked = []
    all_ach = get_achievements()

    for ach in all_ach:
        aid = ach["achievementId"]
        criteria = ach.get("criteria", {})

        # 1. testCount
        if "testCount" in criteria:
            if total_finished >= criteria["testCount"] and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 2. coins
        if "coins" in criteria:
            if user.get("coins", 0) >= criteria["coins"] and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 3. level
        if "level" in criteria:
            if user.get("level", 1) >= criteria["level"] and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 4. minScore
        if "minScore" in criteria:
            if any(ft["percentage"] >= criteria["minScore"] for ft in finished_tests) and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 5. minScoreGlobal
        if "minScoreGlobal" in criteria:
            if finished_tests and all(ft["percentage"] >= criteria["minScoreGlobal"] for ft in finished_tests) and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 6. minScoreInCategory
        if "minScoreInCategory" in criteria:
            for cat, tests_ in category_groups.items():
                if tests_ and all(t["percentage"] >= criteria["minScoreInCategory"] for t in tests_):
                    if aid not in unlocked:
                        unlocked.append(aid)
                        newly_unlocked.append(aid)
                    break
        # 7. perfectTests
        if "perfectTests" in criteria:
            if perfect_tests >= criteria["perfectTests"] and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 8. consecutivePerfects
        if "consecutivePerfects" in criteria:
            if max_consecutive >= criteria["consecutivePerfects"] and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 9. allTestsCompleted
        if "allTestsCompleted" in criteria and criteria["allTestsCompleted"] is True:
            if total_finished >= TOTAL_TESTS and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 10. testsCompletedInCategory
        if "testsCompletedInCategory" in criteria:
            for ccat, ccount in {ccat: len(ts) for ccat, ts in category_groups.items()}.items():
                if ccount >= criteria["testsCompletedInCategory"] and aid not in unlocked:
                    unlocked.append(aid)
                    newly_unlocked.append(aid)
                    break
        # 11. redemption arc
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
