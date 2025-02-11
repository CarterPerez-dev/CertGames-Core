# models.py

from bson.objectid import ObjectId
from datetime import datetime, timedelta
from collections import defaultdict
import math

# Import the new collections from database
from models.database import (
    mainusers_collection,
    shop_collection,
    achievements_collection,
    tests_collection,
    testAttempts_collection,
    correctAnswers_collection
)

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
    purchasedItems, xpBoost, etc. Also automatically equips the default avatar if found.
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

    # Remove big embedded docs:
    # user_data.setdefault("testsProgress", {})
    # user_data.setdefault("perTestCorrect", {})  # replaced by separate collections

    # Shop + XP fields
    user_data.setdefault("xpBoost", 1.0)        # XP multiplier
    user_data.setdefault("currentAvatar", None) # e.g., an ObjectId from shop
    user_data.setdefault("nameColor", None)     # e.g., "blue" or "#ff0000"

    # ------------------------------
    # Automatically equip a default avatar:
    # (Here we look for an avatar with cost=0. 
    #  If instead you identify it by a specific title, 
    #  you could do: {"title": "Default Avatar"} )
    # ------------------------------
    default_avatar = shop_collection.find_one({"type": "avatar", "cost": 0})
    if default_avatar:
        user_data["currentAvatar"] = default_avatar["_id"]
        if default_avatar["_id"] not in user_data["purchasedItems"]:
            user_data["purchasedItems"].append(default_avatar["_id"])
    # ------------------------------

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
# Daily Bonus
##############################################

def apply_daily_bonus(user_id):
    """
    If the user hasn't claimed daily bonus in the last 24 hours,
    +50 coins, update lastDailyClaim
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
    Returns all shop items from shop_collection.
    Each shop item includes:
      - _id, type ("xpBoost", "avatar", "nameColor"), title, cost, ...
    """
    return list(shop_collection.find({}))

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
    # Add to purchased
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$addToSet": {"purchasedItems": oid}}
    )

    # Handle item type
    item_type = item.get("type")
    if item_type == "xpBoost":
        new_boost = item.get("effectValue", 1.0)
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"xpBoost": new_boost}}
        )
    elif item_type == "avatar":
        # Optionally auto-equip
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
    """
    Fetch a single test doc by integer testId field.
    """
    try:
        test_id_int = int(test_id)
    except Exception:
        return None
    return tests_collection.find_one({"testId": test_id_int})

def check_and_unlock_achievements(user_id):
    """
    Checks the user's progress by querying testAttempts_collection
    (instead of user.testsProgress) to see how many tests are finished,
    how many are perfect, etc. Then unlock achievements as needed.
    """
    user = get_user_by_id(user_id)
    if not user:
        return []

    user_oid = user["_id"]
    # Query total finished attempts
    total_finished = testAttempts_collection.count_documents({
        "userId": user_oid,
        "finished": True
    })

    # Count how many are perfect
    perfect_tests = testAttempts_collection.count_documents({
        "userId": user_oid,
        "finished": True,
        "$expr": {"$eq": ["$score", "$totalQuestions"]}
    })

    # For advanced logic (categories, consecutive perfect, etc.)
    finished_cursor = testAttempts_collection.find({"userId": user_oid, "finished": True})
    finished_tests = []
    for doc in finished_cursor:
        tq = doc.get("totalQuestions", 0)
        sc = doc.get("score", 0)
        pct = (sc / tq) * 100 if tq else 0
        cat = doc.get("category", "aplus")
        finished_tests.append({
            "test_id": doc.get("testId", "0"),
            "percentage": pct,
            "category": cat
        })

    # Example: consecutive perfect logic
    perfect_list = [ft for ft in finished_tests if ft["percentage"] == 100]
    try:
        perfect_list.sort(key=lambda x: int(x["test_id"]))
    except:
        perfect_list.sort(key=lambda x: x["test_id"])

    max_consecutive = 0
    current_streak = 0
    previous_test_id = None
    for ft in perfect_list:
        try:
            cid = int(ft["test_id"])
        except:
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

    # Group by category
    category_groups = defaultdict(list)
    for ft in finished_tests:
        cat = ft["category"]
        category_groups[cat].append(ft)

    # If you assume 80 total tests exist for "allTestsCompleted" criteria
    TOTAL_TESTS = 130

    unlocked = user.get("achievements", [])
    newly_unlocked = []
    all_ach = get_achievements()

    for ach in all_ach:
        aid = ach["achievementId"]
        criteria = ach.get("criteria", {})

        # Skip if already unlocked
        if aid in unlocked:
            continue

        # 1) testCount
        if "testCount" in criteria:
            if total_finished >= criteria["testCount"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 2) coins
        if "coins" in criteria:
            if user.get("coins", 0) >= criteria["coins"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 3) level
        if "level" in criteria:
            if user.get("level", 1) >= criteria["level"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 4) perfectTests
        if "perfectTests" in criteria:
            if perfect_tests >= criteria["perfectTests"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 5) consecutivePerfects
        if "consecutivePerfects" in criteria:
            if max_consecutive >= criteria["consecutivePerfects"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 6) allTestsCompleted
        if "allTestsCompleted" in criteria and criteria["allTestsCompleted"] is True:
            if total_finished >= TOTAL_TESTS:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 7) testsCompletedInCategory
        if "testsCompletedInCategory" in criteria:
            for ccat, attempts in category_groups.items():
                if len(attempts) >= criteria["testsCompletedInCategory"]:
                    unlocked.append(aid)
                    newly_unlocked.append(aid)
                    break

        # 8) redemption arc style (optional):
        if ("minScoreBefore" in criteria and 
            "minScoreAfter" in criteria and 
            aid not in unlocked):
            if (any(ft["percentage"] <= criteria["minScoreBefore"] for ft in finished_tests) and
                any(ft["percentage"] >= criteria["minScoreAfter"] for ft in finished_tests)):
                unlocked.append(aid)
                newly_unlocked.append(aid)

    if newly_unlocked:
        mainusers_collection.update_one(
            {"_id": user_oid},
            {"$set": {"achievements": unlocked}}
        )

    return newly_unlocked
