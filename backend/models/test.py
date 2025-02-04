# models.py
from bson.objectid import ObjectId
from datetime import datetime, timedelta

# Import collections from database.py
from models.database import (
    mainusers_collection,
    shop_collection,
    achievements_collection,
    tests_collection
)

def get_user_by_username(username):
    """
    Fetch a user document from the mainusers_collection by username.
    Returns None if not found.
    """
    return mainusers_collection.find_one({"username": username})

def get_user_by_identifier(identifier):
    """
    Fetch a user document using the given identifier.
    If the identifier contains an '@' symbol, assume it is an email;
    otherwise, treat it as a username.
    Returns None if not found.
    """
    if "@" in identifier:
        return mainusers_collection.find_one({"email": identifier})
    else:
        return get_user_by_username(identifier)

def create_user(user_data):
    """
    Create a new user document in mainusers_collection.
    """
    # Check if username/email already exists:
    existing_user = mainusers_collection.find_one({
        "$or": [
            {"username": user_data["username"]},
            {"email": user_data["email"]}
        ]
    })
    if existing_user:
        raise ValueError("Username or email is already taken")

    # Set defaults if not provided
    user_data.setdefault("coins", 0)
    user_data.setdefault("xp", 0)
    user_data.setdefault("level", 1)
    user_data.setdefault("achievements", [])
    user_data.setdefault("subscriptionActive", False)
    user_data.setdefault("subscriptionPlan", None)
    user_data.setdefault("lastDailyClaim", None)
    user_data.setdefault("purchasedItems", [])
    user_data.setdefault("testsProgress", {})

    result = mainusers_collection.insert_one(user_data)
    return result.inserted_id

def get_user_by_id(user_id):
    """
    Fetch a user document by its ObjectId (as string).
    """
    try:
        oid = ObjectId(user_id)
    except:
        return None
    return mainusers_collection.find_one({"_id": oid})

def update_user_coins(user_id, amount):
    """
    Increment a user's 'coins' field by 'amount'.
    """
    try:
        oid = ObjectId(user_id)
    except:
        return None
    mainusers_collection.update_one({"_id": oid}, {"$inc": {"coins": amount}})

def update_user_xp(user_id, xp_to_add):
    """
    Add xp_to_add to the user's xp, and update level if necessary.
    Returns a dict { "xp": new_xp, "level": new_level }.
    """
    user = get_user_by_id(user_id)
    if not user:
        return None

    new_xp = user.get("xp", 0) + xp_to_add
    new_level = user.get("level", 1)
    # Each level requires 100 * current_level XP
    while new_xp >= 100 * new_level:
        new_level += 1

    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"xp": new_xp, "level": new_level}}
    )

    return {"xp": new_xp, "level": new_level}

def apply_daily_bonus(user_id):
    """
    Grants a daily coin bonus if lastDailyClaim is older than 24 hours.
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

def get_shop_items():
    """
    Returns a list of all shop items.
    """
    return list(shop_collection.find({}))

def purchase_item(user_id, item_id):
    """
    Deduct cost from user, add item to purchasedItems.
    """
    user = get_user_by_id(user_id)
    if not user:
        return {"success": False, "message": "User not found"}

    try:
        oid = ObjectId(item_id)
    except:
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
    """
    Returns all achievements from the achievements_collection.
    """
    return list(achievements_collection.find({}))

def get_test_by_id(test_id):
    """
    Fetch a test document by its integer testId.
    """
    try:
        test_id_int = int(test_id)
    except:
        return None
    return tests_collection.find_one({"testId": test_id_int})

# New function to check and unlock achievements
def check_and_unlock_achievements(user_id):
    """
    Check the user's progress against achievement criteria and update unlocked achievements.
    Returns a list of newly unlocked achievement IDs.
    """
    user = get_user_by_id(user_id)
    if not user:
        return []
    
    # Retrieve user's stats from their document.
    xp = user.get("xp", 0)
    level = user.get("level", 1)
    coins = user.get("coins", 0)
    tests_progress = user.get("testsProgress", {})
    testCount = 0
    for category in tests_progress.values():
        testCount += len(category)

    # Get all global achievements.
    achievements = get_achievements()
    unlocked = user.get("achievements", [])
    newly_unlocked = []
    
    for ach in achievements:
        criteria = ach.get("criteria", {})
        # Check test count criteria.
        if "testCount" in criteria and testCount >= criteria["testCount"]:
            if ach["achievementId"] not in unlocked:
                unlocked.append(ach["achievementId"])
                newly_unlocked.append(ach["achievementId"])
        # Check level criteria.
        if "level" in criteria and level >= criteria["level"]:
            if ach["achievementId"] not in unlocked:
                unlocked.append(ach["achievementId"])
                newly_unlocked.append(ach["achievementId"])
        # Check coins criteria.
        if "coins" in criteria and coins >= criteria["coins"]:
            if ach["achievementId"] not in unlocked:
                unlocked.append(ach["achievementId"])
                newly_unlocked.append(ach["achievementId"])
        # (Additional criteria such as minScore, perfectTests, etc. can be added here.)
    
    if newly_unlocked:
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"achievements": unlocked}}
        )
    return newly_unlocked

