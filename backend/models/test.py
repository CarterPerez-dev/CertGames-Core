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
    Creates a new user document, setting default fields including
    coins, xp, level, purchasedItems, xpBoost, etc.
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

    # NEW FIELDS FOR SHOP + XP INTEGRATION
    user_data.setdefault("xpBoost", 1.0)         # user’s current XP multiplier
    user_data.setdefault("currentAvatar", None)  # store an ObjectId from shopItems
    user_data.setdefault("nameColor", None)      # e.g., "blue" or "#ff0000"

    result = mainusers_collection.insert_one(user_data)
    return result.inserted_id


def get_user_by_id(user_id):
    """
    Retrieves a user by ID, returns None if invalid or not found.
    """
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    return mainusers_collection.find_one({"_id": oid})


def update_user_coins(user_id, amount):
    """
    Increments (or decrements) the user's coins by 'amount'.
    """
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    mainusers_collection.update_one({"_id": oid}, {"$inc": {"coins": amount}})


##############################################
# Piecewise XP Logic
#  - builds a "delta array" for L=1..99 => total 75K at L=100
#  - For L>100 => mild ratio=1.02 infinite
##############################################

def build_custom_delta_array():
    """
    Returns a list 'delta' where delta[L] is XP needed from level L -> L+1
    for L in [1..99]. We'll define 4 segments A-D, then scale so L=100 sums to 75k.
    """
    delta = [0]*200  # index 0..199 so that L=1..99 is valid

    # Segment A: L=1..9 => linear from 200 -> 500
    startA = 200.0
    endA = 500.0
    stepsA = 9
    for i in range(1, 10):  # i=1..9
        frac = (i-1)/(stepsA-1) if stepsA > 1 else 0
        delta[i] = startA + frac*(endA - startA)

    # Segment B: L=10..49 => ratio=1.06, start=600
    delta[10] = 600.0
    ratioB = 1.06
    for L in range(11, 50):
        delta[L] = delta[L-1] * ratioB

    # Segment C: L=50..90 => ratio=1.08, start=1200
    delta[50] = 1200.0
    ratioC = 1.08
    for L in range(51, 91):
        delta[L] = delta[L-1] * ratioC

    # Segment D: L=91..99 => ratio=1.05, start=8000
    delta[91] = 8000.0
    ratioD = 1.05
    for L in range(92, 100):
        delta[L] = delta[L-1] * ratioD

    # Sum them to see total at L=100
    sumX = 0.0
    for L in range(1, 100):
        sumX += delta[L]

    # Scale so total => 75k
    factor = 75_000 / sumX
    for L in range(1, 100):
        delta[L] *= factor

    return delta


# Create array once
delta_array = build_custom_delta_array()
ratioE = 1.02  # For L>100, 2% growth each level


def xp_for_level_under_100(level):
    """Sum up delta[1..(level-1)] for L<=100."""
    total = 0.0
    for L in range(1, level):
        total += delta_array[L]
    return total


def xp_for_level_over_100(level):
    """
    For L>100, total XP = 75k + sum of infinite segment from 100->101..(level-1)->level.
    baseE = cost from L=99->100 in delta_array, ratio=1.02
    """
    xp_at_100 = 75000.0
    baseE = delta_array[99]  # cost from 99->100

    steps = level - 100
    if steps <= 0:
        return xp_at_100

    # geometric sum baseE * (ratio^steps -1)/(ratio-1)
    sum_inf = baseE * ((ratioE**steps) - 1)/(ratioE - 1)
    return xp_at_100 + sum_inf


def xp_required_for_level(level):
    """
    Returns total XP needed to *be* at 'level'.
    L=1 => 0 XP
    2..100 => sum of delta array
    >100 => 75k + infinite
    """
    if level < 1:
        return 0
    if level == 1:
        return 0
    if level <= 100:
        return int(round(xp_for_level_under_100(level)))
    # else
    return int(round(xp_for_level_over_100(level)))


def update_user_xp(user_id, xp_to_add):
    """
    Adds xp_to_add to user.xp, then while new_xp >= xp_required_for_level(currentLvl+1),
    increment level. No max. 
    """
    user = get_user_by_id(user_id)
    if not user:
        return None

    old_xp = user.get("xp", 0)
    old_level = user.get("level", 1)

    new_xp = old_xp + xp_to_add
    new_level = old_level

    # keep leveling while we meet the requirement for next level
    while True:
        required_next = xp_required_for_level(new_level + 1)
        if new_xp >= required_next:
            new_level += 1
        else:
            break

    # update doc
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
    If >24h since lastDailyClaim or never claimed, add 50 coins.
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
    e.g. item doc: {
      "_id": ObjectId(...),
      "type": "xpBoost"|"avatar"|"nameColor",
      "title": "...",
      "cost": <int>,
      ...
    }
    """
    return list(shop_collection.find({}))


def purchase_item(user_id, item_id):
    """
    Attempts to purchase an item from the shop:
      - checks user coins
      - ensures not already purchased
      - deduct cost, add to purchasedItems
      - if type= xpBoost => set xpBoost
      - if type= avatar => optionally equip?
      - if type= nameColor => set user.nameColor
    Returns { "success": bool, "message": str }
    """
    user = get_user_by_id(user_id)
    if not user:
        return {"success": False, "message": "User not found"}

    # parse item_id
    try:
        oid = ObjectId(item_id)
    except Exception:
        return {"success": False, "message": "Invalid item ID"}

    # find item doc
    item = shop_collection.find_one({"_id": oid})
    if not item:
        return {"success": False, "message": "Item not found"}

    user_coins = user.get("coins", 0)
    cost = item.get("cost", 0)
    if user_coins < cost:
        return {"success": False, "message": "Not enough coins"}

    # check if already purchased
    purchased = user.get("purchasedItems", [])
    if oid in purchased:
        return {"success": False, "message": "Item already purchased"}

    # deduct cost
    mainusers_collection.update_one({"_id": user["_id"]}, {"$inc": {"coins": -cost}})
    # add to purchasedItems
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$addToSet": {"purchasedItems": oid}}
    )

    # handle item types
    item_type = item.get("type")
    if item_type == "xpBoost":
        new_boost = item.get("effectValue", 1.0)
        # override user's xpBoost with new_boost
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"xpBoost": new_boost}}
        )
    elif item_type == "avatar":
        # optionally equip automatically
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
    Expects each finished test attempt to have:
      finished: bool
      totalQuestions: int
      score: int
      category: str
      finishedAt: str (ISO)
    """
    user = get_user_by_id(user_id)
    if not user:
        return []

    tests_progress = user.get("testsProgress", {})
    finished_tests = []

    # flatten progress
    for tid, progress_entry in tests_progress.items():
        attempts = progress_entry if isinstance(progress_entry, list) else [progress_entry]
        for attempt in attempts:
            if attempt.get("finished"):
                tq = attempt.get("totalQuestions", 100)
                sc = attempt.get("score", 0)
                pct = (sc / tq)*100 if tq else 0
                finished_tests.append({
                    "test_id": tid,
                    "percentage": pct,
                    "category": attempt.get("category", "aplus"),
                    "finishedAt": attempt.get("finishedAt")
                })

    total_finished = len(finished_tests)
    perfect_tests = sum(1 for ft in finished_tests if ft["percentage"] == 100)

    # consecutive perfect tests
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

    # assume 80 total tests exist
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
            for ccat, ccount in {c: len(ts) for c, ts in category_groups.items()}.items():
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
