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
    # For /submit-answer logic
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


##############################################
# [Piecewise XP Logic] 
#  Build a "delta" array for levels 1..99 
#  so total XP at L=100 = 75,000. Then 
#  define a mild infinite ratio for L>100.
##############################################

def build_custom_delta_array():
    """
    Returns a list 'delta' of length at least 100,
    where delta[L] is how much XP is needed to go from level L -> L+1
    for L in [1..99].

    We'll define 4 segments (A–D) for L=1..9, 10..49, 50..90, 91..99,
    fill them with approximate values/ratios, then do a final scaling
    so that the total sum at L=100 = 75,000 exactly.
    """
    delta = [0]*200  # enough for indexing up to 99

    # Segment A: L=1..9
    # linear ramp 200 -> 500
    startA = 200.0
    endA = 500.0
    stepsA = 9  # (1->2 ... 9->10)
    for i in range(1, 10):
        frac = (i-1)/(stepsA-1) if stepsA>1 else 0
        delta[i] = startA + frac*(endA - startA)

    # Segment B: L=10..49 (40 increments)
    # ratio=1.06, start=600
    delta[10] = 600.0
    ratioB = 1.06
    for L in range(11, 50):
        delta[L] = delta[L-1] * ratioB

    # Segment C: L=50..90 (41 increments)
    # ratio=1.08, start=1200
    delta[50] = 1200.0
    ratioC = 1.08
    for L in range(51, 91):
        delta[L] = delta[L-1] * ratioC

    # Segment D: L=91..99 (9 increments)
    # ratio=1.05, start=8000
    delta[91] = 8000.0
    ratioD = 1.05
    for L in range(92, 100):
        delta[L] = delta[L-1] * ratioD

    # Sum from L=1->2.. L=99->100
    sumX = 0.0
    for L in range(1, 100):
        sumX += delta[L]

    # Scale to exactly 75,000
    factor = 75_000 / sumX
    for L in range(1, 100):
        delta[L] *= factor

    return delta


# Create the array once
delta_array = build_custom_delta_array()

# For L>100 => ratio=1.02
ratioE = 1.02


def xp_for_level_under_100(level):
    """Sum delta[1..(level-1)] for level <= 100."""
    total = 0.0
    for L in range(1, level):
        total += delta_array[L]
    return total


def xp_for_level_over_100(level):
    """
    For L>100, total XP = 75k + sum of infinite segment
    from L=100->101..(level-1)->level.
    baseE = cost from L=99->100 in the array, then ratioE^k
    """
    xp_at_100 = 75000.0
    baseE = delta_array[99]

    steps = level - 100
    if steps <= 0:
        return xp_at_100

    # geometric sum
    sum_infinite = baseE * ((ratioE**steps) - 1)/(ratioE - 1)
    return xp_at_100 + sum_infinite


def xp_required_for_level(level):
    """
    Returns total XP required to *be* at 'level'.
    level=1 => 0 XP
    2..100 => sum of delta array
    >100 => 75k + infinite segment
    """
    if level < 1:
        return 0
    if level == 1:
        return 0
    if level <= 100:
        return int(round(xp_for_level_under_100(level)))
    # else L>100
    return int(round(xp_for_level_over_100(level)))


def update_user_xp(user_id, xp_to_add):
    """
    Adds xp_to_add to the user's XP, then checks if they level up.
    We have infinite leveling with ratio=1.02 beyond L=100.
    """
    user = get_user_by_id(user_id)
    if not user:
        return None

    old_xp = user.get("xp", 0)
    old_level = user.get("level", 1)

    new_xp = old_xp + xp_to_add
    new_level = old_level

    # keep leveling while new_xp >= xp_required_for_level(new_level+1)
    while True:
        next_level_required = xp_required_for_level(new_level + 1)
        if new_xp >= next_level_required:
            new_level += 1
        else:
            break

    # no max level clamp (optional)
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "xp": new_xp,
            "level": new_level
        }}
    )
    return {"xp": new_xp, "level": new_level}


##############################################
# apply_daily_bonus, etc.
##############################################

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
    Expects each test attempt to have:
      - finished: bool
      - totalQuestions: int
      - score: int
      - category: str
      - finishedAt: ISO timestamp
    """
    user = get_user_by_id(user_id)
    if not user:
        return []

    tests_progress = user.get("testsProgress", {})
    finished_tests = []

    # Flatten progress: if multiple attempts, consider only finished
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
    perfect_tests = sum(1 for ft in finished_tests if ft["percentage"] == 100)

    # Consecutive perfect tests
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

    from collections import defaultdict
    category_groups = defaultdict(list)
    for ft in finished_tests:
        cat = ft.get("category", "aplus")
        category_groups[cat].append(ft)

    # Assume 80 total tests exist
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
            for cat, tests_ in category_groups.items():
                if tests_ and all(t["percentage"] >= criteria["minScoreInCategory"] for t in tests_):
                    if aid not in unlocked:
                        unlocked.append(aid)
                        newly_unlocked.append(aid)
                    break
        # 7. Perfect Tests
        if "perfectTests" in criteria:
            if perfect_tests >= criteria["perfectTests"] and aid not in unlocked:
                unlocked.append(aid)
                newly_unlocked.append(aid)
        # 8. Memory Master (consecutivePerfects)
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
            for cat, ccount in {cat: len(tests_) for cat, tests_ in category_groups.items()}.items():
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
