# models.py

from bson.objectid import ObjectId
from datetime import datetime, timedelta
from collections import defaultdict
import math
import re
import unicodedata

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
    if not (12 <= length <= 128):
        errors.append("Password must be between 12 and 128 characters long.")

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
      2. 6..254 length.
      3. No control chars, <, >, etc.
      4. Exactly one @.
      5. Stricter regex disallowing consecutive dots, requiring valid domain, TLD 2..20
      6. Possibly disallow punycode (xn--).
    Returns: (True, []) if valid, else (False, [list of error messages]).
    """
    errors = []
    email_nfc = unicodedata.normalize("NFC", email.strip())

    # 1) Length check
    if not (6 <= len(email_nfc) <= 254):
        errors.append("Email length must be between 6 and 254 characters.")

    # 2) Check forbidden Unicode blocks
    if has_forbidden_unicode_scripts(email_nfc):
        errors.append("Email contains forbidden Unicode blocks (private use or surrogates).")

    # 3) Forbid suspicious ASCII
    forbidden_ascii = set(['<','>','`',';',' ', '\t','\r','\n','"',"'", '\\'])
    for ch in email_nfc:
        if ch in forbidden_ascii:
            errors.append("Email contains forbidden characters like <, >, or whitespace.")
            break

    # 4) Must have exactly one @
    if email_nfc.count('@') != 1:
        errors.append("Email must contain exactly one '@' symbol.")

    # 5) Regex for local part, domain subparts, no consecutive dots, TLD 2..20
    pattern = (
        r'^(?!.*\.\.)'
        r'([A-Za-z0-9._%+\-]{1,64})'
        r'@'
        r'([A-Za-z0-9\-]{1,63}(\.[A-Za-z0-9\-]{1,63})+)'
        r'\.[A-Za-z]{2,20}$'
    )
    if not re.match(pattern, email_nfc):
        errors.append("Email format is invalid (check local part, domain, consecutive dots, or TLD length).")

    # 6) Disallow IDN punycode if desired
    if '@' in email_nfc:
        domain_part = email_nfc.split('@')[-1]
        if domain_part.lower().startswith("xn--"):
            errors.append("Email domain uses punycode (xn--), which is not allowed in this system.")

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
    """
    Creates a new user document, setting default fields including coins, xp, level,
    purchasedItems, xpBoost, etc. Also automatically equips a default avatar if found.
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
    user_data.setdefault("xpBoost", 1.0)
    user_data.setdefault("currentAvatar", None)
    user_data.setdefault("nameColor", None)

    # Auto-equip default avatar if cost=null
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
    Returns all shop items from shop_collection,
    in ascending order by title (or another field),
    to ensure stable ordering.
    """
    # If you want them returned in a particular order,
    # you can do .sort("title", 1) or another field:
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

def get_test_by_id_and_category(test_id, category):
    try:
        test_id_int = int(test_id)
    except:
        return None
    return tests_collection.find_one({
        "testId": test_id_int,
        "category": category
    })

def check_and_unlock_achievements(user_id):
    """
    Checks the user's progress by querying testAttempts_collection to see:
      - How many tests are finished (total_finished)
      - How many are perfect (perfect_tests)
      - Their percentage on each finished test
      - If they've done certain minScores, consecutive perfects, etc.
      - Summation of total questions answered across all finished attempts

    Then unlocks achievements as needed, returning newly_unlocked achievementIds.
    """

    user = get_user_by_id(user_id)
    if not user:
        return []

    user_oid = user["_id"]

    # 1) Count how many finished attempts the user has
    total_finished = testAttempts_collection.count_documents({
        "userId": user_oid,
        "finished": True
    })

    # 2) Count how many are perfect (score == totalQuestions)
    perfect_tests = testAttempts_collection.count_documents({
        "userId": user_oid,
        "finished": True,
        "$expr": {"$eq": ["$score", "$totalQuestions"]}
    })

    # 3) Fetch all finished attempts in full, so we can compute percentages, categories, etc.
    finished_cursor = testAttempts_collection.find(
        {"userId": user_oid, "finished": True}
    )
    finished_tests = []
    for doc in finished_cursor:
        tq = doc.get("totalQuestions", 0)
        sc = doc.get("score", 0)
        pct = (sc / tq) * 100 if tq else 0
        cat = doc.get("category", "global")
        finished_at = doc.get("finishedAt", None)  # for chronological consecutive perfects
        finished_tests.append({
            "test_id": doc.get("testId", "0"),
            "score": sc,
            "totalQuestions": tq,
            "percentage": pct,
            "category": cat,
            "finishedAt": finished_at
        })

    # 4) For "consecutivePerfects", do it chronologically by finishedAt
    #    So we sort by finishedAt ascending. If finishedAt is missing, fallback to some default.
    from datetime import datetime
    finished_tests.sort(
        key=lambda x: x["finishedAt"] if x["finishedAt"] else datetime(1970,1,1)
    )

    max_consecutive = 0
    current_streak = 0
    for ft in finished_tests:
        if ft["percentage"] == 100:
            current_streak += 1
            if current_streak > max_consecutive:
                max_consecutive = current_streak
        else:
            current_streak = 0

    # 5) Group tests by category
    from collections import defaultdict
    category_groups = defaultdict(list)
    for ft in finished_tests:
        category_groups[ft["category"]].append(ft)

    # 6) Sum of total questions answered across all finished attempts
    #    (This is for achievements like "answer_machine_1000")
    sum_of_questions = sum(ft["totalQuestions"] for ft in finished_tests)

    # 7) Possibly define total test & question thresholds
    #    If your entire platform has 130 tests total:
    TOTAL_TESTS = 130
    # If you claim to have 10,000 total questions, you can define:
    TOTAL_QUESTIONS = 10000  # or whatever you prefer

    # 8) Gather user data we might check (coins, level, etc.)
    user_coins = user.get("coins", 0)
    user_level = user.get("level", 1)

    # 9) achievements user already has
    unlocked = user.get("achievements", [])
    newly_unlocked = []

    # 10) fetch definitions from DB
    all_ach = get_achievements()

    for ach in all_ach:
        aid = ach["achievementId"]
        criteria = ach.get("criteria", {})

        if aid in unlocked:
            continue  # already got it

        # 1) testCount => e.g. if total_finished >= criteria["testCount"]
        if "testCount" in criteria:
            if total_finished >= criteria["testCount"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 2) coins => e.g. if user_coins >= X
        if "coins" in criteria:
            if user_coins >= criteria["coins"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 3) level => e.g. if user_level >= X
        if "level" in criteria:
            if user_level >= criteria["level"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 4) perfectTests => e.g. if user has >= N perfect tests total
        if "perfectTests" in criteria:
            needed = criteria["perfectTests"]
            if perfect_tests >= needed:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 5) consecutivePerfects => e.g. memory_master
        if "consecutivePerfects" in criteria:
            needed = criteria["consecutivePerfects"]
            if max_consecutive >= needed:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 6) allTestsCompleted => e.g. test_finisher
        #    If your platform has 130 tests, check if user finished >= 130 distinct tests
        if "allTestsCompleted" in criteria and criteria["allTestsCompleted"] is True:
            if total_finished >= TOTAL_TESTS:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 7) testsCompletedInCategory => e.g. "subject_finisher" needs 10 tests in one category
        if "testsCompletedInCategory" in criteria:
            needed = criteria["testsCompletedInCategory"]
            # Check if there's any category ccat that has >= needed tests
            for ccat, attempts in category_groups.items():
                if len(attempts) >= needed:
                    unlocked.append(aid)
                    newly_unlocked.append(aid)
                    break

        # 8) redemption_arc => minScoreBefore & minScoreAfter
        if ("minScoreBefore" in criteria and "minScoreAfter" in criteria
                and aid not in unlocked):
            min_before = criteria["minScoreBefore"]
            min_after = criteria["minScoreAfter"]
            # if user has any test <= min_before% AND any test >= min_after%
            low_test = any(ft["percentage"] <= min_before for ft in finished_tests)
            high_test = any(ft["percentage"] >= min_after for ft in finished_tests)
            if low_test and high_test:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 9) minScore => e.g. "accuracy_king" => user must have >= X% on at least 1 test
        if "minScore" in criteria:
            needed = criteria["minScore"]
            # check if user has at least one test with >= needed
            if any(ft["percentage"] >= needed for ft in finished_tests):
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # 10) minScoreGlobal => e.g. "exam_conqueror" => user must have 80%+ on EVERY test
        if "minScoreGlobal" in criteria:
            min_g = criteria["minScoreGlobal"]
            # Must finish all tests in the platform => total_finished >= TOTAL_TESTS
            # Then check all have >= min_g
            if total_finished >= TOTAL_TESTS:
                # confirm user indeed has attempts for each test? 
                # or assume if total_finished >= 130 => they covered them all
                # check if all attempts have >= min_g
                # slight logic detail: you might need to ensure user actually finished *every* test, i.e. no missing testId
                all_above = all(ft["percentage"] >= min_g for ft in finished_tests)
                if all_above:
                    unlocked.append(aid)
                    newly_unlocked.append(aid)

        # 11) minScoreInCategory => e.g. "subject_specialist" => 80%+ on all 10 tests in one category
        if "minScoreInCategory" in criteria:
            min_cat = criteria["minScoreInCategory"]
            # check each category group. If user has 10 tests in that category & all >= min_cat => unlock
            for ccat, attempts in category_groups.items():
                if len(attempts) == 10:
                    # verify all attempts in that ccat are >= min_cat
                    if all(ft["percentage"] >= min_cat for ft in attempts):
                        unlocked.append(aid)
                        newly_unlocked.append(aid)
                        break

        # 12) perfectTestsInCategory => e.g. "category_perfectionist" => 10 perfect tests in 1 category
        if "perfectTestsInCategory" in criteria:
            needed = criteria["perfectTestsInCategory"]
            for ccat, attempts in category_groups.items():
                perfect_count = sum(1 for ft in attempts if ft["percentage"] == 100)
                if perfect_count >= needed:
                    unlocked.append(aid)
                    newly_unlocked.append(aid)
                    break

        # 13) perfectTestsGlobal => e.g. "absolute_perfectionist" => 100% on ALL tests in platform
        if "perfectTestsGlobal" in criteria and criteria["perfectTestsGlobal"] is True:
            # user must have finished all tests & each is perfect
            if total_finished >= TOTAL_TESTS:
                # check if all are 100%
                all_perfect = all(ft["percentage"] == 100 for ft in finished_tests)
                if all_perfect:
                    unlocked.append(aid)
                    newly_unlocked.append(aid)

        # 14) totalQuestions => e.g. "answer_machine_1000", "knowledge_beast_5000", etc.
        #    means user must have answered >= X questions across all attempts
        if "totalQuestions" in criteria:
            needed_q = criteria["totalQuestions"]
            if sum_of_questions >= needed_q:
                unlocked.append(aid)
                newly_unlocked.append(aid)

    # If we unlocked new ones, save them to the user doc
    if newly_unlocked:
        mainusers_collection.update_one(
            {"_id": user_oid},
            {"$set": {"achievements": unlocked}}
        )

    return newly_unlocked

