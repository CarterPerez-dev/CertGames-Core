## First we need to update the global test page to have exam and practice mode toggle aswell as the 25,50,75,100 options (refer to https://github.com/CarterPerez-dev/ProxyAuthRequired/blob/main/ISSUES-IMPROVEMENTS.md), then we need to Remove the bad achievements (refer down below), then we need to optimize the achivements we are keeping, then we need to convert/update the achievemnts to reflect the exam mode and practice mode, then we need to make them all actually work and verify them.

---
---
---
## 1. Add Counter Fields (Highest Impact)
### Update your user document structure to include achievement-specific counters:

```python 
# Add these fields to your user documents
user_data.setdefault("achievement_counters", {
    "total_tests_completed": 0,
    "perfect_tests_count": 0,
    "perfect_tests_by_category": {},
    "consecutive_perfect_streak": 0,
    "highest_score_ever": 0,
    "lowest_score_ever": 100
})
Then update these incrementally when a test is finished:
pythonCopy@api_bp.route('/attempts/<user_id>/<test_id>/finish', methods=['POST'])
def finish_test_attempt(user_id, test_id):
    # ... existing code ...
    
    # Update counters atomically
    update_operations = {"$inc": {"achievement_counters.total_tests_completed": 1}}
    
    if score == totalQuestions:  # Perfect score
        update_operations["$inc"] = {"achievement_counters.perfect_tests_count": 1}
        update_operations["$inc"].update({f"achievement_counters.perfect_tests_by_category.{category}": 1})
    
    if score/totalQuestions > user["achievement_counters"]["highest_score_ever"]:
        update_operations["$set"] = {"achievement_counters.highest_score_ever": score/totalQuestions}
    
    mainusers_collection.update_one({"_id": user_oid}, update_operations)
    
    newly_unlocked = check_and_unlock_achievements(user_id)
    # ...
```
### 2. Implement Achievement Caching (Moderate Complexity)
```python 
# Add at top of file
achievement_cache = {}
ACHIEVEMENT_CACHE_TTL = 300  # 5 minutes

def check_and_unlock_achievements(user_id):
    """Cached version - checks cache first before expensive calculations"""
    now = time.time()
    cache_key = f"achievements_{user_id}"
    
    if cache_key in achievement_cache and now - achievement_cache[cache_key]["timestamp"] < ACHIEVEMENT_CACHE_TTL:
        return achievement_cache[cache_key]["unlocked"]
    
    # Run the expensive calculation
    newly_unlocked = original_check_and_unlock_achievements(user_id)
    
    # Cache the result
    achievement_cache[cache_key] = {
        "timestamp": now,
        "unlocked": newly_unlocked
    }
    
    return newly_unlocked
```
### 3. Split Achievement Processing (Best Long-term)
```python
def check_and_unlock_achievements(user_id):
    """Two-tier achievement checking"""
    user = get_user_by_id(user_id)
    if not user:
        return []
        
    # TIER 1: Fast, counter-based achievements
    newly_unlocked = check_simple_achievements(user)
    
    # TIER 2: Only check complex achievements once per day
    last_complex_check = user.get("last_complex_achievement_check")
    if not last_complex_check or (datetime.utcnow() - last_complex_check).days >= 1:
        complex_unlocked = check_complex_achievements(user)
        newly_unlocked.extend(complex_unlocked)
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_complex_achievement_check": datetime.utcnow()}}
        )
    
    return newly_unlocked
```
## Which Achievements to Keep vs. Modify
### Keep but Optimize:

#### category_perfectionist - Calculate from counters instead of rechecking tests
#### test_finisher - Simple counter-based check
#### subject_specialist - Check only the specific category that was just completed

#### consecutive_perfects - Track as a counter instead of recalculating

# Remove:

### absolute_perfectionist - Extremely difficult to achieve and very expensive to calculate
### xam_conqueror - Computationally expensive for little gameplay benefit

## These optimizations allow you to keep most of your achievement mechanics while dramatically improving database performance and reducing latency. The counter-based approach especially will let you scale to many users while maintaining the gamification elements your users enjoy.
