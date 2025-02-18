# achievment test
There are several ways to simulate or verify your achievement–unlocking logic without having to complete thousands of tests manually. Here are a few approaches:

Manually Insert Test Data:
You can use the Mongo shell or a database admin tool (like MongoDB Compass) to insert or modify test attempt documents (in the testAttempts_collection) for a specific user. For example, if you want to simulate a “perfect” test (100% score), you can insert a finished attempt with score equal to totalQuestions, and with a finishedAt timestamp. By inserting several such documents (or modifying an existing user’s progress), you can simulate conditions like:

One perfect test (to test the “perfectionist” achievement)
5 perfect tests in a row (for “memory_master”)
Finishing all tests with a certain score threshold (for “exam_conqueror” or “subject_specialist”)
Write a Test Script:
Create a small script (or use a unit testing framework) that:

Creates a dummy user document,
Inserts test attempt documents with the exact properties needed to trigger each achievement,
Calls your check_and_unlock_achievements(user_id) function, and
Verifies that the returned list of achievement IDs matches your expectations.
This allows you to simulate multiple conditions without having to run through your full frontend flow.

Use a Debug/Admin Route:
You could add a temporary admin route (for testing only) that accepts simulated progress data for a given user and calls your achievements function. This endpoint can return the list of achievements unlocked, which you can compare to your expected results.

Example (Manual Mongo Data Insert)
For example, to simulate a perfect test for a user with _id of user123, you might insert a document like:

```javascript
Copy
db.testAttempts.insertOne({
  userId: ObjectId("user123"),
  testId: "1",
  finished: true,
  finishedAt: new Date(),
  score: 10,
  totalQuestions: 10,
  category: "aplus",
  // other fields (e.g., answers, etc.) as needed
});
Repeat with different testIds and values to simulate consecutive perfect scores or tests with a score below/above certain thresholds.

Summary
Manually modify/inject test attempt data to mimic conditions required by each achievement.
Use a test script or temporary endpoint to run the achievements function against simulated data.
Once verified, you can remove any extra debugging endpoints or test code from production.
This way, you can ensure your achievements logic (and popups via your frontend) work as expected without the need to manually complete every test.
```

----------------------------------------------------------------------------------------------------------------------------
For a production‑grade, cross‐device solution that remains fast and scalable, storing progress on the server (Option B) is the better choice.

Here’s why:

Cross‑Device & Cross‑Browser Consistency:
Storing progress in your database means a user’s progress is tied to their account rather than a specific browser’s localStorage. This ensures they can pick up where they left off on any device, OS, or browser.

Scalability:
While localStorage is fast for small amounts of data, it has a strict size limit (around 5MB) and can become inefficient if you store large data (like thousands of questions). A server‑side solution can be optimized with caching, indexing, and proper data structures so that even if a user answers many questions, retrieving their progress remains fast.

Performance & Future-Proofing:
Although server requests add a network round-trip, you can mitigate this with asynchronous calls and caching strategies. This approach avoids potential browser freezes or “quota exceeded” errors as the user’s history grows over time.

Data Integrity & Security:
Centralizing data on the server means you can implement more robust backups, security measures, and audit logs. This is particularly important for features like achievements, shop items, and overall test progress.

Conclusion:
For a site where users might answer thousands of questions—and where progress should be available on any device—the server‑side storage option is faster (in terms of long‑term performance and user experience) and far more scalable.

To implement this, you’d modify your progress-saving logic to send minimal progress data (such as IDs, answer indices, and shuffle order) to your backend, where it’s stored in MongoDB (or your chosen database). Then, when a user returns, you load their progress from the server rather than from localStorage.

This solution pairs well with your existing backend structure (user data, achievements, shop items, etc.) and future improvements for a consistent, cross‑device user experience.




-------------------------------------------------------------------------------------------------------------------------------
Explanation of Key Changes
shuffleOrder and currentQuestionIndex are now stored and updated in the update_test_attempt endpoint:

```python
Copy
Edit
update_doc = {
    "$set": {
        ...
        "currentQuestionIndex": data.get("currentQuestionIndex", 0),
        "shuffleOrder": data.get("shuffleOrder", []),
        "finished": data.get("finished", False)
    }
}
```
This ensures we’re saving minimal data about the user’s test flow (rather than the entire text of each question).

get_test_attempt returns the entire attempt doc (including currentQuestionIndex and shuffleOrder) so the frontend can restore progress from the server for that user and test.

We did not remove local achievements logic, daily bonus, final scoring logic, or any other existing routes. We only enhanced the partial‐progress storage to allow you to offload big data from localStorage to your server’s DB.

With this approach, you no longer need to store big question arrays in localStorage. Instead, the frontend can:

Fetch the test from the server to get the question text each time.
Retrieve the attempt doc from the server (GET /attempts/<userId>/<testId>) to see currentQuestionIndex, shuffleOrder, answers, etc.
Render accordingly, allowing truly cross‐device/cross‐browser continuity.
Next Steps (Frontend Adjustments)
Stop storing large question arrays in localStorage. Instead, fetch from /api/test/tests/<testId> each time you load the test page.
Use the updated GET /attempts/<userId>/<testId> to retrieve partial progress (like shuffleOrder, currentQuestionIndex, answers).
Use POST /attempts/<userId>/<testId> to update partial progress as the user answers each question (or moves to the next one).
Remove references to saving the entire shuffledQuestions array in localStorage. Only keep enough data to show user feedback if you want local ephemeral storage. But all crucial progress data should be in the DB (Mongo) now, removing the 5MB localStorage limit problem.
Once you’ve made the corresponding frontend changes, you’ll have a robust, server‐side storage approach for progress that automatically syncs across devices and solves the “Quota Exceeded” error.

------------------------------------------------------------------------------------------------------------------------------
  Tip: You can adjust how often you call updateServerProgress(...) (e.g., after each question or every few questions) to balance performance vs. real-time saving. But storing large text in localStorage is gone, solving the quota issue while preserving all features.
--------------------------------------------------------------------------------------------------------------------------------1) How Your Current Achievement-Checking Code Works
In your models.py (or wherever check_and_unlock_achievements(user_id) lives), you have logic like:

```
python
Copy
Edit
def check_and_unlock_achievements(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return []

    user_oid = user["_id"]

    # total finished attempts
    total_finished = testAttempts_collection.count_documents({
        "userId": user_oid,
        "finished": True
    })

    # perfect tests (score == totalQuestions)
    perfect_tests = testAttempts_collection.count_documents({
        "userId": user_oid,
        "finished": True,
        "$expr": {"$eq": ["$score", "$totalQuestions"]}
    })

    # fetch finished attempts to get more details (like percentages)
    finished_cursor = testAttempts_collection.find({"userId": user_oid, "finished": True})
    finished_tests = []
    for doc in finished_cursor:
        tq = doc.get("totalQuestions", 0)
        sc = doc.get("score", 0)
        pct = (sc / tq) * 100 if tq else 0
        cat = doc.get("category", "global")
        finished_tests.append({
            "test_id": doc.get("testId", "0"),
            "percentage": pct,
            "category": cat
        })

    # 1) Consecutive perfect logic (based on testId numbering):
    perfect_list = [ft for ft in finished_tests if ft["percentage"] == 100]
    perfect_list.sort(key=lambda x: x["test_id"])  # tries to sort by integer if possible
    max_consecutive = 0
    current_streak = 0
    previous_test_id = None
    for ft in perfect_list:
        # The code tries to see if test_id is consecutive integer
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

    # 2) Group tests by category
    from collections import defaultdict
    category_groups = defaultdict(list)
    for ft in finished_tests:
        cat = ft["category"]
        category_groups[cat].append(ft)

    # Possibly a total test threshold
    #  (In your snippet, there's a mention of TOTAL_TESTS = 130 or something.)
    #  This is used for "allTestsCompleted".
    unlocked = user.get("achievements", [])
    newly_unlocked = []
    all_ach = get_achievements()  # from your achievements collection

    for ach in all_ach:
        aid = ach["achievementId"]
        criteria = ach.get("criteria", {})

        if aid in unlocked:
            continue  # already unlocked

        # Examples of checks your code does:
        if "testCount" in criteria:
            if total_finished >= criteria["testCount"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        if "coins" in criteria:
            if user.get("coins", 0) >= criteria["coins"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        if "level" in criteria:
            if user.get("level", 1) >= criteria["level"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        if "perfectTests" in criteria:
            if perfect_tests >= criteria["perfectTests"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        if "consecutivePerfects" in criteria:
            if max_consecutive >= criteria["consecutivePerfects"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        if "allTestsCompleted" in criteria and criteria["allTestsCompleted"] is True:
            # e.g. if total_finished >= TOTAL_TESTS => unlock
            # (Your code had something like total_finished >= 130 or similar.)
            pass

        if "testsCompletedInCategory" in criteria:
            # your code checks if user has done enough tests in a single category
            # e.g. if len(category_groups[cat]) >= that # => unlock
            pass

        if ("minScoreBefore" in criteria and "minScoreAfter" in criteria):
            # redemption arc
            # the code checks if user has any test with <= X% and any test with >= Y%
            pass

        # (That’s the gist of your existing checks.)
    # End loop

    if newly_unlocked:
        mainusers_collection.update_one(
            {"_id": user_oid},
            {"$set": {"achievements": unlocked}}
        )

    return newly_unlocked
```

Which Criteria Are Actually Implemented?
testCount (like 1, 10, 25, 50, 80) => This works. If you finish enough tests, you get it.

coins (like 5,000 / 10,000 / 50,000) => The code matches “if user’s coin balance >= X.”

level (like 5, 25, 50, 100) => Matches “if user’s level >= X.”

perfectTests => “Score 100% on N tests total.” (like for perfectionist_1, double_trouble_2, etc.) This is actually implemented.

consecutivePerfects => (like for “memory_master” = 5). The code tries to read consecutive test IDs. However, note that it’s not truly “5 perfect attempts in a row chronologically.” Instead, it looks for test IDs like 1,2,3,4,5 (all 100%). If you do tests #1, #3, #2, #5, #4 in random order, it might not count as consecutive. So that might be a mismatch from your intention.

allTestsCompleted: true => E.g. the code might compare total_finished vs. TOTAL_TESTS = 130. If the user has finished 130 tests, it unlocks test_finisher. But your platform only has 13 categories × 10 tests each = 130 total. That part is presumably correct if you set TOTAL_TESTS = 130.

testsCompletedInCategory => E.g. “If user completed 10 tests in that same category,” it unlocks an achievement (like “subject_finisher”). This is in the code snippet:

```
python
Copy
Edit
if "testsCompletedInCategory" in criteria:
    for ccat, attempts in category_groups.items():
        if len(attempts) >= criteria["testsCompletedInCategory"]:
            unlocked.append(aid)
            newly_unlocked.append(aid)
            break
```

That part is basically “complete 10 tests in the same category => unlock.” So subject_finisher is correct for that.

minScoreBefore / minScoreAfter => This is the “redemption_arc.” The code checks if the user has any test with % <= minScoreBefore and any test with % >= minScoreAfter. So that’s good enough for a single check.

Which Criteria Are Not Implemented in the Code
minScore: 90 or accuracy_king:

There’s no top-level check for “score ≥ 90% in any single test.” The existing code has:

```
python
Copy
Edit
if "perfectTests" in criteria: ...
if "consecutivePerfects" in criteria: ...
if "minScoreBefore" and "minScoreAfter" in criteria: ...
But no if "minScore" in criteria: logic.

So “accuracy_king” (which says { minScore: 90 }) won’t ever unlock with current code. You’d need to add something like:

python
Copy
Edit
# e.g. inside your for ach in all_ach loop:
if "minScore" in criteria:
    # means user must have >= minScore on at least one test
    # so check if any finished_tests item has >= criteria["minScore"]
    if any(ft["percentage"] >= criteria["minScore"] for ft in finished_tests):
        unlocked.append(aid)
        newly_unlocked.append(aid)
minScoreGlobal: 80 or exam_conqueror:
```


That means “score 80% or higher on every test in the entire platform.” There is no code that checks “the user’s percentage on every test >= 80%.”
You would need logic that sees if the user has finished all tests, and every test has ≥80%. Something like:
python
Copy
Edit
if "minScoreGlobal" in criteria:
    # Make sure user has finished all tests (or however many total)
    if total_finished >= TOTAL_TESTS:
        # Now check if all are >= criteria["minScoreGlobal"]
        all_above = all(ft["percentage"] >= criteria["minScoreGlobal"] for ft in finished_tests)
        if all_above:
            unlocked.append(aid)
            newly_unlocked.append(aid)
minScoreInCategory: 80 or subject_specialist:

Means “score 80%+ on all 10 tests in one exam category.” The code never checks that.
You’d need something like:
python
Copy
Edit
if "minScoreInCategory" in criteria:
    # For each category ccat, check if user finished all 10 tests in that category
    # And each test in that category has >= minScoreInCategory
    for ccat, attempts in category_groups.items():
        if len(attempts) == 10:  # means user finished all 10 tests in ccat
            if all(ft["percentage"] >= criteria["minScoreInCategory"] for ft in attempts):
                unlocked.append(aid)
                newly_unlocked.append(aid)
                break
perfectTestsInCategory: 10 or category_perfectionist:

Means “score 100% on all 10 tests in one category.”
The code does not do that. It only checks testsCompletedInCategory or overall perfectTests across the entire platform.
You’d need something like:
python
Copy
Edit
if "perfectTestsInCategory" in criteria:
    # user must have 10 perfect tests in the SAME category
    for ccat, attempts in category_groups.items():
        # attempts is a list of dicts w/ "percentage"
        # check how many are 100%
        perfect_count = sum(1 for ft in attempts if ft["percentage"] == 100)
        if perfect_count >= criteria["perfectTestsInCategory"]:
            unlocked.append(aid)
            newly_unlocked.append(aid)
            break
minScore for “accuracy_king” is not covered in your code.

“score 100% on all tests in entire platform” => “absolute_perfectionist.” The code for allTestsCompleted is just finishing them, not scoring 100%. You’d need a new check: do we have perfectTestsGlobal: true? That means user’s # of perfect tests = total tests in the entire platform.

“score 80% in all tests in the platform,” or “score 80% in all tests in a single category,” also not coded.

Large question-based achievements like “Answer 5,000 questions in total,” or “Answer all 10,000.” Currently your code does not track a cumulative sum of all questions answered. It checks test attempts, but not the total # questions answered. If you want to track that, you’d have to sum up sum(totalQuestions) for all finished attempts or store a separate aggregator (like a user’s “questionsAnswered” counter).

Consecutive Perfect logic is ID-based, not time-based. For your “memory_master (5 perfect scores in a row)” requirement, the code sorts by test_id (like 1,2,3,4,5). That only works if you do them in ascending test ID order. If you wanted “5 perfect attempts in a row chronologically,” you’d track the order in which the user finished attempts. The existing code might cause confusion or never unlock if you do tests out of numeric order.

3) Summary of Potential Issues
Achievements referencing minScore, minScoreGlobal, minScoreInCategory, perfectTestsInCategory, or totalQuestions = X are not matched by the code you shared. The code checks for some things but not all.

Some advanced achievements like “score 100% on all 10 tests in one category” or “score ≥80% across all tests in entire platform” have no direct logic in your check_and_unlock_achievements() function.

“Memory Master” is presumably “5 perfect tests in a row,” but your code is checking “are the test IDs consecutive integers?” That might not reflect the real requirement (5 perfect attempts in chronological order).

So you’ll need to extend check_and_unlock_achievements() if you truly want those advanced achievements to unlock. That means adding new conditions like:

python
Copy
Edit
# Example for minScore (like "accuracy_king")
if "minScore" in criteria:
    # Unlock if user has >= that % on at least 1 test
    if any(ft["percentage"] >= criteria["minScore"] for ft in finished_tests):
        unlocked.append(aid)
        newly_unlocked.append(aid)

# Example for minScoreInCategory
if "minScoreInCategory" in criteria:
    min_pct = criteria["minScoreInCategory"]
    # Check for any category with 10 tests all above min_pct
    for ccat, attempts in category_groups.items():
        if len(attempts) == 10:
            if all(ft["percentage"] >= min_pct for ft in attempts):
                unlocked.append(aid)
                newly_unlocked.append(aid)
                break

# Example for perfectTestsInCategory
if "perfectTestsInCategory" in criteria:
    needed_perfects = criteria["perfectTestsInCategory"]
    for ccat, attempts in category_groups.items():
        perfect_count = sum(1 for ft in attempts if ft["percentage"] == 100)
        if perfect_count >= needed_perfects:
            unlocked.append(aid)
            newly_unlocked.append(aid)
            break

# Example for minScoreGlobal
if "minScoreGlobal" in criteria:
    min_pct = criteria["minScoreGlobal"]
    # Must have finished ALL tests in your platform, e.g. total_finished >= 130
    # Then check if every test is >= min_pct
    if total_finished >= TOTAL_TESTS:  # e.g. 130
        if all(ft["percentage"] >= min_pct for ft in finished_tests):
            unlocked.append(aid)
            newly_unlocked.append(aid)

# Example for "absolute_perfectionist" => perfectTestsGlobal: true
# Means user must have perfect attempts on ALL tests.
if "perfectTestsGlobal" in criteria:
    if total_finished >= TOTAL_TESTS:
        all_perfect = all(ft["percentage"] == 100 for ft in finished_tests)
        if all_perfect:
            unlocked.append(aid)
            newly_unlocked.append(aid)

# For large question-based achievements, track sum of questions answered:
# sum_of_questions = sum(ft["totalQuestions"] for ft in user’s finished attempts).
# Then compare to criteria["totalQuestions"].
4) Conclusion
Your base achievements code does handle simpler cases (test counts, coins, level thresholds, perfect test counts, “testsCompletedInCategory = X,” “redemption_arc,” etc.).
Advanced achievements referencing partial logic like minScore, minScoreGlobal, minScoreInCategory, “score 100% across entire category,” or “score≥80% across entire category,” etc., are not actually implemented in your code. They won’t unlock without additional checks.
“Memory Master” is using a numeric test ID to track consecutive perfects. If your real definition is “5 perfect attempts in chronological order,” the current code logic will not match that exactly.
If you want to fix these advanced achievements so that they truly match the definitions you inserted in db.achievements, you must extend check_and_unlock_achievements() to handle all relevant fields (like "minScore", "perfectTestsInCategory", "minScoreGlobal", etc.) and accurately track “consecutive attempts” vs. “consecutive test IDs.”
Once you add these needed checks in code, your more complicated achievements (like “score 90%+ on any test,” or “score 80% in all tests,” or “100% on all 10 tests in a category”) will unlock as expected.
