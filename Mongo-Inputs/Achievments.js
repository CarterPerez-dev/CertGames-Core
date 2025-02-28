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
