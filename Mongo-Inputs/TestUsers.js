
// input into mongodb and then got to admin page and see they if they were achieved

db.mainusers.insertMany([
  // 1) test_rookie => total_tests_completed = 1
  {
    username: "UserTestRookie",
    email: "rookie@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 1,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 0,
      lowest_score_ever: 100,
      total_questions_answered: 0
    }
  },
  // 2) accuracy_king => highest_score_ever >= 90
  {
    username: "UserAccuracyKing",
    email: "accuracy@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 2,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 93, // must be >= 90
      lowest_score_ever: 50,
      total_questions_answered: 0
    }
  },
  // 3) bronze_grinder => total_tests_completed >= 10
  {
    username: "UserBronzeGrinder",
    email: "bronze@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 10,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 60,
      lowest_score_ever: 40,
      total_questions_answered: 100
    }
  },
  // 4) silver_scholar => total_tests_completed >= 25
  {
    username: "UserSilverScholar",
    email: "silver@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 25,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 80,
      lowest_score_ever: 30,
      total_questions_answered: 500
    }
  },
  // 5) gold_god => total_tests_completed >= 50
  {
    username: "UserGoldGod",
    email: "gold@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 50,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 85,
      lowest_score_ever: 30,
      total_questions_answered: 1000
    }
  },
  // 6) platinum_pro => total_tests_completed >= 80
  {
    username: "UserPlatinumPro",
    email: "platinum@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 80,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 88,
      lowest_score_ever: 50,
      total_questions_answered: 1200
    }
  },
  // 7) walking_encyclopedia => total_questions_answered >= 8000
  {
    username: "UserEncyclopedia",
    email: "encyclo@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 20,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 70,
      lowest_score_ever: 30,
      total_questions_answered: 8000
    }
  },
  // 8) redemption_arc => lowest_score_ever <= 40 & highest_score_ever >= 90
  {
    username: "UserRedeemer",
    email: "redeem@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 2,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 94,
      lowest_score_ever: 30,
      total_questions_answered: 100
    }
  },
  // 9) coin_collector_5000 => coins >= 5000
  {
    username: "UserCoin5k",
    email: "coins5k@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 5000, // This triggers coin_collector_5000
    achievements: [],
    achievement_counters: {
      total_tests_completed: 0,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 0,
      lowest_score_ever: 100,
      total_questions_answered: 0
    }
  },
  // 10) coin_hoarder_10000 => coins >= 10000
  {
    username: "UserCoin10k",
    email: "coins10k@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 10000,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 0,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 0,
      lowest_score_ever: 100,
      total_questions_answered: 0
    }
  },
  // 11) coin_tycoon_50000 => coins >= 50000
  {
    username: "UserCoin50k",
    email: "coins50k@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 50000,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 0,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 0,
      lowest_score_ever: 100,
      total_questions_answered: 0
    }
  },
  // 12) perfectionist_1 => perfect_tests_count >= 1
  {
    username: "UserPerf1",
    email: "perf1@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 3,
      perfect_tests_count: 1,
      perfect_tests_by_category: {},
      highest_score_ever: 85,
      lowest_score_ever: 60,
      total_questions_answered: 300
    }
  },
  // 13) double_trouble_2 => perfect_tests_count >= 2
  {
    username: "UserPerf2",
    email: "perf2@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 4,
      perfect_tests_count: 2,
      perfect_tests_by_category: {},
      highest_score_ever: 86,
      lowest_score_ever: 60,
      total_questions_answered: 400
    }
  },
  // 14) error404_failure_not_found => perfect_tests_count >= 3
  {
    username: "UserPerf3",
    email: "perf3@example.com",
    password: "test123",
    level: 1,
    xp: 0,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 5,
      perfect_tests_count: 3,
      perfect_tests_by_category: {},
      highest_score_ever: 87,
      lowest_score_ever: 60,
      total_questions_answered: 500
    }
  },
  // 15) level_up_5 => level >= 5
  {
    username: "UserLevel5",
    email: "level5@example.com",
    password: "test123",
    level: 5,  // triggers level_up_5
    xp: 2000,  // whatever
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 0,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 0,
      lowest_score_ever: 100,
      total_questions_answered: 0
    }
  },
  // 16) mid_tier_grinder_25 => level >= 25
  {
    username: "UserLevel25",
    email: "level25@example.com",
    password: "test123",
    level: 25,
    xp: 20000,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 0,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 0,
      lowest_score_ever: 100,
      total_questions_answered: 0
    }
  },
  // 17) elite_scholar_50 => level >= 50
  {
    username: "UserLevel50",
    email: "level50@example.com",
    password: "test123",
    level: 50,
    xp: 60000,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 0,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 0,
      lowest_score_ever: 100,
      total_questions_answered: 0
    }
  },
  // 18) ultimate_master_100 => level >= 100
  {
    username: "UserLevel100",
    email: "level100@example.com",
    password: "test123",
    level: 100,
    xp: 300000,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 0,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 0,
      lowest_score_ever: 100,
      total_questions_answered: 0
    }
  },
  // 19) answer_machine_1000 => total_questions_answered >= 1000
  {
    username: "UserAnswerMachine",
    email: "answers1000@example.com",
    password: "test123",
    level: 10,
    xp: 5000,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 10,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 80,
      lowest_score_ever: 50,
      total_questions_answered: 1000
    }
  },
  // 20) knowledge_beast_5000 => total_questions_answered >= 5000
  {
    username: "UserKnowledgeBeast",
    email: "answers5000@example.com",
    password: "test123",
    level: 15,
    xp: 8000,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 25,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 85,
      lowest_score_ever: 40,
      total_questions_answered: 5000
    }
  },
  // 21) question_terminator => total_questions_answered >= 10000
  {
    username: "UserQTerminator",
    email: "answers10000@example.com",
    password: "test123",
    level: 20,
    xp: 10000,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 40,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 88,
      lowest_score_ever: 40,
      total_questions_answered: 10000
    }
  },
  // 22) test_finisher => allTestsCompleted == true
  //    The code checks if total_tests_completed >= 130 (or your actual TOTAL_TESTS).
  {
    username: "UserTestFinisher",
    email: "testfinisher@example.com",
    password: "test123",
    level: 10,
    xp: 5000,
    coins: 0,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 130, // If your code uses 130 for all-tests
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 0,
      lowest_score_ever: 100,
      total_questions_answered: 3000
    }
  }
]);
