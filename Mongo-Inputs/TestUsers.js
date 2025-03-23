db.mainusers.insertMany([
  {
    username: "Test01",
    email: "Test01@example.com",
    password: "Test123!",
    level: 200,
    xp: 200000,
    coins: 200000,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 10000,
      perfect_tests_count: 5,
      perfect_tests_by_category: {},
      highest_score_ever: 0,
      lowest_score_ever: 100,
      total_questions_answered: 0
    }
  },
  {
    username: "Test02",
    email: "Test02@example.com",
    password: "Test123!",
    level: 1,
    xp: 480,
    coins: 20000,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 2,
      perfect_tests_count: 0,
      perfect_tests_by_category: {},
      highest_score_ever: 93, 
      lowest_score_ever: 20,
      total_questions_answered: 1000
    }
  },
  {
    username: "Test03",
    email: "Test03@example.com",
    password: "Test123!",
    level: 1,
    xp: 480,
    coins: 20000,
    achievements: [],
    achievement_counters: {
      total_tests_completed: 10,
      perfect_tests_count: 3,
      perfect_tests_by_category: {},
      highest_score_ever: 90,
      lowest_score_ever: 30,
      total_questions_answered: 100000
    }
  }
]);
