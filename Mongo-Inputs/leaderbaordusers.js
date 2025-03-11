db.mainusers.insertMany([
  // Top 3 users
  {
    "username": "BigBalls420",
    "email": "shadow420@example.com",
    "password": "Yoshi2003!!",
    "coins": 200000,
    "xp": 41500, // Level 71
    "level": 71,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50", "ultimate_master_100"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [
      ObjectId("67c8019eafc1b9f001544cca") // Infernal Bastion (Level 70)
    ],
    "xpBoost": 1.5,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cca"), // Infernal Bastion (Level 70)
    "nameColor": "#ff4500",
    "achievement_counters": {
      "total_tests_completed": 352,
      "perfect_tests_count": 180,
      "perfect_tests_by_category": {
        "math": 45,
        "science": 40,
        "history": 35,
        "language": 30,
        "general": 30
      },
      "highest_score_ever": 100.0,
      "lowest_score_ever": 65.5,
      "total_questions_answered": 15240
    }
  },
  {
    "username": "AngelaMoss69",
    "email": "toxic69@example.com",
    "password": "Yoshi2003!!",
    "coins": 184500,
    "xp": 40500, // Level 70
    "level": 70,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [
      ObjectId("67c8019eafc1b9f001544cca") // Infernal Bastion (Level 70)
    ],
    "xpBoost": 1.5,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cca"), // Infernal Bastion (Level 70)
    "nameColor": "#00ff00",
    "achievement_counters": {
      "total_tests_completed": 320,
      "perfect_tests_count": 155,
      "perfect_tests_by_category": {
        "math": 40,
        "science": 35,
        "history": 30,
        "language": 25,
        "general": 25
      },
      "highest_score_ever": 100.0,
      "lowest_score_ever": 68.0,
      "total_questions_answered": 14300
    }
  },
  {
    "username": "Tyrell-Wellick",
    "email": "purple5@example.com",
    "password": "Yoshi2003!!",
    "coins": 172000,
    "xp": 38500, // Level 68
    "level": 68,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [
      ObjectId("67c8019eafc1b9f001544cd5") // Frostbane (Level 60)
    ],
    "xpBoost": 1.25,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd5"), // Frostbane (Level 60)
    "nameColor": "#1e90ff",
    "achievement_counters": {
      "total_tests_completed": 295,
      "perfect_tests_count": 135,
      "perfect_tests_by_category": {
        "math": 35,
        "science": 30,
        "history": 25,
        "language": 25,
        "general": 20
      },
      "highest_score_ever": 100.0,
      "lowest_score_ever": 70.5,
      "total_questions_answered": 13400
    }
  },
  // The rest of the users with gradually decreasing levels
  {
    "username": "Yoshii",
    "email": "pancakes@example.com",
    "password": "Mooseodg635!",
    "coins": 165000,
    "xp": 37500, // Level 67
    "level": 67,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd5")], // Frostbane (Level 60)
    "xpBoost": 1.25,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd5"), // Frostbane (Level 60)
    "nameColor": "#ff6347",
    "achievement_counters": {
      "total_tests_completed": 280,
      "perfect_tests_count": 125,
      "perfect_tests_by_category": {"math": 30, "science": 28, "history": 25},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 72.0,
      "total_questions_answered": 12800
    }
  },
  {
    "username": "Cybernix0G",
    "email": "bread23@example.com",
    "password": "Yoshi2003!!",
    "coins": 158000,
    "xp": 36500, // Level 66
    "level": 66,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd5")], // Frostbane (Level 60)
    "xpBoost": 1.25,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd5"), // Frostbane (Level 60)
    "nameColor": "#8a2be2",
    "achievement_counters": {
      "total_tests_completed": 265,
      "perfect_tests_count": 115,
      "perfect_tests_by_category": {"science": 35, "history": 30, "general": 25},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 73.5,
      "total_questions_answered": 12200
    }
  },
  {
    "username": "Examgod97",
    "email": "rusty97@example.com",
    "password": "Yoshi2003!!",
    "coins": 151000,
    "xp": 35500, // Level 65
    "level": 65,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd5")], // Frostbane (Level 60)
    "xpBoost": 1.25,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd5"), // Frostbane (Level 60)
    "nameColor": "#32cd32",
    "achievement_counters": {
      "total_tests_completed": 250,
      "perfect_tests_count": 105,
      "perfect_tests_by_category": {"math": 28, "language": 25, "science": 22},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 75.0,
      "total_questions_answered": 11600
    }
  },
  {
    "username": "certspeedrunnernumba1",
    "email": "fluffy55@example.com",
    "password": "Yoshi2003!!",
    "coins": 144000,
    "xp": 34500, // Level 64
    "level": 64,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd5")], // Frostbane (Level 60)
    "xpBoost": 1.25,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd5"), // Frostbane (Level 60)
    "nameColor": "#ff69b4",
    "achievement_counters": {
      "total_tests_completed": 235,
      "perfect_tests_count": 95,
      "perfect_tests_by_category": {"history": 30, "language": 22, "general": 20},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 76.5,
      "total_questions_answered": 11000
    }
  },
  {
    "username": "Sniper_Elite47",
    "email": "sniper47@example.com",
    "password": "Yoshi2003!!",
    "coins": 138000,
    "xp": 33500, // Level 63
    "level": 63,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd5")], // Frostbane (Level 60)
    "xpBoost": 1.25,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd5"), // Frostbane (Level 60)
    "nameColor": "#8b4513",
    "achievement_counters": {
      "total_tests_completed": 220,
      "perfect_tests_count": 85,
      "perfect_tests_by_category": {"science": 25, "history": 20, "math": 18},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 78.0,
      "total_questions_answered": 10400
    }
  },
  {
    "username": "Drifs2000",
    "email": "drift2000@example.com",
    "password": "Yoshi2003!!",
    "coins": 132000,
    "xp": 32500, // Level 62
    "level": 62,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd5")], // Frostbane (Level 60)
    "xpBoost": 1.25,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd5"), // Frostbane (Level 60)
    "nameColor": "#ffa500",
    "achievement_counters": {
      "total_tests_completed": 205,
      "perfect_tests_count": 75,
      "perfect_tests_by_category": {"language": 20, "math": 15, "general": 18},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 79.5,
      "total_questions_answered": 9800
    }
  },
  {
    "username": "Banana_blaster9",
    "email": "banana9@example.com",
    "password": "Yoshi2003!!",
    "coins": 126000,
    "xp": 31500, // Level 61
    "level": 61,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd5")], // Frostbane (Level 60)
    "xpBoost": 1.25,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd5"), // Frostbane (Level 60)
    "nameColor": "#9932cc",
    "achievement_counters": {
      "total_tests_completed": 190,
      "perfect_tests_count": 65,
      "perfect_tests_by_category": {"science": 18, "history": 16, "math": 14},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 81.0,
      "total_questions_answered": 9200
    }
  },
  {
    "username": "CoffeeAddiction01",
    "email": "coffee77@example.com",
    "password": "Yoshi2003!!",
    "coins": 120000,
    "xp": 30250, // Level 60
    "level": 60,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd5")], // Frostbane (Level 60)
    "xpBoost": 1.25,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd5"), // Frostbane (Level 60)
    "nameColor": "#ff4500",
    "achievement_counters": {
      "total_tests_completed": 175,
      "perfect_tests_count": 55,
      "perfect_tests_by_category": {"language": 15, "general": 12, "science": 11},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 82.5,
      "total_questions_answered": 8600
    }
  },
  {
    "username": "Rocket--Man",
    "email": "rocket86@example.com",
    "password": "Yoshi2003!!",
    "coins": 114000,
    "xp": 29000, // Level 58
    "level": 58,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd5")], // Frostbane (Level 60)
    "xpBoost": 1.2,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd5"), // Frostbane (Level 60)
    "nameColor": "#00ced1",
    "achievement_counters": {
      "total_tests_completed": 165,
      "perfect_tests_count": 48,
      "perfect_tests_by_category": {"history": 13, "science": 10, "math": 9},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 83.0,
      "total_questions_answered": 8200
    }
  },
  {
    "username": "LavaLamp420",
    "email": "lava420@example.com",
    "password": "Yoshi2003!!",
    "coins": 108000,
    "xp": 27750, // Level 56
    "level": 56,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd5")], // Frostbane (Level 60)
    "xpBoost": 1.2,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd5"), // Frostbane (Level 60)
    "nameColor": "#9370db",
    "achievement_counters": {
      "total_tests_completed": 155,
      "perfect_tests_count": 42,
      "perfect_tests_by_category": {"language": 11, "general": 10, "science": 9},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 83.5,
      "total_questions_answered": 7800
    }
  },
  {
    "username": "_Noodlemaster64_",
    "email": "noodle64@example.com",
    "password": "Yoshi2003!!",
    "coins": 102000,
    "xp": 26500, // Level 54
    "level": 54,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd7")], // Necroforge (Level 50)
    "xpBoost": 1.2,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd7"), // Necroforge (Level 50)
    "nameColor": "#32cd32",
    "achievement_counters": {
      "total_tests_completed": 145,
      "perfect_tests_count": 38,
      "perfect_tests_by_category": {"math": 12, "history": 9, "general": 8},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 84.0,
      "total_questions_answered": 7400
    }
  },
  {
    "username": "Sk8erBoi2005",
    "email": "skater05@example.com",
    "password": "Yoshi2003!!",
    "coins": 96000,
    "xp": 25250, // Level 52
    "level": 52,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd7")], // Necroforge (Level 50)
    "xpBoost": 1.2,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd7"), // Necroforge (Level 50)
    "nameColor": "#ff8c00",
    "achievement_counters": {
      "total_tests_completed": 135,
      "perfect_tests_count": 35,
      "perfect_tests_by_category": {"science": 10, "language": 9, "history": 8},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 84.5,
      "total_questions_answered": 7000
    }
  },
  {
    "username": "XxDawgXX",
    "email": "glitchy@example.com",
    "password": "Yoshi2003!!",
    "coins": 90000,
    "xp": 24000, // Level 50
    "level": 50,
    "achievements": ["level_up_5", "mid_tier_grinder_25", "elite_scholar_50"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd7")], // Necroforge (Level 50)
    "xpBoost": 1.2,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd7"), // Necroforge (Level 50)
    "nameColor": "#4682b4",
    "achievement_counters": {
      "total_tests_completed": 125,
      "perfect_tests_count": 32,
      "perfect_tests_by_category": {"math": 9, "general": 8, "language": 7},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 85.0,
      "total_questions_answered": 6600
    }
  },
  {
    "username": "Carter",
    "email": "crimson@example.com",
    "password": "Yoshi2003!!",
    "coins": 85000,
    "xp": 22750, // Level 48
    "level": 48,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd3")], // Leviathan's Bride (Level 40)
    "xpBoost": 1.2,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd3"), // Leviathan's Bride (Level 40)
    "nameColor": "#ff69b4",
    "achievement_counters": {
      "total_tests_completed": 115,
      "perfect_tests_count": 29,
      "perfect_tests_by_category": {"history": 8, "science": 7, "math": 6},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 85.5,
      "total_questions_answered": 6200
    }
  },
  {
    "username": "CheeseWiz29449333",
    "email": "cheese@example.com",
    "password": "Yoshi2003!!",
    "coins": 80000,
    "xp": 21500, // Level 46
    "level": 46,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd3")], // Leviathan's Bride (Level 40)
    "xpBoost": 1.2,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd3"), // Leviathan's Bride (Level 40)
    "nameColor": "#8b008b",
    "achievement_counters": {
      "total_tests_completed": 105,
      "perfect_tests_count": 26,
      "perfect_tests_by_category": {"language": 7, "general": 6, "science": 6},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 86.0,
      "total_questions_answered": 5800
    }
  },
  {
    "username": "Rex44",
    "email": "radical@example.com",
    "password": "Yoshi2003!!",
    "coins": 75000,
    "xp": 20250, // Level 44
    "level": 44,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd3")], // Leviathan's Bride (Level 40)
    "xpBoost": 1.1,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd3"), // Leviathan's Bride (Level 40)
    "nameColor": "#a0522d",
    "achievement_counters": {
      "total_tests_completed": 95,
      "perfect_tests_count": 23,
      "perfect_tests_by_category": {"math": 7, "history": 6, "general": 5},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 86.5,
      "total_questions_answered": 5400
    }
  },
  {
    "username": "4455548",
    "email": "pixel88@example.com",
    "password": "Yoshi2003!!",
    "coins": 70000,
    "xp": 19000, // Level 42
    "level": 42,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd3")], // Leviathan's Bride (Level 40)
    "xpBoost": 1.1,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd3"), // Leviathan's Bride (Level 40)
    "nameColor": "#008080",
    "achievement_counters": {
      "total_tests_completed": 85,
      "perfect_tests_count": 20,
      "perfect_tests_by_category": {"science": 6, "language": 5, "math": 4},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 87.0,
      "total_questions_answered": 5000
    }
  },
  {
    "username": "AnanAnon_000",
    "email": "dragon99@example.com",
    "password": "Yoshi2003!!",
    "coins": 65000,
    "xp": 17750, // Level 40
    "level": 40,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd3")], // Leviathan's Bride (Level 40)
    "xpBoost": 1.1,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd3"), // Leviathan's Bride (Level 40)
    "nameColor": "#daa520",
    "achievement_counters": {
      "total_tests_completed": 75,
      "perfect_tests_count": 18,
      "perfect_tests_by_category": {"history": 5, "general": 5, "language": 4},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 87.5,
      "total_questions_answered": 4600
    }
  },
  {
    "username": "AApluSMasterYY",
    "email": "neon@example.com",
    "password": "Yoshi2003!!",
    "coins": 60000,
    "xp": 16500, // Level 38
    "level": 38,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cc3")], // Astral Revenant (Level 30)
    "xpBoost": 1.1,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cc3"), // Astral Revenant (Level 30)
    "nameColor": "#7b68ee",
    "achievement_counters": {
      "total_tests_completed": 68,
      "perfect_tests_count": 16,
      "perfect_tests_by_category": {"math": 5, "science": 4, "history": 3},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 88.0,
      "total_questions_answered": 4200
    }
  },
  {
    "username": "MidnightRaven13",
    "email": "midnight13@example.com",
    "password": "Yoshi2003!!",
    "coins": 55000,
    "xp": 15250, // Level 36
    "level": 36,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cc3")], // Astral Revenant (Level 30)
    "xpBoost": 1.1,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cc3"), // Astral Revenant (Level 30)
    "nameColor": "#008000",
    "achievement_counters": {
      "total_tests_completed": 62,
      "perfect_tests_count": 14,
      "perfect_tests_by_category": {"language": 4, "general": 4, "history": 3},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 88.5,
      "total_questions_answered": 3800
    }
  },
  {
    "username": "hiesenburg",
    "email": "frozen42@example.com",
    "password": "Yoshi2003!!",
    "coins": 50000,
    "xp": 14000, // Level 34
    "level": 34,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cc3")], // Astral Revenant (Level 30)
    "xpBoost": 1.1,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cc3"), // Astral Revenant (Level 30)
    "nameColor": "#4169e1",
    "achievement_counters": {
      "total_tests_completed": 56,
      "perfect_tests_count": 12,
      "perfect_tests_by_category": {"math": 4, "science": 3, "general": 3},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 89.0,
      "total_questions_answered": 3400
    }
  },
  {
    "username": "TwistedLogic",
    "email": "twisted@example.com",
    "password": "Yoshi2003!!",
    "coins": 45000,
    "xp": 12750, // Level 32
    "level": 32,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cc3")], // Astral Revenant (Level 30)
    "xpBoost": 1.1,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cc3"), // Astral Revenant (Level 30)
    "nameColor": "#800080",
    "achievement_counters": {
      "total_tests_completed": 50,
      "perfect_tests_count": 10,
      "perfect_tests_by_category": {"language": 3, "history": 3, "science": 2},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 89.5,
      "total_questions_answered": 3000
    }
  },
  {
    "username": "33Mickey3",
    "email": "blossom@example.com",
    "password": "Yoshi2003!!",
    "coins": 40000,
    "xp": 11500, // Level 30
    "level": 30,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cc3")], // Astral Revenant (Level 30)
    "xpBoost": 1.1,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cc3"), // Astral Revenant (Level 30)
    "nameColor": "#b22222",
    "achievement_counters": {
      "total_tests_completed": 45,
      "perfect_tests_count": 9,
      "perfect_tests_by_category": {"math": 3, "general": 3, "language": 2},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 90.0,
      "total_questions_answered": 2700
    }
  },
  {
    "username": "Leon_Tang",
    "email": "savage@example.com",
    "password": "Yoshi2003!!",
    "coins": 35000,
    "xp": 10250, // Level 28
    "level": 28,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cc2")], // Shadow Nyx (Level 25)
    "xpBoost": 1.1,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cc2"), // Shadow Nyx (Level 25)
    "nameColor": "#ff0000",
    "achievement_counters": {
      "total_tests_completed": 40,
      "perfect_tests_count": 8,
      "perfect_tests_by_category": {"history": 3, "science": 2, "math": 2},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 90.5,
      "total_questions_answered": 2400
    }
  },
  {
    "username": "LinuxxDebb02",
    "email": "cosmic@example.com",
    "password": "Yoshi2003!!",
    "coins": 30000,
    "xp": 9000, // Level 26
    "level": 26,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cc2")], // Shadow Nyx (Level 25)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cc2"), // Shadow Nyx (Level 25)
    "nameColor": "#8a2be2",
    "achievement_counters": {
      "total_tests_completed": 35,
      "perfect_tests_count": 7,
      "perfect_tests_by_category": {"language": 2, "general": 2, "history": 2},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 91.0,
      "total_questions_answered": 2100
    }
  },
  {
    "username": "Daenerys-Targaryen❤️",
    "email": "moonlit@example.com",
    "password": "Yoshi2003!!",
    "coins": 25000,
    "xp": 7750, // Level 24
    "level": 24,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cce")], // Flarebound (Level 20)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cce"), // Flarebound (Level 20)
    "nameColor": "#483d8b",
    "achievement_counters": {
      "total_tests_completed": 30,
      "perfect_tests_count": 6,
      "perfect_tests_by_category": {"science": 2, "math": 2, "language": 1},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 91.5,
      "total_questions_answered": 1800
    }
  },
  {
    "username": "Void69",
    "email": "void@example.com",
    "password": "Yoshi2003!!",
    "coins": 20000,
    "xp": 6500, // Level 22
    "level": 22,
    "achievements": ["level_up_5", "mid_tier_grinder_25"],
    "subscriptionActive": true,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cce")], // Flarebound (Level 20)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cce"), // Flarebound (Level 20)
    "nameColor": "#000080",
    "achievement_counters": {
      "total_tests_completed": 25,
      "perfect_tests_count": 5,
      "perfect_tests_by_category": {"general": 2, "science": 1, "history": 1},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 92.0,
      "total_questions_answered": 1500
    }
  },
  {
    "username": "bench225",
    "email": "phantom@example.com",
    "password": "Yoshi2003!!",
    "coins": 18000,
    "xp": 5250, // Level 20
    "level": 20,
    "achievements": ["level_up_5"],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cce")], // Flarebound (Level 20)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cce"), // Flarebound (Level 20)
    "nameColor": "#696969",
    "achievement_counters": {
      "total_tests_completed": 20,
      "perfect_tests_count": 4,
      "perfect_tests_by_category": {"math": 1, "language": 1, "general": 1},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 92.5,
      "total_questions_answered": 1200
    }
  },
  {
    "username": "Cyberdawgs2001",
    "email": "cyber@example.com",
    "password": "Yoshi2003!!",
    "coins": 15000,
    "xp": 4500, // Level 18
    "level": 18,
    "achievements": ["level_up_5"],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cc8")], // Abyssal Empress (Level 15)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cc8"), // Abyssal Empress (Level 15)
    "nameColor": "#00bfff",
    "achievement_counters": {
      "total_tests_completed": 18,
      "perfect_tests_count": 3,
      "perfect_tests_by_category": {"science": 1, "general": 1, "history": 1},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 93.0,
      "total_questions_answered": 1100
    }
  },
  {
    "username": "comptiabro1999",
    "email": "arctic@example.com",
    "password": "Yoshi2003!!",
    "coins": 12000,
    "xp": 3750, // Level 16
    "level": 16,
    "achievements": ["level_up_5"],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cc8")], // Abyssal Empress (Level 15)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cc8"), // Abyssal Empress (Level 15)
    "nameColor": "#add8e6",
    "achievement_counters": {
      "total_tests_completed": 15,
      "perfect_tests_count": 2,
      "perfect_tests_by_category": {"language": 1, "math": 1},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 93.5,
      "total_questions_answered": 900
    }
  },
  {
    "username": "Blaze44",
    "email": "blazing@example.com",
    "password": "Yoshi2003!!",
    "coins": 10000,
    "xp": 3000, // Level 14
    "level": 14,
    "achievements": ["level_up_5"],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccf")], // Cosmos (Level 10)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccf"), // Cosmos (Level 10)
    "nameColor": "#ff4500",
    "achievement_counters": {
      "total_tests_completed": 12,
      "perfect_tests_count": 2,
      "perfect_tests_by_category": {"general": 1, "science": 1},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 94.0,
      "total_questions_answered": 750
    }
  },
  {
    "username": "gamerdude5000",
    "email": "shadow@example.com",
    "password": "Yoshi2003!!",
    "coins": 8000,
    "xp": 2250, // Level 12
    "level": 12,
    "achievements": ["level_up_5"],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccf")], // Cosmos (Level 10)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccf"), // Cosmos (Level 10)
    "nameColor": "#2f4f4f",
    "achievement_counters": {
      "total_tests_completed": 10,
      "perfect_tests_count": 1,
      "perfect_tests_by_category": {"history": 1},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 94.5,
      "total_questions_answered": 600
    }
  },
  {
    "username": "ThunderGod21",
    "email": "thunder21@example.com",
    "password": "Yoshi2003!!",
    "coins": 6000,
    "xp": 1500, // Level 10
    "level": 10,
    "achievements": ["level_up_5"],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccf")], // Cosmos (Level 10)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccf"), // Cosmos (Level 10)
    "nameColor": "#ffd700",
    "achievement_counters": {
      "total_tests_completed": 8,
      "perfect_tests_count": 1,
      "perfect_tests_by_category": {"math": 1},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 95.0,
      "total_questions_answered": 450
    }
  },
  {
    "username": "_Frosty_",
    "email": "frosty@example.com",
    "password": "Yoshi2003!!",
    "coins": 4000,
    "xp": 1000, // Level 8
    "level": 8,
    "achievements": ["level_up_5"],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd4")], // Blue Sentinel (Level 5)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd4"), // Blue Sentinel (Level 5)
    "nameColor": "#87ceeb",
    "achievement_counters": {
      "total_tests_completed": 6,
      "perfect_tests_count": 1,
      "perfect_tests_by_category": {"language": 1},
      "highest_score_ever": 100.0,
      "lowest_score_ever": 95.5,
      "total_questions_answered": 350
    }
  },
  {
    "username": "__secplusG__",
    "email": "rainbow@example.com",
    "password": "Yoshi2003!!",
    "coins": 2500,
    "xp": 750, // Level 6
    "level": 6,
    "achievements": ["level_up_5"],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd4")], // Blue Sentinel (Level 5)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd4"), // Blue Sentinel (Level 5)
    "nameColor": "#ff69b4",
    "achievement_counters": {
      "total_tests_completed": 5,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 95.0,
      "lowest_score_ever": 80.0,
      "total_questions_answered": 250
    }
  },
  {
    "username": "Connor-B",
    "email": "emerald@example.com",
    "password": "Yoshi2003!!",
    "coins": 1500,
    "xp": 500, // Level 5
    "level": 5,
    "achievements": ["level_up_5"],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544cd4")], // Blue Sentinel (Level 5)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544cd4"), // Blue Sentinel (Level 5)
    "nameColor": "#32cd32",
    "achievement_counters": {
      "total_tests_completed": 4,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 90.0,
      "lowest_score_ever": 75.0,
      "total_questions_answered": 200
    }
  },
  {
    "username": "G-777777",
    "email": "crimson@example.com",
    "password": "Yoshi2003!!",
    "coins": 1000,
    "xp": 250, // Level 4
    "level": 4,
    "achievements": [],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccb")], // Default Avatar (Level 1)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccb"), // Default Avatar (Level 1)
    "nameColor": "#dc143c",
    "achievement_counters": {
      "total_tests_completed": 3,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 85.0,
      "lowest_score_ever": 70.0,
      "total_questions_answered": 150
    }
  },
  {
    "username": "lmg333899999",
    "email": "phoenix@example.com",
    "password": "Yoshi2003!!",
    "coins": 500,
    "xp": 140, // Level 3
    "level": 3,
    "achievements": [],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccb")], // Default Avatar (Level 1)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccb"), // Default Avatar (Level 1)
    "nameColor": null,
    "achievement_counters": {
      "total_tests_completed": 2,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 80.0,
      "lowest_score_ever": 65.0,
      "total_questions_answered": 100
    }
  },
  {
    "username": "sexualwallabyies",
    "email": "moonlight@example.com",
    "password": "Yoshi2003!!",
    "coins": 450,
    "xp": 125, // Level 3 range
    "level": 3,
    "achievements": [],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccb")], // Default Avatar (Level 1)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccb"), // Default Avatar (Level 1)
    "nameColor": null,
    "achievement_counters": {
      "total_tests_completed": 2,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 75.0,
      "lowest_score_ever": 65.0,
      "total_questions_answered": 90
    }
  },
  {
    "username": "trump2028",
    "email": "ninja@example.com",
    "password": "Yoshi2003!!",
    "coins": 400,
    "xp": 110, // Level 3 range
    "level": 3,
    "achievements": [],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccb")], // Default Avatar (Level 1)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccb"), // Default Avatar (Level 1)
    "nameColor": null,
    "achievement_counters": {
      "total_tests_completed": 1,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 70.0,
      "lowest_score_ever": 60.0,
      "total_questions_answered": 80
    }
  },
  {
    "username": "PixelWarrior",
    "email": "pixel@example.com",
    "password": "Yoshi2003!!",
    "coins": 350,
    "xp": 90, // Level 2 range
    "level": 2,
    "achievements": [],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccb")], // Default Avatar (Level 1)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccb"), // Default Avatar (Level 1)
    "nameColor": null,
    "achievement_counters": {
      "total_tests_completed": 1,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 65.0,
      "lowest_score_ever": 55.0,
      "total_questions_answered": 70
    }
  },
  {
    "username": "00-OGbobbyjohnson-00",
    "email": "sneaky@example.com",
    "password": "Yoshi2003!!",
    "coins": 300,
    "xp": 80, // Level 2 range
    "level": 2,
    "achievements": [],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccb")], // Default Avatar (Level 1)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccb"), // Default Avatar (Level 1)
    "nameColor": null,
    "achievement_counters": {
      "total_tests_completed": 1,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 62.0,
      "lowest_score_ever": 50.0,
      "total_questions_answered": 60
    }
  },
  {
    "username": "CYSAPrep1990",
    "email": "rocket@example.com",
    "password": "Yoshi2003!!",
    "coins": 250,
    "xp": 70, // Level 2 range
    "level": 2,
    "achievements": [],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccb")], // Default Avatar (Level 1)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccb"), // Default Avatar (Level 1)
    "nameColor": null,
    "achievement_counters": {
      "total_tests_completed": 1,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 60.0,
      "lowest_score_ever": 45.0,
      "total_questions_answered": 50
    }
  },
  {
    "username": "Waffle",
    "email": "waffle@example.com",
    "password": "Yoshi2003!!",
    "coins": 200,
    "xp": 60, // Level 2 range
    "level": 2,
    "achievements": [],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccb")], // Default Avatar (Level 1)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccb"), // Default Avatar (Level 1)
    "nameColor": null,
    "achievement_counters": {
      "total_tests_completed": 1,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 55.0,
      "lowest_score_ever": 40.0,
      "total_questions_answered": 40
    }
  },
  {
    "username": "mw3",
    "email": "taco@example.com",
    "password": "Yoshi2003!!",
    "coins": 150,
    "xp": 35, // Level 1 range
    "level": 1,
    "achievements": [],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccb")], // Default Avatar (Level 1)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccb"), // Default Avatar (Level 1)
    "nameColor": null,
    "achievement_counters": {
      "total_tests_completed": 0,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 50.0,
      "lowest_score_ever": 35.0,
      "total_questions_answered": 30
    }
  },
  {
    "username": "ls-al-grep_",
    "email": "cosmic@example.com",
    "password": "Yoshi2003!!",
    "coins": 100,
    "xp": 25, // Level 1 range
    "level": 1,
    "achievements": [],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccb")], // Default Avatar (Level 1)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccb"), // Default Avatar (Level 1)
    "nameColor": null,
    "achievement_counters": {
      "total_tests_completed": 0,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 45.0,
      "lowest_score_ever": 30.0,
      "total_questions_answered": 20
    }
  },
  {
    "username": "Ryan-Billings__",
    "email": "laser@example.com",
    "password": "Yoshi2003!!",
    "coins": 50,
    "xp": 15, // Level 1 range
    "level": 1,
    "achievements": [],
    "subscriptionActive": false,
    "subscriptionPlan": null,
    "lastDailyClaim": new Date(),
    "purchasedItems": [ObjectId("67c8019eafc1b9f001544ccb")], // Default Avatar (Level 1)
    "xpBoost": 1.0,
    "currentAvatar": ObjectId("67c8019eafc1b9f001544ccb"), // Default Avatar (Level 1)
    "nameColor": null,
    "achievement_counters": {
      "total_tests_completed": 0,
      "perfect_tests_count": 0,
      "perfect_tests_by_category": {},
      "highest_score_ever": 40.0,
      "lowest_score_ever": 25.0,
      "total_questions_answered": 10
    }
  } 
])
