db.shopItems.insertMany([
  {
    type: "xpBoost",
    title: "XP Boost 10",
    description: "Increase your XP gain by 10%.",
    cost: 15000,   
    imageUrl: "/xp/xp10.png",
    effectValue: 1.10
  },
  {
    type: "xpBoost",
    title: "XP Boost 25",
    description: "Increase your XP gain by 25%.",
    cost: 40000,  // adjust 
    imageUrl: "/xp/xp25.png",
    effectValue: 1.25
  },
  {
    type: "xpBoost",
    title: "XP Boost 50",
    description: "Increase your XP gain by 50%.",
    cost: 75000,  // adjust 
    imageUrl: "/xp/xp50.png",
    effectValue: 1.50
  },
  {
    type: "xpBoost",
    title: "XP Boost 100",
    description: "Increase your XP gain by 100%.",
    cost: 100000, 
    imageUrl: "/xp/xp100.png",
    effectValue: 2.00
  },
  {
    type: "xpBoost",
    title: "XP Boost 200",
    description: "Increase your XP gain by 200%.",
    cost: 150000, 
    imageUrl: "/xp/xp200.png",
    effectValue: 3.00
  }
]);

