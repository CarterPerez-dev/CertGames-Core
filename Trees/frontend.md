```ruby
frontend
└── my-react-app
    ├── Dockerfile.audit
    ├── Dockerfile.dev
    ├── Dockerfile.frontend
    ├── craco.config.js
    ├── eslint.config.mjs
    ├── package-lock.json
    ├── package.json
    ├── public
    │   ├── appLogo.png
    │   ├── favicon.ico
    │   ├── index.html
    │   ├── logo2.png
    │   ├── manifest.json
    │   ├── robots.txt
    │   └── xp
    │       ├── xp10.png
    │       ├── xp100.png
    │       ├── xp200.png
    │       ├── xp25.png
    │       ├── xp50.png
    │       └── xp_mongo.js
    └── src
        ├── App.js
        ├── App.test.js
        ├── components
        │   ├── ConfettiAnimation.js
        │   ├── GlobalTestPage.js
        │   ├── ProtectedRoute.js
        │   ├── Sidebar
        │   │   ├── Sidebar.css
        │   │   ├── Sidebar.js
        │   │   └── sidebarlogo.png
        │   ├── colorMapping.js
        │   ├── iconMapping.js
        │   ├── pages
        │   │   ├── AnalogyPage
        │   │   │   ├── AnalogyHub.css
        │   │   │   ├── AnalogyHub.js
        │   │   │   ├── backround1.jpg
        │   │   │   └── loading2.png
        │   │   ├── DailyPage
        │   │   │   ├── DailyCyberBrief.css
        │   │   │   ├── DailyCyberBrief.js
        │   │   │   └── backround7.jpg
        │   │   ├── GRCpage
        │   │   │   ├── GRC.css
        │   │   │   ├── GRC.js
        │   │   │   └── GRCbackground.jpg
        │   │   ├── Info
        │   │   │   ├── InfoPage.css
        │   │   │   └── InfoPage.js
        │   │   ├── ResourcesPage
        │   │   │   ├── Resourcebackground.jpg
        │   │   │   ├── Resources.css
        │   │   │   └── Resources.js
        │   │   ├── ScenarioPage
        │   │   │   ├── ScenarioSphere.css
        │   │   │   ├── ScenarioSphere.js
        │   │   │   ├── attacks.js
        │   │   │   └── backround5.jpg
        │   │   ├── XploitcraftPage
        │   │   │   ├── App.css
        │   │   │   ├── Xploitcraft.js
        │   │   │   ├── backround2.jpg
        │   │   │   ├── global.css
        │   │   │   ├── loading3.png
        │   │   │   └── logo5.png
        │   │   ├── aplus
        │   │   │   ├── APlusTestList.js
        │   │   │   └── APlusTestPage.js
        │   │   ├── aplus2
        │   │   │   ├── APlusCore2TestPage.js
        │   │   │   └── AplusCore2TestList.js
        │   │   ├── auth
        │   │   │   ├── AuthToast.css
        │   │   │   ├── ErrorDisplay.css
        │   │   │   ├── ErrorDisplay.js
        │   │   │   ├── ForgotPassword.css
        │   │   │   ├── ForgotPassword.js
        │   │   │   ├── Login.css
        │   │   │   ├── Login.js
        │   │   │   ├── PasswordRequirements.css
        │   │   │   ├── PasswordRequirements.js
        │   │   │   ├── Register.css
        │   │   │   ├── Register.js
        │   │   │   └── auth.css
        │   │   ├── awscloud
        │   │   │   ├── AWSCloudTestList.js
        │   │   │   └── AWSCloudTestPage.js
        │   │   ├── casp
        │   │   │   ├── CaspPlusTestList.js
        │   │   │   └── CaspPlusTestPage.js
        │   │   ├── cissp
        │   │   │   ├── CisspTestList.js
        │   │   │   └── CisspTestPage.js
        │   │   ├── cloudplus
        │   │   │   ├── CloudPlusTestList.js
        │   │   │   └── CloudPlusTestPage.js
        │   │   ├── cysa
        │   │   │   ├── CySAPlusTestList.js
        │   │   │   └── CySAPlusTestPage.js
        │   │   ├── dataplus
        │   │   │   ├── DataPlusTestList.js
        │   │   │   └── DataPlusTestPage.js
        │   │   ├── linuxplus
        │   │   │   ├── LinuxPlusTestList.js
        │   │   │   └── LinuxPlusTestPage.js
        │   │   ├── nplus
        │   │   │   ├── NPlusTestList.js
        │   │   │   └── NetworkPlusTestPage.js
        │   │   ├── penplus
        │   │   │   ├── PenPlusTestList.js
        │   │   │   └── PenPlusTestPage.js
        │   │   ├── secplus
        │   │   │   ├── SecurityPlusTestList.js
        │   │   │   └── SecurityPlusTestPage.js
        │   │   ├── serverplus
        │   │   │   ├── ServerPlusTestList.js
        │   │   │   └── ServerPlusTestPage.js
        │   │   └── store
        │   │       ├── AchievementPage.css
        │   │       ├── AchievementPage.js
        │   │       ├── AchievementToast.css
        │   │       ├── AchievementToast.js
        │   │       ├── DailyStation.css
        │   │       ├── DailyStationPage.js
        │   │       ├── LeaderboardPage.css
        │   │       ├── LeaderboardPage.js
        │   │       ├── ShopPage.css
        │   │       ├── ShopPage.js
        │   │       ├── StreakCalendar.js
        │   │       ├── UserProfile.css
        │   │       ├── UserProfile.js
        │   │       ├── ach.png
        │   │       ├── achbgs1.jpg
        │   │       ├── achievementsSlice.js
        │   │       ├── leader.jpg
        │   │       ├── shopSlice.js
        │   │       ├── shopbg.png
        │   │       ├── shopbg1.jpg
        │   │       ├── store.js
        │   │       ├── user.jpg
        │   │       └── userSlice.js
        │   └── test.css
        ├── global.css
        ├── index.css
        ├── index.js
        ├── reportWebVitals.js
        └── setupTests.js

30 directories, 121 files
```
