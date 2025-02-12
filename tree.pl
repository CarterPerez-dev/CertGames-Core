── AWS.md
├── INSTALL.md
├── README.md
├── apache
│   ├── Dockerfile.apache
│   ├── apache_server.conf
│   └── httpd.conf
├── backend
│   ├── API
│   │   └── AI.py
│   ├── Dockerfile.backend
│   ├── app.py
│   ├── helpers
│   │   ├── analogy_helper.py
│   │   ├── analogy_stream_helper.py
│   │   ├── async_tasks.py
│   │   ├── celery_app.py
│   │   ├── daily_newsletter_helper.py
│   │   ├── daily_newsletter_task.py
│   │   ├── email_helper.py
│   │   ├── grc_helper.py
│   │   ├── grc_stream_helper.py
│   │   ├── log_generator.py
│   │   ├── log_helper.py
│   │   ├── pbq_ai_helper.py
│   │   ├── scenario_helper.py
│   │   ├── status_helper.py
│   │   └── xploitcraft_helper.py
│   ├── models
│   │   ├── log_history.py
│   │   ├── log_models.py
│   │   ├── newsletter_content.py
│   │   ├── test.py
│   │   └── user_subscription.py
│   ├── mongodb
│   │   └── database.py
│   ├── requirements.txt
│   ├── routes
│   │   ├── admin_newsletter_routes.py
│   │   ├── analogy_routes.py
│   │   ├── celery_routes.py
│   │   ├── daily_brief_routes.py
│   │   ├── grc_routes.py
│   │   ├── log_routes.py
│   │   ├── pbq_routes.py
│   │   ├── scenario_routes.py
│   │   ├── status_routes.py
│   │   ├── subscribe_routes.py
│   │   ├── test_routes.py
│   │   ├── unsubscribe_routes.py
│   │   └── xploit_routes.py
│   └── update_newsletter.py
├── bandit.yaml
├── dark-red-dotted-lines-abstract-tech-background-vector.jpg
├── database
│   └── models.py
├── docker-compose.yml
├── env_EXAMPLE
├── frontend
│   └── my-react-app
│       ├── Dockerfile.audit
│       ├── Dockerfile.dev
│       ├── Dockerfile.frontend
│       ├── eslint.config.mjs
│       ├── package.json
│       ├── public
│       │   ├── appLogo.png
│       │   ├── avatars
│       │   │   ├── avatar1.png
│       │   │   ├── avatar10.png
│       │   │   ├── avatar1000.png
│       │   │   ├── avatar110.png
│       │   │   ├── avatar120.png
│       │   │   ├── avatar135.png
│       │   │   ├── avatar15.png
│       │   │   ├── avatar150.png
│       │   │   ├── avatar175.png
│       │   │   ├── avatar20.png
│       │   │   ├── avatar2000.png
│       │   │   ├── avatar25.png
│       │   │   ├── avatar250.png
│       │   │   ├── avatar30.png
│       │   │   ├── avatar300.png
│       │   │   ├── avatar40.png
│       │   │   ├── avatar5.png
│       │   │   ├── avatar50.png
│       │   │   ├── avatar60.png
│       │   │   ├── avatar70.png
│       │   │   ├── avatar80.png
│       │   │   ├── avatar90.png
│       │   │   └── avatars_mongo.js
│       │   ├── favicon.ico
│       │   ├── index.html
│       │   ├── logo2.png
│       │   ├── manifest.json
│       │   ├── robots.txt
│       │   └── xp
│       │       ├── xp10.png
│       │       ├── xp100.png
│       │       ├── xp200.png
│       │       ├── xp25.png
│       │       ├── xp50.png
│       │       └── xp_mongo.js
│       └── src
│           ├── App.js
│           ├── App.test.js
│           ├── components
│           │   ├── ConfettiAnimation.js
│           │   ├── EasterEgg
│           │   │   ├── A.png
│           │   │   ├── CASP.png
│           │   │   ├── CarterPerez.pdf
│           │   │   ├── Portfolio.css
│           │   │   ├── Portfolio.js
│           │   │   ├── Portfolio_notegg.css
│           │   │   ├── Portfolio_notegg.js
│           │   │   ├── cysa.png
│           │   │   ├── egg.txt
│           │   │   ├── me.png
│           │   │   ├── network.png
│           │   │   ├── pcep.png
│           │   │   ├── pentest.png
│           │   │   ├── project1.jpg
│           │   │   ├── project2.jpg
│           │   │   └── sec.png
│           │   ├── ProtectedRoute.js
│           │   ├── Sidebar
│           │   │   ├── Sidebar.css
│           │   │   ├── Sidebar.js
│           │   │   └── sidebarlogo.png
│           │   ├── pages
│           │   │   ├── AboutPage
│           │   │   │   ├── About.css
│           │   │   │   ├── About.js
│           │   │   │   └── AboutBackground.jpg
│           │   │   ├── AdminInterface
│           │   │   │   ├── AdminInterface.css
│           │   │   │   ├── AdminInterface.js
│           │   │   │   ├── AdminMonitorStatus.css
│           │   │   │   ├── AdminMonitorStatus.js
│           │   │   │   ├── AdminNewsletter.css
│           │   │   │   ├── AdminNewsletter.js
│           │   │   │   ├── AdminSubscribers.css
│           │   │   │   ├── AdminSubscribers.js
│           │   │   │   ├── AdminTriggerTasks.css
│           │   │   │   ├── AdminTriggerTasks.js
│           │   │   │   └── adminbackground.jpg
│           │   │   ├── AnalogyPage
│           │   │   │   ├── AnalogyHub.css
│           │   │   │   ├── AnalogyHub.js
│           │   │   │   ├── backround1.jpg
│           │   │   │   └── loading2.png
│           │   │   ├── DailyPage
│           │   │   │   ├── DailyCyberBrief.css
│           │   │   │   ├── DailyCyberBrief.js
│           │   │   │   └── backround7.jpg
│           │   │   ├── DonatePage
│           │   │   │   ├── Donate.css
│           │   │   │   ├── Donate.js
│           │   │   │   └── backround3.jpg
│           │   │   ├── GRCpage
│           │   │   │   ├── GRC.css
│           │   │   │   ├── GRC.js
│           │   │   │   └── GRCbackground.jpg
│           │   │   ├── Info
│           │   │   │   ├── InfoPage.css
│           │   │   │   └── InfoPage.js
│           │   │   ├── LogPage
│           │   │   │   ├── Log.js
│           │   │   │   ├── log.css
│           │   │   │   └── logbackground.jpg
│           │   │   ├── PBQpage
│           │   │   │   ├── PBQWizard.css
│           │   │   │   └── PBQWizard.js
│           │   │   ├── ResourcesPage
│           │   │   │   ├── Resourcebackground.jpg
│           │   │   │   ├── Resources.css
│           │   │   │   └── Resources.js
│           │   │   ├── ScenarioPage
│           │   │   │   ├── ScenarioSphere.css
│           │   │   │   ├── ScenarioSphere.js
│           │   │   │   ├── attacks.js
│           │   │   │   └── backround5.jpg
│           │   │   ├── XploitcraftPage
│           │   │   │   ├── App.css
│           │   │   │   ├── Xploitcraft.js
│           │   │   │   ├── backround2.jpg
│           │   │   │   ├── global.css
│           │   │   │   ├── loading3.png
│           │   │   │   └── logo5.png
│           │   │   ├── aplus
│           │   │   │   ├── APlusTestList.js
│           │   │   │   └── APlusTestPage.js
│           │   │   ├── aplus2
│           │   │   │   ├── APlusCore2TestPage.js
│           │   │   │   └── AplusCore2TestList.js
│           │   │   ├── auth
│           │   │   │   ├── ForgotPassword.css
│           │   │   │   ├── ForgotPassword.js
│           │   │   │   ├── Login.css
│           │   │   │   ├── Login.js
│           │   │   │   ├── Register.css
│           │   │   │   └── Register.js
│           │   │   ├── awscloud
│           │   │   │   ├── AWSCloudTestList.js
│           │   │   │   └── AWSCloudTestPage.js
│           │   │   ├── casp
│           │   │   │   ├── CaspPlusTestList.js
│           │   │   │   └── CaspPlusTestPage.js
│           │   │   ├── cissp
│           │   │   │   ├── CisspTestList.js
│           │   │   │   └── CisspTestPage.js
│           │   │   ├── cloudplus
│           │   │   │   ├── CloudPlusTestList.js
│           │   │   │   └── CloudPlusTestPage.js
│           │   │   ├── cysa
│           │   │   │   ├── CySAPlusTestList.js
│           │   │   │   └── CySAPlusTestPage.js
│           │   │   ├── dataplus
│           │   │   │   ├── DataPlusTestList.js
│           │   │   │   └── DataPlusTestPage.js
│           │   │   ├── linuxplus
│           │   │   │   ├── LinuxPlusTestList.js
│           │   │   │   ├── LinuxPlusTestPage.js
│           │   │   │   ├── linuxPlusTestList.js
│           │   │   │   └── linuxPlusTestPage.js
│           │   │   ├── nplus
│           │   │   │   ├── NPlusTestList.js
│           │   │   │   └── NetworkPlusTestPage.js
│           │   │   ├── penplus
│           │   │   │   ├── PenPlusTestList.js
│           │   │   │   └── PenPlusTestPage.js
│           │   │   ├── secplus
│           │   │   │   ├── SecurityPlusTestList.js
│           │   │   │   └── SecurityPlusTestPage.js
│           │   │   ├── serverplus
│           │   │   │   ├── ServerPlusTestList.js
│           │   │   │   └── ServerPlusTestPage.js
│           │   │   └── store
│           │   │       ├── AchievementPage.css
│           │   │       ├── AchievementPage.js
│           │   │       ├── AchievementToast.css
│           │   │       ├── AchievementToast.js
│           │   │       ├── LeaderboardPage.css
│           │   │       ├── LeaderboardPage.js
│           │   │       ├── ShopPage.css
│           │   │       ├── ShopPage.js
│           │   │       ├── StreakCalendar.js
│           │   │       ├── UserProfile.css
│           │   │       ├── UserProfile.js
│           │   │       ├── ach.png
│           │   │       ├── achbgs1.jpg
│           │   │       ├── achievementsSlice.js
│           │   │       ├── leader.jpg
│           │   │       ├── shopSlice.js
│           │   │       ├── shopbg.png
│           │   │       ├── shopbg1.jpg
│           │   │       ├── store.js
│           │   │       ├── user.jpg
│           │   │       └── userSlice.js
│           │   └── test.css
│           ├── global.css
│           ├── index.css
│           ├── index.js
│           ├── reportWebVitals.js
│           └── setupTests.js
├── hacking-background-bryw246r4lx5pyue.jpg
├── nginx
│   ├── nginx.conf
│   └── sites-enabled
│       └── reverse_proxy.conf
├── redis
│   └── redis.conf
├── requirements.txt
└── xploitcraft.pem

49 directories, 227 files
