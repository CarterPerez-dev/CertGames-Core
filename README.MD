```ruby
.
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
│   │   ├── analogy_stream_helper.py
│   │   ├── async_tasks.py
│   │   ├── celery_app.py
│   │   ├── grc_stream_helper.py
│   │   ├── rate_limiter.py
│   │   ├── scenario_helper.py
│   │   └── xploitcraft_helper.py
│   ├── models
│   │   ├── newsletter.py
│   │   ├── password_reset.py
│   │   └── test.py
│   ├── mongodb
│   │   └── database.py
│   ├── repomix-output.txt
│   ├── requirements.txt
│   ├── routes
│   │   ├── admin_newsletter_routes.py
│   │   ├── analogy_routes.py
│   │   ├── contact_form.py
│   │   ├── cracked_admin.py
│   │   ├── grc_routes.py
│   │   ├── newsletter_routes.py
│   │   ├── oauth_routes.py
│   │   ├── password_reset_routes.py
│   │   ├── scenario_routes.py
│   │   ├── support_routes.py
│   │   ├── test_routes.py
│   │   └── xploit_routes.py
│   └── utils
│       └── email_sender.py
├── bandit.yaml
├── docker-compose.yml
├── frontend
│   └── my-react-app
│       ├── Dockerfile.audit
│       ├── Dockerfile.dev
│       ├── Dockerfile.frontend
│       ├── eslint.config.mjs
│       ├── package-lock.json
│       ├── package.json
│       ├── public
│       │   ├── appLogo.png
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
│       ├── repomix-output.txt
│       └── src
│           ├── App.js
│           ├── App.test.js
│           ├── components
│           │   ├── ConfettiAnimation.js
│           │   ├── Footer.js
│           │   ├── GlobalTestPage.js
│           │   ├── ProtectedRoute.js
│           │   ├── Sidebar
│           │   │   ├── Sidebar.css
│           │   │   ├── Sidebar.js
│           │   │   └── sidebarlogo.png
│           │   ├── colorMapping.js
│           │   ├── cracked
│           │   │   ├── CrackedAdminDashboard.css
│           │   │   ├── CrackedAdminDashboard.js
│           │   │   ├── CrackedAdminLogin.css
│           │   │   └── CrackedAdminLoginPage.js
│           │   ├── footer.css
│           │   ├── iconMapping.js
│           │   ├── pages
│           │   │   ├── AnalogyPage
│           │   │   │   ├── AnalogyHub.css
│           │   │   │   ├── AnalogyHub.js
│           │   │   │   ├── backround1.jpg
│           │   │   │   └── loading2.png
│           │   │   ├── DailyPage
│           │   │   │   ├── DailyCyberBrief.css
│           │   │   │   ├── DailyCyberBrief.js
│           │   │   │   └── backround7.jpg
│           │   │   ├── GRCpage
│           │   │   │   ├── GRC.css
│           │   │   │   ├── GRC.js
│           │   │   │   └── GRCbackground.jpg
│           │   │   ├── Info
│           │   │   │   ├── ContactPage.css
│           │   │   │   ├── ContactPage.js
│           │   │   │   ├── DemosPage.css
│           │   │   │   ├── DemosPage.js
│           │   │   │   ├── ExamsPage.css
│           │   │   │   ├── ExamsPage.js
│           │   │   │   ├── InfoNavbar.css
│           │   │   │   ├── InfoNavbar.js
│           │   │   │   ├── InfoPage.css
│           │   │   │   ├── InfoPage.js
│           │   │   │   ├── PublicLeaderboardPage.css
│           │   │   │   ├── PublicLeaderboardPage.js
│           │   │   │   └── navbarScrollUtils.js
│           │   │   ├── LegalPages.css
│           │   │   ├── PrivacyPolicy.js
│           │   │   ├── ResourcesPage
│           │   │   │   ├── Resourcebackground.jpg
│           │   │   │   ├── Resources.css
│           │   │   │   └── Resources.js
│           │   │   ├── ScenarioPage
│           │   │   │   ├── ScenarioSphere.css
│           │   │   │   ├── ScenarioSphere.js
│           │   │   │   ├── attacks.js
│           │   │   │   └── backround5.jpg
│           │   │   ├── TermsOfService.js
│           │   │   ├── XploitcraftPage
│           │   │   │   ├── App.css
│           │   │   │   ├── Xploitcraft.js
│           │   │   │   ├── backround2.jpg
│           │   │   │   ├── loading3.png
│           │   │   │   └── logo5.png
│           │   │   ├── aplus
│           │   │   │   ├── APlusTestList.js
│           │   │   │   └── APlusTestPage.js
│           │   │   ├── aplus2
│           │   │   │   ├── APlusCore2TestPage.js
│           │   │   │   └── AplusCore2TestList.js
│           │   │   ├── auth
│           │   │   │   ├── AuthToast.css
│           │   │   │   ├── CreateUsernameForm.css
│           │   │   │   ├── CreateUsernameForm.js
│           │   │   │   ├── ErrorDisplay.css
│           │   │   │   ├── ErrorDisplay.js
│           │   │   │   ├── ForgotPassword.css
│           │   │   │   ├── ForgotPassword.js
│           │   │   │   ├── Login.css
│           │   │   │   ├── Login.js
│           │   │   │   ├── OAuthSuccess.js
│           │   │   │   ├── PasswordRequirements.css
│           │   │   │   ├── PasswordRequirements.js
│           │   │   │   ├── Register.css
│           │   │   │   ├── Register.js
│           │   │   │   ├── ResetPassword.css
│           │   │   │   └── ResetPassword.js
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
│           │   │   │   └── LinuxPlusTestPage.js
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
│           │   │       ├── DailyStation.css
│           │   │       ├── DailyStationPage.js
│           │   │       ├── LeaderboardPage.css
│           │   │       ├── LeaderboardPage.js
│           │   │       ├── ShopPage.css
│           │   │       ├── ShopPage.js
│           │   │       ├── StreakCalendar.js
│           │   │       ├── SupportAskAnythingPage.css
│           │   │       ├── SupportAskAnythingPage.js
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
├── info.md
├── nginx
│   ├── nginx.conf
│   └── sites-enabled
│       └── reverse_proxy.conf
├── redis
│   └── redis.conf
├── repomix-output.txt

43 directories, 187 files
```
