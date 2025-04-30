# ROUTES

## Main Routes
1. `/test/user/<user_id>` (GET) - Retrieves a user's profile information by ID
2. `/test/user` (POST) - Registers a new user account
3. `/test/login` (POST) - Handles user authentication and login
4. `/token/refresh` (POST) - Refreshes JWT access token using a valid refresh token
5. `/test/user/<user_id>/add-xp` (POST) - Adds experience points to a user
6. `/test/user/<user_id>/add-coins` (POST) - Adds coins to a user's account
7. `/test/user/<user_id>/usage-limits` (GET) - Gets current usage limits for free tier users
8. `/test/user/<user_id>/decrement-questions` (POST) - Decrements practice question counter for free users
9. `/test/shop` (GET) - Retrieves available items from the shop
10. `/test/shop/purchase/<item_id>` (POST) - Processes an item purchase
11. `/test/shop/equip` (POST) - Equips an avatar item for a user
12. `/test/tests/<test_id>` (GET) - Fetches a test by its ID
13. `/test/tests/<category>/<test_id>` (GET) - Fetches a test by category and ID
14. `/test/attempts/<user_id>/<test_id>` (GET) - Gets a user's test attempt
15. `/test/attempts/<user_id>/<test_id>` (POST) - Updates a user's test attempt
16. `/test/attempts/<user_id>/<test_id>/finish` (POST) - Completes a test attempt
17. `/test/attempts/<user_id>/list` (GET) - Lists all test attempts for a user
18. `/test/user/<user_id>/submit-answer` (POST) - Submits an answer and awards XP/coins
19. `/test/achievements` (GET) - Retrieves all available achievements
20. `/test/leaderboard` (GET) - Gets the user leaderboard with pagination
21. `/test/user/change-username` (POST) - Updates a user's username
22. `/test/user/change-email` (POST) - Updates a user's email address
23. `/test/user/change-password` (POST) - Updates a user's password
24. `/test/subscription/cancel` (POST) - Placeholder for subscription cancellation
25. `/test/attempts/<user_id>/<test_id>/answer` (POST) - Updates a single answer in a test
26. `/test/attempts/<user_id>/<test_id>/position` (POST) - Updates current question position
27. `/test/user/<user_id>/daily-bonus` (POST) - Claims daily login bonus
28. `/test/daily-question` (GET) - Gets the current daily question
29. `/test/daily-question/answer` (POST) - Submits answer for daily question
30. `/test/public-leaderboard/board` (GET) - Gets public leaderboard with longer cache duration
31. `/test/user/<user_id>/delete` (DELETE) - Deletes a user account and related data
32. `/logout` (POST) - Invalidate JWT tokens on logout

## OAuth Routes 
33. `/oauth/login/google` (GET) - Initiates the Google OAuth login flow, redirecting the user to Google's authentication page
34. `/oauth/auth/google` (GET) - Handles the callback from Google after user authentication, exchanges code for token, fetches user info, creates/updates user, and redirects to frontend
35. `/oauth/login/apple` (GET) - Initiates the Sign in with Apple OAuth flow, redirecting the user to Apple's authentication page
36. `/oauth/auth/apple` (POST) - Handles the callback from Apple after user authentication (via form post), exchanges code/token, fetches user info, creates/updates user, and redirects to frontend (GET on this route redirects to /oauth/login/apple)
37. `/oauth/login/apple/mobile` (POST) - Handles Sign in with Apple specifically for mobile clients, using the identity token provided by the app
38. `/oauth/verify-google-token` (POST) - Verifies a Google access token provided directly (e.g., from a mobile app's Google Sign-In library)
39. `/oauth/admin-login/google` (GET) - Initiates a Google OAuth login flow specifically for the admin dashboard, prompting for account selection
40. `/oauth/admin-auth/google` (GET) - Handles the callback for admin Google login, verifies if the email is authorized, and sets admin session if successful

## Game Routes
### Phishing Phrenzy
41. `/phishing/examples` (GET) - Retrieves a set of phishing and legitimate examples for the Phishing Phrenzy game
42. `/phishing/submit-score` (POST) - Submits a Phishing Phrenzy game score and awards XP/coins based on performance
43. `/phishing/leaderboard` (GET) - Gets the top scores for the Phishing Phrenzy game

### Cipher Challenge
44. `/cipher/challenges` (GET) - Gets all cipher challenges with user progress information
45. `/cipher/submit` (POST) - Submits a solution for a cipher challenge
46. `/cipher/unlock-hint` (POST) - Unlocks a hint for a cipher challenge by spending coins

### Threat Hunter
47. `/threat-hunter/scenarios` (GET) - Gets all log analysis scenarios with metadata
48. `/threat-hunter/start-scenario` (POST) - Starts a log analysis scenario and gets the full scenario data including logs
49. `/threat-hunter/submit-analysis` (POST) - Submits a log analysis for scoring and evaluation

### Incident Response
50. `/incident/scenarios` (GET) - Gets all incident response scenarios
51. `/incident/start` (POST) - Starts a scenario and returns its details
52. `/incident/action` (POST) - Processes a user action in a scenario stage
53. `/incident/complete` (POST) - Completes a scenario and calculates results
54. `/incident/bookmark` (POST) - Toggles bookmark status for a scenario
55. `/incident/bookmarks/<user_id>` (GET) - Gets bookmarked scenarios for a user

## AI Tool Routes 
56. `/scenario/stream_scenario` (POST) - Generates a security scenario based on input parameters (industry, attack type, etc.) and streams the output text
57. `/scenario/stream_questions` (POST) - Generates interactive questions based on a provided scenario text and streams the output JSON
58. `/grc/generate_question` (POST) - Generates a GRC (Governance, Risk, Compliance) question based on category and difficulty (uses Celery, non-streaming)
59. `/grc/stream_question` (POST) - Generates a GRC question based on category and difficulty and streams the output JSON chunk by chunk
60. `/xploit/generate_payload` (POST) - Generates a conceptual exploit payload based on a given vulnerability and optional evasion technique, with streaming support
61. `/analogy/generate_analogy` (POST) - Generates an analogy comparing cybersecurity concepts based on type and input concepts (uses Celery, non-streaming, likely legacy)
62. `/analogy/stream_analogy` (POST) - Generates an analogy comparing cybersecurity concepts and streams the output text chunk by chunk

## Subscription Routes 
63. `/subscription/create-checkout-session` (POST) - Creates a Stripe Checkout session for starting a new subscription purchase
64. `/subscription/config` (GET) - Returns public Stripe configuration details (publishable key, price ID)
65. `/subscription/subscription-status` (GET) - Checks and returns the current subscription status (active, inactive, platform) for a given user
66. `/subscription/session-status` (GET) - Checks the status (e.g., complete, open) of a specific Stripe Checkout session
67. `/subscription/webhook` (POST) - Listens for and processes incoming webhook events from Stripe (e.g., payment success, subscription updates, cancellations)
68. `/subscription/cancel-subscription` (POST) - Allows an authenticated user to request cancellation of their Stripe subscription (sets cancel_at_period_end)
69. `/subscription/check-flow` (GET) - Checks if the current user session is part of an OAuth sign-up flow that includes subscription
70. `/subscription/clear-temp-data` (POST) - Clears temporary registration data stored in the session/database during the checkout process for new users
71. `/subscription/verify-receipt` (POST) - Verifies an Apple App Store receipt (usually from a mobile app) to validate and update the user's subscription status
72. `/subscription/apple-subscription` (POST) - Processes a new Apple subscription activated via the mobile app, using the provided receipt data
73. `/subscription/restore-purchases` (POST) - Handles requests from the mobile app to restore Apple App Store purchases using receipt data
74. `/subscription/apple-webhook` (POST) - Listens for and processes incoming Server-to-Server notifications from Apple about subscription events (renewals, expirations, etc.)
75. `/subscription/apple-webhook` (GET) - A simple endpoint for Apple to verify the webhook URL during setup

## Support Routes 
76. `/support/my-chat` (GET) - Retrieves a list of all support chat threads initiated by the currently authenticated user
77. `/support/my-chat` (POST) - Creates a new support chat thread for the authenticated user
78. `/support/my-chat/{thread_id}` (GET) - Retrieves the messages and details for a specific support thread belonging to the authenticated user
79. `/support/my-chat/{thread_id}` (POST) - Allows the authenticated user to post a message to one of their specific support threads
80. `/support/my-chat/{thread_id}/close` (POST) - Allows the authenticated user to mark their own support thread as closed

## Security Routes
### Honeypot Routes
81. `/honeypot/analytics` (GET) - Returns analytics about honeypot activity
82. `/honeypot/log-interaction` (POST) - Endpoint for logging client-side interactions via AJAX
83. `/honeypot/detailed-stats` (GET) - Returns detailed statistics about honeypot activity
84. `/honeypot/interactions` (GET) - View honeypot interactions with pagination
85. `/honeypot/interactions/<interaction_id>` (GET) - Get detailed information about a specific honeypot interaction
86. `/honeypot/combined-analytics` (GET) - Returns combined analytics from both honeypot collections

### C2 (Command & Control) Routes
87. `/api/analytics/collect` (POST) - C2 primary endpoint disguised as analytics collection
88. `/api/metrics/push` (POST) - C2 fallback endpoint disguised as metrics collection
89. `/api/payload/store` (POST) - Endpoint to receive harvested credentials
90. `/api/scenario/fetch` (POST) - Endpoint for implants to fetch commands
91. `/api/scenario/submit` (POST) - Endpoint for implants to submit command results
92. `/api/c2/sessions` (GET) - Lists active C2 sessions
93. `/api/c2/sessions/<session_id>` (GET) - Gets detailed information about a specific session
94. `/api/c2/sessions/<session_id>/credentials` (GET) - Gets all credentials for a specific session
95. `/api/c2/sessions/<session_id>/command` (POST) - Queues a new command for a specific session
96. `/api/c2/commands/<command_id>/results` (GET) - Gets results for a specific command
97. `/api/metrics/pixel.gif` (GET) - Handle tracking pixel requests for beacon data
98. `/api/c2/credentials` (GET) - Gets all harvested credentials
99. `/api/c2/dashboard` (GET) - Gets summary statistics for the C2 dashboard

## Cracked Admin Routes 
100. `/cracked/request-logs/nginx` (GET) - (Admin) Retrieves recent Nginx access logs
101. `/cracked/request-logs` (GET) - (Admin) Retrieves recent API request logs recorded by the application
102. `/cracked/login` (POST) - (Admin) Authenticates an admin user using the admin password
103. `/cracked/logout` (POST) - (Admin) Logs out the currently authenticated admin user
104. `/cracked/dashboard` (GET) - (Admin) Retrieves aggregated statistics and metrics for the admin dashboard overview
105. `/cracked/users` (GET) - (Admin) Lists registered users with filtering, pagination, and search capabilities
106. `/cracked/users/{user_id}/toggle-subscription` (POST) - (Admin) Manually activates or deactivates a user's subscription status (Requires supervisor role)
107. `/cracked/users/{user_id}` (PUT) - (Admin) Updates specific editable fields (like username, coins, XP) for a given user
108. `/cracked/users/{user_id}` (DELETE) - (Admin) Permanently deletes a user account (Requires supervisor role)
109. `/cracked/users/{user_id}/reset-password` (POST) - (Admin) Resets a user's password and provides the new temporary password (Requires supervisor role)
110. `/cracked/supportThreads` (GET) - (Admin) Lists all support threads across all users for admin review
111. `/cracked/supportThreads/{thread_id}` (GET) - (Admin) Retrieves the details and messages of a specific support thread (regardless of user)
112. `/cracked/supportThreads/{thread_id}/reply` (POST) - (Admin) Allows an admin to post a reply to a specific support thread
113. `/cracked/supportThreads/{thread_id}/close` (POST) - (Admin) Allows an admin to mark a support thread as closed
114. `/cracked/supportThreads/clear-closed` (DELETE) - (Admin) Deletes all support threads that are currently marked as closed (Requires supervisor role)
115. `/cracked/supportThreads/createFromAdmin` (POST) - (Admin) Allows an admin to initiate a new support thread directed at a specific user
116. `/cracked/tests` (GET) - (Admin) Lists all the tests/quizzes available in the system
117. `/cracked/tests` (POST) - (Admin) Creates a new test/quiz definition (Requires supervisor role)
118. `/cracked/tests/{test_id}` (PUT) - (Admin) Updates the details or questions of an existing test/quiz (Requires supervisor role)
119. `/cracked/tests/{test_id}` (DELETE) - (Admin) Deletes a test/quiz definition (Requires supervisor role)
120. `/cracked/daily` (GET) - (Admin) Lists all the daily PBQ (Performance-Based Questions) available
121. `/cracked/daily` (POST) - (Admin) Creates a new daily PBQ question (Requires supervisor role)
122. `/cracked/daily/{obj_id}` (PUT) - (Admin) Updates an existing daily PBQ question (Requires supervisor role)
123. `/cracked/daily/{obj_id}` (DELETE) - (Admin) Deletes a daily PBQ question (Requires supervisor role)
124. `/cracked/performance` (GET) - (Admin) Retrieves application performance metrics (like request times, DB query times) and historical data
125. `/cracked/web-vitals` (GET) - (Admin) Retrieves collected Web Vitals metrics (LCP, FCP, CLS, etc.) reported by the frontend
126. `/cracked/recent-errors` (GET) - (Admin) Retrieves a list of recent errors (HTTP status >= 400) recorded by the performance sampler
127. `/cracked/report-web-vitals` (POST) - Endpoint for the frontend application to send Web Vitals performance data to the backend (Note: Located in admin file, potentially for internal reporting)
128. `/cracked/activity-logs` (GET) - (Admin) Retrieves recent audit log entries, specifically focusing on unsuccessful login attempts
129. `/cracked/db-logs` (GET) - (Admin) Retrieves recent performance sample logs, focusing on database interaction times
130. `/cracked/db-shell/read` (POST) - (Admin) Executes read-only database queries provided in the request body (Requires superadmin role)
131. `/cracked/health-checks` (GET) - (Admin) Retrieves results from periodic API health checks stored in the database
132. `/cracked/revenue/overview` (GET) - (Admin) Provides an overview of revenue metrics (active subscribers, platform breakdown, recent revenue)
133. `/cracked/revenue/signups` (GET) - (Admin) Shows daily signup counts for the last 7 days, broken down by platform (Stripe/Apple)
134. `/cracked/revenue/cancellation` (GET) - (Admin) Displays metrics related to subscription cancellations (rate, average duration, platform breakdown)
135. `/cracked/revenue/recent-signups` (GET) - (Admin) Lists the most recently subscribed users
136. `/cracked/tests/{test_id}/update-name` (PUT) - (Admin) Specifically updates the name of a test/quiz (Requires supervisor role)
137. `/cracked-health-check` (GET) - (Admin) Performs a live health check on the API and database connectivity
138. `/cracked/server-metrics` (GET) - (Admin) Retrieves current server resource usage statistics (CPU, RAM, Disk, Network, Processes)
139. `/cracked/rate-limits` (GET) - (Admin) Displays current rate limit usage across different endpoints and users/IPs
140. `/cracked/newsletter/create` (POST) - (Admin) Creates a new draft newsletter campaign (Requires supervisor role)
141. `/cracked/newsletter/{campaign_id}` (GET) - (Admin) Retrieves the details (title, content, status) of a specific newsletter campaign
142. `/cracked/newsletter/send/{campaign_id}` (POST) - (Admin) Sends a specific newsletter campaign to all active subscribers (Requires supervisor role)
143. `/cracked/newsletter/subscribers` (GET) - (Admin) Retrieves a list of all email addresses subscribed to the newsletter
144. `/cracked/newsletter/campaigns` (GET) - (Admin) Retrieves a list of all created newsletter campaigns
145. `/cracked/newsletter/{campaign_id}` (DELETE) - (Admin) Deletes a newsletter campaign (Requires supervisor role)
146. `/cracked/csrf-token` (GET) - Generate and return a CSRF token
147. `/cracked/admin-access-logs` (GET) - Retrieve admin access logs for the admin dashboard
148. `/cracked/user-requests` (GET) - Get unique user request data
149. `/cracked/api-health-check` (GET) - Simple health check for API and database

## Public Newsletter Routes 
150. `/newsletter/subscribe` (POST) - Allows a user to subscribe their email address to the newsletter list
151. `/newsletter/unsubscribe` (POST) - Allows a user to unsubscribe their email address using the email itself
152. `/newsletter/unsubscribe/{token}` (GET) - Allows a user to unsubscribe using a unique token, typically clicked from a link in an email

## Password Reset Routes 
153. `/password-reset/request-reset` (POST) - Initiates the password reset process by sending a reset link to the provided email (if registered)
154. `/password-reset/verify-token/{token}` (GET) - Checks if a given password reset token is valid and not expired
155. `/password-reset/reset-password` (POST) - Resets the user's password using a valid token and the new password provided

## Contact Form Routes 
156. `/contact/submit` (POST) - Handles submissions from the public contact form, sending the message to support and saving it
