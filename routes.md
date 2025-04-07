# TEST routes


/test/user/<user_id> (GET) - Retrieves a user's profile information by ID
/test/user (POST) - Registers a new user account
/test/login (POST) - Handles user authentication and login
/test/user/<user_id>/add-xp (POST) - Adds experience points to a user
/test/user/<user_id>/add-coins (POST) - Adds coins to a user's account
/test/shop (GET) - Retrieves available items from the shop
/test/shop/purchase/<item_id> (POST) - Processes an item purchase
/test/shop/equip (POST) - Equips an avatar item for a user
/test/tests/<test_id> (GET) - Fetches a test by its ID
/test/tests/<category>/<test_id> (GET) - Fetches a test by category and ID
/test/attempts/<user_id>/<test_id> (GET) - Gets a user's test attempt
/test/attempts/<user_id>/<test_id> (POST) - Updates a user's test attempt
/test/attempts/<user_id>/<test_id>/finish (POST) - Completes a test attempt
/test/attempts/<user_id>/list (GET) - Lists all test attempts for a user
/test/user/<user_id>/submit-answer (POST) - Submits an answer and awards XP/coins
/test/achievements (GET) - Retrieves all available achievements
/test/leaderboard (GET) - Gets the user leaderboard with pagination
/test/user/change-username (POST) - Updates a user's username
/test/user/change-email (POST) - Updates a user's email address
/test/user/change-password (POST) - Updates a user's password
/test/subscription/cancel (POST) - Placeholder for subscription cancellation
/test/attempts/<user_id>/<test_id>/answer (POST) - Updates a single answer in a test
/test/attempts/<user_id>/<test_id>/position (POST) - Updates current question position
/test/user/<user_id>/daily-bonus (POST) - Claims daily login bonus
/test/daily-question (GET) - Gets the current daily question
/test/daily-question/answer (POST) - Submits answer for daily question
/test/public-leaderboard/board (GET) - Gets public leaderboard with longer cache duration
/test/user/<user_id>/delete (DELETE) - Deletes a user account and related data

--------------

# OAuth Routes (oauth_bp, assumed prefix /oauth)

GET /oauth/login/google: Initiates the Google OAuth login flow, redirecting the user to Google's authentication page.
GET /oauth/auth/google: Handles the callback from Google after user authentication, exchanges code for token, fetches user info, creates/updates user, and redirects to frontend.
GET /oauth/login/apple: Initiates the Sign in with Apple OAuth flow, redirecting the user to Apple's authentication page.
POST /oauth/auth/apple: Handles the callback from Apple after user authentication (via form post), exchanges code/token, fetches user info, creates/updates user, and redirects to frontend.
(GET on this route redirects to /oauth/login/apple)
POST /oauth/login/apple/mobile: Handles Sign in with Apple specifically for mobile clients, using the identity token provided by the app.
POST /oauth/verify-google-token: Verifies a Google access token provided directly (e.g., from a mobile app's Google Sign-In library).
GET /oauth/admin-login/google: Initiates a Google OAuth login flow specifically for the admin dashboard, prompting for account selection.
GET /oauth/admin-auth/google: Handles the callback for admin Google login, verifies if the email is authorized, and sets admin session if successful.

--------------

# Subscription Routes (subscription_bp, assumed prefix /subscription)

POST /subscription/create-checkout-session: Creates a Stripe Checkout session for starting a new subscription purchase.
GET /subscription/config: Returns public Stripe configuration details (publishable key, price ID).
GET /subscription/subscription-status: Checks and returns the current subscription status (active, inactive, platform) for a given user.
GET /subscription/session-status: Checks the status (e.g., complete, open) of a specific Stripe Checkout session.
POST /subscription/webhook: Listens for and processes incoming webhook events from Stripe (e.g., payment success, subscription updates, cancellations).
POST /subscription/cancel-subscription: Allows an authenticated user to request cancellation of their Stripe subscription (sets cancel_at_period_end).
GET /subscription/check-flow: Checks if the current user session is part of an OAuth sign-up flow that includes subscription.
POST /subscription/clear-temp-data: Clears temporary registration data stored in the session/database during the checkout process for new users.
POST /subscription/verify-receipt: Verifies an Apple App Store receipt (usually from a mobile app) to validate and update the user's subscription status.
POST /subscription/apple-subscription: Processes a new Apple subscription activated via the mobile app, using the provided receipt data.
POST /subscription/restore-purchases: Handles requests from the mobile app to restore Apple App Store purchases using receipt data.
POST /subscription/apple-webhook: Listens for and processes incoming Server-to-Server notifications from Apple about subscription events (renewals, expirations, etc.).
GET /subscription/apple-webhook: A simple endpoint for Apple to verify the webhook URL during setup.

-----------------

# Support Routes (support_bp, prefix /support)

GET /support/my-chat: Retrieves a list of all support chat threads initiated by the currently authenticated user.
POST /support/my-chat: Creates a new support chat thread for the authenticated user.
GET /support/my-chat/{thread_id}: Retrieves the messages and details for a specific support thread belonging to the authenticated user.
POST /support/my-chat/{thread_id}: Allows the authenticated user to post a message to one of their specific support threads.
POST /support/my-chat/{thread_id}/close: Allows the authenticated user to mark their own support thread as closed.

-----------

# Cracked Admin Routes (cracked_bp, prefix /cracked)

GET /cracked/request-logs/nginx: (Admin) Retrieves recent Nginx access logs.
GET /cracked/request-logs: (Admin) Retrieves recent API request logs recorded by the application.
POST /cracked/login: (Admin) Authenticates an admin user using the admin password.
POST /cracked/logout: (Admin) Logs out the currently authenticated admin user.
GET /cracked/dashboard: (Admin) Retrieves aggregated statistics and metrics for the admin dashboard overview.
GET /cracked/users: (Admin) Lists registered users with filtering, pagination, and search capabilities.
POST /cracked/users/{user_id}/toggle-subscription: (Admin) Manually activates or deactivates a user's subscription status. (Requires supervisor role)
PUT /cracked/users/{user_id}: (Admin) Updates specific editable fields (like username, coins, XP) for a given user.
DELETE /cracked/users/{user_id}: (Admin) Permanently deletes a user account. (Requires supervisor role)
POST /cracked/users/{user_id}/reset-password: (Admin) Resets a user's password and provides the new temporary password. (Requires supervisor role)
GET /cracked/supportThreads: (Admin) Lists all support threads across all users for admin review.
GET /cracked/supportThreads/{thread_id}: (Admin) Retrieves the details and messages of a specific support thread (regardless of user).
POST /cracked/supportThreads/{thread_id}/reply: (Admin) Allows an admin to post a reply to a specific support thread.
POST /cracked/supportThreads/{thread_id}/close: (Admin) Allows an admin to mark a support thread as closed.
DELETE /cracked/supportThreads/clear-closed: (Admin) Deletes all support threads that are currently marked as closed. (Requires supervisor role)
POST /cracked/supportThreads/createFromAdmin: (Admin) Allows an admin to initiate a new support thread directed at a specific user.
GET /cracked/tests: (Admin) Lists all the tests/quizzes available in the system.
POST /cracked/tests: (Admin) Creates a new test/quiz definition. (Requires supervisor role)
PUT /cracked/tests/{test_id}: (Admin) Updates the details or questions of an existing test/quiz. (Requires supervisor role)
DELETE /cracked/tests/{test_id}: (Admin) Deletes a test/quiz definition. (Requires supervisor role)
GET /cracked/daily: (Admin) Lists all the daily PBQ (Performance-Based Questions) available.
POST /cracked/daily: (Admin) Creates a new daily PBQ question. (Requires supervisor role)
PUT /cracked/daily/{obj_id}: (Admin) Updates an existing daily PBQ question. (Requires supervisor role)
DELETE /cracked/daily/{obj_id}: (Admin) Deletes a daily PBQ question. (Requires supervisor role)
GET /cracked/performance: (Admin) Retrieves application performance metrics (like request times, DB query times) and historical data.
GET /cracked/web-vitals: (Admin) Retrieves collected Web Vitals metrics (LCP, FCP, CLS, etc.) reported by the frontend.
GET /cracked/recent-errors: (Admin) Retrieves a list of recent errors (HTTP status >= 400) recorded by the performance sampler.
POST /cracked/report-web-vitals: Endpoint for the frontend application to send Web Vitals performance data to the backend. (Note: Located in admin file, potentially for internal reporting)
GET /cracked/activity-logs: (Admin) Retrieves recent audit log entries, specifically focusing on unsuccessful login attempts.
GET /cracked/db-logs: (Admin) Retrieves recent performance sample logs, focusing on database interaction times.
POST /cracked/db-shell/read: (Admin) Executes read-only database queries provided in the request body. (Requires superadmin role)
GET /cracked/health-checks: (Admin) Retrieves results from periodic API health checks stored in the database.
GET /cracked/revenue/overview: (Admin) Provides an overview of revenue metrics (active subscribers, platform breakdown, recent revenue).
GET /cracked/revenue/signups: (Admin) Shows daily signup counts for the last 7 days, broken down by platform (Stripe/Apple).
GET /cracked/revenue/cancellation: (Admin) Displays metrics related to subscription cancellations (rate, average duration, platform breakdown).
GET /cracked/revenue/recent-signups: (Admin) Lists the most recently subscribed users.
PUT /cracked/tests/{test_id}/update-name: (Admin) Specifically updates the name of a test/quiz. (Requires supervisor role)
GET /cracked-health-check: (Admin) Performs a live health check on the API and database connectivity.
GET /cracked/server-metrics: (Admin) Retrieves current server resource usage statistics (CPU, RAM, Disk, Network, Processes).
GET /cracked/rate-limits: (Admin) Displays current rate limit usage across different endpoints and users/IPs.

------------

# Admin Newsletter Routes (admin_news_bp, assumed prefix /cracked/newsletter)

POST /cracked/newsletter/create: (Admin) Creates a new draft newsletter campaign. (Requires supervisor role)
GET /cracked/newsletter/{campaign_id}: (Admin) Retrieves the details (title, content, status) of a specific newsletter campaign.
POST /cracked/newsletter/send/{campaign_id}: (Admin) Sends a specific newsletter campaign to all active subscribers. (Requires supervisor role)
GET /cracked/newsletter/subscribers: (Admin) Retrieves a list of all email addresses subscribed to the newsletter.
GET /cracked/newsletter/campaigns: (Admin) Retrieves a list of all created newsletter campaigns.
DELETE /cracked/newsletter/{campaign_id}: (Admin) Deletes a newsletter campaign. (Requires supervisor role)

----------------

# Public Newsletter Routes (newsletter_bp, assumed prefix /newsletter)

POST /newsletter/subscribe: Allows a user to subscribe their email address to the newsletter list.
POST /newsletter/unsubscribe: Allows a user to unsubscribe their email address using the email itself.
GET /newsletter/unsubscribe/{token}: Allows a user to unsubscribe using a unique token, typically clicked from a link in an email.

-----------------

# Password Reset Routes (password_reset_bp, assumed prefix /password-reset)

POST /password-reset/request-reset: Initiates the password reset process by sending a reset link to the provided email (if registered).
GET /password-reset/verify-token/{token}: Checks if a given password reset token is valid and not expired.
POST /password-reset/reset-password: Resets the user's password using a valid token and the new password provided.


----------------

# Contact Form Routes (contact_bp, assumed prefix /contact)

POST /contact/submit: Handles submissions from the public contact form, sending the message to support and saving it.

---------------
# Scenario Generation Routes (scenario_bp, assumed prefix /scenario)

POST /scenario/stream_scenario: Generates a security scenario based on input parameters (industry, attack type, etc.) and streams the output text.
POST /scenario/stream_questions: Generates interactive questions based on a provided scenario text and streams the output JSON.

---------------

# GRC Question Routes (grc_bp, assumed prefix /grc)

POST /grc/generate_question: Generates a GRC (Governance, Risk, Compliance) question based on category and difficulty (uses Celery, non-streaming).
POST /grc/stream_question: Generates a GRC question based on category and difficulty and streams the output JSON chunk by chunk.

--------------------

# XploitCraft Routes (xploit_bp, assumed prefix /xploit)

POST /xploit/generate_payload: Generates a conceptual exploit payload based on a given vulnerability and optional evasion technique, with streaming support.

-------------------

# Analogy Generation Routes (analogy_bp, assumed prefix /analogy)

POST /analogy/generate_analogy: Generates an analogy comparing cybersecurity concepts based on type and input concepts (uses Celery, non-streaming, likely legacy).
POST /analogy/stream_analogy: Generates an analogy comparing cybersecurity concepts and streams the output text chunk by chunk.
