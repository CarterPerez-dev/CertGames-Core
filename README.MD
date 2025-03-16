Below is a more in-depth, technical, and comprehensive overview of the repository as gleaned from its code and structure. We will walk through the major components of the project, including the backend (Flask + Celery + MongoDB), the frontend (React), the infrastructure (Docker, Apache, NGINX, Redis), and how everything fits together.

---

## 1. Overall Architecture

This project comprises multiple services that orchestrate to create a full-stack web application:

1. **Frontend**: A React app, built and served via Node-based containers or proxied through Apache/NGINX.
2. **Backend**: A Flask application exposing various REST endpoints, uses:
   - **Flask-PyMongo** for MongoDB interactions
   - **Celery** + **Redis** for asynchronous tasks
   - **Rate limiting** via MongoDB-based counters
3. **MongoDB**: Stores user data, test attempts, newsletters, chat threads, etc.
4. **Redis**: Used as a broker/worker-backend for Celery tasks, possibly also caching.
5. **Apache** or **NGINX**: Reverse proxy setup to route requests to frontend (React) or backend (Flask), with optional WebSocket support for real-time messaging.

A **docker-compose.yml** file orchestrates these services, spinning up containers for:  
- Flask-based backend  
- React-based frontend build / dev environment  
- Redis for Celery  
- MongoDB for data persistence  
- An optional Apache or NGINX container that handles reverse proxy duties

---

## 2. Backend (Flask Application)

### 2.1 Overview

- The Flask app is composed of multiple submodules grouped under `backend/`.
- Uses a modular routing approach: each area of functionality (e.g., **analogy generation**, **scenario generation**, **user management**, **newsletter**, **admin dashboard**, etc.) lives in its own blueprint in the `routes/` directory.
- MongoDB connectivity is provided by `mongodb/database.py`, which initializes a `PyMongo` instance, references collections by name, and shares them throughout the code.

### 2.2 Key Python Modules / Directories

1. **`API/AI.py`**  
   - Loads the OpenAI API key from environment variables.  
   - Creates an `OpenAI` client object for communicating with the GPT-like endpoints.  
   - Provides a base for other “helpers” to call the language model.

2. **`helpers/*`**  
   - **`celery_app.py`**:  
     - Configures the Celery instance (broker & result backend from `redis://redis:6379/0`), concurrency, time zone, and sets up periodic tasks using Celery Beat.
     - Example tasks scheduled: collecting performance metrics, checking API endpoints, cleaning logs, etc.
   - **`async_tasks.py`**:  
     - Defines Celery tasks that perform asynchronous generation or background jobs:  
       - Generating single/comparison/triple analogies (calls `analogy_stream_helper`).  
       - Generating scenario text, breakdown, and interactive questions.  
       - Generating GRC questions.  
       - Aggregating performance metrics from `perfSamples` every 3 minutes.  
       - Health checks on certain endpoints to confirm the app is responsive.
   - **`analogy_stream_helper.py`**:  
     - Streams analogy text from an OpenAI-based ChatCompletion call.  
     - Returns a generator that yields chunks of content in real time.  
   - **`scenario_helper.py`**:  
     - Generates a multi-paragraph cybersecurity scenario tailored by industry, threat level, etc.  
     - Breaks down scenarios to gather context, actors, and mitigation steps.  
     - Generates interactive questions, streaming JSON back to the client.  
   - **`grc_stream_helper.py`**:  
     - Builds GRC-related multiple-choice questions (CISSP/CISM/CRISC style), returning a JSON object with question, options, correct answer, explanations, and an exam tip.  
     - Also supports streaming chunk-by-chunk content.  
   - **`xploitcraft_helper.py`**:  
     - Example logic to generate educational exploit payloads for pen-testing demos.  
     - Splits the logic into multiple code examples plus explanations.  
   - **`rate_limiter.py`**:  
     - Implements an IP or user-based rate-limiter, storing usage info in Mongo (`rateLimits` collection).  
     - Has a decorator `@rate_limit('scenario')`, etc. to block requests if the user has exceeded the allowed calls within a time window.

3. **`models/*`**  
   - **`test.py`**:  
     - One of the most central modules. Manages:  
       - **User creation** & input validation (username, password, email).  
       - Basic user fields (coins, xp, level, achievements).  
       - Mechanisms to compute XP required for a given level, awarding XP after test attempts, awarding coins, applying daily bonuses, etc.  
       - Achievements: tracks counters for completed tests, perfect tests, etc.  
       - Uses special fields like `achievement_counters` to accumulate stats and unlock achievements.  
     - Also contains some password checks, ban lists, etc.  
   - **`newsletter.py`**:  
     - Subscribing/unsubscribing logic.  
     - Creating, sending, and marking newsletter campaigns.  
   - **`password_reset.py`**:  
     - Generating secure random tokens for password reset.  
     - Validating tokens, marking them as used, updating the user’s password if valid.  
   - Other support classes and functions as needed.

4. **`mongodb/database.py`**  
   - Initializes a Flask app for PyMongo (`MONGO_URI` read from environment).  
   - Creates references:  
     ```python
     mainusers_collection = db.mainusers
     shop_collection = db.shopItems
     achievements_collection = db.achievements
     tests_collection = db.tests
     testAttempts_collection = db.testAttempts
     correctAnswers_collection = db.correctAnswers
     # ...
     ```
   - All subsequent modules import these collections to perform database operations.

### 2.3 Routes Organization

In `backend/routes/`, each file is a Flask blueprint:

- **`analogy_routes.py`**  
  - `/generate_analogy`: Old endpoint that uses Celery tasks.  
  - `/stream_analogy`: New endpoint that streams the analogy text chunk-by-chunk.

- **`scenario_routes.py`**  
  - `/stream_scenario`: Streams a multi-paragraph scenario (technical plus storyline).  
  - `/stream_questions`: Streams multiple-choice questions in JSON.

- **`grc_routes.py`**  
  - `/generate_question` (Celery-based) and `/stream_question` (stream-based) to produce a GRC multiple-choice question.

- **`newsletter_routes.py`**  
  - Public routes for newsletter subscribe/unsubscribe, including “one-click unsubscribe by token.”

- **`password_reset_routes.py`**  
  - Routes for requesting a password reset (`/request-reset`) and verifying tokens.

- **`oauth_routes.py`**  
  - Implements **Google OAuth** and **Apple Sign-In**:  
    - Uses the `authlib` or direct requests to Google/Apple endpoints.  
    - On success, if the user doesn’t exist, creates a new user with placeholder username. Otherwise logs them in.  

- **`support_routes.py`**  
  - A user support “chat” system: the user can create a new “thread,” add messages, see admin replies, etc.  
  - Uses `Socket.IO` to broadcast new messages in real time.

- **`test_routes.py`**:  
  - This is effectively the main “user” and “test attempts” API.  
  - Endpoints for user registration, login, awarding XP, claiming daily bonuses, etc.  
  - Endpoints for fetching tests, persisting “testAttempts,” finishing attempts, awarding achievements, etc.  
  - Has a “leaderboard” endpoint that caches results in memory for 15 seconds.  

- **`cracked_admin.py`**  
  - “Cracked admin” routes for an admin dashboard.  
  - Allows superadmin to manage users (list/export in CSV, update fields, reset password), manage tests, see performance metrics, manage “supportThreads,” read logs, etc.  
  - Uses session-based admin password check.

### 2.4 Celery Configuration

- **Celery** is configured in `helpers/celery_app.py`.  
  - `CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND` default to `redis://redis:6379/0`.  
  - Some tasks are scheduled with `celery.beat_schedule`:  
    - **`aggregate-performance-metrics`** every 3 min  
    - **`check-api-endpoints`** every 5 min  
    - **`cleanup-logs`** daily  
  - Celery tasks in `helpers/async_tasks.py` handle background work, e.g. streaming analogy generation or storing scenario data if needed.

---

## 3. Database Layer (MongoDB)

- The code references multiple distinct collections:  
  1. **`mainusers`**: Primary user records (username, email, password, xp, coins, achievements, etc.).  
  2. **`tests`**: Stores test data (e.g., each test’s questions, category, testId).  
  3. **`testAttempts`**: Tracks a user’s in-progress or finished attempts (their answers, score, timestamps).  
  4. **`correctAnswers`**: Optionally logs which questions each user has gotten correct at least once.  
  5. **`newsletterSubscribers`, `newsletterCampaigns`**: Newsletter emailing system.  
  6. **`supportThreads`**: User support chat. Each thread has messages from “user” or “admin.”  
  7. **`performanceMetrics`**: Summaries aggregated by Celery from `perfSamples`.  
  8. **`rateLimits`**: For storing usage info (API calls) to enforce rate limiting.  
  9. **`dailyQuestions`, `dailyAnswers`**: Possibly for daily “PBQ” or question-of-the-day feature.  

Each route or helper method does typical CRUD operations or complex queries/aggregations on these collections.  

---

## 4. Frontend (React)

Within `frontend/my-react-app/`:

1. **`Dockerfile.frontend`, `Dockerfile.dev`, `Dockerfile.audit`**: Multiple Dockerfiles are present, possibly for:
   - **`Dockerfile.frontend`**: Building production React images  
   - **`Dockerfile.dev`**: Development environment  
   - **`Dockerfile.audit`**: Security scanning or static analysis  
2. **`package.json`**, `.gitignore`, `eslint.config.mjs`: Typical Node/React setup.  
3. **`public/`** folder:  
   - Contains static assets, `index.html`, `robots.txt`, `sitemap.xml`, etc.  
4. **`src/` folder**:  
   - **`App.js`**: Main entry point for React Router.  
   - **`components/`**: A wide range of pages for handling different test categories (Security+, PenTest+, Linux+, etc.).  
   - **`store/`**: Redux slices for achievements, user data, leaderboards, etc.  
   - **`auth/`, `pages/`, `Sidebar/`, etc.**: Each subfolder implements additional functional or UI components.  
     - For instance, `pages/AnalogyPage/AnalogyHub.js` integrates with `analogy_routes` from the backend.  
     - `pages/GRCpage/GRC.js` interacts with GRC question endpoints.  
   - **`components/cracked/`**: Some admin or special “cracked admin” UI components.  
   - **API calls** from the React app typically target `http://backend:5000/api/*` or a proxied route depending on the environment.

---

## 5. Infrastructure

### 5.1 Docker & Docker Compose

- The root `docker-compose.yml` likely defines services:
  - **`backend`**: Builds from `backend/Dockerfile.backend`, runs Flask on port 5000.  
  - **`frontend`**: Possibly uses `frontend/my-react-app/Dockerfile.frontend` or a Node builder.  
  - **`mongo`**: An official MongoDB image.  
  - **`redis`**: For Celery.  
  - Possibly an **`apache`** or **`nginx`** service to serve as a reverse proxy.

### 5.2 Apache & NGINX

- **`apache/apache_server.conf`** sets up a VirtualHost on port 8080. Proxies to `backend:5000` for `/api/`, and to `frontend:3000` for everything else.
- Alternatively, **`nginx/`** config uses `reverse_proxy.conf` to do a similar approach for the React frontend and Python backend.

### 5.3 Rate Limiting

- Implemented in Python via a `@rate_limit('analogy')` or similar decorator in the routes.  
- Each request increments a “calls” array in the `rateLimits` collection with timestamps.  
- The code checks how many calls occurred in the last period (e.g., 15 calls/hour for analogy). If exceeded, returns HTTP 429.

### 5.4 Performance Monitoring

- The backend logs each request’s duration to a `perfSamples` collection (via some middleware).  
- A Celery task aggregates these into `performanceMetrics` every 3 minutes (calculating average request time, error rate, throughput, etc.).  
- Admin routes expose a `performance` or `db-logs` endpoint to retrieve logs and metrics.

---

## 6. Application Workflows

### 6.1 User Registration & Login

- A user may register via the `POST /api/user` route (`create_user` logic in `test.py`).
- The password is stored in `user["password"]` as-is in the code shown (though in a production environment you’d expect hashing).
- The user can then log in with `POST /api/login`, which verifies the password, sets `session['userId']`.  
- Session-based authentication is used. Additional checks or expansions (like JWT) are not shown, but you could integrate them.

### 6.2 Taking a Test

- The React frontend calls `GET /api/tests/<category>/<test_id>` to fetch test questions.  
- The user’s answers are stored in a “testAttempt” doc.  
- As they answer each question, `POST /api/user/<user_id>/submit-answer` (for immediate feedback) or updated in `testAttempts` if in “examMode.”  
- When done, `POST /api/attempts/<user_id>/<test_id>/finish` finalizes the attempt, calculates the final score, awards XP and coins, updates achievements, etc.

### 6.3 Achievements & Leveling

- Each user has counters in `achievement_counters`. When tests are finished, these counters are incremented.  
- Then `check_and_unlock_achievements(user_id)` runs, scanning each achievement’s criteria (like total tests, perfect tests, highest score, etc.).  
- The user’s XP is tracked in `user["xp"]`. If XP crosses a threshold, the user’s `level` increments.

### 6.4 Scenario & GRC Generation

- Users can request an “attack scenario” from `/stream_scenario`, which streams paragraphs from an OpenAI model.  
- They can also request “interactive questions” about that scenario from `/stream_questions`.  
- The same pattern applies for GRC questions from `/stream_question` in `grc_routes.py`.

### 6.5 Newsletter System

- `newsletter_subscribers` holds emails that are subscribed.  
- Admin routes can create a campaign in `newsletter_campaigns`.  
- Then an admin can “send” that campaign, iterating over active subscribers, emailing them through `SendGrid`.  
- The email includes an unsubscribe token which hits `/newsletter/unsubscribe/<token>`.

### 6.6 Admin “Cracked” Dashboard

- The user logs in as admin by hitting `/cracked/login` with the `CRACKED_ADMIN_PASSWORD`.  
- Gains access to routes that list users, delete them, see daily performance metrics, manage tests, see support threads, etc.  
- Has a variety of “GET/POST/DELETE” endpoints for powerful actions.

---

## 7. Security Considerations

1. **Passwords** in code appear to be stored in plaintext (based on the provided snippets). In production, you’d normally apply hashing (e.g., bcrypt).  
2. **JWT** or more robust session management might be used in real deployments to strengthen session security.  
3. **Rate-limiting** is done via Mongo-based timestamps to mitigate abuse of certain expensive API endpoints (e.g., generating AI content).
4. **Celery tasks** can generate or store large amounts of content, potentially needing memory constraints or concurrency limits.  
5. **Email** is handled via SendGrid in `utils/email_sender.py` (not fully shown).  
6. **Apple/Google OAuth** is integrated, but custom logic is used for token exchange and ID token decoding (particularly for Apple).  

---

## 8. Summary of Key Technical Highlights

- **Modular Flask** with blueprint-based route organization.  
- **MongoDB** for persistent data and user information.  
- **Celery** with Redis for async tasks, scheduled tasks, and real-time streaming from the OpenAI endpoints.  
- **Rich** “test attempt” tracking system that includes immediate feedback or exam-like “no immediate feedback.”  
- **Achievement engine** that updates user statistics and unlocks achievements based on numeric thresholds.  
- **Newsletter** and **support chat** subsystems, each with dedicated database collections and routes.  
- **Multi-stage Docker** architecture: separate Dockerfiles for dev, auditing, and production.  
- **Apache** or **NGINX** reverse proxy config to unify the application behind a single port, supporting both websockets (for chat) and standard HTTP.  

Overall, this codebase forms a complete, containerized platform that can handle everything from user sign-up and test-taking to AI-driven content generation, with admin capabilities and asynchronous tasks for background processing. It’s a fairly large system with multiple moving parts, each orchestrated via Python, Docker, and the React frontend.




---

## 1. **High-Level Docker Architecture**

My application is composed of multiple containers:

1. **Backend** (Flask/Python) – built from `backend/Dockerfile.backend`.
2. **Frontend** (React/Node) – built from `frontend/my-react-app/Dockerfile.frontend` (with additional dev/audit Dockerfiles).
3. **Apache** (or optionally NGINX) – reverse proxy container, built from `apache/Dockerfile.apache` or using `nginx/` config.
4. **MongoDB** – typically the official `mongo` image from Docker Hub.
5. **Redis** – the official `redis` image from Docker Hub, used by Celery as a broker and result backend.

A `docker-compose.yml` at the root ties everything together, letting me run `docker-compose up -d` to spin up the entire multi-service environment. Each service’s Dockerfile (where applicable) is used to build an image, environment variables are injected, volumes might be mounted, and network connections are configured. The container names (like `backend`, `frontend`, `mongo`, `redis`, `apache`/`nginx`) become hostnames so they can talk to each other.

---

## 2. **Backend Container** (Flask)

### 2.1 Location and Dockerfile

- **Location**: `backend/Dockerfile.backend`  
- Though the entire file wasn’t fully shown in the repomix, the typical pattern is:
  1. Start from an official Python base image (e.g., `python:3.9`).
  2. Copy `requirements.txt` into the container.
  3. Run `pip install -r requirements.txt` to install Flask, PyMongo, Celery, and other dependencies.
  4. Copy in my `backend` code.
  5. Expose the port (likely `5000`) and set the command to run the Flask app.

### 2.2 Behavior

- Once the container starts, it runs **my Flask app** (e.g., `python app.py` or via `gunicorn`).  
- The Flask app then connects to Mongo and Redis by referencing those hostnames (`mongo`, `redis`) from the Compose network.  
- The environment variables (e.g., `MONGO_URI`, `REDIS_PASSWORD`) are typically passed in via `docker-compose.yml`.

---

## 3. **Frontend Container** (React)

### 3.1 Dockerfiles

Under `frontend/my-react-app/`, I see multiple Dockerfiles:

- **`Dockerfile.frontend`** – This is presumably the production build.  
- **`Dockerfile.dev`** – For development environment, possibly with hot-reloading.  
- **`Dockerfile.audit`** – For auditing security or dependencies.  

The “main” Dockerfile is often `Dockerfile.frontend`, which typically:

1. Uses a Node base image (e.g., `node:16` or `node:18`).
2. Copies `package.json` and other config, runs `npm install`.
3. Builds a production bundle with `npm run build`.
4. Optionally uses a multi-stage build to serve the static files with NGINX or another web server.  

### 3.2 Behavior

- In production mode, the React build artifacts (`build/`) might get served from an embedded web server (like `nginx`) or from the **Apache** container.  
- In dev mode, the container might run `npm start` on port `3000`.  
- The rest of my system (Apache or NGINX in the Compose file) proxies requests to `frontend:3000`.

---

## 4. **Apache** (Optional Reverse Proxy)

### 4.1 Dockerfile

- Found at **`apache/Dockerfile.apache`**:
  ```dockerfile
  FROM httpd:2.4

  COPY apache_server.conf /usr/local/apache2/conf/extra/
  COPY httpd.conf /usr/local/apache2/conf/httpd.conf

  # Enable proxy modules via sed
  RUN sed -i '/#LoadModule proxy_module/s/^#//' /usr/local/apache2/conf/httpd.conf && ...
  EXPOSE 8080
  CMD ["httpd-foreground"]
  ```
- It’s based on `httpd:2.4`, copies in custom configs (`apache_server.conf` and `httpd.conf`), and enables various modules (proxy_http, proxy_wstunnel, etc.).

### 4.2 Configuration

- **`apache/apache_server.conf`** sets up a `<VirtualHost *:8080>` block.  
- It proxies all `/api/` requests to **`backend:5000`** and the rest to **`frontend:3000`**.  
- It also sets up WebSocket proxying for `/api/socket.io/` to handle real-time events.

In the `docker-compose.yml`, I would see something like:
```yaml
services:
  apache:
    build: ./apache
    ports:
      - "8080:8080"
    depends_on:
      - backend
      - frontend
    # ...
```
This means Apache is effectively the “front door” on port 8080, forwarding requests to the other containers.

---

## 5. **NGINX** (Alternative Reverse Proxy)

- There is also an **`nginx/`** folder with `Dockerfile` or config (e.g. `reverse_proxy.conf`, `nginx.conf`).  
- If I switch to NGINX, it does the same job: route `/api` to Flask, and everything else to React.  
- My `docker-compose.yml` might only spin up one or the other.

---

## 6. **MongoDB** and **Redis**

1. **MongoDB** – Usually not custom-built. I use the official `mongo:latest` (or a pinned version).  
2. **Redis** – Also an official image.  
3. My code references them in `docker-compose.yml` as:
   ```yaml
   services:
     mongo:
       image: mongo:4.4
       volumes:
         - mongo-data:/data/db
       # ...
     redis:
       image: redis:latest
       volumes:
         - redis-data:/data
       # ...
   ```
4. The backend container’s environment sets `MONGO_URI` to `mongodb://mongo:27017/...` or similar, and Celery uses `redis://redis:6379/0`.

---

## 7. **docker-compose.yml** Orchestration

Although the entire `docker-compose.yml` contents aren’t fully shown, from scanning the references in the code, it typically includes:

1. **`backend`**:
   ```yaml
   services:
     backend:
       build: ./backend
       container_name: backend
       ports:
         - "5000:5000"  # (sometimes only exposed internally if Apache is fronting)
       environment:
         - MONGO_URI=mongodb://mongo:27017/database
         - REDIS_PASSWORD=...
         # ...
   ```
2. **`frontend`**:
   ```yaml
     frontend:
       build: ./frontend/my-react-app
       container_name: frontend
       ports:
         - "3000:3000" # or only internal if proxied
       # ...
   ```
3. **`apache`** or **`nginx`**:
   ```yaml
     apache:
       build: ./apache
       container_name: apache
       ports:
         - "8080:8080"
       depends_on:
         - backend
         - frontend
   ```
4. **`mongo`**:
   ```yaml
     mongo:
       image: mongo
       container_name: mongo
       volumes:
         - mongo-data:/data/db
   ```
5. **`redis`**:
   ```yaml
     redis:
       image: redis
       container_name: redis
   ```
6. **Volumes**:
   ```yaml
   volumes:
     mongo-data:
     redis-data:
   ```
With this setup, I can run `docker-compose up -d`, and Docker Compose will:

- Build images for `backend`, `frontend`, and `apache` from their respective Dockerfiles.
- Pull the official `mongo` and `redis` images.
- Connect them all on a default Docker network, so the service names (`backend`, `mongo`, `redis`, etc.) become DNS hostnames.

---

## 8. **Additional Development Dockerfiles**

Inside `frontend/my-react-app/`, there are:

- **`Dockerfile.dev`**  
  Possibly used to run a dev server with hot reload:
  ```dockerfile
  FROM node:16
  WORKDIR /app
  COPY package.json .
  RUN npm install
  CMD ["npm", "start"]
  ```
- **`Dockerfile.audit`**  
  Could be for a security scanning or code auditing pipeline.  
  For instance, it might install packages like `bandit`, or run `npm audit`.

These Dockerfiles let me spin up an environment specialized for local dev or for scanning the codebase.

---

## 9. **Runtime Flow**

Here’s how it all works once containers are running:

1. **Apache** container listens on port 8080.  
2. Requests to `http://localhost:8080/api/...` get proxied to `backend:5000` (Flask).  
3. Requests to `http://localhost:8080/anything-else` go to the `frontend:3000`.  
4. The **backend** container runs the Flask app, connecting to **MongoDB** for data and **Redis** for Celery tasks.  
5. If the user triggers a route that needs background processing (e.g., generating an analogy, scenario, or GRC question), the Flask route may dispatch a Celery task.  
6. The Celery worker portion is inside the same container (or sometimes a separate worker container) which communicates with Redis.  
7. The user’s requests all remain behind the scenes, but from an external viewpoint, I just hit `localhost:8080` to use the entire app.

---

## 10. **Summary**

- **Multiple Dockerfiles** exist, each specialized: `Dockerfile.backend` (Flask), `Dockerfile.frontend` (React), `Dockerfile.apache` (proxy), plus dev and audit variants.
- **`docker-compose.yml`** references them all to create a cohesive environment.  
- **MongoDB** and **Redis** are run from official images, no custom Dockerfiles needed.  
- **Apache** or **NGINX** acts as the single “entry point” for user traffic, forwarding requests to the correct service.  
- This approach allows me to keep the front end, back end, and support services separated into different containers, making the system easier to manage, scale, and develop.

That’s how **I** have Dockerized my application according to the code and config in `repomix-output.txt`.





---

## 1. Overall Folder Layout

- **`public/`**: Holds static assets like `index.html`, `manifest.json`, `robots.txt`, plus a few special files such as `sitemap.xml`. It also has a subfolder `xp/` with a script (`xp_mongo.js`) that might be used for some external or local reference.
- **`src/`**: Where almost all my React code lives. This includes:
  - **Components**: Each major page or feature is typically under `components/pages/...`.
  - **App.js, index.js**: The main entry points for rendering, routing, and hooking into React DOM.
  - **Global CSS**: e.g., `global.css` and `index.css`.
  - **Redux Store**: A `/store` folder containing slices for achievements, shop, user, etc.

I also included Dockerfiles like **`Dockerfile.frontend`**, **`Dockerfile.dev`**, and **`Dockerfile.audit`** to run or build the React app in different environments.

---

## 2. Key Pages and Features

Under **`src/components/pages/`**, I’ve grouped my pages by functionality or domain area:

1. **`auth/`** (e.g., `Login.js`, `Register.js`, `ForgotPassword.js`):  
   - Handles sign-up, login, forgot/reset password flows.
   - I put form components like `CreateUsernameForm.js`, plus small styling files (`.css`) to keep them consistent and easy to read.
   - Some interesting bits like `AuthToast.css` or `ErrorDisplay.js` help unify user feedback across the app.

2. **`AnalogyPage/`**:  
   - `AnalogyHub.js`, `AnalogyHub.css`: Where I connect to my analogy API endpoints from the backend. The user can generate single, comparison, or triple analogies, and the UI streams results.

3. **`GRCpage/`**:  
   - `GRC.js`, `GRC.css`: Similarly hooks into the GRC question endpoints. Users can get compliance/risk multiple-choice questions.

4. **Exam/Certification Pages**:  
   - Folders like `nplus`, `cysa`, `cloudplus`, `cissp`, `aplus`, `penplus`, etc.
   - Each contains test listing components (e.g., `NPlusTestList.js`) and an actual test page (e.g., `NPlusTestPage.js`).  
   - They typically call the backend’s routes to fetch test data, track user attempts, or store user answers.

5. **`ScenarioPage/`**:  
   - `ScenarioSphere.js`, `ScenarioSphere.css`: UI for generating and displaying attack scenarios, threat intensities, and interactive questions. Ties in with the backend scenario routes.

6. **`DailyPage/`**, **`ResourcesPage/`**, etc.:  
   - More specialized pages. For instance, `DailyCyberBrief.js` might fetch a daily question or scenario, while `Resources.js` could list external docs or references.

7. **`Info/`**:  
   - Pages like `ContactPage.js`, `DemosPage.js`, `ExamsPage.js`, plus an `InfoNavbar`.  
   - Typically these are simpler informational or static content pages.  
   - `PublicLeaderboardPage.js` might display a scoreboard calling the backend’s `/leaderboard` route.

8. **`cracked/`**:  
   - Contains “Cracked Admin” pages: `CrackedAdminDashboard.js`, `CrackedAdminLoginPage.js`.  
   - These tie into the admin routes that the backend calls “cracked_admin.” They can view user data, threads, or handle admin tasks with a specialized UI.

---

## 3. Navigation & Reusables

- **`Sidebar/Sidebar.js`, `Sidebar.css`**: A side navigation for the entire site.  
- **`footer.css`, `Footer.js`**: My global footer component with site links or disclaimers.
- **`iconMapping.js`, `colorMapping.js`**: Consolidated reference files for colors or icons, so I can maintain a consistent theme across different pages.
- **`SEOHelmet.js`, `StructuredData.js`**: Components for injecting metadata or JSON-LD into `<head>` for better SEO.

---

## 4. State Management (Redux)

Inside **`src/components/store/`**, I keep Redux logic:

- **`store.js`**: The main Redux store creation.  
- **Slices**:
  - **`achievementsSlice.js`**: Tracks unlocked achievements, new achievement notifications.  
  - **`shopSlice.js`**: Manages purchased items, avatar equip, coin updates, etc.
  - **`userSlice.js`**: Auth details, profile info, XP, level, etc.  
  - Possibly others for daily tasks, scenario data, or test attempts.

They’re combined in `store.js` and used across the app with `<Provider>` in `index.js`.

---

## 5. Handling Tests and Achievements

- Most test-related pages call the backend for a specific category (e.g., SecurityPlus, NetworkPlus).  
- They show multiple-choice or scenario-driven content, then store results in Redux or local state.  
- Achievements pop up if the backend’s response includes newly unlocked achievements.

---

## 6. Thematic & Stylistic Notes

- I rely on small `.css` files co-located with their `.js` components (`SomePage.css`, `SomePage.js`) to keep styling modular.  
- The `colorMapping.js` helps keep a consistent color scheme for charts, badges, or text highlights.  
- Reusable “toast” notifications (like `AuthToast.js`, `AchievementToast.js`) unify how I give the user quick pop-up messages.

---

## 7. Dev/Production Flow

- **In development**: I might use `npm start` on port 3000 to hot-reload changes.  
- **In production**: I rely on **`Dockerfile.frontend`** to do a production build (`npm run build`) and either:
  - Serve from a Node-based server, or
  - Copy static assets to the `apache` or `nginx` container’s `/var/www/html` directory.  

Then my reverse proxy (Apache/NGINX) routes all user traffic to the right place, so it’s a single domain.

---

## 8. Putting It All Together

This React structure is basically a multi-page approach, where each certification or test subject is a separate folder in `pages/`. The global store handles user authentication, coin/xp updates, and achievements. I connect to the backend for everything from daily scenarios to GRC questions, from contact forms to the user’s admin dashboard (if they have admin privileges).

In short, my React app is organized to keep specialized domain pages (like `SecurityPlusTestPage`) neat and separate, all while sharing a common design style, color palette, Redux store, and approach to user flows. I keep the code modular so it’s straightforward to add new exam categories or new features—just drop new folder(s) under `pages/` or new slices in `store/`.



so that was an ai givuiing a shgort overveiw of my applciation- some it is not as accurate and most of it is more indepth but i thinkj it gives a good gernal picture






here are some real key files

App.js file

// src/App.js
import React, { useEffect } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { fetchUserData } from './components/pages/store/userSlice';

// Import ToastContainer from react-toastify
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

// Public pages
import InfoPage from './components/pages/Info/InfoPage';
import DemosPage from './components/pages/Info/DemosPage';
import ExamsPage from './components/pages/Info/ExamsPage';
import PublicLeaderboardPage from './components/pages/Info/PublicLeaderboardPage';
import ContactPage from './components/pages/Info/ContactPage';
import Login from './components/pages/auth/Login';
import Register from './components/pages/auth/Register';
import ForgotPassword from './components/pages/auth/ForgotPassword';
import ResetPassword from './components/pages/auth/ResetPassword';
import PrivacyPolicy from './components/pages/PrivacyPolicy';
import TermsOfService from './components/pages/TermsOfService';
import CreateUsernameForm from './components/pages/auth/CreateUsernameForm';

// Admin 
import CrackedAdminLoginPage from './components/cracked/CrackedAdminLoginPage';
import CrackedAdminDashboard from './components/cracked/CrackedAdminDashboard'; 

// Protected pages
import ProtectedRoute from './components/ProtectedRoute';
import Sidebar from './components/Sidebar/Sidebar';

import Xploitcraft from './components/pages/XploitcraftPage/Xploitcraft';
import ScenarioSphere from './components/pages/ScenarioPage/ScenarioSphere';
import AnalogyHub from './components/pages/AnalogyPage/AnalogyHub';
import GRC from './components/pages/GRCpage/GRC';
import DailyCyberBrief from './components/pages/DailyPage/DailyCyberBrief';
import Resources from './components/pages/ResourcesPage/Resources';

// Gamified components and userprofile
import DailyStationPage from './components/pages/store/DailyStationPage';
import ShopPage from './components/pages/store/ShopPage';
import UserProfile from './components/pages/store/UserProfile';
import LeaderboardPage from './components/pages/store/LeaderboardPage';
import AchievementPage from './components/pages/store/AchievementPage';
import SupportAskAnythingPage from './components/pages/store/SupportAskAnythingPage';

// Unique Test Pages
import APlusTestPage from './components/pages/aplus/APlusTestPage';
import APlusCore2TestPage from './components/pages/aplus2/APlusCore2TestPage';
import NetworkPlusTestPage from './components/pages/nplus/NetworkPlusTestPage';
import SecurityPlusTestPage from './components/pages/secplus/SecurityPlusTestPage';
import CySAPlusTestPage from './components/pages/cysa/CySAPlusTestPage';
import PenPlusTestPage from './components/pages/penplus/PenPlusTestPage';
import CaspPlusTestPage from './components/pages/casp/CaspPlusTestPage';
import LinuxPlusTestPage from './components/pages/linuxplus/LinuxPlusTestPage';
import CloudPlusTestPage from './components/pages/cloudplus/CloudPlusTestPage';
import DataPlusTestPage from './components/pages/dataplus/DataPlusTestPage';
import ServerPlusTestPage from './components/pages/serverplus/ServerPlusTestPage';
import CisspTestPage from './components/pages/cissp/CisspTestPage';
import AWSCloudTestPage from './components/pages/awscloud/AWSCloudTestPage';

// Global Test Page
import GlobalTestPage from './components/GlobalTestPage';

// OAuth Success Page
import OAuthSuccess from './components/pages/auth/OAuthSuccess';

// Global CSS import
import './global.css';


function HomeOrProfile() {
  const { userId, status } = useSelector((state) => state.user);
  if (status === 'loading') {
    return <div>Loading...</div>;
  }
  if (userId) {
    return <Navigate to="/profile" replace />;
  }
  return <InfoPage />;
}

function App() {
  const dispatch = useDispatch();
  const { userId } = useSelector((state) => state.user);


  useEffect(() => {
    const initializeTheme = () => {
      const savedTheme = localStorage.getItem('selectedTheme') || 'default';
      document.documentElement.setAttribute('data-theme', savedTheme);
    };


    initializeTheme();
  }, []); 
  
  
  useEffect(() => {
    if (userId) {
      dispatch(fetchUserData(userId));
    }
  }, [dispatch, userId]);

  return (
    <div className="App">
      {userId && <Sidebar />}
      {/* React Toastify container for notifications */}
      <ToastContainer 
        position="top-right"
        autoClose={7000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
      />
      <div className="main-content">
        <Routes>
          {/* The default route depends on whether the user is logged in */}
          <Route path="/" element={<HomeOrProfile />} />
          
          {/* Added additional home route that always shows InfoPage */}
          <Route path="/home" element={<InfoPage />} />
          
          {/* New public marketing routes */}
          <Route path="/demos" element={<DemosPage />} />
          <Route path="/exams" element={<ExamsPage />} />
          <Route path="/public-leaderboard" element={<PublicLeaderboardPage />} />
          <Route path="/contact" element={<ContactPage />} />
          
          {/* Authentication routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password/:token" element={<ResetPassword />} />
          <Route path="/create-username" element={<CreateUsernameForm />} />
          <Route path="/oauth/success" element={<OAuthSuccess />} />
          
          {/* Admin routes */}
          <Route path="/cracked/login" element={<CrackedAdminLoginPage />} />
          <Route path="/cracked/dashboard" element={<CrackedAdminDashboard />} />
          
          {/* Legal pages */}
          <Route path="/privacy" element={<PrivacyPolicy />} />
          <Route path="/terms" element={<TermsOfService />} />
          
          {/* Support route */}
          <Route path="/my-support" element={<SupportAskAnythingPage />} />
          
          {/* Protected routes - require login */}
          <Route path="/profile" element={
            <ProtectedRoute>
              <UserProfile />
            </ProtectedRoute>
          }/>
          <Route path="/achievements" element={
            <ProtectedRoute>
              <AchievementPage />
            </ProtectedRoute>
          }/>
          <Route path="/shop" element={
            <ProtectedRoute>
              <ShopPage />
            </ProtectedRoute>
          }/>
          <Route path="/daily" element={
            <ProtectedRoute>
              <DailyStationPage />
            </ProtectedRoute>
          }/>
          <Route path="/leaderboard" element={
            <ProtectedRoute>
              <LeaderboardPage />
            </ProtectedRoute>
          }/>
          <Route path="/xploitcraft" element={
            <ProtectedRoute>
              <Xploitcraft />
            </ProtectedRoute>
          }/>
          <Route path="/scenariosphere" element={
            <ProtectedRoute>
              <ScenarioSphere />
            </ProtectedRoute>
          }/>
          <Route path="/analogyhub" element={
            <ProtectedRoute>
              <AnalogyHub />
            </ProtectedRoute>
          }/>
          <Route path="/grc" element={
            <ProtectedRoute>
              <GRC />
            </ProtectedRoute>
          }/>
          <Route path="/dailycyberbrief" element={<DailyCyberBrief />} />
          <Route path="/resources" element={<Resources />} />
          
          {/* Practice test routes */}
          <Route path="/practice-tests/a-plus" element={
            <ProtectedRoute>
              <APlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/a-plus/:testId" element={
            <ProtectedRoute>
              <APlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/aplus-core2" element={
            <ProtectedRoute>
              <APlusCore2TestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/aplus-core2/:testId" element={
            <ProtectedRoute>
              <APlusCore2TestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/network-plus" element={
            <ProtectedRoute>
              <NetworkPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/network-plus/:testId" element={
            <ProtectedRoute>
              <NetworkPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/security-plus" element={
            <ProtectedRoute>
              <SecurityPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/security-plus/:testId" element={
            <ProtectedRoute>
              <SecurityPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/cysa-plus" element={
            <ProtectedRoute>
              <CySAPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/cysa-plus/:testId" element={
            <ProtectedRoute>
              <CySAPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/pen-plus" element={
            <ProtectedRoute>
              <PenPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/pen-plus/:testId" element={
            <ProtectedRoute>
              <PenPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/casp-plus" element={
            <ProtectedRoute>
              <CaspPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/casp-plus/:testId" element={
            <ProtectedRoute>
              <CaspPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/linux-plus" element={
            <ProtectedRoute>
              <LinuxPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/linux-plus/:testId" element={
            <ProtectedRoute>
              <LinuxPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/cloud-plus" element={
            <ProtectedRoute>
              <CloudPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/cloud-plus/:testId" element={
            <ProtectedRoute>
              <CloudPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/data-plus" element={
            <ProtectedRoute>
              <DataPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/data-plus/:testId" element={
            <ProtectedRoute>
              <DataPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/server-plus" element={
            <ProtectedRoute>
              <ServerPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/server-plus/:testId" element={
            <ProtectedRoute>
              <ServerPlusTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/cissp" element={
            <ProtectedRoute>
              <CisspTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/cissp/:testId" element={
            <ProtectedRoute>
              <CisspTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/aws-cloud" element={
            <ProtectedRoute>
              <AWSCloudTestPage />
            </ProtectedRoute>
          }/>
          <Route path="/practice-tests/aws-cloud/:testId" element={
            <ProtectedRoute>
              <AWSCloudTestPage />
            </ProtectedRoute>
          }/>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </div>
  );
}

export default App;



// src/components/auth/Register.js
import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, Link } from 'react-router-dom';
import { registerUser, clearAuthErrors } from '../store/userSlice';
import {
  FaUser,
  FaLock,
  FaGoogle,
  FaApple,
  FaEnvelope,
  FaChevronRight,
  FaEye,
  FaEyeSlash,
  FaExclamationCircle,
  FaUserSecret,
  FaCheck,
  FaInfoCircle,
  FaTimes
} from 'react-icons/fa';
import PasswordRequirements from './PasswordRequirements';
import Footer from '../../Footer';
import './Register.css';

const Register = () => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [agreeTerms, setAgreeTerms] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [formError, setFormError] = useState('');
  const [showPasswordRequirements, setShowPasswordRequirements] = useState(false);
  const [passwordValidation, setPasswordValidation] = useState({
    hasMinimumLength: false,
    hasUpperCase: false,
    hasLowerCase: false,
    hasNumber: false,
    hasSpecialChar: false
  });
  
  const dispatch = useDispatch();
  const navigate = useNavigate();
  
  const { loading, error, userId } = useSelector((state) => state.user);
  
  // Clear errors when component mounts or unmounts
  useEffect(() => {
    dispatch(clearAuthErrors());
    
    return () => {
      dispatch(clearAuthErrors());
    };
  }, [dispatch]);
  
  useEffect(() => {
    // If already logged in, redirect to profile
    if (userId) {
      navigate('/profile');
    }
  }, [userId, navigate]);
  
  // Update password validation whenever password changes
  useEffect(() => {
    setPasswordValidation({
      hasMinimumLength: password.length >= 6,
      hasUpperCase: /[A-Z]/.test(password),
      hasLowerCase: /[a-z]/.test(password),
      hasNumber: /[0-9]/.test(password),
      hasSpecialChar: /[!@#$%^&*()\-_=+[\]{}|;:'",<.>/?`~\\]/.test(password)
    });
  }, [password]);

  const passwordIsValid = () => {
    return Object.values(passwordValidation).every(val => val === true);
  };
  
  const validateForm = () => {
    // Check if all fields are filled
    if (!username || !email || !password || !confirmPassword) {
      setFormError('All fields are required');
      return false;
    }
    
    // Check if password meets requirements
    if (!passwordIsValid()) {
      setFormError('Password does not meet all requirements');
      setShowPasswordRequirements(true);
      return false;
    }
    
    // Check if passwords match
    if (password !== confirmPassword) {
      setFormError('Passwords do not match');
      return false;
    }
    
    // Check if terms are agreed to
    if (!agreeTerms) {
      setFormError('You must agree to the Terms and Conditions');
      return false;
    }
    
    return true;
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError('');
    
    if (!validateForm()) {
      return;
    }
    
    try {
      const resultAction = await dispatch(registerUser({
        username,
        email,
        password,
        confirmPassword: confirmPassword
      }));
      
      if (registerUser.fulfilled.match(resultAction)) {
        // Registration successful, now login
        navigate('/login', { state: { message: 'Registration successful! Please log in.' } });
      } else {
        // Handle error from the action
        const errorMessage = resultAction.payload || resultAction.error?.message;
        
        // Check for email already taken message
        if (errorMessage && (
            errorMessage.includes("Email is already taken") || 
            errorMessage.includes("Username or email is already taken") ||
            errorMessage.includes("already taken")
        )) {
          setFormError('Email address is already registered. Please use a different email or login.');
        } else {
          setFormError(errorMessage || 'Registration failed. Please try again.');
        }
      }
    } catch (err) {
      // Handle other errors
      if (err.message && (
          err.message.includes("Email is already taken") ||
          err.message.includes("Username or email is already taken") ||
          err.message.includes("already taken")
      )) {
        setFormError('Email address is already registered. Please use a different email or login.');
      } else {
        setFormError('An error occurred. Please try again.');
      }
    }
  };
  
  const handleSocialSignUp = (provider) => {
    setFormError('');
    
    try {
      // Redirect to the backend OAuth route
      window.location.href = `/api/oauth/login/${provider.toLowerCase()}`;
    } catch (err) {
      setFormError(`${provider} sign up failed. Please try again.`);
    }
  };
  
  return (
    <div className="register-container">
      <div className="register-background">
        <div className="register-grid"></div>
        <div className="register-glow"></div>
      </div>
      
      <div className="register-content">
        <div className="register-card">
          <div className="register-header">
            <div className="register-logo">
              <FaUserSecret className="register-logo-icon" />
            </div>
            <h1 className="register-title">Create Account</h1>
            <p className="register-subtitle">Join and start your learning journey</p>
          </div>
          
          {(formError || error) && (
            <div className="register-error-message">
              <FaExclamationCircle />
              <span>{formError || error}</span>
            </div>
          )}
          
          <form className="register-form" onSubmit={handleSubmit}>
            <div className="register-input-group">
              <label htmlFor="username">Username</label>
              <div className="register-input-wrapper">
                <FaUser className="register-input-icon" />
                <input
                  type="text"
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Choose a unique username"
                  disabled={loading}
                />
              </div>
              <div className="register-input-hint">
                <FaInfoCircle className="register-hint-icon" />
                <span>3-30 characters, letters, numbers, dots, underscores, dashes</span>
              </div>
            </div>
            
            <div className="register-input-group">
              <label htmlFor="email">Email Address</label>
              <div className="register-input-wrapper">
                <FaEnvelope className="register-input-icon" />
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email address"
                  disabled={loading}
                />
              </div>
            </div>
            
            <div className="register-input-group">
              <label htmlFor="password">Password</label>
              <div className="register-input-wrapper">
                <FaLock className="register-input-icon" />
                <input
                  type={showPassword ? "text" : "password"}
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onFocus={() => setShowPasswordRequirements(true)}
                  onBlur={() => {
                    // Keep requirements visible if there's text or error
                    if (!password) {
                      setShowPasswordRequirements(false);
                    }
                  }}
                  placeholder="Create a strong password"
                  disabled={loading}
                  className={password && !passwordIsValid() ? "register-input-error" : ""}
                />
                <button
                  type="button"
                  className="register-toggle-password"
                  onClick={() => setShowPassword(!showPassword)}
                  tabIndex="-1"
                >
                  {showPassword ? <FaEyeSlash /> : <FaEye />}
                </button>
              </div>
              
              {showPasswordRequirements && (
                <div className="register-password-requirements">
                  <div className="register-requirements-header">
                    <h4>Password Requirements:</h4>
                    {passwordIsValid() ? (
                      <div className="register-requirements-status valid">
                        <FaCheck /> Valid
                      </div>
                    ) : (
                      <div className="register-requirements-status invalid">
                        <FaTimes /> Invalid
                      </div>
                    )}
                  </div>
                  <ul className="register-requirements-list">
                    <li className={passwordValidation.hasMinimumLength ? 'valid' : 'invalid'}>
                      {passwordValidation.hasMinimumLength ? 
                        <FaCheck className="icon-check" /> : 
                        <FaTimes className="icon-times" />}
                      <span>At least 6 characters long</span>
                    </li>
                    
                    <li className={passwordValidation.hasUpperCase ? 'valid' : 'invalid'}>
                      {passwordValidation.hasUpperCase ? 
                        <FaCheck className="icon-check" /> : 
                        <FaTimes className="icon-times" />}
                      <span>At least one uppercase letter</span>
                    </li>
                    
                    <li className={passwordValidation.hasLowerCase ? 'valid' : 'invalid'}>
                      {passwordValidation.hasLowerCase ? 
                        <FaCheck className="icon-check" /> : 
                        <FaTimes className="icon-times" />}
                      <span>At least one lowercase letter</span>
                    </li>
                    
                    <li className={passwordValidation.hasNumber ? 'valid' : 'invalid'}>
                      {passwordValidation.hasNumber ? 
                        <FaCheck className="icon-check" /> : 
                        <FaTimes className="icon-times" />}
                      <span>At least one number</span>
                    </li>
                    
                    <li className={passwordValidation.hasSpecialChar ? 'valid' : 'invalid'}>
                      {passwordValidation.hasSpecialChar ? 
                        <FaCheck className="icon-check" /> : 
                        <FaTimes className="icon-times" />}
                      <span>At least one special character</span>
                    </li>
                  </ul>
                </div>
              )}
            </div>
            
            <div className="register-input-group">
              <label htmlFor="confirmPassword">Confirm Password</label>
              <div className="register-input-wrapper">
                <FaLock className="register-input-icon" />
                <input
                  type={showConfirmPassword ? "text" : "password"}
                  id="confirmPassword"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm your password"
                  disabled={loading}
                />
                <button
                  type="button"
                  className="register-toggle-password"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  tabIndex="-1"
                >
                  {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
                </button>
              </div>
              
              {password && confirmPassword && (
                <div className={`register-password-match ${password === confirmPassword ? 'match' : 'no-match'}`}>
                  {password === confirmPassword ? (
                    <>
                      <FaCheck className="register-match-icon" />
                      <span>Passwords match</span>
                    </>
                  ) : (
                    <>
                      <FaExclamationCircle className="register-match-icon" />
                      <span>Passwords don't match</span>
                    </>
                  )}
                </div>
              )}
            </div>
            
            <div className="register-terms">
              <input
                type="checkbox"
                id="agreeTerms"
                checked={agreeTerms}
                onChange={(e) => setAgreeTerms(e.target.checked)}
                disabled={loading}
              />
              <label htmlFor="agreeTerms">
                I agree to the <Link to="/terms">Terms and Conditions</Link>
              </label>
            </div>
            
            <button
              type="submit"
              className="register-button"
              disabled={loading}
            >
              {loading ? (
                <span className="register-button-loading">
                  <span className="register-spinner"></span>
                  Creating Account...
                </span>
              ) : (
                <span className="register-button-text">
                  Create Account
                  <FaChevronRight className="register-button-icon" />
                </span>
              )}
            </button>
          </form>
          
          <div className="register-separator">
            <span>or sign up with</span>
          </div>
          
          <div className="register-social-buttons">
            <button
              type="button"
              className="register-social-button register-google"
              onClick={() => handleSocialSignUp('Google')}
              disabled={loading}
            >
              <FaGoogle />
              <span>Google</span>
            </button>
            
            <button
              type="button"
              className="register-social-button register-apple"
              onClick={() => handleSocialSignUp('Apple')}
              disabled={loading}
            >
              <FaApple />
              <span>Apple</span>
            </button>
          </div>
          
          <div className="register-login-link">
            <span>Already have an account?</span>
            <Link to="/login">Sign In</Link>
          </div>
        </div>
      </div>
      
      <Footer />
    </div>
  );
};

export default Register;

// src/components/auth/Login.js
import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, Link, useLocation } from 'react-router-dom';
import { loginUser, clearAuthErrors } from '../store/userSlice';
import { 
  FaUser, 
  FaLock, 
  FaGoogle, 
  FaApple, 
  FaEnvelope, 
  FaChevronRight, 
  FaEye, 
  FaEyeSlash,
  FaExclamationCircle,
  FaFingerprint,
  FaCheckCircle
} from 'react-icons/fa';
import Footer from '../../Footer';
import './Login.css';

const Login = () => {
  const [usernameOrEmail, setUsernameOrEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [formError, setFormError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  
  const { loading, error, userId } = useSelector((state) => state.user);
  
  // Clear errors when component mounts or unmounts
  useEffect(() => {
    dispatch(clearAuthErrors());
    
    // Check for success message from registration
    if (location.state && location.state.message) {
      setSuccessMessage(location.state.message);
      // Clear the location state after reading
      window.history.replaceState({}, document.title);
    }
    
    return () => {
      dispatch(clearAuthErrors());
    };
  }, [dispatch, location]);
  
  useEffect(() => {
    // If already logged in, redirect to profile
    if (userId) {
      navigate('/profile');
    }
  }, [userId, navigate]);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError('');
    setSuccessMessage('');
    
    // Basic validation
    if (!usernameOrEmail || !password) {
      setFormError('Please enter both username/email and password');
      return;
    }

    try {
      const resultAction = await dispatch(loginUser({ usernameOrEmail, password }));
      if (loginUser.fulfilled.match(resultAction)) {
        // Login successful, navigation will happen through useEffect
      } else {
        // Handle error from the action
        setFormError(resultAction.payload || 'Login failed. Please try again.');
      }
    } catch (err) {
      setFormError('An error occurred. Please try again.');
    }
  };
  
  const handleSocialLogin = (provider) => {
    setFormError('');
    setSuccessMessage('');
    
    try {
      // Redirect to the backend OAuth route
      window.location.href = `/api/oauth/login/${provider.toLowerCase()}`;
    } catch (err) {
      setFormError(`${provider} login failed. Please try again.`);
    }
  };
  
  return (
    <div className="login-container">
      <div className="login-background">
        <div className="login-grid"></div>
        <div className="login-glow"></div>
      </div>
      
      <div className="login-content">
        <div className="login-card">
          <div className="login-header">
            <div className="login-logo">
              <FaFingerprint className="login-logo-icon" />
            </div>
            <h1 className="login-title">Welcome Back</h1>
            <p className="login-subtitle">Sign in to continue your journey</p>
          </div>
          
          {successMessage && (
            <div className="login-success-message">
              <FaCheckCircle />
              <span>{successMessage}</span>
            </div>
          )}
          
          {(formError || error) && (
            <div className="login-error-message">
              <FaExclamationCircle />
              <span>{formError || error}</span>
            </div>
          )}
          
          <form className="login-form" onSubmit={handleSubmit}>
            <div className="login-input-group">
              <label htmlFor="usernameOrEmail">Username or Email</label>
              <div className="login-input-wrapper">
                <FaUser className="login-input-icon" />
                <input
                  type="text"
                  id="usernameOrEmail"
                  value={usernameOrEmail}
                  onChange={(e) => setUsernameOrEmail(e.target.value)}
                  placeholder="Enter your username or email"
                  disabled={loading}
                />
              </div>
            </div>
            
            <div className="login-input-group">
              <label htmlFor="password">Password</label>
              <div className="login-input-wrapper">
                <FaLock className="login-input-icon" />
                <input
                  type={showPassword ? "text" : "password"}
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  disabled={loading}
                />
                <button
                  type="button"
                  className="login-toggle-password"
                  onClick={() => setShowPassword(!showPassword)}
                  tabIndex="-1"
                >
                  {showPassword ? <FaEyeSlash /> : <FaEye />}
                </button>
              </div>
            </div>
            
            <div className="login-options">
              <div className="login-remember-me">
                <input
                  type="checkbox"
                  id="rememberMe"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  disabled={loading}
                />
                <label htmlFor="rememberMe">Remember me</label>
              </div>
              
              <Link to="/forgot-password" className="login-forgot-password">
                Forgot password?
              </Link>
            </div>
            
            <button
              type="submit"
              className="login-button"
              disabled={loading}
            >
              {loading ? (
                <span className="login-button-loading">
                  <span className="login-spinner"></span>
                  Signing In...
                </span>
              ) : (
                <span className="login-button-text">
                  Sign In
                  <FaChevronRight className="login-button-icon" />
                </span>
              )}
            </button>
          </form>
          
          <div className="login-separator">
            <span>or continue with</span>
          </div>
          
          <div className="login-social-buttons">
            <button
              type="button"
              className="login-social-button login-google"
              onClick={() => handleSocialLogin('Google')}
              disabled={loading}
            >
              <FaGoogle />
              <span>Google</span>
            </button>
            
            <button
              type="button"
              className="login-social-button login-apple"
              onClick={() => handleSocialLogin('Apple')}
              disabled={loading}
            >
              <FaApple />
              <span>Apple</span>
            </button>
          </div>
          
          <div className="login-register-link">
            <span>Don't have an account?</span>
            <Link to="/register">Create Account</Link>
          </div>
        </div>
      </div>
      
      <Footer />
    </div>
  );
};

export default Login;

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { showAchievementToast } from './AchievementToast';
import {
  FaTrophy, FaMedal, FaStar, FaCrown, FaBolt, FaBook, FaBrain,
  FaCheckCircle, FaRegSmile, FaMagic
} from 'react-icons/fa';

// Import the thunks to fetch achievements and shop items
import { fetchAchievements } from './achievementsSlice';
import { fetchShopItems } from './shopSlice';

// Updated icon mapping: removed memory_master, category_perfectionist, subject_specialist,
// subject_finisher, absolute_perfectionist, exam_conqueror. Keep only those we still have:
const iconMapping = {
  test_rookie: FaTrophy,
  accuracy_king: FaMedal,
  bronze_grinder: FaBook,
  silver_scholar: FaStar,
  gold_god: FaCrown,
  platinum_pro: FaMagic,
  walking_encyclopedia: FaBrain,
  redemption_arc: FaBolt,
  coin_collector_5000: FaBook,
  coin_hoarder_10000: FaBook,
  coin_tycoon_50000: FaBook,
  perfectionist_1: FaCheckCircle,
  double_trouble_2: FaCheckCircle,
  error404_failure_not_found: FaCheckCircle,
  level_up_5: FaTrophy,
  mid_tier_grinder_25: FaMedal,
  elite_scholar_50: FaStar,
  ultimate_master_100: FaCrown,
  answer_machine_1000: FaBook,
  knowledge_beast_5000: FaBrain,
  question_terminator: FaBrain,
  test_finisher: FaCheckCircle
};

// Matching color mapping (remove same IDs):
const colorMapping = {
  test_rookie: "#ff5555",
  accuracy_king: "#ffa500",
  bronze_grinder: "#cd7f32",
  silver_scholar: "#c0c0c0",
  gold_god: "#ffd700",
  platinum_pro: "#e5e4e2",
  walking_encyclopedia: "#00fa9a",
  redemption_arc: "#ff4500",
  coin_collector_5000: "#ff69b4",
  coin_hoarder_10000: "#ff1493",
  coin_tycoon_50000: "#ff0000",
  perfectionist_1: "#adff2f",
  double_trouble_2: "#7fff00",
  error404_failure_not_found: "#00ffff",
  level_up_5: "#f08080",
  mid_tier_grinder_25: "#ff8c00",
  elite_scholar_50: "#ffd700",
  ultimate_master_100: "#ff4500",
  answer_machine_1000: "#ff69b4",
  knowledge_beast_5000: "#00fa9a",
  question_terminator: "#ff1493",
  test_finisher: "#adff2f"
};

// Utility function to show toast for newlyUnlocked achievements:
function showNewlyUnlockedAchievements(newlyUnlocked, allAchievements) {
  if (!newlyUnlocked || newlyUnlocked.length === 0) return;
  newlyUnlocked.forEach((achId) => {
    const Icon = iconMapping[achId] ? iconMapping[achId] : FaTrophy;
    const color = colorMapping[achId] || "#fff";

    const foundAch = allAchievements?.find(a => a.achievementId === achId);
    const title = foundAch?.title || `Unlocked ${achId}`;
    const desc = foundAch?.description || 'Achievement Unlocked!';

    showAchievementToast({
      title,
      description: desc,
      icon: Icon ? <Icon /> : null,
      color
    });
  });
}

const initialUserId = localStorage.getItem('userId');

const initialState = {
  userId: initialUserId ? initialUserId : null,
  username: '',
  email: '',
  xp: 0,
  level: 1,
  coins: 0,
  achievements: [],
  xpBoost: 1.0,
  currentAvatar: null,
  nameColor: null,
  purchasedItems: [],
  subscriptionActive: false,
  oauth_provider: null,

  status: 'idle',
  loading: false,
  error: null,
};

// REGISTER
export const registerUser = createAsyncThunk(
  'user/registerUser',
  async (formData, { rejectWithValue, dispatch, getState }) => {
    try {
      const response = await fetch('/api/test/user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Registration failed');
      }
      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// LOGIN
export const loginUser = createAsyncThunk(
  'user/loginUser',
  async (credentials, { rejectWithValue, dispatch, getState }) => {
    try {
      const response = await fetch('/api/test/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }
      // Immediately fetch achievements + shop data after successful login
      dispatch(fetchAchievements());
      dispatch(fetchShopItems());

      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// FETCH USER DATA
export const fetchUserData = createAsyncThunk(
  'user/fetchUserData',
  async (userId, { rejectWithValue, dispatch }) => {
    try {
      const response = await fetch(`/api/test/user/${userId}`);
      if (!response.ok) {
        throw new Error('Failed to fetch user data');
      }
      const data = await response.json();

      // Also fetch achievements + shop items to ensure they're loaded
      dispatch(fetchAchievements());
      dispatch(fetchShopItems());

      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Example of a daily bonus thunk:
export const claimDailyBonus = createAsyncThunk(
  'user/claimDailyBonus',
  async (userId, { rejectWithValue, dispatch, getState }) => {
    try {
      const response = await fetch(`/api/test/user/${userId}/daily-bonus`, {
        method: 'POST'
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || data.error || 'Daily bonus error');
      }
      // If new achievements came back, display them
      if (data.newlyUnlocked && data.newlyUnlocked.length > 0) {
        const allAchs = getState().achievements.all;
        showNewlyUnlockedAchievements(data.newlyUnlocked, allAchs);
      }
      return data; 
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// If you have an "addCoins" route, likewise
export const addCoins = createAsyncThunk(
  'user/addCoins',
  async ({ userId, amount }, { rejectWithValue, dispatch, getState }) => {
    try {
      const res = await fetch(`/api/test/user/${userId}/add-coins`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ coins: amount })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to add coins');
      }
      // Show newly unlocked achievements
      if (data.newlyUnlocked && data.newlyUnlocked.length > 0) {
        const allAchs = getState().achievements.all;
        showNewlyUnlockedAchievements(data.newlyUnlocked, allAchs);
      }
      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

const userSlice = createSlice({
  name: 'user',
  initialState,
  reducers: {
    setCurrentUserId(state, action) {
      state.userId = action.payload;
    },
    logout(state) {
      state.userId = null;
      state.username = '';
      state.email = '';
      state.xp = 0;
      state.level = 1;
      state.coins = 0;
      state.achievements = [];
      state.xpBoost = 1.0;
      state.currentAvatar = null;
      state.nameColor = null;
      state.purchasedItems = [];
      state.subscriptionActive = false;
      state.status = 'idle';
      localStorage.removeItem('userId');
    },
    setXPAndCoins(state, action) {
      const { xp, coins } = action.payload;
      state.xp = xp;
      state.coins = coins;
    },
    // Add this new action:
    clearAuthErrors(state) {
      state.error = null;
    }
  },
  extraReducers: (builder) => {
    builder
      // REGISTER
      .addCase(registerUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(registerUser.fulfilled, (state) => {
        state.loading = false;
        state.error = null;
      })
      .addCase(registerUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // LOGIN
      .addCase(loginUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loginUser.fulfilled, (state, action) => {
        state.loading = false;
        state.error = null;

        const {
          user_id,
          username,
          email,
          coins,
          xp,
          level,
          achievements,
          xpBoost,
          currentAvatar,
          nameColor,
          purchasedItems,
          subscriptionActive,
          password,
          oauth_provider
        } = action.payload;

        state.userId = user_id;
        state.username = username;
        state.email = email || '';
        state.coins = coins || 0;
        state.xp = xp || 0;
        state.level = level || 1;
        state.achievements = achievements || [];
        state.xpBoost = xpBoost !== undefined ? xpBoost : 1.0;
        state.currentAvatar = currentAvatar || null;
        state.nameColor = nameColor || null;
        state.purchasedItems = purchasedItems || [];
        state.subscriptionActive = subscriptionActive || false;
        state.oauth_provider = oauth_provider || null;

        localStorage.setItem('userId', user_id);
      })
      .addCase(loginUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // FETCH USER DATA
      .addCase(fetchUserData.pending, (state) => {
        state.status = 'loading';
      })
      .addCase(fetchUserData.fulfilled, (state, action) => {
        state.status = 'succeeded';
        state.error = null;
        const userDoc = action.payload;

        state.userId = userDoc._id;
        state.username = userDoc.username;
        state.email = userDoc.email || '';
        state.xp = userDoc.xp || 0;
        state.level = userDoc.level || 1;
        state.coins = userDoc.coins || 0;
        state.achievements = userDoc.achievements || [];
        state.xpBoost = userDoc.xpBoost !== undefined ? userDoc.xpBoost : 1.0;
        state.currentAvatar = userDoc.currentAvatar || null;
        state.nameColor = userDoc.nameColor || null;
        state.purchasedItems = userDoc.purchasedItems || [];
        state.subscriptionActive = userDoc.subscriptionActive || false;
        state.oauth_provider = userDoc.oauth_provider || null;
      })
      .addCase(fetchUserData.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      })

      // DAILY BONUS
      .addCase(claimDailyBonus.pending, (state) => {
        state.loading = true;
      })
      .addCase(claimDailyBonus.fulfilled, (state, action) => {
        state.loading = false;
        // Update local user coins/xp if success
        if (action.payload.success) {
          state.coins = action.payload.newCoins;
          state.xp = action.payload.newXP;
        }
      })
      .addCase(claimDailyBonus.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // ADD COINS
      .addCase(addCoins.fulfilled, (state, action) => {
        // If route succeeded, you could do local updates here or re-fetch user
        // For example:
        // state.coins += ...
      });
  },
});

export const { setCurrentUserId, logout, setXPAndCoins, clearAuthErrors } = userSlice.actions;
export default userSlice.reducer;





// src/store/shopSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';

// Async thunk to fetch shop items from the backend
export const fetchShopItems = createAsyncThunk(
  'shop/fetchShopItems',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/test/shop');
      if (!response.ok) {
        throw new Error('Failed to fetch shop items');
      }
      const data = await response.json();
      return data; // Expected to be an array of shop item objects
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

const initialState = {
  items: [],
  status: 'idle', // 'idle' | 'loading' | 'succeeded' | 'failed'
  error: null,
};

const shopSlice = createSlice({
  name: 'shop',
  initialState,
  reducers: {
    // Optionally add reducers for filtering items or updating local shop state
    // e.g., setFilter(state, action) { state.filter = action.payload; }
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchShopItems.pending, (state) => {
        state.status = 'loading';
      })
      .addCase(fetchShopItems.fulfilled, (state, action) => {
        state.status = 'succeeded';
        state.items = action.payload;
      })
      .addCase(fetchShopItems.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      });
  },
});

export default shopSlice.reducer;


// src/store/achievementsSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { registerUser, loginUser, dailyLoginBonus, addXP, addCoins, fetchUserData, logout, setCurrentUserId } from '../store/userSlice';


export const fetchAchievements = createAsyncThunk(
  'achievements/fetchAchievements',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/test/achievements');
      if (!response.ok) throw new Error('Failed to fetch achievements');
      return await response.json();
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

const achievementsSlice = createSlice({
  name: 'achievements',
  initialState: {
    all: [],
    status: 'idle',
    error: null,
    popups: []  // This can be used for temporary popup notifications
  },
  reducers: {
    // If you want to push a new achievement popup (for example, after unlocking an achievement)
    addPopup: (state, action) => {
      state.popups.push(action.payload);
    },
    removePopup: (state) => {
      state.popups.shift();
    }
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchAchievements.pending, (state) => {
        state.status = 'loading';
      })
      .addCase(fetchAchievements.fulfilled, (state, action) => {
        state.all = action.payload;
        state.status = 'succeeded';
      })
      .addCase(fetchAchievements.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      });
  }
});

export const { addPopup, removePopup } = achievementsSlice.actions;
export default achievementsSlice.reducer;


// store.js
import { configureStore } from '@reduxjs/toolkit';
import userReducer from './userSlice';
import shopReducer from './shopSlice';
import achievementsReducer from './achievementsSlice';

export const store = configureStore({
  reducer: {
    user: userReducer,
    shop: shopReducer,
    achievements: achievementsReducer
  }
});



import React, { useEffect, useState, useRef, useCallback } from 'react';
import { useSelector } from 'react-redux';
import { io } from 'socket.io-client';
import './SupportAskAnythingPage.css';
import { 
  FaPaperPlane, 
  FaPlus, 
  FaSync, 
  FaTimes, 
  FaInfoCircle,
  FaRegSmile,
  FaEnvelope,
  FaHourglassHalf,
  FaCommentDots,
  FaCheck,
  FaComments,
  FaCircleNotch,
  FaExclamationTriangle,
  FaCircle,
  FaArrowLeft,
  FaEllipsisH,
  FaUser,
  FaHeadset,
  FaRobot,
  FaCrown,
  FaSignal,
  FaLock,
  FaBolt
} from 'react-icons/fa';

// Keep a single socket instance at module level
let socket = null;

function SupportAskAnythingPage() {
  // Get user ID from Redux
  const userIdFromRedux = useSelector((state) => state.user.userId);
  
  // Thread and message states
  const [threads, setThreads] = useState([]);
  const [selectedThreadId, setSelectedThreadId] = useState(null);
  const [messages, setMessages] = useState([]);
  
  // UI states
  const [newThreadSubject, setNewThreadSubject] = useState('');
  const [userMessage, setUserMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [adminIsTyping, setAdminIsTyping] = useState(false);
  const [showSupportInfoPopup, setShowSupportInfoPopup] = useState(true);
  const [mobileThreadsVisible, setMobileThreadsVisible] = useState(true);
  
  // Loading and error states
  const [loadingThreads, setLoadingThreads] = useState(false);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [error, setError] = useState(null);
  const [socketStatus, setSocketStatus] = useState('disconnected');
  
  // Refs
  const chatEndRef = useRef(null);
  const messageInputRef = useRef(null);
  const processedMessagesRef = useRef(new Set()); // Track processed messages
  
  // Format timestamps
  const formatTimestamp = (ts) => {
    if (!ts) return '';
    const date = new Date(ts);
    
    // If it's today, just show the time
    const today = new Date();
    if (date.toDateString() === today.toDateString()) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    // Otherwise show date and time
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };
  
  // Get thread status icon and color
  const getStatusInfo = (status = 'open') => {
    const s = status.toLowerCase();
    
    if (s.includes('open')) {
      return { icon: <FaCircle />, label: 'Open', className: 'status-open' };
    }
    if (s.includes('pending')) {
      return { icon: <FaHourglassHalf />, label: 'Pending', className: 'status-pending' };
    }
    if (s.includes('resolved')) {
      return { icon: <FaCheck />, label: 'Resolved', className: 'status-resolved' };
    }
    if (s.includes('closed')) {
      return { icon: <FaLock />, label: 'Closed', className: 'status-closed' };
    }
    
    return { icon: <FaCircle />, label: 'Open', className: 'status-open' };
  };
  
  // Scroll to bottom of messages
  const scrollToBottom = useCallback(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, []);
  
  // Helper function to create a message signature for duplicate detection
  const createMessageSignature = (message) => {
    return `${message.sender}:${message.content}:${message.timestamp}`;
  };
  
  //////////////////////////////////////////////////////////////////////////
  // SOCKET SETUP - Initialize once and handle real-time events
  //////////////////////////////////////////////////////////////////////////
  useEffect(() => {
    // Initialize socket if not already done
    if (!socket) {
      console.log('Initializing Socket.IO for support chat...');
      socket = io(window.location.origin, {
        path: '/api/socket.io',
        transports: ['websocket'],
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000
      });
    }
    
    // Socket connection event handlers
    const handleConnect = () => {
      console.log('Support socket connected:', socket.id);
      setSocketStatus('connected');
      
      // Join user's personal room for notifications
      const userId = userIdFromRedux || localStorage.getItem('userId');
      if (userId) {
        socket.emit('join_user_room', { userId });
        console.log(`Joined user room: user_${userId}`);
      }
      
      // Re-join current thread room if there is one
      if (selectedThreadId) {
        socket.emit('join_thread', { threadId: selectedThreadId });
        console.log(`Rejoined thread room on connect: ${selectedThreadId}`);
      }
    };
    
    const handleDisconnect = () => {
      console.log('Support socket disconnected');
      setSocketStatus('disconnected');
    };
    
    const handleConnectError = (err) => {
      console.error('Socket connection error:', err);
      setSocketStatus('error');
    };
    
    const handleNewMessage = (payload) => {
      console.log('Received new_message event:', payload);
      const { threadId, message } = payload;
      
      // Add message to current thread if it's selected
      if (threadId === selectedThreadId) {
        const messageSignature = createMessageSignature(message);
        
        // Only add the message if we haven't processed it before
        if (!processedMessagesRef.current.has(messageSignature)) {
          processedMessagesRef.current.add(messageSignature);
          
          setMessages((prev) => [...prev, message]);
          scrollToBottom();
        } else {
          console.log('Duplicate message detected and ignored:', messageSignature);
        }
      }
      
      // Update thread's lastUpdated time
      setThreads((prev) =>
        prev.map((t) => {
          if (t._id === threadId) {
            return { ...t, lastUpdated: message.timestamp };
          }
          return t;
        })
      );
    };
    
    const handleNewThread = (threadData) => {
      console.log('Received new_thread event:', threadData);
      
      // Add to threads list if not already there
      setThreads((prev) => {
        if (prev.some((t) => t._id === threadData._id)) {
          return prev;
        }
        return [threadData, ...prev];
      });
      
      // Join the thread room
      socket.emit('join_thread', { threadId: threadData._id });
      console.log(`Joined new thread room: ${threadData._id}`);
    };
    
    const handleAdminTyping = (data) => {
      if (data.threadId === selectedThreadId) {
        setAdminIsTyping(true);
      }
    };
    
    const handleAdminStopTyping = (data) => {
      if (data.threadId === selectedThreadId) {
        setAdminIsTyping(false);
      }
    };
    
    // Register socket event listeners
    socket.on('connect', handleConnect);
    socket.on('disconnect', handleDisconnect);
    socket.on('connect_error', handleConnectError);
    socket.on('new_message', handleNewMessage);
    socket.on('new_thread', handleNewThread);
    socket.on('admin_typing', handleAdminTyping);
    socket.on('admin_stop_typing', handleAdminStopTyping);
    
    // If socket is already connected, manually trigger the connect handler
    if (socket.connected) {
      handleConnect();
    }
    
    // Cleanup function to remove event listeners
    return () => {
      socket.off('connect', handleConnect);
      socket.off('disconnect', handleDisconnect);
      socket.off('connect_error', handleConnectError);
      socket.off('new_message', handleNewMessage);
      socket.off('new_thread', handleNewThread);
      socket.off('admin_typing', handleAdminTyping);
      socket.off('admin_stop_typing', handleAdminStopTyping);
    };
  }, [selectedThreadId, userIdFromRedux, scrollToBottom]);
  
  //////////////////////////////////////////////////////////////////////////
  // FETCH THREADS - Get user's support threads on mount
  //////////////////////////////////////////////////////////////////////////
  const fetchUserThreads = useCallback(async () => {
    setLoadingThreads(true);
    setError(null);
    
    try {
      const res = await fetch('/api/support/my-chat', {
        method: 'GET',
        credentials: 'include'
      });
      
      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Failed to load threads');
        }
        
        const threadList = Array.isArray(data) ? data : [];
        setThreads(threadList);
        
        // Join all thread rooms if socket is connected
        if (socket && socket.connected) {
          threadList.forEach((t) => {
            socket.emit('join_thread', { threadId: t._id });
            console.log(`Joined thread room on load: ${t._id}`);
          });
        }
      } else {
        throw new Error('Server returned unexpected response format');
      }
    } catch (err) {
      setError(err.message);
      console.error('Error fetching threads:', err);
    } finally {
      setLoadingThreads(false);
    }
  }, []);
  
  useEffect(() => {
    fetchUserThreads();
  }, [fetchUserThreads]);
  
  //////////////////////////////////////////////////////////////////////////
  // CREATE THREAD - Start a new support thread
  //////////////////////////////////////////////////////////////////////////
  const createNewThread = async () => {
    if (!newThreadSubject.trim()) {
      setError('Please enter a subject for your thread');
      return;
    }
    
    setError(null);
    
    try {
      const res = await fetch('/api/support/my-chat', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject: newThreadSubject.trim() })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to create thread');
      }
      
      // Add new thread to state
      setThreads((prev) => [data, ...prev]);
      setNewThreadSubject('');
      
      // Select the newly created thread
      setSelectedThreadId(data._id);
      setMessages([]);
      
      // On mobile, show the messages panel after creating a thread
      setMobileThreadsVisible(false);
      
      // Join the thread room
      if (socket && socket.connected) {
        socket.emit('join_thread', { threadId: data._id });
        console.log(`Joined new thread: ${data._id}`);
      }
    } catch (err) {
      setError(err.message);
      console.error('Error creating thread:', err);
    }
  };
  
  //////////////////////////////////////////////////////////////////////////
  // SELECT THREAD - Load messages for a thread
  //////////////////////////////////////////////////////////////////////////
  const selectThread = async (threadId) => {
    // Skip if already selected
    if (threadId === selectedThreadId) {
      // On mobile, just toggle to messages view
      setMobileThreadsVisible(false);
      return;
    }
    
    // Leave current thread room if any
    if (selectedThreadId && socket && socket.connected) {
      socket.emit('leave_thread', { threadId: selectedThreadId });
      console.log(`Left thread room: ${selectedThreadId}`);
    }
    
    setSelectedThreadId(threadId);
    setMessages([]);
    setLoadingMessages(true);
    setError(null);
    
    // On mobile, show the messages panel
    setMobileThreadsVisible(false);
    
    // Clear the processed messages set when switching threads
    processedMessagesRef.current.clear();
    
    // Join new thread room
    if (socket && socket.connected) {
      socket.emit('join_thread', { threadId });
      console.log(`Joined thread room: ${threadId}`);
    }
    
    try {
      const res = await fetch(`/api/support/my-chat/${threadId}`, {
        method: 'GET',
        credentials: 'include'
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to load messages');
      }
      
      // Add all loaded messages to the processed messages set
      const loadedMessages = data.messages || [];
      loadedMessages.forEach(msg => {
        processedMessagesRef.current.add(createMessageSignature(msg));
      });
      
      setMessages(loadedMessages);
      scrollToBottom();
      
      // Focus on message input
      if (messageInputRef.current) {
        messageInputRef.current.focus();
      }
    } catch (err) {
      setError(err.message);
      console.error('Error loading thread messages:', err);
    } finally {
      setLoadingMessages(false);
    }
  };
  
  //////////////////////////////////////////////////////////////////////////
  // SEND MESSAGE - Send a message in the current thread
  //////////////////////////////////////////////////////////////////////////
  const sendMessage = async () => {
    if (!selectedThreadId) {
      setError('Please select a thread first');
      return;
    }
    
    if (!userMessage.trim()) {
      return;
    }
    
    setError(null);
    const messageToSend = userMessage.trim();
    
    // Optimistic update for better UX
    const optimisticMessage = {
      sender: 'user',
      content: messageToSend,
      timestamp: new Date().toISOString(),
      optimistic: true
    };
    
    setMessages((prev) => [...prev, optimisticMessage]);
    setUserMessage('');
    scrollToBottom();
    
    // Stop typing indicator
    if (socket && socket.connected && selectedThreadId) {
      socket.emit('user_stop_typing', { threadId: selectedThreadId });
    }
    setIsTyping(false);
    
    try {
      const res = await fetch(`/api/support/my-chat/${selectedThreadId}`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: messageToSend })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to send message');
      }
      
      // Update the thread's last updated time
      setThreads((prev) =>
        prev.map((t) => {
          if (t._id === selectedThreadId) {
            return { ...t, lastUpdated: new Date().toISOString() };
          }
          return t;
        })
      );
      
      // Replace optimistic message with confirmed one by refetching
      loadMessagesForThread(selectedThreadId);
    } catch (err) {
      setError(err.message);
      console.error('Error sending message:', err);
      
      // Remove optimistic message on error
      setMessages((prev) => prev.filter((msg) => !msg.optimistic));
    }
  };
  
  // Load messages for a thread
  const loadMessagesForThread = async (threadId) => {
    try {
      const res = await fetch(`/api/support/my-chat/${threadId}`, {
        credentials: 'include'
      });
      
      const data = await res.json();
      if (res.ok && data.messages) {
        // Clear previous processed messages when explicitly reloading
        processedMessagesRef.current.clear();
        
        // Add all loaded messages to the processed messages set
        data.messages.forEach(msg => {
          processedMessagesRef.current.add(createMessageSignature(msg));
        });
        
        setMessages(data.messages);
        scrollToBottom();
      }
    } catch (err) {
      console.error('Error reloading messages:', err);
    }
  };
  
  //////////////////////////////////////////////////////////////////////////
  // TYPING HANDLERS - Handle user typing events
  //////////////////////////////////////////////////////////////////////////
  const handleTyping = (e) => {
    const val = e.target.value;
    setUserMessage(val);
    
    // Emit typing events
    if (socket && socket.connected && selectedThreadId) {
      if (!isTyping && val.trim().length > 0) {
        socket.emit('user_typing', { threadId: selectedThreadId });
        setIsTyping(true);
      } else if (isTyping && val.trim().length === 0) {
        socket.emit('user_stop_typing', { threadId: selectedThreadId });
        setIsTyping(false);
      }
    }
  };
  
  // Handle message input keydown (for Enter key)
  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };
  
  // Close thread (user-initiated)
  const closeThread = async () => {
    if (!selectedThreadId) return;
    
    if (!window.confirm('Are you sure you want to close this thread?')) {
      return;
    }
    
    try {
      const res = await fetch(`/api/support/my-chat/${selectedThreadId}/close`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: 'Thread closed by user' })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to close thread');
      }
      
      // Update thread status in the list
      setThreads((prev) =>
        prev.map((t) => {
          if (t._id === selectedThreadId) {
            return { ...t, status: 'closed' };
          }
          return t;
        })
      );
      
      // Reload messages to show closure message
      loadMessagesForThread(selectedThreadId);
    } catch (err) {
      setError(err.message);
      console.error('Error closing thread:', err);
    }
  };
  
  // Get selected thread data
  const selectedThread = threads.find(t => t._id === selectedThreadId);
  const isThreadClosed = selectedThread?.status?.toLowerCase() === 'closed';
  
  // Handle back button on mobile
  const handleBackToThreads = () => {
    setMobileThreadsVisible(true);
  };
  
  return (
    <div className="support-container">
      <div className="support-header">
        <h1 className="support-title">
          <FaHeadset className="support-title-icon" />
          Support / Ask Anything
        </h1>
        
        {showSupportInfoPopup && (
          <div className="support-info-banner">
            <div className="support-info-content">
              <FaBolt className="support-info-icon" />
              <span>We typically respond within 1-24 hours (average ~3 hours)</span>
            </div>
            <button 
              className="support-info-close" 
              onClick={() => setShowSupportInfoPopup(false)}
              aria-label="Close information banner"
            >
              <FaTimes />
            </button>
          </div>
        )}
        
        <p className="support-subtitle">
          Ask us anything about exams, this website, or technical issues. We're here to help!
        </p>
      </div>
      
      {error && (
        <div className="support-error-alert">
          <FaExclamationTriangle className="support-error-icon" />
          <span>{error}</span>
          <button 
            onClick={() => setError(null)}
            aria-label="Dismiss error"
            className="support-error-close"
          >
            <FaTimes />
          </button>
        </div>
      )}
      
      <div className="support-connection-status">
        <span className={`status-indicator status-${socketStatus}`}></span>
        <span className="status-text">
          {socketStatus === 'connected' 
            ? 'Real-time connection active' 
            : socketStatus === 'disconnected'
              ? 'Connecting to real-time service...'
              : 'Connection error - messages may be delayed'}
        </span>
      </div>
      
      <div className={`support-layout ${mobileThreadsVisible ? 'show-threads-mobile' : 'show-messages-mobile'}`}>
        {/* THREADS PANEL */}
        <div className="support-threads-panel">
          <div className="threads-header">
            <h2><FaComments className="threads-header-icon" /> Your Conversations</h2>
            <button 
              className="refresh-button" 
              onClick={fetchUserThreads} 
              title="Refresh threads"
              aria-label="Refresh conversations"
            >
              <FaSync />
            </button>
          </div>
          
          <div className="create-thread-form">
            <input
              type="text"
              placeholder="New conversation subject..."
              value={newThreadSubject}
              onChange={(e) => setNewThreadSubject(e.target.value)}
              className="create-thread-input"
              aria-label="New conversation subject"
            />
            <button 
              className="create-thread-button" 
              onClick={createNewThread}
              disabled={!newThreadSubject.trim()}
              aria-label="Create new conversation"
            >
              <FaPlus />
              <span>Create</span>
            </button>
          </div>
          
          <div className="threads-list-container">
            {loadingThreads ? (
              <div className="threads-loading">
                <FaCircleNotch className="loading-icon spin" />
                <span>Loading conversations...</span>
              </div>
            ) : threads.length === 0 ? (
              <div className="threads-empty">
                <FaRegSmile className="empty-icon" />
                <p>No conversations yet</p>
                <p className="empty-hint">Create one to get started</p>
              </div>
            ) : (
              <ul className="threads-list">
                {threads.map((thread) => {
                  const statusInfo = getStatusInfo(thread.status);
                  
                  return (
                    <li 
                      key={thread._id}
                      className={`thread-item ${selectedThreadId === thread._id ? 'thread-item-active' : ''} ${thread.status?.toLowerCase() === 'closed' ? 'thread-item-closed' : ''}`}
                      onClick={() => selectThread(thread._id)}
                    >
                      <div className="thread-item-header">
                        <span className={`thread-status-indicator ${statusInfo.className}`}>
                          {statusInfo.icon}
                        </span>
                        <h3 className="thread-subject">{thread.subject}</h3>
                      </div>
                      <div className="thread-item-footer">
                        <span className={`thread-status ${statusInfo.className}`}>
                          {statusInfo.label}
                        </span>
                        <span className="thread-timestamp">
                          {thread.lastUpdated ? formatTimestamp(thread.lastUpdated) : 'New'}
                        </span>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
        
        {/* MESSAGES PANEL */}
        <div className="support-messages-panel">
          {!selectedThreadId ? (
            <div className="no-thread-selected">
              <FaEnvelope className="no-thread-icon" />
              <h3>No conversation selected</h3>
              <p>Choose a conversation from the list or create a new one</p>
            </div>
          ) : (
            <>
              <div className="messages-header">
                <button 
                  className="messages-back-button"
                  onClick={handleBackToThreads}
                  aria-label="Back to conversations"
                >
                  <FaArrowLeft />
                </button>
                
                <div className="selected-thread-info">
                  {selectedThread && (
                    <>
                      <span className={`selected-thread-status ${getStatusInfo(selectedThread.status).className}`}>
                        {getStatusInfo(selectedThread.status).icon}
                      </span>
                      <h2>{selectedThread.subject}</h2>
                    </>
                  )}
                </div>
                
                <div className="messages-actions">
                  {!isThreadClosed && selectedThread && (
                    <button 
                      className="close-thread-button" 
                      onClick={closeThread}
                      title="Close conversation"
                      aria-label="Close conversation"
                    >
                      <FaLock />
                      <span>Close</span>
                    </button>
                  )}
                </div>
              </div>
              
              <div className="messages-container">
                {loadingMessages ? (
                  <div className="messages-loading">
                    <FaCircleNotch className="loading-icon spin" />
                    <span>Loading messages...</span>
                  </div>
                ) : messages.length === 0 ? (
                  <div className="messages-empty">
                    <FaCommentDots className="empty-messages-icon" />
                    <p>No messages in this conversation yet</p>
                    <p className="empty-hint">Start the conversation by sending a message</p>
                  </div>
                ) : (
                  <div className="messages-list">
                    {messages.map((message, index) => {
                      const isUser = message.sender === 'user';
                      const isSystem = message.sender === 'system';
                      
                      return (
                        <div 
                          key={index}
                          className={`message ${isUser ? 'message-user' : isSystem ? 'message-system' : 'message-admin'}`}
                        >
                          <div className="message-avatar">
                            {isUser ? (
                              <FaUser className="avatar-icon user" />
                            ) : isSystem ? (
                              <FaRobot className="avatar-icon system" />
                            ) : (
                              <FaCrown className="avatar-icon admin" />
                            )}
                          </div>
                          
                          <div className="message-bubble">
                            {!isSystem && (
                              <div className="message-sender">
                                {isUser ? 'You' : 'Support Team'}
                              </div>
                            )}
                            
                            <div className="message-content">
                              {message.content}
                            </div>
                            
                            <div className="message-timestamp">
                              {formatTimestamp(message.timestamp)}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    
                    {adminIsTyping && (
                      <div className="admin-typing-indicator">
                        <FaCrown className="avatar-icon admin" />
                        <div className="typing-bubble">
                          <div className="typing-dots">
                            <span></span>
                            <span></span>
                            <span></span>
                          </div>
                          <span className="typing-text">Support Team is typing...</span>
                        </div>
                      </div>
                    )}
                    
                    <div ref={chatEndRef} />
                  </div>
                )}
              </div>
              
              <div className="message-input-container">
                {isThreadClosed ? (
                  <div className="thread-closed-notice">
                    <FaLock className="thread-closed-icon" />
                    <span>This conversation is closed. You can create a new one if needed.</span>
                  </div>
                ) : (
                  <>
                    <textarea
                      ref={messageInputRef}
                      className="message-input"
                      placeholder="Type your message here..."
                      value={userMessage}
                      onChange={handleTyping}
                      onKeyDown={handleKeyDown}
                      disabled={isThreadClosed}
                      aria-label="Message input"
                      rows={3}
                    />
                    
                    <button 
                      className="send-message-button" 
                      onClick={sendMessage}
                      disabled={!userMessage.trim() || isThreadClosed}
                      aria-label="Send message"
                    >
                      <FaPaperPlane />
                    </button>
                  </>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default SupportAskAnythingPage;


import React, { useState, useEffect, useCallback, useRef } from "react";
import { io } from "socket.io-client";
import "./CrackedAdminDashboard.css";
import {
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from "recharts";

// Icons
import {
  FaHome,
  FaUsers,
  FaClipboardList,
  FaCalendarDay,
  FaHeadset,
  FaChartLine,
  FaHistory,
  FaDatabase,
  FaTerminal,
  FaHeartbeat,
  FaEnvelope,
  FaChevronRight,
  FaChevronDown,
  FaBell,
  FaSync,
  FaSearch,
  FaUserEdit,
  FaTrash,
  FaKey,
  FaPlus,
  FaTimes,
  FaSave,
  FaCheck,
  FaCommentDots,
  FaInfoCircle,
  FaExclamationTriangle,
  FaSpinner,
  FaSignOutAlt,
  FaPaperPlane,
  FaCheckCircle,
  FaBars,
} from "react-icons/fa";

// We keep this as a top-level variable
let adminSocket = null;

function CrackedAdminDashboard() {
  const [activeTab, setActiveTab] = useState("overview");
  const [isNavCollapsed, setIsNavCollapsed] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const chatEndRef = useRef(null);

  /*****************************************
   * OVERVIEW
   *****************************************/
  const [overviewData, setOverviewData] = useState(null);
  const [overviewLoading, setOverviewLoading] = useState(false);
  const [overviewError, setOverviewError] = useState(null);

  const fetchOverview = useCallback(async () => {
    setOverviewLoading(true);
    setOverviewError(null);
    try {
      const res = await fetch("/api/cracked/dashboard", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch dashboard");
      }
      setOverviewData(data);
    } catch (err) {
      setOverviewError(err.message);
    } finally {
      setOverviewLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "overview") {
      fetchOverview();
    }
  }, [activeTab, fetchOverview]);

  /*****************************************
   * PERFORMANCE
   *****************************************/
  const [performanceData, setPerformanceData] = useState(null);
  const [perfLoading, setPerfLoading] = useState(false);
  const [perfError, setPerfError] = useState(null);

  const fetchPerformance = useCallback(async () => {
    setPerfLoading(true);
    setPerfError(null);
    try {
      const res = await fetch("/api/cracked/performance", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch performance metrics");
      }
      setPerformanceData(data);
    } catch (err) {
      setPerfError(err.message);
    } finally {
      setPerfLoading(false);
    }
  }, []);

  // Auto-refresh performance data every 15 seconds to have "real-time" feeling.
  useEffect(() => {
    if (activeTab === "performance") {
      fetchPerformance();
      const interval = setInterval(fetchPerformance, 15000); // 15s refresh
      return () => clearInterval(interval);
    }
  }, [activeTab, fetchPerformance]);

  /*****************************************
   * USERS
   *****************************************/
  const [users, setUsers] = useState([]);
  const [userTotal, setUserTotal] = useState(0);
  const [userSearch, setUserSearch] = useState("");
  const [userPage, setUserPage] = useState(1);
  const [userLimit] = useState(10);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState(null);

  const [editUserId, setEditUserId] = useState(null);
  const [editUserData, setEditUserData] = useState({});

  const fetchUsers = useCallback(async () => {
    setUsersLoading(true);
    setUsersError(null);
    try {
      const params = new URLSearchParams({
        search: userSearch,
        page: userPage.toString(),
        limit: userLimit.toString()
      });
      const res = await fetch(`/api/cracked/users?${params.toString()}`, {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch users");
      }
      setUsers(data.users || []);
      setUserTotal(data.total || 0);
    } catch (err) {
      setUsersError(err.message);
    } finally {
      setUsersLoading(false);
    }
  }, [userSearch, userPage, userLimit]);

  useEffect(() => {
    if (activeTab === "users") {
      fetchUsers();
    }
  }, [activeTab, fetchUsers]);

  const handleUpdateUserField = (field, value) => {
    setEditUserData((prev) => ({ ...prev, [field]: value }));
  };

  const handleUserEdit = (u) => {
    setEditUserId(u._id);
    setEditUserData({
      username: u.username || "",
      coins: u.coins || 0,
      xp: u.xp || 0,
      level: u.level || 1,
      subscriptionActive: !!u.subscriptionActive,
      suspended: !!u.suspended
    });
  };

  const handleUserUpdateSubmit = async () => {
    if (!editUserId) return;
    try {
      const res = await fetch(`/api/cracked/users/${editUserId}`, {
        method: "PUT",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(editUserData)
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to update user");
        return;
      }
      alert("User updated!");
      fetchUsers();
    } catch (err) {
      console.error("User update error:", err);
    } finally {
      setEditUserId(null);
    }
  };

  const handleUserDelete = async (userId) => {
    if (!window.confirm("Are you sure you want to DELETE this user?")) return;
    try {
      const res = await fetch(`/api/cracked/users/${userId}`, {
        method: "DELETE",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to delete user");
        return;
      }
      alert("User deleted successfully.");
      fetchUsers();
    } catch (err) {
      console.error("User delete error:", err);
    }
  };

  // EXTRA: Reset user password
  const handleResetPassword = async (userId) => {
    if (!window.confirm("Reset this user's password to a random token?")) return;
    try {
      const res = await fetch(`/api/cracked/users/${userId}/reset-password`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" }
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to reset password");
        return;
      }
      alert(`Password reset success. New password: ${data.newPassword}`);
    } catch (err) {
      console.error(err);
      alert("Failed to reset password.");
    }
  };

  /*****************************************
   * TEST MANAGEMENT
   *****************************************/
  const [tests, setTests] = useState([]);
  const [testCategory, setTestCategory] = useState("");
  const [testsLoading, setTestsLoading] = useState(false);
  const [testsError, setTestsError] = useState(null);

  const [newTestData, setNewTestData] = useState({
    category: "",
    testId: "",
    testName: "",
    questions: []
  });

  const fetchTests = useCallback(async () => {
    setTestsLoading(true);
    setTestsError(null);
    try {
      const params = new URLSearchParams();
      if (testCategory) {
        params.set("category", testCategory);
      }
      const res = await fetch(`/api/cracked/tests?${params.toString()}`, {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch tests");
      }
      setTests(data);
    } catch (err) {
      setTestsError(err.message);
    } finally {
      setTestsLoading(false);
    }
  }, [testCategory]);

  useEffect(() => {
    if (activeTab === "tests") {
      fetchTests();
    }
  }, [activeTab, fetchTests]);

  const handleCreateTest = async () => {
    try {
      const body = {
        category: newTestData.category,
        testId: Number(newTestData.testId),
        testName: newTestData.testName,
        questions: []
      };
      const res = await fetch("/api/cracked/tests", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to create test");
        return;
      }
      alert("Test created!");
      fetchTests();
      setNewTestData({ category: "", testId: "", testName: "", questions: [] });
    } catch (err) {
      console.error("Create test error:", err);
    }
  };

  const handleDeleteTest = async (testObj) => {
    if (!window.confirm(`Delete test: ${testObj.testName}?`)) return;
    try {
      const res = await fetch(`/api/cracked/tests/${testObj._id}`, {
        method: "DELETE",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to delete test");
        return;
      }
      alert("Test deleted successfully.");
      fetchTests();
    } catch (err) {
      console.error("Delete test error:", err);
    }
  };

  /*****************************************
   * DAILY PBQs
   *****************************************/
  const [dailyList, setDailyList] = useState([]);
  const [dailyLoading, setDailyLoading] = useState(false);
  const [dailyError, setDailyError] = useState(null);

  const [newDaily, setNewDaily] = useState({
    prompt: "",
    dayIndex: "",
    correctIndex: "",
    explanation: ""
  });

  const fetchDailyPBQs = useCallback(async () => {
    setDailyLoading(true);
    setDailyError(null);
    try {
      const res = await fetch("/api/cracked/daily", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch daily PBQs");
      }
      setDailyList(data);
    } catch (err) {
      setDailyError(err.message);
    } finally {
      setDailyLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "daily") {
      fetchDailyPBQs();
    }
  }, [activeTab, fetchDailyPBQs]);

  const handleCreateDaily = async () => {
    try {
      const body = {
        prompt: newDaily.prompt,
        dayIndex: Number(newDaily.dayIndex) || 0,
        correctIndex: Number(newDaily.correctIndex) || 0,
        explanation: newDaily.explanation
      };
      const res = await fetch("/api/cracked/daily", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to create daily PBQ");
        return;
      }
      alert("Daily PBQ created!");
      fetchDailyPBQs();
      setNewDaily({ prompt: "", dayIndex: "", correctIndex: "", explanation: "" });
    } catch (err) {
      console.error("Create daily PBQ error:", err);
    }
  };

  const handleDeleteDaily = async (pbq) => {
    if (!window.confirm(`Delete daily PBQ: ${pbq.prompt}?`)) return;
    try {
      const res = await fetch(`/api/cracked/daily/${pbq._id}`, {
        method: "DELETE",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to delete daily PBQ");
        return;
      }
      alert("Daily PBQ deleted successfully.");
      fetchDailyPBQs();
    } catch (err) {
      console.error("Delete daily PBQ error:", err);
    }
  };

  /*****************************************
   * SUPPORT
   *****************************************/
  const [threads, setThreads] = useState([]);
  const [threadsLoading, setThreadsLoading] = useState(false);
  const [threadsError, setThreadsError] = useState(null);
  const [threadStatusFilter, setThreadStatusFilter] = useState("");
  const [currentThread, setCurrentThread] = useState(null);
  const [adminReply, setAdminReply] = useState("");

  // We store all threads (including messages) so we can do real‐time merges
  const [allThreadMap, setAllThreadMap] = useState({});
  // Show "user is typing" in real time
  const [userIsTyping, setUserIsTyping] = useState(false);

  // Admin create thread for user
  const [adminTargetUserId, setAdminTargetUserId] = useState("");
  const [adminInitialMsg, setAdminInitialMsg] = useState("");

  const fetchThreads = useCallback(async () => {
    setThreadsLoading(true);
    setThreadsError(null);
    try {
      const params = new URLSearchParams();
      if (threadStatusFilter) {
        params.set("status", threadStatusFilter);
      }
      const res = await fetch(`/api/cracked/supportThreads?${params.toString()}`, {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch support threads");
      }
      setThreads(data);
      setCurrentThread(null);

      // Join all threads so we get real-time updates
      if (adminSocket && data.length > 0) {
        data.forEach((th) => {
          adminSocket.emit("join_thread", { threadId: th._id });
        });
      }
    } catch (err) {
      setThreadsError(err.message);
    } finally {
      setThreadsLoading(false);
    }
  }, [threadStatusFilter]);

  // Initialize adminSocket once
  useEffect(() => {
    if (!adminSocket) {
      const socket = io(window.location.origin, {
        path: "/api/socket.io",
        transports: ["websocket"]
      });
      adminSocket = socket;

      socket.on("connect", () => {
        console.log("Admin socket connected:", socket.id);
      });

      socket.on("disconnect", () => {
        console.log("Admin socket disconnected");
      });

      // Listen for new messages across ANY thread
      socket.on("new_message", (payload) => {
        const { threadId, message } = payload;
        setAllThreadMap((prev) => {
          const oldThread = prev[threadId] || { messages: [] };
          const oldMsgs = oldThread.messages;
          return {
            ...prev,
            [threadId]: {
              ...oldThread,
              messages: [...oldMsgs, message]
            }
          };
        });
        // If the currentThread is the same, append
        setCurrentThread((prev) => {
          if (prev && prev._id === threadId) {
            return {
              ...prev,
              messages: [...prev.messages, message]
            };
          }
          return prev;
        });
      });

      // user_typing / user_stop_typing
      socket.on("user_typing", (data) => {
        if (data.threadId && currentThread && currentThread._id === data.threadId) {
          setUserIsTyping(true);
        }
      });
      socket.on("user_stop_typing", (data) => {
        if (data.threadId && currentThread && currentThread._id === data.threadId) {
          setUserIsTyping(false);
        }
      });

      // Admin sees newly created threads in real-time
      socket.on("new_thread", (threadData) => {
        setThreads((prev) => [threadData, ...prev]);
        socket.emit("join_thread", { threadId: threadData._id });
      });
    }
  }, [currentThread]);

  useEffect(() => {
    if (activeTab === "support") {
      fetchThreads();
    }
  }, [activeTab, fetchThreads]);

  const handleViewThread = async (threadId) => {
    try {
      const res = await fetch(`/api/cracked/supportThreads/${threadId}`, {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to get thread");
        return;
      }
      setCurrentThread(data);
      setAdminReply("");
      setUserIsTyping(false);

      // Merge into allThreadMap
      setAllThreadMap((prev) => ({
        ...prev,
        [threadId]: data
      }));

      // Scroll to bottom of chat after a short delay to ensure render
      setTimeout(() => {
        if (chatEndRef.current) {
          chatEndRef.current.scrollIntoView({ behavior: "smooth" });
        }
      }, 100);
    } catch (err) {
      console.error("View thread error:", err);
    }
  };

  const handleReplyToThread = async () => {
    if (!currentThread || !currentThread._id || adminReply.trim() === "") return;
    try {
      const replyMessage = {
        sender: "admin",
        content: adminReply,
        timestamp: new Date().toISOString()
      };

      if (adminSocket) {
        adminSocket.emit("admin_stop_typing", {
          threadId: currentThread._id
        });
      }

      const res = await fetch(`/api/cracked/supportThreads/${currentThread._id}/reply`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: adminReply })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to reply");
        return;
      }

      // Update the local thread data directly
      setCurrentThread((prevThread) => {
        if (!prevThread) return null;
        return {
          ...prevThread,
          messages: [...prevThread.messages, replyMessage]
        };
      });

      // Update allThreadMap as well
      setAllThreadMap((prev) => {
        const oldThread = prev[currentThread._id] || { messages: [] };
        return {
          ...prev,
          [currentThread._id]: {
            ...oldThread,
            messages: [...oldThread.messages, replyMessage]
          }
        };
      });

      setAdminReply("");
      
      // Scroll to bottom of chat
      setTimeout(() => {
        if (chatEndRef.current) {
          chatEndRef.current.scrollIntoView({ behavior: "smooth" });
        }
      }, 100);
    } catch (err) {
      console.error("Reply thread error:", err);
    }
  };

  const handleAdminReplyTyping = (threadId) => {
    if (adminSocket && threadId) {
      adminSocket.emit("admin_typing", { threadId });
    }
  };

  const handleCloseThread = async (threadId) => {
    const resolution = window.prompt("Enter a resolution note:", "Issue resolved.");
    if (resolution === null) return;
    try {
      const res = await fetch(`/api/cracked/supportThreads/${threadId}/close`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ resolution })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to close thread");
        return;
      }
      alert("Thread closed!");
      fetchThreads();
    } catch (err) {
      console.error("Close thread error:", err);
    }
  };

  const handleClearClosedThreads = async () => {
    if (!window.confirm("Are you sure you want to permanently delete all closed threads?")) return;
    try {
      const res = await fetch("/api/cracked/supportThreads/clear-closed", {
        method: "DELETE",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to clear closed threads");
        return;
      }
      alert(data.message || "Closed threads cleared");
      fetchThreads();
    } catch (err) {
      alert("Error clearing closed threads");
    }
  };

  const handleAdminCreateThread = async () => {
    if (!adminTargetUserId) {
      alert("Please enter a valid userId");
      return;
    }
    try {
      const body = {
        userId: adminTargetUserId,
        initialMessage: adminInitialMsg
      };
      const res = await fetch("/api/cracked/supportThreads/createFromAdmin", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to create thread from admin");
        return;
      }
      alert("Created new thread successfully!");
      setAdminTargetUserId("");
      setAdminInitialMsg("");
      fetchThreads();
    } catch (err) {
      console.error(err);
      alert("Error creating admin thread");
    }
  };

  /*****************************************
   * ACTIVITY LOGS
   *****************************************/
  const [activityLogs, setActivityLogs] = useState([]);
  const [activityLoading, setActivityLoading] = useState(false);
  const [activityError, setActivityError] = useState(null);
  
  const fetchActivityLogs = useCallback(async () => {
    setActivityLoading(true);
    setActivityError(null);
    try {
      const res = await fetch("/api/cracked/activity-logs", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch activity logs");
      }
      if (data.logs) {
        setActivityLogs(data.logs);
      }
    } catch (err) {
      setActivityError(err.message);
    } finally {
      setActivityLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "activity") {
      fetchActivityLogs();
    }
  }, [activeTab, fetchActivityLogs]);

  /*****************************************
   * DB LOGS
   *****************************************/
  const [dbLogs, setDbLogs] = useState([]);
  const [dbLogsLoading, setDbLogsLoading] = useState(false);
  const [dbLogsError, setDbLogsError] = useState(null);
  
  const fetchDbLogs = useCallback(async () => {
    setDbLogsLoading(true);
    setDbLogsError(null);
    try {
      const res = await fetch("/api/cracked/db-logs", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch DB logs");
      }
      setDbLogs(data);
    } catch (err) {
      setDbLogsError(err.message);
    } finally {
      setDbLogsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "dbLogs") {
      fetchDbLogs();
    }
  }, [activeTab, fetchDbLogs]);

  /*****************************************
   * DB SHELL
   *****************************************/
  const [dbShellCollection, setDbShellCollection] = useState("");
  const [dbShellFilter, setDbShellFilter] = useState("{}");
  const [dbShellLimit, setDbShellLimit] = useState(5);
  const [dbShellResults, setDbShellResults] = useState([]);
  const [dbShellLoading, setDbShellLoading] = useState(false);
  const [dbShellError, setDbShellError] = useState(null);

  const handleDbShellRead = async () => {
    setDbShellLoading(true);
    setDbShellError(null);
    try {
      const parsedFilter = JSON.parse(dbShellFilter);
      const body = {
        collection: dbShellCollection,
        filter: parsedFilter,
        limit: dbShellLimit
      };
      const res = await fetch("/api/cracked/db-shell/read", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to read database");
      }
      if (Array.isArray(data)) {
        setDbShellResults(data);
      } else {
        setDbShellError(data.error || "Error reading DB");
      }
    } catch (err) {
      setDbShellError(err.message || "JSON filter is invalid or error occurred");
    } finally {
      setDbShellLoading(false);
    }
  };

  /*****************************************
   * HEALTH CHECKS
   *****************************************/
  const [healthChecks, setHealthChecks] = useState([]);
  const [healthLoading, setHealthLoading] = useState(false);
  const [healthError, setHealthError] = useState(null);
  
  const fetchHealthChecks = useCallback(async () => {
    setHealthLoading(true);
    setHealthError(null);
    try {
      const res = await fetch("/api/cracked/health-checks", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch health checks");
      }
      if (Array.isArray(data)) {
        setHealthChecks(data);
      } else if (data.results) {
        setHealthChecks(data.results);
      }
    } catch (err) {
      setHealthError(err.message);
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "healthChecks") {
      fetchHealthChecks();
    }
  }, [activeTab, fetchHealthChecks]);

  /*****************************************
   * NEWSLETTER
   *****************************************/
  const [subscribers, setSubscribers] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [newsletterLoading, setNewsletterLoading] = useState(false);
  const [newsletterError, setNewsletterError] = useState(null);
  const [activeNewsletterTab, setActiveNewsletterTab] = useState("subscribers");
  
  // New campaign form
  const [newCampaign, setNewCampaign] = useState({
    title: "",
    contentHtml: ""
  });
  
  // Current campaign being viewed/edited
  const [currentCampaign, setCurrentCampaign] = useState(null);

  const fetchSubscribers = async () => {
    setNewsletterLoading(true);
    setNewsletterError(null);
    try {
      // This is a placeholder - you'll need to implement this API endpoint
      const res = await fetch("/api/cracked/newsletter/subscribers", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch subscribers");
      }
      setSubscribers(data.subscribers || []);
    } catch (err) {
      setNewsletterError(err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  const fetchCampaigns = async () => {
    setNewsletterLoading(true);
    setNewsletterError(null);
    try {
      // This is a placeholder - you'll need to implement this API endpoint
      const res = await fetch("/api/cracked/newsletter/campaigns", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch campaigns");
      }
      setCampaigns(data.campaigns || []);
    } catch (err) {
      setNewsletterError(err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === "newsletter") {
      if (activeNewsletterTab === "subscribers") {
        fetchSubscribers();
      } else if (activeNewsletterTab === "campaigns") {
        fetchCampaigns();
      }
    }
  }, [activeTab, activeNewsletterTab]);

  const handleCreateCampaign = async () => {
    if (!newCampaign.title || !newCampaign.contentHtml) {
      alert("Please provide both title and content");
      return;
    }
    
    setNewsletterLoading(true);
    try {
      const res = await fetch("/api/cracked/newsletter/create", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newCampaign)
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to create campaign");
      }
      alert("Newsletter campaign created successfully!");
      setNewCampaign({ title: "", contentHtml: "" });
      fetchCampaigns();
    } catch (err) {
      setNewsletterError(err.message);
      alert("Error creating campaign: " + err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  const handleViewCampaign = async (campaignId) => {
    setNewsletterLoading(true);
    try {
      const res = await fetch(`/api/cracked/newsletter/${campaignId}`, { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch campaign");
      }
      setCurrentCampaign(data);
    } catch (err) {
      setNewsletterError(err.message);
      alert("Error viewing campaign: " + err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  const handleSendCampaign = async (campaignId) => {
    if (!window.confirm("Are you sure you want to send this newsletter to all subscribers?")) {
      return;
    }
    
    setNewsletterLoading(true);
    try {
      const res = await fetch(`/api/cracked/newsletter/send/${campaignId}`, {
        method: "POST",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to send campaign");
      }
      alert(`Newsletter sent to ${data.recipientsCount} recipients!`);
      fetchCampaigns();
    } catch (err) {
      setNewsletterError(err.message);
      alert("Error sending campaign: " + err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  /*****************************************
   * TAB SWITCH
   *****************************************/
  const switchTab = (tabName) => {
    setActiveTab(tabName);
    setMobileNavOpen(false);
  };

  /*****************************************
   * LOGOUT 
   *****************************************/
  const handleLogout = async () => {
    try {
      await fetch("/api/cracked/logout", {
        method: "POST",
        credentials: "include"
      });
      window.location.href = "/cracked/login";
    } catch (err) {
      console.error("Logout error:", err);
    }
  };

  /*****************************************
   * HELPER FUNCTIONS
   *****************************************/
  // Format time in a user-friendly way
  const formatTime = (timestamp) => {
    if (!timestamp) return "";
    
    try {
      const date = new Date(timestamp);
      return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      }).format(date);
    } catch (e) {
      return timestamp;
    }
  };

  // For rendering message content
  const renderMessageContent = (content) => {
    // Add URLs as clickable links
    return content.replace(
      /(https?:\/\/[^\s]+)/g, 
      '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>'
    );
  };

  /*****************************************
   * RENDER: OVERVIEW
   *****************************************/
  const renderOverviewTab = () => {
    const COLORS = ['#6543cc', '#ff4c8b', '#2ecc71', '#3498db', '#e67e22'];

    return (
      <div className="admin-tab-content overview-tab">
        <div className="admin-content-header">
          <h2><FaHome /> Dashboard Overview</h2>
          <button className="admin-refresh-btn" onClick={fetchOverview}>
            <FaSync /> Refresh Data
          </button>
        </div>

        {overviewLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading dashboard data...</p>
          </div>
        )}

        {overviewError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {overviewError}
          </div>
        )}

        {overviewData && !overviewLoading && (
          <>
            <div className="admin-stats-grid">
              <div className="admin-stat-card">
                <div className="admin-stat-icon users-icon">
                  <FaUsers />
                </div>
                <div className="admin-stat-content">
                  <h3>User Count</h3>
                  <div className="admin-stat-value">{overviewData.user_count}</div>
                </div>
              </div>

              <div className="admin-stat-card">
                <div className="admin-stat-icon tests-icon">
                  <FaClipboardList />
                </div>
                <div className="admin-stat-content">
                  <h3>Test Attempts</h3>
                  <div className="admin-stat-value">{overviewData.test_attempts_count}</div>
                </div>
              </div>

              <div className="admin-stat-card">
                <div className="admin-stat-icon bonus-icon">
                  <FaCalendarDay />
                </div>
                <div className="admin-stat-content">
                  <h3>Daily Bonus Claims</h3>
                  <div className="admin-stat-value">{overviewData.daily_bonus_claims}</div>
                </div>
              </div>

              <div className="admin-stat-card">
                <div className="admin-stat-icon score-icon">
                  <FaChartLine />
                </div>
                <div className="admin-stat-content">
                  <h3>Avg Test Score</h3>
                  <div className="admin-stat-value">{overviewData.average_test_score_percent}%</div>
                </div>
              </div>
            </div>

            <div className="admin-charts-section">
              <div className="admin-chart-container">
                <h3>Recent Stats (Last 7 Days)</h3>
                {overviewData.recentStats && overviewData.recentStats.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={overviewData.recentStats}>
                      <defs>
                        <linearGradient id="colorDailyBonus" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#2ecc71" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#2ecc71" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="colorTestAttempts" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#6543cc" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#6543cc" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="label" />
                      <YAxis />
                      <CartesianGrid strokeDasharray="3 3" />
                      <Tooltip />
                      <Legend />
                      <Area
                        type="monotone"
                        dataKey="dailyBonus"
                        stroke="#2ecc71"
                        fill="url(#colorDailyBonus)"
                        name="Daily Bonus Claims"
                      />
                      <Area
                        type="monotone"
                        dataKey="testAttempts"
                        stroke="#6543cc"
                        fill="url(#colorTestAttempts)"
                        name="Test Attempts"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="admin-no-data">No chart data available</div>
                )}
              </div>

              <div className="admin-cards-row">
                <div className="admin-metrics-card">
                  <h3>Performance Snapshot</h3>
                  {overviewData.performance_metrics && (
                    <div className="admin-metrics-list">
                      <div className="admin-metric-item">
                        <span className="admin-metric-label">Request Time:</span>
                        <span className="admin-metric-value">
                          {overviewData.performance_metrics.avg_request_time.toFixed(3)}s
                        </span>
                      </div>
                      <div className="admin-metric-item">
                        <span className="admin-metric-label">DB Query Time:</span>
                        <span className="admin-metric-value">
                          {overviewData.performance_metrics.avg_db_query_time_ms}ms
                        </span>
                      </div>
                      <div className="admin-metric-item">
                        <span className="admin-metric-label">Data Transfer:</span>
                        <span className="admin-metric-value">
                          {overviewData.performance_metrics.data_transfer_rate}
                        </span>
                      </div>
                      <div className="admin-metric-item">
                        <span className="admin-metric-label">Throughput:</span>
                        <span className="admin-metric-value">
                          {overviewData.performance_metrics.throughput} req/min
                        </span>
                      </div>
                      <div className="admin-metric-item">
                        <span className="admin-metric-label">Error Rate:</span>
                        <span className="admin-metric-value">
                          {(overviewData.performance_metrics.error_rate * 100).toFixed(2)}%
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                <div className="admin-metrics-card">
                  <h3>System Status</h3>
                  <div className="admin-status-indicators">
                    <div className="admin-status-item">
                      <div className="admin-status-icon green">
                        <FaDatabase />
                      </div>
                      <div className="admin-status-content">
                        <span className="admin-status-name">Database</span>
                        <span className="admin-status-value">Online</span>
                      </div>
                    </div>
                    <div className="admin-status-item">
                      <div className="admin-status-icon green">
                        <FaHeartbeat />
                      </div>
                      <div className="admin-status-content">
                        <span className="admin-status-name">API</span>
                        <span className="admin-status-value">Healthy</span>
                      </div>
                    </div>
                    <div className="admin-status-item">
                      <div className="admin-status-icon green">
                        <FaBell />
                      </div>
                      <div className="admin-status-content">
                        <span className="admin-status-name">Notifications</span>
                        <span className="admin-status-value">Active</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    );
  };

  /*****************************************
   * RENDER: PERFORMANCE
   *****************************************/
  const renderPerformanceTab = () => {
    return (
      <div className="admin-tab-content performance-tab">
        <div className="admin-content-header">
          <h2><FaChartLine /> Performance Metrics</h2>
          <button className="admin-refresh-btn" onClick={fetchPerformance}>
            <FaSync /> Refresh Metrics
          </button>
        </div>

        {perfLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading performance data...</p>
          </div>
        )}

        {perfError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {perfError}
          </div>
        )}

        {performanceData && !perfLoading && (
          <>
            <div className="admin-stats-grid">
              <div className="admin-stat-card">
                <div className="admin-stat-icon req-time-icon">
                  <FaChartLine />
                </div>
                <div className="admin-stat-content">
                  <h3>Request Time</h3>
                  <div className="admin-stat-value">{performanceData.avg_request_time.toFixed(3)}s</div>
                </div>
              </div>

              <div className="admin-stat-card">
                <div className="admin-stat-icon db-time-icon">
                  <FaDatabase />
                </div>
                <div className="admin-stat-content">
                  <h3>DB Query Time</h3>
                  <div className="admin-stat-value">{performanceData.avg_db_query_time_ms}ms</div>
                </div>
              </div>

              <div className="admin-stat-card">
                <div className="admin-stat-icon transfer-icon">
                  <FaDatabase />
                </div>
                <div className="admin-stat-content">
                  <h3>Data Transfer</h3>
                  <div className="admin-stat-value">{performanceData.data_transfer_rate}</div>
                </div>
              </div>

              <div className="admin-stat-card">
                <div className="admin-stat-icon throughput-icon">
                  <FaDatabase />
                </div>
                <div className="admin-stat-content">
                  <h3>Throughput</h3>
                  <div className="admin-stat-value">{performanceData.throughput} req/min</div>
                </div>
              </div>
            </div>

            <div className="admin-charts-grid">
              {/* Chart 1: Request Time */}
              <div className="admin-chart-container">
                <h3>Avg Request Time (Seconds) - Last Hour</h3>
                {Array.isArray(performanceData.history) && performanceData.history.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={performanceData.history}>
                      <defs>
                        <linearGradient id="colorRequestTime" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#6543cc" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#6543cc" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <CartesianGrid strokeDasharray="3 3" />
                      <Tooltip />
                      <Area
                        type="monotone"
                        dataKey="requestTime"
                        stroke="#6543cc"
                        fill="url(#colorRequestTime)"
                        name="Request Time (s)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="admin-no-data">No chart data available</div>
                )}
              </div>

              {/* Chart 2: DB Time */}
              <div className="admin-chart-container">
                <h3>Avg DB Time (ms) - Last Hour</h3>
                {Array.isArray(performanceData.history) && performanceData.history.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={performanceData.history}>
                      <defs>
                        <linearGradient id="colorDbTime" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ff4c8b" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#ff4c8b" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <CartesianGrid strokeDasharray="3 3" />
                      <Tooltip />
                      <Area
                        type="monotone"
                        dataKey="dbTime"
                        stroke="#ff4c8b"
                        fill="url(#colorDbTime)"
                        name="DB Time (ms)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="admin-no-data">No chart data available</div>
                )}
              </div>

              {/* Chart 3: Throughput */}
              <div className="admin-chart-container">
                <h3>Throughput (Requests/Min) - Last Hour</h3>
                {Array.isArray(performanceData.history) && performanceData.history.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={performanceData.history}>
                      <defs>
                        <linearGradient id="colorThroughput" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#2ecc71" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#2ecc71" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <CartesianGrid strokeDasharray="3 3" />
                      <Tooltip />
                      <Area
                        type="monotone"
                        dataKey="throughput"
                        stroke="#2ecc71"
                        fill="url(#colorThroughput)"
                        name="Throughput (req/min)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="admin-no-data">No chart data available</div>
                )}
              </div>

              {/* Chart 4: Error Rate */}
              <div className="admin-chart-container">
                <h3>Error Rate - Last Hour</h3>
                {Array.isArray(performanceData.history) && performanceData.history.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={performanceData.history}>
                      <defs>
                        <linearGradient id="colorErrorRate" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#e74c3c" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#e74c3c" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <CartesianGrid strokeDasharray="3 3" />
                      <Tooltip />
                      <Area
                        type="monotone"
                        dataKey="errorRate"
                        stroke="#e74c3c"
                        fill="url(#colorErrorRate)"
                        name="Error Rate"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="admin-no-data">No chart data available</div>
                )}
              </div>
            </div>
          </>
        )}
      </div>
    );
  };

  /*****************************************
   * RENDER: USERS
   *****************************************/
  const renderUsersTab = () => {
    return (
      <div className="admin-tab-content users-tab">
        <div className="admin-content-header">
          <h2><FaUsers /> User Management</h2>
          <div className="admin-search-row">
            <div className="admin-search-box">
              <FaSearch />
              <input
                type="text"
                placeholder="Search by username or email"
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
              />
            </div>
            <button className="admin-search-btn" onClick={() => { setUserPage(1); fetchUsers(); }}>
              Search
            </button>
          </div>
        </div>

        <div className="admin-pagination">
          <span>Page: {userPage} / {Math.ceil(userTotal / userLimit)} (Total: {userTotal})</span>
          <div className="admin-pagination-controls">
            <button 
              disabled={userPage <= 1} 
              onClick={() => setUserPage((prev) => Math.max(1, prev - 1))}
              className="admin-pagination-btn"
            >
              Previous
            </button>
            <button 
              disabled={userPage >= Math.ceil(userTotal / userLimit)} 
              onClick={() => setUserPage((prev) => prev + 1)}
              className="admin-pagination-btn"
            >
              Next
            </button>
          </div>
        </div>

        {usersLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading users...</p>
          </div>
        )}

        {usersError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {usersError}
          </div>
        )}

        <div className="admin-data-table-container">
          <table className="admin-data-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Coins</th>
                <th>XP</th>
                <th>Level</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isEditing = editUserId === u._id;
                return (
                  <tr key={u._id} className={isEditing ? "editing-row" : ""}>
                    <td>
                      {isEditing ? (
                        <input
                          type="text"
                          value={editUserData.username}
                          onChange={(e) => handleUpdateUserField("username", e.target.value)}
                          className="admin-edit-input"
                        />
                      ) : (
                        u.username
                      )}
                    </td>
                    <td>{u.email}</td>
                    <td>
                      {isEditing ? (
                        <input
                          type="number"
                          value={editUserData.coins}
                          onChange={(e) => handleUpdateUserField("coins", e.target.value)}
                          className="admin-edit-input"
                        />
                      ) : (
                        u.coins
                      )}
                    </td>
                    <td>
                      {isEditing ? (
                        <input
                          type="number"
                          value={editUserData.xp}
                          onChange={(e) => handleUpdateUserField("xp", e.target.value)}
                          className="admin-edit-input"
                        />
                      ) : (
                        u.xp
                      )}
                    </td>
                    <td>
                      {isEditing ? (
                        <input
                          type="number"
                          value={editUserData.level}
                          onChange={(e) => handleUpdateUserField("level", e.target.value)}
                          className="admin-edit-input"
                        />
                      ) : (
                        u.level
                      )}
                    </td>
                    <td>
                      {isEditing ? (
                        <div className="admin-checkbox-wrap">
                          <label>
                            Suspended:
                            <input
                              type="checkbox"
                              checked={!!editUserData.suspended}
                              onChange={(e) => handleUpdateUserField("suspended", e.target.checked)}
                            />
                          </label>
                        </div>
                      ) : (
                        <span className={u.suspended ? "status-suspended" : "status-active"}>
                          {u.suspended ? "Suspended" : "Active"}
                        </span>
                      )}
                    </td>
                    <td>
                      {isEditing ? (
                        <div className="admin-action-buttons">
                          <button 
                            onClick={handleUserUpdateSubmit}
                            className="admin-btn save-btn"
                            title="Save changes"
                          >
                            <FaSave />
                          </button>
                          <button 
                            onClick={() => setEditUserId(null)}
                            className="admin-btn cancel-btn"
                            title="Cancel"
                          >
                            <FaTimes />
                          </button>
                        </div>
                      ) : (
                        <div className="admin-action-buttons">
                          <button 
                            onClick={() => handleUserEdit(u)}
                            className="admin-btn edit-btn"
                            title="Edit user"
                          >
                            <FaUserEdit />
                          </button>
                          <button 
                            onClick={() => handleResetPassword(u._id)}
                            className="admin-btn reset-btn"
                            title="Reset password"
                          >
                            <FaKey />
                          </button>
                          <button 
                            onClick={() => handleUserDelete(u._id)}
                            className="admin-btn delete-btn"
                            title="Delete user"
                          >
                            <FaTrash />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: TESTS
   *****************************************/
  const renderTestsTab = () => {
    return (
      <div className="admin-tab-content tests-tab">
        <div className="admin-content-header">
          <h2><FaClipboardList /> Test Management</h2>
          <div className="admin-filter-row">
            <input
              type="text"
              placeholder="Filter by category (e.g. aplus)"
              value={testCategory}
              onChange={(e) => setTestCategory(e.target.value)}
              className="admin-filter-input"
            />
            <button className="admin-filter-btn" onClick={fetchTests}>
              <FaSearch /> Filter
            </button>
          </div>
        </div>

        <div className="admin-card">
          <h3><FaPlus /> Create New Test</h3>
          <div className="admin-form-grid">
            <div className="admin-form-group">
              <label>Category:</label>
              <input
                type="text"
                value={newTestData.category}
                onChange={(e) => setNewTestData((prev) => ({ ...prev, category: e.target.value }))}
                placeholder="e.g. aplus"
              />
            </div>
            <div className="admin-form-group">
              <label>Test ID:</label>
              <input
                type="text"
                value={newTestData.testId}
                onChange={(e) => setNewTestData((prev) => ({ ...prev, testId: e.target.value }))}
                placeholder="Numeric test ID"
              />
            </div>
            <div className="admin-form-group">
              <label>Test Name:</label>
              <input
                type="text"
                value={newTestData.testName}
                onChange={(e) => setNewTestData((prev) => ({ ...prev, testName: e.target.value }))}
                placeholder="Test name"
              />
            </div>
          </div>
          <div className="admin-form-actions">
            <button className="admin-submit-btn" onClick={handleCreateTest}>
              Create Test
            </button>
          </div>
        </div>

        {testsLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading tests...</p>
          </div>
        )}

        {testsError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {testsError}
          </div>
        )}

        <div className="admin-data-table-container">
          <table className="admin-data-table">
            <thead>
              <tr>
                <th>Category</th>
                <th>Test ID</th>
                <th>Test Name</th>
                <th>Questions</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tests.map((t) => (
                <tr key={t._id}>
                  <td>{t.category}</td>
                  <td>{t.testId}</td>
                  <td>{t.testName || "(Unnamed)"}</td>
                  <td>{t.questions ? t.questions.length : 0}</td>
                  <td>
                    <div className="admin-action-buttons">
                      <button 
                        onClick={() => handleDeleteTest(t)}
                        className="admin-btn delete-btn"
                        title="Delete test"
                      >
                        <FaTrash />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: DAILY
   *****************************************/
  const renderDailyTab = () => {
    return (
      <div className="admin-tab-content daily-tab">
        <div className="admin-content-header">
          <h2><FaCalendarDay /> Daily PBQ Management</h2>
          <button className="admin-refresh-btn" onClick={fetchDailyPBQs}>
            <FaSync /> Refresh
          </button>
        </div>

        <div className="admin-card">
          <h3><FaPlus /> Create New Daily PBQ</h3>
          <div className="admin-form-grid">
            <div className="admin-form-group">
              <label>Prompt:</label>
              <input
                type="text"
                value={newDaily.prompt}
                onChange={(e) => setNewDaily((prev) => ({ ...prev, prompt: e.target.value }))}
                placeholder="Question prompt"
              />
            </div>
            <div className="admin-form-group">
              <label>Day Index:</label>
              <input
                type="text"
                value={newDaily.dayIndex}
                onChange={(e) => setNewDaily((prev) => ({ ...prev, dayIndex: e.target.value }))}
                placeholder="Numeric day index"
              />
            </div>
            <div className="admin-form-group">
              <label>Correct Index:</label>
              <input
                type="text"
                value={newDaily.correctIndex}
                onChange={(e) => setNewDaily((prev) => ({ ...prev, correctIndex: e.target.value }))}
                placeholder="Correct answer index"
              />
            </div>
          </div>
          <div className="admin-form-group full-width">
            <label>Explanation:</label>
            <textarea
              value={newDaily.explanation}
              onChange={(e) => setNewDaily((prev) => ({ ...prev, explanation: e.target.value }))}
              placeholder="Explanation for the correct answer"
              rows={4}
            ></textarea>
          </div>
          <div className="admin-form-actions">
            <button className="admin-submit-btn" onClick={handleCreateDaily}>
              Create Daily PBQ
            </button>
          </div>
        </div>

        {dailyLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading daily PBQs...</p>
          </div>
        )}

        {dailyError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {dailyError}
          </div>
        )}

        <div className="admin-data-table-container">
          <table className="admin-data-table">
            <thead>
              <tr>
                <th>Prompt</th>
                <th>Day Index</th>
                <th>Correct Index</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {dailyList.map((d) => (
                <tr key={d._id}>
                  <td>{d.prompt}</td>
                  <td>{d.dayIndex}</td>
                  <td>{d.correctIndex}</td>
                  <td>
                    <div className="admin-action-buttons">
                      <button 
                        onClick={() => handleDeleteDaily(d)}
                        className="admin-btn delete-btn"
                        title="Delete PBQ"
                      >
                        <FaTrash />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: SUPPORT
   *****************************************/
  const renderSupportTab = () => {
    return (
      <div className="admin-tab-content support-tab">
        <div className="admin-content-header">
          <h2><FaHeadset /> Support Management</h2>
          <div className="admin-filter-row">
            <input
              type="text"
              placeholder="Filter by status (open/closed)"
              value={threadStatusFilter}
              onChange={(e) => setThreadStatusFilter(e.target.value)}
              className="admin-filter-input"
            />
            <button className="admin-filter-btn" onClick={fetchThreads}>
              <FaSearch /> Filter
            </button>
          </div>
        </div>

        {threadsLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading support threads...</p>
          </div>
        )}

        {threadsError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {threadsError}
          </div>
        )}

        <div className="admin-support-container">
          <div className="admin-threads-panel">
            <h3>Support Threads</h3>
            <div className="admin-threads-list">
              {threads.length > 0 ? (
                threads.map((th) => (
                  <div 
                    key={th._id} 
                    className={`admin-thread-item ${th.status === 'closed' ? 'thread-closed' : ''} ${currentThread && currentThread._id === th._id ? 'active-thread' : ''}`}
                    onClick={() => handleViewThread(th._id)}
                  >
                    <div className="admin-thread-info">
                      <div className="admin-thread-subject">{th.subject || "Untitled Thread"}</div>
                      <div className="admin-thread-meta">
                        <span className={`admin-thread-status status-${th.status}`}>
                          {th.status}
                        </span>
                        <span className="admin-thread-date">
                          {formatTime(th.updatedAt)}
                        </span>
                      </div>
                    </div>
                    <div className="admin-thread-actions">
                      {th.status !== "closed" && (
                        <button 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCloseThread(th._id);
                          }}
                          className="admin-btn close-btn"
                          title="Close thread"
                        >
                          <FaTimes />
                        </button>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div className="admin-no-threads">No threads found matching your criteria</div>
              )}
            </div>
            
            <div className="admin-thread-actions-footer">
              <button 
                className="admin-danger-btn" 
                onClick={handleClearClosedThreads}
              >
                <FaTrash /> Clear All Closed Threads
              </button>
            </div>
          </div>

          <div className="admin-chat-panel">
            {currentThread ? (
              <>
                <div className="admin-chat-header">
                  <h3>{currentThread.subject || "Untitled Thread"}</h3>
                  <div className="admin-chat-meta">
                    <span className={`admin-thread-status status-${currentThread.status}`}>
                      {currentThread.status}
                    </span>
                    <span className="admin-thread-date">
                      Created: {formatTime(currentThread.createdAt)}
                    </span>
                  </div>
                </div>

                <div className="admin-chat-messages">
                  {currentThread.messages.length > 0 ? (
                    currentThread.messages.map((msg, idx) => (
                      <div 
                        key={idx} 
                        className={`admin-chat-message ${msg.sender === 'admin' ? 'admin-message' : msg.sender === 'system' ? 'system-message' : 'user-message'}`}
                      >
                        <div className="admin-message-sender">
                          {msg.sender === 'admin' ? 'Admin' : 
                           msg.sender === 'system' ? 'System' : 'User'}
                        </div>
                        <div 
                          className="admin-message-content"
                          dangerouslySetInnerHTML={{ __html: renderMessageContent(msg.content) }}
                        ></div>
                        <div className="admin-message-time">
                          {formatTime(msg.timestamp)}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="admin-empty-chat">No messages yet in this thread</div>
                  )}
                  {userIsTyping && (
                    <div className="admin-typing-indicator">
                      User is typing...
                    </div>
                  )}
                  <div ref={chatEndRef}></div>
                </div>

                {currentThread.status !== "closed" && (
                  <div className="admin-chat-input">
                    <textarea
                      rows={3}
                      placeholder="Type your reply here..."
                      value={adminReply}
                      onChange={(e) => {
                        setAdminReply(e.target.value);
                        handleAdminReplyTyping(currentThread._id);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault();
                          handleReplyToThread();
                        }
                      }}
                    ></textarea>
                    <button 
                      onClick={handleReplyToThread}
                      disabled={adminReply.trim() === ''}
                      className="admin-send-btn"
                    >
                      <FaPaperPlane />
                    </button>
                  </div>
                )}
              </>
            ) : (
              <div className="admin-no-thread-selected">
                <FaCommentDots className="admin-no-thread-icon" />
                <p>Select a thread to view the conversation</p>
              </div>
            )}
          </div>
        </div>

        <div className="admin-card create-thread-card">
          <h3><FaPlus /> Create Thread for User</h3>
          <div className="admin-form-grid">
            <div className="admin-form-group">
              <label>User ID:</label>
              <input
                type="text"
                value={adminTargetUserId}
                onChange={(e) => setAdminTargetUserId(e.target.value)}
                placeholder="Target user ID"
              />
            </div>
            <div className="admin-form-group">
              <label>Initial Message:</label>
              <input
                type="text"
                value={adminInitialMsg}
                onChange={(e) => setAdminInitialMsg(e.target.value)}
                placeholder="Initial message (optional)"
              />
            </div>
          </div>
          <div className="admin-form-actions">
            <button className="admin-submit-btn" onClick={handleAdminCreateThread}>
              Create Thread
            </button>
          </div>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: ACTIVITY LOGS
   *****************************************/
  const renderActivityLogsTab = () => {
    return (
      <div className="admin-tab-content activity-tab">
        <div className="admin-content-header">
          <h2><FaHistory /> Activity & Audit Logs</h2>
          <button className="admin-refresh-btn" onClick={fetchActivityLogs}>
            <FaSync /> Refresh Logs
          </button>
        </div>

        {activityLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading activity logs...</p>
          </div>
        )}

        {activityError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {activityError}
          </div>
        )}

        <div className="admin-data-table-container">
          <table className="admin-data-table">
            <thead>
              <tr>
                <th>Timestamp (EST)</th>
                <th>IP</th>
                <th>User ID</th>
                <th>Success</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {activityLogs.map((log) => (
                <tr key={log._id} className={log.success ? "" : "error-row"}>
                  <td>{log.timestamp}</td>
                  <td>{log.ip}</td>
                  <td>{log.userId || ""}</td>
                  <td>
                    <span className={log.success ? "status-success" : "status-error"}>
                      {log.success ? "Yes" : "No"}
                    </span>
                  </td>
                  <td>{log.reason || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: DB LOGS
   *****************************************/
  const renderDbLogsTab = () => {
    return (
      <div className="admin-tab-content db-logs-tab">
        <div className="admin-content-header">
          <h2><FaDatabase /> Database Query Logs</h2>
          <button className="admin-refresh-btn" onClick={fetchDbLogs}>
            <FaSync /> Refresh Logs
          </button>
        </div>

        {dbLogsLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading database logs...</p>
          </div>
        )}

        {dbLogsError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {dbLogsError}
          </div>
        )}

        <div className="admin-data-table-container">
          <table className="admin-data-table">
            <thead>
              <tr>
                <th>Timestamp (EST)</th>
                <th>Route</th>
                <th>Method</th>
                <th>Duration (ms)</th>
                <th>DB Time (ms)</th>
                <th>Status</th>
                <th>Bytes</th>
              </tr>
            </thead>
            <tbody>
              {dbLogs.map((log, index) => (
                <tr key={log._id || index} className={log.http_status >= 400 ? "error-row" : ""}>
                  <td>{log.timestamp}</td>
                  <td>{log.route}</td>
                  <td>{log.method}</td>
                  <td>{log.duration_ms}</td>
                  <td>{log.db_time_ms}</td>
                  <td>
                    <span className={log.http_status >= 400 ? "status-error" : "status-success"}>
                      {log.http_status}
                    </span>
                  </td>
                  <td>{log.response_bytes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: DB SHELL
   *****************************************/
  const renderDbShellTab = () => {
    return (
      <div className="admin-tab-content db-shell-tab">
        <div className="admin-content-header">
          <h2><FaTerminal /> Database Shell</h2>
        </div>

        <div className="admin-card">
          <h3><FaDatabase /> Read-Only Database Query</h3>
          <div className="admin-form-grid">
            <div className="admin-form-group">
              <label>Collection:</label>
              <input
                type="text"
                value={dbShellCollection}
                onChange={(e) => setDbShellCollection(e.target.value)}
                placeholder="Collection name"
              />
            </div>
            <div className="admin-form-group">
              <label>Filter (JSON):</label>
              <input
                type="text"
                value={dbShellFilter}
                onChange={(e) => setDbShellFilter(e.target.value)}
                placeholder='e.g. {"username": "test"}'
              />
            </div>
            <div className="admin-form-group">
              <label>Limit:</label>
              <input
                type="number"
                value={dbShellLimit}
                onChange={(e) => setDbShellLimit(e.target.valueAsNumber)}
                min={1}
                max={100}
              />
            </div>
          </div>
          <div className="admin-form-actions">
            <button 
              className="admin-submit-btn" 
              onClick={handleDbShellRead}
              disabled={dbShellLoading}
            >
              {dbShellLoading ? (
                <><FaSpinner className="admin-spinner" /> Executing...</>
              ) : (
                <>Execute Query</>
              )}
            </button>
          </div>
        </div>

        {dbShellError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {dbShellError}
          </div>
        )}

        <div className="admin-shell-results">
          <h3>Query Results</h3>
          <pre>{JSON.stringify(dbShellResults, null, 2)}</pre>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: HEALTH CHECKS
   *****************************************/
  const renderHealthChecksTab = () => {
    return (
      <div className="admin-tab-content health-checks-tab">
        <div className="admin-content-header">
          <h2><FaHeartbeat /> API Health Monitoring</h2>
          <button className="admin-refresh-btn" onClick={fetchHealthChecks}>
            <FaSync /> Refresh Health Checks
          </button>
        </div>

        {healthLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading health checks...</p>
          </div>
        )}

        {healthError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {healthError}
          </div>
        )}

        <div className="admin-stats-grid">
          <div className="admin-stat-card">
            <div className="admin-stat-icon health-icon">
              <FaHeartbeat />
            </div>
            <div className="admin-stat-content">
              <h3>API Status</h3>
              <div className="admin-stat-value status-success">Operational</div>
            </div>
          </div>

          <div className="admin-stat-card">
            <div className="admin-stat-icon db-icon">
              <FaDatabase />
            </div>
            <div className="admin-stat-content">
              <h3>Database</h3>
              <div className="admin-stat-value status-success">Connected</div>
            </div>
          </div>

          <div className="admin-stat-card">
            <div className="admin-stat-icon endpoints-icon">
              <FaCheckCircle />
            </div>
            <div className="admin-stat-content">
              <h3>Endpoints</h3>
              <div className="admin-stat-value">{healthChecks.length || 0} Monitored</div>
            </div>
          </div>

          <div className="admin-stat-card">
            <div className="admin-stat-icon time-icon">
              <FaHistory />
            </div>
            <div className="admin-stat-content">
              <h3>Last Check</h3>
              <div className="admin-stat-value">
                {healthChecks.length > 0 && healthChecks[0].checkedAt ? 
                  formatTime(healthChecks[0].checkedAt) : 
                  "No data"
                }
              </div>
            </div>
          </div>
        </div>

        <div className="admin-data-table-container">
          <table className="admin-data-table">
            <thead>
              <tr>
                <th>Checked At (EST)</th>
                <th>Endpoint</th>
                <th>Status</th>
                <th>OK</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {Array.isArray(healthChecks) && healthChecks.map((hc, idx) => {
                if (hc.results) {
                  // multi results block
                  return hc.results.map((r, j) => (
                    <tr key={`${hc._id}_${j}`} className={r.ok ? "" : "error-row"}>
                      <td>{hc.checkedAt}</td>
                      <td>{r.endpoint}</td>
                      <td>{r.status}</td>
                      <td>
                        <span className={r.ok ? "status-success" : "status-error"}>
                          {r.ok ? "Yes" : "No"}
                        </span>
                      </td>
                      <td>{r.error || ""}</td>
                    </tr>
                  ));
                } else {
                  // single item doc
                  return (
                    <tr key={idx} className={hc.ok ? "" : "error-row"}>
                      <td>{hc.checkedAt}</td>
                      <td>{hc.endpoint}</td>
                      <td>{hc.status}</td>
                      <td>
                        <span className={hc.ok ? "status-success" : "status-error"}>
                          {hc.ok ? "Yes" : "No"}
                        </span>
                      </td>
                      <td>{hc.error || ""}</td>
                    </tr>
                  );
                }
              })}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: NEWSLETTER
   *****************************************/
  const renderNewsletterTab = () => {
    return (
      <div className="admin-tab-content newsletter-tab">
        <div className="admin-content-header">
          <h2><FaEnvelope /> Newsletter Management</h2>
        </div>

        <div className="admin-newsletter-tabs">
          <button 
            className={activeNewsletterTab === "subscribers" ? "active" : ""}
            onClick={() => setActiveNewsletterTab("subscribers")}
          >
            Subscribers
          </button>
          <button 
            className={activeNewsletterTab === "campaigns" ? "active" : ""}
            onClick={() => setActiveNewsletterTab("campaigns")}
          >
            Campaigns
          </button>
          <button 
            className={activeNewsletterTab === "create" ? "active" : ""}
            onClick={() => setActiveNewsletterTab("create")}
          >
            Create New
          </button>
        </div>

        {newsletterLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading newsletter data...</p>
          </div>
        )}

        {newsletterError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {newsletterError}
          </div>
        )}

        {/* Subscribers Tab */}
        {activeNewsletterTab === "subscribers" && (
          <div className="admin-newsletter-content">
            <div className="admin-card">
              <h3><FaUsers /> Email Subscribers</h3>
              <button className="admin-refresh-btn" onClick={fetchSubscribers}>
                <FaSync /> Refresh List
              </button>

              {subscribers.length > 0 ? (
                <div className="admin-data-table-container">
                  <table className="admin-data-table">
                    <thead>
                      <tr>
                        <th>Email</th>
                        <th>Subscribed At</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {subscribers.map((sub, index) => (
                        <tr key={sub._id || index}>
                          <td>{sub.email}</td>
                          <td>{formatTime(sub.subscribedAt)}</td>
                          <td>
                            <span className={sub.unsubscribed ? "status-inactive" : "status-active"}>
                              {sub.unsubscribed ? "Unsubscribed" : "Active"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="admin-no-data">
                  <p>No subscribers found. You can refresh the list or check back later.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Campaigns Tab */}
        {activeNewsletterTab === "campaigns" && (
          <div className="admin-newsletter-content">
            <div className="admin-card">
              <h3><FaEnvelope /> Newsletter Campaigns</h3>
              <button className="admin-refresh-btn" onClick={fetchCampaigns}>
                <FaSync /> Refresh List
              </button>

              {campaigns.length > 0 ? (
                <div className="admin-data-table-container">
                  <table className="admin-data-table">
                    <thead>
                      <tr>
                        <th>Title</th>
                        <th>Created At</th>
                        <th>Status</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {campaigns.map((campaign, index) => (
                        <tr key={campaign._id || index}>
                          <td>{campaign.title}</td>
                          <td>{formatTime(campaign.createdAt)}</td>
                          <td>
                            <span className={campaign.status === "sent" ? "status-success" : "status-waiting"}>
                              {campaign.status}
                            </span>
                          </td>
                          <td>
                            <div className="admin-action-buttons">
                              <button 
                                onClick={() => handleViewCampaign(campaign._id)}
                                className="admin-btn view-btn"
                                title="View campaign"
                              >
                                <FaInfoCircle />
                              </button>
                              {campaign.status !== "sent" && (
                                <button 
                                  onClick={() => handleSendCampaign(campaign._id)}
                                  className="admin-btn send-btn"
                                  title="Send campaign"
                                >
                                  <FaPaperPlane />
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="admin-no-data">
                  <p>No campaigns found. You can create a new campaign from the "Create New" tab.</p>
                </div>
              )}
            </div>

            {currentCampaign && (
              <div className="admin-card">
                <div className="admin-card-header">
                  <h3>{currentCampaign.title}</h3>
                  <button 
                    className="admin-close-btn"
                    onClick={() => setCurrentCampaign(null)}
                  >
                    <FaTimes />
                  </button>
                </div>
                <div className="admin-campaign-details">
                  <div className="admin-campaign-meta">
                    <div><strong>Created:</strong> {formatTime(currentCampaign.createdAt)}</div>
                    <div><strong>Status:</strong> {currentCampaign.status}</div>
                    {currentCampaign.sentAt && (
                      <div><strong>Sent At:</strong> {formatTime(currentCampaign.sentAt)}</div>
                    )}
                  </div>
                  <div className="admin-campaign-preview">
                    <h4>HTML Content Preview:</h4>
                    <div className="admin-html-preview">
                      <div dangerouslySetInnerHTML={{ __html: currentCampaign.contentHtml }}></div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Create New Campaign Tab */}
        {activeNewsletterTab === "create" && (
          <div className="admin-newsletter-content">
            <div className="admin-card">
              <h3><FaPlus /> Create New Newsletter Campaign</h3>
              <div className="admin-form-group">
                <label>Campaign Title:</label>
                <input
                  type="text"
                  value={newCampaign.title}
                  onChange={(e) => setNewCampaign({ ...newCampaign, title: e.target.value })}
                  placeholder="Enter newsletter title"
                />
              </div>
              <div className="admin-form-group">
                <label>HTML Content:</label>
                <textarea
                  value={newCampaign.contentHtml}
                  onChange={(e) => setNewCampaign({ ...newCampaign, contentHtml: e.target.value })}
                  placeholder="Enter newsletter HTML content"
                  rows={10}
                ></textarea>
              </div>
              <div className="admin-form-actions">
                <button 
                  className="admin-submit-btn" 
                  onClick={handleCreateCampaign}
                  disabled={!newCampaign.title || !newCampaign.contentHtml || newsletterLoading}
                >
                  {newsletterLoading ? (
                    <><FaSpinner className="admin-spinner" /> Creating...</>
                  ) : (
                    <>Create Campaign</>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  /*****************************************
   * MAIN RENDER
   *****************************************/
  return (
    <div className={`admin-dashboard ${isNavCollapsed ? 'nav-collapsed' : ''}`}>
              <div className="admin-sidebar">
        <div className="admin-sidebar-header">
          <div className="admin-logo">
            <FaDatabase />
            <h1>Admin</h1>
          </div>
          <button 
            className="admin-collapse-btn"
            onClick={() => setIsNavCollapsed(!isNavCollapsed)}
            title={isNavCollapsed ? "Expand Navigation" : "Collapse Navigation"}
          >
            {isNavCollapsed ? <FaChevronRight /> : <FaChevronDown />}
          </button>
        </div>
        
        <nav className="admin-nav">
          <ul className="admin-nav-list">
            <li className={activeTab === "overview" ? "active" : ""}>
              <button onClick={() => switchTab("overview")}>
                <FaHome />
                <span>Dashboard</span>
              </button>
            </li>
            <li className={activeTab === "users" ? "active" : ""}>
              <button onClick={() => switchTab("users")}>
                <FaUsers />
                <span>Users</span>
              </button>
            </li>
            <li className={activeTab === "tests" ? "active" : ""}>
              <button onClick={() => switchTab("tests")}>
                <FaClipboardList />
                <span>Tests</span>
              </button>
            </li>
            <li className={activeTab === "daily" ? "active" : ""}>
              <button onClick={() => switchTab("daily")}>
                <FaCalendarDay />
                <span>Daily PBQs</span>
              </button>
            </li>
            <li className={activeTab === "support" ? "active" : ""}>
              <button onClick={() => switchTab("support")}>
                <FaHeadset />
                <span>Support</span>
              </button>
            </li>
            <li className={activeTab === "newsletter" ? "active" : ""}>
              <button onClick={() => switchTab("newsletter")}>
                <FaEnvelope />
                <span>Newsletter</span>
              </button>
            </li>
            <li className={activeTab === "performance" ? "active" : ""}>
              <button onClick={() => switchTab("performance")}>
                <FaChartLine />
                <span>Performance</span>
              </button>
            </li>
            <li className={activeTab === "activity" ? "active" : ""}>
              <button onClick={() => switchTab("activity")}>
                <FaHistory />
                <span>Activity</span>
              </button>
            </li>
            <li className={activeTab === "dbLogs" ? "active" : ""}>
              <button onClick={() => switchTab("dbLogs")}>
                <FaDatabase />
                <span>DB Logs</span>
              </button>
            </li>
            <li className={activeTab === "dbShell" ? "active" : ""}>
              <button onClick={() => switchTab("dbShell")}>
                <FaTerminal />
                <span>DB Shell</span>
              </button>
            </li>
            <li className={activeTab === "healthChecks" ? "active" : ""}>
              <button onClick={() => switchTab("healthChecks")}>
                <FaHeartbeat />
                <span>Health Checks</span>
              </button>
            </li>
          </ul>
        </nav>
        
        <div className="admin-sidebar-footer">
          <button className="admin-logout-btn" onClick={handleLogout}>
            <FaSignOutAlt />
            <span>Logout</span>
          </button>
        </div>
      </div>
      
      {/* Mobile Header with menu toggle */}
      <div className="admin-mobile-header">
        <button 
          className="admin-mobile-menu-toggle"
          onClick={() => setMobileNavOpen(!mobileNavOpen)}
        >
          {mobileNavOpen ? <FaTimes /> : <FaBars />}
        </button>
        <div className="admin-mobile-logo">
          <FaDatabase />
          <h1>Admin Dashboard</h1>
        </div>
      </div>
      
      {/* Mobile Navigation Overlay */}
      <div className={`admin-mobile-nav ${mobileNavOpen ? 'active' : ''}`}>
        <nav>
          <ul>
            <li>
              <button onClick={() => switchTab("overview")}>
                <FaHome /> Dashboard
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("users")}>
                <FaUsers /> Users
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("tests")}>
                <FaClipboardList /> Tests
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("daily")}>
                <FaCalendarDay /> Daily PBQs
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("support")}>
                <FaHeadset /> Support
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("newsletter")}>
                <FaEnvelope /> Newsletter
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("performance")}>
                <FaChartLine /> Performance
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("activity")}>
                <FaHistory /> Activity
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("dbLogs")}>
                <FaDatabase /> DB Logs
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("dbShell")}>
                <FaTerminal /> DB Shell
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("healthChecks")}>
                <FaHeartbeat /> Health Checks
              </button>
            </li>
            <li>
              <button onClick={handleLogout} className="mobile-logout-btn">
                <FaSignOutAlt /> Logout
              </button>
            </li>
          </ul>
        </nav>
      </div>
      
      {/* Main Content Area */}
      <div className="admin-main-content">
        {/* Active Tab Content */}
        {activeTab === "overview" && renderOverviewTab()}
        {activeTab === "users" && renderUsersTab()}
        {activeTab === "tests" && renderTestsTab()}
        {activeTab === "daily" && renderDailyTab()}
        {activeTab === "support" && renderSupportTab()}
        {activeTab === "newsletter" && renderNewsletterTab()}
        {activeTab === "performance" && renderPerformanceTab()}
        {activeTab === "activity" && renderActivityLogsTab()}
        {activeTab === "dbLogs" && renderDbLogsTab()}
        {activeTab === "dbShell" && renderDbShellTab()}
        {activeTab === "healthChecks" && renderHealthChecksTab()}
      </div>
    </div>
  );
}

export default CrackedAdminDashboard;


KEEP IN MIND THATS JUST A FEW OF MY KEY FILES



NOW HERE ARE A FEW REAL KEY FILES FOR MY BACKEND

from flask import Blueprint, request, jsonify, session, g  # <-- Added g here for DB time measurement
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import pytz
import time
from mongodb.database import db

# Mongo collections
from mongodb.database import (
    mainusers_collection,
    shop_collection,
    achievements_collection,
    tests_collection,
    testAttempts_collection,
    correctAnswers_collection,
    dailyQuestions_collection,
    dailyAnswers_collection
)

# Models
from models.test import (
    get_user_by_identifier,
    create_user,
    get_user_by_id,
    update_user_coins,
    update_user_xp,
    apply_daily_bonus,
    get_shop_items,
    purchase_item,
    get_achievements,
    get_test_by_id_and_category,
    validate_username,
    validate_email,
    validate_password,
    update_user_fields,
    get_user_by_id,
    award_correct_answers_in_bulk
)

api_bp = Blueprint('test', __name__)
public_leaderboard_bp = Blueprint('public_leaderboard', __name__)
#############################################
# Leaderboard Caching Setup (15-second TTL)
#############################################
leaderboard_cache = []
leaderboard_cache_timestamp = 0
LEADERBOARD_CACHE_DURATION_MS = 15000  # 15 seconds

def serialize_user(user):
    """Helper to convert _id, etc. to strings if needed."""
    if not user:
        return None
    user['_id'] = str(user['_id'])
    if 'currentAvatar' in user and user['currentAvatar']:
        user['currentAvatar'] = str(user['currentAvatar'])
    if 'purchasedItems' in user and isinstance(user['purchasedItems'], list):
        user['purchasedItems'] = [str(item) for item in user['purchasedItems']]
    return user

def serialize_datetime(dt):
    """Helper: convert a datetime to an ISO string (or return None)."""
    return dt.isoformat() if dt else None



def check_and_unlock_achievements(user_id):
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return []

    counters = user.get("achievement_counters", {})
    unlocked = set(user.get("achievements", []))
    newly_unlocked = []

    start_db = time.time()
    all_ach = list(achievements_collection.find({}))  # or get_achievements()
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    for ach in all_ach:
        aid = ach["achievementId"]
        # If already unlocked, skip
        if aid in unlocked:
            continue

        crit = ach.get("criteria", {})

        # 1) testCount => total_tests_completed
        test_count_req = crit.get("testCount")
        if test_count_req is not None:
            if counters.get("total_tests_completed", 0) >= test_count_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 2) minScore => e.g. "accuracy_king" with 90
        min_score_req = crit.get("minScore")
        if min_score_req is not None:
            if counters.get("highest_score_ever", 0) >= min_score_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 3) perfectTests => e.g. "perfectionist_1", "double_trouble_2", etc.
        perfect_req = crit.get("perfectTests")
        if perfect_req is not None:
            if counters.get("perfect_tests_count", 0) >= perfect_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 4) coins => coin achievements
        coin_req = crit.get("coins")
        if coin_req is not None:
            if user.get("coins", 0) >= coin_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 5) level => e.g. "level_up_5", "mid_tier_grinder_25", etc.
        level_req = crit.get("level")
        if level_req is not None:
            if user.get("level", 1) >= level_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 6) totalQuestions => e.g. "answer_machine_1000"
        total_q_req = crit.get("totalQuestions")
        if total_q_req is not None:
            if counters.get("total_questions_answered", 0) >= total_q_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 7) perfectTestsInCategory => "category_perfectionist"
        perfect_in_cat_req = crit.get("perfectTestsInCategory")
        if perfect_in_cat_req is not None:
            perfect_by_cat = counters.get("perfect_tests_by_category", {})
            for cat_name, cat_count in perfect_by_cat.items():
                if cat_count >= perfect_in_cat_req:
                    unlocked.add(aid)
                    newly_unlocked.append(aid)
                    break
            continue

        # 8) redemption_arc => minScoreBefore + minScoreAfter
        min_before = crit.get("minScoreBefore")
        min_after = crit.get("minScoreAfter")
        if min_before is not None and min_after is not None:
            if (counters.get("lowest_score_ever", 100) <= min_before and
                counters.get("highest_score_ever", 0) >= min_after):
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 9) testsCompletedInCategory => "subject_finisher"
        cat_required = crit.get("testsCompletedInCategory")
        if cat_required is not None:
            tcbc = counters.get("tests_completed_by_category", {})
            for cat_name, test_set in tcbc.items():
                if len(test_set) >= cat_required:
                    unlocked.add(aid)
                    newly_unlocked.append(aid)
                    break
            continue

        # 10) allTestsCompleted => "test_finisher"
        if crit.get("allTestsCompleted"):
            user_completed_tests = counters.get("tests_completed_set", set())
            TOTAL_TESTS = 130
            if len(user_completed_tests) >= TOTAL_TESTS:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

    if newly_unlocked:
        start_db = time.time()
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"achievements": list(unlocked)}}
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    return newly_unlocked


# -------------------------------------------------------------------
# USER ROUTES
# -------------------------------------------------------------------
@api_bp.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404
    user = serialize_user(user)
    if "password" not in user:
        user["password"] = user.get("password")
    return jsonify(user), 200

@api_bp.route('/user', methods=['POST'])
def register_user():
    """
    Registration: /api/user
    Expects {username, email, password, confirmPassword} in JSON
    Calls create_user, returns {message, user_id} or error.
    """
    user_data = request.json or {}
    try:
        user_data.setdefault("achievement_counters", {
            "total_tests_completed": 0,
            "perfect_tests_count": 0,
            "perfect_tests_by_category": {},
            "highest_score_ever": 0.0,
            "lowest_score_ever": 100.0,
            "total_questions_answered": 0,
        })

        start_db = time.time()
        user_id = create_user(user_data)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"message": "User created", "user_id": str(user_id)}), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@api_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        start_db = time.time()
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": None,
            "ip": request.remote_addr or "unknown",
            "success": False,
            "reason": "No JSON data provided"
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"error": "No JSON data provided"}), 400

    identifier = data.get("usernameOrEmail")
    password = data.get("password")
    if not identifier or not password:
        start_db = time.time()
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": None,
            "ip": request.remote_addr or "unknown",
            "success": False,
            "reason": "Missing username/password"
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"error": "Username (or Email) and password are required"}), 400

    start_db = time.time()
    user = get_user_by_identifier(identifier)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user or user.get("password") != password:
        start_db = time.time()
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": None,
            "ip": request.remote_addr or "unknown",
            "success": False,
            "reason": "Invalid username or password"
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"error": "Invalid username or password"}), 401

    session['userId'] = str(user["_id"])

    start_db = time.time()
    db.auditLogs.insert_one({
        "timestamp": datetime.utcnow(),
        "userId": user["_id"],
        "ip": request.remote_addr or "unknown",
        "success": True
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    user = serialize_user(user)

    return jsonify({
        "user_id": user["_id"],
        "username": user["username"],
        "email": user.get("email", ""),
        "coins": user.get("coins", 0),
        "xp": user.get("xp", 0),
        "level": user.get("level", 1),
        "achievements": user.get("achievements", []),
        "xpBoost": user.get("xpBoost", 1.0),
        "currentAvatar": user.get("currentAvatar"),
        "nameColor": user.get("nameColor"),
        "purchasedItems": user.get("purchasedItems", []),
        "subscriptionActive": user.get("subscriptionActive", False),
        "password": user.get("password")
    }), 200

@api_bp.route('/user/<user_id>/add-xp', methods=['POST'])
def add_xp_route(user_id):
    data = request.json or {}
    xp_to_add = data.get("xp", 0)

    start_db = time.time()
    updated = update_user_xp(user_id, xp_to_add)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not updated:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    new_achievements = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    updated["newAchievements"] = new_achievements
    return jsonify(updated), 200

@api_bp.route('/user/<user_id>/add-coins', methods=['POST'])
def add_coins_route(user_id):
    data = request.json or {}
    coins_to_add = data.get("coins", 0)

    start_db = time.time()
    update_user_coins(user_id, coins_to_add)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    newly_unlocked = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({
        "message": "Coins updated",
        "newlyUnlocked": newly_unlocked
    }), 200

# -------------------------------------------------------------------
# SHOP ROUTES
# -------------------------------------------------------------------
@api_bp.route('/shop', methods=['GET'])
def fetch_shop():
    start_db = time.time()
    items = get_shop_items()
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    for item in items:
        item["_id"] = str(item["_id"])
    return jsonify(items), 200

@api_bp.route('/shop/purchase/<item_id>', methods=['POST'])
def purchase_item_route(item_id):
    data = request.json or {}
    user_id = data.get("userId")
    if not user_id:
        return jsonify({"success": False, "message": "userId is required"}), 400

    start_db = time.time()
    result = purchase_item(user_id, item_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if result["success"]:
        start_db = time.time()
        newly_unlocked = check_and_unlock_achievements(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        result["newly_unlocked"] = newly_unlocked
        return jsonify(result), 200
    else:
        return jsonify(result), 400

@api_bp.route('/shop/equip', methods=['POST'])
def equip_item_route():
    data = request.json or {}
    user_id = data.get("userId")
    item_id = data.get("itemId")

    if not user_id or not item_id:
        return jsonify({"success": False, "message": "userId and itemId are required"}), 400

    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    try:
        oid = ObjectId(item_id)
    except Exception:
        return jsonify({"success": False, "message": "Invalid item ID"}), 400

    start_db = time.time()
    item_doc = shop_collection.find_one({"_id": oid})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not item_doc:
        return jsonify({"success": False, "message": "Item not found in shop"}), 404

    if oid not in user.get("purchasedItems", []):
        if user.get("level", 1) < item_doc.get("unlockLevel", 1):
            return jsonify({"success": False, "message": "Item not unlocked"}), 400

    start_db = time.time()
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"currentAvatar": oid}}
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"success": True, "message": "Avatar equipped"}), 200

# -------------------------------------------------------------------
# TESTS ROUTES
# -------------------------------------------------------------------
@api_bp.route('/tests/<test_id>', methods=['GET'])
def fetch_test_by_id_route(test_id):
    start_db = time.time()
    test_doc = get_test_by_id_and_category(test_id, None)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not test_doc:
        return jsonify({"error": "Test not found"}), 404
    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200

@api_bp.route('/tests/<category>/<test_id>', methods=['GET'])
def fetch_test_by_category_and_id(category, test_id):
    try:
        test_id_int = int(test_id)
    except Exception:
        return jsonify({"error": "Invalid test ID"}), 400

    start_db = time.time()
    test_doc = tests_collection.find_one({
        "testId": test_id_int,
        "category": category
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not test_doc:
        return jsonify({"error": "Test not found"}), 404

    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200

# -------------------------------------------------------------------
# PROGRESS / ATTEMPTS ROUTES
# -------------------------------------------------------------------
@api_bp.route('/attempts/<user_id>/<test_id>', methods=['GET'])
def get_test_attempt(user_id, test_id):
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = None
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    # IMPORTANT FIX: Handle status parameter to specifically query finished or unfinished
    status = request.args.get("status")
    
    # Build the query based on user ID and test ID
    base_query = {"userId": user_oid}
    if test_id_int is not None:
        base_query["$or"] = [{"testId": test_id_int}, {"testId": test_id}]
    else:
        base_query["testId"] = test_id

    # Add finished status filter if specified
    if status == "finished":
        base_query["finished"] = True
    elif status == "unfinished":
        base_query["finished"] = False
    else:
        # Default behavior (no status parameter): look for unfinished first, then finished
        try:
            unfinished_attempt = testAttempts_collection.find_one({**base_query, "finished": False})
            if unfinished_attempt:
                attempt = unfinished_attempt
            else:
                # If no unfinished attempt, look for most recent finished attempt
                attempt = testAttempts_collection.find_one(
                    {**base_query, "finished": True}, 
                    sort=[("finishedAt", -1)]
                )
            
            # Continue with existing code for handling attempt
            if not attempt:
                return jsonify({"attempt": None}), 200

            # IMPORTANT FIX: Ensure none of the arrays are null/None
            if attempt.get("answers") is None:
                attempt["answers"] = []
            if attempt.get("shuffleOrder") is None:
                attempt["shuffleOrder"] = []
            if attempt.get("answerOrder") is None:
                attempt["answerOrder"] = []

            attempt["_id"] = str(attempt["_id"])
            attempt["userId"] = str(attempt["userId"])
            return jsonify({"attempt": attempt}), 200
        except Exception as e:
            return jsonify({"error": f"Database error: {str(e)}"}), 500

    # If status was specified, execute the query
    start_db = time.time()
    attempt = testAttempts_collection.find_one(base_query)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt:
        return jsonify({"attempt": None}), 200

    # IMPORTANT FIX: Ensure none of the arrays are null/None
    if attempt.get("answers") is None:
        attempt["answers"] = []
    if attempt.get("shuffleOrder") is None:
        attempt["shuffleOrder"] = []
    if attempt.get("answerOrder") is None:
        attempt["answerOrder"] = []

    attempt["_id"] = str(attempt["_id"])
    attempt["userId"] = str(attempt["userId"])
    return jsonify({"attempt": attempt}), 200

@api_bp.route('/attempts/<user_id>/<test_id>', methods=['POST'])
def update_test_attempt(user_id, test_id):
    data = request.json or {}
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    exam_mode_val = data.get("examMode", False)
    selected_length = data.get("selectedLength", data.get("totalQuestions", 0))

    # IMPORTANT FIX: First check if an attempt already exists
    existing_attempt = testAttempts_collection.find_one({
        "userId": user_oid,
        "finished": False,
        "$or": [{"testId": test_id_int}, {"testId": test_id}]
    })

    # If updating an existing attempt but examMode isn't provided,
    # preserve the existing examMode value
    if existing_attempt and "examMode" not in data:
        exam_mode_val = existing_attempt.get("examMode", False)

    filter_ = {
        "userId": user_oid,
        "$or": [{"testId": test_id_int}, {"testId": test_id}]
    }
    
    # IMPORTANT FIX: Include examTimerSeconds in the update
    update_doc = {
        "$set": {
            "userId": user_oid,
            "testId": test_id_int if isinstance(test_id_int, int) else test_id,
            "category": data.get("category", "global"),
            "answers": data.get("answers", []),
            "score": data.get("score", 0),
            "totalQuestions": data.get("totalQuestions", 0),
            "selectedLength": selected_length,
            "currentQuestionIndex": data.get("currentQuestionIndex", 0),
            "shuffleOrder": data.get("shuffleOrder", []),
            "answerOrder": data.get("answerOrder", []),
            "finished": data.get("finished", False),
            "examMode": exam_mode_val,
            "examTimerSeconds": data.get("examTimerSeconds", 0)
        }
    }
    
    if update_doc["$set"]["finished"] is True:
        update_doc["$set"]["finishedAt"] = datetime.utcnow()

    start_db = time.time()
    testAttempts_collection.update_one(filter_, update_doc, upsert=True)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({
        "message": "Progress updated (examMode=%s, selectedLength=%s)" % (exam_mode_val, selected_length)
    }), 200

@api_bp.route('/attempts/<user_id>/<test_id>/finish', methods=['POST'])
def finish_test_attempt(user_id, test_id):
    data = request.json or {}
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    # IMPORTANT FIX: Use more specific query to ensure we're updating the correct test
    category = data.get("category", "global")
    filter_ = {
        "userId": user_oid,
        "finished": False,
    }
    
    # Add testId to the filter
    if test_id_int is not None:
        filter_["$or"] = [{"testId": test_id_int}, {"testId": test_id}]
    else:
        filter_["testId"] = test_id
        
    # Add category to the filter if provided
    if category:
        filter_["category"] = category

    update_doc = {
        "$set": {
            "finished": True,
            "finishedAt": datetime.utcnow(),
            "score": data.get("score", 0),
            "totalQuestions": data.get("totalQuestions", 0),
            "examTimerSeconds": data.get("examTimerSeconds", 0)  # Save timer on finish
        }
    }

    start_db = time.time()
    result = testAttempts_collection.update_one(filter_, update_doc)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    # Log information about whether the update actually happened
    if result.matched_count == 0:
        print(f"Warning: No attempt matched the finish criteria for user={user_id}, test={test_id}")
    
    start_db = time.time()
    # Use same filter but set finished=True to fetch the attempt we just updated
    filter_["finished"] = True
    attempt_doc = testAttempts_collection.find_one(filter_)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt_doc:
        return jsonify({"error": "Attempt not found after finishing."}), 404

    exam_mode = attempt_doc.get("examMode", False)
    selected_length = attempt_doc.get("selectedLength", attempt_doc.get("totalQuestions", 0))
    score = attempt_doc.get("score", 0)
    total_questions = attempt_doc.get("totalQuestions", 0)
    category = attempt_doc.get("category", "global")

    if exam_mode:
        start_db = time.time()
        award_correct_answers_in_bulk(
            user_id=user_id,
            attempt_doc=attempt_doc,
            xp_per_correct=10,
            coins_per_correct=5
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404

    counters = user.get("achievement_counters", {})
    percentage = 0
    if total_questions > 0:
        percentage = (score / total_questions) * 100

    update_ops = {"$inc": {"achievement_counters.total_tests_completed": 1}}

    if score == total_questions and total_questions > 0 and selected_length == 100:
        update_ops["$inc"]["achievement_counters.perfect_tests_count"] = 1
        catKey = f"achievement_counters.perfect_tests_by_category.{category}"
        update_ops["$inc"][catKey] = 1

    if selected_length == 100:
        highest_so_far = counters.get("highest_score_ever", 0.0)
        lowest_so_far = counters.get("lowest_score_ever", 100.0)
        set_ops = {}
        if percentage > highest_so_far:
            set_ops["achievement_counters.highest_score_ever"] = percentage
        if percentage < lowest_so_far:
            set_ops["achievement_counters.lowest_score_ever"] = percentage
        if set_ops:
            update_ops.setdefault("$set", {}).update(set_ops)

    actual_answered_count = sum(1 for ans in attempt_doc.get("answers", []) 
                              if ans.get("userAnswerIndex") is not None)
    update_ops["$inc"]["achievement_counters.total_questions_answered"] = actual_answered_count

    start_db = time.time()
    mainusers_collection.update_one({"_id": user_oid}, update_ops)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    newly_unlocked = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    updated_user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({
        "message": "Test attempt finished",
        "examMode": exam_mode,
        "selectedLength": selected_length,
        "newlyUnlocked": newly_unlocked,
        "newXP": updated_user.get("xp", 0),
        "newCoins": updated_user.get("coins", 0)
    }), 200

@api_bp.route('/attempts/<user_id>/list', methods=['GET'])
def list_test_attempts(user_id):
    try:
        user_oid = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user ID"}), 400

    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=50, type=int)
    skip_count = (page - 1) * page_size

    start_db = time.time()
    cursor = testAttempts_collection.find(
        {"userId": user_oid}
    ).sort("finishedAt", -1).skip(skip_count).limit(page_size)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    attempts = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        doc["userId"] = str(doc["userId"])
        attempts.append(doc)

    return jsonify({
        "page": page,
        "page_size": page_size,
        "attempts": attempts
    }), 200

# -------------------------------------------------------------------
# FIRST-TIME-CORRECT ANSWERS
# -------------------------------------------------------------------
@api_bp.route('/user/<user_id>/submit-answer', methods=['POST'])
def submit_answer(user_id):
    data = request.json or {}
    test_id = str(data.get("testId"))
    question_id = data.get("questionId")
    selected_index = data.get("selectedIndex")
    correct_index = data.get("correctAnswerIndex")
    xp_per_correct = data.get("xpPerCorrect", 10)
    coins_per_correct = data.get("coinsPerCorrect", 5)

    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    attempt_doc = testAttempts_collection.find_one({
        "userId": user["_id"],
        "finished": False,
        "$or": [
            {"testId": int(test_id)} if test_id.isdigit() else {"testId": test_id},
            {"testId": test_id}
        ]
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt_doc:
        return jsonify({"error": "No unfinished attempt doc found"}), 404

    exam_mode = attempt_doc.get("examMode", False)
    is_correct = (selected_index == correct_index)

    existing_answer_index = None
    for i, ans in enumerate(attempt_doc.get("answers", [])):
        if ans.get("questionId") == question_id:
            existing_answer_index = i
            break

    new_score = attempt_doc.get("score", 0)
    if existing_answer_index is not None:
        update_payload = {
            "answers.$.userAnswerIndex": selected_index,
            "answers.$.correctAnswerIndex": correct_index
        }
        if exam_mode is False and is_correct:
            new_score += 1
            update_payload["score"] = new_score

        start_db = time.time()
        testAttempts_collection.update_one(
            {
                "_id": attempt_doc["_id"],
                "answers.questionId": question_id
            },
            {"$set": update_payload}
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    else:
        new_answer_doc = {
            "questionId": question_id,
            "userAnswerIndex": selected_index,
            "correctAnswerIndex": correct_index
        }
        if exam_mode is False and is_correct:
            new_score += 1
        push_update = {"$push": {"answers": new_answer_doc}}
        if exam_mode is False and is_correct:
            push_update["$set"] = {"score": new_score}

        start_db = time.time()
        testAttempts_collection.update_one(
            {"_id": attempt_doc["_id"]},
            push_update
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    awarded_xp = 0
    awarded_coins = 0
    if exam_mode is False:
        start_db = time.time()
        already_correct = correctAnswers_collection.find_one({
            "userId": user["_id"],
            "testId": test_id,
            "questionId": question_id
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        if is_correct and not already_correct:
            start_db = time.time()
            correctAnswers_collection.insert_one({
                "userId": user["_id"],
                "testId": test_id,
                "questionId": question_id
            })
            duration = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration

            start_db = time.time()
            update_user_xp(user_id, xp_per_correct)
            duration2 = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration2

            start_db = time.time()
            update_user_coins(user_id, coins_per_correct)
            duration3 = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration3

            awarded_xp = xp_per_correct
            awarded_coins = coins_per_correct

        start_db = time.time()
        updated_user = get_user_by_id(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({
            "examMode": False,
            "isCorrect": is_correct,
            "alreadyCorrect": bool(already_correct),
            "awardedXP": awarded_xp,
            "awardedCoins": awarded_coins,
            "newXP": updated_user.get("xp", 0),
            "newCoins": updated_user.get("coins", 0)
        }), 200
    else:
        return jsonify({
            "examMode": True,
            "message": "Answer stored. No immediate feedback in exam mode."
        }), 200

# -------------------------------------------------------------------
# ACHIEVEMENTS
# -------------------------------------------------------------------
@api_bp.route('/achievements', methods=['GET'])
def fetch_achievements_route():
    start_db = time.time()
    ach_list = list(achievements_collection.find({}))
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    for ach in ach_list:
        ach["_id"] = str(ach["_id"])
    return jsonify(ach_list), 200

# -------------------------------------------------------------------
# Leaderboard Route with Lazy Loading & Pagination
# -------------------------------------------------------------------
@api_bp.route('/leaderboard', methods=['GET'])
def get_leaderboard():
    global leaderboard_cache
    global leaderboard_cache_timestamp

    now_ms = int(time.time() * 1000)
    if now_ms - leaderboard_cache_timestamp > LEADERBOARD_CACHE_DURATION_MS:
        start_db = time.time()
        cursor = mainusers_collection.find(
            {},
            {"username": 1, "level": 1, "xp": 1, "currentAvatar": 1}
        ).sort("level", -1).limit(1000)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        new_results = []
        rank = 1
        for user in cursor:
            user_data = {
                "username": user.get("username", "unknown"),
                "level": user.get("level", 1),
                "xp": user.get("xp", 0),
                "rank": rank,
                "avatarUrl": None
            }
            if user.get("currentAvatar"):
                start_db = time.time()
                avatar_item = shop_collection.find_one({"_id": user["currentAvatar"]})
                duration = time.time() - start_db
                if not hasattr(g, 'db_time_accumulator'):
                    g.db_time_accumulator = 0.0
                g.db_time_accumulator += duration

                if avatar_item and "imageUrl" in avatar_item:
                    user_data["avatarUrl"] = avatar_item["imageUrl"]
            new_results.append(user_data)
            rank += 1

        leaderboard_cache = new_results
        leaderboard_cache_timestamp = now_ms

    try:
        skip = int(request.args.get("skip", 0))
        limit = int(request.args.get("limit", 50))
    except:
        skip, limit = 0, 50

    total_entries = len(leaderboard_cache)
    end_index = skip + limit
    if skip > total_entries:
        sliced_data = []
    else:
        sliced_data = leaderboard_cache[skip:end_index]

    return jsonify({
        "data": sliced_data,
        "total": total_entries
    }), 200

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# USERNAME/EMAIL/PASSWORD CHANGES
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
@api_bp.route('/user/change-username', methods=['POST'])
def change_username():
    data = request.json or {}
    user_id = data.get("userId")
    new_username = data.get("newUsername")
    if not user_id or not new_username:
        return jsonify({"error": "Missing userId or newUsername"}), 400

    valid, errors = validate_username(new_username)
    if not valid:
        return jsonify({"error": "Invalid new username", "details": errors}), 400

    start_db = time.time()
    existing = mainusers_collection.find_one({"username": new_username})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if existing:
        return jsonify({"error": "Username already taken"}), 400

    start_db = time.time()
    doc = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not doc:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    update_user_fields(user_id, {"username": new_username})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"message": "Username updated"}), 200

@api_bp.route('/user/change-email', methods=['POST'])
def change_email():
    data = request.json or {}
    user_id = data.get("userId")
    new_email = data.get("newEmail")
    if not user_id or not new_email:
        return jsonify({"error": "Missing userId or newEmail"}), 400

    valid, errors = validate_email(new_email)
    if not valid:
        return jsonify({"error": "Invalid email", "details": errors}), 400

    start_db = time.time()
    existing = mainusers_collection.find_one({"email": new_email})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if existing:
        return jsonify({"error": "Email already in use"}), 400

    start_db = time.time()
    doc = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not doc:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    update_user_fields(user_id, {"email": new_email})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"message": "Email updated"}), 200

@api_bp.route('/user/change-password', methods=['POST'])
def change_password():
    data = request.json or {}
    user_id = data.get("userId")
    old_password = data.get("oldPassword")
    new_password = data.get("newPassword")
    confirm = data.get("confirmPassword")

    if not user_id or not old_password or not new_password or not confirm:
        return jsonify({"error": "All fields are required"}), 400
    if new_password != confirm:
        return jsonify({"error": "New passwords do not match"}), 400

    valid, errors = validate_password(new_password)
    if not valid:
        return jsonify({"error": "Invalid new password", "details": errors}), 400

    start_db = time.time()
    user_doc = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user_doc:
        return jsonify({"error": "User not found"}), 404

    if user_doc.get("password") != old_password:
        return jsonify({"error": "Old password is incorrect"}), 401

    start_db = time.time()
    update_user_fields(user_id, {"password": new_password})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"message": "Password updated"}), 200

@api_bp.route('/subscription/cancel', methods=['POST'])
def cancel_subscription():
    return jsonify({"message": "Cancel subscription placeholder"}), 200

# For single answer updates
@api_bp.route('/attempts/<user_id>/<test_id>/answer', methods=['POST'])
def update_single_answer(user_id, test_id):
    data = request.json or {}
    question_id = data.get("questionId")
    user_answer_index = data.get("userAnswerIndex")
    correct_answer_index = data.get("correctAnswerIndex")

    try:
        user_oid = ObjectId(user_id)
        test_id_int = int(test_id) if test_id.isdigit() else test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    start_db = time.time()
    attempt = testAttempts_collection.find_one({
        "userId": user_oid,
        "finished": False,
        "$or": [{"testId": test_id_int}, {"testId": test_id}]
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt:
        return jsonify({"error": "Attempt not found"}), 404

    # Check if this is an exam mode attempt
    exam_mode = attempt.get("examMode", False)
    
    existing_answer_index = None
    for i, ans in enumerate(attempt.get("answers", [])):
        if ans.get("questionId") == question_id:
            existing_answer_index = i
            break

    if existing_answer_index is not None:
        # IMPORTANT FIX: For both exam and non-exam mode, update answers
        update_fields = {
            "answers.$.userAnswerIndex": user_answer_index,
            "answers.$.correctAnswerIndex": correct_answer_index
        }
        
        # Only update score for non-exam mode
        if not exam_mode:
            update_fields["score"] = data.get("score", 0)
            
        start_db = time.time()
        testAttempts_collection.update_one(
            {
                "userId": user_oid,
                "finished": False,
                "$or": [{"testId": test_id_int}, {"testId": test_id}],
                "answers.questionId": question_id
            },
            {"$set": update_fields}
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration
    else:
        # IMPORTANT FIX: For both exam and non-exam mode, add answer
        update_doc = {
            "$push": {
                "answers": {
                    "questionId": question_id,
                    "userAnswerIndex": user_answer_index,
                    "correctAnswerIndex": correct_answer_index
                }
            }
        }
        
        # Only update score for non-exam mode
        if not exam_mode:
            update_doc["$set"] = {"score": data.get("score", 0)}
            
        start_db = time.time()
        testAttempts_collection.update_one(
            {
                "userId": user_oid,
                "finished": False,
                "$or": [{"testId": test_id_int}, {"testId": test_id}]
            },
            update_doc
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    return jsonify({"message": "Answer updated", "examMode": exam_mode}), 200

# For updating the current question position only
@api_bp.route('/attempts/<user_id>/<test_id>/position', methods=['POST'])
def update_position(user_id, test_id):
    data = request.json or {}
    current_index = data.get("currentQuestionIndex", 0)

    try:
        user_oid = ObjectId(user_id)
        test_id_int = int(test_id) if test_id.isdigit() else test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    # IMPORTANT FIX: Include examTimerSeconds in the update
    update_fields = {
        "currentQuestionIndex": current_index,
        "finished": data.get("finished", False)
    }
    
    # Add timer if provided
    if "examTimerSeconds" in data:
        update_fields["examTimerSeconds"] = data["examTimerSeconds"]

    start_db = time.time()
    testAttempts_collection.update_one(
        {
            "userId": user_oid,
            "finished": False,
            "$or": [{"testId": test_id_int}, {"testId": test_id}]
        },
        {"$set": update_fields}
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"message": "Position updated"}), 200

##############################################
# DAILY QUESTION ENDPOINTS
##############################################
@api_bp.route('/user/<user_id>/daily-bonus', methods=['POST'])
def daily_bonus(user_id):
    user = None
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404

    now = datetime.utcnow()
    last_claim = user.get("lastDailyClaim")
    if last_claim and (now - last_claim) < timedelta(hours=24):
        seconds_left = int(24 * 3600 - (now - last_claim).total_seconds())
        return jsonify({
            "success": False,
            "message": f"Already claimed. Next bonus in: {seconds_left} seconds",
            "newCoins": user.get("coins", 0),
            "newXP": user.get("xp", 0),
            "newLastDailyClaim": serialize_datetime(last_claim)
        }), 200
    else:
        start_db = time.time()
        update_user_coins(user_id, 250)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        start_db = time.time()
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"lastDailyClaim": now}}
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        start_db = time.time()
        updated_user = get_user_by_id(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        start_db = time.time()
        newly_unlocked = check_and_unlock_achievements(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({
            "success": True,
            "message": "Daily bonus applied",
            "newCoins": updated_user.get("coins", 0),
            "newXP": updated_user.get("xp", 0),
            "newLastDailyClaim": serialize_datetime(updated_user.get("lastDailyClaim")),
            "newlyUnlocked": newly_unlocked
        }), 200

@api_bp.route('/daily-question', methods=['GET'])
def get_daily_question():
    user_id = request.args.get("userId")
    if not user_id:
        return jsonify({"error": "No userId provided"}), 400

    try:
        user_oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    current_date = datetime.utcnow()
    reference_date = datetime(2025, 3, 11)  # Or any starting date you prefer
    day_index = (current_date - reference_date).days % 300  # This will cycle through 0-29

    start_db = time.time()
    daily_doc = dailyQuestions_collection.find_one({"dayIndex": day_index})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not daily_doc:
        return jsonify({"error": f"No daily question for dayIndex={day_index}"}), 404

    start_db = time.time()
    existing_answer = dailyAnswers_collection.find_one({
        "userId": user_oid,
        "dayIndex": day_index
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    response = {
        "dayIndex": day_index,
        "prompt": daily_doc.get("prompt"),
        "options": daily_doc.get("options"),
        "explanation": daily_doc.get("explanation"),
        "alreadyAnswered": bool(existing_answer)
    }
    return jsonify(response), 200

@api_bp.route('/daily-question/answer', methods=['POST'])
def submit_daily_question():
    data = request.json or {}
    user_id = data.get("userId")
    current_date = datetime.utcnow()
    reference_date = datetime(2025, 3, 11)  # Keep your reference date consistent
    day_index = (current_date - reference_date).days % 300
    selected_index = data.get("selectedIndex")

    if not user_id or day_index is None or selected_index is None:
        return jsonify({"error": "Missing userId, dayIndex, or selectedIndex"}), 400

    try:
        user_oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    start_db = time.time()
    daily_doc = dailyQuestions_collection.find_one({"dayIndex": day_index})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not daily_doc:
        return jsonify({"error": f"No daily question for dayIndex={day_index}"}), 404

    start_db = time.time()
    existing = dailyAnswers_collection.find_one({
        "userId": user_oid,
        "dayIndex": day_index
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if existing:
        return jsonify({"error": "You already answered today's question"}), 400

    correct_index = daily_doc.get("correctIndex", 0)
    is_correct = (selected_index == correct_index)
    awarded_coins = 250 if is_correct else 50

    start_db = time.time()
    dailyAnswers_collection.insert_one({
        "userId": user_oid,
        "dayIndex": day_index,
        "answeredAt": datetime.utcnow(),
        "userAnswerIndex": selected_index,
        "isCorrect": is_correct
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    update_user_coins(str(user_oid), awarded_coins)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    updated_user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    newly_unlocked = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({
        "message": "Answer submitted",
        "correct": is_correct,
        "awardedCoins": awarded_coins,
        "newCoins": updated_user.get("coins", 0),
        "newXP": updated_user.get("xp", 0),
        "newLastDailyClaim": serialize_datetime(updated_user.get("lastDailyClaim")),
        "newlyUnlocked": newly_unlocked,
        "explanation": daily_doc.get("explanation")
    }), 200


#############################################
# Public Leaderboard Caching (30-minute TTL)
#############################################
public_leaderboard_cache = []
public_leaderboard_cache_timestamp = 0
PUBLIC_LEADERBOARD_CACHE_DURATION_MS = 1800000  # 30 minutes (1800 seconds)

@public_leaderboard_bp.route('/board', methods=['GET'])
def get_public_leaderboard():
    """
    Public leaderboard with a longer cache duration (30 minutes)
    This is for the marketing site, separate from the logged-in user leaderboard
    """
    global public_leaderboard_cache
    global public_leaderboard_cache_timestamp

    now_ms = int(time.time() * 1000)
    if now_ms - public_leaderboard_cache_timestamp > PUBLIC_LEADERBOARD_CACHE_DURATION_MS:
        start_db = time.time()
        cursor = mainusers_collection.find(
            {},
            {"username": 1, "level": 1, "xp": 1, "currentAvatar": 1}
        ).sort("level", -1).limit(1000)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        new_results = []
        rank = 1
        for user in cursor:
            user_data = {
                "username": user.get("username", "unknown"),
                "level": user.get("level", 1),
                "xp": user.get("xp", 0),
                "rank": rank,
                "avatarUrl": None
            }
            if user.get("currentAvatar"):
                start_db = time.time()
                avatar_item = shop_collection.find_one({"_id": user["currentAvatar"]})
                duration = time.time() - start_db
                if not hasattr(g, 'db_time_accumulator'):
                    g.db_time_accumulator = 0.0
                g.db_time_accumulator += duration

                if avatar_item and "imageUrl" in avatar_item:
                    user_data["avatarUrl"] = avatar_item["imageUrl"]
            new_results.append(user_data)
            rank += 1

        public_leaderboard_cache = new_results
        public_leaderboard_cache_timestamp = now_ms

    try:
        skip = int(request.args.get("skip", 0))
        limit = int(request.args.get("limit", 50))
        cache_param = request.args.get("cache", "1800")  # Default 30 minutes
    except:
        skip, limit = 0, 50

    total_entries = len(public_leaderboard_cache)
    end_index = skip + limit
    if skip > total_entries:
        sliced_data = []
    else:
        sliced_data = public_leaderboard_cache[skip:end_index]

    return jsonify({
        "data": sliced_data,
        "total": total_entries,
        "cached_at": public_leaderboard_cache_timestamp,
        "cache_duration_ms": PUBLIC_LEADERBOARD_CACHE_DURATION_MS
    }), 200

# routes/oauth_routes.py
from flask import Blueprint, request, redirect, session, jsonify, current_app, url_for
from bson.objectid import ObjectId
import os
import time
import jwt
import json
import secrets
import requests
from datetime import datetime, timedelta
from authlib.integrations.flask_client import OAuth
from models.test import create_user, get_user_by_id, update_user_fields
from mongodb.database import db, mainusers_collection

oauth_bp = Blueprint('oauth', __name__)

# Initialize OAuth
oauth = OAuth()

# Configure Google OAuth
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    # Skip the need for jwks_uri metadata by disabling JWT validation
    server_metadata_url=None
)

# Function to generate Apple client secret JWT
def generate_apple_client_secret():
    team_id = os.getenv('APPLE_TEAM_ID')
    client_id = os.getenv('APPLE_CLIENT_ID')
    key_id = os.getenv('APPLE_KEY_ID')
    
    # Get private key - check if it's content or path
    private_key_path_or_content = os.getenv('APPLE_PRIVATE_KEY')
    
    # If it looks like key content
    if private_key_path_or_content and private_key_path_or_content.startswith('-----BEGIN PRIVATE KEY-----'):
        private_key = private_key_path_or_content
    else:
        # It's a file path
        try:
            with open(private_key_path_or_content, 'r') as key_file:
                private_key = key_file.read()
        except FileNotFoundError:
            current_app.logger.error(f"Error: Apple private key file not found at {private_key_path_or_content}")
            current_app.logger.error(f"Current working directory: {os.getcwd()}")
            raise
    
    # JWT headers
    headers = {
        'kid': key_id
    }
    
    # JWT payload
    payload = {
        'iss': team_id,
        'iat': int(time.time()),
        'exp': int(time.time() + 86400 * 180),  # 180 days (Apple allows up to 6 months)
        'aud': 'https://appleid.apple.com',
        'sub': client_id
    }
    
    # Create and return the JWT token
    token = jwt.encode(
        payload,
        private_key,
        algorithm='ES256',
        headers=headers
    )
    
    # PyJWT >= 2.0.0 returns string instead of bytes
    if isinstance(token, bytes):
        return token.decode('utf-8')
    return token

# Configure Apple OAuth with dynamic client secret
apple = oauth.register(
    name='apple',
    client_id=os.getenv('APPLE_CLIENT_ID'),
    client_secret=generate_apple_client_secret,  # Pass the function, not the result
    authorize_url='https://appleid.apple.com/auth/authorize',
    access_token_url='https://appleid.apple.com/auth/token',
    api_base_url='https://appleid.apple.com/',
    jwks_uri='https://appleid.apple.com/auth/keys',  # Explicitly set JWKS URI
    client_kwargs={
        'scope': 'name email',
        'response_mode': 'form_post',
        'response_type': 'code id_token'
    },
)

def decode_apple_id_token(id_token):
    """
    Manually decode the id_token without validation for Apple Sign In
    """
    try:
        # Split the token into parts
        parts = id_token.split('.')
        if len(parts) != 3:
            return None
        
        # Decode the payload (middle part)
        payload = parts[1]
        # Add padding if needed
        padding = '=' * (4 - len(payload) % 4)
        payload = payload + padding
        
        # Convert from base64 to JSON
        import base64
        decoded = base64.b64decode(payload)
        user_info = json.loads(decoded)
        
        return user_info
    except Exception as e:
        current_app.logger.error(f"Error decoding Apple ID token: {str(e)}")
        return None

def generate_unique_username(base_name):
    """Generate a unique username based on email or name"""
    username = base_name
    count = 0
    
    # Keep checking until we find a unique username
    while mainusers_collection.find_one({'username': username}):
        count += 1
        username = f"{base_name}{count}"
    
    return username

def process_oauth_user(email, name, oauth_provider, oauth_id):
    """Create or retrieve a user from OAuth data"""
    # Check if user exists with this email
    user = mainusers_collection.find_one({'email': email})
    
    if user:
        # User exists, update their OAuth info if not already set
        oauth_field = f"{oauth_provider}_id"
        if not user.get(oauth_field):
            mainusers_collection.update_one(
                {'_id': user['_id']},
                {'$set': {
                    oauth_field: oauth_id,
                    'oauth_provider': oauth_provider
                }}
            )
        
        # Return user_id and is_new_user flag
        return str(user['_id']), False
    
    # Create a new user
    # Generate temporary username from email or name (will be changed by user)
    base_name = name.split()[0].lower() if name else email.split('@')[0]
    temp_username = generate_unique_username(base_name)
    
    # Prepare user data
    user_data = {
        'username': temp_username,  # Temporary username
        'email': email,
        'oauth_provider': oauth_provider,
        f"{oauth_provider}_id": oauth_id,
        'coins': 0,
        'xp': 0,
        'level': 1,
        'achievements': [],
        'xpBoost': 1.0,
        'currentAvatar': None,
        'nameColor': None,
        'purchasedItems': [],
        'subscriptionActive': False,
        'achievement_counters': {
            'total_tests_completed': 0,
            'perfect_tests_count': 0,
            'perfect_tests_by_category': {},
            'highest_score_ever': 0.0,
            'lowest_score_ever': 100.0,
            'total_questions_answered': 0,
        },
        'needs_username': True  # Flag indicating this user needs to set a username
    }
    
    # Insert the new user
    user_id = create_user(user_data)
    
    # Return user_id and is_new_user flag
    return str(user_id), True

# Google OAuth routes
@oauth_bp.route('/login/google')
def google_login():
    # Generate and store a state parameter
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    
    # Use the external URL with /api prefix for your reverse proxy
    base_url = os.getenv('EXTERNAL_URL', 'https://certgames.com')
    redirect_uri = f"{base_url}/api/oauth/auth/google"
    
    # Manual authorize redirect with state parameter
    params = {
        'client_id': google.client_id,
        'redirect_uri': redirect_uri,
        'scope': 'openid email profile',
        'state': state,
        'response_type': 'code'
    }
    
    auth_url = google.authorize_url
    separator = '?' if '?' not in auth_url else '&'
    
    # Build the query string
    query = '&'.join([f"{key}={value}" for key, value in params.items()])
    
    # Full authorization URL
    full_url = f"{auth_url}{separator}{query}"
    
    return redirect(full_url)

@oauth_bp.route('/auth/google')
def google_auth():
    try:
        # Check state parameter to prevent CSRF
        expected_state = session.pop('oauth_state', None)
        received_state = request.args.get('state')
        
        if not expected_state or expected_state != received_state:
            current_app.logger.error(f"State mismatch: expected={expected_state}, received={received_state}")
            return jsonify({"error": "Invalid state parameter"}), 400
        
        # Use the external URL with /api prefix for your reverse proxy
        base_url = os.getenv('EXTERNAL_URL', 'https://certgames.com')
        redirect_uri = f"{base_url}/api/oauth/auth/google"
        
        # Manual token exchange
        code = request.args.get('code')
        if not code:
            return jsonify({"error": "No authorization code received"}), 400
        
        # Exchange code for token
        token_data = google.fetch_access_token(code=code, redirect_uri=redirect_uri)
        if not token_data or 'access_token' not in token_data:
            return jsonify({"error": "Failed to obtain access token"}), 400
        
        # SIMPLIFIED: Instead of using parse_id_token, just get user info directly
        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v1/userinfo',
            headers={'Authorization': f"Bearer {token_data['access_token']}"}
        )
        
        if not userinfo_response.ok:
            return jsonify({"error": "Failed to get user info from Google"}), 400
            
        user_info = userinfo_response.json()
        
        email = user_info.get('email')
        name = user_info.get('name', '')
        google_id = user_info.get('id')
        
        if not email:
            return jsonify({"error": "Email not provided by Google"}), 400
        
        # Process OAuth user and get user_id and is_new_user flag
        user_id, is_new_user = process_oauth_user(email, name, 'google', google_id)
        
        # Store in session
        session['userId'] = user_id
        
        # Log the login
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": ObjectId(user_id),
            "ip": request.remote_addr or "unknown",
            "success": True,
            "provider": "google"
        })
        
        # Redirect based on whether this is a new user or existing user
        frontend_url = os.getenv('FRONTEND_URL', 'https://certgames.com')
        
        if is_new_user:
            # New user needs to set a username
            return redirect(f"{frontend_url}/create-username?provider=google&userId={user_id}")
        else:
            # Existing user can go directly to profile or OAuth success page
            return redirect(f"{frontend_url}/oauth/success?provider=google&userId={user_id}")
        
    except Exception as e:
        current_app.logger.error(f"Error in Google auth: {str(e)}")
        return jsonify({"error": f"Authentication error: {str(e)}"}), 500

# Apple OAuth routes
@oauth_bp.route('/login/apple')
def apple_login():
    # Generate and store a state parameter
    state = secrets.token_urlsafe(16)
    session['apple_oauth_state'] = state
    
    # Use the external URL with /api prefix for your reverse proxy
    base_url = os.getenv('EXTERNAL_URL', 'https://certgames.com')
    redirect_uri = f"{base_url}/api/oauth/auth/apple"
    
    # Manual authorize redirect with state parameter
    params = {
        'client_id': apple.client_id,
        'redirect_uri': redirect_uri,
        'scope': 'name email',
        'state': state,
        'response_type': 'code id_token',
        'response_mode': 'form_post'
    }
    
    auth_url = apple.authorize_url
    separator = '?' if '?' not in auth_url else '&'
    
    # Build the query string
    query = '&'.join([f"{key}={value}" for key, value in params.items()])
    
    # Full authorization URL
    full_url = f"{auth_url}{separator}{query}"
    
    return redirect(full_url)

@oauth_bp.route('/auth/apple', methods=['GET', 'POST'])
def apple_auth():
    if request.method == 'GET':
        return redirect(url_for('oauth.apple_login'))
    
    try:
        # Check state parameter
        expected_state = session.pop('apple_oauth_state', None)
        received_state = request.form.get('state') or request.args.get('state')
        
        if not expected_state or expected_state != received_state:
            current_app.logger.error(f"Apple state mismatch: expected={expected_state}, received={received_state}")
            return jsonify({"error": "Invalid state parameter"}), 400
        
        # Use the external URL with /api prefix for your reverse proxy
        base_url = os.getenv('EXTERNAL_URL', 'https://certgames.com')
        redirect_uri = f"{base_url}/api/oauth/auth/apple"
        
        # Get the authorization code
        code = request.form.get('code') or request.args.get('code')
        if not code:
            return jsonify({"error": "No authorization code received from Apple"}), 400
        
        # Get the id_token directly from the form post (if available)
        id_token = request.form.get('id_token') or request.args.get('id_token')
        
        # If no id_token in the request, we'll need to exchange the code
        if not id_token:
            # Manual token exchange
            client_secret = generate_apple_client_secret()
            token_params = {
                'client_id': apple.client_id,
                'client_secret': client_secret,
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri
            }
            
            # Exchange code for token
            token_response = requests.post(
                'https://appleid.apple.com/auth/token',
                data=token_params
            )
            
            if not token_response.ok:
                return jsonify({"error": "Failed to obtain tokens from Apple"}), 400
                
            token_data = token_response.json()
            id_token = token_data.get('id_token')
            
            if not id_token:
                return jsonify({"error": "No ID token in Apple response"}), 400
        
        # Manually decode the ID token
        user_info = decode_apple_id_token(id_token)
        if not user_info:
            return jsonify({"error": "Failed to decode Apple ID token"}), 400
        
        email = user_info.get('email')
        # Apple doesn't always include name in the ID token
        name_data = user_info.get('name', {})
        if isinstance(name_data, dict):
            full_name = f"{name_data.get('firstName', '')} {name_data.get('lastName', '')}".strip()
        else:
            full_name = ""
        apple_id = user_info.get('sub')  # Apple's unique user ID
        
        if not email:
            return jsonify({"error": "Email not provided by Apple"}), 400
        
        # Process OAuth user and get user_id and is_new_user flag
        user_id, is_new_user = process_oauth_user(email, full_name, 'apple', apple_id)
        
        # Store in session
        session['userId'] = user_id
        
        # Log the login
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": ObjectId(user_id),
            "ip": request.remote_addr or "unknown",
            "success": True,
            "provider": "apple"
        })
        
        # Redirect based on whether this is a new user or existing user
        frontend_url = os.getenv('FRONTEND_URL', 'https://certgames.com')
        
        if is_new_user:
            # New user needs to set a username
            return redirect(f"{frontend_url}/create-username?provider=apple&userId={user_id}")
        else:
            # Existing user can go directly to profile or OAuth success page
            return redirect(f"{frontend_url}/oauth/success?provider=apple&userId={user_id}")
    
    except Exception as e:
        current_app.logger.error(f"Error in Apple auth: {str(e)}")
        return jsonify({"error": f"Authentication error: {str(e)}"}), 500


from flask import Blueprint, request, session, jsonify, g, current_app
from datetime import datetime
import time
from bson import ObjectId
from mongodb.database import db

support_bp = Blueprint('support', __name__, url_prefix='/support')

def require_user_logged_in():
    return bool(session.get('userId'))

@support_bp.route('/my-chat', methods=['GET'])
def list_user_threads():
    # Remove the login check to make it public
    # Get user_id from session if available, otherwise use None
    user_id = session.get('userId')
    if not user_id:
        return jsonify([]), 200  # Return empty list for non-logged in users
        
    user_obj_id = ObjectId(user_id)

    start_db = time.time()
    # Return newest first
    threads_cursor = db.supportThreads.find({"userId": user_obj_id}).sort("updatedAt", -1)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    threads = []
    for t in threads_cursor:
        t_id = str(t['_id'])
        subject = t.get("subject", "")
        status = t.get("status", "open")
        updated_at = t.get("updatedAt")
        threads.append({
            "_id": t_id,
            "subject": subject if subject else "Untitled Thread",
            "status": status,
            "lastUpdated": updated_at.isoformat() if updated_at else None
        })
    return jsonify(threads), 200

@support_bp.route('/my-chat', methods=['POST'])
def create_user_thread():
    """
    User creates a new support thread.
    Must return the FULL THREAD object to avoid parse errors on front end.
    Emits 'new_thread' to admin room only.
    
    For non-logged in users, we'll create anonymous threads.
    """
    # Get user_id from session if available
    user_id = session.get('userId')
    user_obj_id = ObjectId(user_id) if user_id else None
    
    data = request.json or {}
    subject = data.get('subject', '').strip()
    if not subject:
        subject = "Untitled Thread"

    now = datetime.utcnow()

    new_thread = {
        "userId": user_obj_id,  # Will be None for anonymous users
        "subject": subject,
        "messages": [],
        "status": "open",
        "createdAt": now,
        "updatedAt": now
    }

    start_db = time.time()
    result = db.supportThreads.insert_one(new_thread)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if result.inserted_id:
        socketio = current_app.extensions['socketio']

        thread_data = {
            "_id": str(result.inserted_id),
            "userId": str(user_obj_id) if user_obj_id else None,
            "subject": subject,
            "status": "open",
            "createdAt": now.isoformat(),
            "updatedAt": now.isoformat(),
            "messages": []
        }

        # Only emit to "admin" room so admins see new threads
        socketio.emit('new_thread', thread_data, room='admin')

        # Return full thread data to user
        return jsonify(thread_data), 201
    else:
        return jsonify({"error": "Failed to create thread"}), 500

@support_bp.route('/my-chat/<thread_id>', methods=['GET'])
def get_single_thread(thread_id):
    user_id = session.get('userId')
    
    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread ID"}), 400

    start_db = time.time()
    # If user is logged in, only show their threads
    if user_id:
        user_obj_id = ObjectId(user_id)
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
    else:
        # For non-logged in users, check if it's an anonymous thread
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": None})
        
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not thread:
        return jsonify({"error": "Thread not found"}), 404

    thread['_id'] = str(thread['_id'])
    if thread.get('userId'):
        thread['userId'] = str(thread['userId'])
    for m in thread.get("messages", []):
        if "timestamp" in m and isinstance(m["timestamp"], datetime):
            m["timestamp"] = m["timestamp"].isoformat()
    return jsonify(thread), 200

@support_bp.route('/my-chat/<thread_id>', methods=['POST'])
def post_message_to_thread(thread_id):
    user_id = session.get('userId')
    
    data = request.json or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({"error": "No content"}), 400

    now = datetime.utcnow()

    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread ID"}), 400

    start_db = time.time()
    # Query based on whether user is logged in
    if user_id:
        user_obj_id = ObjectId(user_id)
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
    else:
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": None})
        
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not thread:
        return jsonify({"error": "Thread not found"}), 404

    updated_status = thread.get("status", "open")
    if updated_status == "closed":
        # Re-open if user posts again
        db.supportThreads.update_one(
            {"_id": thread["_id"]},
            {
                "$push": {
                    "messages": {
                        "sender": "user",
                        "content": content,
                        "timestamp": now
                    }
                },
                "$set": {
                    "status": "open",
                    "updatedAt": now
                }
            }
        )
        msg_response = "Thread was closed. Reopened with new message"
    else:
        db.supportThreads.update_one(
            {"_id": thread["_id"]},
            {
                "$push": {
                    "messages": {
                        "sender": "user",
                        "content": content,
                        "timestamp": now
                    }
                },
                "$set": {"updatedAt": now}
            }
        )
        msg_response = "Message posted"

    # Emit to the thread's room only
    socketio = current_app.extensions['socketio']
    socketio.emit('new_message', {
        "threadId": str(thread["_id"]),
        "message": {
            "sender": "user",
            "content": content,
            "timestamp": now.isoformat()
        }
    }, room=str(thread["_id"]))

    return jsonify({"message": msg_response}), 200

@support_bp.route('/my-chat/<thread_id>/close', methods=['POST'])
def user_close_specific_thread(thread_id):
    user_id = session.get('userId')
    
    data = request.json or {}
    content = data.get("content", "User closed the thread")
    now = datetime.utcnow()

    try:
        obj_id = ObjectId(thread_id)
    except:
        return jsonify({"error": "Invalid thread ID"}), 400

    start_db = time.time()
    # Query based on whether user is logged in
    if user_id:
        user_obj_id = ObjectId(user_id)
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": user_obj_id})
    else:
        thread = db.supportThreads.find_one({"_id": obj_id, "userId": None})
        
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not thread:
        return jsonify({"error": "Thread not found"}), 404

    if thread.get("status") == "closed":
        return jsonify({"message": "Thread is already closed"}), 200

    db.supportThreads.update_one(
        {"_id": thread["_id"]},
        {
            "$push": {
                "messages": {
                    "sender": "user",
                    "content": content,
                    "timestamp": now
                }
            },
            "$set": {
                "status": "closed",
                "updatedAt": now
            }
        }
    )

    # Get socketio from the current app's extensions
    socketio = current_app.extensions['socketio']

    # Let admin know user closed
    socketio.emit('new_message', {
        "threadId": str(thread["_id"]),
        "message": {
            "sender": "system",
            "content": "Thread closed by user",
            "timestamp": now.isoformat()
        }
    }, room=str(thread["_id"]))

    return jsonify({"message": "Thread closed"}), 200


import os
import logging
import time
import pytz
import redis
from datetime import datetime
from flask import Flask, g, request, jsonify, current_app
from flask_cors import CORS
from flask_session import Session
from flask_socketio import SocketIO, join_room, leave_room, emit
from pymongo import MongoClient
from dotenv import load_dotenv

# routes
from routes.xploit_routes import xploit_bp
from routes.scenario_routes import scenario_bp
from routes.analogy_routes import analogy_bp
from routes.grc_routes import grc_bp
from routes.test_routes import api_bp
from routes.cracked_admin import cracked_bp
from routes.support_routes import support_bp
from routes.newsletter_routes import newsletter_bp
from routes.admin_newsletter_routes import admin_news_bp
from models.test import create_user, get_user_by_id, update_user_fields
from mongodb.database import db
from routes.password_reset_routes import password_reset_bp
from routes.oauth_routes import oauth_bp, oauth
from routes.test_routes import public_leaderboard_bp 
from routes.contact_form import contact_bp


load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
mongo_uri = os.getenv("MONGO_URI")
CRACKED_ADMIN_PASSWORD = os.getenv('CRACKED_ADMIN_PASSWORD', 'authkey')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')
SECRET_KEY = os.getenv('SECRET_KEY', 'supersecret')

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

#######################################
# Initialize Flask & Related
#######################################
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# Setup CORS
CORS(app, supports_credentials=True)

# Setup SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", path="/api/socket.io")

# Setup Redis-based sessions
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'flask_session:'
app.config['SESSION_REDIS'] = redis.StrictRedis(host='redis', port=6379, db=0, password=REDIS_PASSWORD)

Session(app)

oauth.init_app(app) #CHECK -is this the correct location/order of where I put this?

# Make socketio accessible from other files (avoids circular imports)
# so in support_routes.py you can do:
#   socketio = current_app.extensions['socketio']
app.extensions['socketio'] = socketio

@app.route('/health')
def home():
    return 'Backend is running'

@app.before_request
def log_request_info():
    logger.info(f"Handling request to {request.path} with method {request.method}")

# Register blueprints
app.register_blueprint(xploit_bp, url_prefix='/payload')
app.register_blueprint(scenario_bp, url_prefix='/scenario')
app.register_blueprint(analogy_bp, url_prefix='/analogy')
app.register_blueprint(grc_bp, url_prefix='/grc')
app.register_blueprint(api_bp, url_prefix='/test')
app.register_blueprint(cracked_bp, url_prefix="/cracked")
app.register_blueprint(support_bp, url_prefix="/support")
app.register_blueprint(newsletter_bp, url_prefix='/newsletter')
app.register_blueprint(admin_news_bp, url_prefix="/cracked") 
app.register_blueprint(password_reset_bp, url_prefix='/password-reset')
app.register_blueprint(oauth_bp, url_prefix='/oauth')
app.register_blueprint(public_leaderboard_bp, url_prefix='/public-leaderboard')
app.register_blueprint(contact_bp, url_prefix='/contact-form')



###########################
# BEFORE REQUEST
###########################
@app.before_request
def log_request_start():
    g.request_start_time = time.time()
    g.db_time_accumulator = 0.0

###########################
# AFTER REQUEST
###########################
@app.after_request
def log_request_end(response):
    try:
        duration_sec = time.time() - g.request_start_time
        db_time_sec = getattr(g, 'db_time_accumulator', 0.0)
        response_size = 0
        if not response.direct_passthrough and response.data:
            response_size = len(response.data)
        http_status = response.status_code

        # Insert into perfSamples
        doc = {
            "route": request.path,
            "method": request.method,
            "duration_sec": duration_sec,
            "db_time_sec": db_time_sec,
            "response_bytes": response_size,
            "http_status": http_status,
            # Store in UTC
            "timestamp": datetime.utcnow()
        }
        db.perfSamples.insert_one(doc)
    except Exception as e:
        logger.warning(f"Failed to insert perfSample: {e}")
    return response

########################################################################
# Socket.IO event handlers
########################################################################
@socketio.on('connect')
def handle_connect():
    app.logger.info(f"Client connected: {request.sid}")
    socketio.emit('message', {'data': 'Connected to server'})

@socketio.on('join_thread')
def on_join_thread(data):
    thread_id = str(data.get('threadId'))  # Ensure string
    join_room(thread_id)
    app.logger.info(f"Client joined thread room: {thread_id}")

@socketio.on('leave_thread')
def on_leave_thread(data):
    """
    data = { "threadId": "abc123" }
    """
    thread_id = data.get('threadId')
    if thread_id:
        leave_room(thread_id)
        app.logger.info(f"Client left thread room: {thread_id}")

@socketio.on('admin_typing')
def on_admin_typing(data):
    """
    Broadcast to that thread's room that admin is typing
    """
    thread_id = data.get('threadId')
    if thread_id:
        app.logger.info(f"Admin started typing in thread room: {thread_id}")
        socketio.emit('admin_typing', {"threadId": thread_id}, room=thread_id)

@socketio.on('admin_stop_typing')
def on_admin_stop_typing(data):
    thread_id = data.get('threadId')
    if thread_id:
        app.logger.info(f"Admin stopped typing in thread room: {thread_id}")
        socketio.emit('admin_stop_typing', {"threadId": thread_id}, room=thread_id)


@socketio.on('admin_new_message')
def on_admin_new_message(data):
    thread_id = data.get('threadId')
    message = data.get('message')
    if thread_id and message:
        thread_id = str(thread_id)  # Ensure string
        app.logger.info(f"Admin sending message to thread room: {thread_id}")
        socketio.emit('new_message', {
            "threadId": thread_id,
            "message": message
        }, room=thread_id)

@socketio.on('user_typing')
def on_user_typing(data):
    """
    data = { "threadId": "..." }
    Let the admin see "User is typing..."
    """
    thread_id = data.get('threadId')
    if thread_id:
        app.logger.info(f"User started typing in thread room: {thread_id}")
        socketio.emit('user_typing', {"threadId": thread_id}, room=thread_id)

@socketio.on('user_stop_typing')
def on_user_stop_typing(data):
    """
    data = { "threadId": "..." }
    Let the admin see the user is no longer typing
    """
    thread_id = data.get('threadId')
    if thread_id:
        app.logger.info(f"User stopped typing in thread room: {thread_id}")
        socketio.emit('user_stop_typing', {"threadId": thread_id}, room=thread_id)

@socketio.on('join_user_room')
def handle_join_user_room(data):
    user_id = data.get('userId')
    if user_id:
        room_name = f"user_{user_id}"
        join_room(room_name)
        app.logger.info(f"User {user_id} joined personal room: {room_name}")

if __name__ == '__main__':
    # For local dev, run the SocketIO server
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)




KEEP I MIDN THOSE WERE JUST A FEW KEY BACKEND FILES



NNow here arew a few real devops/server/docker container tyep of key files

FROM python:3.11.3


WORKDIR /app


RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    build-essential \
    libffi-dev \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*



RUN python3 -m venv /venv


RUN /venv/bin/pip install --upgrade pip setuptools wheel


COPY requirements.txt /app/requirements.txt


RUN /venv/bin/pip install --no-cache-dir -r /app/requirements.txt


COPY . /app


ENV VIRTUAL_ENV="/venv"
ENV PATH="/venv/bin:$PATH"
ENV FLASK_ENV=production
ENV FLASK_APP=app.py


RUN chmod +x /app/app.py


EXPOSE 5000

CMD ["/venv/bin/gunicorn", "-k", "gevent", "-b", "0.0.0.0:5000", "app:app", "--timeout", "120"]

#docker file frotnend
FROM node:23-alpine
RUN apk add --no-cache bash curl
RUN npm install -g npm@10.9.2
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
RUN npm install -g serve
RUN chown -R node:node /app
USER node
EXPOSE 3000
CMD ["serve", "-s", "build", "-l", "3000"]


#redis conf

bind 0.0.0.0

protected-mode yes





rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command SHUTDOWN ""
rename-command MONITOR ""
rename-command DEBUG ""
rename-command SLAVEOF ""
rename-command MIGRATE ""


loglevel notice


appendonly yes
appendfsync everysec


save 900 1
save 300 10
save 60 10000


maxmemory 12gb

maxmemory-policy allkeys-lru

port 6379


tcp-backlog 511

timeout 0

tcp-keepalive 300



#nginx proxy
server {
    listen 80;
    listen [::]:80;
    server_name _;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {

        proxy_pass http://apache:8080;


        proxy_http_version 1.1;


        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";


        proxy_request_buffering off;
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header X-Accel-Buffering "no";


        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

#apache conf
<VirtualHost *:8080>
    ServerName apache
    ServerAdmin webmaster@localhost


    ProxyRequests Off
    ProxyPreserveHost On


    ProxyPassMatch ^/api/socket.io/(.*) ws://backend:5000/api/socket.io/$1
    ProxyPassReverse ^/api/socket.io/(.*) ws://backend:5000/api/socket.io/$1


    ProxyPass        /api/ http://backend:5000/ keepalive=On flushpackets=on
    ProxyPassReverse /api/ http://backend:5000/


    ProxyPass        / http://frontend:3000/
    ProxyPassReverse / http://frontend:3000/

    <Location /api/>
        Require all granted
    </Location>
</VirtualHost>

#docker-compsoe.yml

version: '3.8'

services:
  backend:
    container_name: backend_service
    build:
      context: ./backend
      dockerfile: Dockerfile.backend
    ports:
      - "5000:5000"
    volumes:
      - ./backend:/app
    env_file:
      - .env
    networks:
      - xploitcraft_network
    restart: always
    depends_on:
      - redis

  frontend:
    container_name: frontend_service
    build:
      context: ./frontend/my-react-app
      dockerfile: Dockerfile.dev
    volumes:
      - ./frontend/my-react-app:/app
      - /app/node_modules
    env_file:
      - .env
    ports:
      - "3000:3000"
    networks:
      - xploitcraft_network
    restart: always

# mongodb:
#     container_name: mongodb_service
#     image: mongo:latest
#     ports:
#       - "27018:27017"
#     volumes:
#       - /mnt/storage/mongo_data:/data/db
#     networks:
#       - xploitcraft_network
#     restart: unless-stopped

  redis:
    container_name: redis_service
    image: redis:latest
    ports:
      - "6380:6379"
    volumes:
      - /mnt/storage/redis_data:/data
      - ./redis/redis.conf:/usr/local/etc/redis/redis.conf
    command: >
      redis-server /usr/local/etc/redis/redis.conf
      --requirepass ${REDIS_PASSWORD}
      --appendonly yes
      --protected-mode yes
      --bind 0.0.0.0
    env_file:
      - .env
    networks:
      - xploitcraft_network
    restart: always

  apache:
    container_name: apache_service
    build:
      context: ./apache
      dockerfile: Dockerfile.apache
    ports:
      - "8080:8080"
    networks:
      - xploitcraft_network
    volumes:
      - ./apache/apache_server.conf:/usr/local/apache2/conf/extra/apache_server.conf
      - ./apache/httpd.conf:/usr/local/apache2/conf/httpd.conf
    restart: always

  nginx:
    container_name: nginx_proxy
    image: nginx:latest
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/sites-enabled:/etc/nginx/sites-enabled
    networks:
      - xploitcraft_network
    depends_on:
      - apache
    restart: unless-stopped

  celery:
    container_name: celery_worker
    build:
      context: ./backend
      dockerfile: Dockerfile.backend
    command: celery -A helpers.async_tasks worker --loglevel=info --concurrency=8
    env_file:
      - .env
    depends_on:
      - backend
      - redis
    networks:
      - xploitcraft_network
    restart: always
    
    
  celery_beat:
    container_name: celery_beat_service
    build:
      context: ./backend
      dockerfile: Dockerfile.backend
    command: celery -A helpers.celery_app beat --loglevel=info
    env_file:
      - .env
    depends_on:
      - backend
      - redis
    networks:
      - xploitcraft_network
    restart: always


networks:
  xploitcraft_network:
    driver: bridge


oh and im liek really dumb so i asked an ai how teh docker copntainer aspect woudl work when imake the ios app sicne i have apache and ngixn and stuff in it and basically its fine i just call th abckend dreeictly yah know
You’d keep running your back-end in Docker exactly like you do now, so the Flask/Apache/Mongo containers keep working the same. Then, for the iOS side:

Spin up Docker as usual (docker-compose up), so your API is accessible at, say, http://localhost:8080/api/... or http://192.168.x.x:8080/api/....
Build your iOS app (in Swift or React Native) outside of Docker – iOS can’t be compiled in Docker because Apple’s toolchain only runs on macOS.
In your app’s code, point your network calls to the Docker address (e.g., fetch("http://192.168.x.x:8080/api/...")).
Run or deploy your iOS app. It now talks to the same Dockerized server you already had for the web, just over HTTP/HTTPS.

ok so anwyay

 
ive started already and heres what weve done

CertGames iOS App Project Overview
What We've Done So Far

Project Architecture Planning

Decided on React Native as the framework for cross-platform compatibility
Established folder structure and organization
Set up Redux for state management


API Configuration

Created apiConfig.js with comprehensive mapping of all backend endpoints
Implemented apiClient.js with authentication handling and error interceptors
Created specialized service files for backend features:

Authentication service
Analogy service
GRC service
Scenario service
Xploit service
Newsletter service
Password reset service




Backend Integration Understanding

Analyzed Python backend code to understand API functionality
Learned about streaming responses from AI endpoints
Mapped backend routes to React Native API calls



Our Next Steps (Immediate Focus)

Tool Features Implementation

Implement the special tools first (Analogy Hub, Scenario Sphere, GRC, Xploitcraft)
Create UI components for each tool
Connect to backend streaming APIs


User Profile Features

Implement profile screens
Achievement system
Shop interface
Leaderboard


Support & Info Features

Q&A support interface
Newsletter subscription
Daily Cyber Brief
Resources page



Future Steps (Later Focus)

Test-Taking System

Implement the 13 different test category pages
Create test-taking interface
Implement scoring and progress tracking


Authentication & Payments

iOS-specific login/registration
Apple Pay integration
App Store subscription handling
Combining database subscription tracking between web and iOS


Deployment & Publishing

App Store submission preparation
Testing across iOS devices
Marketing materials



Project Goals

Create a seamless mobile experience matching the web application
Implement iOS-specific features like Apple Pay and App Store subscriptions
Maintain a single backend serving both web and mobile clients
Ensure data synchronization between platforms

Technical Context

Backend: Flask API with OpenAI integration for AI features
Database: MongoDB for user data, tests, achievements
Authentication: Session-based + OAuth providers (Google, Apple)
Streaming: Several endpoints provide streaming responses for real-time content
Special Features: Advanced AI tools (Analogy, Scenario, GRC, Xploitcraft)

Files Created So Far

API Configuration:

src/api/apiConfig.js - Maps all backend endpoints
src/api/apiClient.js - Configures Axios for API calls


Service Files:

src/api/authService.js
src/api/analogyService.js
src/api/grcService.js
src/api/scenarioService.js
src/api/xploitService.js
src/api/newsletterService.js
src/api/passwordResetService.js


Navigation:

Basic navigation structure planned but not fully implemented



Our implementation approach is to create the mobile app as a client to the existing backend, focusing on maintaining feature parity while adapting the UI for mobile experiences. The most complex part will be implementing the test-taking system and handling iOS-specific subscriptions.




here is my project strutcure so far


refer to images i provied (tehy are teh prject stuture)



and ill provide you all teh files we have doen so far

// src/api/apiConfig.js
import Constants from 'expo-constants';

// Use different URLs based on environment
const DEV_URL = 'http://192.168.1.X:8080/api'; // Replace with your local IP
const PROD_URL = 'https://certgames.com/api';

// Determine which URL to use
const isProduction = !__DEV__;
export const BASE_URL = isProduction ? PROD_URL : DEV_URL;

export const API = {
  // Auth endpoints
  AUTH: {
    LOGIN: `${BASE_URL}/test/login`,
    REGISTER: `${BASE_URL}/test/user`,
    FORGOT_PASSWORD: `${BASE_URL}/password-reset/request-reset`,
    RESET_PASSWORD: `${BASE_URL}/password-reset/reset-password`,
    VERIFY_TOKEN: (token) => `${BASE_URL}/password-reset/verify-token/${token}`,
    OAUTH_GOOGLE: `${BASE_URL}/oauth/login/google`,
    OAUTH_APPLE: `${BASE_URL}/oauth/login/apple`,
  },
  
  // User endpoints
  USER: {
    DETAILS: (userId) => `${BASE_URL}/test/user/${userId}`,
    DAILY_BONUS: (userId) => `${BASE_URL}/test/user/${userId}/daily-bonus`,
    ADD_COINS: (userId) => `${BASE_URL}/test/user/${userId}/add-coins`,
    ADD_XP: (userId) => `${BASE_URL}/test/user/${userId}/add-xp`,
    CHANGE_USERNAME: `${BASE_URL}/test/user/change-username`,
    CHANGE_EMAIL: `${BASE_URL}/test/user/change-email`,
    CHANGE_PASSWORD: `${BASE_URL}/test/user/change-password`,
  },
  
  // Test endpoints
  TESTS: {
    LIST: (category) => `${BASE_URL}/tests/${category}`,
    DETAILS: (category, testId) => `${BASE_URL}/tests/${category}/${testId}`,
    ATTEMPT: (userId, testId) => `${BASE_URL}/attempts/${userId}/${testId}`,
    FINISH: (userId, testId) => `${BASE_URL}/attempts/${userId}/${testId}/finish`,
    SUBMIT_ANSWER: (userId) => `${BASE_URL}/user/${userId}/submit-answer`,
    UPDATE_ANSWER: (userId, testId) => `${BASE_URL}/attempts/${userId}/${testId}/answer`,
    UPDATE_POSITION: (userId, testId) => `${BASE_URL}/attempts/${userId}/${testId}/position`,
    LIST_ATTEMPTS: (userId) => `${BASE_URL}/attempts/${userId}/list`,
  },
  
  // Analogy Tool
  ANALOGY: {
    STREAM: `${BASE_URL}/analogy/stream_analogy`,
    GENERATE: `${BASE_URL}/analogy/generate_analogy`, // Legacy endpoint
  },
  
  // Scenario Tool
  SCENARIO: {
    STREAM_SCENARIO: `${BASE_URL}/scenario/stream_scenario`,
    STREAM_QUESTIONS: `${BASE_URL}/scenario/stream_questions`,
  },
  
  // GRC Tool
  GRC: {
    STREAM_QUESTION: `${BASE_URL}/grc/stream_question`,
    GENERATE_QUESTION: `${BASE_URL}/grc/generate_question`, // Legacy endpoint
  },
  
  // Xploitcraft Tool
  XPLOIT: {
    GENERATE_PAYLOAD: `${BASE_URL}/payload/generate_payload`,
  },
  
  // Daily Question
  DAILY: {
    GET_QUESTION: `${BASE_URL}/test/daily-question`,
    SUBMIT_ANSWER: `${BASE_URL}/test/daily-question/answer`,
  },
  
  // Achievements and shop
  ACHIEVEMENTS: `${BASE_URL}/test/achievements`,
  SHOP: {
    ITEMS: `${BASE_URL}/test/shop`,
    PURCHASE: (itemId) => `${BASE_URL}/test/shop/purchase/${itemId}`,
    EQUIP: `${BASE_URL}/test/shop/equip`,
  },
  
  // Support
  SUPPORT: {
    THREADS: `${BASE_URL}/support/my-chat`,
    THREAD: (threadId) => `${BASE_URL}/support/my-chat/${threadId}`,
    CLOSE_THREAD: (threadId) => `${BASE_URL}/support/my-chat/${threadId}/close`,
  },
  
  // Newsletter
  NEWSLETTER: {
    SUBSCRIBE: `${BASE_URL}/newsletter/subscribe`,
    UNSUBSCRIBE: `${BASE_URL}/newsletter/unsubscribe`,
    UNSUBSCRIBE_BY_TOKEN: (token) => `${BASE_URL}/newsletter/unsubscribe/${token}`,
  },
  
  // Leaderboard
  LEADERBOARD: {
    PUBLIC: `${BASE_URL}/public-leaderboard/board`,
    USER: `${BASE_URL}/test/leaderboard`,
  },
  
  // Contact Form
  CONTACT: `${BASE_URL}/contact-form`,
};

// src/api/apiClient.js
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

// Create an axios instance
const apiClient = axios.create({
  timeout: 30000, // 30 seconds
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
});

// Request interceptor to include auth info and cookies
apiClient.interceptors.request.use(
  async (config) => {
    try {
      const userId = await SecureStore.getItemAsync('userId');
      
      if (userId) {
        // For API calls that expect the userId
        if (config.method === 'post') {
          if (!config.data) {
            config.data = {};
          }
          
          // Only add userId if it's not already in the data
          if (typeof config.data === 'object' && !config.data.userId) {
            config.data.userId = userId;
          }
        }
        
        // Handle cookie-based auth for your backend
        config.withCredentials = true;
        
        // Some APIs might need userId in headers
        config.headers.userId = userId;
      }
      
      return config;
    } catch (error) {
      console.error('API interceptor error:', error);
      return config;
    }
  },
  (error) => Promise.reject(error)
);

// Add response interceptor to handle errors
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    // Handle 401 Unauthorized errors
    if (error.response && error.response.status === 401) {
      // Clear stored credentials
      await SecureStore.deleteItemAsync('userId');
      
      // You could dispatch a logout action here if needed
      // Or redirect to login screen
    }
    
    return Promise.reject(error);
  }
);

export default apiClient;

// src/api/authService.js
import apiClient from './apiClient';
import { API } from './apiConfig';
import * as SecureStore from 'expo-secure-store';

export const loginUser = async (credentials) => {
  try {
    const response = await apiClient.post(API.AUTH.LOGIN, credentials);
    
    if (response.data && response.data.user_id) {
      // Store user ID securely
      await SecureStore.setItemAsync('userId', response.data.user_id);
    }
    
    return response.data;
  } catch (error) {
    console.error('Login error:', error.response?.data || error.message);
    throw error;
  }
};

export const registerUser = async (userData) => {
  try {
    const response = await apiClient.post(API.AUTH.REGISTER, userData);
    return response.data;
  } catch (error) {
    console.error('Registration error:', error.response?.data || error.message);
    throw error;
  }
};

export const fetchUserData = async (userId) => {
  try {
    const response = await apiClient.get(API.USER.DETAILS(userId));
    return response.data;
  } catch (error) {
    console.error('Fetch user error:', error.response?.data || error.message);
    throw error;
  }
};

export const logoutUser = async () => {
  try {
    await SecureStore.deleteItemAsync('userId');
    // No need to call backend logout endpoint if you're using stateless JWT auth
    // If you want to invalidate server-side session, uncomment:
    // await apiClient.post('/api/logout');
    return { success: true };
  } catch (error) {
    console.error('Logout error:', error);
    throw error;
  }
};

export const claimDailyBonus = async (userId) => {
  try {
    const response = await apiClient.post(API.USER.DAILY_BONUS(userId));
    return response.data;
  } catch (error) {
    console.error('Daily bonus error:', error.response?.data || error.message);
    throw error;
  }
};

// src/store/slices/userSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import * as AuthService from '../../api/authService';
import * as SecureStore from 'expo-secure-store';

// Async thunks
export const loginUser = createAsyncThunk(
  'user/loginUser',
  async (credentials, { rejectWithValue }) => {
    try {
      const response = await AuthService.loginUser(credentials);
      return response;
    } catch (error) {
      return rejectWithValue(error.response?.data?.error || 'Login failed');
    }
  }
);

export const fetchUserData = createAsyncThunk(
  'user/fetchUserData',
  async (userId, { rejectWithValue }) => {
    try {
      const response = await AuthService.fetchUserData(userId);
      return response;
    } catch (error) {
      return rejectWithValue(error.response?.data?.error || 'Failed to fetch user data');
    }
  }
);

export const claimDailyBonus = createAsyncThunk(
  'user/claimDailyBonus',
  async (userId, { rejectWithValue }) => {
    try {
      const response = await AuthService.claimDailyBonus(userId);
      return response;
    } catch (error) {
      return rejectWithValue(error.response?.data?.message || 'Failed to claim daily bonus');
    }
  }
);

// Initial state
const initialState = {
  userId: null,
  username: '',
  email: '',
  xp: 0,
  level: 1,
  coins: 0,
  achievements: [],
  xpBoost: 1.0,
  currentAvatar: null,
  nameColor: null,
  purchasedItems: [],
  subscriptionActive: false,
  lastDailyClaim: null,
  
  // Status flags
  status: 'idle', // 'idle' | 'loading' | 'succeeded' | 'failed'
  error: null,
};

// Slice
const userSlice = createSlice({
  name: 'user',
  initialState,
  reducers: {
    // Synchronous reducers
    setUser: (state, action) => {
      const userData = action.payload;
      state.userId = userData.user_id || userData._id;
      state.username = userData.username;
      state.email = userData.email || '';
      state.xp = userData.xp || 0;
      state.level = userData.level || 1;
      state.coins = userData.coins || 0;
      state.achievements = userData.achievements || [];
      state.xpBoost = userData.xpBoost || 1.0;
      state.currentAvatar = userData.currentAvatar;
      state.nameColor = userData.nameColor;
      state.purchasedItems = userData.purchasedItems || [];
      state.subscriptionActive = userData.subscriptionActive || false;
    },
    
    logout: (state) => {
      // Reset to initial state
      Object.assign(state, initialState);
      // Clear storage
      SecureStore.deleteItemAsync('userId');
    },
    
    updateCoins: (state, action) => {
      state.coins = action.payload;
    },
    
    updateXp: (state, action) => {
      state.xp = action.payload;
    }
  },
  extraReducers: (builder) => {
    builder
      // LOGIN
      .addCase(loginUser.pending, (state) => {
        state.status = 'loading';
        state.error = null;
      })
      .addCase(loginUser.fulfilled, (state, action) => {
        state.status = 'succeeded';
        state.userId = action.payload.user_id;
        state.username = action.payload.username;
        state.email = action.payload.email || '';
        state.coins = action.payload.coins || 0;
        state.xp = action.payload.xp || 0;
        state.level = action.payload.level || 1;
        state.achievements = action.payload.achievements || [];
        state.xpBoost = action.payload.xpBoost || 1.0;
        state.currentAvatar = action.payload.currentAvatar;
        state.nameColor = action.payload.nameColor;
        state.purchasedItems = action.payload.purchasedItems || [];
        state.subscriptionActive = action.payload.subscriptionActive || false;
      })
      .addCase(loginUser.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      })
      
      // FETCH USER DATA
      .addCase(fetchUserData.pending, (state) => {
        state.status = 'loading';
      })
      .addCase(fetchUserData.fulfilled, (state, action) => {
        state.status = 'succeeded';
        const userData = action.payload;
        state.userId = userData._id;
        state.username = userData.username;
        state.email = userData.email || '';
        state.xp = userData.xp || 0;
        state.level = userData.level || 1;
        state.coins = userData.coins || 0;
        state.achievements = userData.achievements || [];
        state.xpBoost = userData.xpBoost || 1.0;
        state.currentAvatar = userData.currentAvatar;
        state.nameColor = userData.nameColor;
        state.purchasedItems = userData.purchasedItems || [];
        state.subscriptionActive = userData.subscriptionActive || false;
        state.lastDailyClaim = userData.lastDailyClaim;
      })
      .addCase(fetchUserData.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      })
      
      // DAILY BONUS
      .addCase(claimDailyBonus.fulfilled, (state, action) => {
        if (action.payload.success) {
          state.coins = action.payload.newCoins;
          state.xp = action.payload.newXP;
          state.lastDailyClaim = action.payload.newLastDailyClaim;
          
          // If there are newly unlocked achievements
          if (action.payload.newlyUnlocked && action.payload.newlyUnlocked.length > 0) {
            // Add the new achievements to the array if they don't already exist
            action.payload.newlyUnlocked.forEach(achievementId => {
              if (!state.achievements.includes(achievementId)) {
                state.achievements.push(achievementId);
              }
            });
          }
        }
      });
  },
});

// Export actions and reducer
export const { setUser, logout, updateCoins, updateXp } = userSlice.actions;
export default userSlice.reducer;

// src/store/index.js
import { configureStore } from '@reduxjs/toolkit';
import userReducer from './slices/userSlice';
// Import other reducers as you create them
// import testReducer from './slices/testSlice';
// import achievementsReducer from './slices/achievementsSlice';

export const store = configureStore({
  reducer: {
    user: userReducer,
    // Add other reducers here
    // tests: testReducer,
    // achievements: achievementsReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        // Ignore these paths in the Redux state
        ignoredActions: ['user/fetchUserData/fulfilled'],
        ignoredPaths: ['user.lastDailyClaim'],
      },
    }),
});

export default store;

// src/navigation/AuthNavigator.js
import React from 'react';
import { createStackNavigator } from '@react-navigation/stack';

// Import auth screens
import LoginScreen from '../screens/auth/LoginScreen';
import RegisterScreen from '../screens/auth/RegisterScreen';
import ForgotPasswordScreen from '../screens/auth/ForgotPasswordScreen';
import CreateUsernameScreen from '../screens/auth/CreateUsernameScreen';

const Stack = createStackNavigator();

const AuthNavigator = () => {
  return (
    <Stack.Navigator
      screenOptions={{
        headerShown: false,
        cardStyle: { backgroundColor: '#121212' }
      }}
    >
      <Stack.Screen name="Login" component={LoginScreen} />
      <Stack.Screen name="Register" component={RegisterScreen} />
      <Stack.Screen name="ForgotPassword" component={ForgotPasswordScreen} />
      <Stack.Screen name="CreateUsername" component={CreateUsernameScreen} />
    </Stack.Navigator>
  );
};

export default AuthNavigator;

// src/navigation/MainNavigator.js
import React from 'react';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createStackNavigator } from '@react-navigation/stack';
import { Ionicons } from '@expo/vector-icons';

// Import screens
import HomeScreen from '../screens/HomeScreen';
import ProfileScreen from '../screens/profile/ProfileScreen';
import LeaderboardScreen from '../screens/LeaderboardScreen';
import ShopScreen from '../screens/shop/ShopScreen';
import TestListScreen from '../screens/tests/TestListScreen';
import TestScreen from '../screens/tests/TestScreen';
import AnalogyHubScreen from '../screens/tools/AnalogyHubScreen';
import ScenarioSphereScreen from '../screens/tools/ScenarioSphereScreen';
import GRCScreen from '../screens/tools/GRCScreen';
import AchievementsScreen from '../screens/profile/AchievementsScreen';
import SupportScreen from '../screens/profile/SupportScreen';

// Create Navigators
const Tab = createBottomTabNavigator();
const HomeStack = createStackNavigator();
const ProfileStack = createStackNavigator();
const LeaderboardStack = createStackNavigator();
const ShopStack = createStackNavigator();

// Home Stack
const HomeStackNavigator = () => (
  <HomeStack.Navigator
    screenOptions={{
      headerStyle: {
        backgroundColor: '#1E1E1E',
        elevation: 0, // Android
        shadowOpacity: 0, // iOS
      },
      headerTintColor: '#FFFFFF',
      headerTitleStyle: {
        fontWeight: 'bold',
      },
    }}
  >
    <HomeStack.Screen 
      name="HomeScreen" 
      component={HomeScreen} 
      options={{ title: 'Dashboard' }}
    />
    <HomeStack.Screen 
      name="TestList" 
      component={TestListScreen} 
      options={({ route }) => ({ title: route.params?.title || 'Practice Tests' })}
    />
    <HomeStack.Screen 
      name="Test" 
      component={TestScreen} 
      options={({ route }) => ({ title: route.params?.title || 'Test' })}
    />
    <HomeStack.Screen 
      name="AnalogyHub" 
      component={AnalogyHubScreen} 
      options={{ title: 'Analogy Hub' }}
    />
    <HomeStack.Screen 
      name="ScenarioSphere" 
      component={ScenarioSphereScreen} 
      options={{ title: 'Scenario Sphere' }}
    />
    <HomeStack.Screen 
      name="GRC" 
      component={GRCScreen} 
      options={{ title: 'GRC Questions' }}
    />
  </HomeStack.Navigator>
);

// Profile Stack
const ProfileStackNavigator = () => (
  <ProfileStack.Navigator
    screenOptions={{
      headerStyle: {
        backgroundColor: '#1E1E1E',
        elevation: 0,
        shadowOpacity: 0,
      },
      headerTintColor: '#FFFFFF',
      headerTitleStyle: {
        fontWeight: 'bold',
      },
    }}
  >
    <ProfileStack.Screen 
      name="ProfileScreen" 
      component={ProfileScreen} 
      options={{ title: 'My Profile' }}
    />
    <ProfileStack.Screen 
      name="Achievements" 
      component={AchievementsScreen} 
      options={{ title: 'Achievements' }}
    />
    <ProfileStack.Screen 
      name="Support" 
      component={SupportScreen} 
      options={{ title: 'Support' }}
    />
  </ProfileStack.Navigator>
);

// Leaderboard Stack
const LeaderboardStackNavigator = () => (
  <LeaderboardStack.Navigator
    screenOptions={{
      headerStyle: {
        backgroundColor: '#1E1E1E',
        elevation: 0,
        shadowOpacity: 0,
      },
      headerTintColor: '#FFFFFF',
      headerTitleStyle: {
        fontWeight: 'bold',
      },
    }}
  >
    <LeaderboardStack.Screen 
      name="LeaderboardScreen" 
      component={LeaderboardScreen} 
      options={{ title: 'Leaderboard' }}
    />
  </LeaderboardStack.Navigator>
);

// Shop Stack
const ShopStackNavigator = () => (
  <ShopStack.Navigator
    screenOptions={{
      headerStyle: {
        backgroundColor: '#1E1E1E',
        elevation: 0,
        shadowOpacity: 0,
      },
      headerTintColor: '#FFFFFF',
      headerTitleStyle: {
        fontWeight: 'bold',
      },
    }}
  >
    <ShopStack.Screen 
      name="ShopScreen" 
      component={ShopScreen} 
      options={{ title: 'Shop' }}
    />
  </ShopStack.Navigator>
);

// Main Tab Navigator
const MainNavigator = () => {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused, color, size }) => {
          let iconName;

          if (route.name === 'Home') {
            iconName = focused ? 'home' : 'home-outline';
          } else if (route.name === 'Profile') {
            iconName = focused ? 'person' : 'person-outline';
          } else if (route.name === 'Leaderboard') {
            iconName = focused ? 'trophy' : 'trophy-outline';
          } else if (route.name === 'Shop') {
            iconName = focused ? 'cart' : 'cart-outline';
          }

          return <Ionicons name={iconName} size={size} color={color} />;
        },
        tabBarActiveTintColor: '#6543CC',
        tabBarInactiveTintColor: 'gray',
        tabBarStyle: {
          backgroundColor: '#1A1A1A',
          borderTopColor: '#333333',
        },
        headerShown: false,
      })}
    >
      <Tab.Screen name="Home" component={HomeStackNavigator} />
      <Tab.Screen name="Leaderboard" component={LeaderboardStackNavigator} />
      <Tab.Screen name="Shop" component={ShopStackNavigator} />
      <Tab.Screen name="Profile" component={ProfileStackNavigator} />
    </Tab.Navigator>
  );
};

export default MainNavigator;

// src/navigation/AppNavigator.js
import React, { useEffect, useState } from 'react';
import { NavigationContainer, DefaultTheme } from '@react-navigation/native';
import { useSelector, useDispatch } from 'react-redux';
import * as SecureStore from 'expo-secure-store';
import * as SplashScreen from 'expo-splash-screen';

// Import navigators
import AuthNavigator from './AuthNavigator';
import MainNavigator from './MainNavigator';

// Import actions
import { fetchUserData } from '../store/slices/userSlice';

// Keep the splash screen visible while we fetch resources
SplashScreen.preventAutoHideAsync();

// Custom theme
const MyTheme = {
  ...DefaultTheme,
  colors: {
    ...DefaultTheme.colors,
    background: '#121212',
    text: '#FFFFFF',
    primary: '#6543CC',
    card: '#1E1E1E',
    border: '#333333',
  },
};

const AppNavigator = () => {
  const dispatch = useDispatch();
  const { userId, status } = useSelector((state) => state.user);
  const [appIsReady, setAppIsReady] = useState(false);

  useEffect(() => {
    async function prepare() {
      try {
        // Check if user is already logged in
        const storedUserId = await SecureStore.getItemAsync('userId');
        
        if (storedUserId) {
          // Fetch user data
          await dispatch(fetchUserData(storedUserId));
        }
      } catch (e) {
        console.warn('Error preparing app:', e);
      } finally {
        // Tell the application to render
        setAppIsReady(true);
        await SplashScreen.hideAsync();
      }
    }

    prepare();
  }, [dispatch]);

  if (!appIsReady) {
    return null;
  }

  return (
    <NavigationContainer theme={MyTheme}>
      {userId ? <MainNavigator /> : <AuthNavigator />}
    </NavigationContainer>
  );
};

export default AppNavigator;

// src/screens/auth/LoginScreen.js
import React, { useState } from 'react';
import { 
  View, 
  Text, 
  TextInput, 
  TouchableOpacity, 
  StyleSheet, 
  KeyboardAvoidingView, 
  Platform,
  ActivityIndicator,
  Alert,
  ScrollView,
  Image
} from 'react-native';
import { useDispatch, useSelector } from 'react-redux';
import { Ionicons } from '@expo/vector-icons';
import { loginUser } from '../../store/slices/userSlice';

const LoginScreen = ({ navigation }) => {
  const [usernameOrEmail, setUsernameOrEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  const dispatch = useDispatch();
  const { status, error } = useSelector((state) => state.user);
  const isLoading = status === 'loading';
  
  const handleLogin = async () => {
    if (!usernameOrEmail || !password) {
      Alert.alert('Error', 'Please enter both username/email and password');
      return;
    }
    
    try {
      await dispatch(loginUser({ usernameOrEmail, password })).unwrap();
      // Success is handled by the AppNavigator
    } catch (err) {
      Alert.alert('Login Failed', err || 'Could not log in. Please try again.');
    }
  };
  
  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      style={styles.container}
    >
      <ScrollView contentContainerStyle={styles.scrollContainer}>
        <View style={styles.logoContainer}>
          <Image 
            source={require('../../assets/logo.png')} 
            style={styles.logo}
            resizeMode="contain"
          />
          <Text style={styles.appName}>CertGames</Text>
        </View>
        
        <Text style={styles.welcomeText}>Welcome Back</Text>
        <Text style={styles.subtitleText}>Sign in to continue your journey</Text>
        
        {error && (
          <View style={styles.errorContainer}>
            <Ionicons name="alert-circle" size={20} color="#FF4C8B" />
            <Text style={styles.errorText}>{error}</Text>
          </View>
        )}
        
        <View style={styles.form}>
          <View style={styles.inputContainer}>
            <Ionicons name="person-outline" size={20} color="#AAAAAA" style={styles.inputIcon} />
            <TextInput
              style={styles.input}
              placeholder="Username or Email"
              placeholderTextColor="#AAAAAA"
              value={usernameOrEmail}
              onChangeText={setUsernameOrEmail}
              autoCapitalize="none"
              keyboardType="email-address"
              returnKeyType="next"
              editable={!isLoading}
            />
          </View>
          
          <View style={styles.inputContainer}>
            <Ionicons name="lock-closed-outline" size={20} color="#AAAAAA" style={styles.inputIcon} />
            <TextInput
              style={styles.input}
              placeholder="Password"
              placeholderTextColor="#AAAAAA"
              value={password}
              onChangeText={setPassword}
              secureTextEntry={!showPassword}
              autoCapitalize="none"
              returnKeyType="done"
              editable={!isLoading}
            />
            <TouchableOpacity 
              style={styles.passwordToggle}
              onPress={() => setShowPassword(!showPassword)}
            >
              <Ionicons 
                name={showPassword ? "eye-off-outline" : "eye-outline"} 
                size={20} 
                color="#AAAAAA" 
              />
            </TouchableOpacity>
          </View>
          
          <TouchableOpacity 
            style={styles.forgotPasswordContainer}
            onPress={() => navigation.navigate('ForgotPassword')}
          >
            <Text style={styles.forgotPasswordText}>Forgot Password?</Text>
          </TouchableOpacity>
          
          <TouchableOpacity 
            style={[styles.loginButton, isLoading && styles.disabledButton]}
            onPress={handleLogin}
            disabled={isLoading}
          >
            {isLoading ? (
              <ActivityIndicator color="#FFFFFF" />
            ) : (
              <Text style={styles.loginButtonText}>Sign In</Text>
            )}
          </TouchableOpacity>
          
          <View style={styles.dividerContainer}>
            <View style={styles.divider} />
            <Text style={styles.dividerText}>OR</Text>
            <View style={styles.divider} />
          </View>
          
          <View style={styles.socialButtonsContainer}>
            <TouchableOpacity style={styles.socialButton}>
              <Ionicons name="logo-google" size={20} color="#FFFFFF" />
              <Text style={styles.socialButtonText}>Google</Text>
            </TouchableOpacity>
            
            <TouchableOpacity style={styles.socialButton}>
              <Ionicons name="logo-apple" size={20} color="#FFFFFF" />
              <Text style={styles.socialButtonText}>Apple</Text>
            </TouchableOpacity>
          </View>
          
          <View style={styles.registerContainer}>
            <Text style={styles.registerText}>Don't have an account? </Text>
            <TouchableOpacity onPress={() => navigation.navigate('Register')}>
              <Text style={styles.registerLink}>Create Account</Text>
            </TouchableOpacity>
          </View>
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#121212',
  },
  scrollContainer: {
    flexGrow: 1,
    justifyContent: 'center',
    padding: 20,
  },
  logoContainer: {
    alignItems: 'center',
    marginBottom: 40,
  },
  logo: {
    width: 100,
    height: 100,
  },
  appName: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#FFFFFF',
    marginTop: 10,
  },
  welcomeText: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#FFFFFF',
    textAlign: 'center',
  },
  subtitleText: {
    fontSize: 16,
    color: '#AAAAAA',
    textAlign: 'center',
    marginBottom: 30,
  },
  errorContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(255, 76, 139, 0.1)',
    padding: 10,
    borderRadius: 8,
    marginBottom: 20,
  },
  errorText: {
    color: '#FF4C8B',
    marginLeft: 10,
    flex: 1,
  },
  form: {
    width: '100%',
  },
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#2A2A2A',
    borderRadius: 8,
    marginBottom: 16,
    height: 50,
  },
  inputIcon: {
    marginHorizontal: 15,
  },
  input: {
    flex: 1,
    height: 50,
    color: '#FFFFFF',
    paddingRight: 15,
  },
  passwordToggle: {
    padding: 15,
  },
  forgotPasswordContainer: {
    alignSelf: 'flex-end',
    marginBottom: 20,
  },
  forgotPasswordText: {
    color: '#6543CC',
    fontSize: 14,
  },
  loginButton: {
    backgroundColor: '#6543CC',
    height: 50,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
  },
  disabledButton: {
    backgroundColor: '#4F4F4F',
  },
  loginButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: 'bold',
  },
  dividerContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginVertical: 20,
  },
  divider: {
    flex: 1,
    height: 1,
    backgroundColor: '#333333',
  },
  dividerText: {
    color: '#AAAAAA',
    paddingHorizontal: 10,
    fontSize: 14,
  },
  socialButtonsContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  socialButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#2A2A2A',
    height: 50,
    borderRadius: 8,
    flex: 0.48,
  },
  socialButtonText: {
    color: '#FFFFFF',
    marginLeft: 10,
    fontWeight: 'bold',
  },
  registerContainer: {
    flexDirection: 'row',
    justifyContent: 'center',
    marginTop: 20,
  },
  registerText: {
    color: '#AAAAAA',
  },
  registerLink: {
    color: '#6543CC',
    fontWeight: 'bold',
  },
});

export default LoginScreen;

// src/screens/HomeScreen.js
import React, { useEffect } from 'react';
import { 
  View, 
  Text, 
  ScrollView, 
  StyleSheet, 
  TouchableOpacity, 
  Image,
  RefreshControl
} from 'react-native';
import { useSelector, useDispatch } from 'react-redux';
import { Ionicons } from '@expo/vector-icons';
import { fetchUserData, claimDailyBonus } from '../store/slices/userSlice';

const HomeScreen = ({ navigation }) => {
  const dispatch = useDispatch();
  const { userId, username, level, xp, coins, status, lastDailyClaim } = useSelector((state) => state.user);
  const isLoading = status === 'loading';
  
  useEffect(() => {
    if (userId) {
      dispatch(fetchUserData(userId));
    }
  }, [dispatch, userId]);
  
  const onRefresh = () => {
    if (userId) {
      dispatch(fetchUserData(userId));
    }
  };
  
  const handleClaimDailyBonus = () => {
    if (userId) {
      dispatch(claimDailyBonus(userId));
    }
  };
  
  // Check if daily bonus is available
  const canClaimDaily = () => {
    if (!lastDailyClaim) return true;
    
    const lastClaim = new Date(lastDailyClaim);
    const now = new Date();
    
    // Check if last claim was more than 24 hours ago
    return now - lastClaim > 24 * 60 * 60 * 1000;
  };
  
  const certOptions = [
    { id: 'aplus', name: 'A+ Certification', color: '#6543CC', icon: 'desktop-outline' },
    { id: 'nplus', name: 'Network+', color: '#FF4C8B', icon: 'wifi-outline' },
    { id: 'secplus', name: 'Security+', color: '#2ECC71', icon: 'shield-checkmark-outline' },
    { id: 'cysa', name: 'CySA+', color: '#3498DB', icon: 'analytics-outline' },
    { id: 'penplus', name: 'PenTest+', color: '#E67E22', icon: 'bug-outline' },
    { id: 'linuxplus', name: 'Linux+', color: '#9B59B6', icon: 'terminal-outline' }
  ];
  
  const navigateToTests = (certId, title) => {
    navigation.navigate('TestList', { category: certId, title });
  };
  
  return (
    <ScrollView 
      style={styles.container}
      refreshControl={
        <RefreshControl refreshing={isLoading} onRefresh={onRefresh} />
      }
    >
      <View style={styles.header}>
        <Text style={styles.welcomeText}>Welcome back, {username}!</Text>
        
        <View style={styles.statsContainer}>
          <View style={styles.statItem}>
            <Text style={styles.statValue}>Level {level}</Text>
            <View style={styles.statIconContainer}>
              <Ionicons name="trophy-outline" size={16} color="#6543CC" />
            </View>
          </View>
          
          <View style={styles.statItem}>
            <Text style={styles.statValue}>{xp} XP</Text>
            <View style={styles.statIconContainer}>
              <Ionicons name="flash-outline" size={16} color="#FF4C8B" />
            </View>
          </View>
          
          <View style={styles.statItem}>
            <Text style={styles.statValue}>{coins}</Text>
            <View style={styles.statIconContainer}>
              <Ionicons name="cash-outline" size={16} color="#2ECC71" />
            </View>
          </View>
        </View>
      </View>
      
      {canClaimDaily() && (
        <TouchableOpacity 
          style={styles.dailyBonusCard}
          onPress={handleClaimDailyBonus}
        >
          <View style={styles.dailyBonusContent}>
            <Ionicons name="calendar-outline" size={24} color="#FFFFFF" />
            <View style={styles.dailyBonusTextContainer}>
              <Text style={styles.dailyBonusTitle}>Daily Bonus Available!</Text>
              <Text style={styles.dailyBonusSubtitle}>Claim 250 coins and XP</Text>
            </View>
          </View>
          <Ionicons name="chevron-forward" size={24} color="#FFFFFF" />
        </TouchableOpacity>
      )}
      
      <Text style={styles.sectionTitle}>Practice Tests</Text>
      <View style={styles.certGrid}>
        {certOptions.map((cert) => (
          <TouchableOpacity
            key={cert.id}
            style={[styles.certCard, { backgroundColor: cert.color }]}
            onPress={() => navigateToTests(cert.id, cert.name)}
          >
            <Ionicons name={cert.icon} size={28} color="#FFFFFF" />
            <Text style={styles.certName}>{cert.name}</Text>
          </TouchableOpacity>
        ))}
      </View>
      
      <Text style={styles.sectionTitle}>Training Tools</Text>
      <View style={styles.toolsContainer}>
        <TouchableOpacity 
          style={styles.toolButton}
          onPress={() => navigation.navigate('AnalogyHub')}
        >
          <Ionicons name="bulb-outline" size={24} color="#FF4C8B" />
          <View style={styles.toolTextContainer}>
            <Text style={styles.toolTitle}>Analogy Hub</Text>
            <Text style={styles.toolSubtitle}>Learn complex concepts with analogies</Text>
          </View>
          <Ionicons name="chevron-forward" size={20} color="#AAAAAA" />
        </TouchableOpacity>
        
        <TouchableOpacity 
          style={styles.toolButton}
          onPress={() => navigation.navigate('ScenarioSphere')}
        >
          <Ionicons name="document-text-outline" size={24} color="#2ECC71" />
          <View style={styles.toolTextContainer}>
            <Text style={styles.toolTitle}>Scenario Sphere</Text>
            <Text style={styles.toolSubtitle}>Practice with real-world scenarios</Text>
          </View>
          <Ionicons name="chevron-forward" size={20} color="#AAAAAA" />
        </TouchableOpacity>
        
        <TouchableOpacity 
          style={styles.toolButton}
          onPress={() => navigation.navigate('GRC')}
        >
          <Ionicons name="shield-outline" size={24} color="#3498DB" />
          <View style={styles.toolTextContainer}>
            <Text style={styles.toolTitle}>GRC Questions</Text>
            <Text style={styles.toolSubtitle}>Governance, Risk & Compliance</Text>
          </View>
          <Ionicons name="chevron-forward" size={20} color="#AAAAAA" />
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#121212',
  },
  header: {
    padding: 20,
    backgroundColor: '#1E1E1E',
  },
  welcomeText: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#FFFFFF',
    marginBottom: 20,
  },
  statsContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  statItem: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#2A2A2A',
    paddingHorizontal: 15,
    paddingVertical: 10,
    borderRadius: 8,
    minWidth: 100,
  },
  statValue: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#FFFFFF',
    marginRight: 8,
  },
  statIconContainer: {
    width: 24,
    height: 24,
    borderRadius: 12,
    backgroundColor: 'rgba(255, 255, 255, 0.1)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  dailyBonusCard: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    backgroundColor: '#6543CC',
    margin: 20,
    marginTop: 15,
    padding: 15,
    borderRadius: 10,
  },
  dailyBonusContent: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  dailyBonusTextContainer: {
    marginLeft: 15,
  },
  dailyBonusTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#FFFFFF',
  },
  dailyBonusSubtitle: {
    fontSize: 14,
    color: 'rgba(255, 255, 255, 0.8)',
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#FFFFFF',
    margin: 20,
    marginBottom: 10,
  },
  certGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    padding: 10,
  },
  certCard: {
    width: '45%',
    height: 100,
    margin: '2.5%',
    borderRadius: 10,
    padding: 15,
    justifyContent: 'space-between',
  },
  certName: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: 'bold',
    marginTop: 10,
  },
  toolsContainer: {
    padding: 10,
    paddingBottom: 30, // Extra padding at bottom
  },
  toolButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#2A2A2A',
    padding: 15,
    borderRadius: 8,
    marginBottom: 10,
  },
  toolTextContainer: {
    flex: 1,
    marginLeft: 15,
  },
  toolTitle: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: 'bold',
  },
  toolSubtitle: {
    color: '#AAAAAA',
    fontSize: 14,
  },
});

export default HomeScreen;

// App.js
import React from 'react';
import { StatusBar } from 'react-native';
import { Provider } from 'react-redux';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import store from './src/store';
import AppNavigator from './src/navigation/AppNavigator';

export default function App() {
  return (
    <Provider store={store}>
      <SafeAreaProvider>
        <StatusBar barStyle="light-content" backgroundColor="#121212" />
        <AppNavigator />
      </SafeAreaProvider>
    </Provider>
  );
}

// src/api/analogyService.js
import apiClient from './apiClient';
import { API } from './apiConfig';

export const streamAnalogy = async (analogyType, concept1, concept2 = '', concept3 = '', category = 'real-world') => {
  try {
    const response = await apiClient.post(
      API.ANALOGY.STREAM,
      {
        analogy_type: analogyType,
        concept1,
        concept2,
        concept3,
        category
      },
      {
        responseType: 'text',
        // For streaming responses
        onDownloadProgress: progressEvent => {
          const text = progressEvent.currentTarget.response;
          // You can implement a callback here to handle partial text
          // Or return a promise that resolves with chunks
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Error streaming analogy:', error);
    throw error;
  }
};

// src/api/grcService.js
import apiClient from './apiClient';
import { API } from './apiConfig';

export const streamGRCQuestion = async (category = 'Random', difficulty = 'Easy') => {
  try {
    const response = await apiClient.post(
      API.GRC.STREAM_QUESTION,
      { category, difficulty },
      {
        responseType: 'json',
        onDownloadProgress: progressEvent => {
          const jsonChunks = progressEvent.currentTarget.response;
          // Process JSON chunks here
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Error streaming GRC question:', error);
    throw error;
  }
};

// src/api/scenarioService.js
import apiClient from './apiClient';
import { API } from './apiConfig';

export const streamScenario = async (industry, attackType, skillLevel, threatIntensity) => {
  try {
    const response = await apiClient.post(
      API.SCENARIO.STREAM_SCENARIO,
      {
        industry,
        attack_type: attackType,
        skill_level: skillLevel,
        threat_intensity: threatIntensity
      },
      {
        responseType: 'text',
        onDownloadProgress: progressEvent => {
          const text = progressEvent.currentTarget.response;
          // Process text chunks here
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Error streaming scenario:', error);
    throw error;
  }
};

export const streamScenarioQuestions = async (scenarioText) => {
  try {
    const response = await apiClient.post(
      API.SCENARIO.STREAM_QUESTIONS,
      { scenario_text: scenarioText },
      {
        responseType: 'json',
        onDownloadProgress: progressEvent => {
          const jsonChunks = progressEvent.currentTarget.response;
          // Process JSON chunks here
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Error streaming scenario questions:', error);
    throw error;
  }
};

// src/api/xploitService.js
import apiClient from './apiClient';
import { API } from './apiConfig';

export const generatePayload = async (vulnerability, evasionTechnique, stream = true) => {
  try {
    const response = await apiClient.post(
      API.XPLOIT.GENERATE_PAYLOAD,
      {
        vulnerability,
        evasion_technique: evasionTechnique,
        stream
      },
      {
        responseType: stream ? 'text' : 'json',
        onDownloadProgress: stream ? (progressEvent => {
          const text = progressEvent.currentTarget.response;
          // Process text chunks here
        }) : undefined
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Error generating payload:', error);
    throw error;
  }
};

// src/api/newsletterService.js
import apiClient from './apiClient';
import { API } from './apiConfig';

export const subscribeToNewsletter = async (email) => {
  try {
    const response = await apiClient.post(API.NEWSLETTER.SUBSCRIBE, { email });
    return response.data;
  } catch (error) {
    console.error('Error subscribing to newsletter:', error);
    throw error;
  }
};

export const unsubscribeFromNewsletter = async (email) => {
  try {
    const response = await apiClient.post(API.NEWSLETTER.UNSUBSCRIBE, { email });
    return response.data;
  } catch (error) {
    console.error('Error unsubscribing from newsletter:', error);
    throw error;
  }
};

export const unsubscribeByToken = async (token) => {
  try {
    const response = await apiClient.get(API.NEWSLETTER.UNSUBSCRIBE_BY_TOKEN(token));
    return response.data;
  } catch (error) {
    console.error('Error unsubscribing by token:', error);
    throw error;
  }
};

// src/api/passwordResetService.js
import apiClient from './apiClient';
import { API } from './apiConfig';

export const requestPasswordReset = async (email) => {
  try {
    const response = await apiClient.post(API.AUTH.FORGOT_PASSWORD, { email });
    return response.data;
  } catch (error) {
    console.error('Error requesting password reset:', error);
    throw error;
  }
};

export const verifyResetToken = async (token) => {
  try {
    const response = await apiClient.get(API.AUTH.VERIFY_TOKEN(token));
    return response.data;
  } catch (error) {
    console.error('Error verifying reset token:', error);
    throw error;
  }
};

export const resetPassword = async (token, newPassword, confirmPassword) => {
  try {
    const response = await apiClient.post(API.AUTH.RESET_PASSWORD, {
      token,
      newPassword,
      confirmPassword
    });
    return response.data;
  } catch (error) {
    console.error('Error resetting password:', error);
    throw error;
  }
};



ok so tahts all of them so far- so refer back to out next steps- 



ok so update- we made more files based on my web applciation again and im here to update you/ get you up tp speed now on teh new files we made aswell for my ios app


// src/screens/tools/AnalogyHubScreen.js
import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
  Keyboard,
  Platform,
  SafeAreaView,
  Dimensions
} from 'react-native';
import { Picker } from '@react-native-picker/picker';
import { Ionicons } from '@expo/vector-icons';
import { StatusBar } from 'expo-status-bar';
import * as Clipboard from 'expo-clipboard';
import { streamAnalogy } from '../../api/analogyService';
import { useToast } from 'react-native-toast-notifications';

const AnalogyHubScreen = () => {
  const [analogyType, setAnalogyType] = useState('single');
  const [inputValues, setInputValues] = useState(['']);
  const [analogyCategory, setAnalogyCategory] = useState('real-world');
  const [isStreaming, setIsStreaming] = useState(false);
  const [generatedAnalogy, setGeneratedAnalogy] = useState('');
  
  const toast = useToast();
  const scrollViewRef = useRef();

  // Update input fields based on analogy type
  useEffect(() => {
    switch (analogyType) {
      case 'comparison':
        setInputValues(['', '']);
        break;
      case 'triple':
        setInputValues(['', '', '']);
        break;
      default:
        setInputValues(['']);
    }
  }, [analogyType]);

  const handleInputChange = (index, value) => {
    const newValues = [...inputValues];
    newValues[index] = value;
    setInputValues(newValues);
  };

  const handleGenerateAnalogy = async () => {
    Keyboard.dismiss();
    setIsStreaming(true);
    setGeneratedAnalogy('');

    try {
      const data = {
        analogy_type: analogyType,
        category: analogyCategory,
        concept1: inputValues[0] || '',
        concept2: inputValues[1] || '',
        concept3: inputValues[2] || ''
      };
      
      // Use the service to stream the analogy
      const textChunks = await streamAnalogy(
        analogyType,
        inputValues[0],
        inputValues[1] || '',
        inputValues[2] || '',
        analogyCategory
      );
      
      let accumulatedText = '';
      
      // Simulate streaming by updating the text in chunks
      for (const chunk of textChunks.split('\n')) {
        accumulatedText += chunk + '\n';
        setGeneratedAnalogy(accumulatedText);
        
        // Scroll to bottom as text comes in
        if (scrollViewRef.current) {
          scrollViewRef.current.scrollToEnd({ animated: true });
        }
        
        // Add a small delay to simulate streaming
        await new Promise(resolve => setTimeout(resolve, 50));
      }
    } catch (error) {
      console.error('Error generating analogy:', error);
      toast.show('An error occurred while generating the analogy', {
        type: 'danger',
        duration: 3000,
      });
    } finally {
      setIsStreaming(false);
    }
  };

  const copyToClipboard = async () => {
    if (generatedAnalogy) {
      await Clipboard.setStringAsync(generatedAnalogy);
      toast.show('Copied to clipboard!', {
        type: 'success',
        duration: 2000,
      });
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />
      
      <View style={styles.headerContainer}>
        <Text style={styles.title}>Analogy Hub</Text>
        <Text style={styles.subtitle}>runtime-error.r00</Text>
      </View>
      
      <ScrollView 
        style={styles.scrollView}
        contentContainerStyle={styles.scrollViewContent}
        keyboardShouldPersistTaps="handled"
      >
        <View style={styles.formContainer}>
          {/* Analogy Type Picker */}
          <View style={styles.pickerContainer}>
            <Text style={styles.label}>Analogy Type</Text>
            <View style={styles.pickerWrapper}>
              <Picker
                selectedValue={analogyType}
                onValueChange={(value) => setAnalogyType(value)}
                style={styles.picker}
                dropdownIconColor="#00ffea"
                itemStyle={styles.pickerItem}
                enabled={!isStreaming}
              >
                <Picker.Item label="Single" value="single" />
                <Picker.Item label="Comparison" value="comparison" />
                <Picker.Item label="Triple Comparison" value="triple" />
              </Picker>
            </View>
          </View>
          
          {/* Input Fields */}
          <View style={styles.inputFields}>
            {inputValues.map((value, index) => (
              <TextInput
                key={index}
                style={styles.input}
                placeholder={`Enter concept ${index + 1}`}
                placeholderTextColor="#666"
                value={value}
                onChangeText={(text) => handleInputChange(index, text)}
                editable={!isStreaming}
              />
            ))}
          </View>
          
          {/* Category Picker */}
          <View style={styles.pickerContainer}>
            <Text style={styles.label}>Category</Text>
            <View style={styles.pickerWrapper}>
              <Picker
                selectedValue={analogyCategory}
                onValueChange={(value) => setAnalogyCategory(value)}
                style={styles.picker}
                dropdownIconColor="#00ffea"
                itemStyle={styles.pickerItem}
                enabled={!isStreaming}
              >
                <Picker.Item label="Real World Analogy" value="real-world" />
                <Picker.Item label="Video Games" value="video-games" />
                <Picker.Item label="TV Show" value="tv-show" />
                <Picker.Item label="Sports" value="sports" />
                <Picker.Item label="Fiction" value="fiction" />
                <Picker.Item label="Food & Cooking" value="food" />
                <Picker.Item label="Relationships" value="relationships" />
                <Picker.Item label="Music & Instruments" value="music" />
                <Picker.Item label="Animals" value="animals" />
                <Picker.Item label="Nature & Environment" value="nature" />
                <Picker.Item label="Travel & Exploration" value="travel" />
                <Picker.Item label="Historical Events" value="history" />
                <Picker.Item label="Technology" value="technology" />
                <Picker.Item label="Mythology" value="mythology" />
                <Picker.Item label="Business & Economics" value="business" />
                <Picker.Item label="Art & Creativity" value="art" />
                <Picker.Item label="School & Education" value="school" />
                <Picker.Item label="Construction & Engineering" value="construction" />
                <Picker.Item label="Space & Astronomy" value="space" />
                <Picker.Item label="Superheroes & Comic Books" value="superheroes" />
                <Picker.Item label="Medieval Times" value="medieval" />
                <Picker.Item label="Movies & Cinema" value="movies" />
                <Picker.Item label="Everyday Life" value="everyday-life" />
                <Picker.Item label="Gardening" value="gardening" />
                <Picker.Item label="Mr Robot" value="mr-robot" />
              </Picker>
            </View>
          </View>
          
          {/* Generate Button */}
          <TouchableOpacity 
            style={[styles.generateButton, isStreaming && styles.generateButtonDisabled]} 
            onPress={handleGenerateAnalogy}
            disabled={isStreaming}
          >
            {isStreaming ? (
              <View style={styles.buttonContent}>
                <ActivityIndicator color="#fff" size="small" />
                <Text style={styles.buttonText}>Streaming...</Text>
              </View>
            ) : (
              <Text style={styles.buttonText}>Generate Analogy</Text>
            )}
          </TouchableOpacity>
        </View>
        
        {/* Output Area */}
        {(generatedAnalogy || isStreaming) && (
          <View style={styles.outputContainer}>
            {generatedAnalogy ? (
              <>
                <View style={styles.outputHeader}>
                  <Text style={styles.outputTitle}>Generated Analogy</Text>
                  <TouchableOpacity 
                    style={styles.copyButton}
                    onPress={copyToClipboard}
                  >
                    <Ionicons name="copy-outline" size={16} color="#fff" />
                    <Text style={styles.copyText}>Copy</Text>
                  </TouchableOpacity>
                </View>
                <ScrollView 
                  ref={scrollViewRef}
                  style={styles.analogyTextContainer}
                  contentContainerStyle={styles.analogyTextContent}
                >
                  <Text style={styles.analogyText}>{generatedAnalogy}</Text>
                </ScrollView>
              </>
            ) : (
              <View style={styles.loadingContainer}>
                <ActivityIndicator color="#00ffea" size="large" />
                <Text style={styles.loadingText}>Generating analogy...</Text>
              </View>
            )}
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#121212',
  },
  headerContainer: {
    alignItems: 'center',
    padding: 20,
    backgroundColor: 'rgba(0,0,0,0.5)',
    borderBottomWidth: 2,
    borderBottomColor: '#8B0000',
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#ff4c8b',
    textShadowColor: 'rgba(255,0,0,0.7)',
    textShadowOffset: { width: 1, height: 1 },
    textShadowRadius: 2,
    marginBottom: 5,
  },
  subtitle: {
    fontSize: 16,
    color: '#00ffea',
    textShadowColor: 'rgba(0,0,0,0.7)',
    textShadowOffset: { width: 1, height: 1 },
    textShadowRadius: 2,
  },
  scrollView: {
    flex: 1,
  },
  scrollViewContent: {
    padding: 20,
  },
  formContainer: {
    marginBottom: 20,
  },
  pickerContainer: {
    marginBottom: 16,
  },
  label: {
    fontSize: 16,
    color: '#00ffea',
    marginBottom: 8,
  },
  pickerWrapper: {
    borderWidth: 2,
    borderColor: '#8B0000',
    borderRadius: 10,
    backgroundColor: '#222',
    overflow: 'hidden',
  },
  picker: {
    color: '#00ffea',
    backgroundColor: '#222',
    height: 50,
  },
  pickerItem: {
    fontSize: 16,
    color: '#00ffea',
  },
  inputFields: {
    gap: 16,
    marginBottom: 16,
  },
  input: {
    backgroundColor: '#222',
    borderWidth: 2,
    borderColor: '#8B0000',
    borderRadius: 10,
    color: '#00ffea',
    padding: 12,
    fontSize: 16,
  },
  generateButton: {
    backgroundColor: '#8B0000',
    paddingVertical: 14,
    paddingHorizontal: 20,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 2,
    borderColor: '#000',
    marginTop: 10,
  },
  generateButtonDisabled: {
    backgroundColor: '#550000',
    opacity: 0.7,
  },
  buttonContent: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
  outputContainer: {
    backgroundColor: 'rgba(17, 17, 17, 0.95)',
    borderRadius: 10,
    borderWidth: 2,
    borderColor: '#8B0000',
    padding: 15,
    marginTop: 20,
  },
  outputHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255, 0, 0, 0.2)',
    paddingBottom: 10,
    marginBottom: 10,
  },
  outputTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#ff0000',
  },
  copyButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.5)',
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 5,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.3)',
  },
  copyText: {
    color: '#fff',
    fontSize: 12,
    marginLeft: 5,
  },
  analogyTextContainer: {
    maxHeight: 300,
  },
  analogyTextContent: {
    paddingVertical: 10,
  },
  analogyText: {
    color: '#00ffea',
    fontSize: 16,
    lineHeight: 24,
  },
  loadingContainer: {
    alignItems: 'center',
    padding: 20,
  },
  loadingText: {
    color: '#00ffea',
    marginTop: 10,
    fontSize: 16,
  },
});

export default AnalogyHubScreen;


// src/screens/tools/GRCScreen.js
import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
  SafeAreaView,
  Dimensions
} from 'react-native';
import { Picker } from '@react-native-picker/picker';
import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import { StatusBar } from 'expo-status-bar';
import { useToast } from 'react-native-toast-notifications';
import { streamGRCQuestion } from '../../api/grcService';

const GRCScreen = () => {
  const [category, setCategory] = useState('Random');
  const [difficulty, setDifficulty] = useState('Easy');
  const [loading, setLoading] = useState(false);
  const [questionData, setQuestionData] = useState(null);
  const [selectedOption, setSelectedOption] = useState(null);
  const [showExplanation, setShowExplanation] = useState(false);
  const [copiedToClipboard, setCopiedToClipboard] = useState(false);
  
  const toast = useToast();
  
  // Categories and difficulties arrays
  const categories = [
    "Regulation",
    "Risk Management",
    "Compliance",
    "Audit",
    "Governance",
    "Management",
    "Policy",
    "Ethics",
    "Threat Assessment",
    "Leadership",
    "Business Continuity",
    "Random"
  ];
  
  const difficulties = ["Easy", "Medium", "Hard"];
  
  // Map difficulty to colors
  const difficultyColors = {
    "Easy": "#2ebb77",
    "Medium": "#ffc107",
    "Hard": "#ff4c8b"
  };
  
  // Reset copy status after 2 seconds
  useEffect(() => {
    if (copiedToClipboard) {
      const timer = setTimeout(() => {
        setCopiedToClipboard(false);
      }, 2000);
      return () => clearTimeout(timer);
    }
  }, [copiedToClipboard]);
  
  const fetchQuestion = async () => {
    setLoading(true);
    setQuestionData(null);
    setSelectedOption(null);
    setShowExplanation(false);

    try {
      const data = await streamGRCQuestion(category, difficulty);
      setQuestionData(data);
    } catch (error) {
      console.error('Error fetching question:', error);
      toast.show('Error fetching question. Please try again.', {
        type: 'danger',
        duration: 3000,
      });
    } finally {
      setLoading(false);
    }
  };
  
  const handleAnswer = (optionIndex) => {
    if (!questionData) return;
    
    setSelectedOption(optionIndex);
    setShowExplanation(true);
  };
  
  const handleCopy = async () => {
    if (!questionData || !showExplanation) return;
    
    const correctIndex = questionData.correct_answer_index;
    const correctExplanation = questionData.explanations[correctIndex.toString()];
    const examTip = questionData.exam_tip;
    
    const textToCopy = `Question: ${questionData.question}\n\nOptions:\n${questionData.options.map((opt, i) => `${i + 1}. ${opt}`).join('\n')}\n\nCorrect Answer: ${questionData.options[correctIndex]}\n\nExplanation: ${correctExplanation}\n\nExam Tip: ${examTip}`;
    
    await Clipboard.setStringAsync(textToCopy);
    setCopiedToClipboard(true);
    toast.show('Copied to clipboard!', {
      type: 'success',
      duration: 2000,
    });
  };
  
  const getNewQuestion = () => {
    fetchQuestion();
  };
  
  // Get the letter representation (A, B, C, D) from index
  const getLetterFromIndex = (index) => {
    return String.fromCharCode(65 + index);
  };
  
  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />
      
      <View style={styles.header}>
        <Text style={styles.title}>GRC Wizard</Text>
        <Text style={styles.subtitle}>Master the art of Governance, Risk, and Compliance</Text>
      </View>
      
      <ScrollView style={styles.scrollView}>
        <View style={styles.wizardCard}>
          <View style={styles.cardHeader}>
            <Text style={styles.cardTitle}>Generate a Question</Text>
            <Text style={styles.cardSubtitle}>Select a category and difficulty level</Text>
          </View>
          
          <View style={styles.controls}>
            {/* Category Picker */}
            <View style={styles.controlGroup}>
              <Text style={styles.label}>Category</Text>
              <View style={styles.pickerWrapper}>
                <Picker
                  selectedValue={category}
                  onValueChange={(value) => setCategory(value)}
                  style={styles.picker}
                  dropdownIconColor="#6543cc"
                  itemStyle={styles.pickerItem}
                  enabled={!loading}
                >
                  {categories.map((cat) => (
                    <Picker.Item key={cat} label={cat} value={cat} />
                  ))}
                </Picker>
              </View>
            </View>
            
            {/* Difficulty Picker */}
            <View style={styles.controlGroup}>
              <Text style={styles.label}>Difficulty</Text>
              <View style={styles.pickerWrapper}>
                <Picker
                  selectedValue={difficulty}
                  onValueChange={(value) => setDifficulty(value)}
                  style={styles.picker}
                  dropdownIconColor={difficultyColors[difficulty]}
                  itemStyle={styles.pickerItem}
                  enabled={!loading}
                >
                  {difficulties.map((level) => (
                    <Picker.Item key={level} label={level} value={level} />
                  ))}
                </Picker>
              </View>
            </View>
            
            {/* Generate Button */}
            <TouchableOpacity
              style={styles.generateButton}
              onPress={fetchQuestion}
              disabled={loading}
            >
              {loading ? (
                <View style={styles.buttonContent}>
                  <ActivityIndicator color="#fff" size="small" />
                  <Text style={styles.buttonText}>Generating</Text>
                </View>
              ) : questionData ? (
                <View style={styles.buttonContent}>
                  <Ionicons name="sync" size={20} color="#fff" />
                  <Text style={styles.buttonText}>New Question</Text>
                </View>
              ) : (
                <View style={styles.buttonContent}>
                  <Ionicons name="book" size={20} color="#fff" />
                  <Text style={styles.buttonText}>Generate Question</Text>
                </View>
              )}
            </TouchableOpacity>
          </View>
        </View>
        
        {questionData && (
          <View style={styles.questionCard}>
            <View style={styles.questionHeader}>
              <View style={styles.questionMeta}>
                <Text style={styles.questionCategory}>
                  <Ionicons name={category === 'Random' ? 'shuffle' : 'shield-checkmark'} size={16} color="#AAAAAA" /> {category}
                </Text>
                <Text style={[styles.questionDifficulty, {color: difficultyColors[difficulty]}]}>
                  <Ionicons 
                    name={difficulty === 'Easy' ? 'bulb-outline' : difficulty === 'Medium' ? 'rocket' : 'trophy'} 
                    size={16} 
                    color={difficultyColors[difficulty]} 
                  /> {difficulty}
                </Text>
              </View>
              <Text style={styles.questionTitle}>Question</Text>
            </View>
            
            <View style={styles.questionContent}>
              <Text style={styles.questionText}>{questionData.question}</Text>
              
              <View style={styles.optionsContainer}>
                {questionData.options.map((option, index) => {
                  const isCorrect = index === questionData.correct_answer_index;
                  const isSelected = selectedOption === index;
                  
                  return (
                    <TouchableOpacity
                      key={index}
                      style={[
                        styles.option,
                        isSelected && styles.selectedOption,
                        showExplanation && isCorrect && styles.correctOption,
                        showExplanation && isSelected && !isCorrect && styles.incorrectOption
                      ]}
                      onPress={() => handleAnswer(index)}
                      disabled={selectedOption !== null}
                    >
                      <View style={[
                        styles.optionLetter,
                        showExplanation && isCorrect && styles.correctLetter,
                        showExplanation && isSelected && !isCorrect && styles.incorrectLetter
                      ]}>
                        <Text style={styles.optionLetterText}>{getLetterFromIndex(index)}</Text>
                      </View>
                      <Text style={styles.optionText}>{option}</Text>
                      {showExplanation && isCorrect && (
                        <Ionicons name="checkmark" size={20} color="#2ebb77" style={styles.statusIcon} />
                      )}
                      {showExplanation && isSelected && !isCorrect && (
                        <Ionicons name="close" size={20} color="#ff4e4e" style={styles.statusIcon} />
                      )}
                    </TouchableOpacity>
                  );
                })}
              </View>
            </View>
            
            {showExplanation && (
              <View style={styles.explanationContainer}>
                <View style={styles.explanationHeader}>
                  <Text style={styles.explanationTitle}>
                    {selectedOption === questionData.correct_answer_index ? (
                      <><Ionicons name="checkmark" size={20} color="#2ebb77" /> Correct Answer</>
                    ) : (
                      <><Ionicons name="close" size={20} color="#ff4e4e" /> Incorrect Answer</>
                    )}
                  </Text>
                  <TouchableOpacity 
                    style={[styles.copyButton, copiedToClipboard && styles.copiedButton]}
                    onPress={handleCopy}
                  >
                    {copiedToClipboard ? (
                      <><Ionicons name="checkmark" size={16} color="#fff" /> Copied</>
                    ) : (
                      <><Ionicons name="copy" size={16} color="#fff" /> Copy</>
                    )}
                  </TouchableOpacity>
                </View>
                
                <View style={styles.explanationContent}>
                  <View style={styles.explanationSection}>
                    <Text style={styles.explanationSectionTitle}>Explanation</Text>
                    <Text style={styles.explanationText}>{questionData.explanations[selectedOption.toString()]}</Text>
                  </View>
                  
                  <View style={styles.explanationSection}>
                    <Text style={styles.explanationSectionTitle}>
                      <Ionicons name="bulb" size={18} color="#ffc107" /> Exam Tip
                    </Text>
                    <Text style={styles.tipText}>{questionData.exam_tip}</Text>
                  </View>
                </View>
                
                <View style={styles.actionButtons}>
                  <TouchableOpacity 
                    style={styles.nextButton} 
                    onPress={getNewQuestion}
                  >
                    <Ionicons name="sync" size={20} color="#fff" />
                    <Text style={styles.nextButtonText}>New Question</Text>
                  </TouchableOpacity>
                </View>
              </View>
            )}
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0b0c15',
  },
  header: {
    backgroundColor: '#171a23',
    padding: 20,
    borderRadius: 15,
    margin: 15,
    borderWidth: 1,
    borderColor: '#2a2c3d',
    borderTopWidth: 4,
    borderTopColor: '#6543cc',
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#6543cc',
    textAlign: 'center',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 16,
    color: '#9da8b9',
    textAlign: 'center',
  },
  scrollView: {
    flex: 1,
    padding: 15,
  },
  wizardCard: {
    backgroundColor: '#171a23',
    borderRadius: 15,
    padding: 20,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: '#2a2c3d',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.4,
    shadowRadius: 24,
    elevation: 5,
  },
  cardHeader: {
    marginBottom: 20,
    alignItems: 'center',
  },
  cardTitle: {
    fontSize: 22,
    fontWeight: 'bold',
    color: '#e2e2e2',
    marginBottom: 5,
  },
  cardSubtitle: {
    fontSize: 14,
    color: '#9da8b9',
  },
  controls: {
    gap: 15,
  },
  controlGroup: {
    marginBottom: 15,
  },
  label: {
    fontSize: 14,
    color: '#9da8b9',
    marginBottom: 8,
    fontWeight: '500',
  },
  pickerWrapper: {
    borderWidth: 1,
    borderColor: '#2a2c3d',
    borderRadius: 8,
    backgroundColor: '#333333',
    overflow: 'hidden',
  },
  picker: {
    color: '#e2e2e2',
    height: 50,
  },
  pickerItem: {
    fontSize: 16,
  },
  generateButton: {
    backgroundColor: '#6543cc',
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 20,
    alignItems: 'center',
    justifyContent: 'center',
    shadowColor: 'rgba(101, 67, 204, 0.3)',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 15,
    elevation: 5,
    marginTop: 5,
  },
  buttonContent: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
  questionCard: {
    backgroundColor: '#171a23',
    borderRadius: 15,
    overflow: 'hidden',
    borderWidth: 1,
    borderColor: '#2a2c3d',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.4,
    shadowRadius: 24,
    elevation: 5,
    marginBottom: 20,
  },
  questionHeader: {
    padding: 20,
    backgroundColor: '#333333',
    borderBottomWidth: 1,
    borderBottomColor: '#2a2c3d',
  },
  questionMeta: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 10,
  },
  questionCategory: {
    fontSize: 14,
    color: '#9da8b9',
    flexDirection: 'row',
    alignItems: 'center',
  },
  questionDifficulty: {
    fontSize: 14,
    flexDirection: 'row',
    alignItems: 'center',
  },
  questionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#e2e2e2',
  },
  questionContent: {
    padding: 20,
  },
  questionText: {
    fontSize: 18,
    color: '#e2e2e2',
    lineHeight: 26,
    marginBottom: 25,
  },
  optionsContainer: {
    gap: 15,
  },
  option: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#333333',
    borderWidth: 1,
    borderColor: '#2a2c3d',
    borderRadius: 10,
    padding: 15,
  },
  selectedOption: {
    borderColor: '#6543cc',
    backgroundColor: 'rgba(101, 67, 204, 0.1)',
  },
  correctOption: {
    borderColor: '#2ebb77',
    backgroundColor: 'rgba(46, 187, 119, 0.1)',
  },
  incorrectOption: {
    borderColor: '#ff4e4e',
    backgroundColor: 'rgba(255, 78, 78, 0.1)',
  },
  optionLetter: {
    width: 30,
    height: 30,
    backgroundColor: '#0b0c15',
    borderRadius: 15,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 15,
  },
  correctLetter: {
    backgroundColor: '#2ebb77',
  },
  incorrectLetter: {
    backgroundColor: '#ff4e4e',
  },
  optionLetterText: {
    color: '#e2e2e2',
    fontWeight: 'bold',
    fontSize: 14,
  },
  optionText: {
    flex: 1,
    color: '#e2e2e2',
    fontSize: 16,
    lineHeight: 24,
  },
  statusIcon: {
    marginLeft: 10,
  },
  explanationContainer: {
    padding: 20,
    borderTopWidth: 1,
    borderTopColor: '#2a2c3d',
    backgroundColor: 'rgba(0, 0, 0, 0.15)',
  },
  explanationHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
  },
  explanationTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#e2e2e2',
    flexDirection: 'row',
    alignItems: 'center',
  },
  copyButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#333333',
    borderWidth: 1,
    borderColor: '#2a2c3d',
    borderRadius: 6,
    paddingVertical: 8,
    paddingHorizontal: 12,
    gap: 6,
  },
  copiedButton: {
    backgroundColor: '#2ebb77',
    borderColor: 'transparent',
  },
  explanationContent: {
    gap: 20,
  },
  explanationSection: {
    backgroundColor: '#333333',
    borderWidth: 1,
    borderColor: '#2a2c3d',
    borderRadius: 10,
    padding: 15,
  },
  explanationSectionTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#e2e2e2',
    marginBottom: 10,
    flexDirection: 'row',
    alignItems: 'center',
  },
  explanationText: {
    fontSize: 15,
    color: '#9da8b9',
    lineHeight: 22,
  },
  tipText: {
    fontSize: 15,
    color: '#9da8b9',
    lineHeight: 22,
    fontStyle: 'italic',
    borderLeftWidth: 3,
    borderLeftColor: '#ffc107',
    paddingLeft: 10,
  },
  actionButtons: {
    alignItems: 'center',
    marginTop: 25,
  },
  nextButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#ff4c8b',
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 25,
    shadowColor: 'rgba(255, 76, 139, 0.3)',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 15,
    elevation: 5,
    gap: 10,
  },
  nextButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
});

export default GRCScreen;


// src/screens/tools/ScenarioSphereScreen.js
import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  TextInput,
  ActivityIndicator,
  FlatList,
  Modal,
  SafeAreaView,
  Dimensions
} from 'react-native';
import { Picker } from '@react-native-picker/picker';
import Slider from '@react-native-community/slider';
import { Ionicons } from '@expo/vector-icons';
import { StatusBar } from 'expo-status-bar';
import { useToast } from 'react-native-toast-notifications';
import { streamScenario, streamScenarioQuestions } from '../../api/scenarioService';

// Sample attack types - in a real app, you'd import this from a separate file
const ATTACK_TYPES = [
  "AI Activation Exploit",
  "AI Algorithm Manipulation",
  "AI Data Leakage",
  "AI Data Poisoning",
  "Backdoor",
  "Brute Force",
  "Buffer Overflow",
  "Business Email Compromise",
  "Cloud Service Abuse",
  "Command Injection",
  "Cross-Site Request Forgery",
  "Cross-Site Scripting",
  "Cryptojacking",
  "DDoS Attack",
  "DNS Hijacking",
  "DNS Spoofing",
  "Data Exfiltration",
  "Deepfake",
  "Drive-by Download",
  "Eavesdropping",
  "Evil Twin Attack",
  "File Inclusion",
  "Firmware Attack",
  "GDPR Violation",
  "Honey Trap",
  "IMSI Catcher",
  "Identity Theft",
  "Insider Threat",
  "IoT Botnet",
  "Keylogger",
  "LDAP Injection",
  "LLM Prompt Injection",
  "Logic Bomb",
  "MFA Bypass",
  "MitM Attack",
  "OAuth Token Theft",
  "Password Spraying",
  "Phishing",
  "Ping of Death",
  "Privilege Escalation",
  "Ransomware",
  "Remote Code Execution",
  "Reverse Shell",
  "Rootkit",
  "SAML Attack",
  "SQL Injection",
  "Sandbox Escape",
  "Session Hijacking",
  "Side-Channel Attack",
  "Social Engineering",
  "Software Supply Chain",
  "Spear Phishing",
  "Spyware",
  "Typosquatting",
  "USB Drop Attack",
  "Vishing",
  "Virtual Host Confusion",
  "Watering Hole",
  "Web Shell",
  "Zero-Day Exploit"
];

const ScenarioSphereScreen = () => {
  const [isGenerating, setIsGenerating] = useState(false);
  const [industry, setIndustry] = useState("Finance");
  const [attackType, setAttackType] = useState("");
  const [skillLevel, setSkillLevel] = useState("Script Kiddie");
  const [threatIntensity, setThreatIntensity] = useState(50);

  const [scenarioText, setScenarioText] = useState("");
  const [interactiveQuestions, setInteractiveQuestions] = useState([]);
  const [userAnswers, setUserAnswers] = useState({});
  const [feedback, setFeedback] = useState({});

  const [suggestions, setSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [showAllSuggestions, setShowAllSuggestions] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [scoreCounter, setScoreCounter] = useState(0);

  const [outputExpanded, setOutputExpanded] = useState(true);
  const [questionsExpanded, setQuestionsExpanded] = useState(true);
  const [generationComplete, setGenerationComplete] = useState(false);
  const [scenarioGenerated, setScenarioGenerated] = useState(false);

  const toast = useToast();
  const scrollViewRef = useRef();
  const scenarioOutputRef = useRef();

  const handleAttackTypeChange = (text) => {
    setAttackType(text);
    setShowAllSuggestions(false);
    setErrorMessage("");

    if (text.length > 0) {
      const filteredSuggestions = ATTACK_TYPES.filter(
        (attack) => attack.toLowerCase().includes(text.toLowerCase())
      );
      setSuggestions(filteredSuggestions);
      setShowSuggestions(true);
    } else {
      setSuggestions([]);
      setShowSuggestions(false);
    }
  };

  const selectSuggestion = (suggestion) => {
    setAttackType(suggestion);
    setShowSuggestions(false);
  };

  const handleGenerateScenario = async () => {
    if (!attackType.trim()) {
      setErrorMessage("Please enter the Type of Attack");
      toast.show("Please enter the Type of Attack", {
        type: 'danger',
        duration: 3000,
      });
      return;
    }

    setErrorMessage("");
    setIsGenerating(true);
    setScenarioText("");
    setInteractiveQuestions([]);
    setUserAnswers({});
    setFeedback({});
    setScoreCounter(0);
    setScenarioGenerated(true);
    setGenerationComplete(false);

    try {
      // Start streaming the scenario
      const response = await streamScenario(
        industry,
        attackType,
        skillLevel,
        threatIntensity
      );

      let accumulatedText = '';
      
      // Simulate streaming by updating the text in chunks
      const paragraphs = response.split('\n\n');
      
      for (const paragraph of paragraphs) {
        accumulatedText += paragraph + '\n\n';
        setScenarioText(accumulatedText);
        
        // Simulate delay for streaming effect
        await new Promise(resolve => setTimeout(resolve, 100));
        
        // Scroll to bottom as text comes in
        if (scenarioOutputRef.current) {
          scenarioOutputRef.current.scrollToEnd({ animated: true });
        }
      }
      
      setGenerationComplete(true);
      
      // Now fetch the questions based on the scenario
      fetchQuestions(accumulatedText);
    } catch (error) {
      console.error('Error generating scenario:', error);
      setErrorMessage("An error occurred while generating the scenario");
      toast.show("Error generating scenario. Please try again.", {
        type: 'danger',
        duration: 3000,
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const fetchQuestions = async (finalScenarioText) => {
    if (!finalScenarioText) return;

    try {
      const questions = await streamScenarioQuestions(finalScenarioText);
      
      if (Array.isArray(questions)) {
        const errorObj = questions.find(q => q.error);
        if (errorObj) {
          console.error("Error in questions generation:", errorObj.error);
          setErrorMessage(`Error generating questions: ${errorObj.error}`);
          toast.show(`Error generating questions: ${errorObj.error}`, {
            type: 'danger',
            duration: 3000,
          });
        } else if (questions.length === 3) {
          setInteractiveQuestions(questions);
        } else {
          console.error("Expected exactly 3 questions, but received:", questions);
          setErrorMessage("Unexpected number of questions received");
        }
      } else {
        console.error("Parsed questions are not in an array format.");
        setErrorMessage("Invalid format for interactive questions");
      }
    } catch (error) {
      console.error("Error fetching questions:", error);
      setErrorMessage("Error fetching questions");
      toast.show("Error fetching questions. Please try again.", {
        type: 'danger',
        duration: 3000,
      });
    }
  };

  const handleAnswerSelect = (questionIndex, selectedOption) => {
    // Already answered? do nothing
    if (Object.prototype.hasOwnProperty.call(userAnswers, questionIndex)) {
      return;
    }
    
    const question = interactiveQuestions[questionIndex];
    const isCorrect = selectedOption === question.correct_answer;

    setUserAnswers((prevAnswers) => ({
      ...prevAnswers,
      [questionIndex]: selectedOption,
    }));

    setFeedback((prevFeedback) => ({
      ...prevFeedback,
      [questionIndex]: {
        isCorrect,
        explanation: question.explanation,
      },
    }));
    
    if (isCorrect) {
      setScoreCounter(prev => prev + 1);
      toast.show("Correct answer!", {
        type: 'success',
        duration: 2000,
      });
    } else {
      toast.show("Incorrect answer.", {
        type: 'danger',
        duration: 2000,
      });
    }
  };

  // Calculate a rough progress percentage based on paragraph count
  const calculateStreamProgress = () => {
    if (!scenarioText) return 0;
    const paragraphs = scenarioText.split('\n\n').filter(p => p.trim().length > 0);
    return Math.min(Math.ceil((paragraphs.length / 5) * 100), 90);
  };

  const streamProgress = calculateStreamProgress();

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />
      
      <View style={styles.header}>
        <Text style={styles.title}>
          <Ionicons name="shield" size={24} color="#6543cc" /> Scenario Sphere
        </Text>
        <Text style={styles.subtitle}>
          Immerse yourself in realistic cybersecurity scenarios and test your knowledge
        </Text>
        
        {errorMessage ? (
          <View style={styles.errorContainer}>
            <Ionicons name="warning" size={20} color="#ff4e4e" />
            <Text style={styles.errorText}>{errorMessage}</Text>
            <TouchableOpacity 
              style={styles.errorCloseButton}
              onPress={() => setErrorMessage("")}
            >
              <Ionicons name="close" size={18} color="#9da8b9" />
            </TouchableOpacity>
          </View>
        ) : null}
      </View>
      
      <ScrollView style={styles.scrollView}>
        <View style={styles.content}>
          <View style={styles.paramsCard}>
            <View style={styles.paramsHeader}>
              <View style={styles.paramsHeaderLeft}>
                <Ionicons name="settings" size={20} color="#6543cc" />
                <Text style={styles.paramsTitle}>Generation Parameters</Text>
              </View>
              
              <View style={styles.scoreCounter}>
                <Text style={styles.scoreValue}>
                  <Text style={styles.scoreHighlight}>{scoreCounter}</Text>/3
                </Text>
                <Text style={styles.scoreLabel}>Correct</Text>
              </View>
            </View>
            
            <View style={styles.paramsContent}>
              {/* Industry Picker */}
              <View style={styles.paramGroup}>
                <Text style={styles.paramLabel}>
                  <Ionicons name="business" size={16} color="#6543cc" /> Industry
                </Text>
                <View style={styles.pickerWrapper}>
                  <Picker
                    selectedValue={industry}
                    onValueChange={(value) => setIndustry(value)}
                    style={styles.picker}
                    dropdownIconColor="#6543cc"
                    itemStyle={styles.pickerItem}
                    enabled={!isGenerating}
                  >
                    <Picker.Item label="Finance" value="Finance" />
                    <Picker.Item label="Healthcare" value="Healthcare" />
                    <Picker.Item label="Retail" value="Retail" />
                    <Picker.Item label="Technology" value="Technology" />
                    <Picker.Item label="Energy" value="Energy" />
                    <Picker.Item label="Education" value="Education" />
                    <Picker.Item label="Supply Chain" value="Supply Chain" />
                    <Picker.Item label="Telecommunications" value="Telecommunications" />
                    <Picker.Item label="Pharmaceutical" value="Pharmaceutical" />
                    <Picker.Item label="Transportation" value="Transportation" />
                    <Picker.Item label="Cybersecurity Company" value="Cybersecurity Company" />
                    <Picker.Item label="Manufacturing" value="Manufacturing" />
                    <Picker.Item label="CYBERPUNK2077" value="CYBERPUNK2077" />
                  </Picker>
                </View>
              </View>
              
              {/* Attack Type Input */}
              <View style={styles.paramGroup}>
                <Text style={styles.paramLabel}>
                  <Ionicons name="skull" size={16} color="#6543cc" /> Attack Type
                </Text>
                <View style={styles.inputWrapper}>
                  <Ionicons name="search" size={20} color="#6543cc" style={styles.inputIcon} />
                  <TextInput
                    style={styles.textInput}
                    placeholder="Search or enter attack type..."
                    placeholderTextColor="#9da8b9"
                    value={attackType}
                    onChangeText={handleAttackTypeChange}
                    editable={!isGenerating}
                  />
                </View>
                
                {showSuggestions && suggestions.length > 0 && (
                  <View style={styles.suggestionsContainer}>
                    <FlatList
                      data={showAllSuggestions ? suggestions : suggestions.slice(0, 5)}
                      keyExtractor={(item) => item}
                      renderItem={({ item }) => (
                        <TouchableOpacity
                          style={styles.suggestionItem}
                          onPress={() => selectSuggestion(item)}
                        >
                          <Text style={styles.suggestionText}>{item}</Text>
                        </TouchableOpacity>
                      )}
                      style={styles.suggestionsList}
                    />
                    
                    {!showAllSuggestions && suggestions.length > 5 && (
                      <TouchableOpacity 
                        style={styles.showAllButton}
                        onPress={() => setShowAllSuggestions(true)}
                      >
                        <Ionicons name="chevron-down" size={16} color="#6543cc" />
                        <Text style={styles.showAllText}>
                          Show all options ({suggestions.length})
                        </Text>
                      </TouchableOpacity>
                    )}
                  </View>
                )}
              </View>
              
              {/* Skill Level Picker */}
              <View style={styles.paramGroup}>
                <Text style={styles.paramLabel}>
                  <Ionicons name="person" size={16} color="#6543cc" /> Attacker Skill Level
                </Text>
                <View style={styles.pickerWrapper}>
                  <Picker
                    selectedValue={skillLevel}
                    onValueChange={(value) => setSkillLevel(value)}
                    style={styles.picker}
                    dropdownIconColor="#6543cc"
                    itemStyle={styles.pickerItem}
                    enabled={!isGenerating}
                  >
                    <Picker.Item label="Script Kiddie" value="Script Kiddie" />
                    <Picker.Item label="Intermediate" value="Intermediate" />
                    <Picker.Item label="Advanced" value="Advanced" />
                    <Picker.Item label="APT" value="APT" />
                  </Picker>
                </View>
              </View>
              
              {/* Threat Intensity Slider */}
              <View style={styles.paramGroup}>
                <View style={styles.sliderLabelContainer}>
                  <Text style={styles.paramLabel}>
                    <Ionicons name="thermometer" size={16} color="#6543cc" /> Threat Intensity
                  </Text>
                  <View style={styles.intensityBadge}>
                    <Text style={styles.intensityValue}>{threatIntensity}</Text>
                  </View>
                </View>
                
                <Slider
                  style={styles.slider}
                  minimumValue={1}
                  maximumValue={100}
                  step={1}
                  value={threatIntensity}
                  onValueChange={(value) => setThreatIntensity(value)}
                  minimumTrackTintColor="#6543cc"
                  maximumTrackTintColor="#333333"
                  thumbTintColor="#6543cc"
                  disabled={isGenerating}
                />
                
                <View style={styles.sliderMarkers}>
                  <Text style={styles.sliderMarker}>Low</Text>
                  <Text style={styles.sliderMarker}>Medium</Text>
                  <Text style={styles.sliderMarker}>High</Text>
                </View>
              </View>
              
              {/* Generate Button */}
              <TouchableOpacity
                style={[styles.generateButton, isGenerating && styles.generateButtonDisabled]}
                onPress={handleGenerateScenario}
                disabled={isGenerating}
              >
                {isGenerating ? (
                  <View style={styles.buttonContent}>
                    <ActivityIndicator color="#fff" size="small" />
                    <Text style={styles.buttonText}>Generating...</Text>
                  </View>
                ) : (
                  <View style={styles.buttonContent}>
                    <Ionicons name="play" size={20} color="#fff" />
                    <Text style={styles.buttonText}>Generate Scenario</Text>
                  </View>
                )}
              </TouchableOpacity>
            </View>
          </View>
          
          {scenarioGenerated && (
            <View style={styles.results}>
              {/* Scenario Output Card */}
              <View style={styles.outputCard}>
                <TouchableOpacity 
                  style={styles.outputHeader}
                  onPress={() => setOutputExpanded(!outputExpanded)}
                >
                  <View style={styles.outputHeaderLeft}>
                    <Ionicons name="lock-closed" size={20} color="#6543cc" />
                    <Text style={styles.outputTitle}>Generated Scenario</Text>
                  </View>
                  
                  <View style={styles.outputControls}>
                    {!generationComplete && isGenerating && (
                      <View style={styles.progressContainer}>
                        <View style={styles.progressBar}>
                          <View 
                            style={[styles.progressFill, { width: `${streamProgress}%` }]}
                          />
                        </View>
                        <Text style={styles.progressLabel}>Generating...</Text>
                      </View>
                    )}
                    
                    <TouchableOpacity style={styles.toggleButton}>
                      <Ionicons 
                        name={outputExpanded ? "chevron-up" : "chevron-down"} 
                        size={20} 
                        color="#9da8b9" 
                      />
                    </TouchableOpacity>
                  </View>
                </TouchableOpacity>
                
                {outputExpanded && (
                  <ScrollView 
                    style={styles.outputContent}
                    ref={scenarioOutputRef}
                  >
                    {scenarioText ? (
                      <Text style={styles.scenarioText}>
                        {scenarioText}
                        {isGenerating && <Text style={styles.cursor}>|</Text>}
                      </Text>
                    ) : (
                      <View style={styles.placeholderContainer}>
                        <ActivityIndicator 
                          color="#6543cc" 
                          size="large"
                          animating={isGenerating}
                        />
                        <Text style={styles.placeholderText}>
                          Scenario will appear here...
                        </Text>
                      </View>
                    )}
                  </ScrollView>
                )}
              </View>
              
              {/* Questions Card */}
              {interactiveQuestions.length > 0 && (
                <View style={styles.questionsCard}>
                  <TouchableOpacity 
                    style={styles.questionsHeader}
                    onPress={() => setQuestionsExpanded(!questionsExpanded)}
                  >
                    <View style={styles.questionsHeaderLeft}>
                      <Ionicons name="help-circle" size={20} color="#6543cc" />
                      <Text style={styles.questionsTitle}>Knowledge Assessment</Text>
                    </View>
                    
                    <TouchableOpacity style={styles.toggleButton}>
                      <Ionicons 
                        name={questionsExpanded ? "chevron-up" : "chevron-down"} 
                        size={20} 
                        color="#9da8b9" 
                      />
                    </TouchableOpacity>
                  </TouchableOpacity>
                  
                  {questionsExpanded && (
                    <View style={styles.questionsContent}>
                      {Object.keys(feedback).length === interactiveQuestions.length && (
                        <View style={styles.assessmentComplete}>
                          <Ionicons name="checkmark-circle" size={24} color="#2ebb77" />
                          <View style={styles.assessmentResults}>
                            <Text style={styles.completionMessage}>Assessment Complete</Text>
                            <Text style={styles.scoreMessage}>
                              You scored {scoreCounter} out of {interactiveQuestions.length} correct
                            </Text>
                          </View>
                        </View>
                      )}
                      
                      {interactiveQuestions.map((question, index) => {
                        const questionFeedback = feedback[index];
                        const isCorrect = questionFeedback?.isCorrect;
                        
                        return (
                          <View key={index} style={styles.questionCard}>
                            <View style={styles.questionHeader}>
                              <Text style={styles.questionNumber}>Question {index + 1}</Text>
                              {questionFeedback && (
                                <View style={[
                                  styles.questionStatus,
                                  isCorrect ? styles.correctStatus : styles.incorrectStatus
                                ]}>
                                  <Ionicons 
                                    name={isCorrect ? "checkmark" : "close"} 
                                    size={16} 
                                    color={isCorrect ? "#2ebb77" : "#ff4e4e"} 
                                  />
                                  <Text style={[
                                    styles.statusText,
                                    isCorrect ? styles.correctText : styles.incorrectText
                                  ]}>
                                    {isCorrect ? "Correct" : "Incorrect"}
                                  </Text>
                                </View>
                              )}
                            </View>
                            
                            <Text style={styles.questionText}>{question.question}</Text>
                            
                            <View style={styles.optionsContainer}>
                              {Object.entries(question.options).map(([optionLetter, optionText]) => {
                                const isSelected = userAnswers[index] === optionLetter;
                                const showCorrect = questionFeedback && question.correct_answer === optionLetter;
                                const showIncorrect = questionFeedback && isSelected && !isCorrect;
                                
                                return (
                                  <TouchableOpacity
                                    key={optionLetter}
                                    style={[
                                      styles.optionButton,
                                      isSelected && styles.selectedOption,
                                      showCorrect && styles.correctOption,
                                      showIncorrect && styles.incorrectOption
                                    ]}
                                    onPress={() => handleAnswerSelect(index, optionLetter)}
                                    disabled={Object.prototype.hasOwnProperty.call(userAnswers, index)}
                                  >
                                    <View style={[
                                      styles.optionLetter,
                                      showCorrect && styles.correctLetter,
                                      showIncorrect && styles.incorrectLetter
                                    ]}>
                                      <Text style={styles.optionLetterText}>{optionLetter}</Text>
                                    </View>
                                    
                                    <Text style={styles.optionText}>{optionText}</Text>
                                    
                                    {showCorrect && (
                                      <Ionicons name="checkmark" size={20} color="#2ebb77" style={styles.optionIcon} />
                                    )}
                                    {showIncorrect && (
                                      <Ionicons name="close" size={20} color="#ff4e4e" style={styles.optionIcon} />
                                    )}
                                  </TouchableOpacity>
                                );
                              })}
                            </View>
                            
                            {questionFeedback && (
                              <View style={styles.feedbackContainer}>
                                <Ionicons name="bulb" size={20} color="#ffc107" style={styles.feedbackIcon} />
                                <Text style={styles.feedbackExplanation}>
                                  {questionFeedback.explanation}
                                </Text>
                              </View>
                            )}
                          </View>
                        );
                      })}
                    </View>
                  )}
                </View>
              )}
            </View>
          )}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0b0c15',
  },
  header: {
    backgroundColor: '#171a23',
    borderRadius: 15,
    margin: 15,
    marginBottom: 10,
    padding: 20,
    borderWidth: 1,
    borderColor: '#2a2c3d',
    position: 'relative',
    overflow: 'hidden',
    borderTopWidth: 4,
    borderTopColor: '#6543cc',
  },
  title: {
    fontSize: 26,
    fontWeight: 'bold',
    color: '#e2e2e2',
    textAlign: 'center',
    marginBottom: 5,
  },
  subtitle: {
    fontSize: 14,
    color: '#9da8b9',
    textAlign: 'center',
  },
  errorContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(255, 78, 78, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(255, 78, 78, 0.3)',
    borderRadius: 10,
    padding: 12,
    marginTop: 15,
  },
  errorText: {
    color: '#ff4e4e',
    marginLeft: 10,
    flex: 1,
    fontSize: 14,
  },
  errorCloseButton: {
    padding: 5,
  },
  scrollView: {
    flex: 1,
  },
  content: {
    padding: 15,
    paddingTop: 0,
  },
  paramsCard: {
    backgroundColor: '#171a23',
    borderRadius: 15,
    borderWidth: 1,
    borderColor: '#2a2c3d',
    overflow: 'hidden',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.4,
    shadowRadius: 24,
    elevation: 5,
    marginBottom: 20,
  },
  paramsHeader: {
    padding: 15,
    borderBottomWidth: 1,
    borderBottomColor: '#2a2c3d',
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  paramsHeaderLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  paramsTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#e2e2e2',
  },
  scoreCounter: {
    alignItems: 'center',
  },
  scoreValue: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#e2e2e2',
  },
  scoreHighlight: {
    color: '#6543cc',
  },
  scoreLabel: {
    fontSize: 12,
    color: '#9da8b9',
  },
  paramsContent: {
    padding: 15,
  },
  paramGroup: {
    marginBottom: 15,
  },
  paramLabel: {
    fontSize: 14,
    color: '#9da8b9',
    marginBottom: 8,
    fontWeight: '500',
  },
  pickerWrapper: {
    borderWidth: 1,
    borderColor: '#2a2c3d',
    borderRadius: 8,
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
    overflow: 'hidden',
  },
  picker: {
    color: '#e2e2e2',
    height: 50,
  },
  pickerItem: {
    fontSize: 16,
    color: '#e2e2e2',
  },
  inputWrapper: {
    flexDirection: 'row',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#2a2c3d',
    borderRadius: 8,
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
    paddingHorizontal: 15,
  },
  inputIcon: {
    marginRight: 10,
  },
  textInput: {
    flex: 1,
    color: '#e2e2e2',
    height: 50,
    fontSize: 16,
  },
  suggestionsContainer: {
    backgroundColor: '#171a23',
    borderWidth: 1,
    borderColor: '#2a2c3d',
    borderRadius: 8,
    marginTop: 5,
    maxHeight: 200,
    zIndex: 1,
  },
  suggestionsList: {
    padding: 5,
  },
  suggestionItem: {
    padding: 10,
    borderRadius: 5,
  },
  suggestionText: {
    color: '#e2e2e2',
    fontSize: 14,
  },
  showAllButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 10,
    borderTopWidth: 1,
    borderTopColor: '#2a2c3d',
    gap: 5,
  },
  showAllText: {
    color: '#6543cc',
    fontSize: 14,
  },
  sliderLabelContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  intensityBadge: {
    backgroundColor: '#6543cc',
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 10,
  },
  intensityValue: {
    color: 'white',
    fontSize: 12,
    fontWeight: 'bold',
  },
  slider: {
    width: '100%',
    height: 40,
  },
  sliderMarkers: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  sliderMarker: {
    fontSize: 12,
    color: '#9da8b9',
  },
  generateButton: {
    backgroundColor: '#6543cc',
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 20,
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 10,
    shadowColor: 'rgba(101, 67, 204, 0.3)',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 15,
    elevation: 5,
  },
  generateButtonDisabled: {
    backgroundColor: 'rgba(101, 67, 204, 0.5)',
    opacity: 0.7,
  },
  buttonContent: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
  results: {
    gap: 20,
  },
  outputCard: {
    backgroundColor: '#171a23',
    borderRadius: 15,
    borderWidth: 1,
    borderColor: '#2a2c3d',
    overflow: 'hidden',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.4,
    shadowRadius: 24,
    elevation: 5,
  },
  outputHeader: {
    padding: 15,
    borderBottomWidth: 1,
    borderBottomColor: '#2a2c3d',
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  outputHeaderLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  outputTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#e2e2e2',
  },
  outputControls: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  progressContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  progressBar: {
    width: 100,
    height: 8,
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
    borderRadius: 4,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#6543cc',
  },
  progressLabel: {
    fontSize: 12,
    color: '#9da8b9',
  },
  toggleButton: {
    width: 30,
    height: 30,
    borderRadius: 15,
    alignItems: 'center',
    justifyContent: 'center',
  },
  outputContent: {
    padding: 15,
    maxHeight: 300,
  },
  scenarioText: {
    color: '#e2e2e2',
    fontSize: 16,
    lineHeight: 24,
  },
  cursor: {
    color: '#6543cc',
    fontWeight: 'bold',
  },
  placeholderContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    padding: 30,
    gap: 15,
  },
  placeholderText: {
    color: '#9da8b9',
    fontSize: 16,
  },
  questionsCard: {
    backgroundColor: '#171a23',
    borderRadius: 15,
    borderWidth: 1,
    borderColor: '#2a2c3d',
    overflow: 'hidden',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.4,
    shadowRadius: 24,
    elevation: 5,
    marginBottom: 20,
  },
  questionsHeader: {
    padding: 15,
    borderBottomWidth: 1,
    borderBottomColor: '#2a2c3d',
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  questionsHeaderLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  questionsTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#e2e2e2',
  },
  questionsContent: {
    padding: 15,
  },
  assessmentComplete: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(46, 187, 119, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(46, 187, 119, 0.3)',
    borderRadius: 10,
    padding: 15,
    marginBottom: 20,
    gap: 15,
  },
  assessmentResults: {
    flex: 1,
  },
  completionMessage: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#e2e2e2',
    marginBottom: 5,
  },
  scoreMessage: {
    fontSize: 14,
    color: '#9da8b9',
  },
  questionCard: {
    backgroundColor: 'rgba(0, 0, 0, 0.15)',
    borderWidth: 1,
    borderColor: '#2a2c3d',
    borderRadius: 12,
    padding: 15,
    marginBottom: 20,
  },
  questionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 15,
  },
  questionNumber: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#6543cc',
  },
  questionStatus: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 20,
    gap: 5,
  },
  correctStatus: {
    backgroundColor: 'rgba(46, 187, 119, 0.1)',
  },
  incorrectStatus: {
    backgroundColor: 'rgba(255, 78, 78, 0.1)',
  },
  statusText: {
    fontSize: 12,
    fontWeight: 'bold',
  },
  correctText: {
    color: '#2ebb77',
  },
  incorrectText: {
    color: '#ff4e4e',
  },
  questionText: {
    fontSize: 16,
    color: '#e2e2e2',
    lineHeight: 24,
    marginBottom: 20,
  },
  optionsContainer: {
    gap: 10,
  },
  optionButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
    borderWidth: 1,
    borderColor: '#2a2c3d',
    borderRadius: 10,
    padding: 12,
  },
  selectedOption: {
    borderColor: '#6543cc',
    backgroundColor: 'rgba(101, 67, 204, 0.1)',
  },
  correctOption: {
    borderColor: '#2ebb77',
    backgroundColor: 'rgba(46, 187, 119, 0.1)',
  },
  incorrectOption: {
    borderColor: '#ff4e4e',
    backgroundColor: 'rgba(255, 78, 78, 0.1)',
  },
  optionLetter: {
    width: 30,
    height: 30,
    backgroundColor: '#0b0c15',
    borderRadius: 15,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  correctLetter: {
    backgroundColor: '#2ebb77',
  },
  incorrectLetter: {
    backgroundColor: '#ff4e4e',
  },
  optionLetterText: {
    color: '#e2e2e2',
    fontWeight: 'bold',
    fontSize: 14,
  },
  optionText: {
    flex: 1,
    color: '#e2e2e2',
    fontSize: 15,
    lineHeight: 22,
  },
  optionIcon: {
    marginLeft: 10,
  },
  feedbackContainer: {
    flexDirection: 'row',
    backgroundColor: 'rgba(255, 193, 7, 0.05)',
    borderWidth: 1,
    borderColor: 'rgba(255, 193, 7, 0.2)',
    borderRadius: 10,
    padding: 12,
    marginTop: 15,
    gap: 12,
  },
  feedbackIcon: {
    marginTop: 2,
  },
  feedbackExplanation: {
    flex: 1,
    fontSize: 14,
    color: '#9da8b9',
    lineHeight: 22,
  },
});

export default ScenarioSphereScreen;

// src/screens/tools/XploitCraftScreen.js
import React, { useState, useRef } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
  SafeAreaView,
  Image
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { StatusBar } from 'expo-status-bar';
import * as Clipboard from 'expo-clipboard';
import { useToast } from 'react-native-toast-notifications';
import { generatePayload } from '../../api/xploitService';

const XploitCraftScreen = () => {
  const [vulnerability, setVulnerability] = useState('');
  const [evasionTechnique, setEvasionTechnique] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [generatedPayload, setGeneratedPayload] = useState(null);
  
  const scrollViewRef = useRef();
  const toast = useToast();

  const handleGeneratePayload = async () => {
    if (!vulnerability.trim()) {
      toast.show('Please enter a vulnerability', {
        type: 'danger',
        duration: 3000,
      });
      return;
    }

    setIsLoading(true);
    setGeneratedPayload(null);

    try {
      const result = await generatePayload(vulnerability, evasionTechnique, true);
      
      // Parse the result if it's in a usable format
      if (typeof result === 'string') {
        // If the API just returns a string
        setGeneratedPayload({
          code_examples: [
            { 
              title: 'Payload', 
              code: result 
            }
          ],
          explanations: [
            {
              title: 'Explanation',
              content: 'Payload generated successfully.'
            }
          ]
        });
      } else if (typeof result === 'object') {
        // If the API returns a structured object
        setGeneratedPayload(result);
      }
      
      // Scroll to bottom to show results
      setTimeout(() => {
        if (scrollViewRef.current) {
          scrollViewRef.current.scrollToEnd({ animated: true });
        }
      }, 300);
      
    } catch (error) {
      console.error('Error generating payload:', error);
      toast.show('Error generating payload. Please try again.', {
        type: 'danger',
        duration: 3000,
      });
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = async (text) => {
    try {
      await Clipboard.setStringAsync(text);
      toast.show('Copied to clipboard!', {
        type: 'success',
        duration: 2000,
      });
    } catch (error) {
      console.error('Failed to copy:', error);
      toast.show('Failed to copy to clipboard', {
        type: 'danger',
        duration: 3000,
      });
    }
  };

  const copyAllToClipboard = async () => {
    if (!generatedPayload) return;
    
    try {
      let allText = '';
      
      // Add code examples
      if (generatedPayload.code_examples && generatedPayload.code_examples.length > 0) {
        generatedPayload.code_examples.forEach(example => {
          allText += `### ${example.title} ###\n\n${example.code}\n\n`;
        });
      }
      
      // Add explanations
      if (generatedPayload.explanations && generatedPayload.explanations.length > 0) {
        generatedPayload.explanations.forEach(explanation => {
          allText += `### ${explanation.title} ###\n\n${explanation.content}\n\n`;
        });
      }
      
      await Clipboard.setStringAsync(allText);
      toast.show('All content copied to clipboard!', {
        type: 'success',
        duration: 2000,
      });
    } catch (error) {
      console.error('Failed to copy all:', error);
      toast.show('Failed to copy content', {
        type: 'danger',
        duration: 3000,
      });
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />
      
      {/* Logo and Title */}
      <View style={styles.headerContainer}>
        <Text style={styles.title}>XploitCraft</Text>
      </View>
      
      <ScrollView 
        style={styles.scrollView}
        ref={scrollViewRef}
        contentContainerStyle={styles.scrollViewContent}
      >
        {/* Input Fields */}
        <View style={styles.inputContainer}>
          <TextInput
            style={styles.input}
            placeholder="Enter Vulnerability or Exploit"
            placeholderTextColor="#888"
            value={vulnerability}
            onChangeText={setVulnerability}
            editable={!isLoading}
          />
          
          <TextInput
            style={styles.input}
            placeholder="Enter Evasion Technique or Delivery Method"
            placeholderTextColor="#888"
            value={evasionTechnique}
            onChangeText={setEvasionTechnique}
            editable={!isLoading}
          />
        </View>
        
        {/* Generate Button */}
        <View style={styles.buttonContainer}>
          <TouchableOpacity
            style={[styles.generateButton, isLoading && styles.generateButtonDisabled]}
            onPress={handleGeneratePayload}
            disabled={isLoading}
          >
            {isLoading ? (
              <View style={styles.buttonContent}>
                <ActivityIndicator color="#fff" size="small" />
                <Text style={styles.buttonText}>Generating...</Text>
              </View>
            ) : (
              <Text style={styles.buttonText}>Generate Payload</Text>
            )}
          </TouchableOpacity>
        </View>
        
        {/* Results Container */}
        {generatedPayload && (
          <View style={styles.resultsContainer}>
            {/* Code Examples Section */}
            {generatedPayload.code_examples && generatedPayload.code_examples.length > 0 && (
              <View style={styles.sectionContainer}>
                <Text style={styles.sectionTitle}>Code Examples</Text>
                
                {generatedPayload.code_examples.map((example, index) => (
                  <View key={`code-${index}`} style={styles.codeBlock}>
                    <View style={styles.codeHeader}>
                      <Text style={styles.codeTitle}>{example.title}</Text>
                      <TouchableOpacity
                        style={styles.copyButton}
                        onPress={() => copyToClipboard(example.code)}
                      >
                        <Ionicons name="copy-outline" size={16} color="#fff" />
                        <Text style={styles.copyText}>Copy</Text>
                      </TouchableOpacity>
                    </View>
                    <ScrollView style={styles.codeContent}>
                      <Text style={styles.codeText}>{example.code}</Text>
                    </ScrollView>
                  </View>
                ))}
              </View>
            )}
            
            {/* Explanations Section */}
            {generatedPayload.explanations && generatedPayload.explanations.length > 0 && (
              <View style={styles.sectionContainer}>
                <Text style={styles.sectionTitle}>Explanations</Text>
                
                {generatedPayload.explanations.map((explanation, index) => (
                  <View key={`exp-${index}`} style={styles.explanationBlock}>
                    <Text style={styles.explanationTitle}>{explanation.title}</Text>
                    <Text style={styles.explanationText}>{explanation.content}</Text>
                  </View>
                ))}
              </View>
            )}
            
            {/* Copy All Button */}
            <TouchableOpacity
              style={styles.copyAllButton}
              onPress={copyAllToClipboard}
            >
              <Ionicons name="copy-outline" size={20} color="#fff" />
              <Text style={styles.copyAllText}>Copy All Content</Text>
            </TouchableOpacity>
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#000',
  },
  headerContainer: {
    alignItems: 'center',
    paddingVertical: 20,
    backgroundColor: 'rgba(0, 0, 0, 0.7)',
    borderBottomWidth: 3,
    borderBottomColor: '#660000',
  },
  title: {
    fontSize: 36,
    fontWeight: 'bold',
    color: '#fff',
    textShadowColor: '#ff0000',
    textShadowOffset: { width: 1, height: 1 },
    textShadowRadius: 10,
  },
  scrollView: {
    flex: 1,
  },
  scrollViewContent: {
    padding: 20,
  },
  inputContainer: {
    gap: 15,
    marginBottom: 20,
  },
  input: {
    backgroundColor: 'rgba(51, 51, 51, 0.8)',
    borderWidth: 2,
    borderColor: '#660000',
    borderRadius: 10,
    color: '#fff',
    padding: 15,
    fontSize: 16,
  },
  buttonContainer: {
    alignItems: 'center',
    marginBottom: 20,
  },
  generateButton: {
    backgroundColor: '#660000',
    borderRadius: 10,
    paddingVertical: 15,
    paddingHorizontal: 30,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 3,
    borderColor: '#000',
    minWidth: 200,
  },
  generateButtonDisabled: {
    backgroundColor: '#330000',
    opacity: 0.7,
  },
  buttonContent: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
  },
  buttonText: {
    color: '#fff',
    fontSize: 18,
    fontWeight: 'bold',
    textShadowColor: '#000',
    textShadowOffset: { width: 1, height: 1 },
    textShadowRadius: 2,
  },
  resultsContainer: {
    backgroundColor: 'rgba(30, 30, 30, 0.92)',
    borderRadius: 10,
    borderWidth: 3,
    borderColor: '#660000',
    padding: 20,
    gap: 20,
  },
  sectionContainer: {
    gap: 15,
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#ff0000',
    marginBottom: 10,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255, 0, 0, 0.3)',
    paddingBottom: 5,
  },
  codeBlock: {
    backgroundColor: 'rgba(0, 0, 0, 0.3)',
    borderRadius: 10,
    borderWidth: 1,
    borderColor: 'rgba(255, 0, 0, 0.2)',
    overflow: 'hidden',
  },
  codeHeader: {
    backgroundColor: 'rgba(102, 0, 0, 0.7)',
    paddingVertical: 10,
    paddingHorizontal: 15,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  codeTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#fff',
  },
  copyButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    paddingVertical: 5,
    paddingHorizontal: 10,
    borderRadius: 5,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.3)',
    gap: 5,
  },
  copyText: {
    fontSize: 12,
    color: '#fff',
  },
  codeContent: {
    padding: 15,
    maxHeight: 250,
  },
  codeText: {
    fontFamily: 'monospace',
    fontSize: 14,
    color: '#e0e0e0',
  },
  explanationBlock: {
    backgroundColor: 'rgba(0, 0, 0, 0.3)',
    borderRadius: 10,
    padding: 15,
    borderWidth: 1,
    borderColor: 'rgba(255, 0, 0, 0.2)',
  },
  explanationTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#ff6666',
    marginBottom: 10,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255, 0, 0, 0.2)',
    paddingBottom: 5,
  },
  explanationText: {
    fontSize: 15,
    color: '#e0e0e0',
    lineHeight: 22,
  },
  copyAllButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#660000',
    paddingVertical: 12,
    paddingHorizontal: 20,
    borderRadius: 10,
    borderWidth: 3,
    borderColor: '#000',
    alignSelf: 'center',
    marginTop: 10,
    gap: 10,
  },
  copyAllText: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#fff',
  },
});

export default XploitCraftScreen;

ok so we made the Ui files now fro the tools nwo what do we do next??

so i guess then we move onto the next steps and so on ok? cool? they will be in teh pormpt i giev you directly


tehn well continue on with my next files and so on. adn at teh evry end of eveyrthing ill test the app with expo on iphone (i dont have mac access at the moment) and udpate all UI to my liking but still try your best we want teh ebst mobniel app on teh app stoire, coolest/ bets fucnitoning etc etc. simialr to my web app obviolsya dn ahs to integrate well with it so all user data is replciate don teh ios app adn web app adn you already know, you this this, you are the best! ok lets goo!!











