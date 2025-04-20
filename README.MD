# CertGames Core - Advanced Cybersecurity Training Platform

![CertGames Logo](https://certgames.com/assets/logo-dark.png)

[![React](https://img.shields.io/badge/React-18.3.1-61dafb.svg)](https://reactjs.org/)
[![React Native](https://img.shields.io/badge/React_Native-0.76.7-0088CC.svg)](https://reactnative.dev/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-black.svg)](https://flask.palletsprojects.com/)
[![OpenAI](https://img.shields.io/badge/OpenAI_Integration-GPT4-412991.svg)](https://openai.com/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED.svg)](https://www.docker.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-4DB33D.svg)](https://www.mongodb.com/cloud/atlas)
[![Redis](https://img.shields.io/badge/Redis-6.2-DC382D.svg)](https://redis.io/)

## Overview

CertGames is a comprehensive cybersecurity training platform designed to help IT professionals prepare for certification exams through gamified learning experiences. The platform integrates advanced AI-driven tools, practice tests, and interactive simulations to create an engaging learning environment.

**Live Platform:** [certgames.com](https://certgames.com)  
**iOS App:** [App Store Link](https://apps.apple.com/us/app/comptia-cert-games-practice/id6743811522)  
**LinkedIn:** [CertGames](https://www.linkedin.com/company/certgames/) | [Developer Profile](https://www.linkedin.com/in/carterperez-dev/)  
**Portfolio:** [carterperez-dev.com](https://carterperez-dev.com/)

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Core Components](#core-components)
- [Tech Stack](#tech-stack)
- [Reactive Multi-Platform Design](#reactive-multi-platform-design)
- [API Architecture](#api-architecture)
- [AI Integration](#ai-integration)
- [Database Schema](#database-schema)
- [Security Implementation](#security-implementation)
- [Deployment Architecture](#deployment-architecture)
- [Performance Optimizations](#performance-optimizations)
- [Testing Methodology](#testing-methodology)
- [Future Development Roadmap](#future-development-roadmap)
- [Contact & Support](#contact--support)

## Architecture Overview

CertGames implements a distributed microservices architecture with containerized components, focusing on security, scalability, and high availability. The platform is built on modern web technologies with cross-platform support.

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Cloudflare DNS/CDN Layer                         │
└───────────────────────────────────┬─────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           NGINX Reverse Proxy                           │
└───────────────┬───────────────────────────────────────┬─────────────────┘
               ▼                                       ▼
┌─────────────────────────┐           ┌──────────────────────────────────┐
│    Apache Web Server    │           │        Flask API Server          │
│  (Static Assets/Routing)│           │    (Microservices Endpoints)     │
└──────────┬──────────────┘           └──────────────┬──────────────────┬┘
           │                                         │                  │
           ▼                                         ▼                  ▼
┌────────────────────┐              ┌─────────────────────┐    ┌────────────────┐
│  React Front-end   │              │  Celery Workers     │    │ Socket.IO      │
│  (SPA Application) │              │  (Async Processing) │    │ (Real-time)    │
└────────────────────┘              └─────────┬───────────┘    └────────────────┘
                                              │
                                              ▼
┌──────────────────────┐            ┌─────────────────────┐    ┌────────────────┐
│  React Native iOS    │            │  Redis              │    │  MongoDB Atlas │
│  (Mobile App)        │─ ─ ─ ─ ─ ─▶│  (Cache/Sessions)   │◀───│  (Database)    │
└──────────────────────┘            └─────────────────────┘    └────────────────┘
```

## Core Components

The CertGames platform consists of several interconnected components that work together to deliver a seamless experience:

### 1. Web Application (React)

The web frontend is built as a single-page application using React 18 with Redux for state management. Key features include:

- **Redux Toolkit** implementation for efficient state management
- **Themeable UI** with dynamic color schemes for accessibility
- **Socket.IO** integration for real-time features
- **Responsive design** with mobile-first approach
- **SEO optimization** with React Helmet and structured data
- **Protected routes** with subscription-based access control

### 2. Mobile Application (React Native/Expo)

The iOS application is built with React Native and Expo, sharing business logic with the web application:

- **Expo SDK 52** for simplified native feature access
- **AsyncStorage/SecureStore** for secure data persistence
- **React Navigation 7** for native navigation patterns
- **Offline support** with queue-based synchronization
- **Native authentication** via Apple and Google Sign-In
- **In-app purchases** through Apple's StoreKit

### 3. Backend API (Flask/Python)

A comprehensive Flask application serves as the backend API layer:

- **Modular Blueprint architecture** for organized endpoint groups
- **JWT authentication** with advanced security features
- **Rate limiting** to prevent abuse and DDOS attacks
- **Async processing** with Celery for long-running tasks
- **WebSocket support** via Socket.IO for real-time features
- **OpenAI integration** for AI-assisted learning tools

### 4. Infrastructure Components

- **NGINX** as a reverse proxy and load balancer
- **Apache** for serving static assets
- **Redis** for session management, caching, and Celery broker
- **MongoDB Atlas** as the primary database
- **Docker** for containerization and deployment consistency
- **Cloudflare** for CDN, DNS, and DDoS protection

## Tech Stack

### Frontend (Web)

### Mobile (iOS)

### Backend (API)

### Infrastructure

## Reactive Multi-Platform Design

CertGames employs a reactive architecture pattern to ensure consistency across web and mobile platforms while optimizing for each platform's unique capabilities.

### Shared Logic Pattern

### Key Implementation Points:

1. **Isomorphic Redux Store**: The Redux store structure is identical between web and mobile, with platform-specific middleware handling persistence differences.

2. **Shared API Client**: A custom API client abstraction layer provides consistent data fetching with platform-specific adapters (Axios on web, modified Axios on mobile with offline support).

3. **Cross-Platform Authentication**: OAuth 2.0 flows are standardized but implemented with platform-appropriate SDKs (web browser redirects vs. native iOS authentication).

4. **Custom Hooks Library**: Common business logic is encapsulated in custom React hooks that are reused across platforms with platform-specific implementations where needed.

5. **Responsive Design System**: A unified design system with theme variables that are implemented via CSS variables on web and StyleSheet on mobile.

## API Architecture

The backend API follows a modular architecture using Flask Blueprints. Each functional domain is implemented as a separate blueprint with its own routes, business logic, and middleware.

### API Documentation

The API follows RESTful principles with consistent patterns:

- Base URL structure: `https://certgames.com/api/`
- Authentication: JWT tokens in Authorization header (`Bearer <token>`)
- Response format: JSON with consistent structure
- Error handling: Standardized error codes and messages
- Rate limiting: Progressive with header information

Example endpoint structure:

## AI Integration

CertGames leverages AI throughout the platform to enhance the learning experience. This is primarily implemented through OpenAI's GPT-4 API with custom prompt engineering.

### AI-Powered Features

1. **Analogy Generation**: Creates analogies for complex cybersecurity concepts to aid in understanding
2. **Scenario Creation**: Generates realistic cybersecurity scenarios for hands-on training
3. **GRC Question Generation**: Produces governance, risk, and compliance questions with adaptive difficulty
4. **Exploit Simulation**: Demonstrates conceptual exploit generation for educational purposes
5. **Support Assistance**: Provides AI-enhanced support responses

### AI Integration Architecture

### Prompt Engineering Example

## Database Schema

CertGames uses MongoDB as its primary database, leveraging its document-oriented nature for flexibility and scalability. The schema is designed for performance with appropriate indexing and denormalization where beneficial.

### Core Collections

### Schema Design Principles

1. **Strategic Denormalization**: Test documents include all questions to minimize round trips for test loading, while user activity is stored in separate collections.

2. **Compound Indexing**: Multiple indexes support common query patterns, such as finding unfinished test attempts for a specific user.

3. **Temporal Data Management**: Time-series data like performance metrics and rate limiting have TTL indexes for automatic pruning.

4. **Flexible Document Structure**: Leverages MongoDB's schema flexibility while maintaining consistent patterns for similar document types.

5. **Embedded vs. Referenced**: Uses embedded documents for tightly coupled data (test questions) and references for shared resources (shop items).

## Security Implementation

Security is a top priority in CertGames, with multiple layers of protection throughout the system.

### Authentication System

### Security Features

1. **Multi-layered Authentication**:
   - Password hashing with bcrypt
   - OAuth 2.0 integration (Google, Apple)
   - Session management with Redis
   - Secure token storage (HTTP-only cookies on web, SecureStore on mobile)

2. **Access Control**:
   - Role-based permissions for admin features
   - Subscription-based access control for premium content
   - IP-based restrictions for admin portal

3. **Rate Limiting and DDoS Protection**:
   - Progressive rate limiting with increasing penalties
   - Cloudflare DDoS protection
   - IP-based blocking for repeated violations

4. **Data Protection**:
   - TLS/SSL encryption for all connections
   - Sanitized inputs with custom validation
   - Parameterized database queries
   - Limited data exposure (principle of least privilege)

5. **Infrastructure Security**:
   - Container isolation
   - Regular security updates
   - Least privilege principle for service accounts
   - Network segmentation in Docker

6. **Monitoring and Auditing**:
   - Comprehensive request logging
   - Failed authentication tracking
   - Admin action auditing
   - Automated suspicious activity detection

## Deployment Architecture

CertGames uses a containerized deployment architecture with Docker, orchestrated through docker-compose for simplified deployment and scaling.

### Deployment Process

1. **Development**: Code is developed locally with feature branches
2. **Testing**: Automated testing in GitHub Actions
3. **Build**: Docker images are built and tagged
4. **Deployment**: Docker Compose deployment script
5. **Verification**: Automated health checks post-deployment
6. **Monitoring**: Continuous monitoring of performance metrics

### Infrastructure as Code

The entire infrastructure is defined in code for reproducibility:

## Performance Optimizations

CertGames employs multiple performance optimization techniques to ensure a fast, responsive experience for users.

### Backend Optimizations

1. **Database Indexing**: Strategic indexes on MongoDB collections for common query patterns

2. **Caching Strategy**:
   - Redis for session data and API responses
   - Multi-level caching (memory, Redis, database)
   - Conditional ETag-based caching

3. **Asynchronous Processing**:
   - Celery for long-running tasks
   - Response streaming for AI-generated content
   - WebSockets for real-time updates

4. **Efficient Database Access**:
   - Batch operations for bulk updates
   - Projection queries to retrieve only needed fields
   - Connection pooling with PyMongo

5. **Load Optimization**:
   - NGINX compression and caching
   - Content preloading and lazy loading
   - Resource prioritization

### Frontend Optimizations

1. **Code Splitting**: Dynamic imports reduce initial bundle size

2. **Lazy Loading**: Components and assets loaded only when needed

3. **State Management**: Optimized Redux store with selective persistence

4. **Rendering Optimization**:
   - React.memo for component memoization
   - Virtualized lists for large data sets
   - CSS optimizations with critical path rendering

5. **Network Efficiency**:
   - GraphQL-like request batching
   - Debounced API calls
   - Progressive image loading

### Mobile Optimizations

1. **Native Performance**:
   - React Native gesture handler for fluid animations
   - Native module bridging for performance-critical features
   - Memory management with component lifecycle hooks

2. **Offline Support**:
   - AsyncStorage for data persistence
   - Queue-based synchronization for offline actions
   - Optimistic UI updates

3. **Battery Efficiency**:
   - Reduced background processing
   - Efficient location services usage
   - Network batching to minimize radio usage

## Testing Methodology

CertGames employs a comprehensive testing strategy to ensure quality and reliability:

### Testing Tools and Frameworks

- **Unit Testing**: Jest, React Testing Library, PyTest
- **Integration Testing**: Supertest, Redux Mock Store, MongoDB Memory Server
- **End-to-End Testing**: Cypress, Detox (for React Native)
- **Performance Testing**: Locust, Lighthouse, React Profiler
- **Security Testing**: OWASP ZAP, npm audit, Snyk

### Test Automation

Automated testing is integrated into the development workflow:

1. **Pre-commit Hooks**: Linting and unit tests before commits
2. **CI Pipeline**: Full test suite runs on GitHub Actions
3. **Deployment Gates**: Tests must pass before deployment
4. **Scheduled Scans**: Regular security and performance testing
5. **Monitoring**: Continuous verification in production

## Future Development Roadmap

CertGames is actively evolving with several initiatives in progress:

1. **Android Application**: Currently in development to expand mobile reach

2. **Enhanced AI-Powered Learning Tools**:
   - PBQ (Performance-Based Question) cybersecurity training games
   - Advanced scenario generation with adaptive difficulty
   - AI-guided personalized learning paths

3. **Expanded Content**:
   - Resume builder with AI assistance
   - Interactive penetration testing simulation environment
   - Hands-on "Hack the Box"-style challenges
   - Video course integration directly into the platform

4. **Infrastructure Improvements**:
   - Enhanced monitoring and alerting
   - Automated scaling based on demand
   - Regional distribution for improved latency
   - Advanced caching strategies

5. **Community Features**:
   - Collaborative learning tools
   - Peer review system for practice assignments
   - Mentorship connections

## Current Platform Statistics

- **Total Users**: 508 (108 paid subscribers, 400 free tier)
- **Content Library**: 130+ certification practice tests across 12 certification paths
- **Response Time**: Average API response time under 150ms
- **Uptime**: 99.97% uptime since launch
- **Mobile Engagement**: 65% of premium users access via both web and iOS app

## Contact & Support

- **General Inquiries**: inquiry@certgames.com
- **Support**: support@certgames.com
- **Developer Contact**: dev@certgames.com
- **Phone**: 443-510-0866
- **LinkedIn**: [CertGames Company Page](https://www.linkedin.com/company/certgames/)

---

## License

This codebase is proprietary and confidential. © 2025 CertGames LLC. All rights reserved.

---

*This README was generated for the CertGames Core repository by Carter Perez (https://www.linkedin.com/in/carterperez-dev/), with over 1300+ hours of development invested in the platform.*























































```ruby
.
# 4/20/2025
---
```ruby
Root.
├── Audit
│   └── bandit.yaml
├── ENV
├── Mongo-Inputs
│   ├── Achievments.js
│   ├── ShopItems.js
│   └── TestUsers.js
├── README.MD
├── Stack
│   ├── API
│   │   └── routes.md
│   ├── Architecture
│   │   ├── DB.md
│   │   ├── Optimized3.md
│   │   └── stack.flow.md
│   └── Trees
│       ├── Flask.md
│       ├── React.md
│       └── Root.md
├── apache
│   ├── Dockerfile.apache
│   ├── apache_server.conf
│   └── httpd.conf
├── backend
│   ├── API
│   │   └── AI.py
│   ├── Dockerfile.backend
│   ├── app.py
│   ├── celerybeat-schedule
│   ├── helpers
│   │   ├── analogy_stream_helper.py
│   │   ├── async_tasks.py
│   │   ├── celery_app.py
│   │   ├── global_rate_limiter.py
│   │   ├── grc_stream_helper.py
│   │   ├── rate_limiter.py
│   │   ├── scenario_helper.py
│   │   └── xploitcraft_helper.py
│   ├── middleware
│   │   └── subscription_check.py
│   ├── models
│   │   ├── __init__.py
│   │   ├── newsletter.py
│   │   ├── password_reset.py
│   │   └── test.py
│   ├── mongodb
│   │   ├── __init__.py
│   │   └── database.py
│   ├── requirements.txt
│   ├── routes
│   │   ├── AI
│   │   │   ├── analogy_routes.py
│   │   │   ├── grc_routes.py
│   │   │   ├── scenario_routes.py
│   │   │   └── xploit_routes.py
│   │   ├── SubscriptionAuth
│   │   │   ├── oauth_routes.py
│   │   │   ├── password_reset_routes.py
│   │   │   ├── subscription_routes.py
│   │   │   └── utils.py
│   │   ├── admin
│   │   │   ├── admin_newsletter_routes.py
│   │   │   └── cracked_admin.py
│   │   ├── games
│   │   │   ├── cipher_routes.py
│   │   │   ├── incident_routes.py
│   │   │   ├── phishing_routes.py
│   │   │   └── threat_hunter_routes.py
│   │   ├── info
│   │   │   └── contact_form.py
│   │   └── main
│   │       ├── __init__.py
│   │       ├── achievements_routes.py
│   │       ├── blueprint.py
│   │       ├── cancel_routes.py
│   │       ├── daily_question_routes.py
│   │       ├── leaderboard_routes.py
│   │       ├── newsletter_routes.py
│   │       ├── shop_routes.py
│   │       ├── support_routes.py
│   │       ├── test_attempt_routes.py
│   │       ├── test_routes.py
│   │       ├── user_routes.py
│   │       └── utils.py
│   └── utils
│       ├── __init__.py
│       ├── apple_iap_verification.py
│       ├── email_sender.py
│       └── utils.py
├── docker-compose.yml
├── frontend
│   └── my-react-app
│       ├── Dockerfile.audit
│       ├── Dockerfile.dev
│       ├── Dockerfile.frontend
│       ├── craco.config.js
│       ├── eslint.config.mjs
│       ├── package-lock.json
│       ├── package.json
│       ├── public
│       │   ├── android-chrome-192x192.png
│       │   ├── android-chrome-512x512.png
│       │   ├── apple-touch-icon.png
│       │   ├── favicon-16x16.png
│       │   ├── favicon-32x32.png
│       │   ├── favicon.ico
│       │   ├── images
│       │   ├── index.html
│       │   ├── ios.png
│       │   ├── manifest.json
│       │   ├── robots.txt
│       │   ├── site.webmanifest
│       │   └── sitemap.xml
│       └── src
│           ├── App.js
│           ├── components
│           │   ├── ConfettiAnimation.js
│           │   ├── Footer.js
│           │   ├── FormattedQuestion.js
│           │   ├── GlobalTestList.js
│           │   ├── GlobalTestPage.js
│           │   ├── PrivacyPolicyIOS.js
│           │   ├── ProtectedRoute.js
│           │   ├── QuestionLimitBanner.css
│           │   ├── QuestionLimitBanner.js
│           │   ├── SEOHelmet.js
│           │   ├── Sidebar
│           │   │   ├── Sidebar.css
│           │   │   ├── Sidebar.js
│           │   │   └── sidebarlogo.png
│           │   ├── StructuredData.js
│           │   ├── SubscriptionErrorHandler.js
│           │   ├── UpgradePrompt.css
│           │   ├── UpgradePrompt.js
│           │   ├── colorMapping.js
│           │   ├── cracked
│           │   │   ├── CrackedAdminDashboard.js
│           │   │   ├── CrackedAdminLoginPage.js
│           │   │   ├── images
│           │   │   │   ├── image1.jpg
│           │   │   │   ├── image2.jpg
│           │   │   │   ├── image3.jpg
│           │   │   │   ├── image4.jpg
│           │   │   │   ├── image5.jpg
│           │   │   │   ├── image6.jpg
│           │   │   │   ├── image7.jpg
│           │   │   │   ├── image8.jpg
│           │   │   │   └── image9.jpg
│           │   │   ├── music
│           │   │   │   └── elevator-music.mp3
│           │   │   ├── styles
│           │   │   │   ├── CrackedAdminDashboard.css
│           │   │   │   ├── CrackedAdminLogin.css
│           │   │   │   └── tabstyles
│           │   │   │       ├── ActivityLogsTab.css
│           │   │   │       ├── DailyTab.css
│           │   │   │       ├── DbShellTab.css
│           │   │   │       ├── HealthCheckTab.css
│           │   │   │       ├── NewsletterTab.css
│           │   │   │       ├── OverviewTab.css
│           │   │   │       ├── PerformanceTab.css
│           │   │   │       ├── RateLimitsTab.css
│           │   │   │       ├── RequestLogsTab.css
│           │   │   │       ├── RevenueTab.css
│           │   │   │       ├── ServerMetricsTab.css
│           │   │   │       ├── SupportTab.css
│           │   │   │       ├── TestsTab.css
│           │   │   │       ├── ToolsTab.css
│           │   │   │       └── UsersTab.css
│           │   │   └── tabs
│           │   │       ├── ActivityLogsTab.js
│           │   │       ├── DailyTab.js
│           │   │       ├── DbShellTab.js
│           │   │       ├── HealthChecksTab.js
│           │   │       ├── NewsletterTab.js
│           │   │       ├── OverviewTab.js
│           │   │       ├── PerformanceTab.js
│           │   │       ├── RateLimitsTab.js
│           │   │       ├── RequestLogsTab.js
│           │   │       ├── RevenueTab.js
│           │   │       ├── ServerMetricsTab.js
│           │   │       ├── SupportTab.js
│           │   │       ├── TestsTab.js
│           │   │       ├── ToolsTab.js
│           │   │       └── UsersTab.js
│           │   ├── footer.css
│           │   ├── iconMapping.js
│           │   ├── og-default.jpg
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
│           │   │   │   ├── BlogPage.js
│           │   │   │   ├── BlogPostPage.js
│           │   │   │   ├── ContactPage.js
│           │   │   │   ├── DemosPage.js
│           │   │   │   ├── ExamsPage.js
│           │   │   │   ├── InfoNavbar.js
│           │   │   │   ├── InfoPage.js
│           │   │   │   ├── PublicLeaderboardPage.js
│           │   │   │   ├── YouTubeEmbed.js
│           │   │   │   ├── css
│           │   │   │   │   ├── BlogPage.css
│           │   │   │   │   ├── ContactPage.css
│           │   │   │   │   ├── DemosPage.css
│           │   │   │   │   ├── ExamsPage.css
│           │   │   │   │   ├── InfoNavbar.css
│           │   │   │   │   ├── InfoPage.css
│           │   │   │   │   └── PublicLeaderboardPage.css
│           │   │   │   ├── images
│           │   │   │   │   ├── 1.webp
│           │   │   │   │   ├── 10.webp
│           │   │   │   │   ├── 11.webp
│           │   │   │   │   ├── 12.webp
│           │   │   │   │   ├── 13.webp
│           │   │   │   │   ├── 14.webp
│           │   │   │   │   ├── 15.webp
│           │   │   │   │   ├── 2.webp
│           │   │   │   │   ├── 3.webp
│           │   │   │   │   ├── 4.webp
│           │   │   │   │   ├── 5.webp
│           │   │   │   │   ├── 6.webp
│           │   │   │   │   ├── 7.webp
│           │   │   │   │   ├── 8.webp
│           │   │   │   │   ├── 9.webp
│           │   │   │   │   ├── CISS.webp
│           │   │   │   │   ├── achi.webp
│           │   │   │   │   ├── analogy.webp
│           │   │   │   │   ├── aplus.webp
│           │   │   │   │   ├── apple.svg
│           │   │   │   │   ├── awscloud.webp
│           │   │   │   │   ├── bonus.webp
│           │   │   │   │   ├── cissp.webp
│           │   │   │   │   ├── cloud.webp
│           │   │   │   │   ├── cloudsec.webp
│           │   │   │   │   ├── colors.webp
│           │   │   │   │   ├── cysa.webp
│           │   │   │   │   ├── data.webp
│           │   │   │   │   ├── exammode.webp
│           │   │   │   │   ├── gamified.webp
│           │   │   │   │   ├── grc.webp
│           │   │   │   │   ├── leader (copy 1).webp
│           │   │   │   │   ├── leader.webp
│           │   │   │   │   ├── linux.webp
│           │   │   │   │   ├── network.webp
│           │   │   │   │   ├── news.webp
│           │   │   │   │   ├── pbqs.webp
│           │   │   │   │   ├── pentest.webp
│           │   │   │   │   ├── rec.webp
│           │   │   │   │   ├── review.webp
│           │   │   │   │   ├── scen.webp
│           │   │   │   │   ├── security.webp
│           │   │   │   │   ├── securityplus.webp
│           │   │   │   │   ├── securityx.webp
│           │   │   │   │   ├── server.webp
│           │   │   │   │   ├── shop.webp
│           │   │   │   │   ├── support.webp
│           │   │   │   │   ├── test.webp
│           │   │   │   │   ├── user1.webp
│           │   │   │   │   ├── user2.webp
│           │   │   │   │   ├── user3.webp
│           │   │   │   │   ├── user6.webp
│           │   │   │   │   ├── user8.webp
│           │   │   │   │   ├── xboost.webp
│           │   │   │   │   └── xploit.webp
│           │   │   │   ├── navbarScrollUtils.js
│           │   │   │   └── videoConfig.js
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
│           │   │   ├── StatsPage
│           │   │   │   ├── StatsPage.css
│           │   │   │   └── StatsPage.js
│           │   │   ├── TermsOfService.js
│           │   │   ├── XploitcraftPage
│           │   │   │   ├── App.css
│           │   │   │   ├── Xploitcraft.js
│           │   │   │   ├── backround2.jpg
│           │   │   │   ├── loading3.png
│           │   │   │   └── logo5.png
│           │   │   ├── auth
│           │   │   │   ├── CreateUsernameForm.js
│           │   │   │   ├── ErrorDisplay.js
│           │   │   │   ├── ForgotPassword.js
│           │   │   │   ├── Login.js
│           │   │   │   ├── OAuthSuccess.js
│           │   │   │   ├── PasswordRequirements.js
│           │   │   │   ├── Register.js
│           │   │   │   ├── ResetPassword.js
│           │   │   │   └── css
│           │   │   │       ├── CreateUsernameForm.css
│           │   │   │       ├── ErrorDisplay.css
│           │   │   │       ├── ForgotPassword.css
│           │   │   │       ├── Login.css
│           │   │   │       ├── PasswordRequirements.css
│           │   │   │       ├── Register.css
│           │   │   │       └── ResetPassword.css
│           │   │   ├── games
│           │   │   │   ├── CipherChallenge
│           │   │   │   │   ├── CipherChallenge.css
│           │   │   │   │   ├── CipherChallenge.js
│           │   │   │   │   ├── CipherDisplay.css
│           │   │   │   │   ├── CipherDisplay.js
│           │   │   │   │   ├── CipherHints.css
│           │   │   │   │   ├── CipherHints.js
│           │   │   │   │   ├── CipherInfoModal.css
│           │   │   │   │   ├── CipherInfoModal.js
│           │   │   │   │   ├── CipherInput.css
│           │   │   │   │   ├── CipherInput.js
│           │   │   │   │   ├── CipherTools.css
│           │   │   │   │   ├── CipherTools.js
│           │   │   │   │   ├── CongratulationsModal.css
│           │   │   │   │   ├── CongratulationsModal.js
│           │   │   │   │   ├── LevelSelector.css
│           │   │   │   │   └── LevelSelector.js
│           │   │   │   ├── IncidentResponder
│           │   │   │   │   ├── DifficultySelector.js
│           │   │   │   │   ├── IncidentResponder.css
│           │   │   │   │   ├── IncidentResponder.js
│           │   │   │   │   ├── ScenarioIntro.js
│           │   │   │   │   ├── ScenarioResults.js
│           │   │   │   │   └── ScenarioStage.js
│           │   │   │   ├── PhishingPhrenzy
│           │   │   │   │   ├── GameOverModal.css
│           │   │   │   │   ├── GameOverModal.js
│           │   │   │   │   ├── PhishingCard.css
│           │   │   │   │   ├── PhishingCard.js
│           │   │   │   │   ├── PhishingPhrenzy.css
│           │   │   │   │   └── PhishingPhrenzy.js
│           │   │   │   └── ThreatHunter
│           │   │   │       ├── AnalysisTools.js
│           │   │   │       ├── GameInstructions.css
│           │   │   │       ├── GameInstructions.js
│           │   │   │       ├── LogViewer.js
│           │   │   │       ├── ScenarioSelector.js
│           │   │   │       ├── ThreatControls.js
│           │   │   │       ├── ThreatHunter.css
│           │   │   │       ├── ThreatHunter.js
│           │   │   │       └── ThreatResultsModal.js
│           │   │   ├── ios
│           │   │   │   ├── AppleLegalPages.css
│           │   │   │   ├── PrivacyPolicyIOS.js
│           │   │   │   └── TermsOfServiceIOS.js
│           │   │   ├── store
│           │   │   │   ├── AchievementPage.js
│           │   │   │   ├── AchievementToast.js
│           │   │   │   ├── DailyStationPage.js
│           │   │   │   ├── LeaderboardPage.js
│           │   │   │   ├── ShopPage.js
│           │   │   │   ├── SupportAskAnythingPage.js
│           │   │   │   ├── UserProfile.js
│           │   │   │   ├── css
│           │   │   │   │   ├── AchievementPage.css
│           │   │   │   │   ├── AchievementToast.css
│           │   │   │   │   ├── DailyStation.css
│           │   │   │   │   ├── LeaderboardPage.css
│           │   │   │   │   ├── ShopPage.css
│           │   │   │   │   ├── SupportAskAnythingPage.css
│           │   │   │   │   └── UserProfile.css
│           │   │   │   ├── slice
│           │   │   │   │   ├── achievementsSlice.js
│           │   │   │   │   ├── cipherChallengeSlice.js
│           │   │   │   │   ├── incidentResponderSlice.js
│           │   │   │   │   ├── phishingPhrenzySlice.js
│           │   │   │   │   ├── shopSlice.js
│           │   │   │   │   ├── threatHunterSlice.js
│           │   │   │   │   └── userSlice.js
│           │   │   │   └── store.js
│           │   │   ├── subscription
│           │   │   │   ├── StripeCheckout.js
│           │   │   │   ├── SubscriptionCancel.js
│           │   │   │   ├── SubscriptionPage.js
│           │   │   │   ├── SubscriptionSuccess.js
│           │   │   │   └── css
│           │   │   │       ├── StripeCheckout.css
│           │   │   │       ├── SubscriptionCancel.css
│           │   │   │       ├── SubscriptionPage.css
│           │   │   │       └── SubscriptionSuccess.css
│           │   │   └── tests
│           │   │       ├── aplus
│           │   │       │   ├── APlusTestList.js
│           │   │       │   └── APlusTestPage.js
│           │   │       ├── aplus2
│           │   │       │   ├── APlusCore2TestPage.js
│           │   │       │   └── AplusCore2TestList.js
│           │   │       ├── awscloud
│           │   │       │   ├── AWSCloudTestList.js
│           │   │       │   └── AWSCloudTestPage.js
│           │   │       ├── casp
│           │   │       │   ├── CaspPlusTestList.js
│           │   │       │   └── CaspPlusTestPage.js
│           │   │       ├── cissp
│           │   │       │   ├── CisspTestList.js
│           │   │       │   └── CisspTestPage.js
│           │   │       ├── cloudplus
│           │   │       │   ├── CloudPlusTestList.js
│           │   │       │   └── CloudPlusTestPage.js
│           │   │       ├── cysa
│           │   │       │   ├── CySAPlusTestList.js
│           │   │       │   └── CySAPlusTestPage.js
│           │   │       ├── dataplus
│           │   │       │   ├── DataPlusTestList.js
│           │   │       │   └── DataPlusTestPage.js
│           │   │       ├── linuxplus
│           │   │       │   ├── LinuxPlusTestList.js
│           │   │       │   └── LinuxPlusTestPage.js
│           │   │       ├── nplus
│           │   │       │   ├── NPlusTestList.js
│           │   │       │   └── NetworkPlusTestPage.js
│           │   │       ├── penplus
│           │   │       │   ├── PenPlusTestList.js
│           │   │       │   └── PenPlusTestPage.js
│           │   │       ├── secplus
│           │   │       │   ├── SecurityPlusTestList.js
│           │   │       │   └── SecurityPlusTestPage.js
│           │   │       └── serverplus
│           │   │           ├── ServerPlusTestList.js
│           │   │           └── ServerPlusTestPage.js
│           │   └── test.css
│           ├── global.css
│           ├── index.js
│           └── reportWebVitals.js
├── nginx
│   ├── logs
│   │   ├── access.log
│   │   └── error.log
│   ├── nginx.conf
│   └── sites-enabled
│       └── reverse_proxy.conf
└── redis
    └── redis.conf
```
77 directories, 374 files

-----

63 directories, 320 files
```
