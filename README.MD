 [![Carter Perez](https://img.shields.io/badge/Carter%20Perez-red)](https://www.linkedin.com/in/carterperez-dev/) [![CertGames Core](https://img.shields.io/badge/CertGames%20Core-grey)](https://github.com/CarterPerez-dev/CertGames-Core) [![CertGames iOS](https://img.shields.io/badge/CertGames%20iOS-red)](https://github.com/CarterPerez-dev/CertGames-IOS) [![CertGames Android](https://img.shields.io/badge/CertGames%20Android-grey)](https://github.com/CarterPerez-dev/CertGames-Android) [![MongoDB Atlas](https://img.shields.io/badge/MongoDB%20Atlas-red)](https://www.mongodb.com/) [![React](https://img.shields.io/badge/React%20-grey)](https://react.dev/) [![Flask API](https://img.shields.io/badge/Flask%20API-red)](https://flask.palletsprojects.com/en/stable/) [![Redis](https://img.shields.io/badge/Redis%20-grey)](https://redis.io/lp/try1/?utm_campaign=gg_s_core_amert1_en_brand_acq_21168833255&utm_source=google&utm_medium=cpc&utm_content=redis_exact&utm_term=&gad_source=1&gbraid=0AAAAADg3Ge_5koxi193wqVhI7kcL_lQuN&gclid=Cj0KCQjwtpLABhC7ARIsALBOCVp3zRdpkqM2OorthgU16DwmVH1_SI0q9GmiUPxrIdNgpEyAexHTweoaAsq0EALw_wcB) [![Docker](https://img.shields.io/badge/Docker-red)](https://www.docker.com/) [![Cybersecurity](https://img.shields.io/badge/Cybersecurity-grey)](https://apps.apple.com/us/app/comptia-cert-games-practice/id6743811522) [![Nginx](https://img.shields.io/badge/Nginx%20-red)](https://nginx.org/) [![Apache](https://img.shields.io/badge/Apache-grey)](https://www.apache.org/) [![Angela Moss](https://img.shields.io/badge/Angela%20Moss-red)](https://youtu.be/hoHr4W_0Viw?si=xmJH3cfUDTYk9Nyy)
![Typing SVG](https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=30&duration=1500&pause=400&color=A50021&center=true&vCenter=true&width=1100&lines=CertGames;Advanced+Cybersecurity+Application)
![CertGames Logo](https://raw.githubusercontent.com/CarterPerez-dev/CertGames-Core/main/frontend/my-react-app/public/ios.png)

[![React](https://img.shields.io/badge/React-18.3.1-61dafb.svg)](https://reactjs.org/)
[![React Native](https://img.shields.io/badge/React_Native-0.76.7-0088CC.svg)](https://reactnative.dev/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-black.svg)](https://flask.palletsprojects.com/)
[![OpenAI](https://img.shields.io/badge/OpenAI_Integration-GPT4-412991.svg)](https://openai.com/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED.svg)](https://www.docker.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-4DB33D.svg)](https://www.mongodb.com/cloud/atlas)
[![Redis](https://img.shields.io/badge/Redis-6.2-DC382D.svg)](https://redis.io/)

## Overview

CertGames is a comprehensive cybersecurity training platform designed to help IT professionals prepare for certification exams through gamified learning experiences. The platform integrates advanced AI-driven tools, practice tests, and interactive simulations to create an engaging learning environment.

**Live Platform:** [CertGames.com](https://certgames.com)  
**iOS App:** [App Store Link](https://apps.apple.com/us/app/comptia-cert-games-practice/id6743811522)  
**LinkedIn:** [CertGames](https://www.linkedin.com/company/certgames/) | [Developer Profile](https://www.linkedin.com/in/carterperez-dev/)  
**Portfolio:** [CarterPerez-dev.com](https://carterperez-dev.com/)

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

The web frontend is built as a single-page application using React with Redux for state management. Key features include:

- **Redux Toolkit** implementation for efficient state management
- **Themeable UI** with dynamic color schemes for accessibility
- **Socket.IO** integration for real-time features
- **Responsive design** with mobile-first approach
- **SEO optimization** with React Helmet and structured data
- **Protected routes** with subscription-based access control for Defense In Depth

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
- **Git** For Version Control and CI/CD

## Tech Stack

### Frontend (Web)

```json
{
  "Core": {
    "Framework": "React",
    "State Management": "Redux Toolkit",
    "Routing": "React Router"
  },
  "UI/UX": {
    "Styling": "CSS Modules + CSS Variables for theming",
    "Icons": "React Icons",
    "Charts": "Recharts",
    "Animations": "CSS Transitions + React Spring",
    "Data Visualization": "D3.js (integrated via Recharts)"
  },
  "Performance": {
    "Code Splitting": "Dynamic imports with React.lazy()",
    "Bundle Optimization": "Craco + Webpack 5 custom config",
    "Caching Strategy": "Redux persistor + Local Storage",
    "Lazy Loading": "React Suspense + window.IntersectionObserver"
  },
  "Build Tools": {
    "Package Manager": "npm",
    "Bundler": "Webpack 5 (via Craco)",
    "Transpiler": "Babel with custom plugins",
    "Minification": "Terser + CSS Minimizer"
  },
  "DevOps": {
    "Linting": "ESLint with custom config",
    "Testing": "Jest + React Testing Library",
    "CI/CD": "GitHub Actions",
    "Monitoring": "Custom performance metrics + Web Vitals tracking"
  }
}
```
---
### Mobile (iOS)

```json
{
  "Core": {
    "Framework": "React Native",
    "Expo": "Expo SDK 52",
    "State Management": "Redux Toolkit",
    "Navigation": "React Navigation"
  },
  "Native Features": {
    "Authentication": "Expo Apple Authentication, Google Sign-In",
    "Storage": "Expo SecureStore + AsyncStorage",
    "Network": "Axios with custom retry logic",
    "In-App Purchases": "React Native IAP"
  },
  "UI/UX": {
    "Components": "Custom components with native styling",
    "Animations": "React Native Reanimated",
    "Haptics": "Expo Haptics",
    "Gestures": "React Native Gesture Handler"
  },
  "Device Support": {
    "iOS Version": "iOS 14+",
    "Form Factors": "iPhone, iPad (Universal App)",
    "Orientation": "Portrait only (optimized experience)",
    "Deep Linking": "Universal Links via Expo"
  },
  "Build System": {
    "Development": "Expo Go + Dev Client",
    "Production": "EAS Build with custom profile",
    "Distribution": "App Store Connect + EAS Update"
  }
}
```
---
### Backend (API)

```json
{
  "Core": {
    "Framework": "Flask",
    "WSGI Server": "Gunicorn with Gevent workers",
    "Authentication": "JWT + OAuth 2.0",
    "Session Management": "Flask-Session with Redis backend"
  },
  "Data Layer": {
    "Database": "MongoDB Atlas (Document-oriented NoSQL)",
    "ORM": "PyMongo with custom abstraction layer",
    "Caching": "Redis with tiered expiration strategy",
    "Data Validation": "Custom schema validation"
  },
  "Asynchronous Processing": {
    "Task Queue": "Celery",
    "Message Broker": "Redis",
    "Scheduling": "Celery Beat for periodic tasks",
    "Concurrency": "Gevent workers (8) with thread pool (5)"
  },
  "AI Integration": {
    "LLM Provider": "OpenAI GPT-4o API",
    "Streaming Support": "Flask response streaming + OpenAI streaming",
    "Prompt Engineering": "Custom prompt templates with parameter injection",
    "Rate Limiting": "Tiered per-feature limits with progressive penalties"
  },
  "APIs and Protocols": {
    "REST API": "JSON with Flask Blueprints",
    "WebSockets": "Socket.IO for real-time features",
    "Webhooks": "For Stripe integration and Apple IAP verification",
    "Payment Processing": "Stripe API + Apple In-App Purchase Server Notifications"
  },
  "Security": {
    "Authentication": "OAuth 2.0 + JWT + Secure HTTP-only cookies",
    "Rate Limiting": "IP-based, progressive with Redis tracking",
    "Input Validation": "Custom sanitization and validation",
    "Headers": "Strict security headers via NGINX"
  }
}
```
---
### Infrastructure

```json
{
  "Containerization": {
    "Platform": "Docker with docker-compose",
    "Container Registry": "Private Docker Hub repository",
    "Resource Limits": "Defined per-service CPU and memory constraints",
    "Networking": "Custom bridge network with internal DNS"
  },
  "Web Servers": {
    "Load Balancer": "NGINX with optimized configurations",
    "Static Content": "Apache HTTPD 2.4 with mpm_event",
    "SSL Termination": "Cloudflare at edge + internal self-signed certs"
  },
  "Message Queuing": {
    "Primary Queue": "Redis for Celery tasks",
    "Durability": "Redis AOF persistence with 1-second fsync",
    "Monitoring": "Redis INFO stats collection via Celery Beat tasks"
  },
  "Caching": {
    "Session Cache": "Redis with 24-hour expiry",
    "Content Cache": "Cloudflare edge caching + Redis L2 cache",
    "Query Cache": "MongoDB query results in Redis (30-minute TTL)"
  },
  "Database": {
    "Primary DB": "MongoDB Atlas M20 cluster (3 nodes)",
    "Replication": "Atlas automatic replication with 3 nodes",
    "Backup": "Daily automated backups with 30-day retention",
    "Scaling": "Auto-scaling enabled with custom triggers"
  },
  "CDN & DNS": {
    "Provider": "Cloudflare Enterprise",
    "Configuration": "Custom page rules, cache TTLs by content type",
    "Security": "WAF with custom ruleset + Bot Management",
    "DNS": "Cloudflare DNS with DNSSEC enabled"
  },
  "Monitoring": {
    "Application Metrics": "Custom in-app telemetry with MongoDB storage",
    "Server Monitoring": "Resource utilization tracking via Celery Beat",
    "Scheduled Health Checks": "10-minute interval API endpoint verification",
    "Logs": "Structured JSON logging with automatic rotation"
  },
  "Disaster Recovery": {
    "Database": "Point-in-time recovery via MongoDB Atlas",
    "Configuration": "Docker Compose templates in version control",
    "Deployment": "Automated build and deployment pipeline",
    "Backup Testing": "Monthly restoration tests for validation"
  }
}
```
---
## Reactive Multi-Platform Design

CertGames employs a reactive architecture pattern to ensure consistency across web and mobile platforms while optimizing for each platform's unique capabilities.

### Shared Logic Pattern

![Shared Logic Pattern Diagram](https://raw.githubusercontent.com/CarterPerez-dev/CertGames-Core/main/Stack/Architecture/Shared-Logic-Pattern.png)

### Key Implementation Points:

1. **Isomorphic Redux Store**: The Redux store structure is identical between web and mobile, with platform-specific middleware handling persistence differences.

2. **Shared API Client**: A custom API client abstraction layer provides consistent data fetching with platform-specific adapters (Axios on web, modified Axios on mobile with offline support).

3. **Cross-Platform Authentication**: OAuth 2.0 flows are standardized but implemented with platform-appropriate SDKs (web browser redirects vs. native iOS authentication).

4. **Custom Hooks Library**: Common business logic is encapsulated in custom React hooks that are reused across platforms with platform-specific implementations where needed.

5. **Responsive Design System**: A unified design system with theme variables that are implemented via CSS variables on web and StyleSheet on mobile.

## API Architecture

![API Architecture Diagram](https://raw.githubusercontent.com/CarterPerez-dev/CertGames-Core/main/Stack/Architecture/api-architecture.png)

The backend API follows a modular architecture using Flask Blueprints. Each functional domain is implemented as a separate blueprint with its own routes, business logic, and middleware.

### API Documentation

The API follows RESTful principles with consistent patterns:

- Base URL structure: `https://certgames.com/api/`
- Authentication: JWT tokens in Authorization header (`Bearer <token>`)
- Response format: JSON with consistent structure
- Error handling: Standardized error codes and messages
- Rate limiting: Progressive with header information

Example endpoint structure:

```json
{
  "Authentication": {
    "/api/test/login": {
      "method": "POST",
      "description": "User login with credentials",
      "parameters": {
        "usernameOrEmail": "string",
        "password": "string"
      },
      "response": {
        "user_id": "string",
        "username": "string",
        "email": "string",
        "coins": "integer",
        "xp": "integer",
        "level": "integer",
        "achievements": "array",
        "subscriptionActive": "boolean"
      }
    },
    "/api/oauth/verify-google-token": {
      "method": "POST",
      "description": "Verify Google OAuth token from mobile",
      "parameters": {
        "token": "string",
        "userData": "object",
        "platform": "string"
      },
      "response": {
        "success": "boolean",
        "userId": "string"
      }
    }
  },
  "User Management": {
    "/api/test/user/{user_id}": {
      "method": "GET",
      "description": "Get user details",
      "parameters": {
        "user_id": "path parameter"
      },
      "response": "User object with full details"
    },
    "/api/test/user/{user_id}/daily-bonus": {
      "method": "POST",
      "description": "Claim daily login bonus",
      "parameters": {
        "user_id": "path parameter"
      },
      "response": {
        "success": "boolean",
        "newCoins": "integer",
        "newXP": "integer",
        "newlyUnlocked": "array of achievement IDs"
      }
    }
  },
  "Test System": {
    "/api/test/tests/{category}/{test_id}": {
      "method": "GET",
      "description": "Get test by category and ID",
      "parameters": {
        "category": "path parameter",
        "test_id": "path parameter"
      },
      "response": "Complete test object with questions"
    },
    "/api/test/attempts/{user_id}/{test_id}/finish": {
      "method": "POST",
      "description": "Complete a test attempt",
      "parameters": {
        "user_id": "path parameter",
        "test_id": "path parameter",
        "score": "integer",
        "totalQuestions": "integer"
      },
      "response": {
        "message": "string",
        "newlyUnlocked": "array of achievement IDs",
        "newXP": "integer",
        "newCoins": "integer"
      }
    }
  },
  "AI Generation": {
    "/api/analogy/stream_analogy": {
      "method": "POST",
      "description": "Generate and stream analogy text",
      "parameters": {
        "analogy_type": "string (single|comparison|triple)",
        "concept1": "string",
        "concept2": "string (optional)",
        "concept3": "string (optional)",
        "category": "string"
      },
      "response": "Streaming text response"
    },
    "/api/scenario/stream_scenario": {
      "method": "POST",
      "description": "Generate cybersecurity scenario",
      "parameters": {
        "industry": "string",
        "attack_type": "string",
        "skill_level": "string",
        "threat_intensity": "string"
      },
      "response": "Streaming text response"
    }
  }
}
```
---
## AI Integration

CertGames leverages AI throughout the platform to enhance the learning experience. This is primarily implemented through OpenAI's GPT-4o API with custom prompt engineering.

### AI-Powered Features

1. **Analogy Generation**: Creates analogies for complex cybersecurity concepts to aid in understanding
2. **Scenario Creation**: Generates realistic cybersecurity scenarios for hands-on training
3. **GRC Question Generation**: Produces governance, risk, and compliance questions with adaptive difficulty
4. **Exploit Simulation**: Demonstrates conceptual exploit generation for educational purposes

### AI Integration Architecture

![AI Integration Diagram](https://raw.githubusercontent.com/CarterPerez-dev/CertGames-Core/main/Stack/Architecture/AI-Integration.png)

### Prompt Engineering Example

```python
def generate_grc_question(category, difficulty):
    """
    Generates a GRC-related multiple-choice question in JSON format.
    The model returns a JSON object with keys:
      question (string)
      options (array of 4 strings)
      correct_answer_index (int)
      explanations (dict of strings for "0","1","2","3")
      exam_tip (string)
    """
    prompt = f""" 
You are an expert in concepts found in certifications like CISSP, CompTIA Advanced Security Practitioner (CASP+), CISM, CRISC, and others. Your role is to generate 
challenging and diverse test questions using advanced mult-layered reasoning, related to governance, risk management, risk thresholds, types of risk, Audit, Management, Policy, Cyber Security Ethics, Threat Assessment, 
Leadership, Business Continuity, compliance, regulations, incident resposne, Incident Response and more. focusing on preparing for exams like CISSP/ISC2 and CompTIA certifications. Ensure the questions cover a wide range of scenarios,
principles, and concepts, with multiple-choice answers that are nuanced and complex and specific, avoiding repetitive patterns or overly simplified examples.

CONTEXT: The user has selected:
- Category: {category} (e.g., 'Regulation', 'Risk Management', 'Compliance', 'Audit', 'Governance', 'Management', 'Policy', 'Ethics', 'Threat Assessment', 'Leadership', 'Business Continuity', 'Incident Response', 'Random')
- Difficulty: {difficulty} (e.g., 'Easy', 'Medium', 'Hard')

REQUIREMENTS
1. Four options (0, 1, 2, 3) total, one correct answer. The incorrect options should be very plausible but not correct, requiring the test-taker to carefully differentiate.

2. Explanations:
   - For the correct answer: Provide multiple sentences detailing exactly why it's correct, clearly tying it back to the question's scenario or concept. Show how it fulfills the requirements asked in the question as well as why the other answer choices are incorrect/not the correct answer..
   - For each incorrect answer: Provide multiple sentences detailing why it is NOT correct aswell as why the other incorrect answer choices are incorrect, and why then tell the user what the correct answer is and why it is correct using advanced multi-layered reasoning. 
     Do not just say it's incorrect; fully explain why it falls short. 
     Highlight conceptual differences, limitations, or focus areas that differ from the question's criteria.
   - Regardless of user choice, the generated output must contain full explanations for all answer choices provided. The explanations are produced in advance as part of the JSON object. Each explanation should be at least 3 sentences, rich in detail and conceptual clarity using advanced multi-layered reasoning.

3. Include an "exam_tip" field that provides a short, memorable takeaway or mnemonic to help differentiate the correct concept from the others. The exam tip should help the user recall why the correct answer stands out using advanced multi-layered reasoning.

4. Return ONLY a JSON object with the fields:
   "question", "options", "correct_answer_index", "explanations", and "exam_tip"
   No extra text, no Markdown, no commentary outside the JSON.

5. For each explanation (correct and incorrect):
   - At minimum of 3 sentences for the correct answer.
   - if the user gets the answer correct provide minium 3 senetence answer as to why it is correct, but also why the other answer choices listed are not the correct answer using advanced multi-layered reasoning.
   - Substantial detail.
   - Clearly articulate conceptual reasons, not just factual statements using advanced multi-layered reasoning.

EXAMPLE FORMAT (this is not real content, just structure, make sure to use all topics not just the topic provided in this example):
{{
  "question": "The question",
  "options": ["Option 0","Option 1","Option 2","Option 3"],
  "correct_answer_index": 2,
  "explanations": {{
    "0": "Explain thoroughly why option 0 fails. Mention its scope, focus areas, and why that doesn't meet the question criteria and then explain what the correct answer is and why it is correct aswell as why the other answer choices are incorrect using advanced multi-layered reasoning.",
    "1": "Explain thoroughly why option 1 fails. Mention its scope, focus areas, and why that doesn't meet the question criteria and then explain what the correct answer is and why it is correct aswell as why the other answer choices are incorrect using advanced multi-layered reasoning.",
    "2": "Explain thoroughly why option 2 is correct, linking its characteristics to the question scenario and why the other answer choices are incorrect using advanced multi-layered reasoning",
    "3": "Explain thoroughly why option 3 fails. Mention its scope, focus areas, and why that doesn't meet the question criteria and then explain what the correct answer is and why it is correct aswell as why the other answer choices are incorrect using advanced multi-layered reasoning."
  }},
  "exam_tip": "A short, memorable hint or mnemonic that differentiates the correct approach from others using advanced multi-layered reasoning."
}}

Now generate the JSON object following these instructions.
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",  
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1200,
            temperature=0.7,
        )

        content = response.choices[0].message.content.strip()
      
        content = re.sub(r'^```.*\n', '', content)
        content = re.sub(r'\n```$', '', content)

        try:
            generated_question = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error("JSON parsing error in generate_grc_question: %s", e)
            logger.error("Model returned: %s", content)
            raise ValueError("Model did not return valid JSON.") from e

        logger.info("Generated GRC question successfully.")
        return generated_question

    except Exception as e:
        logger.error(f"Error generating GRC question: {str(e)}")
        raise

def generate_grc_questions_stream(category, difficulty):
    """
    Streams the GRC question JSON response chunk by chunk.
    Instead of returning a complete JSON object, it returns a generator
    that yields chunks of the response as they come in.
    
    Args:
        category: Question category
        difficulty: Question difficulty level
        
    Returns:
        Generator yielding chunks of JSON string
    """
    prompt = f"""
You are an expert in concepts found in certifications like CISSP, CompTIA Advanced Security Practitioner (CASP+), CISM, CRISC, and others. 
Your role is to generate very diverse with alot of variation in concepts test question with highly plausible distractors related to governance, risk management, risk thresholds, types of risk, 
Audit, Management, Policy, Cyber Security Ethics, Threat Assessment, Leadership, Business Continuity, compliance, regulations, 
incident response, and more, focusing on preparing for exams like CISSP and CompTIA certifications.

CONTEXT: The user has selected:
- Category: {category}
- Difficulty: {difficulty}

REQUIREMENTS:
1. Generate ONE question in valid JSON format with:
   - "question": string,
   - "options": array of exactly 4 strings with highly plasuible distractors (indexes 0,1,2,3),
   - "correct_answer_index": integer (0,1,2,3),
   - "explanations": object with keys "0","1","2","3" (multi-sentence detail),
   - "exam_tip": short mnemonic/hint.

2. The correct answer's explanation has at least 3 sentences describing precisely why it is correct, 
   and also clarifies why the others are incorrect.

3. Each incorrect answer's explanation has multiple sentences explaining why it is wrong, 
   plus clarifies what the correct choice is and why the other answer choices are also incorrect or less suitable.

4. Provide an "exam_tip" as a short, memorable mnemonic or hint to help the test-taker recall the correct concept.

5. Return ONLY the JSON object. No extra text, disclaimers, or preludes.

6. Each explanation must be at least 3 sentences, offering substantial detail and conceptual clarity.

Now generate the JSON object following these instructions. 
Remember: Provide ONLY valid JSON, nothing else.
"""

    try:
        # Make the streaming request
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1200,
            temperature=0.7,
            stream=True
        )

        def generator():
            try:
                for chunk in response:
                    delta = chunk.choices[0].delta
                    if delta:
                        content = getattr(delta, "content", None)
                        if content:
                            yield content
            except Exception as e:
                logger.error(f"Error streaming GRC question: {e}")
                yield f"{{\"error\": \"Error streaming content: {str(e)}\"}}"

        return generator()

    except Exception as e:
        logger.error(f"Error generating GRC question (stream): {e}")
        def err_gen():
            yield f"{{\"error\": \"Error generating question: {str(e)}\"}}"
        return err_gen()
```
---
## Database Schema

```json
{
  "mainusers": {
    "indexes": ["username", "email", "subscriptionActive"],
    "fields": {
      "_id": "ObjectId",
      "username": "string",
      "email": "string",
      "password": "string (hashed)",
      "oauth_provider": "string (null|google|apple)",
      "coins": "integer",
      "xp": "integer",
      "level": "integer",
      "achievements": ["string (achievement IDs)"],
      "xpBoost": "float",
      "currentAvatar": "ObjectId (reference to shop)",
      "nameColor": "string (null|color code)",
      "purchasedItems": ["ObjectId (references to shop)"],
      "subscriptionActive": "boolean",
      "subscriptionStatus": "string (null|active|canceling|expired)",
      "subscriptionPlatform": "string (null|stripe|apple)",
      "lastDailyClaim": "Date",
      "practiceQuestionsRemaining": "integer",
      "subscriptionType": "string (free|premium)",
      "achievement_counters": {
        "total_tests_completed": "integer",
        "perfect_tests_count": "integer",
        "perfect_tests_by_category": {
          "[category]": "integer"
        },
        "highest_score_ever": "float",
        "lowest_score_ever": "float",
        "total_questions_answered": "integer"
      }
    }
  },
  "tests": {
    "indexes": ["testId", "category"],
    "fields": {
      "_id": "ObjectId",
      "testId": "integer",
      "testName": "string",
      "category": "string",
      "difficulty": "string",
      "description": "string",
      "questions": [{
        "id": "string",
        "question": "string",
        "options": ["string"],
        "correctAnswerIndex": "integer",
        "explanation": "string",
        "examTip": "string (optional)"
      }]
    }
  },
  "testAttempts": {
    "indexes": ["userId", "testId", "finished"],
    "fields": {
      "_id": "ObjectId",
      "userId": "ObjectId",
      "testId": "integer or string",
      "category": "string",
      "score": "integer",
      "totalQuestions": "integer",
      "selectedLength": "integer",
      "currentQuestionIndex": "integer",
      "shuffleOrder": ["integer"],
      "answerOrder": ["[integer]"],
      "finished": "boolean",
      "finishedAt": "Date (optional)",
      "examMode": "boolean",
      "examTimerSeconds": "integer",
      "answers": [{
        "questionId": "string",
        "userAnswerIndex": "integer or null",
        "correctAnswerIndex": "integer"
      }]
    }
  },
  "shop": {
    "indexes": ["type", "cost"],
    "fields": {
      "_id": "ObjectId",
      "title": "string",
      "description": "string",
      "imageUrl": "string",
      "type": "string (avatar|nameColor|xpBoost)",
      "cost": "integer or null",
      "effectValue": "any (depends on type)"
    }
  },
  "achievements": {
    "indexes": ["achievementId"],
    "fields": {
      "_id": "ObjectId",
      "achievementId": "string",
      "title": "string",
      "description": "string",
      "icon": "string",
      "criteria": {
        "testCount": "integer (optional)",
        "minScore": "float (optional)",
        "perfectTests": "integer (optional)",
        "coins": "integer (optional)",
        "level": "integer (optional)",
        "totalQuestions": "integer (optional)",
        "perfectTestsInCategory": "integer (optional)",
        "minScoreBefore": "float (optional)",
        "minScoreAfter": "float (optional)",
        "testsCompletedInCategory": "integer (optional)",
        "allTestsCompleted": "boolean (optional)"
      }
    }
  },
  "supportThreads": {
    "indexes": ["userId", "createdAt", "status"],
    "fields": {
      "_id": "ObjectId",
      "userId": "ObjectId",
      "title": "string",
      "status": "string (open|closed)",
      "createdAt": "Date",
      "updatedAt": "Date",
      "messages": [{
        "sender": "string (user|admin)",
        "content": "string",
        "timestamp": "Date"
      }]
    }
  },
  "subscriptionEvents": {
    "indexes": ["userId", "event", "timestamp"],
    "fields": {
      "_id": "ObjectId",
      "userId": "ObjectId",
      "event": "string (subscription_created|subscription_renewed|subscription_canceled|subscription_expired)",
      "platform": "string (stripe|apple)",
      "timestamp": "Date",
      "data": "object (platform-specific data)"
    }
  },
  "performanceMetrics": {
    "indexes": ["timestamp"],
    "fields": {
      "_id": "ObjectId",
      "avg_request_time": "float (seconds)",
      "avg_db_query_time": "float (seconds)",
      "data_transfer_rate": "float (MB/s)",
      "throughput": "float (requests/minute)",
      "error_rate": "float (0.0-1.0)",
      "timestamp": "Date"
    }
  },
  "globalRateLimits": {
    "indexes": ["clientId", "endpoint", "updatedAt"],
    "fields": {
      "_id": "ObjectId",
      "clientId": "string (hashed identifier)",
      "endpoint": "string (endpoint type)",
      "calls": ["Date (timestamps)"],
      "violations": "integer",
      "blockUntil": "Date (optional)",
      "updatedAt": "Date"
    }
  }
}
```
---
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

![Authentication Flow Diagram](https://raw.githubusercontent.com/CarterPerez-dev/CertGames-Core/main/Stack/Architecture/Auth-flow.png)

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

![Deployment Architecture Diagram](https://raw.githubusercontent.com/CarterPerez-dev/CertGames-Core/main/Stack/Architecture/Deployment.png)

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

```yml
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
      - ./nginx/logs:/var/log/nginx
    env_file:
      - .env
    networks:
      - xploitcraft_network
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: '9G'
        reservations:
          cpus: '2'
          memory: '7G'
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    depends_on:
      - redis

  frontend:
    container_name: frontend_service
    build:
      context: ./frontend/my-react-app
      dockerfile: Dockerfile.frontend
    volumes:
      - ./frontend/my-react-app:/app
      - /app/node_modules    
    env_file:
      - .env
    ports:
      - "3000:3000"
    networks:
      - xploitcraft_network
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: '4G'
        reservations:
          cpus: '1'
          memory: '2G'
    restart: unless-stopped

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
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: '4G'
        reservations:
          cpus: '0.5'
          memory: '2G'
    restart: always
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

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
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: '4G'
        reservations:
          cpus: '1'
          memory: '2G'
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

  nginx:
    container_name: nginx_proxy
    image: nginx:latest
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/sites-enabled:/etc/nginx/sites-enabled
      - ./nginx/logs:/var/log/nginx/
    networks:
      - xploitcraft_network
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: '2G'
        reservations:
          cpus: '0.5'
          memory: '1G'
    depends_on:
      - apache
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  celery:
    container_name: celery_worker
    build:
      context: ./backend
      dockerfile: Dockerfile.backend
    command: celery -A helpers.async_tasks worker --loglevel=info --concurrency=8
    env_file:
      - .env
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: '6G'
        reservations:
          cpus: '2'
          memory: '3G'
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
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: '2G'
        reservations:
          cpus: '0.5'
          memory: '1G'
    depends_on:
      - backend
      - redis
    networks:
      - xploitcraft_network
    volumes:
      - ./backend:/app  
      - ./nginx/logs:/var/log/nginx   
    restart: always

networks:
  xploitcraft_network:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 172.28.0.0/16
```
---
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

![Unit Testing Diagram](https://raw.githubusercontent.com/CarterPerez-dev/CertGames-Core/main/Stack/Architecture/Unit-Testing.png)

### Testing Tools and Frameworks

- **Unit Testing**: Jest, React Testing Library, PyTest
- **Integration Testing**: Supertest, Redux Mock Store, MongoDB Memory Server
- **End-to-End Testing**: Cypress, Detox (for React Native)
- **Performance Testing**: Locust, Lighthouse, React Profiler
- **Security Testing**: OWASP ZAP, npm audit, Snyk, Bandit

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

2. **Game-like Learning Tools**:
   - PBQ (Performance-Based Question) cybersecurity training games
   - Advanced scenario generation with adaptive difficulty
   - Personalized learning paths

3. **Expanded Content**:
   - Resume builder
   - Interactive penetration testing simulation environment
   - Hands-on "Hack the Box"-style challenges using dummy websites I have created
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
   - Community Forum

## Current Platform Statistics

- **Total Users**: 508 (108 paid subscribers, 400 free tier)
- **Content Library**: 130+ certification practice tests across 12 certification paths with 13,000 practice questions across all certifications
- **Response Time**: Average API response time under 30ms
- **Uptime**: 99.97% uptime since launch
- **Mobile Engagement**: 65% of premium users access via both web and iOS app

## Contact & Support

- **General Inquiries**: inquiry@certgames.com
- **Support**: support@certgames.com
- **Developer Contact**: dev@certgames.com
- **Phone**: 443-510-0866
- **LinkedIn**: [CertGames Company Page](https://www.linkedin.com/company/certgames/)

---

# License

*This codebase is Open-Source* 
-
*© 2025 CertGames | © 2025 AngelaMoss*
-
*Devloped and Designed  ~/Carter-perez-dev*
--
*This README was created for the CertGames repository family
-
*Last updated - @4/20/25 16:52:00*
------
*[Privacy Policy](https://certgames.com/privacy)*  😎  *[Terms of Service](https://certgames.com/terms)*
----
*"My confidence is powerful. I recognize myself as exceptional. I recognize myself as exceptional. I recognize myself as exceptional."*
     --One of the good ones...

  
