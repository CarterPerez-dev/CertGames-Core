ok so ingest this dat first and foremost

## SEO Implementation Guide for CertGames

### 1. Meta Tags Implementation

To add proper meta tags for each page, create a reusable Helmet component (using React Helmet) to manage document head tags:

First, install React Helmet if you haven't already:
```
npm install react-helmet
```

Then create a `SEOHelmet.js` component:

```jsx
// src/components/SEOHelmet.js
import React from 'react';
import { Helmet } from 'react-helmet';

const SEOHelmet = ({ 
  title, 
  description, 
  canonicalUrl,
  ogImage = 'https://certgames.com/images/og-default.jpg', // Default image
  ogType = 'website'
}) => {
  // Base URL - update with your actual domain
  const baseUrl = 'https://certgames.com';
  
  // Full canonical URL
  const fullCanonicalUrl = canonicalUrl ? `${baseUrl}${canonicalUrl}` : baseUrl;
  
  return (
    <Helmet>
      {/* Basic Metadata */}
      <title>{title}</title>
      <meta name="description" content={description} />
      <link rel="canonical" href={fullCanonicalUrl} />
      
      {/* Open Graph / Facebook */}
      <meta property="og:type" content={ogType} />
      <meta property="og:url" content={fullCanonicalUrl} />
      <meta property="og:title" content={title} />
      <meta property="og:description" content={description} />
      <meta property="og:image" content={ogImage} />
      
      {/* Twitter */}
      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:url" content={fullCanonicalUrl} />
      <meta name="twitter:title" content={title} />
      <meta name="twitter:description" content={description} />
      <meta name="twitter:image" content={ogImage} />
    </Helmet>
  );
};

export default SEOHelmet;
```

Now, add the SEO component to each page. Here's an example for adding it to the InfoPage (Home):

```jsx
// In InfoPage.js, add this import
import SEOHelmet from '../../SEOHelmet';

// Then at the top of your InfoPage component, add:
<SEOHelmet 
  title="CertGames - Gamified Cybersecurity Training & Certification Prep"
  description="Level up your cybersecurity skills with CertGames. Practice for CompTIA, ISC2, and AWS certifications with 13,000+ questions in a fun, gamified learning environment."
  canonicalUrl="/"
/>
```

Here are the recommended meta tags for your other pages:

#### Demos Page
```jsx
<SEOHelmet 
  title="Interactive Feature Demos | CertGames"
  description="See CertGames' interactive learning tools in action. Watch demos of our gamified cybersecurity training features, exam simulators, and specialized learning tools."
  canonicalUrl="/demos"
/>
```

#### All Exams Page
```jsx
<SEOHelmet 
  title="Certification Exam Practice Tests | CertGames"
  description="Prepare for 13 top cybersecurity certifications including CompTIA, ISC2, and AWS with 13,000+ practice questions. Performance-based questions, exam simulations, and detailed explanations."
  canonicalUrl="/exams"
/>
```

#### Public Leaderboard Page
```jsx
<SEOHelmet 
  title="Cybersecurity Training Leaderboard | CertGames"
  description="See who's leading the cybersecurity learning race at CertGames. Our gamified learning platform rewards knowledge with XP, levels, and achievements."
  canonicalUrl="/public-leaderboard"
/>
```

#### Contact Page
```jsx
<SEOHelmet 
  title="Contact CertGames | Support & Inquiries"
  description="Get in touch with the CertGames team. Questions about our cybersecurity training platform? Need technical support? We're here to help."
  canonicalUrl="/contact"
/>
```

### 2. Structured Data for Rich Search Results

Add structured data to help search engines better understand your content and potentially display rich results. Here's how to implement it for your homepage:

Create a `StructuredData.js` component:

```jsx
// src/components/StructuredData.js
import React from 'react';
import { Helmet } from 'react-helmet';

const StructuredData = ({ data }) => {
  return (
    <Helmet>
      <script type="application/ld+json">
        {JSON.stringify(data)}
      </script>
    </Helmet>
  );
};

export default StructuredData;
```

Now implement different structured data types for different pages:

#### Homepage (InfoPage.js)
```jsx
// Import the component
import StructuredData from '../../StructuredData';

// Include this in your InfoPage component
const websiteSchema = {
  "@context": "https://schema.org",
  "@type": "WebSite",
  "name": "CertGames",
  "url": "https://certgames.com",
  "potentialAction": {
    "@type": "SearchAction",
    "target": "https://certgames.com/search?q={search_term_string}",
    "query-input": "required name=search_term_string"
  }
};

const courseSchema = {
  "@context": "https://schema.org",
  "@type": "Course",
  "name": "Cybersecurity Certification Training",
  "description": "Gamified cybersecurity training for CompTIA, ISC2, and AWS certifications with 13,000+ practice questions.",
  "provider": {
    "@type": "Organization",
    "name": "CertGames",
    "sameAs": "https://certgames.com"
  }
};

// Include these in your return statement
<StructuredData data={websiteSchema} />
<StructuredData data={courseSchema} />
```

#### Exams Page (ExamsPage.js)
```jsx
const examProductSchema = {
  "@context": "https://schema.org",
  "@type": "Product",
  "name": "CertGames Certification Exam Prep",
  "description": "Practice tests for 13 cybersecurity certifications with over 13,000 questions",
  "offers": {
    "@type": "Offer",
    "price": "14.99",
    "priceCurrency": "USD",
    "availability": "https://schema.org/InStock"
  },
  "review": {
    "@type": "Review",
    "reviewRating": {
      "@type": "Rating",
      "ratingValue": "4.8",
      "bestRating": "5"
    },
    "author": {
      "@type": "Person",
      "name": "Security Professional"
    }
  }
};

<StructuredData data={examProductSchema} />
```

#### For the FAQ section on your homepage
```jsx
// This would be added alongside the other structured data in your InfoPage
const faqSchema = {
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "How up-to-date are the practice questions?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Our team of certified experts regularly updates all questions to match the latest exam objectives and industry changes. We ensure our content remains current with all certification requirements."
      }
    },
    {
      "@type": "Question",
      "name": "Can I access CertGames on my mobile device?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Absolutely! CertGames is fully responsive and works on all devices including desktop, tablet, and mobile phones. Your progress syncs across all platforms automatically."
      }
    },
    {
      "@type": "Question",
      "name": "How does the subscription work?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "For $14.99 per month, you gain unlimited access to all practice tests, tools, resources, and features. You can cancel your subscription at any time with no questions asked."
      }
    },
    {
      "@type": "Question",
      "name": "Is there a guarantee I'll pass my certification exam?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "While we can't guarantee passing (no one ethically can), our success rates are extremely high. Users who complete all practice tests for their target certification and maintain a score of 85% or higher have a passing rate of over 95% on their actual exams."
      }
    },
    {
      "@type": "Question",
      "name": "What if I need help with a specific concept?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Our 24/7 \"Ask Anything\" support feature allows you to ask any certification-related question and receive a thorough, personalized answer from our expert team, typically within 3 hours."
      }
    }
  ]
};

<StructuredData data={faqSchema} />
```

### Implementation Strategy

1. Create the `SEOHelmet` and `StructuredData` components first
2. Add the appropriate SEO tags to each page one by one
3. Test using Google's Rich Results Test tool: https://search.google.com/test/rich-results
4. Monitor performance in Google Search Console after implementation

### Additional SEO Best Practices

1. **Image Optimization**:
   - Add descriptive alt text to all images 
   - Compress images for faster loading
   - Use responsive image techniques where appropriate

2. **Performance**:
   - Monitor Core Web Vitals in Google Search Console
   - Lazy load off-screen images and components
   - Minimize unnecessary JavaScript

3. **URL Structure**:
   - Your current URL structure is good - simple and descriptive
   - Ensure all links on the site use relative URLs for internal links

4. **Content Freshness**:
   - Update your content regularly 
   - Consider adding a blog section with cybersecurity tips and news






ok no with all that said



how should i go about this/implmenet this, how? and what esle? and how/what should i implement this and go about this?


so im gonna provide you my entire info page which consists of like my examspage,demo page,contact,home,etc etc. addionally kinda paired iwth that is my prvacy page,terms of service page.
keep in mind i havent done my demos yet as they are just placeholders for now- however it shoudlnt matter whther the videos are input or not becsue all the info is there.
so my goal audiecne is cyber security and IT, and data students, professioanlsl, and jst gernal career people in IT and cybersecurity. pretty much tryying t get people to subcribe to my websiet that need certfication practice/learning. and a slight uniuqe thing is that its gamified but i dont want tooo much empahsis on that becasue i dont wanan stray away people but aslo want it to be known at the same time.

ok so here are all my pages thatare public bascially- except fro liek my login/regsiter/oauth/username stuff

so for extar context ill also give you my app.js

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


ok here are relvant pages for implementaion

also btw this si my footer jjst for extra context

// src/components/Footer.js
import React from 'react';
import { Link } from 'react-router-dom';
import './footer.css'

const Footer = () => {
  return (
    <footer className="site-footer">
      <div className="footer-content">
        <div className="footer-links">
          <Link to="/">Home</Link>
          <Link to="/privacy">Privacy Policy</Link>
          <Link to="/terms">Terms of Service</Link>
        </div>
        <p className="footer-copyright">© {new Date().getFullYear()} Certgames.com. All rights reserved.</p>
      </div>
    </footer>
  );
};

export default Footer;

// src/components/pages/Info/navbarScrollUtils.js

/**
 * Updates the active tab in the navbar based on scroll position
 * This can be imported and used in InfoNavbar.js to highlight the active section
 */

// Determine which section is currently in view
export const getActiveSection = () => {
  // Get all sections we want to track
  const sections = {
    home: document.querySelector('.info-hero-section'),
    features: document.querySelector('.info-gamified-section'),
    exams: document.querySelector('.info-tests-section'),
    tools: document.querySelector('.info-tools-section'),
    resources: document.querySelector('.info-resources-section'),
    support: document.querySelector('.info-support-section'),
    pricing: document.querySelector('.info-pricing-section')
  };
  
  // Calculate which section is most visible
  let maxVisibleSection = null;
  let maxVisibleHeight = 0;
  
  Object.entries(sections).forEach(([id, element]) => {
    if (!element) return;
    
    const rect = element.getBoundingClientRect();
    const windowHeight = window.innerHeight;
    
    // Calculate how much of the section is visible
    let visibleHeight = 0;
    
    if (rect.top <= 0 && rect.bottom >= 0) {
      // Section starts above viewport and extends into it
      visibleHeight = Math.min(rect.bottom, windowHeight);
    } else if (rect.top >= 0 && rect.top < windowHeight) {
      // Section starts in the viewport
      visibleHeight = Math.min(rect.height, windowHeight - rect.top);
    }
    
    // Adjust weight for the first section (home) to make it active only when truly at the top
    if (id === 'home') {
      // Make home section active only when it's at the very top
      if (rect.top > -100) {
        visibleHeight += 1000; // Add significant weight to keep it active at the top
      } else {
        visibleHeight = 0; // Otherwise don't count it
      }
    }
    
    // Update the most visible section
    if (visibleHeight > maxVisibleHeight) {
      maxVisibleHeight = visibleHeight;
      maxVisibleSection = id;
    }
  });
  
  return maxVisibleSection || 'home';
};

// Map section IDs to nav tab IDs
export const mapSectionToTab = (sectionId) => {
  const mapping = {
    'home': 'home',
    'features': 'home',  // These sections are all part of the home page
    'exams': 'exams',
    'tools': 'demos',    // Tools section maps to demos page
    'resources': 'home',
    'support': 'contact',
    'pricing': 'home',
  };
  
  return mapping[sectionId] || 'home';
};

// Set up scroll event listener to update active tab
export const setupScrollListener = (setActiveTab) => {
  const handleScroll = () => {
    const activeSection = getActiveSection();
    const activeTab = mapSectionToTab(activeSection);
    setActiveTab(activeTab);
  };
  
  window.addEventListener('scroll', handleScroll);
  handleScroll(); // Initialize on load
  
  // Return cleanup function
  return () => {
    window.removeEventListener('scroll', handleScroll);
  };
};

// src/components/pages/Info/PublicLeaderboardPage.js
import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { 
  FaTrophy, 
  FaMedal, 
  FaStar, 
  FaUserAlt,
  FaSearch,
  FaSyncAlt,
  FaChevronUp,
  FaSpinner,
  FaExclamationTriangle,
  FaChevronDown,
  FaCode
} from 'react-icons/fa';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import './PublicLeaderboardPage.css';

// Skeleton component for loading state
const SkeletonItem = ({ index }) => {
  return (
    <div className="leaderboard-item skeleton">
      <div className="leaderboard-rank">
        <div className="skeleton-pulse rank-number"></div>
      </div>
      <div className="leaderboard-avatar-container">
        <div className="skeleton-pulse avatar-circle"></div>
      </div>
      <div className="leaderboard-user-info">
        <div className="skeleton-pulse username-line"></div>
        <div className="leaderboard-user-stats">
          <div className="skeleton-pulse stat-line"></div>
          <div className="skeleton-pulse stat-line shorter"></div>
        </div>
      </div>
    </div>
  );
};

// Top player card component
const TopPlayerCard = ({ player, position }) => {
  const positionClass = position === 1 ? 'gold' : position === 2 ? 'silver' : 'bronze';
  
  return (
    <div className={`top-player-card ${positionClass}`}>
      <div className="position-badge">
        {position === 1 ? (
          <FaTrophy className="position-icon" />
        ) : position === 2 ? (
          <FaMedal className="position-icon" />
        ) : (
          <FaMedal className="position-icon" />
        )}
        <span>{position}</span>
      </div>
      
      <div className="player-avatar">
        {player.avatarUrl ? (
          <img src={player.avatarUrl} alt={`${player.username}'s avatar`} />
        ) : (
          <FaUserAlt />
        )}
      </div>
      
      <div className="player-info">
        <h3>{player.username}</h3>
        <div className="player-stats">
          <div className="player-level">
            <span className="stat-label">Level</span>
            <span className="stat-value">{player.level}</span>
          </div>
          <div className="player-xp">
            <span className="stat-label">XP</span>
            <span className="stat-value">{player.xp.toLocaleString()}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

const PublicLeaderboardPage = () => {
  const [leaders, setLeaders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showScrollToTop, setShowScrollToTop] = useState(false);
  const [codeVisible, setCodeVisible] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(true);

  // Reference to the leaderboard container for scrolling functionality
  const leaderboardRef = useRef(null);

  useEffect(() => {
    fetchLeaderboardData();
  }, []);

  // Handle scroll event to show/hide scroll-to-top button
  useEffect(() => {
    const handleScroll = () => {
      if (leaderboardRef.current) {
        const { scrollTop } = leaderboardRef.current;
        setShowScrollToTop(scrollTop > 300);
      }
    };
    
    const currentRef = leaderboardRef.current;
    if (currentRef) {
      currentRef.addEventListener('scroll', handleScroll);
    }
    
    return () => {
      if (currentRef) {
        currentRef.removeEventListener('scroll', handleScroll);
      }
    };
  }, []);

  const fetchLeaderboardData = async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Using the new public leaderboard endpoint with longer cache time
      const response = await fetch('/api/public-leaderboard/board?skip=0&limit=50');
      
      if (!response.ok) {
        throw new Error('Failed to fetch leaderboard data');
      }
      
      const data = await response.json();
      setLeaders(data.data);
      setHasMore(data.data.length < data.total);
      setLoading(false);
    } catch (err) {
      setError('Failed to load leaderboard. Please try again.');
      setLoading(false);
    }
  };

  const loadMoreLeaders = async () => {
    if (isLoadingMore || !hasMore) return;
    
    setIsLoadingMore(true);
    
    try {
      const response = await fetch(`/api/public-leaderboard/board?skip=${leaders.length}&limit=20`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch more leaderboard data');
      }
      
      const data = await response.json();
      setLeaders(prevLeaders => [...prevLeaders, ...data.data]);
      setHasMore(leaders.length + data.data.length < data.total);
    } catch (err) {
      console.error('Error loading more leaders:', err);
      // Don't set the main error state, just log it
    } finally {
      setIsLoadingMore(false);
    }
  };

  // Filter leaders by username
  const filteredLeaders = searchTerm.trim() === '' 
    ? leaders 
    : leaders.filter(user => 
        user.username.toLowerCase().includes(searchTerm.toLowerCase())
      );

  // Scroll to top function
  const scrollToTop = () => {
    if (leaderboardRef.current) {
      leaderboardRef.current.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
    }
  };

  // Render trophy icon based on rank
  const renderRankIcon = (rank) => {
    if (rank === 1) return <FaTrophy className="rank-icon gold" />;
    if (rank === 2) return <FaTrophy className="rank-icon silver" />;
    if (rank === 3) return <FaTrophy className="rank-icon bronze" />;
    if (rank <= 10) return <FaStar className="rank-icon top-ten" />;
    return null;
  };

  // Get top 3 players
  const topPlayers = leaders.slice(0, 3);

  return (
    <div className="public-leaderboard-container">
      <InfoNavbar />
      
      <div className="public-leaderboard-content">
        <div className="public-leaderboard-header">
          <h1 className="public-leaderboard-title">
            <FaTrophy className="title-icon" />
            CertGames Leaderboard
          </h1>
          <p className="public-leaderboard-subtitle">See who's leading the cybersecurity learning race!</p>
        </div>
        
        {loading ? (
          <div className="loading-container">
            <FaSpinner className="loading-spinner" />
            <p>Loading top cybersecurity learners...</p>
          </div>
        ) : error ? (
          <div className="error-container">
            <FaExclamationTriangle className="error-icon" />
            <p>{error}</p>
            <button className="refresh-button" onClick={fetchLeaderboardData}>
              <FaSyncAlt /> Refresh
            </button>
          </div>
        ) : (
          <>
            {/* Top Players Podium */}
            {topPlayers.length > 0 && (
              <div className="top-players-podium">
                {topPlayers.map((player, index) => (
                  <TopPlayerCard 
                    key={player.rank} 
                    player={player} 
                    position={index + 1} 
                  />
                ))}
              </div>
            )}
            
            {/* Search Bar */}
            <div className="leaderboard-search-container">
              <div className="search-box">
                <FaSearch className="search-icon" />
                <input 
                  type="text" 
                  placeholder="Search by username..." 
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="search-input"
                />
                {searchTerm && (
                  <button 
                    className="clear-search"
                    onClick={() => setSearchTerm('')}
                  >
                    &times;
                  </button>
                )}
              </div>
              
              <div className="leaderboard-stats">
                <div className="stat-pill">
                  <span className="stat-value">{leaders.length}</span>
                  <span className="stat-label">Players</span>
                </div>
              </div>
            </div>
            
            {/* Leaderboard List */}
            <div className="leaderboard-list-container" ref={leaderboardRef}>
              {filteredLeaders.length === 0 ? (
                <div className="no-results">
                  <FaUserAlt className="no-results-icon" />
                  <p>No players found matching "{searchTerm}"</p>
                  <button 
                    className="clear-button"
                    onClick={() => setSearchTerm('')}
                  >
                    Clear Search
                  </button>
                </div>
              ) : (
                <>
                  <div className="leaderboard-list">
                    {filteredLeaders.map((player) => {
                      const rankClass = 
                        player.rank === 1 ? 'gold-rank' : 
                        player.rank === 2 ? 'silver-rank' : 
                        player.rank === 3 ? 'bronze-rank' : 
                        player.rank <= 10 ? 'top-rank' : '';
                      
                      return (
                        <div key={player.rank} className={`leaderboard-item ${rankClass}`}>
                          <div className="leaderboard-rank">
                            <span className="rank-number">{player.rank}</span>
                            {renderRankIcon(player.rank)}
                          </div>
                          
                          <div className="leaderboard-avatar-container">
                            {player.avatarUrl ? (
                              <img 
                                src={player.avatarUrl} 
                                alt={`${player.username}'s avatar`} 
                                className="leaderboard-avatar" 
                              />
                            ) : (
                              <div className="leaderboard-avatar default">
                                <FaUserAlt />
                              </div>
                            )}
                          </div>
                          
                          <div className="leaderboard-user-info">
                            <h3 className="leaderboard-username">{player.username}</h3>
                            <div className="leaderboard-user-stats">
                              <div className="leaderboard-user-level">
                                <span className="level-label">Level</span>
                                <span className="level-value">{player.level}</span>
                              </div>
                              <div className="leaderboard-user-xp">
                                <span className="xp-label">XP</span>
                                <span className="xp-value">{player.xp.toLocaleString()}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  
                  {hasMore && !searchTerm && (
                    <div className="load-more-container">
                      <button 
                        className="load-more-button"
                        onClick={loadMoreLeaders}
                        disabled={isLoadingMore}
                      >
                        {isLoadingMore ? (
                          <>
                            <FaSpinner className="spinner-icon" />
                            Loading more players...
                          </>
                        ) : (
                          <>
                            <FaChevronDown className="down-icon" />
                            Load More Players
                          </>
                        )}
                      </button>
                    </div>
                  )}
                </>
              )}
              
              {showScrollToTop && (
                <button 
                  className="scroll-top-button"
                  onClick={scrollToTop}
                  title="Scroll to top"
                >
                  <FaChevronUp />
                </button>
              )}
            </div>
            
            {/* Join CTA */}
            <div className="join-cta">
              <div className="cta-content">
                <h2>Want to be on this leaderboard?</h2>
                <p>Create your account today and start climbing the ranks!</p>
                <div className="cta-buttons">
                  <Link to="/register" className="register-button">
                    Register Now
                  </Link>
                </div>
              </div>
              
              <div className="code-snippet-container">
                <div className="code-header">
                  <span>How it works</span>
                  <button 
                    className="toggle-code-button"
                    onClick={() => setCodeVisible(!codeVisible)}
                  >
                    <FaCode />
                    {codeVisible ? 'Hide Code' : 'Show Code'}
                  </button>
                </div>
                {codeVisible && (
                  <div className="code-snippet">
                    <pre>
                      <code>
{`// XP System Example
function awardXP(user, correctAnswer) {
  // Base XP for correct answer
  const baseXP = 10;
  
  // Apply any XP boosts the user might have
  const xpMultiplier = user.xpBoost || 1.0;
  const xpAwarded = baseXP * xpMultiplier;
  
  // Update user's total XP
  user.xp += xpAwarded;
  
  // Check if user leveled up
  const newLevel = calculateLevel(user.xp);
  if (newLevel > user.level) {
    user.level = newLevel;
    console.log(\`Level up! You are now level \${newLevel}\`);
  }
  
  return xpAwarded;
}

// Calculate level based on total XP
function calculateLevel(totalXP) {
  // Simple level calculation - each level requires more XP
  return Math.floor(Math.sqrt(totalXP / 100)) + 1;
}`}
                      </code>
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>
      
      <Footer />
    </div>
  );
};

export default PublicLeaderboardPage;


// src/components/pages/Info/InfoNavbar.js
import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { FaHome, FaUserPlus, FaPlayCircle, FaList, FaTrophy, FaEnvelope, FaSignInAlt, FaBars, FaTimes } from 'react-icons/fa';
import { setupScrollListener } from './navbarScrollUtils';
import './InfoNavbar.css';

const InfoNavbar = () => {
  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [activeTab, setActiveTab] = useState('home');
  const location = useLocation();

  // Handle scroll effects for navbar appearance
  useEffect(() => {
    const handleScroll = () => {
      const isScrolled = window.scrollY > 50;
      if (isScrolled !== scrolled) {
        setScrolled(isScrolled);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, [scrolled]);

  // Set active tab based on current route when component mounts
  useEffect(() => {
    const path = location.pathname;
    if (path === '/') {
      setActiveTab('home');
    } else if (path === '/demos') {
      setActiveTab('demos');
    } else if (path === '/exams') {
      setActiveTab('exams');
    } else if (path === '/public-leaderboard') {
      setActiveTab('leaderboard');
    } else if (path === '/contact') {
      setActiveTab('contact');
    } else if (path === '/register') {
      setActiveTab('register');
    } else if (path === '/login') {
      setActiveTab('login');
    }
  }, [location]);

  // Set up scroll-based active tab highlighting, but only on the home page
  useEffect(() => {
    if (location.pathname === '/') {
      const cleanup = setupScrollListener(setActiveTab);
      return cleanup;
    }
  }, [location.pathname]);

  const toggleMenu = () => {
    setMenuOpen(!menuOpen);
  };

  const closeMenu = () => {
    setMenuOpen(false);
  };

  const handleTabClick = (tab) => {
    setActiveTab(tab);
    closeMenu();
  };

  return (
    <nav className={`info-navbar ${scrolled ? 'scrolled' : ''}`}>
      <div className="info-navbar-container">
        <div className="info-navbar-logo">
          <Link to="/" onClick={() => handleTabClick('home')}>
            <span className="logo-text">Cert<span className="logo-highlight">Games</span></span>
          </Link>
        </div>

        <div className="info-navbar-toggle" onClick={toggleMenu}>
          {menuOpen ? <FaTimes /> : <FaBars />}
        </div>

        <div className={`info-navbar-links ${menuOpen ? 'active' : ''}`}>
          <ul>
            <li className={activeTab === 'home' ? 'active' : ''}>
              <Link to="/" onClick={() => handleTabClick('home')}>
                <FaHome className="nav-icon" />
                <span>Home</span>
              </Link>
            </li>
            <li className={activeTab === 'register' ? 'active' : ''}>
              <Link to="/register" onClick={() => handleTabClick('register')}>
                <FaUserPlus className="nav-icon" />
                <span>Register</span>
              </Link>
            </li>
            <li className={activeTab === 'demos' ? 'active' : ''}>
              <Link to="/demos" onClick={() => handleTabClick('demos')}>
                <FaPlayCircle className="nav-icon" />
                <span>Demos</span>
              </Link>
            </li>
            <li className={activeTab === 'exams' ? 'active' : ''}>
              <Link to="/exams" onClick={() => handleTabClick('exams')}>
                <FaList className="nav-icon" />
                <span>All Exams</span>
              </Link>
            </li>
            <li className={activeTab === 'leaderboard' ? 'active' : ''}>
              <Link to="/public-leaderboard" onClick={() => handleTabClick('leaderboard')}>
                <FaTrophy className="nav-icon" />
                <span>Leaderboard</span>
              </Link>
            </li>
            <li className={activeTab === 'contact' ? 'active' : ''}>
              <Link to="/contact" onClick={() => handleTabClick('contact')}>
                <FaEnvelope className="nav-icon" />
                <span>Contact</span>
              </Link>
            </li>
            <li className={activeTab === 'login' ? 'active' : ''}>
              <Link to="/login" onClick={() => handleTabClick('login')}>
                <FaSignInAlt className="nav-icon" />
                <span>Login</span>
              </Link>
            </li>
          </ul>
        </div>
      </div>
      
      {/* Animated background elements */}
      <div className="navbar-matrix-background">
        <div className="code-rain"></div>
      </div>
    </nav>
  );
};

export default InfoNavbar;

// src/components/pages/Info/ExamsPage.js
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { FaSearch, FaFilter, FaChevronDown, FaChevronUp, FaCheckCircle } from 'react-icons/fa';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import './ExamsPage.css';
import aplusLogo from './images/aplus.webp';
import awscloudLogo from './images/awscloud.webp';
import cisspLogo from './images/cissp.webp';
import cloudLogo from './images/cloud.webp';
import cyssaLogo from './images/cysa.webp';
import dataLogo from './images/data.webp';
import linuxLogo from './images/linux.webp';
import networkLogo from './images/network.webp';
import pentestLogo from './images/pentest.webp';
import securityLogo from './images/security.webp';
import securityxLogo from './images/securityx.webp';
import serverLogo from './images/server.webp';


const ExamsPage = () => {
  const [activeCategory, setActiveCategory] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [expandedCert, setExpandedCert] = useState(null);

  // Mock data for certifications
  const certifications = [
    {
      id: 'aplus-core1',
      title: 'CompTIA A+ Core 1',
      code: '220-1101',
      logo: aplusLogo,
      category: 'comptia',
      level: 'beginner',
      questionCount: 1000,
      description: 'Mobile devices, networking technology, hardware, virtualization and cloud computing and hardware and network troubleshooting.',
      skills: ['Hardware', 'Network Troubleshooting', 'Mobile Devices', 'Virtualization'],
      popular: true
    },
    {
      id: 'aplus-core2',
      title: 'CompTIA A+ Core 2',
      code: '220-1102',
      logo: aplusLogo,
      category: 'comptia',
      level: 'beginner',
      questionCount: 1000,
      description: 'Operating systems, security, software troubleshooting and operational procedures.',
      skills: ['Windows', 'Security', 'Troubleshooting', 'Operational Procedures'],
      popular: true
    },
    {
      id: 'network-plus',
      title: 'CompTIA Network+',
      code: 'N10-009',
      logo: networkLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Design and implement functional networks, configure, manage, and maintain essential network devices.',
      skills: ['Networking', 'Subnetting', 'Routing', 'Troubleshooting'],
      popular: true
    },
    {
      id: 'security-plus',
      title: 'CompTIA Security+',
      code: 'SY0-701',
      logo: securityLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Assess the security posture of an enterprise environment and recommend and implement appropriate security solutions.',
      skills: ['Security', 'Cryptography', 'Risk Management', 'Identity Management'],
      popular: true
    },
    {
      id: 'cysa-plus',
      title: 'CompTIA CySA+',
      code: 'CS0-003',
      logo: cyssaLogo,
      category: 'comptia',
      level: 'advanced',
      questionCount: 1000,
      description: 'Apply behavioral analytics to networks to improve the overall state of IT security.',
      skills: ['Threat Detection', 'Security Analytics', 'Vulnerability Management', 'Incident Response'],
      popular: false
    },
    {
      id: 'pentest-plus',
      title: 'CompTIA PenTest+',
      code: 'PT0-003',
      logo: pentestLogo,
      category: 'comptia',
      level: 'advanced',
      questionCount: 1000,
      description: 'Plan and scope a penetration testing engagement, understand legal and compliance requirements.',
      skills: ['Penetration Testing', 'Vulnerability Scanning', 'Exploitation', 'Reporting'],
      popular: false
    },
    {
      id: 'security-x',
      title: 'CompTIA Security X (formerly CASP+)',
      code: 'CAS-005',
      logo: securityxLogo,
      category: 'comptia',
      level: 'expert',
      questionCount: 1000,
      description: 'Security advanced security concepts, principles, and implementations that pertain to enterprise environments.',
      skills: ['Enterprise Security', 'Risk Management', 'Integration', 'Security Architecture'],
      popular: false
    },
    {
      id: 'linux-plus',
      title: 'CompTIA Linux+',
      code: 'XK0-005',
      logo: linuxLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Using Linux command line for maintenance and troubleshooting, as well as system configuration of the OS.',
      skills: ['Linux', 'Command Line', 'System Administration', 'Scripting'],
      popular: false
    },
    {
      id: 'data-plus',
      title: 'CompTIA Data+',
      code: 'DA0-001',
      logo: dataLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Data mining, visualization techniques, building data models, and manipulating data.',
      skills: ['Data Analysis', 'Data Mining', 'Visualization', 'Data Modeling'],
      popular: false
    },
    {
      id: 'server-plus',
      title: 'CompTIA Server+',
      code: 'SK0-005',
      logo: serverLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Server hardware and software technologies, as well as disaster recovery.',
      skills: ['Server Administration', 'Storage', 'Security', 'Virtualization'],
      popular: false
    },
    {
      id: 'cloud-plus',
      title: 'CompTIA Cloud+',
      code: 'CV0-004',
      logo: cloudLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Deploy, secure, and automate cloud environments and understand how to use cloud computing to accomplish business objectives.',
      skills: ['Cloud Computing', 'Deployment', 'Security', 'Automation'],
      popular: false
    },
    {
      id: 'cissp',
      title: 'ISC2 CISSP',
      code: 'CISSP',
      logo: cisspLogo,
      category: 'isc2',
      level: 'expert',
      questionCount: 1000,
      description: 'Security and risk management, asset security, security architecture and engineering, and more.',
      skills: ['Security Management', 'Asset Security', 'Security Engineering', 'Communications'],
      popular: true
    },
    {
      id: 'aws-cloud',
      title: 'AWS Cloud Practitioner',
      code: 'CLF-C02',
      logo: awscloudLogo,
      category: 'aws',
      level: 'beginner',
      questionCount: 1000,
      description: 'Understanding of the AWS Cloud, security and compliance within the AWS Cloud, and core AWS services.',
      skills: ['Cloud Concepts', 'Security', 'AWS Services', 'Billing and Pricing'],
      popular: true
    }
  ];
  
  // Filter certifications based on active category and search term
  const filteredCerts = certifications.filter(cert => {
    // Filter by category
    if (activeCategory !== 'all' && cert.category !== activeCategory) return false;
    
    // Filter by search term
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      return (
        cert.title.toLowerCase().includes(searchLower) ||
        cert.code.toLowerCase().includes(searchLower) ||
        cert.description.toLowerCase().includes(searchLower) ||
        cert.skills.some(skill => skill.toLowerCase().includes(searchLower))
      );
    }
    
    return true;
  });
  
  // Toggle expanded certification
  const toggleExpand = (certId) => {
    if (expandedCert === certId) {
      setExpandedCert(null);
    } else {
      setExpandedCert(certId);
    }
  };
  
  return (
    <div className="exams-container">
      <InfoNavbar />
      
      <div className="exams-content">
        <div className="exams-header">
          <h1 className="exams-title">
            <span className="exams-icon">🎓</span>
            Certification Exam Prep
          </h1>
          <p className="exams-subtitle">
            Access to all exams with a single subscription — 13,000+ practice questions across 13 certifications
          </p>
          
          <div className="exams-access-notice">
            <FaCheckCircle className="notice-icon" />
            <p>Your subscription includes unlimited access to all certification practice tests</p>
          </div>
        </div>
        
        {/* Search and Filter */}
        <div className="exams-search-filters">
          <div className="exams-search">
            <FaSearch className="search-icon" />
            <input
              type="text"
              placeholder="Search certifications..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input"
            />
          </div>
          
          <div className="exams-filters">
            <div 
              className="filters-toggle" 
              onClick={() => setFiltersOpen(!filtersOpen)}
            >
              <FaFilter className="filter-icon" />
              <span>Filter</span>
              {filtersOpen ? <FaChevronUp /> : <FaChevronDown />}
            </div>
            
            {filtersOpen && (
              <div className="filters-dropdown">
                <div className="filter-group">
                  <h4>Vendor</h4>
                  <div className="filter-options">
                    <button 
                      className={`filter-option ${activeCategory === 'all' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('all')}
                    >
                      All
                    </button>
                    <button 
                      className={`filter-option ${activeCategory === 'comptia' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('comptia')}
                    >
                      CompTIA
                    </button>
                    <button 
                      className={`filter-option ${activeCategory === 'isc2' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('isc2')}
                    >
                      ISC2
                    </button>
                    <button 
                      className={`filter-option ${activeCategory === 'aws' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('aws')}
                    >
                      AWS
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
        
        {/* Certifications Grid */}
        <div className="exams-grid">
          {filteredCerts.length > 0 ? (
            filteredCerts.map((cert) => (
              <div 
                key={cert.id} 
                className={`cert-card ${expandedCert === cert.id ? 'expanded' : ''} ${cert.popular ? 'popular' : ''}`}
              >
                {cert.popular && <div className="popular-badge">Popular</div>}
                
                <div className="cert-header">
                  <div className="cert-logo">
                    <img src={cert.logo} alt={`${cert.title} logo`} />
                  </div>
                  <div className="cert-title-info">
                    <h3>{cert.title}</h3>
                    <div className="cert-meta">
                      <span className="cert-code">{cert.code}</span>
                      <span className={`cert-level ${cert.level}`}>
                        {cert.level.charAt(0).toUpperCase() + cert.level.slice(1)}
                      </span>
                    </div>
                  </div>
                  <button 
                    className="expand-button"
                    onClick={() => toggleExpand(cert.id)}
                  >
                    {expandedCert === cert.id ? <FaChevronUp /> : <FaChevronDown />}
                  </button>
                </div>
                
                <div className="cert-content">
                  <p className="cert-description">{cert.description}</p>
                  
                  <div className="cert-stats">
                    <div className="cert-stat">
                      <span className="stat-value">{cert.questionCount.toLocaleString()}</span>
                      <span className="stat-label">Questions</span>
                    </div>
                    <div className="cert-stat">
                      <span className="stat-value">10</span>
                      <span className="stat-label">Practice Tests</span>
                    </div>
                    <div className="cert-stat">
                      <span className="stat-value">100%</span>
                      <span className="stat-label">Coverage</span>
                    </div>
                  </div>
                  
                  {expandedCert === cert.id && (
                    <div className="cert-details">
                      <div className="cert-skills">
                        <h4>Key Skills Covered:</h4>
                        <div className="skills-list">
                          {cert.skills.map((skill, index) => (
                            <span key={index} className="skill-tag">{skill}</span>
                          ))}
                        </div>
                      </div>
                      
                      <div className="cert-features">
                        <div className="feature-item">
                          <FaCheckCircle className="feature-icon" />
                          <span>Performance-based Questions</span>
                        </div>
                        <div className="feature-item">
                          <FaCheckCircle className="feature-icon" />
                          <span>Detailed Explanations</span>
                        </div>
                        <div className="feature-item">
                          <FaCheckCircle className="feature-icon" />
                          <span>Progress Tracking</span>
                        </div>
                        <div className="feature-item">
                          <FaCheckCircle className="feature-icon" />
                          <span>Exam Simulation Mode</span>
                        </div>
                      </div>
                    </div>
                  )}
                  
                  <div className="cert-actions">
                    <Link to="/register" className="try-cert-button">Try This Exam</Link>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="no-results">
              <h3>No certifications found</h3>
              <p>Try adjusting your search or filters</p>
              <button 
                className="reset-button"
                onClick={() => {
                  setSearchTerm('');
                  setActiveCategory('all');
                }}
              >
                Reset Filters
              </button>
            </div>
          )}
        </div>
        
        {/* Subscribe CTA */}
        <div className="exams-subscribe-cta">
          <div className="subscribe-card">
            <div className="subscribe-content">
              <h2>Ready to pass your certification exams?</h2>
              <p>Get unlimited access to all 13 certification paths with 13,000+ practice questions</p>
              <div className="price-section">
                <div className="price">
                  <span className="currency">$</span>
                  <span className="amount">14</span>
                  <span className="decimal">.99</span>
                  <span className="period">/month</span>
                </div>
                <p className="price-note">Cancel anytime. No long-term commitment.</p>
              </div>
              <Link to="/register" className="subscribe-button">
                Start Your Journey
              </Link>
            </div>
            
            <div className="subscribe-features">
              <div className="feature">
                <FaCheckCircle className="feature-icon" />
                <span>13 Certification Paths</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" />
                <span>13,000+ Practice Questions</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" />
                <span>All Learning Tools Included</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" />
                <span>24/7 Support</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" />
                <span>Gamified Learning Experience</span>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <Footer />
    </div>
  );
};

export default ExamsPage;

// src/components/pages/Info/DemosPage.js
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FaPlay, FaChevronLeft, FaChevronRight } from 'react-icons/fa';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import './DemosPage.css';

const DemosPage = () => {
  const [activeSection, setActiveSection] = useState('featured');
  const [activeDemo, setActiveDemo] = useState(null);

  // Demo data - this would be replaced with actual demo data
  const demoData = {
    gamification: [
      {
        id: 'xp-system',
        title: 'XP & Leveling System',
        description: 'See how completing tests and answering questions correctly earns you XP to level up your profile.',
        videoUrl: '/demos/xp-system.mp4', // Placeholder - will be replaced
        thumbnail: 'https://via.placeholder.com/600x338?text=XP+System+Demo'
      },
      {
        id: 'coins-system',
        title: 'Coins & Shop System',
        description: 'Watch how to earn coins and spend them in the shop to unlock unique avatars and boosts.',
        videoUrl: '/demos/coins-system.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Coins+System+Demo'
      },
      {
        id: 'achievements',
        title: 'Achievement System',
        description: 'Discover the various achievements you can unlock as you progress through your certification journey.',
        videoUrl: '/demos/achievements.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Achievements+Demo'
      },
      {
        id: 'leaderboards',
        title: 'Leaderboards',
        description: 'See how you stack up against other cybersecurity enthusiasts on our global leaderboards.',
        videoUrl: '/demos/leaderboards.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Leaderboards+Demo'
      }
    ],
    learning: [
      {
        id: 'scenario-sphere',
        title: 'ScenarioSphere',
        description: 'Experience realistic security scenarios with detailed storylines to build your incident response skills.',
        videoUrl: '/demos/scenario-sphere.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=ScenarioSphere+Demo'
      },
      {
        id: 'analogy-hub',
        title: 'Analogy Hub',
        description: 'See how complex security concepts are broken down using memorable analogies to enhance understanding.',
        videoUrl: '/demos/analogy-hub.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Analogy+Hub+Demo'
      },
      {
        id: 'grc-wizard',
        title: 'GRC Wizard',
        description: 'Watch how our GRC Wizard helps you master governance, risk, and compliance topics with custom-generated questions.',
        videoUrl: '/demos/grc-wizard.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=GRC+Wizard+Demo'
      },
      {
        id: 'xploitcraft',
        title: 'XploitCraft',
        description: 'Learn about exploitation techniques through educational code examples with detailed explanations.',
        videoUrl: '/demos/xploitcraft.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=XploitCraft+Demo'
      }
    ],
    daily: [
      {
        id: 'daily-bonus',
        title: 'Daily Bonus',
        description: 'See how to claim your daily free coins to spend in the shop.',
        videoUrl: '/demos/daily-bonus.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Daily+Bonus+Demo'
      },
      {
        id: 'pbq-challenge',
        title: 'Daily PBQ Challenge',
        description: 'Watch how the daily performance-based question challenges work and how to solve them.',
        videoUrl: '/demos/pbq-challenge.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=PBQ+Challenge+Demo'
      },
      {
        id: 'cyber-brief',
        title: 'Cyber Brief',
        description: 'Check out our daily cybersecurity news and study tips feature.',
        videoUrl: '/demos/cyber-brief.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Cyber+Brief+Demo'
      }
    ],
    tests: [
      {
        id: 'test-interface',
        title: 'Test Interface',
        description: 'See how our intuitive test interface makes studying for your certification exams a breeze.',
        videoUrl: '/demos/test-interface.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Test+Interface+Demo'
      },
      {
        id: 'exam-mode',
        title: 'Exam Mode',
        description: 'Experience our realistic exam simulation mode to prepare for the real thing.',
        videoUrl: '/demos/exam-mode.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Exam+Mode+Demo'
      },
      {
        id: 'review-answers',
        title: 'Review & Analytics',
        description: 'See how our detailed review and analytics help you identify and improve your weak areas.',
        videoUrl: '/demos/review-analytics.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Review+Analytics+Demo'
      }
    ],
    support: [
      {
        id: 'ask-anything',
        title: 'Ask Anything',
        description: 'Watch how our 24/7 support system works to help you with any questions or issues.',
        videoUrl: '/demos/ask-anything.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Ask+Anything+Demo'
      }
    ]
  };

  // Create a featured demos array with 1 demo from each category
  const featuredDemos = [
    demoData.gamification[0],
    demoData.learning[0],
    demoData.daily[0],
    demoData.tests[0],
    demoData.support[0]
  ];

  // Handle demo selection
  const handleDemoSelect = (demo) => {
    setActiveDemo(demo);
    // Scroll to video player
    document.getElementById('demo-player').scrollIntoView({ behavior: 'smooth' });
  };

  // Get current demos based on active section
  const getCurrentDemos = () => {
    switch(activeSection) {
      case 'featured':
        return featuredDemos;
      case 'gamification':
        return demoData.gamification;
      case 'learning':
        return demoData.learning;
      case 'daily':
        return demoData.daily;
      case 'tests':
        return demoData.tests;
      case 'support':
        return demoData.support;
      default:
        return featuredDemos;
    }
  };

  // Set default active demo when section changes
  useEffect(() => {
    const currentDemos = getCurrentDemos();
    if (currentDemos.length > 0) {
      setActiveDemo(currentDemos[0]);
    }
  }, [activeSection]);

  return (
    <div className="demos-container">
      <InfoNavbar />
      
      <div className="demos-content">
        <div className="demos-header">
          <h1 className="demos-title">
            <span className="demos-icon">🎬</span>
            Feature Demos
          </h1>
          <p className="demos-subtitle">Watch our interactive demos to see CertGames in action</p>
        </div>

        {/* Demo Player Section */}
        <div id="demo-player" className="demo-player-section">
          {activeDemo && (
            <div className="demo-player-container">
              <div className="demo-video">
                {/* This would be replaced with an actual video player component */}
                <div className="demo-video-placeholder">
                  <img src={activeDemo.thumbnail} alt={activeDemo.title} />
                  <div className="play-overlay">
                    <FaPlay className="play-icon" />
                    <span>Demo Video Placeholder</span>
                  </div>
                </div>
              </div>
              <div className="demo-info">
                <h2>{activeDemo.title}</h2>
                <p>{activeDemo.description}</p>
                <div className="demo-cta">
                  <Link to="/register" className="demo-register-btn">
                    Try This Feature
                  </Link>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Demo Categories Navigation */}
        <div className="demo-categories">
          <button
            className={`category-button ${activeSection === 'featured' ? 'active' : ''}`}
            onClick={() => setActiveSection('featured')}
          >
            Featured
          </button>
          <button
            className={`category-button ${activeSection === 'gamification' ? 'active' : ''}`}
            onClick={() => setActiveSection('gamification')}
          >
            Gamification
          </button>
          <button
            className={`category-button ${activeSection === 'learning' ? 'active' : ''}`}
            onClick={() => setActiveSection('learning')}
          >
            Learning Tools
          </button>
          <button
            className={`category-button ${activeSection === 'daily' ? 'active' : ''}`}
            onClick={() => setActiveSection('daily')}
          >
            Daily Features
          </button>
          <button
            className={`category-button ${activeSection === 'tests' ? 'active' : ''}`}
            onClick={() => setActiveSection('tests')}
          >
            Test Experience
          </button>
          <button
            className={`category-button ${activeSection === 'support' ? 'active' : ''}`}
            onClick={() => setActiveSection('support')}
          >
            Support
          </button>
        </div>

        {/* Demo Thumbnails */}
        <div className="demo-thumbnails">
          <div className="thumbnails-header">
            <h3>{activeSection.charAt(0).toUpperCase() + activeSection.slice(1)} Demos</h3>
            <div className="thumbnails-navigation">
              <button className="nav-button">
                <FaChevronLeft />
              </button>
              <button className="nav-button">
                <FaChevronRight />
              </button>
            </div>
          </div>
          
          <div className="thumbnails-grid">
            {getCurrentDemos().map((demo) => (
              <div 
                key={demo.id} 
                className={`thumbnail-item ${activeDemo && activeDemo.id === demo.id ? 'active' : ''}`}
                onClick={() => handleDemoSelect(demo)}
              >
                <div className="thumbnail-image">
                  <img src={demo.thumbnail} alt={demo.title} />
                  <div className="thumbnail-overlay">
                    <FaPlay className="thumbnail-play" />
                  </div>
                </div>
                <h4 className="thumbnail-title">{demo.title}</h4>
              </div>
            ))}
          </div>
        </div>

        {/* Register CTA Section */}
        <div className="demos-cta-section">
          <div className="demos-cta-content">
            <h2>Ready to experience all these features?</h2>
            <p>Create your free account today and start your cybersecurity journey with CertGames!</p>
            <Link to="/register" className="cta-button">
              Create Your Account
            </Link>
          </div>
        </div>
      </div>

      <Footer />
    </div>
  );
};

export default DemosPage;

// src/components/pages/Info/ContactPage.js
import React, { useState } from 'react';
import { 
  FaEnvelope, 
  FaPaperPlane, 
  FaLinkedin, 
  FaTwitter, 
  FaInstagram, 
  FaReddit, 
  FaFacebook,
  FaCheck,
  FaExclamationTriangle
} from 'react-icons/fa';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import './ContactPage.css';

const ContactPage = () => {
  const [formData, setFormData] = useState({
    email: '',
    message: ''
  });
  const [formErrors, setFormErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState(null); // 'success', 'error', or null

  const validateForm = () => {
    const errors = {};
    
    // Email validation
    if (!formData.email) {
      errors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      errors.email = 'Email address is invalid';
    }
    
    // Message validation
    if (!formData.message) {
      errors.message = 'Message is required';
    } else if (formData.message.length < 10) {
      errors.message = 'Message must be at least 10 characters';
    }
    
    return errors;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
    
    // Clear error for this field when user starts typing
    if (formErrors[name]) {
      setFormErrors({
        ...formErrors,
        [name]: ''
      });
    }
  };

 // Updated handleSubmit function for ContactPage.js

const handleSubmit = async (e) => {
  e.preventDefault();
  
  // Validate form
  const errors = validateForm();
  if (Object.keys(errors).length > 0) {
    setFormErrors(errors);
    return;
  }
  
  setIsSubmitting(true);
  setSubmitStatus(null);
  
  try {
    // Call the actual API endpoint
    const response = await fetch('/api/contact-form/submit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: formData.email,
        message: formData.message
      })
    });
    
    const data = await response.json();
    
    if (response.ok && data.success) {
      // Success case
      setSubmitStatus('success');
      
      // Reset form
      setFormData({
        email: '',
        message: ''
      });
      
      // Reset success message after 5 seconds
      setTimeout(() => {
        setSubmitStatus(null);
      }, 5000);
    } else {
      // API returned an error
      console.error('Error submitting form:', data.error);
      setSubmitStatus('error');
    }
  } catch (error) {
    console.error('Network error submitting form:', error);
    setSubmitStatus('error');
  } finally {
    setIsSubmitting(false);
  }
};

  return (
    <div className="contact-container">
      <InfoNavbar />
      
      <div className="contact-content">
        <div className="contact-header">
          <h1 className="contact-title">
            <FaEnvelope className="title-icon" />
            Contact Us
          </h1>
          <p className="contact-subtitle">
            Have questions or feedback? We'd love to hear from you!
          </p>
        </div>
        
        <div className="contact-grid">
          <div className="contact-form-container">
            <div className="contact-form-card">
              <h2>Send us a message</h2>
              
              {submitStatus === 'success' && (
                <div className="form-success">
                  <FaCheck className="success-icon" />
                  <p>Message sent successfully! We'll get back to you soon.</p>
                </div>
              )}
              
              {submitStatus === 'error' && (
                <div className="form-error">
                  <FaExclamationTriangle className="error-icon" />
                  <p>There was an error sending your message. Please try again later.</p>
                </div>
              )}
              
              <form className="contact-form" onSubmit={handleSubmit}>
                <div className="form-group">
                  <label htmlFor="email">Email Address</label>
                  <input
                    type="email"
                    id="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="Enter your email address"
                    disabled={isSubmitting}
                    className={formErrors.email ? 'input-error' : ''}
                  />
                  {formErrors.email && (
                    <div className="error-message">{formErrors.email}</div>
                  )}
                </div>
                
                <div className="form-group">
                  <label htmlFor="message">Message</label>
                  <textarea
                    id="message"
                    name="message"
                    value={formData.message}
                    onChange={handleChange}
                    placeholder="What would you like to tell us?"
                    rows="6"
                    disabled={isSubmitting}
                    className={formErrors.message ? 'input-error' : ''}
                  ></textarea>
                  {formErrors.message && (
                    <div className="error-message">{formErrors.message}</div>
                  )}
                </div>
                
                <button 
                  type="submit" 
                  className="send-button"
                  disabled={isSubmitting}
                >
                  {isSubmitting ? (
                    <span className="submitting">
                      <span className="spinner"></span>
                      Sending...
                    </span>
                  ) : (
                    <span className="send-text">
                      <FaPaperPlane className="send-icon" />
                      Send Message
                    </span>
                  )}
                </button>
              </form>
            </div>
          </div>
          
          <div className="contact-info-container">
            <div className="contact-info-card">
              <h2>Get in Touch</h2>
              
              <div className="contact-channels">
                <div className="contact-channel">
                  <div className="channel-icon">
                    <FaEnvelope />
                  </div>
                  <div className="channel-details">
                    <h3>Support Email</h3>
                    <p>support@certgames.com</p>
                    <p className="response-time">Usually responds within 24 hours</p>
                  </div>
                </div>
                
                <div className="contact-channel">
                  <div className="channel-icon business">
                    <FaEnvelope />
                  </div>
                  <div className="channel-details">
                    <h3>Business Inquiries</h3>
                    <p>inquiry@certgames.com</p>
                    <p className="response-time">For partnership opportunities</p>
                  </div>
                </div>
              </div>
              
              <div className="social-links">
                <h3>Connect With Us</h3>
                <div className="social-icons">
                  <a href="https://www.linkedin.com/company/certgames/?viewAsMember=true" target="_blank" rel="noopener noreferrer" className="social-icon linkedin">
                    <FaLinkedin />
                  </a>
                  <a href="https://x.com/CertsGamified" target="_blank" rel="noopener noreferrer" className="social-icon twitter">
                    <FaTwitter />
                  </a>
                  <a href="https://www.instagram.com/certsgamified/" target="_blank" rel="noopener noreferrer" className="social-icon instagram">
                    <FaInstagram />
                  </a>
                  <a href="https://www.reddit.com/user/Hopeful_Beat7161/" target="_blank" rel="noopener noreferrer" className="social-icon reddit">
                    <FaReddit />
                  </a>
                  <a href="https://www.facebook.com/people/CertGames/61574087485497/" target="_blank" rel="noopener noreferrer" className="social-icon facebook">
                    <FaFacebook />
                  </a>
                </div>
              </div>
            </div>
            
            <div className="faq-section">
              <h3>Frequently Asked Questions</h3>
              
              <div className="faq-item">
                <h4>How do I reset my password?</h4>
                <p>You can reset your password by clicking on the "Forgot Password" link on the login page and following the instructions sent to your email.</p>
              </div>
              
              <div className="faq-item">
                <h4>How do I cancel my subscription?</h4>
                <p>You can cancel your subscription at any time from your account settings. Your access will continue until the end of your current billing period.</p>
              </div>
              
              <div className="faq-item">
                <h4>Can I access CertGames on my mobile device?</h4>
                <p>Yes! CertGames is fully responsive and works on all devices, including mobile phones and tablets.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <Footer />
    </div>
  );
};

export default ContactPage;


main kinda page(home)

// src/components/pages/Info/InfoPage.js
import React, { useEffect, useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import { 
  FaApple, 
  FaGoogle, 
  FaAppStore, 
  FaPlay, 
  FaArrowRight, 
  FaInfoCircle, 
  FaExternalLinkAlt 
} from 'react-icons/fa';
import './InfoPage.css';

const InfoPage = () => {
  // For tab switching functionality
  const [activeTab, setActiveTab] = useState('comptia');
  
  // For the typing animation effect in hero section
  const [displayText, setDisplayText] = useState('');
  const fullText = 'Level up your cybersecurity skills';
  
  // For counting animation
  const [questionCount, setQuestionCount] = useState(0);
  const [certCount, setCertCount] = useState(0);
  const [resourceCount, setResourceCount] = useState(0);
  
  // Refs for scroll sections
  const featuresRef = useRef(null);
  const toolsRef = useRef(null);
  const testsRef = useRef(null);
  const pricingRef = useRef(null);
  
  // Functions to handle card flipping and demo views
  const handleCardClick = (event, demoId = null) => {
    const card = event.currentTarget;
    card.classList.toggle('info-flipped');
    
    // Reset other flipped cards
    document.querySelectorAll('.info-flipped').forEach(flippedCard => {
      if (flippedCard !== card) {
        flippedCard.classList.remove('info-flipped');
      }
    });
    
    // If demoId is provided, store it for navigation
    if (demoId) {
      localStorage.setItem('lastViewedDemo', demoId);
    }
  };
  
  // Scroll to section function
  const scrollToSection = (ref) => {
    if (ref && ref.current) {
      ref.current.scrollIntoView({ behavior: 'smooth' });
    }
  };
  
  // For parallax effect on scroll
  useEffect(() => {
    const handleScroll = () => {
      const elements = document.querySelectorAll('.info-animate-on-scroll');
      
      elements.forEach(el => {
        const position = el.getBoundingClientRect();
        
        // If element is in viewport
        if(position.top < window.innerHeight && position.bottom >= 0) {
          el.classList.add('info-visible');
        }
      });
    };
    
    window.addEventListener('scroll', handleScroll);
    handleScroll(); // Check on initial load
    
    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);
  
  // Typing effect
  useEffect(() => {
    if (displayText.length < fullText.length) {
      const timer = setTimeout(() => {
        setDisplayText(fullText.slice(0, displayText.length + 1));
      }, 100);
      
      return () => clearTimeout(timer);
    }
  }, [displayText]);
  
  // Counting animation
  useEffect(() => {
    const questionsTarget = 13000;
    const certsTarget = 13;
    const resourcesTarget = 600;
    const duration = 2000; // ms
    const steps = 50;
    
    const questionsIncrement = questionsTarget / steps;
    const certsIncrement = certsTarget / steps;
    const resourcesIncrement = resourcesTarget / steps;
    const interval = duration / steps;
    
    let currentStep = 0;
    
    const timer = setInterval(() => {
      currentStep++;
      
      if (currentStep <= steps) {
        setQuestionCount(Math.floor(questionsIncrement * currentStep));
        setCertCount(Math.floor(certsIncrement * currentStep));
        setResourceCount(Math.floor(resourcesIncrement * currentStep));
      } else {
        setQuestionCount(questionsTarget);
        setCertCount(certsTarget);
        setResourceCount(resourcesTarget);
        clearInterval(timer);
      }
    }, interval);
    
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="info-container">
      {/* Navbar */}
      <InfoNavbar />
      
      {/* Hero Section */}
      <section className="info-hero-section">
        <div className="info-overlay"></div>
        <div className="info-hero-content">
          <div className="info-hero-text">
            <h1 className="info-hero-title">
              <span className="info-logo-text">Cert<span className="info-highlight">Games</span></span>
            </h1>
            <h2 className="info-hero-subtitle">{displayText}<span className="info-cursor"></span></h2>
            <p className="info-hero-description">
              The ultimate gamified cybersecurity training platform that makes learning fun, effective, and addictive.
            </p>
            <div className="info-hero-cta">
              <Link to="/register" className="info-button info-primary-button">
                Start Your Journey <FaArrowRight className="info-icon" />
              </Link>
              <Link to="/login" className="info-button info-secondary-button">
                Log In
              </Link>
            </div>
            <div className="info-quick-links">
              <button onClick={() => scrollToSection(featuresRef)} className="info-quick-link">
                <span>Features</span>
              </button>
              <button onClick={() => scrollToSection(toolsRef)} className="info-quick-link">
                <span>Learning Tools</span>
              </button>
              <button onClick={() => scrollToSection(testsRef)} className="info-quick-link">
                <span>Certification Tests</span>
              </button>
              <button onClick={() => scrollToSection(pricingRef)} className="info-quick-link">
                <span>Pricing</span>
              </button>
            </div>
          </div>

          <div className="info-hero-stats">
            <div className="info-stat-card">
              <div className="info-stat-value">{questionCount.toLocaleString()}</div>
              <div className="info-stat-label">Practice Questions</div>
            </div>
            <div className="info-stat-card">
              <div className="info-stat-value">{certCount}</div>
              <div className="info-stat-label">Certifications</div>
            </div>
            <div className="info-stat-card">
              <div className="info-stat-value">{resourceCount}+</div>
              <div className="info-stat-label">Learning Resources</div>
            </div>
          </div>
        </div>
        <div className="info-scroll-indicator">
          <div className="info-mouse"></div>
          <p>Scroll to explore</p>
        </div>
      </section>

      {/* Gamified Experience Section */}
      <section ref={featuresRef} className="info-feature-section info-gamified-section">
        <div className="info-section-header info-animate-on-scroll">
          <h2>
            <span className="info-section-icon">🎮</span>
            Gamified Learning Experience
          </h2>
          <p>Level up your skills while having fun</p>
        </div>
        <div className="info-feature-grid">
          <div 
            className="info-feature-card info-animate-on-scroll info-clickable-card"
            onClick={(e) => handleCardClick(e, 'xp-system')}
          >
            <div className="info-feature-icon">
              <i className="info-exp-icon">XP</i>
            </div>
            <h3>Earn XP & Level Up</h3>
            <p>Answer questions correctly to gain experience points and climb the ranks from rookie to elite hacker.</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch XP System Demo</span>
                </Link>
              </div>
            </div>
          </div>
          <div 
            className="info-feature-card info-animate-on-scroll info-clickable-card" 
            onClick={(e) => handleCardClick(e, 'coins-system')}
          >
            <div className="info-feature-icon">
              <i className="info-coins-icon">💰</i>
            </div>
            <h3>Collect Coins</h3>
            <p>Earn virtual currency by completing tests and daily challenges to unlock exclusive avatars and boosts.</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch Coins System Demo</span>
                </Link>
              </div>
            </div>
          </div>
          <div 
            className="info-feature-card info-animate-on-scroll info-clickable-card"
            onClick={(e) => handleCardClick(e, 'achievements')}
          >
            <div className="info-feature-icon">
              <i className="info-trophy-icon">🏆</i>
            </div>
            <h3>Unlock Achievements</h3>
            <p>Complete special tasks to earn badges and trophies that showcase your growing expertise.</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch Achievements Demo</span>
                </Link>
              </div>
            </div>
          </div>
          <div 
            className="info-feature-card info-animate-on-scroll info-clickable-card"
            onClick={(e) => handleCardClick(e, 'leaderboards')}
          >
            <div className="info-feature-icon">
              <i className="info-leaderboard-icon">📊</i>
            </div>
            <h3>Compete on Leaderboards</h3>
            <p>See how you rank against other cybersecurity enthusiasts and strive to climb to the top.</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/public-leaderboard" className="info-demo-link">
                  <FaExternalLinkAlt className="info-demo-icon" />
                  <span>View Current Leaderboard</span>
                </Link>
              </div>
            </div>
          </div>
          <div 
            className="info-feature-card info-animate-on-scroll info-clickable-card"
            onClick={(e) => handleCardClick(e, 'themes')}
          >
            <div className="info-feature-icon">
              <i className="info-theme-icon">🎨</i>
            </div>
            <h3>Customize Your Experience</h3>
            <p>Choose from multiple themes and personalize your learning environment to suit your style.</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch Theme Customization Demo</span>
                </Link>
              </div>
            </div>
          </div>
          <div 
            className="info-feature-card info-animate-on-scroll info-clickable-card"
            onClick={(e) => handleCardClick(e, 'mobile')}
          >
            <div className="info-feature-icon">
              <i className="info-mobile-icon">📱</i>
            </div>
            <h3>Learn Anywhere</h3>
            <p>Access all features on desktop, mobile browsers, and our dedicated iOS app for learning on the go.</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch Mobile App Demo</span>
                </Link>
              </div>
            </div>
          </div>
        </div>
        
        <div className="info-feature-links info-animate-on-scroll">
          <Link to="/demos" className="info-feature-link">
            <span>View All Feature Demos</span>
            <FaArrowRight className="info-link-icon" />
          </Link>
          <Link to="/public-leaderboard" className="info-feature-link">
            <span>Browse Leaderboard</span>
            <FaArrowRight className="info-link-icon" />
          </Link>
        </div>
        
        <div className="info-preview-placeholder info-animate-on-scroll">
          <div className="info-preview-overlay">
            <p>Leaderboard Preview</p>
          </div>
        </div>
      </section>

      {/* Certification Tests Section */}
      <section ref={testsRef} className="info-feature-section info-tests-section">
        <div className="info-section-header info-animate-on-scroll">
          <h2>
            <span className="info-section-icon">📝</span>
            Master 13 Certification Paths
          </h2>
          <p>13,000 practice questions across the most in-demand certifications</p>
        </div>
        <div className="info-test-features info-animate-on-scroll">
          <div className="info-test-features-list">
            <div className="info-test-feature">
              <span className="info-check-icon">✓</span>
              <span>Performance-Based Questions (PBQs)</span>
            </div>
            <div className="info-test-feature">
              <span className="info-check-icon">✓</span>
              <span>Realistic Exam Simulations</span>
            </div>
            <div className="info-test-feature">
              <span className="info-check-icon">✓</span>
              <span>Detailed Explanations</span>
            </div>
            <div className="info-test-feature">
              <span className="info-check-icon">✓</span>
              <span>Difficulty Progression System</span>
            </div>
            <div className="info-test-feature">
              <span className="info-check-icon">✓</span>
              <span>Customizable Test Lengths</span>
            </div>
            <div className="info-test-feature">
              <span className="info-check-icon">✓</span>
              <span>Memorable Exam Tips</span>
            </div>
            <div className="info-test-feature">
              <span className="info-check-icon">✓</span>
              <span>Progress Tracking & Analytics</span>
            </div>
            <div className="info-test-feature">
              <span className="info-check-icon">✓</span>
              <span>Exam Mode with Timed Sessions</span>
            </div>
          </div>
          <div className="info-test-selector">
            <div className="info-test-tabs">
              <button 
                className={`info-test-tab ${activeTab === 'comptia' ? 'info-active' : ''}`} 
                onClick={() => setActiveTab('comptia')}
              >
                CompTIA
              </button>
              <button 
                className={`info-test-tab ${activeTab === 'isc2' ? 'info-active' : ''}`} 
                onClick={() => setActiveTab('isc2')}
              >
                ISC2
              </button>
              <button 
                className={`info-test-tab ${activeTab === 'aws' ? 'info-active' : ''}`} 
                onClick={() => setActiveTab('aws')}
              >
                AWS
              </button>
            </div>
            
            {/* CompTIA Tab Content */}
            <div className={`info-cert-list ${activeTab !== 'comptia' ? 'info-hidden' : ''}`}>
              <div className="info-cert-item">
                <span className="info-cert-badge">A+</span>
                <span className="info-cert-name">A+ Core 1 & Core 2</span>
                <span className="info-cert-count">2,000 questions</span>
              </div>
              <div className="info-cert-item">
                <span className="info-cert-badge">N+</span>
                <span className="info-cert-name">Network+</span>
                <span className="info-cert-count">1,000 questions</span>
              </div>
              <div className="info-cert-item">
                <span className="info-cert-badge">S+</span>
                <span className="info-cert-name">Security+</span>
                <span className="info-cert-count">1,000 questions</span>
              </div>
              <div className="info-cert-item">
                <span className="info-cert-badge">CySA+</span>
                <span className="info-cert-name">CySA+</span>
                <span className="info-cert-count">1,000 questions</span>
              </div>
              <div className="info-cert-item">
                <span className="info-cert-badge">PenTest+</span>
                <span className="info-cert-name">PenTest+</span>
                <span className="info-cert-count">1,000 questions</span>
              </div>
              <div className="info-cert-dropdown">
                <div className="info-show-more">
                  <span>+7 more certifications</span>
                </div>
                <div className="info-dropdown-content">
                  <div className="info-cert-item">
                    <span className="info-cert-badge">CASP+</span>
                    <span className="info-cert-name">CASP+</span>
                    <span className="info-cert-count">1,000 questions</span>
                  </div>
                  <div className="info-cert-item">
                    <span className="info-cert-badge">Linux+</span>
                    <span className="info-cert-name">Linux+</span>
                    <span className="info-cert-count">1,000 questions</span>
                  </div>
                  <div className="info-cert-item">
                    <span className="info-cert-badge">Data+</span>
                    <span className="info-cert-name">Data+</span>
                    <span className="info-cert-count">1,000 questions</span>
                  </div>
                  <div className="info-cert-item">
                    <span className="info-cert-badge">Server+</span>
                    <span className="info-cert-name">Server+</span>
                    <span className="info-cert-count">1,000 questions</span>
                  </div>
                  <div className="info-cert-item">
                    <span className="info-cert-badge">Cloud+</span>
                    <span className="info-cert-name">Cloud+</span>
                    <span className="info-cert-count">1,000 questions</span>
                  </div>
                </div>
              </div>
            </div>
            
            {/* ISC2 Tab Content */}
            <div className={`info-cert-list ${activeTab !== 'isc2' ? 'info-hidden' : ''}`}>
              <div className="info-cert-item">
                <span className="info-cert-badge">CISSP</span>
                <span className="info-cert-name">CISSP</span>
                <span className="info-cert-count">1,000 questions</span>
              </div>
            </div>
            
            {/* AWS Tab Content */}
            <div className={`info-cert-list ${activeTab !== 'aws' ? 'info-hidden' : ''}`}>
              <div className="info-cert-item">
                <span className="info-cert-badge">CCP</span>
                <span className="info-cert-name">Cloud Practitioner</span>
                <span className="info-cert-count">1,000 questions</span>
              </div>
            </div>
          </div>
        </div>
        
        <div className="info-feature-links info-animate-on-scroll">
          <Link to="/exams" className="info-feature-link">
            <span>View All Certification Exams</span>
            <FaArrowRight className="info-link-icon" />
          </Link>
        </div>
      </section>

      {/* Interactive Tools Section */}
      <section ref={toolsRef} className="info-feature-section info-tools-section">
        <div className="info-section-header info-animate-on-scroll">
          <h2>
            <span className="info-section-icon">🛠️</span>
            Cutting-Edge Learning Tools
          </h2>
          <p>Unique tools to boost your cybersecurity understanding</p>
        </div>
        <div className="info-tools-grid">
          <div 
            className="info-tool-card info-animate-on-scroll info-clickable-card"
            onClick={(e) => handleCardClick(e, 'scenario-sphere')}
          >
            <h3>
              <span className="info-tool-icon">🔎</span>
              ScenarioSphere
            </h3>
            <p>Immerse yourself in realistic security scenarios with detailed storylines. Tackle simulated cyberattacks to build your incident response skills.</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch ScenarioSphere Demo</span>
                </Link>
              </div>
            </div>
          </div>
          <div 
            className="info-tool-card info-animate-on-scroll info-clickable-card"
            onClick={(e) => handleCardClick(e, 'analogy-hub')}
          >
            <h3>
              <span className="info-tool-icon">🔄</span>
              Analogy Hub
            </h3>
            <p>Complex concepts made simple through custom analogies. Compare security concepts using memorable examples to reinforce your learning.</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch Analogy Hub Demo</span>
                </Link>
              </div>
            </div>
          </div>
          <div 
            className="info-tool-card info-animate-on-scroll info-clickable-card"
            onClick={(e) => handleCardClick(e, 'grc-wizard')}
          >
            <h3>
              <span className="info-tool-icon">📋</span>
              GRC Wizard
            </h3>
            <p>Master governance, risk, and compliance topics with custom generated questions across multiple categories and difficulty levels.</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch GRC Wizard Demo</span>
                </Link>
              </div>
            </div>
          </div>
          <div 
            className="info-tool-card info-animate-on-scroll info-clickable-card"
            onClick={(e) => handleCardClick(e, 'xploitcraft')}
          >
            <h3>
              <span className="info-tool-icon">⚔️</span>
              XploitCraft
            </h3>
            <p>Learn about exploitation techniques through educational code examples with detailed explanations for real world understanding.</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch XploitCraft Demo</span>
                </Link>
              </div>
            </div>
          </div>
        </div>
        
        <div className="info-feature-links info-animate-on-scroll">
          <Link to="/demos" className="info-feature-link">
            <span>View All Tool Demos</span>
            <FaArrowRight className="info-link-icon" />
          </Link>
        </div>
      </section>

      {/* Resources Section */}
      <section className="info-feature-section info-resources-section">
        <div className="info-section-header info-animate-on-scroll">
          <h2>
            <span className="info-section-icon">📚</span>
            Comprehensive Resource Library
          </h2>
          <p>600+ curated resources to accelerate your learning</p>
        </div>
        <div className="info-resources-preview info-animate-on-scroll">
          <div className="info-resources-categories">
            <div className="info-resource-category">
              <span className="info-category-icon">🔧</span>
              <span>Security Tools</span>
            </div>
            <div className="info-resource-category">
              <span className="info-category-icon">🎓</span>
              <span>Courses</span>
            </div>
            <div className="info-resource-category">
              <span className="info-category-icon">📹</span>
              <span>YouTube Resources</span>
            </div>
            <div className="info-resource-category">
              <span className="info-category-icon">📜</span>
              <span>Certification Guides</span>
            </div>
            <div className="info-resource-category">
              <span className="info-category-icon">🛡️</span>
              <span>Security Frameworks</span>
            </div>
            <div className="info-resource-category">
              <span className="info-resource-more">+400 more</span>
            </div>
          </div>
        </div>
      </section>

      {/* Support Section */}
      <section className="info-feature-section info-support-section">
        <div className="info-section-header info-animate-on-scroll">
          <h2>
            <span className="info-section-icon">🤝</span>
            24/7 Expert Support
          </h2>
          <p>Get help whenever you need it</p>
        </div>
        <div className="info-support-content info-animate-on-scroll">
          <div 
            className="info-support-preview info-clickable-card"
            onClick={(e) => handleCardClick(e, 'support')}
          >
            <div className="info-support-chat">
              <div className="info-chat-header">
                <h4>Support / Ask Anything</h4>
              </div>
              <div className="info-chat-message info-user-message">
                <p>How do I know I am prepared for the Security+ exam?</p>
                <span className="info-message-time">09:38 AM</span>
              </div>
              <div className="info-chat-message info-support-message">
                <div className="info-support-avatar"></div>
                <div className="info-message-content">
                  <p>Take a quick self check: grab the exam objectives PDF, skim each bullet point, and try to explain each one in your own words. If you can do that for most of them, go ahead and schedule the exam!</p>
                  <p>Would you like some tips on how to be confident during your exam?</p>
                </div>
                <span className="info-message-time">09:44 AM</span>
              </div>
              <div className="info-chat-input">
                <input type="text" placeholder="Type your message here..." disabled />
                <button className="info-send-button" disabled></button>
              </div>
            </div>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch Support System Demo</span>
                </Link>
              </div>
            </div>
          </div>
          <div className="info-support-details">
            <h3>Your Personal Cybersecurity Tutor</h3>
            <ul className="info-support-features">
              <li>
                <span className="info-check-icon">✓</span>
                <span>Ask questions about any certification topic</span>
              </li>
              <li>
                <span className="info-check-icon">✓</span>
                <span>Get help with difficult concepts</span>
              </li>
              <li>
                <span className="info-check-icon">✓</span>
                <span>Receive customized study advice</span>
              </li>
              <li>
                <span className="info-check-icon">✓</span>
                <span>Average response time: 3 hours</span>
              </li>
              <li>
                <span className="info-check-icon">✓</span>
                <span>Technical assistance with platform features</span>
              </li>
            </ul>
            
            <div className="info-support-links">
              <Link to="/contact" className="info-support-link">
                <span>Contact Support</span>
                <FaArrowRight className="info-link-icon" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Daily Rewards Section */}
      <section className="info-feature-section info-daily-section">
        <div className="info-section-header info-animate-on-scroll">
          <h2>
            <span className="info-section-icon">🎁</span>
            Daily Rewards & Challenges
          </h2>
          <p>Keep the momentum going with daily incentives</p>
        </div>
        <div className="info-daily-content info-animate-on-scroll">
          <div 
            className="info-daily-card info-clickable-card"
            onClick={(e) => handleCardClick(e, 'daily-bonus')}
          >
            <div className="info-daily-icon">🪙</div>
            <h3>Daily Bonus</h3>
            <p>Claim free coins every 24 hours to spend in the shop</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch Daily Bonus Demo</span>
                </Link>
              </div>
            </div>
          </div>
          <div 
            className="info-daily-card info-clickable-card"
            onClick={(e) => handleCardClick(e, 'daily-pbq')}
          >
            <div className="info-daily-icon">🧩</div>
            <h3>Daily PBQ Challenge</h3>
            <p>Tackle a new performance-based question each day to earn bonus coins</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch Daily PBQ Demo</span>
                </Link>
              </div>
            </div>
          </div>
          <div 
            className="info-daily-card info-clickable-card"
            onClick={(e) => handleCardClick(e, 'cyber-brief')}
          >
            <div className="info-daily-icon">📰</div>
            <h3>Cyber Brief</h3>
            <p>Stay informed with curated cybersecurity news and study tips</p>
            <div className="info-card-flip">
              <div className="info-demo-preview">
                <Link to="/demos" className="info-demo-link">
                  <FaPlay className="info-demo-icon" />
                  <span>Watch Cyber Brief Demo</span>
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section ref={pricingRef} className="info-pricing-section">
        <div className="info-section-header info-animate-on-scroll">
          <h2>
            <span className="info-section-icon">💎</span>
            Unlock Your Full Potential
          </h2>
          <p>Affordable access to premium cybersecurity training</p>
        </div>
        
        <div className="info-pricing-card info-animate-on-scroll">
          <h3 className="info-plan-name">Access</h3>
          <div className="info-price">
            <span className="info-currency">$</span>
            <span className="info-amount">14</span>
            <span className="info-decimal">.99</span>
            <span className="info-period">/month</span>
          </div>
          
          <ul className="info-pricing-features">
            <li>
              <span className="info-check-icon">✓</span>
              <span>13,000+ Practice Questions</span>
            </li>
            <li>
              <span className="info-check-icon">✓</span>
              <span>13 Certification Paths</span>
            </li>
            <li>
              <span className="info-check-icon">✓</span>
              <span>All Interactive Learning Tools</span>
            </li>
            <li>
              <span className="info-check-icon">✓</span>
              <span>Complete Resource Library</span>
            </li>
            <li>
              <span className="info-check-icon">✓</span>
              <span>24/7 Support / Ask Anything</span>
            </li>
            <li>
              <span className="info-check-icon">✓</span>
              <span>Gamified Learning Experience</span>
            </li>
            <li>
              <span className="info-check-icon">✓</span>
              <span>Daily Rewards & Challenges</span>
            </li>
          </ul>
          
          <Link to="/register" className="info-button info-cta-button">
            Get Started Now
          </Link>
          <p className="info-pricing-note">Cancel anytime. No long-term commitment.</p>
        </div>
      </section>

      {/* Testimonials Section */}
      <section className="info-testimonials-section">
        <div className="info-section-header info-animate-on-scroll">
          <h2>
            <span className="info-section-icon">💬</span>
            Testimonials
          </h2>
          <p>Join other IT enthusiasts who have leveled up their studying!</p>
        </div>
        
        <div className="info-testimonials-grid">
          <div className="info-testimonial-card info-animate-on-scroll">
            <div className="info-testimonial-content">
              <p>"I never thought I'd say this about a study site, but it's genuinely fun. The gamified aspect takes the monotomy out of studying, and having a that centralized resource hub is brilliant. My browser bookmarks are thanking me."</p>
            </div>
            <div className="info-testimonial-author">
              <div className="info-author-avatar" style={{ backgroundColor: '#4e54c8' }}></div>
              <div className="info-author-info">
                <p className="info-author-name">Connor B.</p>
                <p className="info-author-title">Security Analyst</p>
              </div>
            </div>
          </div>
          
          <div className="info-testimonial-card info-animate-on-scroll">
            <div className="info-testimonial-content">
              <p>"This site hits that sweet spot between education and entertainment. Studying for CompTIA certs feels rewarding instead of tedious. Big thumbs-up for the gamification, because I always tried to study like that myself, but now there is finally a dedicated webiste I can use."</p>
            </div>
            <div className="info-testimonial-author">
              <div className="info-author-avatar" style={{ backgroundColor: '#43cea2' }}></div>
              <div className="info-author-info">
                <p className="info-author-name">Samantha K.</p>
                <p className="info-author-title">Cybersecurity Manager</p>
              </div>
            </div>
          </div>
          
          <div className="info-testimonial-card info-animate-on-scroll">
            <div className="info-testimonial-content">
              <p>"I appreciate how this website doesn't feel like a lecture—more like playing a game that just happens to teach certifications. I also think the question page helped me alot when I needed to ask questions regarding my upcoming exam."</p>
            </div>
            <div className="info-testimonial-author">
              <div className="info-author-avatar" style={{ backgroundColor: '#ff9966' }}></div>
              <div className="info-author-info">
                <p className="info-author-name">Leon T.</p>
                <p className="info-author-title">IT Student</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section className="info-faq-section">
        <div className="info-section-header info-animate-on-scroll">
          <h2>
            <span className="info-section-icon">❓</span>
            Frequently Asked Questions
          </h2>
          <p>Everything you need to know</p>
        </div>
        
        <div className="info-faq-content">
          <div className="info-faq-item info-animate-on-scroll">
            <h3 className="info-faq-question">How up-to-date are the practice questions?</h3>
            <p className="info-faq-answer">Our team of certified experts regularly updates all questions to match the latest exam objectives and industry changes. We ensure our content remains current with all certification requirements.</p>
          </div>
          
          <div className="info-faq-item info-animate-on-scroll">
            <h3 className="info-faq-question">Can I access CertGames on my mobile device?</h3>
            <p className="info-faq-answer">Absolutely! CertGames is fully responsive and works on all devices including desktop, tablet, and mobile phones. We also have a dedicated IOS app you can donwload in the App Store. Your progress syncs across all platforms automatically.</p>
          </div>
          
          <div className="info-faq-item info-animate-on-scroll">
            <h3 className="info-faq-question">How does the subscription work?</h3>
            <p className="info-faq-answer">For $9.99 per month, you gain unlimited access to all practice tests, tools, resources, and features. You can cancel your subscription at any time with no questions asked.</p>
          </div>
          
          <div className="info-faq-item info-animate-on-scroll">
            <h3 className="info-faq-question">Is there a guarantee I'll pass my certification exam?</h3>
            <p className="info-faq-answer">While we can't guarantee passing, our success rates are extremely high. Users who complete just half of our practice tests for their target certification and maintain a score of 75% or higher have a passing rate of over 95% on their actual exams.</p>
          </div>
          
          <div className="info-faq-item info-animate-on-scroll">
            <h3 className="info-faq-question">What if I need help with a specific concept?</h3>
            <p className="info-faq-answer">Our 24/7 "Ask Anything" support feature allows you to ask any certification-related question, test question, exam questions, study advice, and whatever you might need help with, you will receive a thorough, personalized answer from our expert team who have passed all certifications listed, typically within 3 hours.</p>
          </div>
          
          <div className="info-more-questions">
            <Link to="/contact" className="info-more-questions-link">
              <FaInfoCircle className="info-question-icon" />
              <span>Have more questions? Contact us</span>
            </Link>
          </div>
        </div>
      </section>

      {/* Final CTA Section */}
      <section className="info-final-cta">
        <div className="info-cta-content info-animate-on-scroll">
          <h2>Ready to Begin Your Cybersecurity Journey?</h2>
          <p>Join oter security professionals and IT enthusiasts who've transformed their careers/study prep with CertGames</p>
          <div className="info-cta-buttons">
            <Link to="/register" className="info-button info-primary-button">
              Create Your Account
            </Link>
            <Link to="/login" className="info-button info-secondary-button">
              Log In
            </Link>
          </div>
          <div className="info-oauth-options">
            <span>Quick sign-up with:</span>
            <div className="info-oauth-buttons">
              <button className="info-oauth-button info-google" onClick={() => window.location.href = "/api/oauth/login/google"}>
                <FaGoogle className="info-oauth-icon" /> Google
              </button>
              <button className="info-oauth-button info-apple" onClick={() => window.location.href = "/api/oauth/login/apple"}>
                <FaApple className="info-oauth-icon" /> Apple ID
              </button>
            </div>
          </div>
          <div className="info-app-download">
            <a href="#" className="info-app-link">
              <FaAppStore className="info-app-icon" />
              <span>Download on the App Store</span>
            </a>
          </div>
        </div>
        <div className="info-cta-graphic">
          <div className="info-glow"></div>
        </div>
      </section>

      {/* Footer */}
      <Footer />
    </div>
  );
};

export default InfoPage;


ok so thats all teh files now provide in depth step by step and best way to implement all SEO and otehr good stuff etc etc and how and why
