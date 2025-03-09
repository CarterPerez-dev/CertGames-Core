ok so here is what i need you to do for me. so i have an info page (i ahevnt mad eit yet) i just made the file name and put it into my app.js so far so i have it as import InfoPage from './components/pages/Info/InfoPage'; adn then the path is 
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

so keep the name as is.

so anyway- im sellinga  subscription to the paltform fro $14.99 USD a month, any bqsically i need an "info" page that essentially convices teh user to subsrivbe to the platfrom, so it shsodul aslo throughly explain my paltfrom and convice them aslo, and it shoudl be in afun way not derpsate, and also really cool looking- so it shoudl ber clear obviolsy but also gamified style, like imagien tehy look at the info page and tehy already wanan subscribe becasue its so cool looking and tells the mevrythinghg they need to  know, so it should have all teh best features we have- with an empahsis on teh tests- becasue hoenstly tahst one of my biggest selling point is havinga  wopping 13,0000 practice quetsions in total adn 13 certs to stduy fro (1000) each whcih is alot, and liek all teh etst features we haev isa cool too like teh exam mode, length selection, explantiosn in depth, and exam tips and so on, also a big selling poiint is teh resource page whihc has 60-0 reosucerss all relating to certfuictauioins (a little more detaisls below) and also anoteh rbig deslling point annd mainly its the unique aspect about my platfrom is that its gamified learning, so veyrhting is gamifeid liek teh lvling up, xp, coins, shop, avaatrs, xp boosts, leaderbaord, teh wueol appis teh style of liek a gamified website too, and more. the ntheres more selling points obvisoly lkiek all thr "tools" we have, and also teh "question" tab which is essentially just an ask us anything tab where they badcially have a 24/7 tutor taht asnwers tyhem whatver question they want wheve rthey weant (more deteaisl below) so ye im probaly misisng more selling points you will hellp with taht aswell

im gonna provide an overview with a little more details about all of it and even irreleavnmt deatisl liek by backend and tech stack whiuch is mroe so just fro you to know a little more oconet but might no herlp withg the page, were really focusing on what teh user see's, gets. and ill also provide you some pictures of my web app to help with conetxt


i havent really amde the inffo page yet but i do know i need mayeb 2 obvious regsiter buttons and login buttons, becasue my mindsaet is if tehyc an t find out how to regsiter than all of this is pointless so dont make it depserate liek spamming the resgiter button but aslo make sure they see it a coupel times atleast aswella s haveing obvios login aswell

so ill just give you my whole entire app.js so you know teh path for those two

so heres my aapp.js

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
import Login from './components/pages/auth/Login';
import Register from './components/pages/auth/Register';
import ForgotPassword from './components/pages/auth/ForgotPassword';
import ResetPassword from './components/pages/auth/ResetPassword';
import PrivacyPolicy from './components/pages/PrivacyPolicy';
import TermsOfService from './components/pages/TermsOfService';
import CreateUsernameForm from './components/pages/auth/CreateUsernameForm'; // Add this line

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


/* 
  - If user data is still loading, shows a loading message.
  - If user is logged in, redirects to /profile.
  - Otherwise, renders the public InfoPage.
*/

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
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password/:token" element={<ResetPassword />} />
          <Route path="/create-username" element={<CreateUsernameForm />} />
          <Route path="/oauth/success" element={<OAuthSuccess />} />
          <Route path="/cracked/login" element={<CrackedAdminLoginPage />} />
          <Route path="/cracked/dashboard" element={<CrackedAdminDashboard />} />
          <Route path="/my-support" element={<SupportAskAnythingPage />} />
          <Route path="/privacy" element={<PrivacyPolicy />} />
          <Route path="/terms" element={<TermsOfService />} />
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

addionally- i have a footer fro my login and regsiter page which is naslo needed for my info page

so heres my footer and its css 
/* Add to global.css */

/* Footer Styles - Updated */
.site-footer {
  width: 100%;
  background-color: rgba(20, 20, 30, 0.7);
  backdrop-filter: blur(8px);
  border-top: 1px solid rgba(128, 128, 255, 0.15);
  padding: 0.8rem 0;
  margin-top: auto;
  position: relative;
  z-index: 10;
}

.footer-content {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
}

.footer-links {
  display: flex;
  justify-content: center;
  gap: 1.5rem;
}

.footer-links a {
  color: rgba(255, 255, 255, 0.7);
  font-size: 0.85rem;
  text-decoration: none;
  transition: all 0.2s ease;
  position: relative;
}

.footer-links a:hover {
  color: rgba(128, 128, 255, 0.9);
}

.footer-links a:after {
  content: "";
  position: absolute;
  width: 0;
  height: 1px;
  bottom: -2px;
  left: 0;
  background-color: rgba(128, 128, 255, 0.7);
  transition: width 0.2s ease;
}

.footer-links a:hover:after {
  width: 100%;
}

.footer-copyright {
  font-size: 0.75rem;
  color: rgba(255, 255, 255, 0.5);
  margin: 0;
}

/* Make sure these container elements have flex column and min-height 100vh */
.info-container,
.login-container,
.register-container,
.policy-container {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

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

addiotnally it shopudl be comptbale with all browsers/devices/iphones etc etc, and last thjing tehcinal wise is it should have very unique css names so you dont acciedntly overide my othert pages css name blocks yah know



pictuirs proovided aswell







### 1. General Overview
- **Purpose**: Our platform is a gamified cybersecurity training environment that helps users learn, test, and enhance their skills in various IT security and governance-related domains.
- **Technology Stack**: 
  - **Backend**: Python/Flask API, Celery-based asynchronous tasks, MongoDB for data persistence, Redis for caching and background job management, Docker for containerization, Apache/Nginx for server routing.(not really useful fro my inffo page tho)
  - **Frontend**: A React application that delivers an immersive and interactive user experience, with dedicated pages for tests, daily content, achievements, user profiles, a store, scenario-based learning, and more.

---

### 2. Frontend Features (React App)
- **Multiple Certification Test Pages**:
  - We provide practice tests with PBQ type questions, scernario based qustions, cocneptual basedd questions, and more, tahta re very diffuclt to process of elimiante just liek real compita exam, addionally it has exam mode where answers are shown at the edn which simulates teh real exam, and non exam mode which giev syou immediater feedback at teh end, each expapmtion is very in depth adn aslo a sperate feidl which is "exam tip" whcih giev syou a memeorable short 1 senetcne tip that wuill make you learn the cocnept better, for a variety of certifications, including:
    -Each certifation categroy has 1000 practice questioisn split it tino 10 differente tests ranging in difculty from test 1 is a nromal tets on par with real exam- and teh tets 2 starts with "very easy" and progressivly gets harder up tpo test 10 "ultra leevl", addionally each test has default 100 quetsiosn btu youc an take teh etst at 25 questions, 50 questions, or 75 questions, CompTIA certications A+ Core 1 and Core 2 Security+, Network+, Linux+, Server+, Cloud+, CySA+, PenTest+, Data+, and CASP+. AWS Cloud Practitioner, and ISC2 CISSP. with more ocming in teh future


- a tool tab with a variety of toosl to help you learn such as 

**ScenarioSphere** (ScenarioPage):
  - Users can tackle interactive security scenarios (cyberattacks, real-time threat setups) with detailed storylines, threat intensities, and skill levels. adn 3 test questiosn at the end of teh scanerio related top teh scernio taghat test you on concepts in teh scenrio
  - Encourages critical thinking: Attack or defense steps, potential outcomes, and recommended solutions are explored.

- **Analogy Page**:
  - Interactive tool that generates custom analogies to explain cybersecurity or IT concepts in simple, fun ways, wehtehr you want a single concept as an anolgy, or compare two concepts or even tripel comaprisonw her eyou can compare 3 different concepts into one memeorable uniuqe anaolgy

- **GRC Page**:
  - Generates governance, risk management, and compliance (GRC) questions. Users can study for advanced certifications by focusing on risk management or compliance topics.

- ** xploitcarft** enetr in an exploit AND OR an evasiuon tehcinique and it generates 3 exampel code snippets of what that exploit and or evasion techniuqe looks like with 3 expalntiosn of each aswell.

so those were the tools (under thr tool tab)

- **Cyber Brief**: (it says "daily" in the sidebar but im changing taht soon ebacsue its actually liek 2-3 times a week)
  - A  newldstter of interesting news or short challenges, exam tips, satudy tips, and even life toips in which users can sign up for if they choose

- **Resources Page**:
  - Central location with curated references, study materials, courses, subreddits, cyber/pentetsing tools, cyber frameworks, youtibve videos and playslist and creators, top linkiden coruses and people, and moree, with over 600 resoruces.

- **User Profile**:
  - Tracks user progress: coins, XP, level, achievements, purchased items, test stats, daily bonus claims, etc. setting to chaneg username, email, password etc, addionally it has 20 colors of teh colro them eo fthe webiste you want.

- **Shop & Achievements**:
  - **Virtual Coins**: Earn by completing test quetsions and can  Spend them on unique items ijn the shop adn also unlcoiks avatarst with lvling up (avatars, name color changes, XP boosts, etc.).
 
 - **Achievements**: Trophies awarded for milestone completions (e.g., perfect test scores, finishing a certain number of tests and questions, lvling up etc etc.).
- 
**Bonus**:
  - Users can claim a “daily bonus” of coins once every 24 hours, aswell as a daily PBQ that gievs teh suer 250 coins if correctly asnwered or 50 coins if answered wortng.

--- Leaderbaord - shows evryoen on teh platfrom in order of lvl and shows profiel avatar and what lvl tehya re. so it encourage suers ot rank up etc


might not be helpful for the info page but heres addional conext of my backend
### 3. Backend & Core Functionalities
- **User Management**:
  - Registration, login, password resets, OAuth (Google and Apple) for quick sign-in.
  - Strict input sanitization (usernames, passwords, emails) to maintain security and data integrity.
- **Test & Attempt Management**:
  - MongoDB-based storing of tests, user attempts, correct answers, and scoring data.
  - Detailed tracking of each question answered, with feedback and explanations.
- **Scenario Generation**:
  - AI-based scenario helper that dynamically creates realistic cybersecurity incidents. Incorporates parameters like industry type, attack style, threat intensity, and skill level.
- **GRC Question Generation**:
  - Creates advanced multi-choice questions covering risk management, compliance, auditing, regulations, and more. Ideal for high-level certifications (CISSP, CRISC, CASP+, etc.).
- **Analogy Generation**:
  - AI can produce playful or instructive analogies to clarify complex IT/cyber concepts, either single, comparative, or triple comparisons.
- **XploitCraft Helper**:
  - Generates educational example payloads for various exploit or evasion techniques (for authorized training & demonstration). Demonstrates code snippets and explains how each exploit might be mitigated.
- **Rate Limiting**:
  - Built-in system to ensure fair usage and prevent spam or abuse of the AI endpoints.
- **Newsletter System**:
  - Campaign creation and subscriber management, allowing administrators to push updates or announcements directly to email lists. Includes subscribe/unsubscribe logic and personalized links.
- **Admin Tools**:
  - “Cracked Admin” panel with:
    - User CRUD (create, read, update, delete),
    - Test management (uploading, editing, or removing test sets),
    - Daily PBQ (Performance-Based Question) creation,
    - Viewing & managing logs or performance metrics,
    - Health checks and endpoint monitoring.
- **Performance Monitoring**:
  - Automatic tasks capture average request time, DB query time, data transfer rates, throughput, and error rates every few minutes. 
  - Admin can view these metrics and logs to optimize system performance.
- **Docker & Deployment**:
  - The platform is containerized with separate Docker images for the backend, frontend, Apache server, and more. 
  - Integrates seamlessly with environment variables for easy scaling and management.

---

 Key Benefits
**Holistic Cybersecurity Training**: Multiple certifications covered + scenario-based learning + daily briefs, and most importantly its gamified, aslo all tests are saved for the suer and prgress is saved across all apps, broswers, devices etc
 **Gamified Experience**: Earn coins, level up, collect achievements, unlock items, and keep training exciting.
 **Dynamic Content**: uniuqe generation of GRC questions, analogies, and exploit examples so content never gets stale.
 **Real-World Relevance**: The scenario approach helps learners experience practical threat simulations.
 **Community & Support**: Support threads system with user-admin messaging for quick help or Q&A. wher eteh suer can aks literally anyhthing in real time to us whetehr ist about the exma tehir stufdying for, or websiet questions, or questiosn about a test question or ewven life quetsions, we are willing to answe anything wheever, and average repsoone time is 3 hours.
8



ok soall of that was brief overveiw just fro your context, becsue you have full creative conrtyol to make teh coolest/ gamified but clear/ very evry convicjng but not despreate, awesoem/ promoptipnal/ info page, with a palcehodler video soemhwere wehever you want whatevr is best idk adn tell me what it should be and ill make teh vdeio and put it there- it shoud prbably have pictures too idk tho so its all up topt you liek i said you haved full cearyive co0nrtol- but if you want to add poictures/videos just make them placeholders and then tell me what they shoudl be and ill put them wherever you put them yah know- all up to you bro. taht baially if you saw it you wopudl 1000& subsribe!!  Ok so now give me the info page js and css!!!!! its gonan be amzing!!







