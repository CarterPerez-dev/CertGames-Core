// src/App.js
import React, { useEffect, useState } from 'react';
import { Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { fetchUserData, logout } from './components/pages/store/userSlice';

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
import BlogPage from './components/pages/Info/BlogPage';
import BlogPostPage from './components/pages/Info/BlogPostPage';
import SubscriptionCancel from './components/pages/subscription/SubscriptionCancel';
import SubscriptionPage from './components/pages/subscription/SubscriptionPage';
import SubscriptionSuccess from './components/pages/subscription/SubscriptionSuccess';

// Admin 
import CrackedAdminLoginPage from './components/cracked/CrackedAdminLoginPage';
import CrackedAdminDashboard from './components/cracked/CrackedAdminDashboard'; 

// Protected pages
import ProtectedRoute from './components/ProtectedRoute';
import Sidebar from './components/Sidebar/Sidebar';

// Your components imports (Xploitcraft, etc.)
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

// Practice test pages
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
  const { userId, subscriptionActive } = useSelector((state) => state.user);
  const navigate = useNavigate();
  const location = useLocation();
  const [isCheckingSubscription, setIsCheckingSubscription] = useState(false);

  // Initialize theme
  useEffect(() => {
    const initializeTheme = () => {
      const savedTheme = localStorage.getItem('selectedTheme') || 'default';
      document.documentElement.setAttribute('data-theme', savedTheme);
    };

    initializeTheme();
  }, []); 
  
  // Check user authentication and fetch data
  useEffect(() => {
    if (userId) {
      // Fetch user data
      dispatch(fetchUserData(userId))
        .catch((error) => {
          console.error('Error fetching user data:', error);
        });
    }
  }, [dispatch, userId]);
  
  // Check subscription status
  useEffect(() => {
    const checkSubscriptionStatus = async () => {
      if (userId && !isCheckingSubscription) {
        setIsCheckingSubscription(true);
        
        try {
          // Add path check to prevent subscription checks on certain pages
          const isSubscriptionRelatedPage = [
            '/subscription', 
            '/subscription/success', 
            '/subscription/cancel',
            '/create-username',
            '/oauth/success'
          ].includes(location.pathname);
          
          // Check if we recently checked (avoid rapid re-checks)
          const lastCheck = localStorage.getItem('lastSubscriptionCheck');
          const checkThrottleMs = 30000; // 30 seconds
          const shouldSkipCheck = isSubscriptionRelatedPage || 
            (lastCheck && (Date.now() - parseInt(lastCheck)) < checkThrottleMs);
          
          if (!shouldSkipCheck) {
            // Set last check timestamp
            localStorage.setItem('lastSubscriptionCheck', Date.now().toString());
            
            // Check with API directly instead of fetching all user data
            const response = await axios.get(`/api/subscription/check-status?userId=${userId}`);
            
            if (response.data && !response.data.subscriptionActive) {
              console.log('Subscription inactive, redirecting to subscription page');
              
              // Store userId for renewal
              localStorage.setItem('tempUserId', userId);
              
              // Store renewal info
              localStorage.setItem('pendingRegistration', JSON.stringify({
                userId: userId,
                registrationType: 'renewal'
              }));
              
              // Log out
              dispatch(logout());
              
              // Navigate to subscription page
              navigate('/subscription', { 
                state: { renewSubscription: true, userId }
              });
            }
          }
        } catch (error) {
          console.error('Error checking subscription status:', error);
        } finally {
          setIsCheckingSubscription(false);
        }
      }
    };
    
    // Check on initial load, but with a delay to prevent immediate redirect loops
    const initialTimer = setTimeout(checkSubscriptionStatus, 3000);
    
    // Normal interval check hourly
    const interval = setInterval(checkSubscriptionStatus, 36000000); // 1 hour
    
    return () => {
      clearTimeout(initialTimer);
      clearInterval(interval);
    };
  }, [userId, dispatch, navigate, location.pathname, isCheckingSubscription]);
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
          <Route path="/blog" element={<BlogPage />} />
          <Route path="/blog/:postId" element={<BlogPostPage />} />
          
          {/* Authentication routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password/:token" element={<ResetPassword />} />
          <Route path="/create-username" element={<CreateUsernameForm />} />
          <Route path="/oauth/success" element={<OAuthSuccess />} />
          <Route path="/subscription" element={<SubscriptionPage />} />
          <Route path="/subscription/success" element={<SubscriptionSuccess />} />
          <Route path="/subscription/cancel" element={<SubscriptionCancel />} />
          
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
