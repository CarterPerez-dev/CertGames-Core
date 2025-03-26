// src/components/subscription/SubscriptionSuccess.js
import React, { useEffect, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { useNavigate, useLocation } from 'react-router-dom';
import { fetchUserData } from '../store/userSlice';
import './SubscriptionSuccess.css';

// Icons import
import {
  FaCheckCircle,
  FaUserShield,
  FaCrown,
  FaUnlockAlt,
  FaHome,
  FaCoins,
  FaRocket,
  FaInfo,
  FaTrophy,
  FaCalendarAlt,
  FaCreditCard,
  FaRegClock
} from 'react-icons/fa';

const SubscriptionSuccess = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  
  // Get subscription data from URL params or state
  const urlParams = new URLSearchParams(location.search);
  const subscriptionId = urlParams.get('subscriptionId') || (location.state && location.state.subscriptionId);
  const paymentMethod = urlParams.get('paymentMethod') || (location.state && location.state.paymentMethod);
  const platform = urlParams.get('platform') || (location.state && location.state.platform) || 'website';
  
  // Get user data from Redux store
  const { userId, username, email, subscriptionActive } = useSelector((state) => state.user);
  
  // Generate display-friendly subscription data
  const [subData, setSubData] = useState({
    plan: 'Premium',
    price: '$9.99/month',
    startDate: new Date().toLocaleDateString(),
    nextBillingDate: (() => {
      const date = new Date();
      date.setMonth(date.getMonth() + 1);
      return date.toLocaleDateString();
    })(),
    paymentMethod: formatPaymentMethod(paymentMethod),
    platform: formatPlatform(platform)
  });
  
  // Format payment method for display
  function formatPaymentMethod(method) {
    if (!method) return 'Credit Card';
    
    const methodMap = {
      'cc': 'Credit Card',
      'credit_card': 'Credit Card',
      'paypal': 'PayPal',
      'apple': 'Apple Pay',
      'google': 'Google Pay',
      'stripe': 'Stripe'
    };
    
    return methodMap[method.toLowerCase()] || method;
  }
  
  // Format platform for display
  function formatPlatform(platform) {
    if (!platform) return 'Website';
    
    const platformMap = {
      'web': 'Website',
      'ios': 'iOS App'
      // Removed Android since you don't have an Android app
    };
    
    return platformMap[platform.toLowerCase()] || platform;
  }
  
  // Refresh user data to update subscription status
  useEffect(() => {
    if (userId) {
      dispatch(fetchUserData(userId));
    }
  }, [dispatch, userId]);
  
  // Keep checking for subscriptionActive if it's not set yet
  useEffect(() => {
    if (!subscriptionActive) {
      const checkSubscription = setInterval(() => {
        dispatch(fetchUserData(userId));
      }, 3000);
      
      return () => clearInterval(checkSubscription);
    }
  }, [dispatch, userId, subscriptionActive]);
  
  // Navigate to home or dashboard
  const handleGoHome = () => {
    navigate('/');
  };
  
  // Navigate to user profile
  const handleGoToProfile = () => {
    navigate('/profile');
  };
  
  return (
    <div className="subscription-success-container">
      {/* Animated glow effects */}
      <div className="glow-effect"></div>
      <div className="glow-effect"></div>
      <div className="glow-effect"></div>
      
      <div className="subscription-success-wrapper">
        <div className="subscription-success-header">
          <h1 className="subscription-success-title">
            <FaCheckCircle className="subscription-success-icon" />
            Subscription Activated!
          </h1>
        </div>
        
        <div className="subscription-success-content">
          <div className="subscription-success-message">
            <p>Thank you for subscribing to our Premium plan! Your account has been successfully upgraded, and you now have full access to all premium features and content.</p>
          </div>
          
          <div className="subscription-success-details">
            <div className="subscription-detail-row">
              <span className="subscription-detail-label">Plan:</span>
              <span className="subscription-detail-value">{subData.plan}</span>
            </div>
            
            <div className="subscription-detail-row">
              <span className="subscription-detail-label">Price:</span>
              <span className="subscription-detail-value">{subData.price}</span>
            </div>
            
            <div className="subscription-detail-row">
              <span className="subscription-detail-label">Start Date:</span>
              <span className="subscription-detail-value">{subData.startDate}</span>
            </div>
            
            <div className="subscription-detail-row">
              <span className="subscription-detail-label">Next Billing Date:</span>
              <span className="subscription-detail-value">{subData.nextBillingDate}</span>
            </div>
            
            <div className="subscription-detail-row">
              <span className="subscription-detail-label">Payment Method:</span>
              <span className="subscription-detail-value">{subData.paymentMethod}</span>
            </div>
            
            <div className="subscription-detail-row">
              <span className="subscription-detail-label">Platform:</span>
              <span className="subscription-detail-value">{subData.platform}</span>
            </div>
            
            {subscriptionId && (
              <div className="subscription-detail-row">
                <span className="subscription-detail-label">Subscription ID:</span>
                <span className="subscription-detail-value">{subscriptionId}</span>
              </div>
            )}
          </div>
          
          <div className="subscription-features">
            <div className="subscription-feature-card">
              <FaUnlockAlt className="subscription-feature-icon" />
              <h3 className="subscription-feature-title">Unlimited Access</h3>
              <p className="subscription-feature-description">Enjoy unlimited access to all premium content and features without restrictions.</p>
            </div>
            
            <div className="subscription-feature-card">
              <FaCoins className="subscription-feature-icon" />
              <h3 className="subscription-feature-title">Bonus Points</h3>
              <p className="subscription-feature-description">Earn 2x coins for all completed tests and activities.</p>
            </div>
            
            <div className="subscription-feature-card">
              <FaTrophy className="subscription-feature-icon" />
              <h3 className="subscription-feature-title">Special Achievements</h3>
              <p className="subscription-feature-description">Unlock exclusive premium achievements and rewards.</p>
            </div>
          </div>
          
          <div className="subscription-success-actions">
            <button onClick={handleGoToProfile} className="subscription-success-btn subscription-primary-btn">
              <FaUserShield />
              <span>Go to Profile</span>
            </button>
            
            <button onClick={handleGoHome} className="subscription-success-btn subscription-secondary-btn">
              <FaHome />
              <span>Back to Dashboard</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SubscriptionSuccess;
