// src/components/pages/Subscription/SubscriptionSuccess.js
import React, { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { fetchUserData } from '../store/userSlice';
import './SubscriptionPage.css';

const SubscriptionSuccess = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const dispatch = useDispatch();
  
  useEffect(() => {
    // Extract session_id from URL
    const searchParams = new URLSearchParams(location.search);
    const sessionId = searchParams.get('session_id');
    
    if (sessionId) {
      // Refresh user data to get updated subscription status
      dispatch(fetchUserData());
    }
  }, [location, dispatch]);
  
  return (
    <div className="subscription-success">
      <div className="success-icon">✓</div>
      <h1>Subscription Activated!</h1>
      <p>Your premium access is now active. Thank you for subscribing!</p>
      <button 
        className="navigate-button"
        onClick={() => navigate('/profile')}
      >
        Go to My Profile
      </button>
    </div>
  );
};

export default SubscriptionSuccess;
