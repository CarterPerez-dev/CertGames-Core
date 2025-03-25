// src/components/pages/subscription/SubscriptionSuccess.js
import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { setCurrentUserId, fetchUserData } from '../store/userSlice';
import { FaCheckCircle, FaSpinner } from 'react-icons/fa';
import './SubscriptionPage.css';

const SubscriptionSuccess = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const [pendingRegistration, setPendingRegistration] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  useEffect(() => {
    // Extract session_id from URL
    const searchParams = new URLSearchParams(location.search);
    const sessionId = searchParams.get('session_id');
    
    // Retrieve pending registration data
    const regData = localStorage.getItem('pendingRegistration');
    if (regData) {
      setPendingRegistration(JSON.parse(regData));
    }
    
    if (sessionId) {
      // Verify the session with the backend
      fetch('/api/subscription/verify-session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId })
      })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          handleRegistrationCompletion(data.userId);
          setLoading(false);
        } else {
          setError(data.error || 'Failed to verify subscription');
          setLoading(false);
        }
      })
      .catch(err => {
        console.error('Error verifying session:', err);
        setError('An error occurred while verifying your subscription');
        setLoading(false);
      });
    } else {
      setLoading(false);
    }
  }, [location, dispatch, navigate]);
  
  const handleRegistrationCompletion = (userId) => {
    if (!pendingRegistration) return;
    
    // Save userId to localStorage
    localStorage.setItem('userId', userId);
    
    // Update Redux state
    dispatch(setCurrentUserId(userId));
    
    // Clean up pending registration
    localStorage.removeItem('pendingRegistration');
    
    // Determine where to navigate next
    if (pendingRegistration.registrationType === 'oauth' && pendingRegistration.needsUsername) {
      // OAuth user needs to set username (delayed navigation)
      setTimeout(() => {
        navigate('/create-username', { 
          state: { userId, provider: pendingRegistration.provider }
        });
      }, 3000);
    } else if (pendingRegistration.registrationType === 'standard') {
      // Standard user should log in (no auto-navigation, user clicks button)
    } else if (pendingRegistration.registrationType === 'renewal') {
      // User renewed subscription, go to profile
      dispatch(fetchUserData(userId))
        .then(() => {
          setTimeout(() => {
            navigate('/profile');
          }, 3000);
        });
    } else {
      // OAuth user with username already set
      dispatch(fetchUserData(userId))
        .then(() => {
          setTimeout(() => {
            navigate('/profile');
          }, 3000);
        });
    }
  };
  
  return (
    <div className="subscription-success-container">
      <div className="subscription-background">
        <div className="subscription-grid"></div>
        <div className="subscription-glow"></div>
      </div>
      
      <div className="subscription-success-content">
        <div className="subscription-success-card">
          {loading ? (
            <div className="subscription-loading">
              <FaSpinner className="subscription-spinner" />
              <p>Verifying your subscription...</p>
            </div>
          ) : error ? (
            <div className="subscription-error">
              <h2>Something went wrong</h2>
              <p>{error}</p>
              <button
                className="subscription-button"
                onClick={() => navigate('/subscription')}
              >
                Try Again
              </button>
            </div>
          ) : (
            <>
              <div className="subscription-success-icon">
                <FaCheckCircle />
              </div>
              <h1 className="subscription-success-title">Subscription Activated!</h1>
              <p className="subscription-success-message">
                Thank you for subscribing to CertGames Premium. Your account is now active.
              </p>
              
              {pendingRegistration?.registrationType === 'standard' && (
                <>
                  <p className="subscription-next-steps">
                    Please log in to access your premium features.
                  </p>
                  <button 
                    className="subscription-button"
                    onClick={() => navigate('/login', {
                      state: { message: 'Registration and subscription successful! Please log in.' }
                    })}
                  >
                    Log In Now
                  </button>
                </>
              )}
              
              {pendingRegistration?.registrationType === 'oauth' && pendingRegistration?.needsUsername && (
                <p className="subscription-next-steps">
                  Redirecting you to create your username...
                </p>
              )}
              
              {(pendingRegistration?.registrationType === 'renewal' || 
                (pendingRegistration?.registrationType === 'oauth' && !pendingRegistration?.needsUsername)) && (
                <p className="subscription-next-steps">
                  Redirecting to your profile...
                </p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default SubscriptionSuccess;
