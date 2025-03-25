// src/components/pages/subscription/SubscriptionSuccess.js
import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { setCurrentUserId, fetchUserData } from '../store/userSlice';
import { FaCheckCircle, FaSpinner, FaExclamationCircle } from 'react-icons/fa';
import axios from 'axios';
import './SubscriptionPage.css';

const SubscriptionSuccess = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [pendingRegistration, setPendingRegistration] = useState(null);
  
  useEffect(() => {
    // Extract session_id from URL
    const searchParams = new URLSearchParams(location.search);
    const sessionId = searchParams.get('session_id');
    
    // Retrieve pending registration data
    const regData = localStorage.getItem('pendingRegistration');
    if (regData) {
      try {
        setPendingRegistration(JSON.parse(regData));
      } catch (e) {
        console.error('Failed to parse pendingRegistration:', e);
      }
    }
    
    if (sessionId) {
      console.log('Session ID received:', sessionId); // Debug log
      
      // Verify the session with the backend
      axios.post('/api/subscription/verify-session', { sessionId })
        .then(response => {
          console.log('Verification response:', response.data); // Debug log
          
          if (response.data.success) {
            const userId = response.data.userId;
            const needsUsername = response.data.needsUsername;
            
            // Save userId to localStorage
            localStorage.setItem('userId', userId);
            
            // Update Redux store
            dispatch(setCurrentUserId(userId));
            
            // Fetch the user data
            dispatch(fetchUserData(userId));
            
            // Clean up the pending registration data
            localStorage.removeItem('pendingRegistration');
            
            setLoading(false);
            
            // Determine where to navigate based on registration type
            if (pendingRegistration) {
              if (pendingRegistration.registrationType === 'oauth' && needsUsername) {
                // Delay before redirecting to username creation
                setTimeout(() => {
                  navigate('/create-username', { 
                    state: { userId, provider: pendingRegistration.provider }
                  });
                }, 3000);
              } else if (pendingRegistration.registrationType === 'renewal') {
                // User renewed subscription, go to profile
                setTimeout(() => {
                  navigate('/profile');
                }, 3000);
              } else {
                // For standard registration, we'll stay on the success page with a login button
              }
            }
          } else {
            setError(response.data.error || 'Failed to verify subscription');
            setLoading(false);
          }
        })
        .catch(err => {
          console.error('Error verifying session:', err);
          setError('An error occurred while verifying your subscription. Please contact support if the issue persists.');
          setLoading(false);
        });
    } else {
      setError('No session ID found in the URL');
      setLoading(false);
    }
  }, [location, dispatch, navigate, pendingRegistration]);
  
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
              <FaExclamationCircle className="subscription-error-icon" />
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
