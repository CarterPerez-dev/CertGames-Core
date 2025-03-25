// src/components/pages/subscription/SubscriptionSuccess.js
import React, { useEffect, useState, useRef } from 'react';
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
  const verificationAttempted = useRef(false);
  
  useEffect(() => {
    // Prevent multiple verification attempts
    if (verificationAttempted.current) {
      return;
    }
    
    // Mark that we've attempted verification
    verificationAttempted.current = true;
    
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
    
    if (!sessionId) {
      setError('No session ID found in the URL');
      setLoading(false);
      return;
    }
    
    console.log('Verifying session:', sessionId);
    
    // Verify the session with the backend - use setTimeout to prevent race conditions
    setTimeout(() => {
      axios.post('/api/subscription/verify-session', { sessionId })
        .then(response => {
          console.log('Verification response:', response.data);
          
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
            localStorage.removeItem('tempUserId');
            
            setLoading(false);
            
            // Determine where to navigate based on registration type
            if (regData) {
              const regDataObj = JSON.parse(regData);
              
              // For OAuth registrations that need username
              if (regDataObj.registrationType === 'oauth' && needsUsername) {
                setTimeout(() => {
                  navigate('/create-username', { 
                    state: { userId, provider: regDataObj.provider }
                  });
                }, 2000);
              } 
              // For subscription renewals
              else if (regDataObj.registrationType === 'renewal') {
                setTimeout(() => {
                  navigate('/profile');
                }, 2000);
              }
              // For standard registrations, stay on success page (user will click login)
            }
          } else {
            setError(response.data.error || 'Failed to verify subscription');
            setLoading(false);
          }
        })
        .catch(err => {
          console.error('Error verifying session:', err);
          setError('Error connecting to the server. Please try refreshing the page or contact support.');
          setLoading(false);
        });
    }, 1500);
    
  }, [location.search, dispatch, navigate]);
  
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
              
              {pendingRegistration?.registrationType === 'renewal' && (
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
