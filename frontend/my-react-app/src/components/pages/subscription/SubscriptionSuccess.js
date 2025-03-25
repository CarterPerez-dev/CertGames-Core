// src/components/pages/subscription/SubscriptionSuccess.js
import React, { useState, useEffect, useRef } from 'react';
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
  
  // Use a ref to ensure the verification only happens ONCE per component lifecycle
  const verificationStarted = useRef(false);
  
  useEffect(() => {
    // THE ROOT PROBLEM FIX: Prevent verification from happening multiple times
    // by using a ref that persists between renders
    if (verificationStarted.current) {
      console.log('Verification already started, skipping');
      return;
    }
    
    // Parse the query parameter once
    const params = new URLSearchParams(location.search);
    const sessionId = params.get('session_id');
    
    if (!sessionId) {
      setError('No session ID found in the URL');
      setLoading(false);
      return;
    }
    
    // Mark verification as started
    verificationStarted.current = true;
    
    // Get registration data
    try {
      const regData = localStorage.getItem('pendingRegistration');
      if (regData) {
        setPendingRegistration(JSON.parse(regData));
      }
    } catch (e) {
      console.error('Failed to parse registration data', e);
    }
    
    // Simple timeout to allow the state to update and prevent race conditions
    const timeoutId = setTimeout(() => {
      // ONE single request to verify the session
      console.log('Verifying session ID:', sessionId);
      
      axios.post('/api/subscription/verify-session', { sessionId })
        .then(response => {
          console.log('Verification response:', response.data);
          
          if (response.data.success) {
            const userId = response.data.userId;
            const needsUsername = response.data.needsUsername;
            
            // Update storage and state
            localStorage.setItem('userId', userId);
            localStorage.removeItem('pendingRegistration');
            localStorage.removeItem('tempUserId');
            
            // Update Redux
            dispatch(setCurrentUserId(userId));
            dispatch(fetchUserData(userId));
            
            setLoading(false);
            
            // Handle redirect based on registration type
            const regData = localStorage.getItem('pendingRegistration');
            if (regData) {
              try {
                const parsedData = JSON.parse(regData);
                
                if (parsedData.registrationType === 'oauth' && needsUsername) {
                  setTimeout(() => {
                    navigate('/create-username', { 
                      state: { userId, provider: parsedData.provider }
                    });
                  }, 1500);
                } else if (parsedData.registrationType === 'renewal') {
                  setTimeout(() => {
                    navigate('/profile');
                  }, 1500);
                }
              } catch (e) {
                console.error('Error parsing registration data', e);
              }
            }
          } else {
            setError(response.data.error || 'Failed to verify subscription');
            setLoading(false);
          }
        })
        .catch(err => {
          console.error('Error verifying session:', err);
          if (err.response && err.response.data) {
            console.error('Error details:', err.response.data);
          }
          setError('Error connecting to the server. Please try again later.');
          setLoading(false);
        });
    }, 1000);
    
    return () => clearTimeout(timeoutId);
  }, []); // Empty dependency array crucial for this fix
  
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
                onClick={() => {
                  // Reset verification status to allow retry
                  verificationStarted.current = false;
                  navigate('/subscription');
                }}
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
