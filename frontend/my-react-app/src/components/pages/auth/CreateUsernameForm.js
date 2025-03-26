// src/components/auth/OAuthSuccess.js
import React, { useEffect, useState } from 'react';
import { useDispatch } from 'react-redux';
import { useNavigate, useLocation } from 'react-router-dom';
import { setCurrentUserId, fetchUserData } from '../store/userSlice';
import { FaShieldAlt, FaSpinner } from 'react-icons/fa';
import './Login.css';

const OAuthSuccess = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    // Parse query parameters
    const searchParams = new URLSearchParams(location.search);
    const userId = searchParams.get('userId');
    const provider = searchParams.get('provider');
    
    if (!userId) {
      setError('Authentication failed. Please try again.');
      setLoading(false);
      return;
    }
    
    // Check if this is a new user registration flow
    const isOauthFlow = sessionStorage.getItem('isOauthFlow') === 'true';
    
    // Handle successful login
    const handleSuccess = async () => {
      try {
        // Save userId to localStorage regardless of flow
        localStorage.setItem('userId', userId);
        
        // Update Redux state
        dispatch(setCurrentUserId(userId));
        
        // For new registrations, check if needs_username is true
        await dispatch(fetchUserData(userId)).unwrap();
        
        // Get the current user state
        const userState = await dispatch(fetchUserData(userId)).unwrap();
        
        if (userState.needs_username) {
          // If user needs to set username, direct to username creation form
          navigate('/create-username', { 
            state: { 
              provider: provider || 'oauth'
            },
            search: `?userId=${userId}&provider=${provider || 'oauth'}`
          });
        } else if (!userState.subscriptionActive) {
          // If user doesn't have an active subscription, direct to subscription page
          navigate('/subscription', { 
            state: { 
              userId: userId,
              isOauthFlow: true 
            } 
          });
        } else {
          // For existing users with active subscription, proceed to profile
          navigate('/profile', { 
            state: { 
              message: `Successfully signed in with ${provider ? provider.charAt(0).toUpperCase() + provider.slice(1) : 'OAuth'}`
            }
          });
        }
      } catch (err) {
        console.error('Error during OAuth completion:', err);
        setError('Failed to complete authentication. Please try again.');
        setLoading(false);
      }
    };
    
    handleSuccess();
  }, [dispatch, navigate, location.search]);
  
  return (
    <div className="login-container">
      <div className="login-background">
        <div className="login-grid"></div>
        <div className="login-glow"></div>
      </div>
      
      <div className="login-content">
        <div className="login-card">
          <div className="login-header">
            <div className="login-logo">
              <FaShieldAlt className="login-logo-icon" />
            </div>
            <h1 className="login-title">Authentication</h1>
            <p className="login-subtitle">
              {error ? 'Authentication Error' : 'Completing your sign-in...'}
            </p>
          </div>
          
          <div className="oauth-loading-container">
            {error ? (
              <div className="oauth-error">
                <p>{error}</p>
                <button 
                  className="login-button"
                  onClick={() => navigate('/login')}
                >
                  Return to Login
                </button>
              </div>
            ) : (
              <div className="oauth-loading">
                <div className="oauth-spinner"></div>
                <p>Please wait while we complete your authentication...</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default OAuthSuccess;
