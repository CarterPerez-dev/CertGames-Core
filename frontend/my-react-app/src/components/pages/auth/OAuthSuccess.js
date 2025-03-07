// src/components/auth/OAuthSuccess.js
import React, { useEffect, useState } from 'react';
import { useDispatch } from 'react-redux';
import { useNavigate, useLocation } from 'react-router-dom';
import { setCurrentUserId, fetchUserData } from '../pages/store/userSlice';
import { FaShieldAlt } from 'react-icons/fa';
import './Login.css';

const OAuthSuccess = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState('');
  
  useEffect(() => {
    // Parse query parameters
    const searchParams = new URLSearchParams(location.search);
    const userId = searchParams.get('userId');
    const provider = searchParams.get('provider');
    
    if (!userId) {
      setError('Authentication failed. Please try again.');
      return;
    }
    
    // Handle successful login
    const handleSuccess = async () => {
      try {
        // Save userId to localStorage
        localStorage.setItem('userId', userId);
        
        // Update Redux state
        dispatch(setCurrentUserId(userId));
        
        // Fetch user data
        await dispatch(fetchUserData(userId)).unwrap();
        
        // Navigate to profile page
        navigate('/profile', { 
          state: { 
            message: `Successfully signed in with ${provider ? provider.charAt(0).toUpperCase() + provider.slice(1) : 'OAuth'}`
          }
        });
      } catch (err) {
        console.error('Error during OAuth completion:', err);
        setError('Failed to complete authentication. Please try again.');
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
