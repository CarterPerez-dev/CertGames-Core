// src/components/pages/auth/OAuthSuccess.js
import React, { useEffect, useState } from 'react';
import { useDispatch } from 'react-redux';
import { useNavigate, useLocation } from 'react-router-dom';
import { setCurrentUserId } from '../store/userSlice';
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
    const needsUsername = searchParams.get('needsUsername') === 'true';
    
    if (!userId) {
      setError('Authentication failed. Please try again.');
      setLoading(false);
      return;
    }
    
    // Store OAuth data in localStorage for subscription flow
    localStorage.setItem('pendingRegistration', JSON.stringify({
      userId,
      provider,
      needsUsername,
      registrationType: 'oauth'
    }));
    
    // Redirect to subscription page instead of logging in directly
    navigate('/subscription');
    
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
