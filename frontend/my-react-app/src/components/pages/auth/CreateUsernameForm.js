// src/components/auth/CreateUsernameForm.js
import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, useLocation } from 'react-router-dom';
import { fetchUserData } from '../store/userSlice';
import { FaUser, FaCheck, FaTimes, FaShieldAlt, FaInfoCircle, FaExclamationCircle } from 'react-icons/fa';
import './CreateUsernameForm.css';

const CreateUsernameForm = () => {
  const [username, setUsername] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [submitted, setSubmitted] = useState(false);
  
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  
  // Get userId and provider from URL params
  const searchParams = new URLSearchParams(location.search);
  const userId = searchParams.get('userId');
  const provider = searchParams.get('provider');
  
  useEffect(() => {
    if (!userId) {
      navigate('/login');
    }
  }, [userId, navigate]);
  
  const validateUsername = (username) => {
    // Basic frontend validation
    if (!username || username.length < 3) {
      return "Username must be at least 3 characters long";
    }
    
    if (username.length > 30) {
      return "Username must be no more than 30 characters long";
    }
    
    // Letters, numbers, underscores, dots, and dashes only
    if (!/^[A-Za-z0-9._-]+$/.test(username)) {
      return "Username can only contain letters, numbers, dots, underscores, and dashes";
    }
    
    // No leading/trailing dots, underscores, or dashes
    if (/^[._-]|[._-]$/.test(username)) {
      return "Username cannot start or end with dots, underscores, or dashes";
    }
    
    // No triple repeats
    if (/(.)\1{2,}/.test(username)) {
      return "Username cannot contain three identical consecutive characters";
    }
    
    return null; // No errors
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Validate username
    const validationError = validateUsername(username);
    if (validationError) {
      setError(validationError);
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      // Update username via API
      const response = await fetch('/api/test/user/change-username', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId: userId,
          newUsername: username,
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to set username');
      }
      
      // Success! Mark as submitted
      setSubmitted(true);
      
      // Fetch the updated user data
      await dispatch(fetchUserData(userId));
      
      // Navigate to profile page after a brief delay (to show success message)
      setTimeout(() => {
        navigate('/profile', {
          state: {
            message: `Welcome! You've successfully created your account with ${
              provider.charAt(0).toUpperCase() + provider.slice(1)
            }`
          }
        });
      }, 1500);
    } catch (err) {
      console.error('Error setting username:', err);
      setError(err.message || 'Failed to set username. Please try again.');
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="create-username-container">
      <div className="create-username-background">
        <div className="create-username-grid"></div>
        <div className="create-username-glow"></div>
      </div>
      
      <div className="create-username-content">
        <div className="create-username-card">
          <div className="create-username-header">
            <div className="create-username-logo">
              <FaShieldAlt className="create-username-logo-icon" />
            </div>
            <h1 className="create-username-title">Create Your Username</h1>
            <p className="create-username-subtitle">
              Choose a unique username for your account
            </p>
          </div>
          
          {error && (
            <div className="create-username-error">
              <FaExclamationCircle />
              <span>{error}</span>
            </div>
          )}
          
          {submitted ? (
            <div className="create-username-success">
              <FaCheck />
              <h3>Username Set Successfully!</h3>
              <p>Redirecting you to your profile...</p>
              <div className="create-username-spinner"></div>
            </div>
          ) : (
            <form className="create-username-form" onSubmit={handleSubmit}>
              <div className="create-username-input-group">
                <label htmlFor="username">Username</label>
                <div className="create-username-input-wrapper">
                  <FaUser className="create-username-input-icon" />
                  <input
                    type="text"
                    id="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Choose a unique username"
                    disabled={loading}
                    required
                  />
                </div>
                <div className="create-username-input-hint">
                  <FaInfoCircle className="create-username-hint-icon" />
                  <span>3-30 characters, letters, numbers, dots, underscores, dashes</span>
                </div>
              </div>
              
              <button
                type="submit"
                className="create-username-button"
                disabled={loading}
              >
                {loading ? (
                  <span className="create-username-button-loading">
                    <span className="create-username-spinner"></span>
                    Setting Username...
                  </span>
                ) : (
                  <span className="create-username-button-text">
                    Set Username & Continue
                  </span>
                )}
              </button>
              
              <p className="create-username-note">
                <FaInfoCircle />
                <span>You can always change your username later from your profile settings</span>
              </p>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

export default CreateUsernameForm;
