// src/components/auth/Register.js
import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, Link } from 'react-router-dom';
import { registerUser } from '../store/userSlice';
import {
  FaUser,
  FaLock,
  FaGoogle,
  FaApple,
  FaEnvelope,
  FaChevronRight,
  FaEye,
  FaEyeSlash,
  FaExclamationCircle,
  FaUserSecret,
  FaCheck,
  FaInfoCircle
} from 'react-icons/fa';
import PasswordRequirements from './PasswordRequirements';
import './Register.css';

const Register = () => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [agreeTerms, setAgreeTerms] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [formError, setFormError] = useState('');
  const [showPasswordRequirements, setShowPasswordRequirements] = useState(false);
  
  const dispatch = useDispatch();
  const navigate = useNavigate();
  
  const { loading, error, userId } = useSelector((state) => state.user);
  
  useEffect(() => {
    // If already logged in, redirect to profile
    if (userId) {
      navigate('/profile');
    }
  }, [userId, navigate]);
  
  const validateForm = () => {
    // Check if all fields are filled
    if (!username || !email || !password || !confirmPassword) {
      setFormError('All fields are required');
      return false;
    }
    
    // Check if passwords match
    if (password !== confirmPassword) {
      setFormError('Passwords do not match');
      return false;
    }
    
    // Check if terms are agreed to
    if (!agreeTerms) {
      setFormError('You must agree to the Terms and Conditions');
      return false;
    }
    
    return true;
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError('');
    
    if (!validateForm()) {
      return;
    }
    
    try {
      const resultAction = await dispatch(registerUser({
        username,
        email,
        password,
        confirmPassword: confirmPassword
      }));
      
      if (registerUser.fulfilled.match(resultAction)) {
        // Registration successful, now login
        navigate('/login', { state: { message: 'Registration successful! Please log in.' } });
      } else {
        // Handle error from the action
        setFormError(resultAction.payload || 'Registration failed. Please try again.');
      }
    } catch (err) {
      setFormError('An error occurred. Please try again.');
    }
  };
  
  const handleSocialSignUp = (provider) => {
    setFormError('');
    // This would be implemented with actual OAuth providers
    setFormError(`${provider} registration will be implemented soon`);
  };
  
  return (
    <div className="register-container">
      <div className="register-background">
        <div className="register-grid"></div>
        <div className="register-glow"></div>
      </div>
      
      <div className="register-content">
        <div className="register-card">
          <div className="register-header">
            <div className="register-logo">
              <FaUserSecret className="register-logo-icon" />
            </div>
            <h1 className="register-title">Create Account</h1>
            <p className="register-subtitle">Join and start your learning journey</p>
          </div>
          
          {(formError || error) && (
            <div className="register-error-message">
              <FaExclamationCircle />
              <span>{formError || error}</span>
            </div>
          )}
          
          <form className="register-form" onSubmit={handleSubmit}>
            <div className="register-input-group">
              <label htmlFor="username">Username</label>
              <div className="register-input-wrapper">
                <FaUser className="register-input-icon" />
                <input
                  type="text"
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Choose a unique username"
                  disabled={loading}
                />
              </div>
              <div className="register-input-hint">
                <FaInfoCircle className="register-hint-icon" />
                <span>3-30 characters, letters, numbers, dots, underscores, dashes</span>
              </div>
            </div>
            
            <div className="register-input-group">
              <label htmlFor="email">Email Address</label>
              <div className="register-input-wrapper">
                <FaEnvelope className="register-input-icon" />
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email address"
                  disabled={loading}
                />
              </div>
            </div>
            
            <div className="register-input-group">
              <label htmlFor="password">Password</label>
              <div className="register-input-wrapper">
                <FaLock className="register-input-icon" />
                <input
                  type={showPassword ? "text" : "password"}
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onFocus={() => setShowPasswordRequirements(true)}
                  placeholder="Create a strong password"
                  disabled={loading}
                />
                <button
                  type="button"
                  className="register-toggle-password"
                  onClick={() => setShowPassword(!showPassword)}
                  tabIndex="-1"
                >
                  {showPassword ? <FaEyeSlash /> : <FaEye />}
                </button>
              </div>
              
              {showPasswordRequirements && (
                <div className="register-password-requirements">
                  <PasswordRequirements password={password} />
                </div>
              )}
            </div>
            
            <div className="register-input-group">
              <label htmlFor="confirmPassword">Confirm Password</label>
              <div className="register-input-wrapper">
                <FaLock className="register-input-icon" />
                <input
                  type={showConfirmPassword ? "text" : "password"}
                  id="confirmPassword"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm your password"
                  disabled={loading}
                />
                <button
                  type="button"
                  className="register-toggle-password"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  tabIndex="-1"
                >
                  {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
                </button>
              </div>
              
              {password && confirmPassword && (
                <div className={`register-password-match ${password === confirmPassword ? 'match' : 'no-match'}`}>
                  {password === confirmPassword ? (
                    <>
                      <FaCheck className="register-match-icon" />
                      <span>Passwords match</span>
                    </>
                  ) : (
                    <>
                      <FaExclamationCircle className="register-match-icon" />
                      <span>Passwords don't match</span>
                    </>
                  )}
                </div>
              )}
            </div>
            
            <div className="register-terms">
              <input
                type="checkbox"
                id="agreeTerms"
                checked={agreeTerms}
                onChange={(e) => setAgreeTerms(e.target.checked)}
                disabled={loading}
              />
              <label htmlFor="agreeTerms">
                I agree to the <a href="/terms" target="_blank">Terms and Conditions</a>
              </label>
            </div>
            
            <button
              type="submit"
              className="register-button"
              disabled={loading}
            >
              {loading ? (
                <span className="register-button-loading">
                  <span className="register-spinner"></span>
                  Creating Account...
                </span>
              ) : (
                <span className="register-button-text">
                  Create Account
                  <FaChevronRight className="register-button-icon" />
                </span>
              )}
            </button>
          </form>
          
          <div className="register-separator">
            <span>or sign up with</span>
          </div>
          
          <div className="register-social-buttons">
            <button
              type="button"
              className="register-social-button register-google"
              onClick={() => handleSocialSignUp('Google')}
              disabled={loading}
            >
              <FaGoogle />
              <span>Google</span>
            </button>
            
            <button
              type="button"
              className="register-social-button register-apple"
              onClick={() => handleSocialSignUp('Apple')}
              disabled={loading}
            >
              <FaApple />
              <span>Apple</span>
            </button>
          </div>
          
          <div className="register-login-link">
            <span>Already have an account?</span>
            <Link to="/login">Sign In</Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;
