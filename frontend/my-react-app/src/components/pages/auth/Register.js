// src/components/auth/Register.js
import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, Link } from 'react-router-dom';
import { registerUser, clearAuthErrors } from '../store/userSlice';
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
  FaShieldAlt,
  FaCheck,
  FaInfoCircle,
  FaTimes
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
  const [passwordValidation, setPasswordValidation] = useState({
    hasMinimumLength: false,
    hasUpperCase: false,
    hasLowerCase: false,
    hasNumber: false,
    hasSpecialChar: false
  });
  
  const dispatch = useDispatch();
  const navigate = useNavigate();
  
  const { loading, error, userId } = useSelector((state) => state.user);
  
  // Clear errors when component mounts or unmounts
  useEffect(() => {
    dispatch(clearAuthErrors());
    
    return () => {
      dispatch(clearAuthErrors());
    };
  }, [dispatch]);
  
  useEffect(() => {
    // If already logged in, redirect to profile
    if (userId) {
      navigate('/profile');
    }
  }, [userId, navigate]);
  
  // Update password validation whenever password changes
  useEffect(() => {
    setPasswordValidation({
      hasMinimumLength: password.length >= 6,
      hasUpperCase: /[A-Z]/.test(password),
      hasLowerCase: /[a-z]/.test(password),
      hasNumber: /[0-9]/.test(password),
      hasSpecialChar: /[!@#$%^&*()\-_=+[\]{}|;:'",<.>/?`~\\]/.test(password)
    });
  }, [password]);

  const passwordIsValid = () => {
    return Object.values(passwordValidation).every(val => val === true);
  };
  
  const validateForm = () => {
    // Check if all fields are filled
    if (!username || !email || !password || !confirmPassword) {
      setFormError('All fields are required');
      return false;
    }
    
    // Check if password meets requirements
    if (!passwordIsValid()) {
      setFormError('Password does not meet all requirements');
      setShowPasswordRequirements(true);
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
        const errorMessage = resultAction.payload || resultAction.error?.message;
        
        // Check for email already taken message
        if (errorMessage && (
            errorMessage.includes("Email is already taken") || 
            errorMessage.includes("Username or email is already taken") ||
            errorMessage.includes("already taken")
        )) {
          setFormError('Email address is already registered. Please use a different email or login.');
        } else {
          setFormError(errorMessage || 'Registration failed. Please try again.');
        }
      }
    } catch (err) {
      // Handle other errors
      if (err.message && (
          err.message.includes("Email is already taken") ||
          err.message.includes("Username or email is already taken") ||
          err.message.includes("already taken")
      )) {
        setFormError('Email address is already registered. Please use a different email or login.');
      } else {
        setFormError('An error occurred. Please try again.');
      }
    }
  };
  
  const handleSocialSignUp = (provider) => {
    setFormError('');
    
    // Show loading state
    setLoading(true);
    
    try {
      // Redirect to the backend OAuth route
      window.location.href = `/api/oauth/login/${provider.toLowerCase()}`;
    } catch (err) {
      setLoading(false);
      setFormError(`${provider} sign up failed. Please try again.`);
    }
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
              <FaShieldAlt className="register-logo-icon" />
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
                  onBlur={() => {
                    // Keep requirements visible if there's text or error
                    if (!password) {
                      setShowPasswordRequirements(false);
                    }
                  }}
                  placeholder="Create a strong password"
                  disabled={loading}
                  className={password && !passwordIsValid() ? "register-input-error" : ""}
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
                  <div className="register-requirements-header">
                    <h4>Password Requirements:</h4>
                    {passwordIsValid() ? (
                      <div className="register-requirements-status valid">
                        <FaCheck /> Valid
                      </div>
                    ) : (
                      <div className="register-requirements-status invalid">
                        <FaTimes /> Invalid
                      </div>
                    )}
                  </div>
                  <ul className="register-requirements-list">
                    <li className={passwordValidation.hasMinimumLength ? 'valid' : 'invalid'}>
                      {passwordValidation.hasMinimumLength ? 
                        <FaCheck className="icon-check" /> : 
                        <FaTimes className="icon-times" />}
                      <span>At least 6 characters long</span>
                    </li>
                    
                    <li className={passwordValidation.hasUpperCase ? 'valid' : 'invalid'}>
                      {passwordValidation.hasUpperCase ? 
                        <FaCheck className="icon-check" /> : 
                        <FaTimes className="icon-times" />}
                      <span>At least one uppercase letter</span>
                    </li>
                    
                    <li className={passwordValidation.hasLowerCase ? 'valid' : 'invalid'}>
                      {passwordValidation.hasLowerCase ? 
                        <FaCheck className="icon-check" /> : 
                        <FaTimes className="icon-times" />}
                      <span>At least one lowercase letter</span>
                    </li>
                    
                    <li className={passwordValidation.hasNumber ? 'valid' : 'invalid'}>
                      {passwordValidation.hasNumber ? 
                        <FaCheck className="icon-check" /> : 
                        <FaTimes className="icon-times" />}
                      <span>At least one number</span>
                    </li>
                    
                    <li className={passwordValidation.hasSpecialChar ? 'valid' : 'invalid'}>
                      {passwordValidation.hasSpecialChar ? 
                        <FaCheck className="icon-check" /> : 
                        <FaTimes className="icon-times" />}
                      <span>At least one special character</span>
                    </li>
                  </ul>
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
