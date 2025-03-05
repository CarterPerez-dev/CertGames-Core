// src/components/auth/ForgotPassword.js
import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { 
  FaEnvelope, 
  FaChevronRight, 
  FaArrowLeft, 
  FaKey,
  FaCheckCircle,
  FaExclamationCircle
} from 'react-icons/fa';
import './ForgotPassword.css';

const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const navigate = useNavigate();
  
  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (!email) {
      setError('Please enter your email address.');
      return;
    }
    
    setLoading(true);
    
    // Simulate API call
    setTimeout(() => {
      setSent(true);
      setLoading(false);
      
      // Redirect after showing success message
      setTimeout(() => {
        navigate('/login');
      }, 5000);
    }, 1500);
  };
  
  return (
    <div className="forgot-container">
      <div className="forgot-background">
        <div className="forgot-grid"></div>
        <div className="forgot-glow"></div>
      </div>
      
      <div className="forgot-content">
        <div className="forgot-card">
          {/* Back button */}
          <Link to="/login" className="forgot-back-button">
            <FaArrowLeft />
            <span>Back to Login</span>
          </Link>
          
          <div className="forgot-header">
            <div className="forgot-logo">
              <FaKey className="forgot-logo-icon" />
            </div>
            <h1 className="forgot-title">Reset Password</h1>
            <p className="forgot-subtitle">
              Enter your email address to receive a password reset link
            </p>
          </div>
          
          {sent ? (
            <div className="forgot-success-message">
              <FaCheckCircle className="forgot-success-icon" />
              <h3>Reset Link Sent!</h3>
              <p>
                We've sent instructions to reset your password to <strong>{email}</strong>. 
                Please check your inbox and follow the link to complete the process.
              </p>
              <p className="forgot-redirect-notice">
                Redirecting to login page in a few seconds...
              </p>
            </div>
          ) : (
            <>
              {error && (
                <div className="forgot-error-message">
                  <FaExclamationCircle />
                  <span>{error}</span>
                </div>
              )}
              
              <form className="forgot-form" onSubmit={handleSubmit}>
                <div className="forgot-input-group">
                  <label htmlFor="email">Email Address</label>
                  <div className="forgot-input-wrapper">
                    <FaEnvelope className="forgot-input-icon" />
                    <input
                      type="email"
                      id="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="Enter your registered email"
                      disabled={loading}
                    />
                  </div>
                </div>
                
                <button
                  type="submit"
                  className="forgot-button"
                  disabled={loading}
                >
                  {loading ? (
                    <span className="forgot-button-loading">
                      <span className="forgot-spinner"></span>
                      Sending...
                    </span>
                  ) : (
                    <span className="forgot-button-text">
                      Send Reset Link
                      <FaChevronRight className="forgot-button-icon" />
                    </span>
                  )}
                </button>
              </form>
            </>
          )}
          
          <div className="forgot-links">
            <span>Remember your password?</span>
            <Link to="/login">Sign In</Link>
          </div>
          
          <div className="forgot-register-link">
            <span>Don't have an account?</span>
            <Link to="/register">Create Account</Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;
