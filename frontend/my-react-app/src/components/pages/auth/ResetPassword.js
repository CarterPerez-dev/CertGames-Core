import React, { useState, useEffect } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import {
  FaLock,
  FaChevronRight,
  FaArrowLeft,
  FaKey,
  FaCheckCircle,
  FaExclamationCircle,
  FaEye,
  FaEyeSlash
} from 'react-icons/fa';
import PasswordRequirements from './PasswordRequirements';
import './css/ResetPassword.css';

const ResetPassword = () => {
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [showRequirements, setShowRequirements] = useState(false);
  const [tokenValid, setTokenValid] = useState(null);
  const [loading, setLoading] = useState(false);
  const [verifyLoading, setVerifyLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  
  const navigate = useNavigate();
  const { token } = useParams();
  
  // Debug logging
  console.log("Component rendered with token:", token);
  
  // Verify token on component mount
  useEffect(() => {
    const verifyToken = async () => {
      if (!token) {
        console.log("No token provided");
        setTokenValid(false);
        setError('No reset token provided');
        setVerifyLoading(false);
        return;
      }
      
      console.log("Verifying token:", token);
      setVerifyLoading(true);
      
      try {
        const response = await fetch(`/api/password-reset/verify-token/${token}`);
        console.log("Verification response status:", response.status);
        
        // For debugging, let's see the raw response first
        const responseText = await response.text();
        console.log("Raw verification response:", responseText);
        
        let data;
        try {
          data = JSON.parse(responseText);
          console.log("Parsed verification data:", data);
        } catch (parseError) {
          console.error("Failed to parse response:", parseError);
          setTokenValid(false);
          setError('Invalid server response');
          setVerifyLoading(false);
          return;
        }
        
        if (response.ok && data.valid) {
          console.log("Token is valid!");
          setTokenValid(true);
        } else {
          console.log("Token is invalid:", data.error);
          setTokenValid(false);
          setError(data.error || 'Invalid or expired token');
        }
      } catch (err) {
        console.error('Error verifying token:', err);
        setTokenValid(false);
        setError('Failed to verify reset token. Please try again.');
      } finally {
        console.log("Setting verifyLoading to false");
        setVerifyLoading(false);
      }
    };
    
    verifyToken();
  }, [token]);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    // Basic validation
    if (!newPassword || !confirmPassword) {
      setError('Both fields are required');
      return;
    }
    
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    
    setLoading(true);
    
    try {
      console.log("Submitting new password...");
      const response = await fetch('/api/password-reset/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token,
          newPassword,
          confirmPassword
        }),
      });
      
      // For debugging, let's see the raw response
      const responseText = await response.text();
      console.log("Raw password reset response:", responseText);
      
      let data;
      try {
        data = JSON.parse(responseText);
      } catch (parseError) {
        console.error("Failed to parse reset response:", parseError);
        throw new Error("Invalid server response");
      }
      
      if (!response.ok) {
        let errorMsg = data.error || 'Failed to reset password';
        if (data.details && data.details.length > 0) {
          errorMsg += ': ' + data.details.join(', ');
        }
        throw new Error(errorMsg);
      }
      
      console.log("Password reset successful!");
      setSuccess(true);
      
      // Redirect to login page after showing success message
      setTimeout(() => {
        navigate('/login');
      }, 5000);
    } catch (err) {
      console.error("Password reset error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };
  
  console.log("Current state:", { 
    tokenValid, 
    verifyLoading, 
    loading, 
    success, 
    error 
  });
  
  // Show loading state while verifying token
  if (verifyLoading) {
    return (
      <div className="reset-container">
        <div className="reset-background">
          <div className="reset-grid"></div>
          <div className="reset-glow"></div>
        </div>
        
        <div className="reset-content">
          <div className="reset-card">
            <div className="reset-loading">
              <div className="reset-spinner"></div>
              <p>Verifying reset token...</p>
            </div>
          </div>
        </div>
      </div>
    );
  }
  
  return (
    <div className="reset-container">
      <div className="reset-background">
        <div className="reset-grid"></div>
        <div className="reset-glow"></div>
      </div>
      
      <div className="reset-content">
        <div className="reset-card">
          {/* Back button */}
          <Link to="/login" className="reset-back-button">
            <FaArrowLeft />
            <span>Back to Login</span>
          </Link>
          
          <div className="reset-header">
            <div className="reset-logo">
              <FaKey className="reset-logo-icon" />
            </div>
            <h1 className="reset-title">Reset Your Password</h1>
            <p className="reset-subtitle">
              Create a new, strong password for your account
            </p>
          </div>
          
          {!tokenValid ? (
            <div className="reset-error-state">
              <FaExclamationCircle className="reset-error-icon" />
              <h3>Invalid or Expired Link</h3>
              <p>
                This password reset link is invalid or has expired. 
                Please request a new password reset link.
              </p>
              <Link to="/forgot-password" className="reset-request-new-link">
                Request New Reset Link
              </Link>
            </div>
          ) : success ? (
            <div className="reset-success-message">
              <FaCheckCircle className="reset-success-icon" />
              <h3>Password Reset Successfully!</h3>
              <p>
                Your password has been updated. You can now log in with your new password.
              </p>
              <p className="reset-redirect-notice">
                Redirecting to login page in a few seconds...
              </p>
            </div>
          ) : (
            <>
              {error && (
                <div className="reset-error-message">
                  <FaExclamationCircle />
                  <span>{error}</span>
                </div>
              )}
              
              <form className="reset-form" onSubmit={handleSubmit}>
                <div className="reset-input-group">
                  <label htmlFor="newPassword">New Password</label>
                  <div className="reset-input-wrapper">
                    <FaLock className="reset-input-icon" />
                    <input
                      type={showNewPassword ? "text" : "password"}
                      id="newPassword"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="Enter your new password"
                      onFocus={() => setShowRequirements(true)}
                      disabled={loading}
                    />
                    <button
                      type="button"
                      className="reset-toggle-password"
                      onClick={() => setShowNewPassword(!showNewPassword)}
                      tabIndex="-1"
                    >
                      {showNewPassword ? <FaEyeSlash /> : <FaEye />}
                    </button>
                  </div>
                  
                  {showRequirements && (
                    <div className="reset-password-requirements">
                      <PasswordRequirements password={newPassword} />
                    </div>
                  )}
                </div>
                
                <div className="reset-input-group">
                  <label htmlFor="confirmPassword">Confirm Password</label>
                  <div className="reset-input-wrapper">
                    <FaLock className="reset-input-icon" />
                    <input
                      type={showConfirmPassword ? "text" : "password"}
                      id="confirmPassword"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Confirm your new password"
                      disabled={loading}
                    />
                    <button
                      type="button"
                      className="reset-toggle-password"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      tabIndex="-1"
                    >
                      {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
                    </button>
                  </div>
                  
                  {newPassword && confirmPassword && (
                    <div className={`reset-password-match ${newPassword === confirmPassword ? 'match' : 'no-match'}`}>
                      {newPassword === confirmPassword ? (
                        <>
                          <FaCheckCircle className="reset-match-icon" />
                          <span>Passwords match</span>
                        </>
                      ) : (
                        <>
                          <FaExclamationCircle className="reset-match-icon" />
                          <span>Passwords don't match</span>
                        </>
                      )}
                    </div>
                  )}
                </div>
                
                <button
                  type="submit"
                  className="reset-button"
                  disabled={loading}
                >
                  {loading ? (
                    <span className="reset-button-loading">
                      <span className="reset-spinner"></span>
                      Resetting Password...
                    </span>
                  ) : (
                    <span className="reset-button-text">
                      Reset Password
                      <FaChevronRight className="reset-button-icon" />
                    </span>
                  )}
                </button>
              </form>
            </>
          )}
          
          <div className="reset-links">
            <span>Remember your password?</span>
            <Link to="/login">Sign In</Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResetPassword;
