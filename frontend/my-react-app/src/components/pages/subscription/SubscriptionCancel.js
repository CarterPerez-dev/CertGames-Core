// src/components/pages/subscription/SubscriptionCancel.js
import React, { useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { 
  FaTimesCircle, 
  FaArrowLeft, 
  FaHome,
  FaSignInAlt
} from 'react-icons/fa';
import './SubscriptionCancel.css';

const SubscriptionCancel = () => {
  const location = useLocation();
  const navigate = useNavigate();
  
  // Get user ID from URL parameters
  const searchParams = new URLSearchParams(location.search);
  const userId = searchParams.get('user_id');
  const isNewUser = userId === 'new';
  
  // Handle the redirect based on where the user came from
  useEffect(() => {
    // Reset any temporary session data
    // This is just a precaution to clear any lingering registration data
    const clearSessionData = async () => {
      try {
        await fetch('/api/subscription/clear-temp-data', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          }
        });
      } catch (err) {
        console.error('Error clearing session data:', err);
      }
    };
    
    clearSessionData();
  }, []);
  
  return (
    <div className="subscription-cancel-container">
      <div className="subscription-cancel-background">
        <div className="subscription-cancel-grid"></div>
        <div className="subscription-cancel-glow"></div>
      </div>
      
      <div className="subscription-cancel-content">
        <div className="subscription-cancel-card">
          <div className="subscription-cancel-icon-container">
            <FaTimesCircle className="subscription-cancel-icon" />
          </div>
          
          <h1 className="subscription-cancel-title">Subscription Cancelled</h1>
          <p className="subscription-cancel-message">
            Your subscription process was cancelled. No charges have been made to your account.
          </p>
          
          <div className="subscription-cancel-options">
            <h3>What would you like to do?</h3>
            
            <div className="subscription-cancel-buttons">
              <Link 
                to={isNewUser ? "/register" : "/subscription"} 
                className="subscription-cancel-button subscription-cancel-try-again"
              >
                <FaArrowLeft className="subscription-cancel-button-icon" />
                <span>{isNewUser ? "Back to Registration" : "Try Again"}</span>
              </Link>
              
              {isNewUser ? (
                <Link 
                  to="/login" 
                  className="subscription-cancel-button subscription-cancel-login"
                >
                  <FaSignInAlt className="subscription-cancel-button-icon" />
                  <span>Sign In Instead</span>
                </Link>
              ) : (
                <Link 
                  to="/" 
                  className="subscription-cancel-button subscription-cancel-home"
                >
                  <FaHome className="subscription-cancel-button-icon" />
                  <span>Go to Home Page</span>
                </Link>
              )}
            </div>
          </div>
          
          <div className="subscription-cancel-note">
            <p>
              If you have any questions or need assistance, please don't hesitate to {' '}
              <Link to="/contact" className="subscription-cancel-contact-link">
                contact our support team
              </Link>.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SubscriptionCancel;
