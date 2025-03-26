// src/components/pages/subscription/SubscriptionCancel.js
import React, { useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { 
  FaTimesCircle, 
  FaArrowLeft, 
  FaHome,
  FaSignInAlt,
  FaCreditCard,
  FaInfoCircle,
  FaQuestionCircle,
  FaShieldAlt
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
    <div className="cancel-container">
      <div className="cancel-background">
        <div className="cancel-grid"></div>
        <div className="cancel-particles">
          {Array.from({ length: 20 }).map((_, i) => (
            <div key={i} className="cancel-particle"></div>
          ))}
        </div>
        <div className="cancel-glow"></div>
      </div>
      
      <div className="cancel-content">
        <div className="cancel-card">
          <div className="cancel-card-accent"></div>
          
          <div className="cancel-header">
            <div className="cancel-logo">
              <FaTimesCircle className="cancel-logo-icon" />
              <div className="cancel-logo-pulse"></div>
            </div>
            <h1 className="cancel-title">Subscription Cancelled</h1>
            <p className="cancel-subtitle">
              Your subscription process was cancelled. No charges have been made to your account.
            </p>
          </div>
          
          <div className="cancel-info-box">
            <FaInfoCircle className="cancel-info-icon" />
            <div>
              <h3>What would you like to do next?</h3>
              <p>You can try again or return to where you were.</p>
            </div>
          </div>
          
          <div className="cancel-actions">
            <Link 
              to={isNewUser ? "/register" : "/subscription"} 
              className="cancel-button cancel-button-primary"
            >
              <span className="cancel-button-text">
                <FaCreditCard className="cancel-button-icon" />
                <span>{isNewUser ? "Back to Registration" : "Try Subscribing Again"}</span>
              </span>
            </Link>
            
            {isNewUser ? (
              <Link 
                to="/login" 
                className="cancel-button cancel-button-secondary"
              >
                <span className="cancel-button-text">
                  <FaSignInAlt className="cancel-button-icon" />
                  <span>Sign In Instead</span>
                </span>
              </Link>
            ) : (
              <Link 
                to="/" 
                className="cancel-button cancel-button-secondary"
              >
                <span className="cancel-button-text">
                  <FaHome className="cancel-button-icon" />
                  <span>Go to Home Page</span>
                </span>
              </Link>
            )}
          </div>
          
          <div className="cancel-help">
            <FaQuestionCircle className="cancel-help-icon" />
            <p>
              If you have any questions or need assistance, please don't hesitate to {' '}
              <Link to="/contact" className="cancel-contact-link">
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
