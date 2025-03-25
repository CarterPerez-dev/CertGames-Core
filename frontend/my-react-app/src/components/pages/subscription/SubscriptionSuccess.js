// src/components/pages/subscription/SubscriptionSuccess.js
import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import axios from 'axios';
import { 
  FaCheckCircle, 
  FaSpinner, 
  FaTimesCircle, 
  FaTrophy, 
  FaSignInAlt,
  FaUser
} from 'react-icons/fa';
import './SubscriptionSuccess.css';

const SubscriptionSuccess = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [isNewUser, setIsNewUser] = useState(false);
  const [isOauthFlow, setIsOauthFlow] = useState(false);
  
  const location = useLocation();
  const navigate = useNavigate();
  const dispatch = useDispatch();
  
  // Get session ID and user ID from URL parameters
  const searchParams = new URLSearchParams(location.search);
  const sessionId = searchParams.get('session_id');
  const userId = searchParams.get('user_id');
  
  useEffect(() => {
    const verifySession = async () => {
      if (!sessionId) {
        setError('Missing session information');
        setLoading(false);
        return;
      }
      
      try {
        // Verify the checkout session status
        const response = await axios.get(`/api/subscription/session-status?sessionId=${sessionId}`);
        
        if (response.data.status === 'complete' || response.data.paymentStatus === 'paid') {
          // Payment was successful
          
          // Determine if this is a new user registration or an existing user
          if (userId === 'new') {
            setIsNewUser(true);
            
            // Check if this is an OAuth flow
            // We'll use a flag from the session to determine this
            try {
              const checkOauth = await axios.get('/api/subscription/check-flow');
              setIsOauthFlow(checkOauth.data.isOauthFlow || false);
            } catch (err) {
              console.error('Error checking OAuth flow:', err);
              // Default to standard flow if we can't determine
              setIsOauthFlow(false);
            }
          }
          
          setLoading(false);
        } else {
          // Payment is still processing or failed
          setError('Your payment is still processing or could not be completed. Please check your payment details.');
          setLoading(false);
        }
      } catch (err) {
        console.error('Error verifying checkout session:', err);
        setError('Error verifying your subscription. Please contact support if your subscription is not active.');
        setLoading(false);
      }
    };
    
    verifySession();
  }, [sessionId, userId]);
  
  // Handle the next steps based on user status
  const handleContinue = () => {
    if (isNewUser) {
      if (isOauthFlow) {
        // OAuth flow - needs to create username
        navigate('/create-username');
      } else {
        // Regular flow - proceed to login
        navigate('/login', { 
          state: { 
            message: 'Your account has been created! Please sign in with your credentials.'
          }
        });
      }
    } else {
      // Existing user - proceed to profile
      navigate('/profile', {
        state: {
          message: 'Your subscription has been activated successfully!'
        }
      });
    }
  };
  
  return (
    <div className="subscription-success-container">
      <div className="subscription-success-background">
        <div className="subscription-success-grid"></div>
        <div className="subscription-success-glow"></div>
      </div>
      
      <div className="subscription-success-content">
        <div className="subscription-success-card">
          {loading ? (
            <div className="subscription-success-loading">
              <FaSpinner className="subscription-success-spinner" />
              <h2>Verifying your subscription...</h2>
              <p>Please wait while we complete your registration.</p>
            </div>
          ) : error ? (
            <div className="subscription-success-error">
              <FaTimesCircle className="subscription-success-error-icon" />
              <h2>Subscription Error</h2>
              <p>{error}</p>
              <div className="subscription-success-actions">
                <Link to="/subscription" className="subscription-success-button subscription-success-try-again">
                  Try Again
                </Link>
                <Link to="/contact" className="subscription-success-contact-link">
                  Contact Support
                </Link>
              </div>
            </div>
          ) : (
            <div className="subscription-success-confirmed">
              <div className="subscription-success-icon-container">
                <FaCheckCircle className="subscription-success-check-icon" />
                <FaTrophy className="subscription-success-trophy-icon" />
              </div>
              
              <h1 className="subscription-success-title">Subscription Successful!</h1>
              <p className="subscription-success-message">
                Thank you for subscribing to CertGames Premium! Your account is now activated with full access to all premium features.
              </p>
              
              <div className="subscription-success-info">
                <h3>What's Next?</h3>
                <p>
                  {isNewUser 
                    ? isOauthFlow
                      ? "You'll need to set up your username to complete your account setup."
                      : "You can now sign in to your new account using the credentials you provided during registration."
                    : "You can now access all premium features in your account."
                  }
                </p>
              </div>
              
              <button
                className="subscription-success-button"
                onClick={handleContinue}
              >
                {isNewUser 
                  ? isOauthFlow
                    ? <><FaUser /> Complete Account Setup</>
                    : <><FaSignInAlt /> Sign In to Your Account</>
                  : <><FaTrophy /> Continue to Your Account</>
                }
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SubscriptionSuccess;
