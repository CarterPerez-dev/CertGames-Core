// src/components/pages/subscription/SubscriptionPage.js
import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useSelector } from 'react-redux';
import axios from 'axios';
import {
  FaCheckCircle,
  FaTimesCircle,
  FaDragon,
  FaLock,
  FaCreditCard,
  FaInfoCircle,
  FaSpinner,
  FaArrowLeft,
  FaArrowRight,
  FaRedo,
  FaTrophy,
  FaMedal,
  FaGraduationCap,
  FaFighterJet,
  FaUserSecret,
  FaHome
} from 'react-icons/fa';
import './css/SubscriptionPage.css';

const SubscriptionPage = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [stripeConfig, setStripeConfig] = useState({});
  const [redirecting, setRedirecting] = useState(false);
  const [searchParams] = useSearchParams();
  const isRenewal = searchParams.get('renewal') === 'true';
  
  const location = useLocation();
  const navigate = useNavigate();
  const { userId } = useSelector((state) => state.user);
  
  // Check if there's registration data in the location state
  const registrationData = location.state?.registrationData;
  const isOauthFlow = location.state?.isOauthFlow || false;
  
  useEffect(() => {
    // Fetch Stripe configuration
    const fetchStripeConfig = async () => {
      try {
        const response = await axios.get('/api/subscription/config');
        setStripeConfig(response.data);
      } catch (err) {
        console.error('Error fetching Stripe configuration:', err);
        setError('Error loading payment configuration. Please try again.');
      }
    };
    
    fetchStripeConfig();
  }, []);
  
  const handleSubscribe = async () => {
    setLoading(true);
    setError('');
    
    try {
      // Create a Stripe checkout session
      const response = await axios.post('/api/subscription/create-checkout-session', {
        userId: userId || null,
        registrationData: registrationData || null,
        isOauthFlow: isOauthFlow
      });
      
      // Set redirecting state to show feedback
      setRedirecting(true);
      
      // Redirect to Stripe Checkout page
      window.location.href = response.data.url;
    } catch (err) {
      console.error('Error creating checkout session:', err);
      setError('Please navigate to certgames.com/register and create an account before attempting to susbcribe.');
      setLoading(false);
    }
  };
  
  const handleGoBack = () => {
    if (registrationData) {
      // Go back to registration
      navigate('/register');
    } else if (userId) {
      // Go back to profile for existing users
      navigate('/profile');
    } else {
      // Default fallback
      navigate('/');
    }
  };
  
  // New function to handle escaping the subscription flow
  const handleEscapeRenewal = () => {
    // Set the escape flag in session storage
    sessionStorage.setItem('escapeSubscriptionRenewal', 'true');
    // Navigate to home page
    navigate('/home');
  };
  
  // Benefits array for display
  const benefits = [
    {
      title: 'Comprehensive Practice Exams',
      description: '13,000+ questions covering CompTIA, ISC2, and AWS certifications',
      icon: <FaGraduationCap className="benefit-icon" />
    },
    {
      title: 'Exclusive Learning Tools',
      description: 'Access ScenarioSphere, AnalogyHub, GRC Wizard, and XploitCraft',
      icon: <FaFighterJet className="benefit-icon" />
    },
    {
      title: 'Gamified Learning Experience',
      description: 'Earn XP, avatars, unlock achievements, and compete on leaderboards',
      icon: <FaTrophy className="benefit-icon" />
    },
    {
      title: '24/7 Expert Support',
      description: 'Get answers or support for your upcoming exam at any time',
      icon: <FaUserSecret className="benefit-icon" />
    }
  ];
  
  return (
    <div className="subscription-container">
      <div className="subscription-background">
        <div className="subscription-grid"></div>
        <div className="subscription-particles">
          {Array.from({ length: 20 }).map((_, i) => (
            <div key={i} className="subscription-particle"></div>
          ))}
        </div>
        <div className="subscription-glow"></div>
      </div>
      
      <div className="subscription-content">
        <div className="subscription-card">
          <div className="subscription-card-accent"></div>
          
          <div className="subscription-header">
            <div className="subscription-logo">
              <FaDragon className="subscription-logo-icon" />
            </div>
            <h1 className="subscription-title">
              {isRenewal ? 'Reactivate Unlimited Access' : 'Level Up Your Cybersecurity Skills'}
            </h1>
            <p className="subscription-subtitle">
              {isRenewal 
                ? 'Continue your learning journey with unlimited access' 
                : 'Join other professionals excelling in their certification exams'}
            </p>
          </div>
          
          {error && (
            <div className="subscription-error">
              <FaTimesCircle />
              <span>{error}</span>
            </div>
          )}
          
          <div className="subscription-pricing">
            <div className="subscription-price">
              <span className="subscription-price-badge">Unlimited</span>
              <div className="subscription-trial-badge">
                <span className="subscription-trial-text">3-Day Free Trial</span>
              </div>
              <div className="subscription-price-amount">
                <span className="subscription-price-then">then</span>
                <span className="subscription-price-currency">$</span>
                <span className="subscription-price-value">9</span>
                <span className="subscription-price-decimal">.99</span>
                <span className="subscription-price-period">/month</span>
              </div>
            </div>
            <div className="subscription-price-features">
              <div className="subscription-price-feature">
                <FaCheckCircle />
                <span>Cancel anytime</span>
              </div>
              <div className="subscription-price-feature">
                <FaCheckCircle />
                <span>Immediate access to all content</span>
              </div>
              <div className="subscription-price-feature">
                <FaCheckCircle />
                <span>Access to web and iOS app</span>
              </div>
            </div>
          </div>
          
          {isRenewal && (
            <div className="subscription-renewal-message">
              <FaInfoCircle className="subscription-renewal-icon" />
              <p>Your previous subscription has expired. Renewing now will immediately restore access to all features and your saved progress.</p>
            </div>
          )}
          
          <div className="subscription-benefits">
            <h3 className="subscription-benefits-title">
              {isRenewal ? 'What You\'ll Get Back' : 'What You\'ll Get'}
            </h3>
            <div className="subscription-benefits-list">
              {benefits.map((benefit, index) => (
                <div key={index} className="subscription-benefit-item">
                  {benefit.icon}
                  <div className="subscription-benefit-text">
                    <h4>{benefit.title}</h4>
                    <p>{benefit.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
          
          <div className="subscription-security">
            <FaLock className="subscription-security-icon" />
            <p>Secure payments powered by Stripe. Your payment information is never stored on our servers.</p>
          </div>
          
          <div className="subscription-actions">
            <button
              className="subscription-button subscription-button-large"
              onClick={handleSubscribe}
              disabled={loading || redirecting}
            >
              {loading || redirecting ? (
                <span className="subscription-button-loading">
                  <div className="subscription-spinner"></div>
                  <span>{redirecting ? 'Redirecting...' : 'Processing...'}</span>
                </span>
              ) : (
                <span className="subscription-button-text">
                  <FaCreditCard className="subscription-button-icon" />
                  <span>{isRenewal ? 'RENEW SUBSCRIPTION' : 'START FREE TRIAL'}</span>
                  {isRenewal ? 
                    <FaRedo className="subscription-button-icon-right" /> : 
                    <FaArrowRight className="subscription-button-icon-right" />}
                </span>
              )}
            </button>
            
            {/* Add escape button when in renewal mode */}
            {isRenewal && (
              <button
                className="subscription-escape-button"
                onClick={handleEscapeRenewal}
                disabled={loading || redirecting}
              >
                <FaHome className="subscription-button-icon" />
                <span>GO TO HOME PAGE</span>
              </button>
            )}
            
            <button
              className="subscription-back-button"
              onClick={handleGoBack}
              disabled={loading || redirecting}
            >
              <FaArrowLeft className="subscription-button-icon" />
              <span>Go Back</span>
            </button>
          </div>
          
          {/* Add additional escape notice */}
          {isRenewal && (
            <div className="subscription-escape-notice">
              <FaInfoCircle className="subscription-note-icon" />
              <p>
                Need to explore other sections first? Click "Go to Home Page" to temporarily bypass the subscription reminder.
              </p>
            </div>
          )}
          
          <div className="subscription-note">
            <FaInfoCircle className="subscription-note-icon" />
            <p>
              By subscribing, you agree to our <a href="/terms">Terms of Service</a> and 
              <a href="/privacy">Privacy Policy</a>. You can cancel your subscription at any time
              from your profile page.
            </p>
          </div>
        </div>
      </div>
      
      {/* Add this CSS block at the end of the component */}
      <style jsx>{`
        .subscription-escape-button {
          display: flex;
          align-items: center;
          justify-content: center;
          margin-top: 1rem;
          padding: 0.75rem 1.5rem;
          background-color: #2e3856;
          color: #ffffff;
          border: none;
          border-radius: 8px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s ease;
          width: 100%;
        }
        
        .subscription-escape-button:hover {
          background-color: #3a4675;
        }
        
        .subscription-escape-notice {
          margin-top: 1rem;
          padding: 0.75rem;
          background-color: rgba(46, 56, 86, 0.1);
          border-radius: 8px;
          display: flex;
          align-items: center;
          font-size: 0.9rem;
        }
        
        .subscription-escape-notice .subscription-note-icon {
          color: #4a90e2;
          margin-right: 0.5rem;
          flex-shrink: 0;
        }
      `}</style>
    </div>
  );
};

export default SubscriptionPage;
