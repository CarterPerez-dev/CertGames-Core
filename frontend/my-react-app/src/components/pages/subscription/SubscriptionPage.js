// src/components/pages/subscription/SubscriptionPage.js
import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useSelector } from 'react-redux';
import axios from 'axios';
import {
  FaCheckCircle,
  FaTimesCircle,
  FaShieldAlt,
  FaLock,
  FaCreditCard,
  FaInfoCircle,
  FaSpinner,
  FaArrowLeft,
  FaArrowRight,
  FaRedo
} from 'react-icons/fa';
import './SubscriptionPage.css';

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
      setError('Error starting the subscription process. Please try again.');
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
  
  // Benefits array for display
  const benefits = [
    {
      title: 'Premium Features',
      description: 'Get access to all premium features and practice exams',
      icon: <FaCheckCircle className="benefit-icon" />
    },
    {
      title: 'Regular Updates',
      description: 'Receive the latest exam questions and study materials',
      icon: <FaCheckCircle className="benefit-icon" />
    },
    {
      title: 'Unlimited Attempts',
      description: 'Take unlimited practice tests and track your progress',
      icon: <FaCheckCircle className="benefit-icon" />
    },
    {
      title: 'Cross-Platform Access',
      description: 'Use on web and iOS app with a single subscription',
      icon: <FaCheckCircle className="benefit-icon" />
    }
  ];
  
  return (
    <div className="subscription-container">
      <div className="subscription-background">
        <div className="subscription-grid"></div>
        <div className="subscription-glow"></div>
      </div>
      
      <div className="subscription-content">
        <div className="subscription-card">
          <div className="subscription-header">
            <div className="subscription-logo">
              <FaShieldAlt className="subscription-logo-icon" />
            </div>
            <h1 className="subscription-title">
              {isRenewal ? 'Renew Your Premium Access' : 'Start Your Premium Journey'}
            </h1>
            <p className="subscription-subtitle">
              {isRenewal 
                ? 'Reactivate your subscription to continue your learning path' 
                : 'Unlock all features with a CertGames subscription'}
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
              <span className="subscription-price-currency">$</span>
              <span className="subscription-price-value">9.99</span>
              <span className="subscription-price-period">/month</span>
            </div>
            <div className="subscription-price-description">
              <p>Billed monthly. Cancel anytime.</p>
              <p>Access on all devices with a single account</p>
            </div>
          </div>
          
          {isRenewal && (
            <div className="subscription-renewal-message">
              <FaInfoCircle className="subscription-renewal-icon" />
              <p>Your previous subscription has been canceled or expired. Renewing will give you immediate access to all premium content.</p>
            </div>
          )}
          
          <div className="subscription-benefits">
            <h3 className="subscription-benefits-title">
              {isRenewal ? 'What You\'ll Get Back' : 'What You\'ll Get'}
            </h3>
            <ul className="subscription-benefits-list">
              {benefits.map((benefit, index) => (
                <li key={index} className="subscription-benefit-item">
                  {benefit.icon}
                  <div className="subscription-benefit-text">
                    <h4>{benefit.title}</h4>
                    <p>{benefit.description}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
          
          <div className="subscription-security">
            <FaLock className="subscription-security-icon" />
            <p>Secure payments powered by Stripe. Your payment information is never stored on our servers.</p>
          </div>
          
          <div className="subscription-actions">
            <button
              className="subscription-back-button"
              onClick={handleGoBack}
              disabled={loading || redirecting}
            >
              <FaArrowLeft className="subscription-button-icon" />
              <span>Go Back</span>
            </button>
            
            <button
              className="subscription-button"
              onClick={handleSubscribe}
              disabled={loading || redirecting}
            >
              {loading || redirecting ? (
                <span className="subscription-button-loading">
                  <FaSpinner className="subscription-spinner" />
                  {redirecting ? 'Redirecting...' : 'Processing...'}
                </span>
              ) : (
                <span className="subscription-button-text">
                  <FaCreditCard className="subscription-button-icon" />
                  <span>{isRenewal ? 'Renew Subscription' : 'Subscribe Now'}</span>
                  {isRenewal ? 
                    <FaRedo className="subscription-button-icon-right" /> : 
                    <FaArrowRight className="subscription-button-icon-right" />}
                </span>
              )}
            </button>
          </div>
          
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
    </div>
  );
};

export default SubscriptionPage;
