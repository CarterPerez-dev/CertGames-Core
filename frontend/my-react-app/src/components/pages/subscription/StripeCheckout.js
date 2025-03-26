// src/components/pages/subscription/StripeCheckout.js
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { FaLock, FaSpinner, FaExclamationCircle, FaCreditCard, FaPaypal, FaApplePay, FaGooglePay } from 'react-icons/fa';
import './StripeCheckout.css';

const StripeCheckout = ({ userId, registrationData, isOauthFlow }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [progress, setProgress] = useState(0);
  const navigate = useNavigate();

  // Simulate progress for better user experience
  useEffect(() => {
    if (loading) {
      const interval = setInterval(() => {
        setProgress(prevProgress => {
          // Cap progress at 70% while waiting for redirect
          // The real redirect will happen before it reaches 100%
          return prevProgress < 70 ? prevProgress + 5 : prevProgress;
        });
      }, 500);
      
      return () => clearInterval(interval);
    }
  }, [loading]);

  useEffect(() => {
    // Create a Stripe checkout session when component mounts
    const createCheckoutSession = async () => {
      setLoading(true);
      try {
        const response = await axios.post('/api/subscription/create-checkout-session', {
          userId: userId || null,
          registrationData: registrationData || null,
          isOauthFlow: isOauthFlow || false
        });
        
        // Redirect to Stripe Checkout
        window.location.href = response.data.url;
      } catch (err) {
        console.error('Error creating checkout session:', err);
        setError('Error starting the payment process. Please try again.');
        setLoading(false);
      }
    };
    
    createCheckoutSession();
  }, [userId, registrationData, isOauthFlow]);

  return (
    <div className="stripe-checkout-container">
      {/* Animated glow effects */}
      <div className="glow-effect"></div>
      <div className="glow-effect"></div>
      <div className="glow-effect"></div>
      
      {loading ? (
        <div className="stripe-checkout-loading">
          <img 
            src="/logo-light.png" 
            alt="Company Logo" 
            className="stripe-checkout-brand-logo"
          />
          
          <FaSpinner className="stripe-checkout-spinner" />
          <p>Preparing secure payment environment...</p>
          
          {/* Progress indicator */}
          <div className="stripe-checkout-progress">
            <div className="stripe-checkout-progress-bar"></div>
          </div>
          
          <div className="stripe-checkout-security">
            <FaLock className="stripe-checkout-security-icon" />
            <span>Secure transaction powered by Stripe</span>
          </div>
          
          <div className="stripe-checkout-payment-logos">
            <FaCreditCard className="stripe-checkout-payment-logo" />
            <FaPaypal className="stripe-checkout-payment-logo" />
            <FaApplePay className="stripe-checkout-payment-logo" />
            <FaGooglePay className="stripe-checkout-payment-logo" />
          </div>
        </div>
      ) : error ? (
        <div className="stripe-checkout-error">
          <FaExclamationCircle className="stripe-checkout-error-icon" />
          <p>{error}</p>
          <button 
            className="stripe-checkout-retry"
            onClick={() => window.location.reload()}
          >
            Try Again
          </button>
        </div>
      ) : null}
    </div>
  );
};

export default StripeCheckout;
