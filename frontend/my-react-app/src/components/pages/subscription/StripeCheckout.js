// src/components/pages/subscription/StripeCheckout.js
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { FaLock, FaSpinner, FaExclamationCircle } from 'react-icons/fa';
import './StripeCheckout.css';

const StripeCheckout = ({ userId, registrationData, isOauthFlow }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const navigate = useNavigate();

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
      {loading ? (
        <div className="stripe-checkout-loading">
          <FaSpinner className="stripe-checkout-spinner" />
          <p>Preparing secure payment environment...</p>
          <div className="stripe-checkout-security">
            <FaLock className="stripe-checkout-security-icon" />
            <span>Secure transaction powered by Stripe</span>
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
