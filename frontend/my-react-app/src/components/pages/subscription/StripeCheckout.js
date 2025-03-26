// src/components/pages/subscription/StripeCheckout.js
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { FaLock, FaSpinner, FaExclamationCircle, FaCreditCard, FaShieldAlt } from 'react-icons/fa';
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
    <div className="checkout-container">
      <div className="checkout-background">
        <div className="checkout-grid"></div>
        <div className="checkout-particles">
          {Array.from({ length: 20 }).map((_, i) => (
            <div key={i} className="checkout-particle"></div>
          ))}
        </div>
        <div className="checkout-glow"></div>
      </div>
      
      <div className="checkout-content">
        <div className="checkout-card">
          <div className="checkout-card-accent"></div>
          
          {loading ? (
            <div className="checkout-loading">
              <div className="checkout-logo">
                <FaCreditCard className="checkout-logo-icon-primary" />
                <FaShieldAlt className="checkout-logo-icon-secondary" />
              </div>
              <h2>Preparing Secure Payment</h2>
              <p>You'll be redirected to Stripe's secure payment platform in a moment...</p>
              <div className="checkout-spinner-container">
                <FaSpinner className="checkout-spinner" />
              </div>
              <div className="checkout-security">
                <FaLock className="checkout-security-icon" />
                <span>Secure transaction powered by Stripe</span>
              </div>
            </div>
          ) : error ? (
            <div className="checkout-error">
              <div className="checkout-error-icon">
                <FaExclamationCircle />
              </div>
              <h2>Payment Error</h2>
              <p>{error}</p>
              <button 
                className="checkout-retry-button"
                onClick={() => window.location.reload()}
              >
                Try Again
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
};

export default StripeCheckout;
