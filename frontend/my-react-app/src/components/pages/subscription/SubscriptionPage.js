// src/components/pages/subscription/SubscriptionPage.js
import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { setCurrentUserId } from '../store/userSlice';
import axios from 'axios';
import { FaShieldAlt, FaCheck, FaSpinner } from 'react-icons/fa';
import './SubscriptionPage.css';

const SubscriptionPage = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [pendingRegistration, setPendingRegistration] = useState(null);
  
  const navigate = useNavigate();
  const location = useLocation();
  const dispatch = useDispatch();
  
  useEffect(() => {
    // Load pending registration data
    const regData = localStorage.getItem('pendingRegistration');
    
    // Check if coming from login with expired subscription
    const renewalState = location.state?.renewSubscription;
    const renewUserId = location.state?.userId || localStorage.getItem('tempUserId');
    
    if (renewalState && renewUserId) {
      // Set up for subscription renewal
      setPendingRegistration({
        userId: renewUserId,
        registrationType: 'renewal'
      });
    } else if (regData) {
      setPendingRegistration(JSON.parse(regData));
    } else {
      // No pending registration, redirect to register page
      navigate('/register');
    }
  }, [navigate, location]);
  
  const handleSubscribe = async () => {
    if (!pendingRegistration) {
      setError('Registration data not found');
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      // If OAuth registration, use the userId directly
      const userId = pendingRegistration.userId || null;
      
      console.log('Sending data to checkout:', {
        userId,
        email: pendingRegistration.email,
        pendingRegistration: JSON.stringify(pendingRegistration)
      });
      
      const response = await axios.post('/api/subscription/create-checkout-session', {
        userId,
        email: pendingRegistration.email,
        pendingRegistration: JSON.stringify(pendingRegistration)
      });
      
      console.log('Checkout response:', response.data);
      
      // Check the exact structure of the response
      if (response.data && response.data.url) {
        // Redirect to Stripe Checkout
        window.location.href = response.data.url;
      } else {
        console.error('Missing URL in response:', response.data);
        setError('Invalid response from server. Please try again.');
      }
    } catch (err) {
      console.error('Checkout error details:', err.response?.data || err.message || err);
      setError('Failed to start checkout process. Please try again.');
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="subscription-container">
      <div className="subscription-background">
        <div className="subscription-grid"></div>
        <div className="subscription-glow"></div>
      </div>
      
      <div className="subscription-content">
        <div className="subscription-card">
          <div className="subscription-card-accent"></div>
          
          <div className="subscription-header">
            <div className="subscription-logo">
              <FaShieldAlt className="subscription-logo-icon" />
            </div>
            <h1 className="subscription-title">Premium Membership</h1>
            <p className="subscription-subtitle">
              {pendingRegistration?.registrationType === 'renewal' 
                ? 'Renew your premium access' 
                : 'Subscribe to unlock all features'}
            </p>
          </div>
          
          <div className="subscription-price-container">
            <span className="subscription-price">$9.99</span>
            <span className="subscription-period">/month</span>
          </div>
          
          <div className="subscription-features">
            <h3>Premium Features</h3>
            <ul className="subscription-features-list">
              <li>
                <FaCheck className="subscription-check" />
                <span>Unlimited access to all practice tests</span>
              </li>
              <li>
                <FaCheck className="subscription-check" />
                <span>Advanced analytics and progress tracking</span>
              </li>
              <li>
                <FaCheck className="subscription-check" />
                <span>Personalized study recommendations</span>
              </li>
              <li>
                <FaCheck className="subscription-check" />
                <span>Additional practice materials</span>
              </li>
              <li>
                <FaCheck className="subscription-check" />
                <span>Access across web and mobile</span>
              </li>
            </ul>
          </div>
          
          {error && (
            <div className="subscription-error">
              <p>{error}</p>
            </div>
          )}
          
          <button 
            className="subscription-button"
            onClick={handleSubscribe}
            disabled={loading || !pendingRegistration}
          >
            {loading ? (
              <span className="subscription-button-loading">
                <FaSpinner className="subscription-spinner" />
                <span>Processing...</span>
              </span>
            ) : (
              <span className="subscription-button-text">
                {pendingRegistration?.registrationType === 'renewal' 
                  ? 'Renew Subscription' 
                  : 'Subscribe Now'}
              </span>
            )}
          </button>
          
          <div className="subscription-cancel">
            <p>Cancel anytime. No hidden fees.</p>
          </div>
          
          <div className="subscription-secure">
            <p>Secure payment powered by Stripe</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SubscriptionPage;
