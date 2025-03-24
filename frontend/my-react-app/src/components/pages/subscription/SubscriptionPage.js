// src/components/pages/Subscription/SubscriptionPage.js
import React, { useState } from 'react';
import { useSelector } from 'react-redux';
import axios from 'axios';
import './SubscriptionPage.css';

const SubscriptionPage = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { userId } = useSelector((state) => state.user);

  const handleSubscribe = async () => {
    if (!userId) {
      setError('Please log in to subscribe');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const response = await axios.post('/api/subscription/create-checkout-session', {
        userId
      });

      // Redirect to Stripe Checkout
      window.location.href = response.data.url;
    } catch (err) {
      setError('Failed to start checkout process. Please try again.');
      console.error('Checkout error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="subscription-container">
      <div className="subscription-card">
        <h1 className="subscription-title">Premium Membership</h1>
        <div className="subscription-price">
          <span className="subscription-amount">$9.99</span>
          <span className="subscription-period">/month</span>
        </div>
        
        <div className="subscription-features">
          <h2>Features</h2>
          <ul>
            <li>Unlimited access to all practice tests</li>
            <li>Advanced analytics and progress tracking</li>
            <li>Personalized study recommendations</li>
            <li>Additional practice materials</li>
            <li>Access across web and mobile</li>
          </ul>
        </div>
        
        {error && <div className="subscription-error">{error}</div>}
        
        <button 
          className="subscription-button" 
          onClick={handleSubscribe}
          disabled={loading}
        >
          {loading ? 'Processing...' : 'Subscribe Now'}
        </button>
        
        <div className="subscription-info">
          <p>Cancel anytime. No hidden fees.</p>
        </div>
      </div>
    </div>
  );
};

export default SubscriptionPage;
