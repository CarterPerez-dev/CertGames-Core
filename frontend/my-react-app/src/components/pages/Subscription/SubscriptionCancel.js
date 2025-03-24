// src/components/pages/Subscription/SubscriptionCancel.js
import React from 'react';
import { useNavigate } from 'react-router-dom';
import './SubscriptionPage.css';

const SubscriptionCancel = () => {
  const navigate = useNavigate();
  
  return (
    <div className="subscription-cancel">
      <h1>Subscription Not Completed</h1>
      <p>Your subscription process was canceled. No charges were made.</p>
      <button 
        className="navigate-button"
        onClick={() => navigate('/subscription')}
      >
        Try Again
      </button>
    </div>
  );
};

export default SubscriptionCancel;
