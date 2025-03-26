import React, { useState, useEffect } from 'react';
import './SubscriptionPage.css';
import header from './header.png';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Subscription() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [processingPayment, setProcessingPayment] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    async function fetchUserData() {
      try {
        const response = await axios.get('/api/user', {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        setUser(response.data);
        setLoading(false);
      } catch (err) {
        setError('Failed to fetch user data');
        setLoading(false);
      }
    }

    fetchUserData();
  }, [navigate]);

  const handleSubscribe = async () => {
    setProcessingPayment(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post('/api/subscribe', {}, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      if (response.data.success) {
        setShowModal(true);
        // Update user data
        const userResponse = await axios.get('/api/user', {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        setUser(userResponse.data);
      } else {
        setError('Subscription failed. Please try again.');
      }
    } catch (err) {
      setError('An error occurred while processing your subscription.');
    } finally {
      setProcessingPayment(false);
    }
  };

  const closeModal = () => {
    setShowModal(false);
  };

  if (loading) {
    return (
      <div className="subscription-container">
        <div className="loading-spinner">Loading...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="subscription-container">
        <div className="error-message">{error}</div>
      </div>
    );
  }

  return (
    <div className="subscription-container">
      <div className="subscription-card">
        <div className="header-container">
          <img src={header} alt="Cert Games Logo" className="logo-header" />
        </div>
        
        <div className="content-wrapper">
          <h1 className="subscription-title">Unlock Premium Certification Training</h1>
          
          <div className="benefits-container">
            <div className="benefit-item">
              <div className="benefit-icon">🎯</div>
              <div className="benefit-text">
                <h3>Exam-Ready Practice</h3>
                <p>Access realistic certification questions updated regularly</p>
              </div>
            </div>
            
            <div className="benefit-item">
              <div className="benefit-icon">🚀</div>
              <div className="benefit-text">
                <h3>Career Advancement</h3>
                <p>95% of our users report promotions within 6 months</p>
              </div>
            </div>
            
            <div className="benefit-item">
              <div className="benefit-icon">🔒</div>
              <div className="benefit-text">
                <h3>Pass Guarantee</h3>
                <p>Free extension if you don't pass on your first attempt</p>
              </div>
            </div>
          </div>

          <div className="pricing-container">
            <div className="price-tag">
              <span className="price-amount">$29.99</span>
              <span className="price-period">/month</span>
            </div>
            <div className="price-guarantee">30-day money back guarantee</div>
          </div>

          <div className="action-container">
            <button 
              className="subscribe-button" 
              onClick={handleSubscribe}
              disabled={processingPayment}
            >
              {processingPayment ? 'Processing...' : 'Subscribe Now'}
            </button>
            <p className="subscription-note">Join 50,000+ IT professionals who've accelerated their careers</p>
          </div>
        </div>
      </div>

      {showModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h2>Subscription Successful!</h2>
            <p>Thank you for subscribing to Cert Games Premium. Your account has been upgraded.</p>
            <button className="modal-close-button" onClick={closeModal}>Continue</button>
          </div>
        </div>
      )}
    </div>
  );
}

export default Subscription;
