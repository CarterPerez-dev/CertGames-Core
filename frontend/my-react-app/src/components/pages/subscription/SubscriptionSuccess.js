// src/components/pages/subscription/SubscriptionSuccess.js
import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { setCurrentUserId, fetchUserData } from '../store/userSlice';
import { FaCheckCircle, FaSpinner, FaExclamationCircle } from 'react-icons/fa';
import './SubscriptionPage.css';

const SubscriptionSuccess = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [logs, setLogs] = useState([]);
  const [pendingRegistration, setPendingRegistration] = useState(null);
  
  const addLog = (message) => {
    console.log(message);
    setLogs(prev => [...prev, `${new Date().toISOString().substring(11, 23)}: ${message}`]);
  };

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const sessionId = params.get('session_id');
    
    if (!sessionId) {
      setError('No session ID found in the URL');
      setLoading(false);
      return;
    }
    
    addLog(`Starting with session ID: ${sessionId}`);
    
    // Load registration data from localStorage
    try {
      const regData = localStorage.getItem('pendingRegistration');
      if (regData) {
        const parsedData = JSON.parse(regData);
        setPendingRegistration(parsedData);
        addLog(`Loaded registration data: ${regData}`);
      } else {
        addLog('No pendingRegistration found in localStorage');
      }
    } catch (e) {
      addLog(`Failed to parse registration data: ${e.message}`);
      console.error('Failed to parse registration data', e);
    }
    
    // Proceed directly to verification
    verifySession(sessionId);
  }, [location.search]);
  
  const verifySession = (sessionId) => {
    addLog('Starting session verification...');
    
    // Use plain fetch API for maximum compatibility
    fetch('/api/subscription/verify-session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ sessionId })
    })
    .then(response => {
      addLog(`Received response: status ${response.status}`);
      if (!response.ok) {
        return response.text().then(text => {
          throw new Error(`Server responded with ${response.status}: ${text}`);
        });
      }
      return response.json();
    })
    .then(data => {
      addLog(`Verification succeeded: ${JSON.stringify(data)}`);
      
      if (data.success) {
        const userId = data.userId;
        const needsUsername = data.needsUsername;
        
        // Store in localStorage and cleanup
        localStorage.setItem('userId', userId);
        localStorage.removeItem('pendingRegistration');
        localStorage.removeItem('tempUserId');
        
        // Update Redux
        dispatch(setCurrentUserId(userId));
        dispatch(fetchUserData(userId));
        
        // Show success state
        setLoading(false);
        
        // Handle redirects based on registration type
        if (pendingRegistration) {
          if (pendingRegistration.registrationType === 'oauth' && needsUsername) {
            addLog('Redirecting to create username page');
            setTimeout(() => {
              navigate('/create-username', { 
                state: { userId, provider: pendingRegistration.provider }
              });
            }, 2000);
          } else if (pendingRegistration.registrationType === 'renewal') {
            addLog('Redirecting to profile after renewal');
            setTimeout(() => {
              navigate('/profile');
            }, 2000);
          } else {
            // Standard registration
            addLog('Redirecting to login after standard registration');
            setTimeout(() => {
              navigate('/login', {
                state: { message: 'Registration and subscription successful! Please log in.' }
              });
            }, 2000);
          }
        } else {
          // Default redirect
          addLog('Using default redirect to login page');
          setTimeout(() => {
            navigate('/login', {
              state: { message: 'Subscription successful! Please log in.' }
            });
          }, 2000);
        }
      } else {
        setError(data.error || 'Unknown error in verification');
        setLoading(false);
      }
    })
    .catch(err => {
      addLog(`Error during verification: ${err.message}`);
      setError(`Verification failed: ${err.message}`);
      setLoading(false);
    });
  };
  
  return (
    <div className="subscription-success-container">
      <div className="subscription-background">
        <div className="subscription-grid"></div>
        <div className="subscription-glow"></div>
      </div>
      
      <div className="subscription-success-content">
        <div className="subscription-success-card">
          {loading ? (
            <div className="subscription-loading">
              <FaSpinner className="subscription-spinner" />
              <p>Verifying your subscription...</p>
              <p className="subscription-small-text">This may take a few moments</p>
              
              {/* Show logs for debugging */}
              <div className="subscription-debug-logs">
                <p>Debug logs:</p>
                <pre>
                  {logs.map((log, i) => <div key={i}>{log}</div>)}
                </pre>
              </div>
            </div>
          ) : error ? (
            <div className="subscription-error">
              <FaExclamationCircle className="subscription-error-icon" />
              <h2>Verification Error</h2>
              <p>{error}</p>
              
              <div className="subscription-error-actions">
                <button
                  className="subscription-button"
                  onClick={() => window.location.reload()}
                >
                  Try Again
                </button>
                
                <button
                  className="subscription-button subscription-button-secondary"
                  onClick={() => navigate('/subscription')}
                >
                  Back to Subscription
                </button>
              </div>
              
              <div className="subscription-debug-logs">
                <p>Debug logs:</p>
                <pre>
                  {logs.map((log, i) => <div key={i}>{log}</div>)}
                </pre>
              </div>
            </div>
          ) : (
            <div className="subscription-success">
              <div className="subscription-success-icon">
                <FaCheckCircle />
              </div>
              <h1 className="subscription-success-title">Subscription Activated!</h1>
              <p className="subscription-success-message">
                Thank you for subscribing to CertGames Premium. Your account is now active.
              </p>
              
              {pendingRegistration?.registrationType === 'standard' && (
                <>
                  <p className="subscription-next-steps">
                    Please log in to access your premium features.
                  </p>
                  <button 
                    className="subscription-button"
                    onClick={() => navigate('/login', {
                      state: { message: 'Registration and subscription successful! Please log in.' }
                    })}
                  >
                    Log In Now
                  </button>
                </>
              )}
              
              {pendingRegistration?.registrationType === 'oauth' && pendingRegistration?.needsUsername && (
                <p className="subscription-next-steps">
                  Redirecting you to create your username...
                </p>
              )}
              
              {pendingRegistration?.registrationType === 'renewal' && (
                <p className="subscription-next-steps">
                  Redirecting to your profile...
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SubscriptionSuccess;
