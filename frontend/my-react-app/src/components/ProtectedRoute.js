// src/components/ProtectedRoute.js
import React, { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import { checkSubscription } from './pages/store/userSlice';

const ProtectedRoute = ({ children }) => {
  const { userId, subscriptionActive, status } = useSelector((state) => state.user);
  const [isChecking, setIsChecking] = useState(true);
  const location = useLocation();
  const dispatch = useDispatch();
  
  useEffect(() => {
    const verifySubscription = async () => {
      if (userId) {
        try {
          await dispatch(checkSubscription(userId)).unwrap();
          setIsChecking(false);
        } catch (err) {
          console.error('Error checking subscription:', err);
          setIsChecking(false);
        }
      } else {
        setIsChecking(false);
      }
    };
    
    verifySubscription();
  }, [userId, dispatch]);
  
  if (isChecking || status === 'loading') {
    // Show loading state
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }
  
  if (!userId) {
    // Not logged in, redirect to login
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  
  if (!subscriptionActive) {
    // Subscription inactive, redirect to subscription page
    return <Navigate to="/subscription" state={{ userId, from: location }} replace />;
  }
  
  // User is logged in and has active subscription
  return children;
};

export default ProtectedRoute;
