// src/components/ProtectedRoute.js
import React from 'react';
import { useSelector } from 'react-redux';
import { Navigate } from 'react-router-dom';

const ProtectedRoute = ({ children }) => {
  const { userId, status } = useSelector((state) => state.user);
  
  // If user data is still loading, return a loader (or null)
  if (status === 'loading') {
    return <div>Loading...</div>;
  }
  
  // If userId exists, render the protected content; otherwise, redirect to login.
  return userId ? children : <Navigate to="/login" replace />;
};

export default ProtectedRoute;

