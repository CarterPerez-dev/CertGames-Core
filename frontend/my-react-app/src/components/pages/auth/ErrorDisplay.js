// ErrorDisplay.js
import React from 'react';
import { FaExclamationTriangle } from 'react-icons/fa';
import './css/ErrorDisplay.css';

const ErrorDisplay = ({ errors }) => {
  if (!errors || errors.length === 0) return null;

  return (
    <div className="error-display">
      {errors.map((err, idx) => (
        <div key={idx} className="error-item">
          <FaExclamationTriangle className="error-icon" />
          <span>{err}</span>
        </div>
      ))}
    </div>
  );
};

export default ErrorDisplay;
