// frontend/my-react-app/src/components/common/ErrorMessage.js
import React from 'react';
import './common.css';

const ErrorMessage = ({ message, onDismiss }) => {
  return (
    <div className="error-message-container">
      <div className="error-content">
        <div className="error-icon">⚠️</div>
        <p className="error-text">{message}</p>
      </div>
      {onDismiss && (
        <button className="error-dismiss-button" onClick={onDismiss}>
          Dismiss
        </button>
      )}
    </div>
  );
};

export default ErrorMessage;
