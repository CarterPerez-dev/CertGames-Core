// src/components/ErrorConsole.js
import React, { useState, useEffect } from 'react';
import './ErrorConsole.css';

const ErrorConsole = ({ errors, onFixError }) => {
  const [isExpanded, setIsExpanded] = useState(true);
  const [errorCount, setErrorCount] = useState(0);

  useEffect(() => {
    setErrorCount(errors.length);
  }, [errors]);

  const toggleExpand = () => {
    setIsExpanded(!isExpanded);
  };

  const handleFixError = (error) => {
    if (onFixError) {
      onFixError(error);
    }
  };

  return (
    <div className={`error-console ${isExpanded ? 'expanded' : 'collapsed'}`}>
      <div className="error-console-header" onClick={toggleExpand}>
        <div className="error-title">
          <span className="error-icon">⚠️</span>
          <h3>Error Console {errorCount > 0 && `(${errorCount})`}</h3>
        </div>
        <button className="toggle-button">
          {isExpanded ? '▼' : '▶'}
        </button>
      </div>
      
      {isExpanded && (
        <div className="error-console-content">
          {errors.length === 0 ? (
            <div className="no-errors">
              <span className="success-icon">✓</span>
              <p>No errors detected</p>
            </div>
          ) : (
            <ul className="error-list">
              {errors.map((error, index) => (
                <li key={index} className="error-item">
                  <div className="error-item-header">
                    <span className="file-path">{error.file}</span>
                    <button 
                      className="fix-button"
                      onClick={() => handleFixError(error)}
                    >
                      Fix
                    </button>
                  </div>
                  <div className="error-message">
                    {error.message}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
};

export default ErrorConsole;
