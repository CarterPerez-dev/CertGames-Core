// src/components/pages/Portfolio/DeploymentMonitor.js
import React, { useState, useEffect } from 'react';
import { FaSpinner, FaExclamationTriangle, FaCheckCircle } from 'react-icons/fa';

const DeploymentMonitor = ({ userId, deploymentId, onComplete, onError }) => {
  const [status, setStatus] = useState('pending');
  const [progress, setProgress] = useState(0);
  const [deploymentUrl, setDeploymentUrl] = useState('');
  const [error, setError] = useState(null);
  
  useEffect(() => {
    if (!deploymentId) return;
    
    const checkInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/portfolio/deployment-status/${deploymentId}`, {
          headers: {
            'X-User-Id': userId
          }
        });
        
        if (!response.ok) {
          throw new Error('Failed to check deployment status');
        }
        
        const data = await response.json();
        
        setStatus(data.status);
        setProgress(data.progress || 0);
        
        if (data.status === 'complete') {
          setDeploymentUrl(data.url);
          clearInterval(checkInterval);
          onComplete({
            deployment_url: data.url,
            github_repo: data.github_repo
          });
        } else if (data.status === 'failed') {
          setError(data.error);
          clearInterval(checkInterval);
          onError(data.error);
        }
      } catch (err) {
        console.error('Error checking deployment status:', err);
        setError(err.message);
        clearInterval(checkInterval);
        onError(err.message);
      }
    }, 5000);
    
    return () => clearInterval(checkInterval);
  }, [deploymentId, userId, onComplete, onError]);
  
  return (
    <div className="deployment-monitor">
      {status === 'complete' ? (
        <div className="deployment-success">
          <FaCheckCircle className="success-icon" />
          <h3>Deployment Complete!</h3>
          <p>Your portfolio is now live at:</p>
          <a href={deploymentUrl} target="_blank" rel="noopener noreferrer" className="deployment-url">
            {deploymentUrl}
          </a>
        </div>
      ) : status === 'failed' ? (
        <div className="deployment-error">
          <FaExclamationTriangle className="error-icon" />
          <h3>Deployment Failed</h3>
          <p>{error || 'An error occurred during deployment.'}</p>
        </div>
      ) : (
        <div className="deployment-progress">
          <FaSpinner className="spinner-icon" />
          <h3>Deployment in Progress</h3>
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${progress}%` }}></div>
          </div>
          <p>{progress}% complete</p>
        </div>
      )}
    </div>
  );
};

export default DeploymentMonitor;
