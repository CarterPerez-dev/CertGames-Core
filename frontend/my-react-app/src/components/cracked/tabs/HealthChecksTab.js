// src/components/cracked/tabs/HealthChecksTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaHeartbeat, FaDatabase, FaCheckCircle, FaSync,
  FaSpinner, FaExclamationTriangle, FaServer, FaBolt
} from "react-icons/fa";
import { adminFetch } from '../csrfHelper';

const HealthChecksTab = () => {
  const [apiStatus, setApiStatus] = useState({
    healthy: false,
    lastChecked: null,
    responseTime: null
  });
  const [isChecking, setIsChecking] = useState(false);
  const [error, setError] = useState(null);
  
  const checkApiHealth = useCallback(async () => {
    setIsChecking(true);
    setError(null);
    const startTime = performance.now();
    
    try {
      const res = await adminFetch("/api/cracked/api-health-check", { 
        // Cache-busting to ensure fresh results
        headers: { "Cache-Control": "no-cache" }
      });
      
      const endTime = performance.now();
      const responseTime = Math.round(endTime - startTime);
      
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "API health check failed");
      }
      
      const data = await res.json();
      setApiStatus({
        healthy: data.healthy === true,
        lastChecked: new Date().toLocaleString(),
        responseTime: responseTime
      });
    } catch (err) {
      setError(err.message);
      setApiStatus({
        healthy: false,
        lastChecked: new Date().toLocaleString(),
        responseTime: null
      });
    } finally {
      setIsChecking(false);
    }
  }, []);

  // Check health on component mount
  useEffect(() => {
    checkApiHealth();
    
    // Set up interval to check health every 3 minutes (180000ms)
    const interval = setInterval(checkApiHealth, 180000);
    
    return () => clearInterval(interval);
  }, [checkApiHealth]);

  return (
    <div className="admin-tab-content health-checks-tab">
      <div className="admin-content-header">
        <h2><FaHeartbeat /> API Health Monitoring</h2>
        <button 
          className="admin-refresh-btn" 
          onClick={checkApiHealth}
          disabled={isChecking}
        >
          {isChecking ? (
            <><FaSpinner className="admin-spinner" /> Checking...</>
          ) : (
            <><FaSync /> Check API Health</>
          )}
        </button>
      </div>

      {error && (
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {error}
        </div>
      )}

      <div className="admin-health-overview">
        <div className={`admin-health-card ${apiStatus.healthy ? 'healthy' : 'unhealthy'}`}>
          <div className="admin-health-status-icon">
            {apiStatus.healthy ? (
              <FaCheckCircle className="status-icon healthy" />
            ) : (
              <FaExclamationTriangle className="status-icon unhealthy" />
            )}
          </div>
          <div className="admin-health-details">
            <h3>Backend API Status</h3>
            <div className="admin-health-status">
              {apiStatus.healthy ? 'Operational' : 'Service Disruption'}
            </div>
            <div className="admin-health-meta">
              <div className="admin-health-meta-item">
                <span className="label">Last Checked:</span>
                <span className="value">{apiStatus.lastChecked || 'N/A'}</span>
              </div>
              {apiStatus.responseTime && (
                <div className="admin-health-meta-item">
                  <span className="label">Response Time:</span>
                  <span className="value">{apiStatus.responseTime}ms</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="admin-stats-grid">
        <div className="admin-stat-card">
          <div className="admin-stat-icon health-icon">
            <FaServer />
          </div>
          <div className="admin-stat-content">
            <h3>API Status</h3>
            <div className={`admin-stat-value ${apiStatus.healthy ? 'status-success' : 'status-error'}`}>
              {apiStatus.healthy ? 'Operational' : 'Down'}
            </div>
          </div>
        </div>

        <div className="admin-stat-card">
          <div className="admin-stat-icon db-icon">
            <FaDatabase />
          </div>
          <div className="admin-stat-content">
            <h3>Database</h3>
            <div className={`admin-stat-value ${apiStatus.healthy ? 'status-success' : 'status-error'}`}>
              {apiStatus.healthy ? 'Connected' : 'Unreachable'}
            </div>
          </div>
        </div>

        <div className="admin-stat-card">
          <div className="admin-stat-icon response-icon">
            <FaBolt />
          </div>
          <div className="admin-stat-content">
            <h3>Response Time</h3>
            <div className="admin-stat-value">
              {apiStatus.responseTime ? `${apiStatus.responseTime}ms` : 'N/A'}
            </div>
          </div>
        </div>

        <div className="admin-stat-card">
          <div className="admin-stat-icon time-icon">
            <FaHeartbeat />
          </div>
          <div className="admin-stat-content">
            <h3>Last Check</h3>
            <div className="admin-stat-value">
              {apiStatus.lastChecked || 'Never'}
            </div>
          </div>
        </div>
      </div>

      <div className="admin-health-info">
        <div className="admin-info-card">
          <h3>Health Check Information</h3>
          <p>This panel monitors the health of your backend API. The status is automatically checked every 3 minutes.</p>
          <p>If you experience any issues with the application, you can click the "Check API Health" button to perform an immediate check.</p>
          <p>The health check verifies that your API is responding properly and can connect to the database.</p>
        </div>
      </div>
    </div>
  );
};

export default HealthChecksTab;
