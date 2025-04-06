// src/components/cracked/tabs/HealthChecksTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaHeartbeat, FaDatabase, FaCheckCircle, FaSync,
  FaSpinner, FaExclamationTriangle
} from "react-icons/fa";

const HealthChecksTab = () => {
  const [healthChecks, setHealthChecks] = useState([]);
  const [healthLoading, setHealthLoading] = useState(false);
  const [healthError, setHealthError] = useState(null);
  
  const fetchHealthChecks = useCallback(async () => {
    setHealthLoading(true);
    setHealthError(null);
    try {
      const res = await fetch("/api/cracked/health-checks", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch health checks");
      }
      if (Array.isArray(data)) {
        setHealthChecks(data);
      } else if (data.results) {
        setHealthChecks(data.results);
      }
    } catch (err) {
      setHealthError(err.message);
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealthChecks();
  }, [fetchHealthChecks]);

  return (
    <div className="admin-tab-content health-checks-tab">
      <div className="admin-content-header">
        <h2><FaHeartbeat /> API Health Monitoring</h2>
        <button className="admin-refresh-btn" onClick={fetchHealthChecks}>
          <FaSync /> Refresh Health Checks
        </button>
      </div>

      {healthLoading && (
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading health checks...</p>
        </div>
      )}

      {healthError && (
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {healthError}
        </div>
      )}

      <div className="admin-stats-grid">
        <div className="admin-stat-card">
          <div className="admin-stat-icon health-icon">
            <FaHeartbeat />
          </div>
          <div className="admin-stat-content">
            <h3>API Status</h3>
            <div className="admin-stat-value status-success">Operational</div>
          </div>
        </div>

        <div className="admin-stat-card">
          <div className="admin-stat-icon db-icon">
            <FaDatabase />
          </div>
          <div className="admin-stat-content">
            <h3>Database</h3>
            <div className="admin-stat-value status-success">Connected</div>
          </div>
        </div>

        <div className="admin-stat-card">
          <div className="admin-stat-icon endpoints-icon">
            <FaCheckCircle />
          </div>
          <div className="admin-stat-content">
            <h3>Endpoints</h3>
            <div className="admin-stat-value">{healthChecks.length || 0} Monitored</div>
          </div>
        </div>

        <div className="admin-stat-card">
          <div className="admin-stat-icon time-icon">
            <FaHeartbeat />
          </div>
          <div className="admin-stat-content">
            <h3>Last Check</h3>
            <div className="admin-stat-value">
              {healthChecks.length > 0 && healthChecks[0].checkedAt ? 
                formatTime(healthChecks[0].checkedAt) : 
                "No data"
              }
            </div>
          </div>
        </div>
      </div>

      <div className="admin-data-table-container">
        <table className="admin-data-table">
          <thead>
            <tr>
              <th>Checked At (EST)</th>
              <th>Endpoint</th>
              <th>Status</th>
              <th>OK</th>
              <th>Error</th>
            </tr>
          </thead>
          <tbody>
            {Array.isArray(healthChecks) && healthChecks.map((hc, idx) => {
              if (hc.results) {
                // multi results block
                return hc.results.map((r, j) => (
                  <tr key={`${hc._id}_${j}`} className={r.ok ? "" : "error-row"}>
                    <td>{hc.checkedAt}</td>
                    <td>{r.endpoint}</td>
                    <td>{r.status}</td>
                    <td>
                      <span className={r.ok ? "status-success" : "status-error"}>
                        {r.ok ? "Yes" : "No"}
                      </span>
                    </td>
                    <td>{r.error || ""}</td>
                  </tr>
                ));
              } else {
                // single item doc
                return (
                  <tr key={idx} className={hc.ok ? "" : "error-row"}>
                    <td>{hc.checkedAt}</td>
                    <td>{hc.endpoint}</td>
                    <td>{hc.status}</td>
                    <td>
                      <span className={hc.ok ? "status-success" : "status-error"}>
                        {hc.ok ? "Yes" : "No"}
                      </span>
                    </td>
                    <td>{hc.error || ""}</td>
                  </tr>
                );
              }
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// Helper function for formatting timestamps
const formatTime = (timestamp) => {
  if (!timestamp) return "";
  
  try {
    const date = new Date(timestamp);
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }).format(date);
  } catch (e) {
    return timestamp;
  }
};

export default HealthChecksTab;
