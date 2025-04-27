// src/components/cracked/tabs/RequestLogsTab.js (renamed from DbLogsTab.js)
import React, { useState, useEffect, useCallback } from "react";
import {
  FaClipboardList, FaSync, FaSpinner, FaExclamationTriangle,
  FaFilter, FaServer, FaNetworkWired, FaTimes, FaSearch
} from "react-icons/fa";
import { adminFetch } from '../csrfHelper';

const RequestLogsTab = () => {
  // State for API logs
  const [apiLogs, setApiLogs] = useState([]);
  const [apiLogsLoading, setApiLogsLoading] = useState(false);
  const [apiLogsError, setApiLogsError] = useState(null);
  const [apiFilter, setApiFilter] = useState("");
  const [appliedApiFilter, setAppliedApiFilter] = useState("");
  
  // State for NGINX logs
  const [nginxLogs, setNginxLogs] = useState([]);
  const [nginxLogsLoading, setNginxLogsLoading] = useState(false);
  const [nginxLogsError, setNginxLogsError] = useState(null);
  const [nginxFilter, setNginxFilter] = useState("");
  const [appliedNginxFilter, setAppliedNginxFilter] = useState("");
  
  // State for tab switching
  const [activeLogType, setActiveLogType] = useState("api");
  
  // Polling interval for auto-refresh (in milliseconds)
  const POLLING_INTERVAL = 80000; // 10 seconds
  
  // Fetch API logs
  const fetchApiLogs = useCallback(async () => {
    setApiLogsLoading(true);
    setApiLogsError(null);
    try {
      const url = `/api/cracked/request-logs/api${appliedApiFilter ? `?filter=${encodeURIComponent(appliedApiFilter)}` : ''}`;
      const res = await adminFetch(url, { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch API logs");
      }
      setApiLogs(data);
    } catch (err) {
      setApiLogsError(err.message);
    } finally {
      setApiLogsLoading(false);
    }
  }, [appliedApiFilter]);
  
  // Fetch NGINX logs
  const fetchNginxLogs = useCallback(async (refresh = false) => {
    setNginxLogsLoading(true);
    setNginxLogsError(null);
    try {
      const url = `/api/cracked/request-logs/nginx${appliedNginxFilter ? `?filter=${encodeURIComponent(appliedNginxFilter)}` : ''}${refresh ? '&refresh=true' : ''}`;
      const res = await adminFetch(url, { credentials: "include" });
      
      // Check content type first
      const contentType = res.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        const text = await res.text();
        throw new Error(`Server returned non-JSON response: ${text.substring(0, 100)}...`);
      }
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch NGINX logs");
      }
      setNginxLogs(data);
    } catch (err) {
      console.error("Error fetching nginx logs:", err);
      setNginxLogsError(err.message);
    } finally {
      setNginxLogsLoading(false);
    }
  }, [appliedNginxFilter]);
  
  // Initial fetch
  useEffect(() => {
    if (activeLogType === "api" || activeLogType === "both") {
      fetchApiLogs();
    }
    if (activeLogType === "nginx" || activeLogType === "both") {
      fetchNginxLogs(true); // true to force a refresh on initial load
    }
  }, [fetchApiLogs, fetchNginxLogs, activeLogType]);
  
  // Set up polling
  useEffect(() => {
    const interval = setInterval(() => {
      if (activeLogType === "api" || activeLogType === "both") {
        fetchApiLogs();
      }
      if (activeLogType === "nginx" || activeLogType === "both") {
        fetchNginxLogs();
      }
    }, POLLING_INTERVAL);
    
    return () => clearInterval(interval);
  }, [fetchApiLogs, fetchNginxLogs, activeLogType]);
  
  // Handle API filter apply
  const handleApiFilterApply = () => {
    setAppliedApiFilter(apiFilter);
  };
  
  // Handle NGINX filter apply
  const handleNginxFilterApply = () => {
    setAppliedNginxFilter(nginxFilter);
  };
  
  // Clear filters
  const clearApiFilter = () => {
    setApiFilter("");
    setAppliedApiFilter("");
  };
  
  const clearNginxFilter = () => {
    setNginxFilter("");
    setAppliedNginxFilter("");
  };
  
  return (
    <div className="admin-tab-content request-logs-tab">
      <div className="admin-content-header">
        <h2><FaClipboardList /> Request Logs Monitor</h2>
        <div className="admin-refresh-actions">
          <button 
            className="admin-refresh-btn" 
            onClick={() => {
              if (activeLogType === "api" || activeLogType === "both") {
                fetchApiLogs();
              }
              if (activeLogType === "nginx" || activeLogType === "both") {
                fetchNginxLogs(true);
              }
            }}
          >
            <FaSync /> Refresh Logs
          </button>
        </div>
      </div>
      
      <div className="admin-logs-tabs">
        <button 
          className={`admin-logs-tab-btn ${activeLogType === "api" ? "active" : ""}`}
          onClick={() => setActiveLogType("api")}
        >
          <FaServer /> API Requests
        </button>
        <button 
          className={`admin-logs-tab-btn ${activeLogType === "nginx" ? "active" : ""}`}
          onClick={() => setActiveLogType("nginx")}
        >
          <FaNetworkWired /> NGINX Requests
        </button>
        <button 
          className={`admin-logs-tab-btn ${activeLogType === "both" ? "active" : ""}`}
          onClick={() => setActiveLogType("both")}
        >
          <FaClipboardList /> All Requests
        </button>
      </div>
      
      {/* API Logs Section */}
      {(activeLogType === "api" || activeLogType === "both") && (
        <div className="admin-logs-section">
          <div className="admin-section-header">
            <h3><FaServer /> API Request Logs</h3>
            <div className="admin-filter-container">
              <div className="admin-filter-input-group">
                <FaSearch className="admin-filter-icon" />
                <input
                  type="text"
                  value={apiFilter}
                  onChange={(e) => setApiFilter(e.target.value)}
                  placeholder="Filter by path, method, IP..."
                  className="admin-filter-input"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleApiFilterApply();
                  }}
                />
                {apiFilter && (
                  <button 
                    className="admin-clear-filter-btn"
                    onClick={clearApiFilter}
                    title="Clear filter"
                  >
                    <FaTimes />
                  </button>
                )}
              </div>
              <button 
                className="admin-filter-btn" 
                onClick={handleApiFilterApply}
              >
                <FaFilter /> Filter
              </button>
            </div>
          </div>
          
          {apiLogsLoading && (
            <div className="admin-loading">
              <FaSpinner className="admin-spinner" />
              <p>Loading API logs...</p>
            </div>
          )}
          
          {apiLogsError && (
            <div className="admin-error-message">
              <FaExclamationTriangle /> Error: {apiLogsError}
            </div>
          )}
          
          {!apiLogsLoading && !apiLogsError && (
            <div className="admin-data-table-container">
              <table className="admin-data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>Method</th>
                    <th>Path</th>
                    <th>User Agent</th>
                  </tr>
                </thead>
                <tbody>
                  {apiLogs.length > 0 ? (
                    apiLogs.map((log, index) => (
                      <tr key={`api-${index}`}>
                        <td>{log.timestamp}</td>
                        <td>{log.ip}</td>
                        <td className={`method-${log.method.toLowerCase()}`}>{log.method}</td>
                        <td>{log.path}</td>
                        <td className="user-agent-cell">{log.user_agent}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="5" className="admin-no-data">No API logs available</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      
      {/* NGINX Logs Section */}
      {(activeLogType === "nginx" || activeLogType === "both") && (
        <div className="admin-logs-section">
          <div className="admin-section-header">
            <h3><FaNetworkWired /> NGINX Request Logs</h3>
            <div className="admin-filter-container">
              <div className="admin-filter-input-group">
                <FaSearch className="admin-filter-icon" />
                <input
                  type="text"
                  value={nginxFilter}
                  onChange={(e) => setNginxFilter(e.target.value)}
                  placeholder="Filter by path, method, IP..."
                  className="admin-filter-input"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleNginxFilterApply();
                  }}
                />
                {nginxFilter && (
                  <button 
                    className="admin-clear-filter-btn"
                    onClick={clearNginxFilter}
                    title="Clear filter"
                  >
                    <FaTimes />
                  </button>
                )}
              </div>
              <button 
                className="admin-filter-btn" 
                onClick={handleNginxFilterApply}
              >
                <FaFilter /> Filter
              </button>
            </div>
          </div>
          
          {nginxLogsLoading && (
            <div className="admin-loading">
              <FaSpinner className="admin-spinner" />
              <p>Loading NGINX logs...</p>
            </div>
          )}
          
          {nginxLogsError && (
            <div className="admin-error-message">
              <FaExclamationTriangle /> Error: {nginxLogsError}
            </div>
          )}
          
          {!nginxLogsLoading && !nginxLogsError && (
            <div className="admin-data-table-container">
              <table className="admin-data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Bytes</th>
                  </tr>
                </thead>
                <tbody>
                  {nginxLogs.length > 0 ? (
                    nginxLogs.map((log, index) => (
                      <tr key={`nginx-${index}`}>
                        <td>{log.timestamp}</td>
                        <td>{log.ip}</td>
                        <td className={`method-${log.method.toLowerCase()}`}>{log.method}</td>
                        <td>{log.path}</td>
                        <td className={`status-${Math.floor(log.status / 100)}xx`}>{log.status}</td>
                        <td>{log.bytes}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="6" className="admin-no-data">No NGINX logs available</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default RequestLogsTab;
