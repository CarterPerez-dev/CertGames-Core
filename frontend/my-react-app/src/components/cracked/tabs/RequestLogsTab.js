// src/components/cracked/tabs/RequestLogsTab.js (renamed from DbLogsTab.js)
import React, { useState, useEffect, useCallback } from "react";
import {
  FaClipboardList, FaSync, FaSpinner, FaExclamationTriangle,
  FaFilter, FaServer, FaTimes, FaSearch
} from "react-icons/fa";
import { adminFetch } from '../csrfHelper';

const RequestLogsTab = () => {
  // State for API logs
  const [apiLogs, setApiLogs] = useState([]);
  const [apiLogsLoading, setApiLogsLoading] = useState(false);
  const [apiLogsError, setApiLogsError] = useState(null);
  const [apiFilter, setApiFilter] = useState("");
  const [appliedApiFilter, setAppliedApiFilter] = useState("");

  // Polling interval for auto-refresh (in milliseconds)
  const POLLING_INTERVAL = 80000; // 80 seconds, adjusted from original 10 sec comment

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

  // Initial fetch
  useEffect(() => {
    fetchApiLogs();
  }, [fetchApiLogs]);

  // Set up polling
  useEffect(() => {
    const interval = setInterval(() => {
      fetchApiLogs();
    }, POLLING_INTERVAL);

    return () => clearInterval(interval);
  }, [fetchApiLogs]);

  // Handle API filter apply
  const handleApiFilterApply = () => {
    setAppliedApiFilter(apiFilter);
  };

  // Clear filters
  const clearApiFilter = () => {
    setApiFilter("");
    setAppliedApiFilter("");
  };

  return (
    <div className="admin-tab-content request-logs-tab">
      <div className="admin-content-header">
        <h2><FaClipboardList /> Request Logs Monitor</h2>
        <div className="admin-refresh-actions">
          <button
            className="admin-refresh-btn"
            onClick={() => {
              fetchApiLogs();
            }}
          >
            <FaSync /> Refresh Logs
          </button>
        </div>
      </div>

      {/* API Logs Section */}
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
    </div>
  );
};

export default RequestLogsTab;
