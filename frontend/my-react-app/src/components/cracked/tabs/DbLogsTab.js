// src/components/cracked/tabs/DbLogsTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaDatabase, FaSync, FaSpinner, FaExclamationTriangle
} from "react-icons/fa";

const DbLogsTab = () => {
  const [dbLogs, setDbLogs] = useState([]);
  const [dbLogsLoading, setDbLogsLoading] = useState(false);
  const [dbLogsError, setDbLogsError] = useState(null);
  
  const fetchDbLogs = useCallback(async () => {
    setDbLogsLoading(true);
    setDbLogsError(null);
    try {
      const res = await fetch("/api/cracked/db-logs", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch DB logs");
      }
      setDbLogs(data);
    } catch (err) {
      setDbLogsError(err.message);
    } finally {
      setDbLogsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDbLogs();
  }, [fetchDbLogs]);

  return (
    <div className="admin-tab-content db-logs-tab">
      <div className="admin-content-header">
        <h2><FaDatabase /> Database Query Logs</h2>
        <button className="admin-refresh-btn" onClick={fetchDbLogs}>
          <FaSync /> Refresh Logs
        </button>
      </div>

      {dbLogsLoading && (
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading database logs...</p>
        </div>
      )}

      {dbLogsError && (
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {dbLogsError}
        </div>
      )}

      <div className="admin-data-table-container">
        <table className="admin-data-table">
          <thead>
            <tr>
              <th>Timestamp (EST)</th>
              <th>Route</th>
              <th>Method</th>
              <th>Duration (ms)</th>
              <th>DB Time (ms)</th>
              <th>Status</th>
              <th>Bytes</th>
            </tr>
          </thead>
          <tbody>
            {dbLogs.map((log, index) => (
              <tr key={log._id || index} className={log.http_status >= 400 ? "error-row" : ""}>
                <td>{log.timestamp}</td>
                <td>{log.route}</td>
                <td>{log.method}</td>
                <td>{log.duration_ms}</td>
                <td>{log.db_time_ms}</td>
                <td>
                  <span className={log.http_status >= 400 ? "status-error" : "status-success"}>
                    {log.http_status}
                  </span>
                </td>
                <td>{log.response_bytes}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default DbLogsTab;
