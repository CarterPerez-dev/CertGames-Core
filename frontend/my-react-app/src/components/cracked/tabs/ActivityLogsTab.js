// src/components/cracked/tabs/ActivityLogsTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaHistory, FaSync, FaSpinner, FaExclamationTriangle
} from "react-icons/fa";

const ActivityLogsTab = () => {
  const [activityLogs, setActivityLogs] = useState([]);
  const [activityLoading, setActivityLoading] = useState(false);
  const [activityError, setActivityError] = useState(null);
  
  const fetchActivityLogs = useCallback(async () => {
    setActivityLoading(true);
    setActivityError(null);
    try {
      const res = await fetch("/api/cracked/activity-logs", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch activity logs");
      }
      if (data.logs) {
        setActivityLogs(data.logs);
      }
    } catch (err) {
      setActivityError(err.message);
    } finally {
      setActivityLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchActivityLogs();
  }, [fetchActivityLogs]);

  return (
    <div className="admin-tab-content activity-tab">
      <div className="admin-content-header">
        <h2><FaHistory /> Activity & Audit Logs</h2>
        <button className="admin-refresh-btn" onClick={fetchActivityLogs}>
          <FaSync /> Refresh Logs
        </button>
      </div>

      {activityLoading && (
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading activity logs...</p>
        </div>
      )}

      {activityError && (
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {activityError}
        </div>
      )}

      <div className="admin-data-table-container">
        <table className="admin-data-table">
          <thead>
            <tr>
              <th>Timestamp (EST)</th>
              <th>IP</th>
              <th>User ID</th>
              <th>Success</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {activityLogs.map((log) => (
              <tr key={log._id} className={log.success ? "" : "error-row"}>
                <td>{log.timestamp}</td>
                <td>{log.ip}</td>
                <td>{log.userId || ""}</td>
                <td>
                  <span className={log.success ? "status-success" : "status-error"}>
                    {log.success ? "Yes" : "No"}
                  </span>
                </td>
                <td>{log.reason || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ActivityLogsTab;
