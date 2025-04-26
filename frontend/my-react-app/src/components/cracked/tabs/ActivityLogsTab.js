// Updated ActivityLogsTab.js
import React, { useState, useEffect, useCallback } from "react";
import { FaShieldAlt, FaUserSecret, FaExclamationTriangle, FaSpinner, FaSearch } from "react-icons/fa";
import { adminFetch } from "../csrfHelper";

const AdminAccessLogSection = () => {
  const [adminLogs, setAdminLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [filterText, setFilterText] = useState("");

  const fetchAdminAccessLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await adminFetch("/api/cracked/admin-access-logs");
      if (!response.ok) {
        throw new Error("Failed to fetch admin access logs");
      }
      const data = await response.json();
      setAdminLogs(data.logs || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAdminAccessLogs();
  }, []);

  const filteredLogs = adminLogs.filter(log => {
    if (!filterText) return true;
    const searchText = filterText.toLowerCase();
    return (
      (log.ip && log.ip.toLowerCase().includes(searchText)) ||
      (log.email && log.email.toLowerCase().includes(searchText)) ||
      (log.reason && log.reason.toLowerCase().includes(searchText)) ||
      (log.timestamp && log.timestamp.toLowerCase().includes(searchText))
    );
  });

  return (
    <div className="admin-section admin-access-logs">
      <div className="admin-section-header">
        <h3><FaUserSecret /> Admin Access Logs</h3>
        <div className="admin-filter">
          <input
            type="text"
            placeholder="Filter logs..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
          />
          <button onClick={fetchAdminAccessLogs} className="admin-refresh-btn">
            <FaSearch />
          </button>
        </div>
      </div>

      {loading && (
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading access logs...</p>
        </div>
      )}

      {error && (
        <div className="admin-error">
          <FaExclamationTriangle />
          <p>{error}</p>
        </div>
      )}

      <div className="admin-logs-table">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>IP Address</th>
              <th>Email</th>
              <th>Status</th>
              <th>Reason</th>
              <th>Provider</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length > 0 ? (
              filteredLogs.map((log, index) => (
                <tr key={index} className={log.success ? "success-row" : "failure-row"}>
                  <td>{log.timestamp}</td>
                  <td>{log.ip || "N/A"}</td>
                  <td>{log.email || "N/A"}</td>
                  <td>
                    {log.success ? (
                      <span className="success-status">Success</span>
                    ) : (
                      <span className="failure-status">Failed</span>
                    )}
                  </td>
                  <td>{log.reason || "N/A"}</td>
                  <td>{log.provider || "Direct"}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="6" className="no-data">
                  No access logs found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ActivityLogsTab;
