// src/components/cracked/tabs/ActivityLogsTab.js
import React, { useState, useEffect } from 'react';
import { 
  FaShieldAlt, FaSpinner, FaExclamationTriangle, FaUserShield, 
  FaCheck, FaTimes, FaCalendarAlt, FaSearch, FaFilter, FaDownload, 
  FaUserSecret, FaNetworkWired, FaServer
} from 'react-icons/fa';
import { adminFetch } from '../csrfHelper';

const ActivityLogsTab = () => {
  // Regular failed login attempts logs
  const [regularLogs, setRegularLogs] = useState([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [logsError, setLogsError] = useState(null);
  const [filterText, setFilterText] = useState('');
  
  // Admin access logs
  const [adminLogs, setAdminLogs] = useState([]);
  const [adminLogsLoading, setAdminLogsLoading] = useState(false);
  const [adminLogsError, setAdminLogsError] = useState(null);
  
  // Fetch regular activity logs
  const fetchActivityLogs = async () => {
    setLogsLoading(true);
    setLogsError(null);
    
    try {
      const response = await adminFetch('/api/cracked/activity-logs');
      
      if (response.ok) {
        const data = await response.json();
        setRegularLogs(data.logs || []);
      } else {
        const errorData = await response.json();
        setLogsError(errorData.error || 'Failed to fetch activity logs');
      }
    } catch (err) {
      setLogsError('Network error while fetching logs');
      console.error('Error fetching activity logs:', err);
    } finally {
      setLogsLoading(false);
    }
  };
  
  // Fetch admin access logs
  const fetchAdminLogs = async () => {
    setAdminLogsLoading(true);
    setAdminLogsError(null);
    
    try {
      const response = await adminFetch('/api/cracked/admin-access-logs');
      
      if (response.ok) {
        const data = await response.json();
        setAdminLogs(data.logs || []);
      } else {
        const errorData = await response.json();
        setAdminLogsError(errorData.error || 'Failed to fetch admin access logs');
      }
    } catch (err) {
      setAdminLogsError('Network error while fetching admin logs');
      console.error('Error fetching admin logs:', err);
    } finally {
      setAdminLogsLoading(false);
    }
  };

  // Apply filter to logs
  const getFilteredLogs = () => {
    if (!filterText) return regularLogs;
    
    return regularLogs.filter(log => 
      (log.ip && log.ip.includes(filterText)) ||
      (log.reason && log.reason.toLowerCase().includes(filterText.toLowerCase())) ||
      (log.userId && log.userId.includes(filterText))
    );
  };
  
  // Export logs to CSV
  const exportLogsToCSV = () => {
    const csvContent = "data:text/csv;charset=utf-8," 
      + "Timestamp,IP,Status,User ID,Reason\n"
      + regularLogs.map(log => {
          return `${log.timestamp || ''},${log.ip || ''},"${log.success ? 'Success' : 'Failed'}",${log.userId || ''},"${log.reason || ''}"`;
        }).join("\n");
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `activity-logs-${new Date().toISOString().slice(0,10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Initialize data on component mount
  useEffect(() => {
    fetchActivityLogs();
    fetchAdminLogs();
  }, []);

  return (
    <div className="admin-tab-content activity-logs-tab">
      <div className="admin-content-header">
        <h2><FaShieldAlt /> Security & Activity Logs</h2>
        <div className="admin-header-actions">
          <div className="admin-search-box">
            <input
              type="text"
              placeholder="Filter logs..."
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
            />
            <FaSearch className="admin-search-icon" />
          </div>
          <button 
            className="admin-action-btn"
            onClick={exportLogsToCSV}
            title="Export logs to CSV"
          >
            <FaDownload /> Export
          </button>
        </div>
      </div>
      
      {/* Admin Access Logs Section */}
      <div className="admin-card">
        <div className="admin-card-header">
          <h3><FaUserShield /> Admin Access Logs</h3>
          <button 
            className="admin-refresh-btn" 
            onClick={fetchAdminLogs}
            disabled={adminLogsLoading}
          >
            {adminLogsLoading ? 
              <FaSpinner className="admin-spinner" /> : 
              <FaCalendarAlt />
            } Refresh
          </button>
        </div>

        {adminLogsError && (
          <div className="admin-error-message">
            <FaExclamationTriangle />
            <span>{adminLogsError}</span>
          </div>
        )}

        {adminLogsLoading && adminLogs.length === 0 ? (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading admin access logs...</p>
          </div>
        ) : (
          <div className="admin-table-responsive">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>IP Address</th>
                  <th>Status</th>
                  <th>Email</th>
                  <th>Provider</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {adminLogs.length > 0 ? (
                  adminLogs.map((log, index) => (
                    <tr key={index} className={log.success ? 'success-row' : 'error-row'}>
                      <td>{log.timestamp}</td>
                      <td>{log.ip}</td>
                      <td>
                        {log.success ? (
                          <span className="status-badge success">
                            <FaCheck /> Success
                          </span>
                        ) : (
                          <span className="status-badge error">
                            <FaTimes /> Failed
                          </span>
                        )}
                      </td>
                      <td>{log.email || 'N/A'}</td>
                      <td>{log.provider || 'Password'}</td>
                      <td>{log.reason || (log.success ? 'Successful login' : 'Login failed')}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="6" className="admin-empty-table">
                      No admin access logs found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
      
      {/* Regular Failed Login Attempts Section */}
      <div className="admin-card">
        <div className="admin-card-header">
          <h3><FaNetworkWired /> Failed Login Attempts</h3>
          <button 
            className="admin-refresh-btn" 
            onClick={fetchActivityLogs}
            disabled={logsLoading}
          >
            {logsLoading ? 
              <FaSpinner className="admin-spinner" /> : 
              <FaCalendarAlt />
            } Refresh
          </button>
        </div>
        
        {logsError && (
          <div className="admin-error-message">
            <FaExclamationTriangle />
            <span>{logsError}</span>
          </div>
        )}
        
        {logsLoading && regularLogs.length === 0 ? (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading activity logs...</p>
          </div>
        ) : (
          <div className="admin-table-responsive">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>IP Address</th>
                  <th>User ID</th>
                  <th>Failure Reason</th>
                </tr>
              </thead>
              <tbody>
                {getFilteredLogs().length > 0 ? (
                  getFilteredLogs().map((log, index) => (
                    <tr key={index} className="error-row">
                      <td>{log.timestamp}</td>
                      <td>{log.ip}</td>
                      <td>{log.userId || 'N/A'}</td>
                      <td>{log.reason || 'Unknown reason'}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="4" className="admin-empty-table">
                      {filterText ? 'No logs match your filter criteria' : 'No failed login attempts found'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
      
      {/* Security Stats Summary */}
      <div className="admin-stats-grid">
        <div className="admin-stat-card">
          <div className="admin-stat-icon">
            <FaUserSecret />
          </div>
          <div className="admin-stat-content">
            <div className="admin-stat-title">Total Failed Attempts</div>
            <div className="admin-stat-value">{regularLogs.length}</div>
          </div>
        </div>
        
        <div className="admin-stat-card">
          <div className="admin-stat-icon">
            <FaServer />
          </div>
          <div className="admin-stat-content">
            <div className="admin-stat-title">Admin Access Events</div>
            <div className="admin-stat-value">{adminLogs.length}</div>
          </div>
        </div>
        
        <div className="admin-stat-card">
          <div className="admin-stat-icon">
            <FaUserShield />
          </div>
          <div className="admin-stat-content">
            <div className="admin-stat-title">Unique IPs</div>
            <div className="admin-stat-value">
              {new Set([...regularLogs, ...adminLogs].map(log => log.ip)).size}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ActivityLogsTab;
