// src/components/cracked/tabs/RateLimitsTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaThermometerThreeQuarters, FaSync, FaSpinner, FaExclamationTriangle,
  FaFilter, FaTimesCircle, FaCheckCircle, FaExclamationCircle, FaClock
} from "react-icons/fa";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, 
  Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell
} from "recharts";
import { adminFetch } from '../csrfHelper';

const RateLimitsTab = () => {
  const [rateLimits, setRateLimits] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [filterText, setFilterText] = useState("");
  const [filteredLimits, setFilteredLimits] = useState([]);
  const [activeEndpoint, setActiveEndpoint] = useState("all");

  // Define colors for charts
  const COLORS = {
    safe: "#82ca9d",
    warning: "#ffc658",
    danger: "#ff8042",
    primary: "#8884d8"
  };

  // For the pie charts
  const PIE_COLORS = ["#8884d8", "#82ca9d", "#ffc658", "#ff8042", "#8dd1e1"];

  // Function to fetch rate limits
  const fetchRateLimits = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/cracked/rate-limits", {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch rate limits data");
      }
      
      setRateLimits(data);
      // Initially, no filter, so all results
      applyFilter(data.rate_limits, filterText);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [filterText]);

  // Apply filter to rate limits
  const applyFilter = (limits, text) => {
    if (!text) {
      setFilteredLimits(limits);
      return;
    }
    
    const lowercaseFilter = text.toLowerCase();
    const filtered = limits.filter(limit => 
      (limit.userId && limit.userId.toLowerCase().includes(lowercaseFilter)) ||
      (limit.endpoint && limit.endpoint.toLowerCase().includes(lowercaseFilter))
    );
    
    setFilteredLimits(filtered);
  };

  // Initial fetch
  useEffect(() => {
    fetchRateLimits();
    // Refresh data every 30 seconds
    const interval = setInterval(fetchRateLimits, 30000);
    return () => clearInterval(interval);
  }, [fetchRateLimits]);

  // Filter handler
  const handleFilterChange = (e) => {
    const filterValue = e.target.value;
    setFilterText(filterValue);
    
    if (rateLimits && rateLimits.rate_limits) {
      applyFilter(rateLimits.rate_limits, filterValue);
    }
  };

  // Clear filter
  const clearFilter = () => {
    setFilterText("");
    if (rateLimits && rateLimits.rate_limits) {
      setFilteredLimits(rateLimits.rate_limits);
    }
  };

  // Switch between endpoints
  const switchEndpoint = (endpoint) => {
    setActiveEndpoint(endpoint);
    
    // Filter results by endpoint if not "all"
    if (rateLimits && rateLimits.rate_limits) {
      if (endpoint === "all") {
        applyFilter(rateLimits.rate_limits, filterText);
      } else {
        const endpointLimits = rateLimits.rate_limits.filter(limit => 
          limit.endpoint === endpoint
        );
        applyFilter(endpointLimits, filterText);
      }
    }
  };

  // Get status color based on usage percentage
  const getStatusColor = (percentage) => {
    if (percentage < 50) return COLORS.safe;
    if (percentage < 80) return COLORS.warning;
    return COLORS.danger;
  };

  // Get status icon based on usage percentage
  const getStatusIcon = (percentage) => {
    if (percentage < 50) return <FaCheckCircle className="status-icon status-safe" />;
    if (percentage < 80) return <FaExclamationCircle className="status-icon status-warning" />;
    return <FaTimesCircle className="status-icon status-danger" />;
  };

  // Format timestamp
  const formatTimestamp = (timestamp) => {
    if (!timestamp) return "N/A";
    
    try {
      const date = new Date(timestamp);
      return date.toLocaleString();
    } catch (e) {
      return timestamp;
    }
  };

  return (
    <div className="admin-tab-content rate-limits-tab">
      <div className="admin-content-header">
        <h2><FaThermometerThreeQuarters /> Rate Limits Monitor</h2>
        <div className="admin-refresh-btn-container">
          <button 
            className="admin-refresh-btn" 
            onClick={fetchRateLimits}
            disabled={loading}
          >
            {loading ? <FaSpinner className="admin-spinner" /> : <FaSync />} Refresh Data
          </button>
        </div>
      </div>

      {error && (
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {error}
        </div>
      )}

      {rateLimits && (
        <>
          {/* Endpoint Summary */}
          <div className="admin-rate-limit-summary">
            <h3>Endpoint Usage Summary</h3>
            <div className="admin-endpoint-cards">
              <div 
                className={`admin-endpoint-card ${activeEndpoint === 'all' ? 'active' : ''}`}
                onClick={() => switchEndpoint('all')}
              >
                <div className="admin-endpoint-card-title">All Endpoints</div>
                <div className="admin-endpoint-card-stats">
                  <div className="admin-endpoint-stat">
                    <span className="admin-stat-value">
                      {rateLimits.endpoint_summary.reduce((sum, endpoint) => sum + endpoint.total_users, 0)}
                    </span>
                    <span className="admin-stat-label">Users</span>
                  </div>
                  <div className="admin-endpoint-stat">
                    <span className="admin-stat-value">
                      {rateLimits.endpoint_summary.reduce((sum, endpoint) => sum + endpoint.recent_calls, 0)}
                    </span>
                    <span className="admin-stat-label">Recent Calls</span>
                  </div>
                </div>
              </div>

              {rateLimits.endpoint_summary.map((endpoint) => (
                <div 
                  key={endpoint.endpoint}
                  className={`admin-endpoint-card ${activeEndpoint === endpoint.endpoint ? 'active' : ''}`}
                  onClick={() => switchEndpoint(endpoint.endpoint)}
                >
                  <div className="admin-endpoint-card-title">{endpoint.endpoint}</div>
                  <div className="admin-endpoint-card-usage">
                    <div 
                      className="admin-usage-bar" 
                      style={{ 
                        width: `${Math.min(100, endpoint.usage_percent)}%`,
                        backgroundColor: getStatusColor(endpoint.usage_percent)
                      }}
                    ></div>
                    <span className="admin-usage-text">{endpoint.usage_percent.toFixed(1)}%</span>
                  </div>
                  <div className="admin-endpoint-card-stats">
                    <div className="admin-endpoint-stat">
                      <span className="admin-stat-value">{endpoint.total_users}</span>
                      <span className="admin-stat-label">Users</span>
                    </div>
                    <div className="admin-endpoint-stat">
                      <span className="admin-stat-value">{endpoint.recent_calls}</span>
                      <span className="admin-stat-label">Recent Calls</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Usage Chart */}
          <div className="admin-rate-limit-chart">
            <h3>API Usage by Endpoint</h3>
            <div className="admin-chart-container">
              <ResponsiveContainer width="100%" height={300}>
                <BarChart
                  data={rateLimits.endpoint_summary}
                  margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                  <XAxis 
                    dataKey="endpoint" 
                    tick={{fill: 'var(--admin-text-secondary)'}}
                  />
                  <YAxis 
                    tick={{fill: 'var(--admin-text-secondary)'}}
                  />
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'var(--admin-bg-card)',
                      border: '1px solid var(--admin-border)',
                      borderRadius: '8px'
                    }}
                    labelStyle={{color: 'var(--admin-text)'}}
                    itemStyle={{color: 'var(--admin-text)'}}
                  />
                  <Legend />
                  <Bar 
                    dataKey="recent_calls" 
                    name="Recent Calls" 
                    fill={COLORS.primary} 
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Usage Distribution */}
          <div className="admin-rate-limit-distribution">
            <h3>Usage Distribution</h3>
            <div className="admin-chart-container">
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={rateLimits.endpoint_summary}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    outerRadius={120}
                    fill="#8884d8"
                    dataKey="recent_calls"
                    nameKey="endpoint"
                    label={({name, percent}) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  >
                    {rateLimits.endpoint_summary.map((entry, index) => (
                      <Cell 
                        key={`cell-${index}`} 
                        fill={PIE_COLORS[index % PIE_COLORS.length]} 
                      />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'var(--admin-bg-card)',
                      border: '1px solid var(--admin-border)',
                      borderRadius: '8px'
                    }}
                    labelStyle={{color: 'var(--admin-text)'}}
                    itemStyle={{color: 'var(--admin-text)'}}
                    formatter={(value, name, props) => [`${value} calls`, props.payload.endpoint]}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Rate Limits Table */}
          <div className="admin-rate-limits-table-section">
            <h3>Rate Limits by User</h3>
            <div className="admin-filter-container">
              <div className="admin-filter-input-wrapper">
                <FaFilter className="admin-filter-icon" />
                <input
                  type="text"
                  className="admin-filter-input"
                  placeholder="Filter by user or endpoint..."
                  value={filterText}
                  onChange={handleFilterChange}
                />
                {filterText && (
                  <button 
                    className="admin-clear-filter-btn"
                    onClick={clearFilter}
                    title="Clear filter"
                  >
                    <FaTimesCircle />
                  </button>
                )}
              </div>
            </div>
            <div className="admin-data-table-container">
              <table className="admin-data-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Endpoint</th>
                    <th>Recent Calls</th>
                    <th>Limit</th>
                    <th>Usage</th>
                    <th>Last Used</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLimits.map((limit, index) => (
                    <tr key={index}>
                      <td>{limit.userId}</td>
                      <td>{limit.endpoint}</td>
                      <td>{limit.recent_calls}</td>
                      <td>{limit.limit} per {limit.period_minutes} min</td>
                      <td>
                        <div className="admin-usage-progress">
                          <div 
                            className="admin-usage-bar" 
                            style={{ 
                              width: `${Math.min(100, limit.usage_percent)}%`,
                              backgroundColor: getStatusColor(limit.usage_percent)
                            }}
                          ></div>
                          <span className="admin-usage-text">{limit.usage_percent.toFixed(1)}%</span>
                        </div>
                      </td>
                      <td>
                        <div className="admin-timestamp">
                          <FaClock className="admin-timestamp-icon" />
                          <span>{formatTimestamp(limit.last_used)}</span>
                        </div>
                      </td>
                      <td className="admin-status-cell">
                        {getStatusIcon(limit.usage_percent)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {loading && !rateLimits && (
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading rate limits data...</p>
        </div>
      )}
    </div>
  );
};

export default RateLimitsTab;
