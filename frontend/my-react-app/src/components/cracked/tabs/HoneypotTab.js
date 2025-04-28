// src/components/cracked/tabs/HoneypotTab.js
import React, { useState, useEffect, useCallback } from "react";
import { 
  FaSpider, FaSync, FaSpinner, FaExclamationTriangle, FaFilter, 
  FaNetworkWired, FaGlobe, FaTimes, FaSort, FaDownload, FaChartBar,
  FaSortUp, FaSortDown, FaUserSecret, FaAngleRight, FaClock
} from "react-icons/fa";
import { adminFetch } from '../csrfHelper';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, 
  ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line 
} from 'recharts';

const HoneypotTab = () => {
  // State management
  const [honeypotData, setHoneypotData] = useState(null);
  const [detailedStats, setDetailedStats] = useState(null);
  const [interactions, setInteractions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(false);
  const [interactionsLoading, setInteractionsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState("");
  const [filterCategory, setFilterCategory] = useState("all");
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(20);
  const [totalInteractions, setTotalInteractions] = useState(0);
  const [sortField, setSortField] = useState("timestamp");
  const [sortOrder, setSortOrder] = useState("desc");
  const [selectedInteraction, setSelectedInteraction] = useState(null);
  const [viewMode, setViewMode] = useState("overview"); // overview, interactions, details

  // Chart colors
  const COLORS = ['#8884d8', '#82ca9d', '#ffc658', '#ff8042', '#a4de6c', '#d0ed57'];

  // Fetch main honeypot data
  const fetchHoneypotData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await adminFetch("/api/cracked/honeypot/analytics");
      if (!response.ok) {
        throw new Error("Failed to fetch honeypot analytics");
      }
      const data = await response.json();
      setHoneypotData(data);
      setTotalInteractions(data.total_attempts || 0);
    } catch (err) {
      console.error("Error fetching honeypot data:", err);
      setError(err.message || "Failed to fetch honeypot data");
    } finally {
      setLoading(false);
    }
  }, []);

  // Fetch detailed statistics
  const fetchDetailedStats = useCallback(async () => {
    setStatsLoading(true);
    try {
      const response = await adminFetch("/api/cracked/honeypot/detailed-stats");
      if (!response.ok) {
        throw new Error("Failed to fetch detailed statistics");
      }
      const data = await response.json();
      setDetailedStats(data);
    } catch (err) {
      console.error("Error fetching detailed stats:", err);
      // Don't set main error, just log it
    } finally {
      setStatsLoading(false);
    }
  }, []);

  // Fetch honeypot interactions with filtering, pagination and sorting
  const fetchInteractions = useCallback(async () => {
    setInteractionsLoading(true);
    try {
      const queryParams = new URLSearchParams({
        page,
        limit,
        sort_field: sortField,
        sort_order: sortOrder,
      });
      
      if (filter) {
        queryParams.append('filter', filter);
      }
      
      if (filterCategory !== "all") {
        queryParams.append('page_type', filterCategory);
      }
      
      const response = await adminFetch(`/api/cracked/honeypot/interactions?${queryParams.toString()}`);
      if (!response.ok) {
        throw new Error("Failed to fetch honeypot interactions");
      }
      const data = await response.json();
      setInteractions(data.interactions || []);
      setTotalInteractions(data.total || 0);
    } catch (err) {
      console.error("Error fetching interactions:", err);
      // Don't set main error, just log it
    } finally {
      setInteractionsLoading(false);
    }
  }, [page, limit, sortField, sortOrder, filter, filterCategory]);

  // Get detailed interaction info
  const fetchInteractionDetails = useCallback(async (id) => {
    try {
      const response = await adminFetch(`/api/cracked/honeypot/interactions/${id}`);
      if (!response.ok) {
        throw new Error("Failed to fetch interaction details");
      }
      const data = await response.json();
      setSelectedInteraction(data);
      setViewMode("details");
    } catch (err) {
      console.error("Error fetching interaction details:", err);
      // Show error in a toast or alert instead
    }
  }, []);

  // Initial data load
  useEffect(() => {
    fetchHoneypotData();
    fetchDetailedStats();
  }, [fetchHoneypotData, fetchDetailedStats]);

  // Fetch interactions when filter, sort, or pagination changes
  useEffect(() => {
    if (viewMode === "interactions") {
      fetchInteractions();
    }
  }, [fetchInteractions, viewMode, page, limit, sortField, sortOrder, filter, filterCategory]);

  // Handle filter changes
  const handleFilterChange = (e) => {
    setFilter(e.target.value);
  };

  // Apply filter
  const applyFilter = () => {
    setPage(1); // Reset to first page
    fetchInteractions();
  };

  // Clear filter
  const clearFilter = () => {
    setFilter("");
    setFilterCategory("all");
    setPage(1);
    fetchInteractions();
  };

  // Handle sort changes
  const handleSort = (field) => {
    if (sortField === field) {
      // Toggle order if same field
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      // New field, default to desc
      setSortField(field);
      setSortOrder("desc");
    }
  };

  // Format timestamp
  const formatTimestamp = (timestamp) => {
    if (!timestamp) return "Unknown";
    try {
      const date = new Date(timestamp);
      return date.toLocaleString();
    } catch (e) {
      return timestamp;
    }
  };

  // Export data as JSON
  const exportData = () => {
    try {
      // Create a blob with the JSON data
      const jsonData = JSON.stringify(interactions, null, 2);
      const blob = new Blob([jsonData], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      
      // Create a temporary link and trigger download
      const link = document.createElement("a");
      link.href = url;
      link.download = `honeypot-interactions-${new Date().toISOString()}.json`;
      document.body.appendChild(link);
      link.click();
      
      // Clean up
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Error exporting data:", err);
    }
  };

  // Render sort indicator
  const renderSortIndicator = (field) => {
    if (sortField !== field) return null;
    return sortOrder === "asc" ? <FaSortUp className="honeypot-sort-icon" /> : <FaSortDown className="honeypot-sort-icon" />;
  };

  // Handle pagination
  const handlePageChange = (newPage) => {
    setPage(newPage);
  };

  // Calculate statistics for overview charts
  const prepareChartData = () => {
    if (!honeypotData) return { pathData: [], ipData: [], timeData: [] };
    
    // Most accessed paths
    const pathData = honeypotData.top_paths.map(item => ({
      name: item._id.length > 20 ? item._id.substring(0, 20) + '...' : item._id,
      value: item.count,
      fullPath: item._id
    }));
    
    // Top source IPs
    const ipData = honeypotData.top_ips.map(item => ({
      name: item._id,
      value: item.count
    }));
    
    // Activity over time
    const timeData = [];
    // In a real implementation, this would process time-series data
    
    return { pathData, ipData, timeData };
  };

  // Render function for different views
  const renderContent = () => {
    if (loading && !honeypotData) {
      return (
        <div className="honeypot-loading-container">
          <FaSpinner className="honeypot-spinner" />
          <p>Loading honeypot data...</p>
        </div>
      );
    }

    if (error) {
      return (
        <div className="honeypot-error-message">
          <FaExclamationTriangle /> Error: {error}
          <button 
            className="honeypot-retry-btn" 
            onClick={fetchHoneypotData}
          >
            Retry
          </button>
        </div>
      );
    }

    // Different views based on viewMode
    switch (viewMode) {
      case "overview":
        return renderOverviewContent();
      case "interactions":
        return renderInteractionsContent();
      case "details":
        return renderDetailsContent();
      default:
        return renderOverviewContent();
    }
  };

  // Render overview dashboard
  const renderOverviewContent = () => {
    if (!honeypotData) return null;
    
    const { pathData, ipData, timeData } = prepareChartData();
    
    return (
      <div className="honeypot-overview-container">
        {/* Stats summary cards */}
        <div className="honeypot-stats-cards">
          <div className="honeypot-stat-card">
            <div className="honeypot-stat-icon">
              <FaSpider />
            </div>
            <div className="honeypot-stat-content">
              <div className="honeypot-stat-value">{honeypotData.total_attempts}</div>
              <div className="honeypot-stat-label">Total Interactions</div>
            </div>
          </div>
          
          <div className="honeypot-stat-card">
            <div className="honeypot-stat-icon">
              <FaGlobe />
            </div>
            <div className="honeypot-stat-content">
              <div className="honeypot-stat-value">{honeypotData.unique_ips}</div>
              <div className="honeypot-stat-label">Unique IPs</div>
            </div>
          </div>
          
          <div className="honeypot-stat-card">
            <div className="honeypot-stat-icon">
              <FaUserSecret />
            </div>
            <div className="honeypot-stat-content">
              <div className="honeypot-stat-value">{honeypotData.unique_clients}</div>
              <div className="honeypot-stat-label">Unique Clients</div>
            </div>
          </div>
          
          {detailedStats && (
            <div className="honeypot-stat-card">
              <div className="honeypot-stat-icon">
                <FaNetworkWired />
              </div>
              <div className="honeypot-stat-content">
                <div className="honeypot-stat-value">
                  {detailedStats.threats_detected || 0}
                </div>
                <div className="honeypot-stat-label">Threats Detected</div>
              </div>
            </div>
          )}
        </div>
        
        {/* Charts section */}
        <div className="honeypot-charts-container">
          {/* Top Paths Chart */}
          <div className="honeypot-chart-card">
            <h3 className="honeypot-chart-title">Most Targeted Paths</h3>
            <div className="honeypot-chart-content">
              <ResponsiveContainer width="100%" height={300}>
                <BarChart 
                  data={pathData} 
                  margin={{ top: 20, right: 30, left: 20, bottom: 70 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                  <XAxis 
                    dataKey="name" 
                    angle={-45} 
                    textAnchor="end"
                    tick={{fill: 'var(--admin-text-secondary)'}}
                    height={70}
                  />
                  <YAxis tick={{fill: 'var(--admin-text-secondary)'}} />
                  <Tooltip 
                    formatter={(value, name, props) => [value, 'Hits']}
                    labelFormatter={(label, props) => props[0].payload.fullPath}
                    contentStyle={{
                      backgroundColor: 'var(--admin-bg-card)',
                      border: '1px solid var(--admin-border)',
                      borderRadius: '8px'
                    }}
                  />
                  <Bar dataKey="value" fill="#8884d8" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
          
          {/* Top IPs Chart */}
          <div className="honeypot-chart-card">
            <h3 className="honeypot-chart-title">Source IPs</h3>
            <div className="honeypot-chart-content">
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={ipData}
                    cx="50%"
                    cy="50%"
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                    nameKey="name"
                    label={({name, percent}) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  >
                    {ipData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip 
                    formatter={(value) => [`${value} hits`, 'Count']}
                    contentStyle={{
                      backgroundColor: 'var(--admin-bg-card)',
                      border: '1px solid var(--admin-border)',
                      borderRadius: '8px'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
          
          {/* Activity over time chart - Only show if we have time data */}
          {timeData.length > 0 && (
            <div className="honeypot-chart-card honeypot-full-width">
              <h3 className="honeypot-chart-title">Activity Over Time</h3>
              <div className="honeypot-chart-content">
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart
                    data={timeData}
                    margin={{ top: 20, right: 30, left: 20, bottom: 20 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                      dataKey="time" 
                      tick={{fill: 'var(--admin-text-secondary)'}}
                    />
                    <YAxis tick={{fill: 'var(--admin-text-secondary)'}} />
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: 'var(--admin-bg-card)',
                        border: '1px solid var(--admin-border)',
                        borderRadius: '8px'
                      }}
                    />
                    <Legend />
                    <Line 
                      type="monotone" 
                      dataKey="interactions" 
                      stroke="#8884d8" 
                      activeDot={{ r: 8 }} 
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>
        
        {/* Recent Activity Table */}
        <div className="honeypot-recent-activity">
          <div className="honeypot-section-header">
            <h3>Recent Honeypot Activity</h3>
            <button 
              className="honeypot-view-all-btn"
              onClick={() => setViewMode("interactions")}
            >
              View All <FaAngleRight />
            </button>
          </div>
          
          <div className="honeypot-table-container">
            <table className="honeypot-data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>IP Address</th>
                  <th>Path</th>
                  <th>Type</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {honeypotData.recent_activity.slice(0, 10).map((activity, index) => (
                  <tr key={index} className="honeypot-activity-row">
                    <td>
                      <div className="honeypot-timestamp">
                        <FaClock className="honeypot-timestamp-icon" />
                        {formatTimestamp(activity.timestamp)}
                      </div>
                    </td>
                    <td>{activity.ip}</td>
                    <td className="honeypot-path-cell">{activity.path}</td>
                    <td>
                      <span className={`honeypot-type-badge ${activity.type || 'page_view'}`}>
                        {activity.interaction_type || "page_view"}
                      </span>
                    </td>
                    <td>
                      <button 
                        className="honeypot-action-btn"
                        onClick={() => fetchInteractionDetails(activity._id)}
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  // Render interactions list view
  const renderInteractionsContent = () => {
    return (
      <div className="honeypot-interactions-container">
        <div className="honeypot-interactions-header">
          <h3 className="honeypot-interactions-title">Honeypot Interactions</h3>
          <div className="honeypot-interactions-actions">
            <button 
              className="honeypot-back-btn" 
              onClick={() => setViewMode("overview")}
            >
              Back to Overview
            </button>
            <button 
              className="honeypot-export-btn" 
              onClick={exportData}
            >
              <FaDownload /> Export Data
            </button>
          </div>
        </div>
        
        {/* Filters */}
        <div className="honeypot-filter-section">
          <div className="honeypot-filter-container">
            <div className="honeypot-filter-field">
              <label>Filter By:</label>
              <div className="honeypot-filter-input-wrapper">
                <FaFilter className="honeypot-filter-icon" />
                <input 
                  type="text" 
                  className="honeypot-filter-input" 
                  placeholder="IP, path, user agent..." 
                  value={filter}
                  onChange={handleFilterChange}
                  onKeyDown={(e) => e.key === 'Enter' && applyFilter()}
                />
                {filter && (
                  <button 
                    className="honeypot-clear-filter-btn" 
                    onClick={clearFilter}
                  >
                    <FaTimes />
                  </button>
                )}
              </div>
              <button 
                className="honeypot-apply-filter-btn" 
                onClick={applyFilter}
              >
                Apply Filter
              </button>
            </div>
            
            <div className="honeypot-filter-field">
              <label>Category:</label>
              <select 
                className="honeypot-filter-select"
                value={filterCategory}
                onChange={(e) => setFilterCategory(e.target.value)}
              >
                <option value="all">All Categories</option>
                <option value="admin_panel">Admin Panel</option>
                <option value="wordpress">WordPress</option>
                <option value="phpmyadmin">phpMyAdmin</option>
                <option value="cpanel">cPanel</option>
                {/* Add other categories as needed */}
              </select>
            </div>
          </div>
          
          <div className="honeypot-results-info">
            Showing {interactions.length} of {totalInteractions} interactions
          </div>
        </div>
        
        {/* Interactions Table */}
        <div className="honeypot-interactions-table-container">
          {interactionsLoading ? (
            <div className="honeypot-loading-container">
              <FaSpinner className="honeypot-spinner" />
              <p>Loading interactions...</p>
            </div>
          ) : interactions.length > 0 ? (
            <>
              <table className="honeypot-data-table">
                <thead>
                  <tr>
                    <th 
                      className="honeypot-sortable-header" 
                      onClick={() => handleSort("timestamp")}
                    >
                      Time {renderSortIndicator("timestamp")}
                    </th>
                    <th 
                      className="honeypot-sortable-header" 
                      onClick={() => handleSort("ip_address")}
                    >
                      IP Address {renderSortIndicator("ip_address")}
                    </th>
                    <th 
                      className="honeypot-sortable-header" 
                      onClick={() => handleSort("page_type")}
                    >
                      Page Type {renderSortIndicator("page_type")}
                    </th>
                    <th 
                      className="honeypot-sortable-header" 
                      onClick={() => handleSort("interaction_type")}
                    >
                      Interaction {renderSortIndicator("interaction_type")}
                    </th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {interactions.map((interaction, index) => (
                    <tr key={index} className="honeypot-interaction-row">
                      <td>
                        <div className="honeypot-timestamp">
                          <FaClock className="honeypot-timestamp-icon" />
                          {formatTimestamp(interaction.timestamp)}
                        </div>
                      </td>
                      <td>{interaction.ip_address}</td>
                      <td>
                        <span className={`honeypot-page-type-badge ${interaction.page_type}`}>
                          {interaction.page_type}
                        </span>
                      </td>
                      <td>
                        <span className={`honeypot-interaction-type-badge ${interaction.interaction_type}`}>
                          {interaction.interaction_type}
                        </span>
                      </td>
                      <td>
                        <button 
                          className="honeypot-view-details-btn"
                          onClick={() => fetchInteractionDetails(interaction._id)}
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              
              {/* Pagination */}
              <div className="honeypot-pagination">
                <button 
                  className="honeypot-page-btn" 
                  disabled={page === 1}
                  onClick={() => handlePageChange(1)}
                >
                  First
                </button>
                <button 
                  className="honeypot-page-btn" 
                  disabled={page === 1}
                  onClick={() => handlePageChange(page - 1)}
                >
                  Previous
                </button>
                
                <span className="honeypot-page-info">
                  Page {page} of {Math.ceil(totalInteractions / limit)}
                </span>
                
                <button 
                  className="honeypot-page-btn" 
                  disabled={page >= Math.ceil(totalInteractions / limit)}
                  onClick={() => handlePageChange(page + 1)}
                >
                  Next
                </button>
                <button 
                  className="honeypot-page-btn" 
                  disabled={page >= Math.ceil(totalInteractions / limit)}
                  onClick={() => handlePageChange(Math.ceil(totalInteractions / limit))}
                >
                  Last
                </button>
                
                <select 
                  className="honeypot-limit-select"
                  value={limit}
                  onChange={(e) => setLimit(Number(e.target.value))}
                >
                  <option value="10">10 per page</option>
                  <option value="20">20 per page</option>
                  <option value="50">50 per page</option>
                  <option value="100">100 per page</option>
                </select>
              </div>
            </>
          ) : (
            <div className="honeypot-no-data">
              No interactions found matching your criteria.
            </div>
          )}
        </div>
      </div>
    );
  };

  // Render detailed view of a single interaction
  const renderDetailsContent = () => {
    if (!selectedInteraction) {
      return (
        <div className="honeypot-no-selection">
          <p>No interaction selected.</p>
          <button 
            className="honeypot-back-btn"
            onClick={() => setViewMode("interactions")}
          >
            Back to Interactions
          </button>
        </div>
      );
    }
    
    return (
      <div className="honeypot-details-container">
        <div className="honeypot-details-header">
          <h3 className="honeypot-details-title">
            Interaction Details
          </h3>
          <div className="honeypot-details-actions">
            <button 
              className="honeypot-back-btn"
              onClick={() => setViewMode("interactions")}
            >
              Back to Interactions
            </button>
          </div>
        </div>
        
        {/* Interaction metadata */}
        <div className="honeypot-details-meta">
          <div className="honeypot-meta-item">
            <span className="honeypot-meta-label">Timestamp:</span>
            <span className="honeypot-meta-value">
              {formatTimestamp(selectedInteraction.timestamp)}
            </span>
          </div>
          <div className="honeypot-meta-item">
            <span className="honeypot-meta-label">IP Address:</span>
            <span className="honeypot-meta-value">
              {selectedInteraction.ip_address}
            </span>
          </div>
          <div className="honeypot-meta-item">
            <span className="honeypot-meta-label">Page Type:</span>
            <span className="honeypot-meta-value">
              <span className={`honeypot-page-type-badge ${selectedInteraction.page_type}`}>
                {selectedInteraction.page_type}
              </span>
            </span>
          </div>
          <div className="honeypot-meta-item">
            <span className="honeypot-meta-label">Interaction Type:</span>
            <span className="honeypot-meta-value">
              <span className={`honeypot-interaction-type-badge ${selectedInteraction.interaction_type}`}>
                {selectedInteraction.interaction_type}
              </span>
            </span>
          </div>
        </div>
        
        {/* Tabs for different data sections */}
        <div className="honeypot-details-tabs">
          <button className="honeypot-details-tab-btn active">
            Overview
          </button>
          <button className="honeypot-details-tab-btn">
            Headers
          </button>
          <button className="honeypot-details-tab-btn">
            Additional Data
          </button>
          <button className="honeypot-details-tab-btn">
            Raw JSON
          </button>
        </div>
        
        {/* Details content */}
        <div className="honeypot-details-content">
          <div className="honeypot-details-section">
            <h4 className="honeypot-section-title">Browser Information</h4>
            <div className="honeypot-details-table-container">
              <table className="honeypot-details-table">
                <tbody>
                  <tr>
                    <td>User Agent</td>
                    <td>{selectedInteraction.user_agent}</td>
                  </tr>
                  <tr>
                    <td>Referer</td>
                    <td>{selectedInteraction.referer || "None"}</td>
                  </tr>
                  {selectedInteraction.headers && (
                    <>
                      <tr>
                        <td>Accept</td>
                        <td>{selectedInteraction.headers.Accept || "Not provided"}</td>
                      </tr>
                      <tr>
                        <td>Accept-Language</td>
                        <td>{selectedInteraction.headers["Accept-Language"] || "Not provided"}</td>
                      </tr>
                    </>
                  )}
                </tbody>
              </table>
            </div>
          </div>
          
          {/* Additional Data Section */}
          {selectedInteraction.additional_data && (
            <div className="honeypot-details-section">
              <h4 className="honeypot-section-title">Additional Data</h4>
              <div className="honeypot-details-json">
                <pre>{JSON.stringify(selectedInteraction.additional_data, null, 2)}</pre>
              </div>
            </div>
          )}
          
          {/* Raw JSON Viewer */}
          <div className="honeypot-details-section">
            <h4 className="honeypot-section-title">Raw JSON Data</h4>
            <div className="honeypot-details-json">
              <pre>{JSON.stringify(selectedInteraction, null, 2)}</pre>
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="admin-tab-content honeypot-tab">
      <div className="admin-content-header">
        <h2><FaSpider /> Honeypot Dashboard</h2>
        <div className="honeypot-header-actions">
          <button 
            className="honeypot-action-btn"
            onClick={() => setViewMode("overview")}
            disabled={viewMode === "overview"}
          >
            <FaChartBar /> Overview
          </button>
          <button 
            className="honeypot-action-btn"
            onClick={() => {
              setViewMode("interactions");
              fetchInteractions();
            }}
            disabled={viewMode === "interactions"}
          >
            <FaSpider /> Interactions
          </button>
          <button 
            className="honeypot-refresh-btn" 
            onClick={() => {
              fetchHoneypotData();
              fetchDetailedStats();
              if (viewMode === "interactions") {
                fetchInteractions();
              }
            }}
            disabled={loading}
          >
            {loading ? <FaSpinner className="honeypot-spinner" /> : <FaSync />} Refresh
          </button>
        </div>
      </div>
      
      {renderContent()}
    </div>
  );
};

export default HoneypotTab;
