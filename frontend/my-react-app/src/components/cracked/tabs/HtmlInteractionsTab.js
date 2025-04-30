// src/components/cracked/tabs/HtmlInteractionsTab.js
import React, { useState, useEffect, useCallback } from "react";
import { 
  FaCode, FaSync, FaSpinner, FaExclamationTriangle, 
  FaFilter, FaSearch, FaTable, FaChartBar, FaDownload, 
  FaAngleRight, FaClock, FaLocationArrow, FaFingerprint, 
  FaUser, FaKey, FaShieldAlt, FaSortUp, FaSortDown, FaSort
} from "react-icons/fa";
import { adminFetch } from '../csrfHelper';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, 
  ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line 
} from 'recharts';

const HtmlInteractionsTab = () => {
  // State management
  const [interactions, setInteractions] = useState([]);
  const [stats, setStats] = useState(null);
  const [selectedInteraction, setSelectedInteraction] = useState(null);
  const [loading, setLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [viewMode, setViewMode] = useState("overview"); // overview, interactions, details
  
  // Filter states
  const [pageType, setPageType] = useState("all");
  const [interactionType, setInteractionType] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [pageTypes, setPageTypes] = useState([]);
  const [interactionTypes, setInteractionTypes] = useState([]);
  
  // Pagination states
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(20);
  const [total, setTotal] = useState(0);
  
  // Sorting states
  const [sortField, setSortField] = useState("timestamp");
  const [sortOrder, setSortOrder] = useState("desc");
  
  // Custom colors for charts
  const COLORS = ['#8884d8', '#82ca9d', '#ffc658', '#ff8042', '#a4de6c', '#d0ed57'];

  // Fetch interactions with filters and pagination
  const fetchInteractions = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const queryParams = new URLSearchParams({
        page,
        limit,
        page_type: pageType !== "all" ? pageType : "",
        interaction_type: interactionType !== "all" ? interactionType : "",
        search: searchTerm,
      });
      
      const response = await adminFetch(`/api/honeypot/html-interactions?${queryParams.toString()}`);
      
      if (!response.ok) {
        throw new Error("Failed to fetch interactions");
      }
      
      const data = await response.json();
      
      setInteractions(data.interactions || []);
      setTotal(data.total || 0);
      setPageTypes(data.page_types || []);
      setInteractionTypes(data.interaction_types || []);
      
    } catch (err) {
      console.error("Error fetching interactions:", err);
      setError(err.message || "Failed to fetch interactions");
    } finally {
      setLoading(false);
    }
  }, [page, limit, pageType, interactionType, searchTerm]);

  // Fetch statistics
  const fetchStats = useCallback(async () => {
    setStatsLoading(true);
    
    try {
      const response = await adminFetch("/api/honeypot/html-interactions/stats");
      
      if (!response.ok) {
        throw new Error("Failed to fetch statistics");
      }
      
      const data = await response.json();
      setStats(data);
      
    } catch (err) {
      console.error("Error fetching statistics:", err);
      // Don't set main error, just log it
    } finally {
      setStatsLoading(false);
    }
  }, []);

  // Fetch interaction details
  const fetchInteractionDetails = useCallback(async (id) => {
    setLoading(true);
    
    try {
      const response = await adminFetch(`/api/honeypot/html-interactions/${id}`);
      
      if (!response.ok) {
        throw new Error("Failed to fetch interaction details");
      }
      
      const data = await response.json();
      
      setSelectedInteraction(data);
      setViewMode("details");
      
    } catch (err) {
      console.error("Error fetching interaction details:", err);
      alert("Error loading details: " + (err.message || "Unknown error"));
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial data load
  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  // Fetch interactions when filter, pagination changes
  useEffect(() => {
    if (viewMode === "interactions") {
      fetchInteractions();
    }
  }, [fetchInteractions, viewMode, page, limit]);

  // Apply filters
  const applyFilters = () => {
    setPage(1); // Reset to first page
    fetchInteractions();
  };

  // Handle search
  const handleSearch = (e) => {
    if (e.key === 'Enter') {
      applyFilters();
    }
  };

  // Reset filters
  const resetFilters = () => {
    setPageType("all");
    setInteractionType("all");
    setSearchTerm("");
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
    
    // Refetch with new sort
    fetchInteractions();
  };

  // Render sort indicator
  const renderSortIndicator = (field) => {
    if (sortField !== field) return <FaSort className="html-sort-icon" />;
    return sortOrder === "asc" ? <FaSortUp className="html-sort-icon" /> : <FaSortDown className="html-sort-icon" />;
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
      link.download = `html-interactions-${new Date().toISOString()}.json`;
      document.body.appendChild(link);
      link.click();
      
      // Clean up
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Error exporting data:", err);
    }
  };

  // Render function for different views
  const renderContent = () => {
    if (loading && !interactions.length && !stats) {
      return (
        <div className="html-loading-container">
          <FaSpinner className="html-spinner" />
          <p>Loading data...</p>
        </div>
      );
    }

    if (error) {
      return (
        <div className="html-error-message">
          <FaExclamationTriangle /> Error: {error}
          <button 
            className="html-retry-btn" 
            onClick={() => {
              fetchStats();
              if (viewMode === "interactions") fetchInteractions();
            }}
          >
            Retry
          </button>
        </div>
      );
    }

    switch (viewMode) {
      case "overview":
        return renderOverview();
      case "interactions":
        return renderInteractionsList();
      case "details":
        return renderInteractionDetails();
      default:
        return renderOverview();
    }
  };

  // Render overview stats
  const renderOverview = () => {
    if (statsLoading && !stats) {
      return (
        <div className="html-loading-container">
          <FaSpinner className="html-spinner" />
          <p>Loading statistics...</p>
        </div>
      );
    }

    // Use placeholder if no stats
    const statsData = stats || {
      total_interactions: 0,
      today_interactions: 0,
      week_interactions: 0,
      month_interactions: 0,
      page_types: [],
      interaction_types: [],
      top_ips: [],
      credential_attempts: [],
      time_series: []
    };

    return (
      <div className="html-overview-container">
        {/* Stats Cards */}
        <div className="html-stats-cards">
          <div className="html-stat-card">
            <div className="html-stat-icon">
              <FaCode />
            </div>
            <div className="html-stat-content">
              <div className="html-stat-value">{statsData.total_interactions}</div>
              <div className="html-stat-label">Total Interactions</div>
            </div>
          </div>
          
          <div className="html-stat-card">
            <div className="html-stat-icon">
              <FaClock />
            </div>
            <div className="html-stat-content">
              <div className="html-stat-value">{statsData.today_interactions}</div>
              <div className="html-stat-label">Today's Interactions</div>
            </div>
          </div>
          
          <div className="html-stat-card">
            <div className="html-stat-icon">
              <FaUser />
            </div>
            <div className="html-stat-content">
              <div className="html-stat-value">{statsData.week_interactions}</div>
              <div className="html-stat-label">This Week</div>
            </div>
          </div>
          
          <div className="html-stat-card">
            <div className="html-stat-icon">
              <FaKey />
            </div>
            <div className="html-stat-content">
              <div className="html-stat-value">
                {statsData.credential_attempts ? statsData.credential_attempts.length : 0}
              </div>
              <div className="html-stat-label">Credential Harvesting</div>
            </div>
          </div>
        </div>
        
        {/* Charts */}
        <div className="html-charts-container">
          {/* Page Types Chart */}
          <div className="html-chart-card">
            <h3 className="html-chart-title">Most Active Pages</h3>
            <div className="html-chart-content">
              {statsData.page_types && statsData.page_types.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart 
                    data={statsData.page_types.map(item => ({
                      name: item._id || "Unknown",
                      value: item.count || 0
                    }))} 
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
                      formatter={(value) => [`${value} interactions`, 'Count']}
                      contentStyle={{
                        backgroundColor: 'var(--admin-bg-card)',
                        border: '1px solid var(--admin-border)',
                        borderRadius: '8px'
                      }}
                    />
                    <Bar dataKey="value" fill="#8884d8" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="html-no-chart-data">
                  <p>No page type data available</p>
                </div>
              )}
            </div>
          </div>
          
          {/* Interaction Types Chart */}
          <div className="html-chart-card">
            <h3 className="html-chart-title">Interaction Types</h3>
            <div className="html-chart-content">
              {statsData.interaction_types && statsData.interaction_types.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={statsData.interaction_types.map(item => ({
                        name: item._id || "Unknown",
                        value: item.count || 0
                      }))}
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                      nameKey="name"
                      label={({name, percent}) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    >
                      {statsData.interaction_types.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip 
                      formatter={(value) => [`${value} interactions`, 'Count']}
                      contentStyle={{
                        backgroundColor: 'var(--admin-bg-card)',
                        border: '1px solid var(--admin-border)',
                        borderRadius: '8px'
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="html-no-chart-data">
                  <p>No interaction type data available</p>
                </div>
              )}
            </div>
          </div>
          
          {/* Time Series Chart */}
          <div className="html-chart-card html-full-width">
            <h3 className="html-chart-title">Interactions Over Time</h3>
            <div className="html-chart-content">
              {statsData.time_series && statsData.time_series.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart
                    data={statsData.time_series}
                    margin={{ top: 20, right: 30, left: 20, bottom: 20 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                    <XAxis dataKey="date" tick={{fill: 'var(--admin-text-secondary)'}} />
                    <YAxis tick={{fill: 'var(--admin-text-secondary)'}} />
                    <Tooltip 
                      formatter={(value) => [`${value} interactions`, 'Count']}
                      contentStyle={{
                        backgroundColor: 'var(--admin-bg-card)',
                        border: '1px solid var(--admin-border)',
                        borderRadius: '8px'
                      }}
                    />
                    <Line type="monotone" dataKey="count" stroke="#8884d8" activeDot={{ r: 8 }} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="html-no-chart-data">
                  <p>No time series data available</p>
                </div>
              )}
            </div>
          </div>
        </div>
        
        {/* Credential Harvesting Table */}
        <div className="html-credentials-section">
          <h3 className="html-section-title">Recent Credential Harvesting Attempts</h3>
          
          <div className="html-table-container">
            {statsData.credential_attempts && statsData.credential_attempts.length > 0 ? (
              <table className="html-data-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Page Type</th>
                    <th>Username</th>
                    <th>Password</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {statsData.credential_attempts.slice(0, 10).map((attempt, index) => {
                    const username = attempt.additional_data?.username || "N/A";
                    const password = attempt.additional_data?.password || "N/A";
                    
                    return (
                      <tr key={index}>
                        <td>{formatTimestamp(attempt.timestamp)}</td>
                        <td>
                          <span className={`html-badge ${attempt.page_type}`}>
                            {attempt.page_type || "unknown"}
                          </span>
                        </td>
                        <td className="html-credential">{username}</td>
                        <td className="html-credential">{password}</td>
                        <td>
                          <button 
                            className="html-view-details-btn"
                            onClick={() => fetchInteractionDetails(attempt._id)}
                          >
                            View Details
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ) : (
              <div className="html-no-data">
                <p>No credential harvesting attempts recorded</p>
              </div>
            )}
          </div>
          
          <div className="html-view-all-container">
            <button 
              className="html-view-all-btn"
              onClick={() => {
                setViewMode("interactions");
                setInteractionType("login_attempt");
                setPage(1);
                fetchInteractions();
              }}
            >
              View All Interactions <FaAngleRight />
            </button>
          </div>
        </div>
      </div>
    );
  };

  // Render list of interactions
  const renderInteractionsList = () => {
    return (
      <div className="html-interactions-container">
        <div className="html-interactions-header">
          <h3 className="html-interactions-title">HTML Page Interactions</h3>
          <div className="html-interactions-actions">
            <button 
              className="html-back-btn" 
              onClick={() => setViewMode("overview")}
            >
              Back to Overview
            </button>
            <button 
              className="html-export-btn" 
              onClick={exportData}
              disabled={interactions.length === 0}
            >
              <FaDownload /> Export Data
            </button>
          </div>
        </div>
        
        {/* Filters */}
        <div className="html-filter-section">
          <div className="html-filter-container">
            <div className="html-filter-fields">
              <div className="html-filter-field">
                <label>Page Type:</label>
                <select 
                  className="html-filter-select"
                  value={pageType}
                  onChange={(e) => setPageType(e.target.value)}
                >
                  <option value="all">All Pages</option>
                  {pageTypes.map((type, index) => (
                    <option key={index} value={type}>{type || "Unknown"}</option>
                  ))}
                </select>
              </div>
              
              <div className="html-filter-field">
                <label>Interaction Type:</label>
                <select 
                  className="html-filter-select"
                  value={interactionType}
                  onChange={(e) => setInteractionType(e.target.value)}
                >
                  <option value="all">All Interactions</option>
                  {interactionTypes.map((type, index) => (
                    <option key={index} value={type}>{type || "Unknown"}</option>
                  ))}
                </select>
              </div>
              
              <div className="html-filter-field html-search-box">
                <label>Search:</label>
                <div className="html-search-input-wrapper">
                  <FaSearch className="html-search-icon" />
                  <input 
                    type="text" 
                    className="html-search-input" 
                    placeholder="Search by keyword..." 
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    onKeyDown={handleSearch}
                  />
                </div>
              </div>
            </div>
            
            <div className="html-filter-buttons">
              <button 
                className="html-apply-filter-btn" 
                onClick={applyFilters}
              >
                <FaFilter /> Apply Filters
              </button>
              <button 
                className="html-reset-filter-btn" 
                onClick={resetFilters}
              >
                <FaSync /> Reset
              </button>
            </div>
          </div>
          
          <div className="html-results-info">
            Showing {interactions.length} of {total} interactions
          </div>
        </div>
        
        {/* Interactions Table */}
        <div className="html-table-container">
          {loading ? (
            <div className="html-loading-container">
              <FaSpinner className="html-spinner" />
              <p>Loading interactions...</p>
            </div>
          ) : interactions.length > 0 ? (
            <>
              <table className="html-data-table">
                <thead>
                  <tr>
                    <th 
                      className="html-sortable-header" 
                      onClick={() => handleSort("timestamp")}
                    >
                      Time {renderSortIndicator("timestamp")}
                    </th>
                    <th 
                      className="html-sortable-header" 
                      onClick={() => handleSort("page_type")}
                    >
                      Page Type {renderSortIndicator("page_type")}
                    </th>
                    <th 
                      className="html-sortable-header" 
                      onClick={() => handleSort("interaction_type")}
                    >
                      Interaction {renderSortIndicator("interaction_type")}
                    </th>
                    <th 
                      className="html-sortable-header" 
                      onClick={() => handleSort("ip_address")}
                    >
                      IP Address {renderSortIndicator("ip_address")}
                    </th>
                    <th>Details</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {interactions.map((interaction, index) => {
                    // Get key details from additional_data
                    const additionalData = interaction.additional_data || {};
                    const detailsText = getInteractionDetails(interaction);
                    
                    return (
                      <tr key={index} className="html-interaction-row">
                        <td>
                          <div className="html-timestamp">
                            <FaClock className="html-timestamp-icon" />
                            {formatTimestamp(interaction.timestamp)}
                          </div>
                        </td>
                        <td>
                          <span className={`html-badge html-page-type-${interaction.page_type}`}>
                            {interaction.page_type || "unknown"}
                          </span>
                        </td>
                        <td>
                          <span className={`html-badge html-interaction-type-${interaction.interaction_type}`}>
                            {interaction.interaction_type || "unknown"}
                          </span>
                        </td>
                        <td>{interaction.ip_address}</td>
                        <td className="html-details-cell">{detailsText}</td>
                        <td>
                          <button 
                            className="html-view-details-btn"
                            onClick={() => fetchInteractionDetails(interaction._id)}
                          >
                            View Details
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              
              {/* Pagination */}
              <div className="html-pagination">
                <button 
                  className="html-page-btn" 
                  disabled={page === 1}
                  onClick={() => setPage(1)}
                >
                  First
                </button>
                <button 
                  className="html-page-btn" 
                  disabled={page === 1}
                  onClick={() => setPage(page - 1)}
                >
                  Previous
                </button>
                
                <span className="html-page-info">
                  Page {page} of {Math.ceil(total / limit) || 1}
                </span>
                
                <button 
                  className="html-page-btn" 
                  disabled={page >= Math.ceil(total / limit)}
                  onClick={() => setPage(page + 1)}
                >
                  Next
                </button>
                <button 
                  className="html-page-btn" 
                  disabled={page >= Math.ceil(total / limit)}
                  onClick={() => setPage(Math.ceil(total / limit) || 1)}
                >
                  Last
                </button>
                
                <select 
                  className="html-limit-select"
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
            <div className="html-no-data">
              <p>No interactions found matching your criteria</p>
            </div>
          )}
        </div>
      </div>
    );
  };

  // Helper function to get a summary of interaction details
  const getInteractionDetails = (interaction) => {
    const additionalData = interaction.additional_data || {};
    
    switch (interaction.interaction_type) {
      case "login_attempt":
        return `Username: ${additionalData.username || "N/A"}, Password: ${additionalData.password || "N/A"}`;
      case "form_submit":
        return `Form data submitted: ${Object.keys(additionalData).length} fields`;
      case "button_click":
        return `Button: ${additionalData.button || additionalData.label || "Unknown"}`;
      case "terminal_command":
        return `Command: ${additionalData.command || "Unknown"}`;
      case "chat_message":
        return `Message: ${additionalData.message || "Unknown"}`;
      case "captcha_attempt":
        return `Captcha: ${additionalData.captcha_entered || "Unknown"}`;
      case "download_attempt":
        return `File: ${additionalData.filename || "Unknown"}`;
      case "sql_injection_attempt":
        return `SQL pattern detected in ${additionalData.input_field || "input"}`;
      default:
        if (additionalData.username && additionalData.password) {
          return `Username: ${additionalData.username}, Password: ${additionalData.password}`;
        }
        return `Additional data: ${Object.keys(additionalData).length} fields`;
    }
  };

  // Render detailed view of a single interaction
  const renderInteractionDetails = () => {
    if (!selectedInteraction) {
      return (
        <div className="html-no-selection">
          <p>No interaction selected.</p>
          <button 
            className="html-back-btn"
            onClick={() => setViewMode("interactions")}
          >
            Back to Interactions
          </button>
        </div>
      );
    }
    
    const additionalData = selectedInteraction.additional_data || {};
    const explanations = selectedInteraction.explanations || {};
    
    return (
      <div className="html-details-container">
        <div className="html-details-header">
          <h3 className="html-details-title">
            Interaction Details
          </h3>
          <div className="html-details-actions">
            <button 
              className="html-back-btn"
              onClick={() => setViewMode("interactions")}
            >
              Back to Interactions
            </button>
          </div>
        </div>
        
        {/* Interaction metadata */}
        <div className="html-details-meta">
          <div className="html-meta-item">
            <span className="html-meta-label">Timestamp:</span>
            <span className="html-meta-value">
              {formatTimestamp(selectedInteraction.timestamp)}
            </span>
          </div>
          <div className="html-meta-item">
            <span className="html-meta-label">IP Address:</span>
            <span className="html-meta-value">
              {selectedInteraction.ip_address}
            </span>
          </div>
          <div className="html-meta-item">
            <span className="html-meta-label">Page Type:</span>
            <span className="html-meta-value">
              <span className={`html-badge html-page-type-${selectedInteraction.page_type}`}>
                {selectedInteraction.page_type || "unknown"}
              </span>
            </span>
          </div>
          <div className="html-meta-item">
            <span className="html-meta-label">Interaction Type:</span>
            <span className="html-meta-value">
              <span className={`html-badge html-interaction-type-${selectedInteraction.interaction_type}`}>
                {selectedInteraction.interaction_type || "unknown"}
              </span>
            </span>
          </div>
          {selectedInteraction.geoInfo && (
            <div className="html-meta-item">
              <span className="html-meta-label">Location:</span>
              <span className="html-meta-value">
                {selectedInteraction.geoInfo.country || "Unknown"} 
                {selectedInteraction.geoInfo.asn && ` (${selectedInteraction.geoInfo.asn})`}
              </span>
            </div>
          )}
          {explanations.risk_level && (
            <div className="html-meta-item">
              <span className="html-meta-label">Risk Level:</span>
              <span className={`html-meta-value html-risk-${explanations.risk_level.level.toLowerCase()}`}>
                {explanations.risk_level.level}
              </span>
            </div>
          )}
        </div>
        
        {/* Human-readable explanation */}
        {explanations && Object.keys(explanations).length > 0 && (
          <div className="html-details-section">
            <h4 className="html-section-title">
              <FaShieldAlt /> Analysis
            </h4>
            <div className="html-explanation-box">
              <p><strong>What happened:</strong> {explanations.summary}</p>
              
              <p><strong>Page Type:</strong> {explanations.page_type}</p>
              
              <p><strong>Interaction Type:</strong> {explanations.interaction_type}</p>
              
              {explanations.risk_level && explanations.risk_level.reasons && (
                <>
                  <h5>Risk Assessment:</h5>
                  <ul className="html-risk-factors">
                    {explanations.risk_level.reasons.map((reason, index) => (
                      <li key={index} className={`html-risk-${explanations.risk_level.level.toLowerCase()}`}>
                        {reason}
                      </li>
                    ))}
                  </ul>
                </>
              )}
              
              <p><em>{explanations.technical_details}</em></p>
            </div>
          </div>
        )}
        
        {/* Browser Information Section */}
        {additionalData.browser_info && (
          <div className="html-details-section">
            <h4 className="html-section-title">
              <FaUser /> Browser Information
            </h4>
            <div className="html-details-table-container">
              <table className="html-details-table">
                <tbody>
                  <tr>
                    <td>User Agent</td>
                    <td>{additionalData.browser_info.userAgent || "Unknown"}</td>
                  </tr>
                  <tr>
                    <td>Language</td>
                    <td>{additionalData.browser_info.language || "Unknown"}</td>
                  </tr>
                  <tr>
                    <td>Platform</td>
                    <td>{additionalData.browser_info.platform || "Unknown"}</td>
                  </tr>
                  <tr>
                    <td>Screen Size</td>
                    <td>{additionalData.browser_info.screenSize || "Unknown"}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}
        
        {/* Interaction Data Section */}
        <div className="html-details-section">
          <h4 className="html-section-title">Interaction Data</h4>
          <div className="html-details-table-container">
            <table className="html-details-table">
              <tbody>
                {Object.entries(additionalData)
                  .filter(([key]) => key !== 'browser_info')
                  .map(([key, value]) => (
                    <tr key={key}>
                      <td>{key}</td>
                      <td>
                        {typeof value === 'object' 
                          ? JSON.stringify(value) 
                          : String(value)}
                      </td>
                    </tr>
                  ))
                }
              </tbody>
            </table>
          </div>
        </div>
        
        {/* Raw JSON Viewer */}
        <div className="html-details-section">
          <h4 className="html-section-title">Raw JSON Data</h4>
          <div className="html-details-json">
            <pre>{JSON.stringify(selectedInteraction, null, 2)}</pre>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="admin-tab-content html-interactions-tab">
      <div className="admin-content-header">
        <h2><FaCode /> HTML Interactions</h2>
        <div className="html-header-actions">
          <button 
            className={`html-action-btn ${viewMode === "overview" ? "active" : ""}`}
            onClick={() => setViewMode("overview")}
          >
            <FaChartBar /> Overview
          </button>
          <button 
            className={`html-action-btn ${viewMode === "interactions" ? "active" : ""}`}
            onClick={() => {
              setViewMode("interactions");
              fetchInteractions();
            }}
          >
            <FaTable /> All Interactions
          </button>
          <button 
            className="html-refresh-btn" 
            onClick={() => {
              fetchStats();
              if (viewMode === "interactions") fetchInteractions();
            }}
            disabled={loading || statsLoading}
          >
            {loading || statsLoading ? <FaSpinner className="html-spinner" /> : <FaSync />} Refresh
          </button>
        </div>
      </div>
      
      {renderContent()}
    </div>
  );
};

export default HtmlInteractionsTab;
