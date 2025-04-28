// src/components/cracked/tabs/CredentialsTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaKey, FaSync, FaSpinner, FaExclamationTriangle, FaSearch,
  FaTimes, FaDownload, FaCopy, FaTrash, FaFilter, FaClock,
  FaShieldAlt, FaDatabase, FaSortUp, FaSortDown, FaSort, 
  FaDesktop, FaGlobe, FaEye, FaEyeSlash, FaUserSecret
} from "react-icons/fa";
import { adminFetch } from '../csrfHelper';

const CredentialsTab = () => {
  // State for credentials
  const [credentials, setCredentials] = useState([]);
  const [filteredCredentials, setFilteredCredentials] = useState([]);
  const [selectedCredential, setSelectedCredential] = useState(null);
  
  // State for filter and pagination
  const [filter, setFilter] = useState("");
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);
  const [totalCredentials, setTotalCredentials] = useState(0);
  const [sourceFilter, setSourceFilter] = useState("all");
  const [dateRange, setDateRange] = useState({ from: "", to: "" });
  
  // Sorting state
  const [sortField, setSortField] = useState("timestamp");
  const [sortOrder, setSortOrder] = useState("desc");
  
  // UI state
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isFiltersOpen, setIsFiltersOpen] = useState(false);
  const [showSensitiveData, setShowSensitiveData] = useState(false);
  const [selectedSystems, setSelectedSystems] = useState([]);
  const [availableSystems, setAvailableSystems] = useState([]);
  const [availableSources, setAvailableSources] = useState([]);
  
  // Statistics
  const [stats, setStats] = useState({
    total: 0,
    unique_sources: 0,
    unique_systems: 0,
    today: 0,
    sensitive_count: 0
  });

  // Fetch credentials with filtering, sorting, and pagination
  const fetchCredentials = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Build query parameters
      const queryParams = new URLSearchParams({
        page: page,
        limit: limit,
        sort_field: sortField,
        sort_order: sortOrder
      });
      
      // Add filters if present
      if (filter) {
        queryParams.append('filter', filter);
      }
      
      if (sourceFilter !== "all") {
        queryParams.append('source', sourceFilter);
      }
      
      if (dateRange.from) {
        queryParams.append('from_date', dateRange.from);
      }
      
      if (dateRange.to) {
        queryParams.append('to_date', dateRange.to);
      }
      
      if (selectedSystems.length > 0) {
        queryParams.append('systems', selectedSystems.join(','));
      }
      
      // Make the API call
      const response = await adminFetch(`/api/cracked/c2/credentials?${queryParams.toString()}`);
      
      if (!response.ok) {
        throw new Error("Failed to fetch credentials");
      }
      
      const data = await response.json();
      setCredentials(data.credentials || []);
      setFilteredCredentials(data.credentials || []);
      setTotalCredentials(data.total || 0);
      
      // Update stats if provided
      if (data.stats) {
        setStats(data.stats);
      }
      
      // Update available filters
      if (data.available_systems) {
        setAvailableSystems(data.available_systems);
      }
      
      if (data.available_sources) {
        setAvailableSources(data.available_sources);
      }
    } catch (err) {
      console.error("Error fetching credentials:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [page, limit, sortField, sortOrder, filter, sourceFilter, dateRange, selectedSystems]);

  // Initial data load
  useEffect(() => {
    fetchCredentials();
  }, [fetchCredentials]);

  // Apply local filtering for search input
  useEffect(() => {
    if (!filter) {
      setFilteredCredentials(credentials);
      return;
    }
    
    const lowercaseFilter = filter.toLowerCase();
    const filtered = credentials.filter(cred => {
      // Search in various fields
      return (
        (cred.source && cred.source.toLowerCase().includes(lowercaseFilter)) ||
        (cred.session_id && cred.session_id.toLowerCase().includes(lowercaseFilter)) ||
        (cred.url && cred.url.toLowerCase().includes(lowercaseFilter)) ||
        (cred.ip && cred.ip.toLowerCase().includes(lowercaseFilter)) ||
        // Search in data if it's an object
        (cred.data && typeof cred.data === 'object' && 
          Object.entries(cred.data).some(([key, val]) => 
            key.toLowerCase().includes(lowercaseFilter) || 
            (typeof val === 'string' && val.toLowerCase().includes(lowercaseFilter))
          )
        )
      );
    });
    
    setFilteredCredentials(filtered);
  }, [credentials, filter]);

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

  // Handle sort toggle
  const toggleSort = (field) => {
    if (field === sortField) {
      // Toggle sort order
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      // New field, default to descending
      setSortField(field);
      setSortOrder("desc");
    }
  };

  // Get sort indicator
  const getSortIndicator = (field) => {
    if (field !== sortField) return <FaSort className="credentials-sort-icon" />;
    
    return sortOrder === "asc" 
      ? <FaSortUp className="credentials-sort-icon active" /> 
      : <FaSortDown className="credentials-sort-icon active" />;
  };

  // Copy to clipboard
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
      .then(() => {
        // Could add a toast notification here
        console.log("Copied to clipboard");
      })
      .catch(err => {
        console.error("Failed to copy:", err);
      });
  };

  // Export selected credentials or all filtered credentials
  const exportCredentials = () => {
    const dataToExport = selectedCredential 
      ? [selectedCredential] 
      : filteredCredentials;
    
    const jsonStr = JSON.stringify(dataToExport, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement("a");
    link.href = url;
    link.download = selectedCredential 
      ? `credential-${selectedCredential._id}.json` 
      : `credentials-export-${new Date().toISOString()}.json`;
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Delete a credential (admin only)
  const deleteCredential = async (id) => {
    if (!confirm("Are you sure you want to delete this credential? This action cannot be undone.")) {
      return;
    }
    
    try {
      const response = await adminFetch(`/api/cracked/c2/credentials/${id}`, {
        method: "DELETE"
      });
      
      if (!response.ok) {
        throw new Error("Failed to delete credential");
      }
      
      // Remove from state
      setCredentials(prev => prev.filter(cred => cred._id !== id));
      setFilteredCredentials(prev => prev.filter(cred => cred._id !== id));
      
      // If this was the selected credential, clear selection
      if (selectedCredential && selectedCredential._id === id) {
        setSelectedCredential(null);
      }
      
      // Update stats
      setStats(prev => ({
        ...prev,
        total: prev.total - 1
      }));
    } catch (err) {
      console.error("Error deleting credential:", err);
      alert(`Failed to delete credential: ${err.message}`);
    }
  };

  // View credential details
  const viewCredential = (credential) => {
    setSelectedCredential(credential === selectedCredential ? null : credential);
  };

  // Reset all filters
  const resetFilters = () => {
    setFilter("");
    setSourceFilter("all");
    setDateRange({ from: "", to: "" });
    setSelectedSystems([]);
    setPage(1);
    setSortField("timestamp");
    setSortOrder("desc");
  };

  // Handle system selection in filter
  const toggleSystemSelection = (systemId) => {
    setSelectedSystems(prev => {
      if (prev.includes(systemId)) {
        return prev.filter(id => id !== systemId);
      } else {
        return [...prev, systemId];
      }
    });
  };

  // Update date range
  const handleDateChange = (field, value) => {
    setDateRange(prev => ({
      ...prev,
      [field]: value
    }));
  };

  // Apply filters
  const applyFilters = () => {
    setPage(1); // Reset to first page
    fetchCredentials();
  };

  // Render source badge
  const renderSourceBadge = (source) => {
    // Determine badge color based on source
    let badgeClass = "credentials-source-badge";
    
    switch (source) {
      case "form-submission":
      case "form-hook":
      case "form":
        badgeClass += " form";
        break;
      case "localStorage":
      case "sessionStorage":
        badgeClass += " storage";
        break;
      case "cookie":
        badgeClass += " cookie";
        break;
      case "apiauth":
      case "jwt":
      case "token":
        badgeClass += " token";
        break;
      case "object-property":
      case "global-variable":
        badgeClass += " object";
        break;
      default:
        badgeClass += " other";
        break;
    }
    
    return (
      <span className={badgeClass}>
        {source}
      </span>
    );
  };

  // Determine if data contains sensitive information
  const hasSensitiveData = (data) => {
    if (!data) return false;
    
    const sensitiveKeys = [
      "password", "pass", "pwd", "secret", "token", "key", "auth", 
      "credit", "card", "ssn", "social", "dob", "birth"
    ];
    
    // Check if it's an object
    if (typeof data === 'object') {
      return Object.keys(data).some(key => 
        sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))
      );
    }
    
    // If it's a string
    if (typeof data === 'string') {
      return sensitiveKeys.some(sensitive => 
        data.toLowerCase().includes(sensitive)
      );
    }
    
    return false;
  };

  // Mask sensitive data
  const maskSensitiveData = (data) => {
    if (!data || showSensitiveData) return data;
    
    const sensitiveKeys = [
      "password", "pass", "pwd", "secret", "token", "key", "auth", 
      "credit", "card", "ssn", "social", "dob", "birth"
    ];
    
    // Handle object data
    if (typeof data === 'object') {
      const masked = {};
      
      Object.entries(data).forEach(([key, value]) => {
        if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {
          if (typeof value === 'string') {
            masked[key] = '*'.repeat(value.length);
          } else {
            masked[key] = '******';
          }
        } else {
          masked[key] = value;
        }
      });
      
      return masked;
    }
    
    // If it's a string, just return it
    return data;
  };

  // Render credential data
  const renderCredentialData = (credential) => {
    if (!credential.data) return <p>No data available</p>;
    
    const isSensitive = hasSensitiveData(credential.data);
    const dataToDisplay = isSensitive ? maskSensitiveData(credential.data) : credential.data;
    
    return (
      <div className="credentials-data-container">
        {isSensitive && (
          <div className="credentials-sensitive-badge">
            <FaShieldAlt />
            <span>Contains sensitive data</span>
            <button 
              className="credentials-toggle-sensitive-btn"
              onClick={(e) => {
                e.stopPropagation(); // Prevent selecting the credential
                setShowSensitiveData(prev => !prev);
              }}
              title={showSensitiveData ? "Hide sensitive data" : "Show sensitive data"}
            >
              {showSensitiveData ? <FaEyeSlash /> : <FaEye />}
            </button>
          </div>
        )}
        
        <pre className="credentials-data-json">
          {JSON.stringify(dataToDisplay, null, 2)}
        </pre>
      </div>
    );
  };

  return (
    <div className="admin-tab-content credentials-tab">
      <div className="admin-content-header">
        <h2><FaKey /> Harvested Credentials</h2>
        <div className="credentials-actions">
          <button 
            className="credentials-filter-toggle" 
            onClick={() => setIsFiltersOpen(!isFiltersOpen)}
          >
            <FaFilter /> {isFiltersOpen ? "Hide Filters" : "Show Filters"}
          </button>
          <button 
            className="credentials-export-btn" 
            onClick={exportCredentials}
            disabled={filteredCredentials.length === 0}
          >
            <FaDownload /> Export {selectedCredential ? "Selected" : "All"}
          </button>
          <button 
            className="credentials-refresh-btn" 
            onClick={fetchCredentials}
            disabled={loading}
          >
            {loading ? <FaSpinner className="credentials-spinner" /> : <FaSync />} Refresh
          </button>
        </div>
      </div>
      
      {error && (
        <div className="credentials-error-message">
          <FaExclamationTriangle /> {error}
        </div>
      )}
      
      {/* Stats Section */}
      <div className="credentials-stats-cards">
        <div className="credentials-stat-card">
          <div className="credentials-stat-icon">
            <FaKey />
          </div>
          <div className="credentials-stat-content">
            <div className="credentials-stat-value">{stats.total}</div>
            <div className="credentials-stat-label">Total Credentials</div>
          </div>
        </div>
        
        <div className="credentials-stat-card">
          <div className="credentials-stat-icon">
            <FaDatabase />
          </div>
          <div className="credentials-stat-content">
            <div className="credentials-stat-value">{stats.unique_sources}</div>
            <div className="credentials-stat-label">Unique Sources</div>
          </div>
        </div>
        
        <div className="credentials-stat-card">
          <div className="credentials-stat-icon">
            <FaDesktop />
          </div>
          <div className="credentials-stat-content">
            <div className="credentials-stat-value">{stats.unique_systems}</div>
            <div className="credentials-stat-label">Unique Systems</div>
          </div>
        </div>
        
        <div className="credentials-stat-card">
          <div className="credentials-stat-icon">
            <FaShieldAlt />
          </div>
          <div className="credentials-stat-content">
            <div className="credentials-stat-value">{stats.sensitive_count}</div>
            <div className="credentials-stat-label">Sensitive Credentials</div>
          </div>
        </div>
      </div>
      
      {/* Filters Section - Collapsible */}
      {isFiltersOpen && (
        <div className="credentials-filters-panel">
          <div className="credentials-filters-grid">
            <div className="credentials-filter-group">
              <label htmlFor="text-filter">Search Text:</label>
              <div className="credentials-search-box">
                <FaSearch className="credentials-search-icon" />
                <input
                  id="text-filter"
                  type="text"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder="Search in all fields..."
                  className="credentials-filter-input"
                />
                {filter && (
                  <button 
                    className="credentials-clear-btn"
                    onClick={() => setFilter("")}
                    title="Clear filter"
                  >
                    <FaTimes />
                  </button>
                )}
              </div>
            </div>
            
            <div className="credentials-filter-group">
              <label htmlFor="source-filter">Source Type:</label>
              <select
                id="source-filter"
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="credentials-filter-select"
              >
                <option value="all">All Sources</option>
                {availableSources.map((source, index) => (
                  <option key={index} value={source}>{source}</option>
                ))}
              </select>
            </div>
            
            <div className="credentials-filter-group">
              <label htmlFor="date-from">Date Range:</label>
              <div className="credentials-date-inputs">
                <input
                  id="date-from"
                  type="date"
                  value={dateRange.from}
                  onChange={(e) => handleDateChange("from", e.target.value)}
                  className="credentials-date-input"
                />
                <span className="credentials-date-separator">to</span>
                <input
                  type="date"
                  value={dateRange.to}
                  onChange={(e) => handleDateChange("to", e.target.value)}
                  className="credentials-date-input"
                />
              </div>
            </div>
            
            <div className="credentials-filter-group full-width">
              <label>Systems:</label>
              <div className="credentials-systems-filter">
                {availableSystems.length > 0 ? (
                  availableSystems.map((system, index) => (
                    <label key={index} className="credentials-system-checkbox">
                      <input
                        type="checkbox"
                        checked={selectedSystems.includes(system.id)}
                        onChange={() => toggleSystemSelection(system.id)}
                      />
                      {system.name || system.id.substring(0, 8)}
                    </label>
                  ))
                ) : (
                  <span className="credentials-no-systems">No systems available</span>
                )}
              </div>
            </div>
          </div>
          
          <div className="credentials-filter-actions">
            <button 
              className="credentials-apply-filters-btn" 
              onClick={applyFilters}
            >
              <FaFilter /> Apply Filters
            </button>
            <button 
              className="credentials-reset-filters-btn" 
              onClick={resetFilters}
            >
              <FaTimes /> Reset Filters
            </button>
          </div>
        </div>
      )}
      
      {/* Main Content */}
      <div className="credentials-content">
        {/* Credentials Table */}
        <div className="credentials-table-container">
          {loading ? (
            <div className="credentials-loading">
              <FaSpinner className="credentials-spinner" />
              <p>Loading credentials...</p>
            </div>
          ) : filteredCredentials.length > 0 ? (
            <table className="credentials-table">
              <thead>
                <tr>
                  <th onClick={() => toggleSort("timestamp")} className="credentials-sortable">
                    Timestamp {getSortIndicator("timestamp")}
                  </th>
                  <th onClick={() => toggleSort("source")} className="credentials-sortable">
                    Source {getSortIndicator("source")}
                  </th>
                  <th onClick={() => toggleSort("session_id")} className="credentials-sortable">
                    Session {getSortIndicator("session_id")}
                  </th>
                  <th onClick={() => toggleSort("ip")} className="credentials-sortable">
                    IP Address {getSortIndicator("ip")}
                  </th>
                  <th>URL</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredCredentials.map((credential, index) => (
                  <tr 
                    key={index} 
                    className={`credentials-row ${selectedCredential && selectedCredential._id === credential._id ? 'selected' : ''}`}
                    onClick={() => viewCredential(credential)}
                  >
                    <td>
                      <div className="credentials-timestamp">
                        <FaClock className="credentials-time-icon" />
                        {formatTimestamp(credential.timestamp)}
                      </div>
                    </td>
                    <td>
                      {renderSourceBadge(credential.source)}
                    </td>
                    <td>
                      <span className="credentials-session-id" title={credential.session_id}>
                        {credential.session_id?.substring(0, 8)}...
                      </span>
                    </td>
                    <td>{credential.ip}</td>
                    <td className="credentials-url-cell">
                      {credential.url ? (
                        <a 
                          href={credential.url} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="credentials-url-link"
                          title={credential.url}
                        >
                          {new URL(credential.url).hostname}
                        </a>
                      ) : (
                        <span>N/A</span>
                      )}
                    </td>
                    <td>
                      <div className="credentials-actions">
                        <button 
                          className="credentials-action-btn view"
                          onClick={(e) => {
                            e.stopPropagation();
                            viewCredential(credential);
                          }}
                          title="View details"
                        >
                          <FaEye />
                        </button>
                        <button 
                          className="credentials-action-btn copy"
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(JSON.stringify(credential.data, null, 2));
                          }}
                          title="Copy data"
                        >
                          <FaCopy />
                        </button>
                        <button 
                          className="credentials-action-btn delete"
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteCredential(credential._id);
                          }}
                          title="Delete credential"
                        >
                          <FaTrash />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="credentials-no-data">
              <FaUserSecret className="credentials-no-data-icon" />
              <p>No credentials found matching your criteria.</p>
              {(filter || sourceFilter !== "all" || dateRange.from || dateRange.to || selectedSystems.length > 0) && (
                <button 
                  className="credentials-reset-filters-btn"
                  onClick={resetFilters}
                >
                  Reset Filters
                </button>
              )}
            </div>
          )}
        </div>
        
        {/* Pagination */}
        {filteredCredentials.length > 0 && (
          <div className="credentials-pagination">
            <div className="credentials-pagination-controls">
              <button 
                className="credentials-page-btn"
                onClick={() => setPage(1)}
                disabled={page === 1 || loading}
              >
                First
              </button>
              <button 
                className="credentials-page-btn"
                onClick={() => setPage(prev => Math.max(1, prev - 1))}
                disabled={page === 1 || loading}
              >
                Previous
              </button>
              <span className="credentials-page-info">
                Page {page} of {Math.ceil(totalCredentials / limit)}
              </span>
              <button 
                className="credentials-page-btn"
                onClick={() => setPage(prev => Math.min(Math.ceil(totalCredentials / limit), prev + 1))}
                disabled={page >= Math.ceil(totalCredentials / limit) || loading}
              >
                Next
              </button>
              <button 
                className="credentials-page-btn"
                onClick={() => setPage(Math.ceil(totalCredentials / limit))}
                disabled={page >= Math.ceil(totalCredentials / limit) || loading}
              >
                Last
              </button>
            </div>
            
            <div className="credentials-page-size">
              <label htmlFor="page-size">Show:</label>
              <select 
                id="page-size"
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
                className="credentials-page-size-select"
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
              <span>per page</span>
            </div>
          </div>
        )}
        
        {/* Selected Credential Details */}
        {selectedCredential && (
          <div className="credentials-detail-panel">
            <div className="credentials-detail-header">
              <h3>Credential Details</h3>
              <button 
                className="credentials-close-detail-btn"
                onClick={() => setSelectedCredential(null)}
              >
                <FaTimes />
              </button>
            </div>
            
            <div className="credentials-detail-content">
              <div className="credentials-detail-metadata">
                <div className="credentials-metadata-item">
                  <span className="credentials-metadata-label">Source:</span>
                  <span className="credentials-metadata-value">{renderSourceBadge(selectedCredential.source)}</span>
                </div>
                <div className="credentials-metadata-item">
                  <span className="credentials-metadata-label">Timestamp:</span>
                  <span className="credentials-metadata-value">{formatTimestamp(selectedCredential.timestamp)}</span>
                </div>
                <div className="credentials-metadata-item">
                  <span className="credentials-metadata-label">Session ID:</span>
                  <span className="credentials-metadata-value">
                    <div className="credentials-copy-wrapper">
                      {selectedCredential.session_id}
                      <button 
                        className="credentials-copy-btn"
                        onClick={() => copyToClipboard(selectedCredential.session_id)}
                        title="Copy to clipboard"
                      >
                        <FaCopy />
                      </button>
                    </div>
                  </span>
                </div>
                <div className="credentials-metadata-item">
                  <span className="credentials-metadata-label">IP Address:</span>
                  <span className="credentials-metadata-value">{selectedCredential.ip}</span>
                </div>
                {selectedCredential.url && (
                  <div className="credentials-metadata-item">
                    <span className="credentials-metadata-label">URL:</span>
                    <span className="credentials-metadata-value">
                      <a 
                        href={selectedCredential.url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="credentials-url-link"
                      >
                        {selectedCredential.url}
                      </a>
                    </span>
                  </div>
                )}
                {selectedCredential.user_agent && (
                  <div className="credentials-metadata-item full-width">
                    <span className="credentials-metadata-label">User Agent:</span>
                    <span className="credentials-metadata-value credentials-user-agent">
                      {selectedCredential.user_agent}
                    </span>
                  </div>
                )}
              </div>
              
              <div className="credentials-detail-data">
                <h4>Captured Credentials</h4>
                {renderCredentialData(selectedCredential)}
              </div>
              
              <div className="credentials-detail-actions">
                <button 
                  className="credentials-detail-btn export"
                  onClick={() => exportCredentials()}
                >
                  <FaDownload /> Export JSON
                </button>
                <button 
                  className="credentials-detail-btn copy"
                  onClick={() => copyToClipboard(JSON.stringify(selectedCredential.data, null, 2))}
                >
                  <FaCopy /> Copy Data
                </button>
                <button 
                  className="credentials-detail-btn delete"
                  onClick={() => deleteCredential(selectedCredential._id)}
                >
                  <FaTrash /> Delete
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CredentialsTab;
