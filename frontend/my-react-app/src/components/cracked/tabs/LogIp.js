import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { 
  FaGlobe, FaUser, FaFingerprint, FaUserSecret, FaNetworkWired, FaBan, 
  FaSearch, FaSyncAlt, FaCalendarAlt, FaDownload, FaExpand, FaCompress,
  FaExclamationTriangle, FaShieldAlt, FaFilter, FaSort, FaSortUp, FaSortDown,
  FaChartBar, FaMapMarkerAlt, FaServer, FaFileExport, FaEye, FaEyeSlash
} from 'react-icons/fa';
import { adminFetch } from '../csrfHelper';
import '../styles/tabstyles/LogIp.css';

function LogIp() {
  // State management
  const [requestData, setRequestData] = useState([]);
  const [groupedData, setGroupedData] = useState({});
  const [filteredData, setFilteredData] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [advancedFilter, setAdvancedFilter] = useState(false);
  const [dateRange, setDateRange] = useState({ start: '', end: '' });
  const [methodFilter, setMethodFilter] = useState('');
  const [countryFilter, setCountryFilter] = useState('');
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' });
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(50);
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [flaggedIPs, setFlaggedIPs] = useState(new Set());
  const [statsVisible, setStatsVisible] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [autoRefresh, setAutoRefresh] = useState(true);
  
  // Refs
  const tableRef = useRef(null);
  const intervalRef = useRef(null);
  
  // Fetch request data from the API
  const fetchUserRequests = useCallback(async (showLoadingState = true) => {
    try {
      if (showLoadingState) {
        setIsLoading(true);
      }
      
      const response = await adminFetch('/api/cracked/user-requests');
      if (!response.ok) {
        throw new Error(`Failed to fetch user requests: ${response.status} ${response.statusText}`);
      }
      
      const data = await response.json();
      
      // Process data - convert timestamps to Date objects for easier sorting
      const processedData = data.requests.map(req => ({
        ...req,
        timestampObj: new Date(req.timestamp),
        ipInfo: {
          suspicious: req.ipAddress && isSuspiciousIP(req.ipAddress),
          blocked: req.ipAddress && isBlockedIP(req.ipAddress),
        }
      }));
      
      setRequestData(processedData);
      setGroupedData(data.grouped);
      setLastRefresh(new Date());
      setIsLoading(false);
    } catch (err) {
      console.error('Error fetching user requests:', err);
      setError(err.message || 'Failed to fetch request data');
      setIsLoading(false);
    }
  }, []);
  
  // Check if IP appears suspicious (example logic)
  const isSuspiciousIP = (ip) => {
    // Implement your suspicious IP detection logic here
    // For example: Check if multiple requests from this IP in a short time
    const ipRequests = requestData.filter(req => req.ipAddress === ip);
    return ipRequests.length > 10;
  };
  
  // Check if IP is blocked
  const isBlockedIP = (ip) => {
    return flaggedIPs.has(ip);
  };
  
  // Toggle flagging an IP address
  const toggleFlagIP = (ip) => {
    setFlaggedIPs(prevFlagged => {
      const newFlagged = new Set(prevFlagged);
      if (newFlagged.has(ip)) {
        newFlagged.delete(ip);
      } else {
        newFlagged.add(ip);
      }
      return newFlagged;
    });
  };
  
  // Handle sorting
  const handleSort = (key) => {
    setSortConfig(prevConfig => {
      if (prevConfig.key === key) {
        // Toggle direction if clicking the same column
        return { 
          key, 
          direction: prevConfig.direction === 'asc' ? 'desc' : 'asc' 
        };
      }
      // Default to descending for new column
      return { key, direction: 'desc' };
    });
  };
  
  // Get sort icon based on current sort configuration
  const getSortIcon = (key) => {
    if (sortConfig.key !== key) return <FaSort className="usrreq-sort-icon" />;
    return sortConfig.direction === 'asc' 
      ? <FaSortUp className="usrreq-sort-icon active" /> 
      : <FaSortDown className="usrreq-sort-icon active" />;
  };
  
  // Toggle expanded row
  const toggleRowExpanded = (id) => {
    setExpandedRows(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };
  
  // Export data to CSV
  const exportToCSV = () => {
    const headers = [
      'Time', 'Identifier Type', 'Identifier Value', 'IP Address',
      'Country', 'Organization', 'Method', 'Path', 'User Agent'
    ];
    
    const csvRows = [
      headers.join(','),
      ...filteredData.map(req => [
        new Date(req.timestamp).toISOString(),
        req.identifierType,
        req.identifierValue,
        req.ipAddress,
        req.geoInfo?.country || 'Unknown',
        `"${(req.geoInfo?.org || 'Unknown').replace(/"/g, '""')}"`,
        req.method,
        `"${req.path.replace(/"/g, '""')}"`,
        `"${req.userAgent.replace(/"/g, '""')}"`
      ].join(','))
    ];
    
    const csvContent = csvRows.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `user-requests-${new Date().toISOString().slice(0, 10)}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };
  
  // Reset all filters
  const resetFilters = () => {
    setSearchTerm('');
    setDateRange({ start: '', end: '' });
    setMethodFilter('');
    setCountryFilter('');
    setAdvancedFilter(false);
  };
  
  // Calculate statistics from the request data
  const calculateStats = useMemo(() => {
    if (!requestData.length) return null;
    
    // Group by various properties
    const byIP = {};
    const byPath = {};
    const byMethod = {};
    const byCountry = {};
    const byIdentifierType = {};
    
    requestData.forEach(req => {
      // Count by IP
      byIP[req.ipAddress] = (byIP[req.ipAddress] || 0) + 1;
      
      // Count by path
      byPath[req.path] = (byPath[req.path] || 0) + 1;
      
      // Count by method
      byMethod[req.method] = (byMethod[req.method] || 0) + 1;
      
      // Count by country
      const country = req.geoInfo?.country || 'Unknown';
      byCountry[country] = (byCountry[country] || 0) + 1;
      
      // Count by identifier type
      byIdentifierType[req.identifierType] = (byIdentifierType[req.identifierType] || 0) + 1;
    });
    
    // Get top 5 of each category
    const getTop5 = (obj) => {
      return Object.entries(obj)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([key, count]) => ({ key, count }));
    };
    
    return {
      totalRequests: requestData.length,
      uniqueIPs: Object.keys(byIP).length,
      uniquePaths: Object.keys(byPath).length,
      topIPs: getTop5(byIP),
      topPaths: getTop5(byPath),
      byMethod,
      byCountry: getTop5(byCountry),
      byIdentifierType,
    };
  }, [requestData]);
  
  // Apply filters and sorting to get data for the current view
  useEffect(() => {
    // Get base data for the active tab
    let baseData = activeTab === 'all' 
      ? requestData 
      : (groupedData[activeTab] || []);
    
    // Apply search filters
    let filtered = baseData;
    
    if (searchTerm) {
      const search = searchTerm.toLowerCase();
      filtered = filtered.filter(req => 
        (req.path?.toLowerCase().includes(search)) ||
        (req.identifierValue?.toLowerCase().includes(search)) ||
        (req.ipAddress?.toLowerCase().includes(search)) ||
        (req.geoInfo?.country?.toLowerCase().includes(search)) ||
        (req.geoInfo?.org?.toLowerCase().includes(search)) ||
        (req.userAgent?.toLowerCase().includes(search))
      );
    }
    
    // Apply advanced filters
    if (advancedFilter) {
      // Date range filter
      if (dateRange.start || dateRange.end) {
        filtered = filtered.filter(req => {
          const reqDate = new Date(req.timestamp);
          const startOk = !dateRange.start || new Date(dateRange.start) <= reqDate;
          const endOk = !dateRange.end || reqDate <= new Date(`${dateRange.end}T23:59:59`);
          return startOk && endOk;
        });
      }
      
      // Method filter
      if (methodFilter) {
        filtered = filtered.filter(req => 
          req.method?.toLowerCase() === methodFilter.toLowerCase()
        );
      }
      
      // Country filter
      if (countryFilter) {
        filtered = filtered.filter(req => 
          req.geoInfo?.country?.toLowerCase().includes(countryFilter.toLowerCase())
        );
      }
    }
    
    // Apply sorting
    if (sortConfig.key) {
      filtered = [...filtered].sort((a, b) => {
        let aValue = sortConfig.key === 'timestamp' ? new Date(a.timestamp) : a[sortConfig.key];
        let bValue = sortConfig.key === 'timestamp' ? new Date(b.timestamp) : b[sortConfig.key];
        
        // Handle nested properties
        if (sortConfig.key === 'country') {
          aValue = a.geoInfo?.country || '';
          bValue = b.geoInfo?.country || '';
        }
        
        if (aValue < bValue) return sortConfig.direction === 'asc' ? -1 : 1;
        if (aValue > bValue) return sortConfig.direction === 'asc' ? 1 : -1;
        return 0;
      });
    }
    
    setFilteredData(filtered);
    // Reset to first page when filters change
    setCurrentPage(1);
  }, [requestData, groupedData, activeTab, searchTerm, advancedFilter, 
      dateRange, methodFilter, countryFilter, sortConfig]);
  
  // Set up auto-refresh interval
  useEffect(() => {
    // Initial fetch
    fetchUserRequests();
    
    // Set up auto-refresh interval
    if (autoRefresh) {
      intervalRef.current = setInterval(() => {
        fetchUserRequests(false); // Don't show loading state for auto-refresh
      }, 60000); // Refresh every minute
    }
    
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [fetchUserRequests, autoRefresh]);
  
  // Toggle auto-refresh
  const toggleAutoRefresh = () => {
    if (autoRefresh) {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    } else {
      intervalRef.current = setInterval(() => {
        fetchUserRequests(false);
      }, 60000);
    }
    setAutoRefresh(!autoRefresh);
  };
  
  // Format time with options for display
  const formatTime = (isoString, options = {}) => {
    try {
      const date = new Date(isoString);
      const defaultOptions = { 
        dateStyle: 'medium', 
        timeStyle: 'medium'
      };
      return date.toLocaleString(undefined, {...defaultOptions, ...options});
    } catch {
      return isoString || 'Unknown';
    }
  };
  
  // Get methods from all requests for filters
  const availableMethods = useMemo(() => {
    const methods = new Set();
    requestData.forEach(req => {
      if (req.method) methods.add(req.method.toUpperCase());
    });
    return Array.from(methods).sort();
  }, [requestData]);
  
  // Get countries from all requests for filters
  const availableCountries = useMemo(() => {
    const countries = new Set();
    requestData.forEach(req => {
      if (req.geoInfo?.country) countries.add(req.geoInfo.country);
    });
    return Array.from(countries).sort();
  }, [requestData]);
  
  // Get icon for the identifier type
  const getIdentifierIcon = (type) => {
    switch (type) {
      case 'username': return <FaUser className="usrreq-id-icon usrreq-username" />;
      case 'userId': return <FaFingerprint className="usrreq-id-icon usrreq-userid" />;
      case 'sessionId': return <FaUserSecret className="usrreq-id-icon usrreq-sessionid" />;
      case 'xUserId': return <FaUser className="usrreq-id-icon usrreq-xuserid" />;
      case 'ipOnly': return <FaNetworkWired className="usrreq-id-icon usrreq-iponly" />;
      default: return <FaNetworkWired className="usrreq-id-icon" />;
    }
  };
  
  // Pagination helpers
  const totalPages = Math.ceil(filteredData.length / itemsPerPage);
  const currentData = filteredData.slice(
    (currentPage - 1) * itemsPerPage, 
    currentPage * itemsPerPage
  );
  
  // Go to a specific page
  const goToPage = (page) => {
    const validPage = Math.max(1, Math.min(page, totalPages));
    setCurrentPage(validPage);
    if (tableRef.current) {
      tableRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };
  
  // Render the component
  return (
    <div className="usrreq-container">
      {/* Header section */}
      <div className="usrreq-header">
        <div className="usrreq-title-section">
          <h2><FaGlobe className="usrreq-title-icon" /> User Requests Monitor</h2>
          <div className="usrreq-subtitle">
            <p>Tracking unique requests across the platform with geolocation and device information</p>
            <div className="usrreq-last-refresh">
              <span>Last updated: {formatTime(lastRefresh)}</span>
              <button 
                className={`usrreq-auto-refresh-toggle ${autoRefresh ? 'active' : ''}`}
                onClick={toggleAutoRefresh}
                title={autoRefresh ? "Disable auto-refresh" : "Enable auto-refresh"}
              >
                <FaSyncAlt /> {autoRefresh ? 'Auto-refresh on' : 'Auto-refresh off'}
              </button>
            </div>
          </div>
        </div>
        
        {/* Control panel */}
        <div className="usrreq-control-panel">
          <div className="usrreq-top-controls">
            <div className="usrreq-search-box">
              <FaSearch className="usrreq-search-icon" />
              <input
                type="text"
                placeholder="Search by IP, path, country..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="usrreq-search-input"
              />
              {searchTerm && (
                <button 
                  className="usrreq-clear-search" 
                  onClick={() => setSearchTerm('')}
                  aria-label="Clear search"
                >
                  ×
                </button>
              )}
            </div>
            
            <div className="usrreq-action-buttons">
              <button 
                className="usrreq-refresh-button" 
                onClick={() => fetchUserRequests()}
                disabled={isLoading}
                title="Refresh data"
              >
                <FaSyncAlt className={isLoading ? 'usrreq-spinning' : ''} />
                <span>Refresh</span>
              </button>
              
              <button 
                className="usrreq-filter-toggle"
                onClick={() => setAdvancedFilter(!advancedFilter)}
                title={advancedFilter ? "Hide filters" : "Show advanced filters"}
              >
                <FaFilter />
                <span>Filters {advancedFilter ? 'on' : 'off'}</span>
              </button>
              
              <button 
                className="usrreq-stats-toggle"
                onClick={() => setStatsVisible(!statsVisible)}
                title={statsVisible ? "Hide statistics" : "Show statistics"}
              >
                <FaChartBar />
                <span>Statistics</span>
              </button>
              
              <button 
                className="usrreq-export-button"
                onClick={exportToCSV}
                title="Export to CSV"
              >
                <FaFileExport />
                <span>Export</span>
              </button>
            </div>
          </div>
          
          {/* Advanced filters */}
          {advancedFilter && (
            <div className="usrreq-advanced-filters">
              <div className="usrreq-filter-row">
                <div className="usrreq-filter-group">
                  <label htmlFor="startDate">Date Range:</label>
                  <div className="usrreq-date-inputs">
                    <input
                      type="date"
                      id="startDate"
                      value={dateRange.start}
                      onChange={e => setDateRange({...dateRange, start: e.target.value})}
                      className="usrreq-date-input"
                    />
                    <span>to</span>
                    <input
                      type="date"
                      id="endDate"
                      value={dateRange.end}
                      onChange={e => setDateRange({...dateRange, end: e.target.value})}
                      className="usrreq-date-input"
                    />
                  </div>
                </div>
                
                <div className="usrreq-filter-group">
                  <label htmlFor="methodFilter">Method:</label>
                  <select
                    id="methodFilter"
                    value={methodFilter}
                    onChange={e => setMethodFilter(e.target.value)}
                    className="usrreq-select-input"
                  >
                    <option value="">All Methods</option>
                    {availableMethods.map(method => (
                      <option key={method} value={method}>{method}</option>
                    ))}
                  </select>
                </div>
                
                <div className="usrreq-filter-group">
                  <label htmlFor="countryFilter">Country:</label>
                  <select
                    id="countryFilter"
                    value={countryFilter}
                    onChange={e => setCountryFilter(e.target.value)}
                    className="usrreq-select-input"
                  >
                    <option value="">All Countries</option>
                    {availableCountries.map(country => (
                      <option key={country} value={country}>{country}</option>
                    ))}
                  </select>
                </div>
                
                <button 
                  className="usrreq-reset-filters"
                  onClick={resetFilters}
                  title="Reset all filters"
                >
                  Clear Filters
                </button>
              </div>
              
              {/* Filter status indicators */}
              <div className="usrreq-filter-status">
                <div className="usrreq-active-filters">
                  {searchTerm && (
                    <span className="usrreq-filter-tag">
                      Search: {searchTerm}
                    </span>
                  )}
                  {dateRange.start && (
                    <span className="usrreq-filter-tag">
                      From: {dateRange.start}
                    </span>
                  )}
                  {dateRange.end && (
                    <span className="usrreq-filter-tag">
                      To: {dateRange.end}
                    </span>
                  )}
                  {methodFilter && (
                    <span className="usrreq-filter-tag">
                      Method: {methodFilter}
                    </span>
                  )}
                  {countryFilter && (
                    <span className="usrreq-filter-tag">
                      Country: {countryFilter}
                    </span>
                  )}
                </div>
                
                <div className="usrreq-result-count">
                  Showing {filteredData.length} of {requestData.length} requests
                </div>
              </div>
            </div>
          )}
          
          {/* Statistics panel */}
          {statsVisible && calculateStats && (
            <div className="usrreq-stats-panel">
              <div className="usrreq-stats-header">
                <h3>Request Statistics</h3>
                <button 
                  className="usrreq-close-stats"
                  onClick={() => setStatsVisible(false)}
                  aria-label="Close statistics"
                >
                  ×
                </button>
              </div>
              
              <div className="usrreq-stats-grid">
                <div className="usrreq-stat-card">
                  <div className="usrreq-stat-icon-wrapper">
                    <FaGlobe className="usrreq-stat-icon" />
                  </div>
                  <div className="usrreq-stat-content">
                    <div className="usrreq-stat-value">{calculateStats.totalRequests}</div>
                    <div className="usrreq-stat-label">Total Requests</div>
                  </div>
                </div>
                
                <div className="usrreq-stat-card">
                  <div className="usrreq-stat-icon-wrapper">
                    <FaNetworkWired className="usrreq-stat-icon" />
                  </div>
                  <div className="usrreq-stat-content">
                    <div className="usrreq-stat-value">{calculateStats.uniqueIPs}</div>
                    <div className="usrreq-stat-label">Unique IP Addresses</div>
                  </div>
                </div>
                
                <div className="usrreq-stat-card">
                  <div className="usrreq-stat-icon-wrapper">
                    <FaServer className="usrreq-stat-icon" />
                  </div>
                  <div className="usrreq-stat-content">
                    <div className="usrreq-stat-value">{calculateStats.uniquePaths}</div>
                    <div className="usrreq-stat-label">Unique Endpoints</div>
                  </div>
                </div>
                
                <div className="usrreq-stat-card">
                  <div className="usrreq-stat-icon-wrapper">
                    <FaUser className="usrreq-stat-icon" />
                  </div>
                  <div className="usrreq-stat-content">
                    <div className="usrreq-stat-value">
                      {calculateStats.byIdentifierType.username || 0}
                    </div>
                    <div className="usrreq-stat-label">User Sessions</div>
                  </div>
                </div>
              </div>
              
              <div className="usrreq-detailed-stats">
                <div className="usrreq-stat-section">
                  <h4>Top IP Addresses</h4>
                  <div className="usrreq-stat-bars">
                    {calculateStats.topIPs.map(item => (
                      <div className="usrreq-stat-bar" key={item.key}>
                        <div className="usrreq-stat-bar-label">
                          {item.key}
                        </div>
                        <div className="usrreq-stat-bar-container">
                          <div 
                            className="usrreq-stat-bar-fill"
                            style={{ width: `${(item.count / calculateStats.topIPs[0].count) * 100}%` }}
                          ></div>
                          <span className="usrreq-stat-bar-value">{item.count}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="usrreq-stat-section">
                  <h4>Request Distribution by Method</h4>
                  <div className="usrreq-method-distribution">
                    {Object.entries(calculateStats.byMethod).map(([method, count]) => (
                      <div className="usrreq-method-item" key={method}>
                        <span className={`usrreq-method-badge ${method.toLowerCase()}`}>
                          {method}
                        </span>
                        <span className="usrreq-method-count">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="usrreq-stat-section">
                  <h4>Top Countries</h4>
                  <div className="usrreq-country-distribution">
                    {calculateStats.byCountry.map(item => (
                      <div className="usrreq-country-item" key={item.key}>
                        <FaMapMarkerAlt className="usrreq-country-icon" />
                        <span className="usrreq-country-name">{item.key}</span>
                        <span className="usrreq-country-count">{item.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
        
        {/* Request category tabs */}
        <div className="usrreq-tabs">
          <button 
            className={`usrreq-tab ${activeTab === 'all' ? 'active' : ''}`} 
            onClick={() => setActiveTab('all')}
          >
            All Requests <span className="usrreq-count">{requestData.length}</span>
          </button>
          <button 
            className={`usrreq-tab ${activeTab === 'username' ? 'active' : ''}`} 
            onClick={() => setActiveTab('username')}
          >
            By Username <span className="usrreq-count">{groupedData.username?.length || 0}</span>
          </button>
          <button 
            className={`usrreq-tab ${activeTab === 'userId' ? 'active' : ''}`} 
            onClick={() => setActiveTab('userId')}
          >
            By User ID <span className="usrreq-count">{groupedData.userId?.length || 0}</span>
          </button>
          <button 
            className={`usrreq-tab ${activeTab === 'sessionId' ? 'active' : ''}`} 
            onClick={() => setActiveTab('sessionId')}
          >
            By Session <span className="usrreq-count">{groupedData.sessionId?.length || 0}</span>
          </button>
          <button 
            className={`usrreq-tab ${activeTab === 'xUserId' ? 'active' : ''}`} 
            onClick={() => setActiveTab('xUserId')}
          >
            By X-User-ID <span className="usrreq-count">{groupedData.xUserId?.length || 0}</span>
          </button>
          <button 
            className={`usrreq-tab ${activeTab === 'ipOnly' ? 'active' : ''}`} 
            onClick={() => setActiveTab('ipOnly')}
          >
            By IP Only <span className="usrreq-count">{groupedData.ipOnly?.length || 0}</span>
          </button>
        </div>
      </div>
      
      {/* Main content area */}
      <div className="usrreq-content">
        {isLoading && !requestData.length ? (
          <div className="usrreq-loading">
            <div className="usrreq-spinner"></div>
            <p>Loading request data...</p>
          </div>
        ) : error ? (
          <div className="usrreq-error">
            <FaExclamationTriangle className="usrreq-error-icon" />
            <p>Error: {error}</p>
            <button 
              className="usrreq-retry-button"
              onClick={() => fetchUserRequests()}
            >
              Retry
            </button>
          </div>
        ) : filteredData.length === 0 ? (
          <div className="usrreq-no-results">
            <FaBan className="usrreq-no-results-icon" />
            <p>No requests found matching your criteria</p>
            <button 
              className="usrreq-reset-button"
              onClick={resetFilters}
            >
              Reset Filters
            </button>
          </div>
        ) : (
          <>
            {/* Data table */}
            <div className="usrreq-table-container" ref={tableRef}>
              <table className="usrreq-table">
                <thead>
                  <tr>
                    <th className="usrreq-col-expand"></th>
                    <th 
                      className="usrreq-col-time"
                      onClick={() => handleSort('timestamp')}
                    >
                      <div className="usrreq-th-content">
                        <span>Time</span>
                        {getSortIcon('timestamp')}
                      </div>
                    </th>
                    <th className="usrreq-col-identifier">
                      <div className="usrreq-th-content">
                        <span>Identifier</span>
                      </div>
                    </th>
                    <th 
                      className="usrreq-col-ip"
                      onClick={() => handleSort('ipAddress')}
                    >
                      <div className="usrreq-th-content">
                        <span>IP Address</span>
                        {getSortIcon('ipAddress')}
                      </div>
                    </th>
                    <th 
                      className="usrreq-col-location"
                      onClick={() => handleSort('country')}
                    >
                      <div className="usrreq-th-content">
                        <span>Location</span>
                        {getSortIcon('country')}
                      </div>
                    </th>
                    <th 
                      className="usrreq-col-method"
                      onClick={() => handleSort('method')}
                    >
                      <div className="usrreq-th-content">
                        <span>Method</span>
                        {getSortIcon('method')}
                      </div>
                    </th>
                    <th 
                      className="usrreq-col-path"
                      onClick={() => handleSort('path')}
                    >
                      <div className="usrreq-th-content">
                        <span>Path</span>
                        {getSortIcon('path')}
                      </div>
                    </th>
                    <th className="usrreq-col-actions"></th>
                  </tr>
                </thead>
                <tbody>
                  {isLoading && (
                    <tr className="usrreq-loading-overlay">
                      <td colSpan="8">
                        <div className="usrreq-table-loader">
                          <div className="usrreq-spinner-sm"></div>
                          <span>Refreshing data...</span>
                        </div>
                      </td>
                    </tr>
                  )}
                  
                  {currentData.map(req => (
                    <React.Fragment key={req._id}>
                      <tr className={`usrreq-data-row ${expandedRows.has(req._id) ? 'expanded' : ''} ${req.ipInfo?.suspicious ? 'suspicious' : ''} ${flaggedIPs.has(req.ipAddress) ? 'flagged' : ''}`}>
                        <td className="usrreq-col-expand">
                          <button
                            className="usrreq-expand-toggle"
                            onClick={() => toggleRowExpanded(req._id)}
                            aria-label={expandedRows.has(req._id) ? "Collapse row" : "Expand row"}
                          >
                            {expandedRows.has(req._id) ? <FaCompress /> : <FaExpand />}
                          </button>
                        </td>
                        <td className="usrreq-col-time">
                          {formatTime(req.timestamp, { dateStyle: 'short', timeStyle: 'medium' })}
                        </td>
                        <td className="usrreq-col-identifier">
                          <div className="usrreq-identifier">
                            {getIdentifierIcon(req.identifierType)}
                            <span className="usrreq-id-value" title={req.identifierValue}>
                              {req.identifierValue?.length > 15 
                                ? `${req.identifierValue.substring(0, 15)}...` 
                                : req.identifierValue}
                            </span>
                          </div>
                        </td>
                        <td className="usrreq-col-ip">
                          <div className={`usrreq-ip-wrapper ${req.ipInfo?.suspicious ? 'suspicious' : ''} ${flaggedIPs.has(req.ipAddress) ? 'flagged' : ''}`}>
                            {req.ipAddress}
                            {req.ipInfo?.suspicious && (
                              <div className="usrreq-suspicious-indicator" title="Suspicious activity detected">
                                <FaExclamationTriangle />
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="usrreq-col-location">
                          <div className="usrreq-location">
                            <div className="usrreq-country">
                              {req.geoInfo?.country || "Unknown"}
                            </div>
                            <div className="usrreq-org" title={req.geoInfo?.org}>
                              {req.geoInfo?.org 
                                ? (req.geoInfo.org.length > 20 
                                  ? `${req.geoInfo.org.substring(0, 20)}...` 
                                  : req.geoInfo.org)
                                : "Unknown"}
                            </div>
                          </div>
                        </td>
                        <td className="usrreq-col-method">
                          <span className={`usrreq-method-badge ${req.method?.toLowerCase()}`}>
                            {req.method}
                          </span>
                        </td>
                        <td className="usrreq-col-path">
                          <div className="usrreq-path" title={req.path}>
                            {req.path.length > 30 
                              ? `${req.path.substring(0, 30)}...` 
                              : req.path}
                          </div>
                        </td>
                        <td className="usrreq-col-actions">
                          <button
                            className={`usrreq-flag-button ${flaggedIPs.has(req.ipAddress) ? 'active' : ''}`}
                            onClick={() => toggleFlagIP(req.ipAddress)}
                            title={flaggedIPs.has(req.ipAddress) ? "Unflag IP" : "Flag IP"}
                          >
                            <FaShieldAlt />
                          </button>
                        </td>
                      </tr>
                      
                      {/* Expanded detail row */}
                      {expandedRows.has(req._id) && (
                        <tr className="usrreq-expanded-row">
                          <td colSpan="8">
                            <div className="usrreq-expanded-content">
                              <div className="usrreq-detail-grid">
                                <div className="usrreq-detail-section">
                                  <h4>Request Details</h4>
                                  <div className="usrreq-detail-item">
                                    <span className="usrreq-detail-label">Full Path:</span>
                                    <span className="usrreq-detail-value">{req.path}</span>
                                  </div>
                                  <div className="usrreq-detail-item">
                                    <span className="usrreq-detail-label">Request Time:</span>
                                    <span className="usrreq-detail-value">
                                      {formatTime(req.timestamp, { dateStyle: 'full', timeStyle: 'long' })}
                                    </span>
                                  </div>
                                  <div className="usrreq-detail-item">
                                    <span className="usrreq-detail-label">Identifier Type:</span>
                                    <span className="usrreq-detail-value">{req.identifierType}</span>
                                  </div>
                                  <div className="usrreq-detail-item">
                                    <span className="usrreq-detail-label">Identifier Value:</span>
                                    <span className="usrreq-detail-value">{req.identifierValue}</span>
                                  </div>
                                </div>
                                
                                <div className="usrreq-detail-section">
                                  <h4>Location Information</h4>
                                  <div className="usrreq-detail-item">
                                    <span className="usrreq-detail-label">IP Address:</span>
                                    <span className="usrreq-detail-value">{req.ipAddress}</span>
                                  </div>
                                  <div className="usrreq-detail-item">
                                    <span className="usrreq-detail-label">Country:</span>
                                    <span className="usrreq-detail-value">{req.geoInfo?.country || "Unknown"}</span>
                                  </div>
                                  <div className="usrreq-detail-item">
                                    <span className="usrreq-detail-label">Organization:</span>
                                    <span className="usrreq-detail-value">{req.geoInfo?.org || "Unknown"}</span>
                                  </div>
                                  <div className="usrreq-detail-item">
                                    <span className="usrreq-detail-label">ASN:</span>
                                    <span className="usrreq-detail-value">{req.geoInfo?.asn || "Unknown"}</span>
                                  </div>
                                </div>
                                
                                <div className="usrreq-detail-section usrreq-full-width">
                                  <h4>User Agent</h4>
                                  <div className="usrreq-detail-item">
                                    <span className="usrreq-detail-value usrreq-user-agent">
                                      {req.userAgent || "Unknown"}
                                    </span>
                                  </div>
                                </div>
                                
                                <div className="usrreq-detail-section usrreq-full-width">
                                  <h4>Actions</h4>
                                  <div className="usrreq-detail-actions">
                                    <button 
                                      className={`usrreq-detail-action ${flaggedIPs.has(req.ipAddress) ? 'active' : ''}`}
                                      onClick={() => toggleFlagIP(req.ipAddress)}
                                    >
                                      {flaggedIPs.has(req.ipAddress) ? (
                                        <>
                                          <FaEye /> Remove Flag from IP
                                        </>
                                      ) : (
                                        <>
                                          <FaEyeSlash /> Flag IP Address
                                        </>
                                      )}
                                    </button>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
            
            {/* Pagination controls */}
            {totalPages > 1 && (
              <div className="usrreq-pagination">
                <span className="usrreq-page-info">
                  Page {currentPage} of {totalPages} ({filteredData.length} items)
                </span>
                
                <div className="usrreq-page-controls">
                  <button
                    className="usrreq-page-button"
                    onClick={() => goToPage(1)}
                    disabled={currentPage === 1}
                  >
                    First
                  </button>
                  <button
                    className="usrreq-page-button"
                    onClick={() => goToPage(currentPage - 1)}
                    disabled={currentPage === 1}
                  >
                    Previous
                  </button>
                  
                  <div className="usrreq-page-numbers">
                    {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                      // Calculate page number to display - center around current page
                      let pageNum;
                      if (totalPages <= 5) {
                        pageNum = i + 1;
                      } else {
                        const offset = Math.min(
                          Math.max(1, currentPage - 2),
                          totalPages - 4
                        );
                        pageNum = i + offset;
                      }
                      
                      return (
                        <button
                          key={pageNum}
                          className={`usrreq-page-number ${currentPage === pageNum ? 'active' : ''}`}
                          onClick={() => goToPage(pageNum)}
                        >
                          {pageNum}
                        </button>
                      );
                    })}
                  </div>
                  
                  <button
                    className="usrreq-page-button"
                    onClick={() => goToPage(currentPage + 1)}
                    disabled={currentPage === totalPages}
                  >
                    Next
                  </button>
                  <button
                    className="usrreq-page-button"
                    onClick={() => goToPage(totalPages)}
                    disabled={currentPage === totalPages}
                  >
                    Last
                  </button>
                </div>
                
                <div className="usrreq-items-per-page">
                  <label htmlFor="itemsPerPage">Items per page:</label>
                  <select
                    id="itemsPerPage"
                    value={itemsPerPage}
                    onChange={e => setItemsPerPage(Number(e.target.value))}
                    className="usrreq-select-sm"
                  >
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                    <option value={250}>250</option>
                  </select>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default LogIp;
