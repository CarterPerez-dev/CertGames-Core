import React, { useState, useEffect } from 'react';
import { FaGlobe, FaUser, FaFingerprint, FaUserSecret, FaNetworkWired, FaBan } from 'react-icons/fa';
import { adminFetch } from '../csrfHelper';
import '../styles/tabstyles/LogIp.css';

function LogIp() {
  const [requests, setRequests] = useState([]);
  const [grouped, setGrouped] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  
  useEffect(() => {
    fetchUserRequests();
    
    // Refresh data every minute
    const interval = setInterval(fetchUserRequests, 60000);
    return () => clearInterval(interval);
  }, []);
  
  const fetchUserRequests = async () => {
    try {
      setLoading(true);
      const response = await adminFetch('/api/cracked/user-requests');
      if (!response.ok) {
        throw new Error('Failed to fetch user requests');
      }
      
      const data = await response.json();
      setRequests(data.requests);
      setGrouped(data.grouped);
      setLoading(false);
    } catch (err) {
      console.error('Error fetching user requests:', err);
      setError(err.message);
      setLoading(false);
    }
  };
  
  const getTabData = () => {
    if (activeTab === 'all') {
      return requests;
    } else {
      return grouped[activeTab] || [];
    }
  };
  
  const filteredData = getTabData().filter(req => {
    if (!searchTerm) return true;
    const searchLower = searchTerm.toLowerCase();
    
    return (
      req.path?.toLowerCase().includes(searchLower) ||
      req.identifierValue?.toLowerCase().includes(searchLower) ||
      req.ipAddress?.toLowerCase().includes(searchLower) ||
      req.geoInfo?.country?.toLowerCase().includes(searchLower) ||
      req.geoInfo?.org?.toLowerCase().includes(searchLower)
    );
  });
  
  const getIdentifierIcon = (type) => {
    switch (type) {
      case 'username': return <FaUser className="id-icon username" />;
      case 'userId': return <FaFingerprint className="id-icon userid" />;
      case 'sessionId': return <FaUserSecret className="id-icon sessionid" />;
      case 'xUserId': return <FaUser className="id-icon xuserid" />;
      case 'ipOnly': return <FaNetworkWired className="id-icon iponly" />;
      default: return <FaNetworkWired className="id-icon" />;
    }
  };
  
  const formatTime = (isoString) => {
    try {
      const date = new Date(isoString);
      return date.toLocaleString();
    } catch {
      return isoString;
    }
  };
  
  if (loading && !requests.length) {
    return <div className="requests-loading">Loading request data...</div>;
  }
  
  if (error) {
    return <div className="requests-error">Error: {error}</div>;
  }
  
  return (
    <div className="requests-tab-container">
      <div className="requests-header">
        <h2><FaGlobe /> User Requests Monitor</h2>
        <p>Tracking unique user requests across the platform with a 5-minute cooldown per request.</p>
        
        <div className="requests-controls">
          <div className="search-box">
            <input
              type="text"
              placeholder="Search requests..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
            />
          </div>
          
          <button className="refresh-button" onClick={fetchUserRequests}>
            Refresh Data
          </button>
        </div>
        
        <div className="requests-tabs">
          <button 
            className={activeTab === 'all' ? 'active' : ''} 
            onClick={() => setActiveTab('all')}
          >
            All Requests ({requests.length})
          </button>
          <button 
            className={activeTab === 'username' ? 'active' : ''} 
            onClick={() => setActiveTab('username')}
          >
            By Username ({grouped.username?.length || 0})
          </button>
          <button 
            className={activeTab === 'userId' ? 'active' : ''} 
            onClick={() => setActiveTab('userId')}
          >
            By User ID ({grouped.userId?.length || 0})
          </button>
          <button 
            className={activeTab === 'sessionId' ? 'active' : ''} 
            onClick={() => setActiveTab('sessionId')}
          >
            By Session ID ({grouped.sessionId?.length || 0})
          </button>
          <button 
            className={activeTab === 'xUserId' ? 'active' : ''} 
            onClick={() => setActiveTab('xUserId')}
          >
            By X-User-ID ({grouped.xUserId?.length || 0})
          </button>
          <button 
            className={activeTab === 'ipOnly' ? 'active' : ''} 
            onClick={() => setActiveTab('ipOnly')}
          >
            By IP Only ({grouped.ipOnly?.length || 0})
          </button>
        </div>
      </div>
      
      <div className="requests-content">
        {filteredData.length === 0 ? (
          <div className="no-requests">
            <FaBan />
            <p>No requests found matching your criteria</p>
          </div>
        ) : (
          <table className="requests-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Identifier</th>
                <th>IP Address</th>
                <th>Location</th>
                <th>Method</th>
                <th>Path</th>
                <th>User Agent</th>
              </tr>
            </thead>
            <tbody>
              {filteredData.map(req => (
                <tr key={req._id}>
                  <td>{formatTime(req.timestamp)}</td>
                  <td>
                    {getIdentifierIcon(req.identifierType)}
                    <span className="id-value">{req.identifierValue}</span>
                  </td>
                  <td>{req.ipAddress}</td>
                  <td>
                    <div className="geo-info">
                      <div>{req.geoInfo?.country || "Unknown"}</div>
                      <div className="org-name">{req.geoInfo?.org || "Unknown"}</div>
                    </div>
                  </td>
                  <td>
                    <span className={`method-badge ${req.method?.toLowerCase()}`}>
                      {req.method}
                    </span>
                  </td>
                  <td>
                    <div className="request-path">{req.path}</div>
                  </td>
                  <td>
                    <div className="user-agent">{req.userAgent}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export default LogIp;
