// frontend/my-react-app/src/components/pages/AdminInterface/AdminInterface.js

import React, { useState } from 'react';
import { Tabs, Tab, Box } from '@mui/material';  // Material-UI tabs
import './AdminInterface.css';

// Import each sub-component
import AdminNewsletter from './AdminNewsletter';
import AdminSubscribers from './AdminSubscribers';
import AdminTriggerTasks from './AdminTriggerTasks';
import AdminMonitorStatus from './AdminMonitorStatus';

// Import the background image
import adminBackground from './adminbackground.jpg'; // Ensure the path is correct

const AdminInterface = () => {
  const [authKey, setAuthKey] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [apiKey, setApiKey] = useState('');
  const [message, setMessage] = useState('');
  const [tabIndex, setTabIndex] = useState(0);

  const handleAuthSubmit = () => {
    if (!authKey) {
      setMessage("API Key is required to proceed.");
      return;
    }
    setApiKey(authKey.trim());
    setIsAuthenticated(true);
    setMessage('');
  };

  const handleTabChange = (event, newValue) => {
    setTabIndex(newValue);
  };

  // Inline style for background image on the password page
  const authBackgroundStyle = {
    backgroundImage: `url(${adminBackground})`,
    backgroundSize: 'cover',
    backgroundPosition: 'center',
    minHeight: '100vh', /* Ensure the background covers the entire viewport */
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  };

  // Screen 1: Authentication
  if (!isAuthenticated) {
    return (
      <div className="admin-interface-container" style={authBackgroundStyle}>
        <div style={{ width: '100%' }}>
          <h2>Admin Interface</h2>
          <div className="form-group">
            <label>Enter admin password:</label>
            <input
              type="password"
              value={authKey}
              onChange={(e) => setAuthKey(e.target.value)}
              placeholder="password"
              className="admin-input"
            />
          </div>
          <button
            onClick={handleAuthSubmit}
            className="admin-submit-button"
          >
            Submit
          </button>
          {message && <p className="admin-message">{message}</p>}
        </div>
      </div>
    );
  }

  // Screen 2: Admin Dashboard with Tabs
  return (
    <div className="admin-interface-container">
      <h2>Admin Interface</h2>
      <Tabs value={tabIndex} onChange={handleTabChange} aria-label="admin tabs">
        <Tab label="Update Newsletter" />
        <Tab label="Manage Subscribers" />
        <Tab label="Trigger Tasks" />
        <Tab label="Monitor Status" />
      </Tabs>
      <Box sx={{ p: 3 }}>
        {tabIndex === 0 && <AdminNewsletter apiKey={apiKey} />}
        {tabIndex === 1 && <AdminSubscribers apiKey={apiKey} />}
        {tabIndex === 2 && <AdminTriggerTasks apiKey={apiKey} />}
        {tabIndex === 3 && <AdminMonitorStatus apiKey={apiKey} />}
      </Box>
    </div>
  );
};

export default AdminInterface;

