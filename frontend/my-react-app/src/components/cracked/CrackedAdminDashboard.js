// src/components/cracked/CrackedAdminDashboard.js
import React, { useState, useEffect, useCallback } from "react";


import "./styles/CrackedAdminDashboard.css";
import "./styles/tabstyles/DailyTab.css";
import "./styles/tabstyles/DbLogsTab.css";
import "./styles/tabstyles/DbShellTab.css";
import "./styles/tabstyles/NewsletterTab.css";
import "./styles/tabstyles/PerformanceTab.css";
import "./styles/tabstyles/SupportTab.css";
import "./styles/tabstyles/TestsTab.css";
import "./styles/tabstyles/UsersTab.css";
import "./styles/tabstyles/ActivityLogsTab.css";
import "./styles/tabstyles/OverviewTab.css";
import "./styles/tabstyles/HealthCheckTab.css";
import "./styles/tabstyles/RevenueTab.css"; // Added for Revenue Tab




import { 
  FaHome, FaUsers, FaClipboardList, FaCalendarDay, FaHeadset, 
  FaChartLine, FaHistory, FaDatabase, FaTerminal, FaHeartbeat, 
  FaEnvelope, FaChevronRight, FaChevronDown, FaBars, FaTimes, 
  FaSignOutAlt, FaMoneyBillWave // Added for Revenue Tab
} from "react-icons/fa";

// Import tab components
import OverviewTab from "./tabs/OverviewTab";
import UsersTab from "./tabs/UsersTab";
import TestsTab from "./tabs/TestsTab";
import DailyTab from "./tabs/DailyTab";
import SupportTab from "./tabs/SupportTab";
import NewsletterTab from "./tabs/NewsletterTab";
import PerformanceTab from "./tabs/PerformanceTab";
import ActivityLogsTab from "./tabs/ActivityLogsTab";
import DbLogsTab from "./tabs/DbLogsTab";
import DbShellTab from "./tabs/DbShellTab";
import HealthChecksTab from "./tabs/HealthChecksTab";
import RevenueTab from "./tabs/RevenueTab"; // Added for Revenue Tab

function CrackedAdminDashboard() {
  const [activeTab, setActiveTab] = useState("overview");
  const [isNavCollapsed, setIsNavCollapsed] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  /*****************************************
   * LOGOUT 
   *****************************************/
  const handleLogout = async () => {
    try {
      await fetch("/api/cracked/logout", {
        method: "POST",
        credentials: "include"
      });
      window.location.href = "/cracked/login";
    } catch (err) {
      console.error("Logout error:", err);
    }
  };

  /*****************************************
   * TAB SWITCH
   *****************************************/
  const switchTab = (tabName) => {
    setActiveTab(tabName);
    setMobileNavOpen(false);
  };

  // Render the appropriate tab component based on activeTab
  const renderTabContent = () => {
    switch(activeTab) {
      case 'overview': return <OverviewTab />;
      case 'users': return <UsersTab />;
      case 'tests': return <TestsTab />;
      case 'daily': return <DailyTab />;
      case 'support': return <SupportTab />;
      case 'newsletter': return <NewsletterTab />;
      case 'revenue': return <RevenueTab />; // Added for Revenue Tab
      case 'performance': return <PerformanceTab />;
      case 'activity': return <ActivityLogsTab />;
      case 'dbLogs': return <DbLogsTab />;
      case 'dbShell': return <DbShellTab />;
      case 'healthChecks': return <HealthChecksTab />;
      default: return <OverviewTab />;
    }
  };

  return (
    <div className={`admin-dashboard ${isNavCollapsed ? 'nav-collapsed' : ''}`}>
      <div className="admin-sidebar">
        <div className="admin-sidebar-header">
          <div className="admin-logo">
            <FaDatabase />
            <h1>Admin</h1>
          </div>
          <button 
            className="admin-collapse-btn"
            onClick={() => setIsNavCollapsed(!isNavCollapsed)}
            title={isNavCollapsed ? "Expand Navigation" : "Collapse Navigation"}
          >
            {isNavCollapsed ? <FaChevronRight /> : <FaChevronDown />}
          </button>
        </div>
        
        <nav className="admin-nav">
          <ul className="admin-nav-list">
            <li className={activeTab === "overview" ? "active" : ""}>
              <button onClick={() => switchTab("overview")}>
                <FaHome />
                <span>Dashboard</span>
              </button>
            </li>
            <li className={activeTab === "users" ? "active" : ""}>
              <button onClick={() => switchTab("users")}>
                <FaUsers />
                <span>Users</span>
              </button>
            </li>
            <li className={activeTab === "tests" ? "active" : ""}>
              <button onClick={() => switchTab("tests")}>
                <FaClipboardList />
                <span>Tests</span>
              </button>
            </li>
            <li className={activeTab === "daily" ? "active" : ""}>
              <button onClick={() => switchTab("daily")}>
                <FaCalendarDay />
                <span>Daily PBQs</span>
              </button>
            </li>
            <li className={activeTab === "support" ? "active" : ""}>
              <button onClick={() => switchTab("support")}>
                <FaHeadset />
                <span>Support</span>
              </button>
            </li>
            <li className={activeTab === "newsletter" ? "active" : ""}>
              <button onClick={() => switchTab("newsletter")}>
                <FaEnvelope />
                <span>Newsletter</span>
              </button>
            </li>
            <li className={activeTab === "revenue" ? "active" : ""}>
              <button onClick={() => switchTab("revenue")}>
                <FaMoneyBillWave />
                <span>Revenue</span>
              </button>
            </li>
            <li className={activeTab === "performance" ? "active" : ""}>
              <button onClick={() => switchTab("performance")}>
                <FaChartLine />
                <span>Performance</span>
              </button>
            </li>
            <li className={activeTab === "activity" ? "active" : ""}>
              <button onClick={() => switchTab("activity")}>
                <FaHistory />
                <span>Activity</span>
              </button>
            </li>
            <li className={activeTab === "dbLogs" ? "active" : ""}>
              <button onClick={() => switchTab("dbLogs")}>
                <FaDatabase />
                <span>DB Logs</span>
              </button>
            </li>
            <li className={activeTab === "dbShell" ? "active" : ""}>
              <button onClick={() => switchTab("dbShell")}>
                <FaTerminal />
                <span>DB Shell</span>
              </button>
            </li>
            <li className={activeTab === "healthChecks" ? "active" : ""}>
              <button onClick={() => switchTab("healthChecks")}>
                <FaHeartbeat />
                <span>Health Checks</span>
              </button>
            </li>
          </ul>
        </nav>
        
        <div className="admin-sidebar-footer">
          <button className="admin-logout-btn" onClick={handleLogout}>
            <FaSignOutAlt />
            <span>Logout</span>
          </button>
        </div>
      </div>
      
      {/* Mobile Header with menu toggle */}
      <div className="admin-mobile-header">
        <button 
          className="admin-mobile-menu-toggle"
          onClick={() => setMobileNavOpen(!mobileNavOpen)}
        >
          {mobileNavOpen ? <FaTimes /> : <FaBars />}
        </button>
        <div className="admin-mobile-logo">
          <FaDatabase />
          <h1>Admin Dashboard</h1>
        </div>
      </div>
      
      {/* Mobile Navigation Overlay */}
      <div className={`admin-mobile-nav ${mobileNavOpen ? 'active' : ''}`}>
        <nav>
          <ul>
            <li>
              <button onClick={() => switchTab("overview")}>
                <FaHome /> Dashboard
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("users")}>
                <FaUsers /> Users
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("tests")}>
                <FaClipboardList /> Tests
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("daily")}>
                <FaCalendarDay /> Daily PBQs
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("support")}>
                <FaHeadset /> Support
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("newsletter")}>
                <FaEnvelope /> Newsletter
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("revenue")}>
                <FaMoneyBillWave /> Revenue
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("performance")}>
                <FaChartLine /> Performance
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("activity")}>
                <FaHistory /> Activity
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("dbLogs")}>
                <FaDatabase /> DB Logs
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("dbShell")}>
                <FaTerminal /> DB Shell
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("healthChecks")}>
                <FaHeartbeat /> Health Checks
              </button>
            </li>
            <li>
              <button onClick={handleLogout} className="mobile-logout-btn">
                <FaSignOutAlt /> Logout
              </button>
            </li>
          </ul>
        </nav>
      </div>
      
      {/* Main Content Area */}
      <div className="admin-main-content">
        {renderTabContent()}
      </div>
    </div>
  );
}

export default CrackedAdminDashboard;
