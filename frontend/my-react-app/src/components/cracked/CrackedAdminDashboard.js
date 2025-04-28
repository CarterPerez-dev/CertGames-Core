// src/components/cracked/CrackedAdminDashboard.js
import React, { useState, useEffect, useCallback } from "react";

import "./styles/CrackedAdminDashboard.css";
import "./styles/tabstyles/DailyTab.css";
import "./styles/tabstyles/RequestLogsTab.css";
import "./styles/tabstyles/DbShellTab.css";
import "./styles/tabstyles/NewsletterTab.css";
import "./styles/tabstyles/PerformanceTab.css";
import "./styles/tabstyles/SupportTab.css";
import "./styles/tabstyles/TestsTab.css";
import "./styles/tabstyles/UsersTab.css";
import "./styles/tabstyles/ActivityLogsTab.css";
import "./styles/tabstyles/OverviewTab.css";
import "./styles/tabstyles/HealthCheckTab.css";
import "./styles/tabstyles/RevenueTab.css"; 
import "./styles/tabstyles/RateLimitsTab.css";
import "./styles/tabstyles/ServerMetricsTab.css"; 
import "./styles/tabstyles/ToolsTab.css"; 
import "./styles/tabstyles/LogIp.css";
import "./styles/tabstyles/C2Tab.css";
import "./styles/tabstyles/HoneypotTab.css";
import "./styles/tabstyles/CredentialsTab.css";

import { 
  FaHome, FaUsers, FaClipboardList, FaCalendarDay, FaHeadset, 
  FaChartLine, FaHistory, FaDatabase, FaTerminal, FaHeartbeat, 
  FaEnvelope, FaChevronRight, FaChevronDown, FaBars, FaTimes, 
  FaSignOutAlt, FaMoneyBillWave, FaChessKnight, FaSpider, 
  FaHatWizard, FaEye, FaLinux, FaFingerprint, FaTools, FaDragon, FaFighterJet, FaGlobe, FaGhost, FaGitkraken, FaBattleNet
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
import RequestLogsTab from "./tabs/RequestLogsTab";
import DbShellTab from "./tabs/DbShellTab";
import HealthChecksTab from "./tabs/HealthChecksTab";
import RevenueTab from "./tabs/RevenueTab"; 
import RateLimitsTab from "./tabs/RateLimitsTab";
import ServerMetricsTab from "./tabs/ServerMetricsTab";
import ToolsTab from "./tabs/ToolsTab"; 
import LogIpTab from "./tabs/LogIp";
import C2Tab from "./tabs/C2Tab";
import HoneypotTab from "./tabs/HoneypotTab"; 
import CredentialsTab from "./tabs/CredentialsTab";


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
      window.location.href = "/cracked";
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
      case 'revenue': return <RevenueTab />; 
      case 'performance': return <PerformanceTab />;
      case 'tools': return <ToolsTab />;      
      case 'activity': return <ActivityLogsTab />;
      case 'dbLogs': return <RequestLogsTab />;
      case 'logIp': return <LogIpTab />;   
      case 'honeypot': return <HoneypotTab />;
      case 'c2': return <C2Tab />;
      case 'credentials': return <CredentialsTab />;        
      case 'rateLimits': return <RateLimitsTab />;         
      case 'dbShell': return <DbShellTab />;
      case 'healthChecks': return <HealthChecksTab />;
      case 'serverMetrics': return <ServerMetricsTab />;
      default: return <OverviewTab />;
      
    }
  };

  return (
    <div className={`admin-dashboard ${isNavCollapsed ? 'nav-collapsed' : ''}`}>
      <div className="admin-sidebar">
        <div className="admin-sidebar-header">
          <div className="admin-logo">
            <FaChessKnight />
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
                <FaSpider />
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
            <li className={activeTab === "tools" ? "active" : ""}>
              <button onClick={() => switchTab("tools")}>
                <FaHatWizard />
                <span>Tools</span>
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
                <FaDragon />
                <span>Security</span>
              </button>
            </li>
            <li className={activeTab === "dbLogs" ? "active" : ""}>
              <button onClick={() => switchTab("dbLogs")}>
                <FaEye />
                <span>Requests</span>
              </button>
            </li>
            <li className={activeTab === "logIp" ? "active" : ""}>
              <button onClick={() => switchTab("logIp")}>
                <FaGlobe />
                <span>User Requests</span>
              </button>
            </li>             
            <li className={activeTab === "honeypot" ? "active" : ""}>
              <button onClick={() => switchTab("honeypot")}>
                <FaBattleNet/> 
                <span>Honeypot</span>                
              </button>
            </li>
            <li className={activeTab === "c2" ? "active" : ""}>
              <button onClick={() => switchTab("c2")}>
                <FaGitkraken /> 
                <span>C2 Server</span>
              </button>
            </li>          
            <li className={activeTab === "credentials" ? "active" : ""}>
              <button onClick={() => switchTab("credentials")}>
                <FaGhost /> 
                <span>Extracted</span>
              </button>
            </li>     
           <li className={activeTab === "rateLimits" ? "active" : ""}>
              <button onClick={() => switchTab("rateLimits")}>
                <FaFingerprint />
                <span>Rate Limits</span>
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
            <li className={activeTab === "serverMetrics" ? "active" : ""}>
              <button onClick={() => switchTab("serverMetrics")}>
                <FaLinux />
                <span>Server Metrics</span>
              </button>
            </li>                              
          </ul>
        </nav>            
                       
        <div className="admin-sidebar-footer">
          <button className="admin-logout-btn" onClick={handleLogout}>
            <FaFighterJet />
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
                <FaSpider /> Dashboard
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
              <button onClick={() => switchTab("tools")}>
                <FaHatWizard /> Tools
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("performance")}>
                <FaChartLine /> Performance
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("activity")}>
                <FaDragon /> Activity
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("dbLogs")}>
                <FaEye /> Request Logs
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("logIp")}>
                <FaGlobe /> User Requests
              </button>
            </li>                    
            <li>
              <button onClick={() => switchTab("honeypot")}>
                <FaBattleNet/> Honeypot
              </button>
            </li>                
            <li>
              <button onClick={() => switchTab("c2")}>
                <FaGitkraken /> C2 Server
              </button>
            </li>                               
            <li>
              <button onClick={() => switchTab("credentials")}>
                <FaGhost/> Extracted
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("rateLimits")}>
                <FaFingerprint /> Rate Limits
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
              <button onClick={() => switchTab("serverMetrics")}>
                <FaLinux /> Server Metrics
              </button>
            </li>
            <li>
              <button onClick={handleLogout} className="mobile-logout-btn">
                <FaFighterJet /> Logout
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
