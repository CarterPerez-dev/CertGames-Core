
import React, { useState, useRef, useEffect } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import './Sidebar.css';
import sidebarLogo from './sidebarlogo.png'; 
import { 
  FaChevronDown, 
  FaChevronUp, 
  FaBars, 
  FaTimes,
  FaUser,
  FaTrophy, 
  FaStore, 
  FaGift, 
  FaChartBar,
  FaQuestion,
  FaTools,
  FaNewspaper,
  FaBook,
  FaLaptopCode
} from 'react-icons/fa';

const Sidebar = () => {
  const [collapsed, setCollapsed] = useState(true);
  const [toolsOpen, setToolsOpen] = useState(false);
  const [practiceTestsOpen, setPracticeTestsOpen] = useState(false);

  const navigate = useNavigate();
  const sidebarRef = useRef(null);
  const toggleButtonRef = useRef(null);

  const toggleSidebar = () => {
    setCollapsed(!collapsed);
  };

  const toggleTools = () => {
    setToolsOpen(!toolsOpen);
  };

  const togglePracticeTests = () => {
    setPracticeTestsOpen(!practiceTestsOpen);
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      // if sidebar is open
      if (!collapsed) {
        // check if clicked inside sidebar
        const clickedInsideSidebar = sidebarRef.current?.contains(event.target);
        // check if clicked on the toggle button
        const clickedToggleButton = toggleButtonRef.current?.contains(event.target);

        // if the click is outside sidebar AND not on the toggle button, collapse
        if (!clickedInsideSidebar && !clickedToggleButton) {
          setCollapsed(true);
        }
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [collapsed]);

  // Icon mapping for main menu items
  const getIcon = (path) => {
    switch(path) {
      case '/profile': return <FaUser className="sidebar-icon" />;
      case '/achievements': return <FaTrophy className="sidebar-icon" />;
      case '/shop': return <FaStore className="sidebar-icon" />;
      case '/daily': return <FaGift className="sidebar-icon" />;
      case '/leaderboard': return <FaChartBar className="sidebar-icon" />;
      case '/my-support': return <FaQuestion className="sidebar-icon" />;
      case '/dailycyberbrief': return <FaNewspaper className="sidebar-icon" />;
      case '/resources': return <FaBook className="sidebar-icon" />;
      default: return null;
    }
  };

  return (
    <>
      {/* Sidebar Toggle Button */}
      <button
        ref={toggleButtonRef}
        className="sidebar-toggle"
        onClick={toggleSidebar}
        aria-label={collapsed ? "Open sidebar" : "Close sidebar"}
      >
        {collapsed ? <FaBars /> : <FaTimes />}
      </button>

      <div ref={sidebarRef} className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
        <div className="sidebar-content">
          <h2 className="sidebar-title">root@</h2>
          
          <nav className="sidebar-nav">
            <ul className="sidebar-list">
              <li>
                <NavLink to="/profile" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/profile')}
                  <span className="sidebar-link-text">/Profile</span>
                </NavLink>
              </li>
              <li>
                <NavLink to="/achievements" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/achievements')}
                  <span className="sidebar-link-text">/Achievements</span>
                </NavLink>
              </li>
              <li>
                <NavLink to="/shop" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/shop')}
                  <span className="sidebar-link-text">/Shop</span>
                </NavLink>
              </li>
              <li>
                <NavLink to="/daily" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/daily')}
                  <span className="sidebar-link-text">/Bonus</span>
                </NavLink>
              </li>
              <li>
                <NavLink to="/leaderboard" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/leaderboard')}
                  <span className="sidebar-link-text">/Leaderboard</span>
                </NavLink>
              </li>
              <li>
                <NavLink to="/my-support" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/my-support')}
                  <span className="sidebar-link-text">/Questions</span>
                </NavLink>
              </li>
              
              {/* Tools group */}
              <li className="sidebar-group">
                <div
                  className="group-header"
                  onClick={toggleTools}
                  role="button"
                  tabIndex={0}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') toggleTools();
                  }}
                >
                  <div className="group-header-content">
                    <FaTools className="sidebar-icon" />
                    <span className="sidebar-link-text">/Tools</span>
                  </div>
                  {toolsOpen ? <FaChevronUp className="group-icon" /> : <FaChevronDown className="group-icon" />}
                </div>
                <ul className={`group-sublist ${toolsOpen ? 'expanded' : ''}`}>
                  <li>
                    <NavLink to="/xploitcraft" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Xploitcraft</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/scenariosphere" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Scenario Sphere</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/analogyhub" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Analogy Hub</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/grc" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">GRC Wizard</span>
                    </NavLink>
                  </li>
                </ul>
              </li>

              {/* Daily CyberBrief */}
              <li>
                <NavLink to="/dailycyberbrief" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/dailycyberbrief')}
                  <span className="sidebar-link-text">/Daily CyberBrief</span>
                </NavLink>
              </li>

              {/* Study Resources */}
              <li>
                <NavLink to="/resources" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/resources')}
                  <span className="sidebar-link-text">/Study Resources</span>
                </NavLink>
              </li>

              {/* Practice Tests group */}
              <li className="sidebar-group">
                <div
                  className="group-header"
                  onClick={togglePracticeTests}
                  role="button"
                  tabIndex={0}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') togglePracticeTests();
                  }}
                >
                  <div className="group-header-content">
                    <FaLaptopCode className="sidebar-icon" />
                    <span className="sidebar-link-text">/Practice Tests</span>
                  </div>
                  {practiceTestsOpen ? <FaChevronUp className="group-icon" /> : <FaChevronDown className="group-icon" />}
                </div>
                <ul className={`group-sublist ${practiceTestsOpen ? 'expanded' : ''}`}>
                  <li>
                    <NavLink to="/practice-tests/a-plus" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">A+ Core 1</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/aplus-core2" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">A+ Core 2</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/network-plus" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Network+</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/security-plus" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Security+</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/cysa-plus" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">CySa+</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/pen-plus" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Pentest+</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/casp-plus" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">CASP+</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/linux-plus" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Linux+</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/cloud-plus" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Cloud+</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/data-plus" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Data+</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/server-plus" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Server+</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/cissp" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">CISSP</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/practice-tests/aws-cloud" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">AWS Cloud Practitioner</span>
                    </NavLink>
                  </li>
                </ul>
              </li>
            </ul>
          </nav>

          <div className="sidebar-logo-container">
            <img src={sidebarLogo} alt="Sidebar Logo" className="sidebar-logo" />
          </div>
        </div>
      </div>
    </>
  );
};

export default Sidebar;
/* Sidebar.css - Enhanced styling while maintaining core functionality */

:root {
  --sidebar-bg: #121212;
  --sidebar-border: #222222;
  --sidebar-text: #e2dfd2;
  --sidebar-text-hover: #ffffff;
  --sidebar-accent: #cc0000;
  --sidebar-accent-hover: #ff3333;
  --sidebar-item-hover-bg: rgba(255, 255, 255, 0.05);
  --sidebar-active-bg: rgba(204, 0, 0, 0.1);
  --sidebar-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
  --sidebar-glow: 0 0 10px rgba(204, 0, 0, 0.5);
}

/* Reset some defaults */
body, html {
  margin: 0;
  padding: 0;
  overflow-x: hidden;
  font-family: 'Orbitron', sans-serif;
}

/* Sidebar Container */
.sidebar {
  position: fixed;
  top: 0;
  left: 0;
  width: 220px;
  height: 100vh;
  background-color: var(--sidebar-bg);
  color: var(--sidebar-text);
  padding: 10px;
  border: 2px solid var(--sidebar-border);
  border-left: none;
  border-top-right-radius: 12px;
  border-bottom-right-radius: 12px;
  display: flex;
  flex-direction: column;
  transform: translateX(-220px);
  transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  z-index: 1500;
  box-shadow: var(--sidebar-shadow);
}

.sidebar-content {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow-y: auto;
  overflow-x: hidden;
  scrollbar-width: none; /* Firefox */
  -ms-overflow-style: none; /* IE and Edge */
}

/* Hide scrollbar */
.sidebar-content::-webkit-scrollbar {
  display: none; /* Chrome, Safari, Opera */
}

.sidebar:not(.collapsed) {
  transform: translateX(0);
}

.sidebar.collapsed {
  transform: translateX(-220px);
}

/* Sidebar Title */
.sidebar-title {
  font-family: 'Orbitron', sans-serif;
  font-size: 1.9em;
  margin-bottom: 28px;
  color: var(--sidebar-accent);
  text-align: center;
  text-shadow: 1px 1px 0px #ffffff;
  padding: 10px 0;
}

/* Sidebar Navigation */
.sidebar-nav {
  flex-grow: 1;
}

/* Sidebar List */
.sidebar-list {
  list-style-type: none;
  padding: 0;
  margin: 0;
  font-family: 'Orbitron', sans-serif;
}

.sidebar-list li {
  margin-bottom: 12px;
}

/* Standard Link */
.sidebar-link {
  color: var(--sidebar-text);
  text-decoration: none;
  font-weight: bold;
  transition: all 0.2s ease;
  padding: 10px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  gap: 10px;
  position: relative;
  overflow: hidden;
}

.sidebar-link::before {
  content: "";
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 3px;
  background-color: transparent;
  transition: background-color 0.2s ease;
}

.sidebar-link:hover {
  background-color: var(--sidebar-item-hover-bg);
  color: var(--sidebar-text-hover);
}

.sidebar-link:hover::before {
  background-color: var(--sidebar-accent);
}

.sidebar-link.active-link {
  background-color: var(--sidebar-active-bg);
  color: var(--sidebar-accent);
}

.sidebar-link.active-link::before {
  background-color: var(--sidebar-accent);
}

.sidebar-icon {
  font-size: 18px;
  color: var(--sidebar-accent);
  min-width: 20px;
  transition: transform 0.2s ease;
}

.sidebar-link:hover .sidebar-icon {
  transform: scale(1.1);
  color: var(--sidebar-accent-hover);
}

/* Group Header (for Tools, Practice Tests) */
.sidebar-group .group-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: var(--sidebar-text);
  font-weight: bold;
  cursor: pointer;
  padding: 10px;
  border-radius: 8px;
  transition: all 0.2s ease;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
  margin-bottom: 5px;
}

.group-header-content {
  display: flex;
  align-items: center;
  gap: 10px;
}

.sidebar-group .group-header:hover {
  background-color: var(--sidebar-item-hover-bg);
  color: var(--sidebar-text-hover);
}

.sidebar-group .group-header:hover .sidebar-icon {
  transform: scale(1.1);
  color: var(--sidebar-accent-hover);
}

.group-icon {
  font-size: 14px;
  color: var(--sidebar-accent);
  transition: transform 0.2s ease;
}

/* Group Sublist */
.group-sublist {
  list-style-type: none;
  padding-left: 25px;
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.3s ease, opacity 0.3s ease;
  opacity: 0;
}

.group-sublist.expanded {
  max-height: 1000px; /* This should be large enough to accommodate all items */
  opacity: 1;
}

.group-sublist li {
  margin-bottom: 10px;
}

.sidebar-sublink {
  color: var(--sidebar-text);
  text-decoration: none;
  transition: all 0.2s ease;
  padding: 8px 10px;
  border-radius: 8px;
  display: block;
  font-size: 0.9em;
  position: relative;
}

.sidebar-sublink::before {
  content: "-";
  margin-right: 5px;
  color: var(--sidebar-accent);
  transition: content 0.2s ease, color 0.2s ease;
}

.sidebar-sublink:hover {
  background-color: var(--sidebar-item-hover-bg);
  color: var(--sidebar-text-hover);
}

.sidebar-sublink:hover::before {
  content: "→";
  color: var(--sidebar-text-hover);
}

.sidebar-sublink.active-subtab {
  background-color: var(--sidebar-active-bg);
  color: var(--sidebar-accent);
}

/* Sidebar Logo Container */
.sidebar-logo-container {
  text-align: center;
  margin-top: 20px;
  padding-bottom: 20px;
}

.sidebar-logo {
  width: 80%;
  max-width: 180px;
  border-radius: 5px;
  filter: brightness(2.2);
  transition: transform 0.3s ease;
}

.sidebar-logo:hover {
  transform: scale(1.05);
}

/* Toggle Button */
.sidebar-toggle {
  position: fixed;
  top: 15px;
  left: 15px;
  z-index: 2001;
  background-color: rgba(18, 18, 18, 0.8);
  border: 1px solid var(--sidebar-border);
  border-radius: 8px;
  color: var(--sidebar-accent);
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  font-size: 20px;
  cursor: pointer;
  transition: all 0.2s ease;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
  backdrop-filter: blur(5px);
}

.sidebar-toggle:hover {
  background-color: var(--sidebar-accent);
  color: white;
  transform: scale(1.05);
}

.sidebar:not(.collapsed) ~ .sidebar-toggle {
  left: 230px;
}

/* Responsive Adjustments */

/* Tablets */
@media (max-width: 768px) {
  .sidebar {
    width: 180px;
    transform: translateX(-180px);
  }
  
  .sidebar:not(.collapsed) {
    transform: translateX(0);
  }
  
  .sidebar.collapsed {
    transform: translateX(-180px);
  }
  
  .sidebar-title {
    font-size: 1.7em;
    margin-bottom: 20px;
  }
  
  .sidebar-link, .sidebar-group .group-header {
    padding: 8px;
  }
  
  .sidebar-icon {
    font-size: 16px;
  }
  
  .sidebar:not(.collapsed) ~ .sidebar-toggle {
    left: 190px;
  }
  
  .sidebar-logo-container {
    padding-bottom: 30px;
  }
  
  .sidebar-logo {
    max-width: 160px;
  }
  
  .group-sublist {
    padding-left: 20px;
  }
}

/* Mobile Phones */
@media (max-width: 480px) {
  .sidebar {
    width: 160px;
    transform: translateX(-160px);
    border-radius: 0;
    border-right: 1px solid var(--sidebar-border);
    border-left: none;
    border-top: none;
    border-bottom: none;
  }
  
  .sidebar:not(.collapsed) {
    transform: translateX(0);
  }
  
  .sidebar.collapsed {
    transform: translateX(-160px);
  }
  
  .sidebar-title {
    font-size: 1.5em;
    margin-bottom: 15px;
    padding: 5px 0;
  }
  
  .sidebar-link, .sidebar-group .group-header {
    padding: 8px 5px;
    font-size: 0.9em;
  }
  
  .sidebar-icon {
    font-size: 14px;
  }
  
  .sidebar:not(.collapsed) ~ .sidebar-toggle {
    left: 170px;
  }
  
  .sidebar-toggle {
    width: 36px;
    height: 36px;
    font-size: 18px;
    top: 10px;
    left: 10px;
  }
  
  .sidebar-logo-container {
    padding-bottom: 20px;
  }
  
  .sidebar-logo {
    max-width: 130px;
  }
  
  .group-sublist {
    padding-left: 15px;
  }
  
  .group-sublist li {
    margin-bottom: 8px;
  }
  
  .sidebar-sublink {
    padding: 6px 8px;
    font-size: 0.85em;
  }
}

/* Very small screens */
@media (max-width: 320px) {
  .sidebar {
    width: 140px;
    transform: translateX(-140px);
  }
  
  .sidebar:not(.collapsed) {
    transform: translateX(0);
  }
  
  .sidebar.collapsed {
    transform: translateX(-140px);
  }
  
  .sidebar-title {
    font-size: 1.3em;
    margin-bottom: 10px;
  }
  
  .sidebar-link-text {
    font-size: 0.9em;
  }
  
  .sidebar:not(.collapsed) ~ .sidebar-toggle {
    left: 150px;
  }
  
  .sidebar-toggle {
    width: 32px;
    height: 32px;
    font-size: 16px;
  }
  
  .sidebar-logo {
    max-width: 110px;
  }
  
  .sidebar-logo-container {
    padding-bottom: 15px;
  }
  
  .group-sublist {
    padding-left: 12px;
  }
}
// src/components/pages/store/UserProfile.js
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { logout, fetchUserData } from '../store/userSlice';
import { useNavigate } from 'react-router-dom';
import './UserProfile.css';

// Icons import
import {
  FaTrophy,
  FaMedal,
  FaStar,
  FaCrown,
  FaBolt,
  FaBook,
  FaBrain,
  FaCheckCircle,
  FaRegSmile,
  FaMagic,
  FaEye,
  FaEyeSlash,
  FaCoins,
  FaEdit,
  FaUserAlt,
  FaEnvelope,
  FaKey,
  FaSignOutAlt,
  FaChevronRight,
  FaChevronDown,
  FaChevronUp,
  FaStore,
  FaTimes,
  FaCheck,
  FaUserCircle,
  FaLevelUpAlt
} from 'react-icons/fa';

// Requirements component for password validation
import PasswordRequirements from '../auth/PasswordRequirements';

// ==========================
// FRONTEND VALIDATION HELPERS
// ==========================

// Example small dictionary of very common passwords
const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "qwerty", "letmein", "welcome"
]);

// Private Use / Surrogates ranges
const PRIVATE_USE_RANGES = [
  [0xE000, 0xF8FF],
  [0xF0000, 0xFFFFD],
  [0x100000, 0x10FFFD]
];
const SURROGATES_RANGE = [0xD800, 0xDFFF];

// Basic check for private use / surrogate codepoints
function hasForbiddenUnicodeScripts(str) {
  for (let i = 0; i < str.length; i++) {
    const cp = str.codePointAt(i);
    // Surrogates
    if (cp >= SURROGATES_RANGE[0] && cp <= SURROGATES_RANGE[1]) {
      return true;
    }
    // Private use
    for (const [start, end] of PRIVATE_USE_RANGES) {
      if (cp >= start && cp <= end) {
        return true;
      }
    }
  }
  return false;
}

// Disallow mixing major scripts
function disallowMixedScripts(str) {
  const scriptSets = new Set();
  for (let i = 0; i < str.length; i++) {
    const cp = str.codePointAt(i);
    // Basic Latin & extended
    if (cp >= 0x0041 && cp <= 0x024F) {
      scriptSets.add("Latin");
    }
    // Greek
    else if (cp >= 0x0370 && cp <= 0x03FF) {
      scriptSets.add("Greek");
    }
    // Cyrillic
    else if (cp >= 0x0400 && cp <= 0x04FF) {
      scriptSets.add("Cyrillic");
    }
    if (scriptSets.size > 1) {
      return true;
    }
  }
  return false;
}

// ========================
// FRONTEND: Validate Username
// ========================
function frontValidateUsername(username) {
  const errors = [];
  const name = username.normalize("NFC");

  // 1) Length
  if (name.length < 3 || name.length > 30) {
    errors.push("Username must be between 3 and 30 characters long.");
  }

  // 2) Forbidden Unicode script checks
  if (hasForbiddenUnicodeScripts(name)) {
    errors.push("Username contains forbidden Unicode blocks.");
  }

  // 3) Disallow mixing multiple major scripts
  if (disallowMixedScripts(name)) {
    errors.push("Username cannot mix multiple Unicode scripts.");
  }

  // 4) Forbid control chars [0..31, 127] + suspicious punctuation
  const forbiddenRanges = [[0, 31], [127, 127]];
  const forbiddenChars = new Set(['<', '>', '\\', '/', '"', "'", ';', '`',' ', '\t', '\r', '\n']);
  for (let i = 0; i < name.length; i++) {
    const cp = name.charCodeAt(i);
    // Check ranges
    if (forbiddenRanges.some(([start, end]) => cp >= start && cp <= end)) {
      errors.push("Username contains forbidden control characters.");
      break;
    }
    if (forbiddenChars.has(name[i])) {
      errors.push("Username contains forbidden characters.");
      break;
    }
  }

  // 5) Strict allowlist pattern
  const pattern = /^[A-Za-z0-9._-]+$/;
  if (!pattern.test(name)) {
    errors.push("Username can only contain letters, digits, underscores, dashes, or dots.");
  }

  // 6) Disallow triple identical consecutive characters
  if (/(.)\1{2,}/.test(name)) {
    errors.push("Username cannot contain three identical consecutive characters.");
  }

  // 7) Disallow leading or trailing punctuation
  if (/^[._-]|[._-]$/.test(name)) {
    errors.push("Username cannot start or end with . - or _.");
  }

  return errors;
}

// ========================
// FRONTEND: Validate Email
// ========================
function frontValidateEmail(email) {
  const errors = [];
  const e = email.normalize("NFC").trim();

  // 1) Length
  if (e.length < 5 || e.length > 128) {
    errors.push("Email length must be between 5 and 128 characters.");
  }

  // 3) Forbid suspicious ASCII
  const forbiddenAscii = new Set(['<','>','`',';',' ', '\t','\r','\n','"',"'", '\\']);
  for (let i = 0; i < e.length; i++) {
    if (forbiddenAscii.has(e[i])) {
      errors.push("Email contains forbidden characters.");
      break;
    }
  }

  // 4) Must have exactly one @
  const atCount = (e.match(/@/g) || []).length;
  if (atCount !== 1) {
    errors.push("Email must contain exactly one '@' symbol.");
  }

  return errors;
}

// ========================
// FRONTEND: Validate Password
// ========================
function frontValidatePassword(password, username, email) {
  const errors = [];
  const pwd = password;

  // 1) Length
  if (pwd.length < 6 || pwd.length > 64) {
    errors.push("Password must be between 6 and 64 characters long.");
  }

  // 2) Disallow whitespace or < >
  if (/[ \t\r\n<>]/.test(pwd)) {
    errors.push("Password cannot contain whitespace or < or > characters.");
  }

  // 3) Complexity
  if (!/[A-Z]/.test(pwd)) {
    errors.push("Password must contain at least one uppercase letter.");
  }
  if (!/[a-z]/.test(pwd)) {
    errors.push("Password must contain at least one lowercase letter.");
  }
  if (!/\d/.test(pwd)) {
    errors.push("Password must contain at least one digit.");
  }
  const specialPattern = /[!@#$%^&*()\-_=+\[\]{}|;:'",<.>\/?`~\\]/;
  if (!specialPattern.test(pwd)) {
    errors.push("Password must contain at least one special character.");
  }

  // 4) Disallow triple identical consecutive characters
  if (/(.)\1{2,}/.test(pwd)) {
    errors.push("Password must not contain three identical consecutive characters.");
  }

  // 5) Check common password list
  const lowerPwd = pwd.toLowerCase();
  if (COMMON_PASSWORDS.has(lowerPwd)) {
    errors.push("Password is too common. Please choose a stronger password.");
  }

  // 6) Disallow certain dictionary words
  const dictionaryPatterns = ['password', 'qwerty', 'abcdef', 'letmein', 'welcome', 'admin'];
  for (const pat of dictionaryPatterns) {
    if (lowerPwd.includes(pat)) {
      errors.push(`Password must not contain the word '${pat}'.`);
    }
  }

  // 7) Disallow if password contains username or local part of email
  if (username && lowerPwd.includes(username.toLowerCase())) {
    errors.push("Password must not contain your username.");
  }
  if (email) {
    const emailLocalPart = email.split('@')[0].toLowerCase();
    if (lowerPwd.includes(emailLocalPart)) {
      errors.push("Password must not contain the local part of your email address.");
    }
  }

  return errors;
}

// ============================
// ACHIEVEMENT ICON MAPPING
// ============================
const iconMapping = {
  "test_rookie": FaTrophy,
  "accuracy_king": FaMedal,
  "bronze_grinder": FaBook,
  "silver_scholar": FaStar,
  "gold_god": FaCrown,
  "platinum_pro": FaMagic,
  "walking_encyclopedia": FaBrain,
  "redemption_arc": FaBolt,
  "coin_collector_5000": FaBook,
  "coin_hoarder_10000": FaBook,
  "coin_tycoon_50000": FaBook,
  "perfectionist_1": FaCheckCircle,
  "double_trouble_2": FaCheckCircle,
  "error404_failure_not_found": FaCheckCircle,
  "level_up_5": FaTrophy,
  "mid_tier_grinder_25": FaMedal,
  "elite_scholar_50": FaStar,
  "ultimate_master_100": FaCrown,
  "answer_machine_1000": FaBook,
  "knowledge_beast_5000": FaBrain,
  "question_terminator": FaBrain,
  "test_finisher": FaCheckCircle
};

// ============================
// COLOR MAPPING FOR ACHIEVEMENTS
// ============================
const colorMapping = {
  "test_rookie": "#ff5555",
  "accuracy_king": "#ffa500",
  "bronze_grinder": "#cd7f32",
  "silver_scholar": "#c0c0c0",
  "gold_god": "#ffd700",
  "platinum_pro": "#e5e4e2",
  "walking_encyclopedia": "#00fa9a",
  "redemption_arc": "#ff4500",
  "coin_collector_5000": "#ff69b4",
  "coin_hoarder_10000": "#ff1493",
  "coin_tycoon_50000": "#ff0000",
  "perfectionist_1": "#adff2f",
  "double_trouble_2": "#7fff00",
  "error404_failure_not_found": "#00ffff",
  "level_up_5": "#f08080",
  "mid_tier_grinder_25": "#ff8c00",
  "elite_scholar_50": "#ffd700",
  "ultimate_master_100": "#ff4500",
  "answer_machine_1000": "#ff69b4",
  "knowledge_beast_5000": "#00fa9a",
  "question_terminator": "#ff1493",
  "test_finisher": "#adff2f"
};

// Main UserProfile Component
const UserProfile = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();

  // Get user data from Redux store
  const {
    userId,
    username,
    email,
    xp,
    level,
    coins,
    achievements = [],
    currentAvatar,
    purchasedItems,
    subscriptionActive
  } = useSelector((state) => state.user);

  // Get achievements and shop items data
  const allAchievements = useSelector((state) => state.achievements.all);
  const allShopItems = useSelector((state) => state.shop.items);

  // Tabs state management
  const [activeTab, setActiveTab] = useState('overview');

  // Toggles for showing/hiding different forms
  const [showChangeUsername, setShowChangeUsername] = useState(false);
  const [newUsername, setNewUsername] = useState('');

  const [showChangeEmail, setShowChangeEmail] = useState(false);
  const [newEmail, setNewEmail] = useState('');

  const [showChangePassword, setShowChangePassword] = useState(false);

  // Password form states
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [oldPassword, setOldPassword] = useState('');

  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [showRequirements, setShowRequirements] = useState(false);

  // Status message
  const [statusMessage, setStatusMessage] = useState('');
  const [statusType, setStatusType] = useState(''); // 'success', 'error'

  // Stats display toggles
  const [showMoreAchievements, setShowMoreAchievements] = useState(false);
  const [showMoreItems, setShowMoreItems] = useState(false);

  // Calculate the percentage of XP to next level (just a visual approximation)
  const calculateXpPercentage = () => {
    const baseXpPerLevel = 1000; // Assuming 1000 XP per level
    const currentLevelBaseXp = (level - 1) * baseXpPerLevel;
    const nextLevelBaseXp = level * baseXpPerLevel;
    const xpInCurrentLevel = xp - currentLevelBaseXp;
    const xpRequiredForNextLevel = nextLevelBaseXp - currentLevelBaseXp;
    return Math.min(100, (xpInCurrentLevel / xpRequiredForNextLevel) * 100);
  };

  // XP progress percentage
  const xpPercentage = calculateXpPercentage();

  // Get user avatar from shop items
  let profilePicUrl = '/avatars/default-avatar.png'; // Default avatar
  if (currentAvatar) {
    const foundAvatar = allShopItems.find(item => item._id === currentAvatar);
    if (foundAvatar && foundAvatar.imageUrl) {
      profilePicUrl = foundAvatar.imageUrl;
    }
  }

  // Handle logout
  const handleLogout = () => {
    dispatch(logout());
    localStorage.removeItem('userId');
    navigate('/login');
  };

  // Refresh user data
  const refetchUser = () => {
    if (userId) {
      dispatch(fetchUserData(userId));
    }
  };

  // Clear status message after 5 seconds
  useEffect(() => {
    if (statusMessage) {
      const timer = setTimeout(() => {
        setStatusMessage('');
        setStatusType('');
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [statusMessage]);

  // =======================
  // CHANGE USERNAME
  // =======================
  const handleChangeUsername = async () => {
    setStatusMessage('');
    setStatusType('');
    
    const errors = frontValidateUsername(newUsername);
    if (errors.length > 0) {
      setStatusMessage(errors.join(' '));
      setStatusType('error');
      return;
    }

    try {
      const res = await fetch('/api/test/user/change-username', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, newUsername })
      });
      const data = await res.json();

      if (!res.ok) {
        let errorMsg = data.error || 'Failed to change username';
        if (data.details && data.details.length > 0) {
          errorMsg += ': ' + data.details.join(', ');
        }
        throw new Error(errorMsg);
      }
      setStatusMessage('Username updated successfully!');
      setStatusType('success');
      setShowChangeUsername(false);
      setNewUsername('');
      refetchUser();
    } catch (err) {
      setStatusMessage('Error: ' + err.message);
      setStatusType('error');
    }
  };

  // =======================
  // CHANGE EMAIL
  // =======================
  const handleChangeEmail = async () => {
    setStatusMessage('');
    setStatusType('');
    
    const errors = frontValidateEmail(newEmail);
    if (errors.length > 0) {
      setStatusMessage(errors.join(' '));
      setStatusType('error');
      return;
    }

    try {
      const res = await fetch('/api/test/user/change-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, newEmail })
      });
      const data = await res.json();

      if (!res.ok) {
        let errorMsg = data.error || 'Failed to change email';
        if (data.details && data.details.length > 0) {
          errorMsg += ': ' + data.details.join(', ');
        }
        throw new Error(errorMsg);
      }
      setStatusMessage('Email updated successfully!');
      setStatusType('success');
      setShowChangeEmail(false);
      setNewEmail('');
      refetchUser();
    } catch (err) {
      setStatusMessage('Error: ' + err.message);
      setStatusType('error');
    }
  };

  // =======================
  // CHANGE PASSWORD
  // =======================
  const handleChangePassword = async () => {
    setStatusMessage('');
    setStatusType('');

    if (!oldPassword || !newPassword || !confirmPassword) {
      setStatusMessage('All password fields are required');
      setStatusType('error');
      return;
    }
    if (newPassword !== confirmPassword) {
      setStatusMessage('New passwords do not match');
      setStatusType('error');
      return;
    }

    const errors = frontValidatePassword(newPassword, username, email);
    if (errors.length > 0) {
      setStatusMessage(errors.join(' '));
      setStatusType('error');
      return;
    }

    try {
      const res = await fetch('/api/test/user/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          oldPassword,
          newPassword,
          confirmPassword
        })
      });
      const data = await res.json();

      if (!res.ok) {
        let errorMsg = data.error || 'Failed to change password';
        if (data.details && data.details.length > 0) {
          errorMsg += ': ' + data.details.join(', ');
        }
        throw new Error(errorMsg);
      }

      setStatusMessage('Password changed successfully!');
      setStatusType('success');
      setShowChangePassword(false);
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setShowRequirements(false);
    } catch (err) {
      setStatusMessage('Error: ' + err.message);
      setStatusType('error');
    }
  };

  // CANCEL SUBSCRIPTION (placeholder)
  const handleCancelSubscription = async () => {
    try {
      const res = await fetch('/api/test/subscription/cancel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to cancel subscription');
      }
      setStatusMessage('Subscription cancelled successfully');
      setStatusType('success');
      refetchUser();
    } catch (err) {
      setStatusMessage('Error: ' + err.message);
      setStatusType('error');
    }
  };

  // Map user achievements IDs to full achievement data
  const userAchievementsData = achievements
    .map(achId => allAchievements.find(a => a.achievementId === achId))
    .filter(Boolean);

  // Map user purchased item IDs to full shop item data
  const userPurchasedItems = purchasedItems
    .map(itemId => allShopItems.find(item => item._id === itemId))
    .filter(Boolean);

  return (
    <div className="user-profile-container">
      {/* Notification */}
      {statusMessage && (
        <div className={`profile-notification ${statusType === 'success' ? 'profile-notification-success' : 'profile-notification-error'}`}>
          <span>{statusMessage}</span>
          <button onClick={() => setStatusMessage('')} className="profile-notification-close">
            <FaTimes />
          </button>
        </div>
      )}

      {/* Main wrapper */}
      <div className="profile-wrapper">
        {/* Header section with profile info */}
        <div className="profile-header-section">
          <div className="profile-header-content">
            <div className="profile-avatar-wrapper">
              <img src={profilePicUrl} alt={`${username}'s avatar`} className="profile-avatar" />
            </div>
            
            <div className="profile-header-info">
              <h1 className="profile-username">{username}</h1>
              
              <div className="profile-level-container">
                <div className="profile-level-badge">
                  <span className="profile-level-number">{level}</span>
                  <FaLevelUpAlt className="profile-level-icon" />
                </div>
                
                <div className="profile-xp-container">
                  <div className="profile-xp-bar">
                    <div 
                      className="profile-xp-progress" 
                      style={{ width: `${xpPercentage}%` }}
                    ></div>
                  </div>
                  <span className="profile-xp-text">{xp} XP</span>
                </div>
              </div>
              
              <div className="profile-stats">
                <div className="profile-stat-item">
                  <FaCoins className="profile-stat-icon" />
                  <span className="profile-stat-value">{coins}</span>
                </div>
                <div className="profile-stat-item">
                  <FaTrophy className="profile-stat-icon" />
                  <span className="profile-stat-value">{achievements.length}</span>
                </div>
                <div className="profile-stat-item">
                  <FaStore className="profile-stat-icon" />
                  <span className="profile-stat-value">{purchasedItems.length}</span>
                </div>
              </div>
            </div>
            
            <div className="profile-actions">
              <button className="profile-logout-btn" onClick={handleLogout}>
                <FaSignOutAlt />
                <span>Logout</span>
              </button>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="profile-tabs">
          <button 
            className={`profile-tab ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </button>
          <button 
            className={`profile-tab ${activeTab === 'achievements' ? 'active' : ''}`}
            onClick={() => setActiveTab('achievements')}
          >
            Achievements
          </button>
          <button 
            className={`profile-tab ${activeTab === 'items' ? 'active' : ''}`}
            onClick={() => setActiveTab('items')}
          >
            Items
          </button>
          <button 
            className={`profile-tab ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveTab('settings')}
          >
            Settings
          </button>
        </div>

        {/* Content section based on active tab */}
        <div className="profile-content">
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="profile-overview-tab">
              <div className="profile-overview-cards">
                <div className="profile-card">
                  <h2 className="profile-card-title">
                    <FaUserAlt className="profile-card-icon" />
                    User Info
                  </h2>
                  <div className="profile-card-content">
                    <div className="profile-detail-item">
                      <span className="profile-detail-label">ID:</span>
                      <span className="profile-detail-value">{userId}</span>
                    </div>
                    <div className="profile-detail-item">
                      <span className="profile-detail-label">Username:</span>
                      <span className="profile-detail-value">{username}</span>
                    </div>
                    <div className="profile-detail-item">
                      <span className="profile-detail-label">Email:</span>
                      <span className="profile-detail-value">{email}</span>
                    </div>
                    <div className="profile-detail-item">
                      <span className="profile-detail-label">Subscription:</span>
                      <span className="profile-detail-value">
                        {subscriptionActive ? (
                          <span className="profile-subscription-active">Active</span>
                        ) : (
                          <span className="profile-subscription-inactive">Inactive</span>
                        )}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="profile-card">
                  <h2 className="profile-card-title">
                    <FaTrophy className="profile-card-icon" />
                    Latest Achievements
                  </h2>
                  <div className="profile-card-content">
                    {userAchievementsData.length > 0 ? (
                      <div className="profile-mini-achievements">
                        {userAchievementsData.slice(0, 3).map((ach) => {
                          const AchIcon = iconMapping[ach.achievementId] || FaTrophy;
                          const achColor = colorMapping[ach.achievementId] || "#ffffff";
                          
                          return (
                            <div key={ach.achievementId} className="profile-mini-achievement">
                              <div className="profile-mini-achievement-icon" style={{ color: achColor }}>
                                <AchIcon />
                              </div>
                              <div className="profile-mini-achievement-info">
                                <span className="profile-mini-achievement-title">{ach.title}</span>
                              </div>
                            </div>
                          );
                        })}
                        {userAchievementsData.length > 3 && (
                          <button 
                            className="profile-view-more-btn"
                            onClick={() => setActiveTab('achievements')}
                          >
                            View All ({userAchievementsData.length})
                          </button>
                        )}
                      </div>
                    ) : (
                      <p className="profile-empty-message">No achievements yet. Start completing tests!</p>
                    )}
                  </div>
                </div>

                <div className="profile-card">
                  <h2 className="profile-card-title">
                    <FaStore className="profile-card-icon" />
                    Latest Items
                  </h2>
                  <div className="profile-card-content">
                    {userPurchasedItems && userPurchasedItems.length > 0 ? (
                      <div className="profile-mini-items">
                        {userPurchasedItems.slice(0, 3).map((item) => (
                          <div key={item._id} className="profile-mini-item">
                            <img
                              src={item.imageUrl}
                              alt={item.title}
                              className="profile-mini-item-image"
                            />
                            <span className="profile-mini-item-title">{item.title}</span>
                          </div>
                        ))}
                        {userPurchasedItems.length > 3 && (
                          <button 
                            className="profile-view-more-btn"
                            onClick={() => setActiveTab('items')}
                          >
                            View All ({userPurchasedItems.length})
                          </button>
                        )}
                      </div>
                    ) : (
                      <p className="profile-empty-message">No items purchased yet. Visit the shop!</p>
                    )}
                  </div>
                </div>
              </div>

              <div className="profile-overview-stats">
                <div className="profile-stats-card">
                  <h2 className="profile-card-title">Player Stats</h2>
                  <div className="profile-stats-grid">
                    <div className="profile-stat-card">
                      <div className="profile-stat-header">
                        <FaLevelUpAlt className="profile-stat-header-icon" />
                        <span>Level</span>
                      </div>
                      <div className="profile-stat-number">{level}</div>
                    </div>

                    <div className="profile-stat-card">
                      <div className="profile-stat-header">
                        <FaStar className="profile-stat-header-icon" />
                        <span>XP</span>
                      </div>
                      <div className="profile-stat-number">{xp}</div>
                    </div>

                    <div className="profile-stat-card">
                      <div className="profile-stat-header">
                        <FaCoins className="profile-stat-header-icon" />
                        <span>Coins</span>
                      </div>
                      <div className="profile-stat-number">{coins}</div>
                    </div>

                    <div className="profile-stat-card">
                      <div className="profile-stat-header">
                        <FaTrophy className="profile-stat-header-icon" />
                        <span>Achievements</span>
                      </div>
                      <div className="profile-stat-number">{achievements.length}</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Achievements Tab */}
          {activeTab === 'achievements' && (
            <div className="profile-achievements-tab">
              <h2 className="profile-section-title">Your Achievements</h2>
              
              {userAchievementsData.length > 0 ? (
                <div className="profile-achievements-grid">
                  {userAchievementsData.map((ach) => {
                    const AchIcon = iconMapping[ach.achievementId] || FaTrophy;
                    const achColor = colorMapping[ach.achievementId] || "#ffffff";
                    
                    return (
                      <div key={ach.achievementId} className="profile-achievement-card">
                        <div className="profile-achievement-icon" style={{ color: achColor }}>
                          {ach.title.includes('🏆') ? (
                            <span className="profile-achievement-emoji">{ach.title.split(' ')[0]}</span>
                          ) : (
                            <AchIcon />
                          )}
                        </div>
                        <div className="profile-achievement-content">
                          <h3 className="profile-achievement-title">
                            {ach.title.includes('🏆') ? ach.title.split(' ').slice(1).join(' ') : ach.title}
                          </h3>
                          <p className="profile-achievement-description">{ach.description}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="profile-empty-state">
                  <FaTrophy className="profile-empty-icon" />
                  <p>You haven't unlocked any achievements yet.</p>
                  <p>Complete tests and challenges to earn achievements!</p>
                </div>
              )}
            </div>
          )}

          {/* Items Tab */}
          {activeTab === 'items' && (
            <div className="profile-items-tab">
              <h2 className="profile-section-title">Your Items</h2>
              
              {userPurchasedItems && userPurchasedItems.length > 0 ? (
                <div className="profile-items-grid">
                  {userPurchasedItems.map((item) => (
                    <div key={item._id} className="profile-item-card">
                      <div className="profile-item-image-container">
                        <img
                          src={item.imageUrl}
                          alt={item.title}
                          className="profile-item-image"
                        />
                      </div>
                      <div className="profile-item-content">
                        <h3 className="profile-item-title">{item.title}</h3>
                        {item.description && (
                          <p className="profile-item-description">{item.description}</p>
                        )}
                        <div className="profile-item-status">
                          {item._id === currentAvatar ? (
                            <span className="profile-item-equipped">Equipped</span>
                          ) : (
                            <span className="profile-item-owned">Owned</span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="profile-empty-state">
                  <FaStore className="profile-empty-icon" />
                  <p>You haven't purchased any items yet.</p>
                  <p>Visit the shop to buy avatars and other items!</p>
                </div>
              )}
            </div>
          )}

          {/* Settings Tab */}
          {activeTab === 'settings' && (
            <div className="profile-settings-tab">
              <h2 className="profile-section-title">Account Settings</h2>
              
              <div className="profile-settings-grid">
                {/* Change Username */}
                <div className="profile-setting-card">
                  <div className="profile-setting-header">
                    <FaUserAlt className="profile-setting-icon" />
                    <h3 className="profile-setting-title">Username</h3>
                  </div>
                  
                  <div className="profile-setting-content">
                    <p className="profile-setting-current">Current: <span>{username}</span></p>
                    
                    {!showChangeUsername ? (
                      <button 
                        className="profile-setting-action-btn"
                        onClick={() => setShowChangeUsername(true)}
                      >
                        <FaEdit />
                        <span>Change Username</span>
                      </button>
                    ) : (
                      <div className="profile-setting-form">
                        <div className="profile-setting-input-group">
                          <input
                            type="text"
                            className="profile-setting-input"
                            placeholder="New username"
                            value={newUsername}
                            onChange={(e) => setNewUsername(e.target.value)}
                          />
                        </div>
                        <div className="profile-setting-buttons">
                          <button 
                            className="profile-setting-submit-btn"
                            onClick={handleChangeUsername}
                          >
                            <FaCheck />
                            <span>Save</span>
                          </button>
                          <button 
                            className="profile-setting-cancel-btn"
                            onClick={() => {
                              setShowChangeUsername(false);
                              setNewUsername('');
                            }}
                          >
                            <FaTimes />
                            <span>Cancel</span>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Change Email */}
                <div className="profile-setting-card">
                  <div className="profile-setting-header">
                    <FaEnvelope className="profile-setting-icon" />
                    <h3 className="profile-setting-title">Email</h3>
                  </div>
                  
                  <div className="profile-setting-content">
                    <p className="profile-setting-current">Current: <span>{email}</span></p>
                    
                    {!showChangeEmail ? (
                      <button 
                        className="profile-setting-action-btn"
                        onClick={() => setShowChangeEmail(true)}
                      >
                        <FaEdit />
                        <span>Change Email</span>
                      </button>
                    ) : (
                      <div className="profile-setting-form">
                        <div className="profile-setting-input-group">
                          <input
                            type="email"
                            className="profile-setting-input"
                            placeholder="New email address"
                            value={newEmail}
                            onChange={(e) => setNewEmail(e.target.value)}
                          />
                        </div>
                        <div className="profile-setting-buttons">
                          <button 
                            className="profile-setting-submit-btn"
                            onClick={handleChangeEmail}
                          >
                            <FaCheck />
                            <span>Save</span>
                          </button>
                          <button 
                            className="profile-setting-cancel-btn"
                            onClick={() => {
                              setShowChangeEmail(false);
                              setNewEmail('');
                            }}
                          >
                            <FaTimes />
                            <span>Cancel</span>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Change Password */}
                <div className="profile-setting-card">
                  <div className="profile-setting-header">
                    <FaKey className="profile-setting-icon" />
                    <h3 className="profile-setting-title">Password</h3>
                  </div>
                  
                  <div className="profile-setting-content">
                    <p className="profile-setting-current">Status: <span>*********</span></p>
                    
                    {!showChangePassword ? (
                      <button 
                        className="profile-setting-action-btn"
                        onClick={() => setShowChangePassword(true)}
                      >
                        <FaEdit />
                        <span>Change Password</span>
                      </button>
                    ) : (
                      <div className="profile-setting-form">
                        {/* Old Password */}
                        <div className="profile-setting-input-group">
                          <div className="profile-setting-password-field">
                            <input
                              type={showOldPassword ? 'text' : 'password'}
                              className="profile-setting-input"
                              placeholder="Current password"
                              value={oldPassword}
                              onChange={(e) => setOldPassword(e.target.value)}
                            />
                            <button
                              type="button"
                              className="profile-setting-password-toggle"
                              onClick={() => setShowOldPassword(!showOldPassword)}
                            >
                              {showOldPassword ? <FaEyeSlash /> : <FaEye />}
                            </button>
                          </div>
                        </div>
                        
                        {/* New Password */}
                        <div className="profile-setting-input-group">
                          <div className="profile-setting-password-field">
                            <input
                              type={showNewPassword ? 'text' : 'password'}
                              className="profile-setting-input"
                              placeholder="New password"
                              value={newPassword}
                              onChange={(e) => setNewPassword(e.target.value)}
                              onFocus={() => setShowRequirements(true)}
                              onBlur={() => {
                                if (!newPassword) {
                                  setShowRequirements(false);
                                }
                              }}
                            />
                            <button
                              type="button"
                              className="profile-setting-password-toggle"
                              onClick={() => setShowNewPassword(!showNewPassword)}
                            >
                              {showNewPassword ? <FaEyeSlash /> : <FaEye />}
                            </button>
                          </div>
                        </div>
                        
                        {/* Password Requirements */}
                        {showRequirements && (
                          <div className="profile-password-requirements">
                            <PasswordRequirements password={newPassword} />
                          </div>
                        )}
                        
                        {/* Confirm Password */}
                        <div className="profile-setting-input-group">
                          <div className="profile-setting-password-field">
                            <input
                              type={showConfirmPassword ? 'text' : 'password'}
                              className="profile-setting-input"
                              placeholder="Confirm new password"
                              value={confirmPassword}
                              onChange={(e) => setConfirmPassword(e.target.value)}
                            />
                            <button
                              type="button"
                              className="profile-setting-password-toggle"
                              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                            >
                              {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
                            </button>
                          </div>
                        </div>
                        
                        <div className="profile-setting-buttons">
                          <button 
                            className="profile-setting-submit-btn"
                            onClick={handleChangePassword}
                          >
                            <FaCheck />
                            <span>Save</span>
                          </button>
                          <button 
                            className="profile-setting-cancel-btn"
                            onClick={() => {
                              setShowChangePassword(false);
                              setOldPassword('');
                              setNewPassword('');
                              setConfirmPassword('');
                              setShowRequirements(false);
                            }}
                          >
                            <FaTimes />
                            <span>Cancel</span>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Subscription Management */}
                <div className="profile-setting-card">
                  <div className="profile-setting-header">
                    <FaUserCircle className="profile-setting-icon" />
                    <h3 className="profile-setting-title">Subscription</h3>
                  </div>
                  
                  <div className="profile-setting-content">
                    <p className="profile-setting-current">
                      Status: 
                      <span className={subscriptionActive ? "subscription-active" : "subscription-inactive"}>
                        {subscriptionActive ? "Active" : "Inactive"}
                      </span>
                    </p>
                    
                    {subscriptionActive && (
                      <button 
                        className="profile-setting-action-btn profile-setting-danger-btn"
                        onClick={handleCancelSubscription}
                      >
                        <FaTimes />
                        <span>Cancel Subscription</span>
                      </button>
                    )}
                    
                    {!subscriptionActive && (
                      <button 
                        className="profile-setting-action-btn"
                        onClick={() => navigate('/subscription')}
                      >
                        <FaCheck />
                        <span>Subscribe Now</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UserProfile;
/* UserProfile.css - Gamified User Profile */

:root {
  --profile-bg-dark: #0c0e14;
  --profile-bg-card: #171a23;
  --profile-accent: #b30000;
  --profile-accent-glow: #990000;
  --profile-accent-secondary: #990000;
  --profile-border: #000;
  --profile-text: #e2e2e2;
  --profile-text-secondary: #9da8b9;
  --profile-success: #2ebb77;
  --profile-error: #ff4e4e;
  --profile-warning: #ffc107;
  --profile-gradient-primary: #990000;
  --profile-gradient-secondary: linear-gradient(135deg, #ff4c8b, #ff7950);
  --profile-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  --profile-glow: 0 0 15px #990000;
}

/* Main container for the entire profile page */
.user-profile-container {
  font-family: 'Orbitron', 'Roboto', sans-serif;
  color: var(--profile-text);
  margin: 0;
  padding: 0;
  min-height: 100vh;
  width: 100%;
  background-color: var(--profile-bg-dark);
  background-image: 
    radial-gradient(circle at 10% 20%, rgba(26, 20, 64, 0.4) 0%, transparent 45%),
    radial-gradient(circle at 80% 70%, rgba(42, 26, 89, 0.3) 0%, transparent 40%),
    repeating-linear-gradient(rgba(0, 0, 0, 0.05) 0px, rgba(0, 0, 0, 0.05) 1px, transparent 1px, transparent 10px);
  position: relative;
}

/* This wrapper keeps all profile content centered */
.profile-wrapper {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

/* =================== */
/* NOTIFICATION STYLES */
/* =================== */

.profile-notification {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 9999;
  padding: 15px 20px;
  border-radius: 8px;
  background: var(--profile-bg-card);
  border-left: 4px solid;
  box-shadow: var(--profile-shadow);
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-width: 280px;
  max-width: 450px;
  animation: notification-slide-in 0.3s ease forwards;
}

@keyframes notification-slide-in {
  from {
    transform: translateX(100%);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}

.profile-notification-success {
  border-left-color: var(--profile-success);
}

.profile-notification-error {
  border-left-color: var(--profile-error);
}

.profile-notification span {
  font-size: 14px;
  flex-grow: 1;
}

.profile-notification-close {
  background: none;
  border: none;
  color: var(--profile-text-secondary);
  cursor: pointer;
  padding: 5px;
  margin-left: 10px;
  font-size: 16px;
  transition: color 0.2s;
}

.profile-notification-close:hover {
  color: var(--profile-text);
}

/* =================== */
/* HEADER SECTION      */
/* =================== */

.profile-header-section {
  background: var(--profile-bg-card);
  border-radius: 15px;
  margin-bottom: 20px;
  padding: 25px;
  box-shadow: var(--profile-shadow);
  border: 1px solid var(--profile-border);
  position: relative;
  overflow: hidden;
}

.profile-header-section::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 4px;
  background: var(--profile-gradient-primary);
}

.profile-header-content {
  display: flex;
  flex-wrap: wrap;
  gap: 30px;
  align-items: center;
}

.profile-avatar-wrapper {
  position: relative;
  flex-shrink: 0;
}

.profile-avatar {
  width: 120px;
  height: 120px;
  border-radius: 50%;
  object-fit: cover;
  border: 3px solid var(--profile-accent);
  box-shadow: var(--profile-glow);
}

.profile-header-info {
  flex: 1;
  min-width: 250px;
}

.profile-username {
  font-size: 28px;
  margin: 0 0 10px 0;
  background: var(--profile-gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-shadow: 0 0 2px rgba(0, 0, 0, 0.5);
  font-weight: 700;
}

.profile-level-container {
  display: flex;
  align-items: center;
  gap: 15px;
  margin-bottom: 15px;
}

.profile-level-badge {
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--profile-gradient-primary);
  border-radius: 50%;
  width: 40px;
  height: 40px;
  flex-shrink: 0;
  box-shadow: var(--profile-glow);
  position: relative;
}

.profile-level-number {
  font-size: 18px;
  font-weight: 700;
  color: white;
}

.profile-level-icon {
  position: absolute;
  top: -8px;
  right: -8px;
  background: var(--profile-bg-card);
  border-radius: 50%;
  padding: 3px;
  font-size: 12px;
  color: var(--profile-accent-glow);
}

.profile-xp-container {
  flex-grow: 1;
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.profile-xp-bar {
  width: 100%;
  height: 10px;
  background: rgba(255, 255, 255, 0.1);
  border-radius: 5px;
  overflow: hidden;
}

.profile-xp-progress {
  height: 100%;
  background: var(--profile-gradient-primary);
  border-radius: 5px;
  transition: width 0.5s ease;
}

.profile-xp-text {
  font-size: 12px;
  color: var(--profile-text-secondary);
  text-align: right;
}

.profile-stats {
  display: flex;
  gap: 20px;
}

.profile-stat-item {
  display: flex;
  align-items: center;
  gap: 5px;
}

.profile-stat-icon {
  color: var(--profile-accent);
  font-size: 16px;
}

.profile-stat-value {
  font-size: 16px;
  font-weight: 600;
}

.profile-actions {
  margin-left: auto;
  display: flex;
  flex-direction: column;
  gap: 10px;
  align-items: flex-end;
}

.profile-logout-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid var(--profile-border);
  color: var(--profile-text);
  border-radius: 20px;
  padding: 8px 16px;
  cursor: pointer;
  font-family: inherit;
  font-size: 14px;
  transition: all 0.2s;
}

.profile-logout-btn:hover {
  background: rgba(255, 255, 255, 0.1);
  color: var(--profile-accent-secondary);
}

/* =================== */
/* NAVIGATION TABS     */
/* =================== */

.profile-tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 20px;
  overflow-x: auto;
  padding-bottom: 5px;
  scrollbar-width: thin;
  scrollbar-color: var(--profile-accent) var(--profile-bg-dark);
}

.profile-tabs::-webkit-scrollbar {
  height: 5px;
}

.profile-tabs::-webkit-scrollbar-track {
  background: var(--profile-bg-dark);
}

.profile-tabs::-webkit-scrollbar-thumb {
  background-color: var(--profile-accent);
  border-radius: 10px;
}

.profile-tab {
  padding: 12px 24px;
  background: var(--profile-bg-card);
  border: 1px solid var(--profile-border);
  border-radius: 8px;
  color: var(--profile-text-secondary);
  cursor: pointer;
  font-family: inherit;
  font-size: 14px;
  font-weight: 600;
  transition: all 0.2s;
  min-width: max-content;
}

.profile-tab:hover {
  background: rgba(255, 255, 255, 0.05);
  color: var(--profile-text);
}

.profile-tab.active {
  background: var(--profile-gradient-primary);
  color: white;
  box-shadow: var(--profile-glow);
  border-color: transparent;
}

/* =================== */
/* CONTENT SECTION     */
/* =================== */

.profile-content {
  min-height: 400px;
}

.profile-section-title {
  font-size: 20px;
  margin: 0 0 20px 0;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--profile-border);
  color: var(--profile-text);
}

/* =================== */
/* OVERVIEW TAB        */
/* =================== */

.profile-overview-tab {
  display: grid;
  grid-template-columns: 1fr;
  gap: 20px;
}

.profile-overview-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
}

.profile-card {
  background: var(--profile-bg-card);
  border-radius: 12px;
  padding: 20px;
  box-shadow: var(--profile-shadow);
  border: 1px solid var(--profile-border);
  height: 100%;
  display: flex;
  flex-direction: column;
}

.profile-card-title {
  font-size: 18px;
  margin: 0 0 15px 0;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--profile-border);
  color: var(--profile-text);
  display: flex;
  align-items: center;
  gap: 10px;
}

.profile-card-icon {
  color: var(--profile-accent);
}

.profile-card-content {
  flex-grow: 1;
}

.profile-detail-item {
  margin-bottom: 10px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.profile-detail-label {
  color: var(--profile-text-secondary);
  font-size: 14px;
}

.profile-detail-value {
  font-weight: 500;
  font-size: 14px;
}

.profile-subscription-active {
  color: var(--profile-success);
  font-weight: 600;
}

.profile-subscription-inactive {
  color: var(--profile-text-secondary);
}

.profile-mini-achievements, 
.profile-mini-items {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.profile-mini-achievement,
.profile-mini-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px;
  background: rgba(255, 255, 255, 0.03);
  border-radius: 8px;
  transition: transform 0.2s, background 0.2s;
}

.profile-mini-achievement:hover,
.profile-mini-item:hover {
  background: rgba(255, 255, 255, 0.05);
  transform: translateX(5px);
}

.profile-mini-achievement-icon {
  font-size: 20px;
  flex-shrink: 0;
}

.profile-mini-achievement-info {
  overflow: hidden;
}

.profile-mini-achievement-title {
  font-size: 14px;
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.profile-mini-item-image {
  width: 32px;
  height: 32px;
  border-radius: 4px;
  object-fit: cover;
  flex-shrink: 0;
}

.profile-mini-item-title {
  font-size: 14px;
  font-weight: 500;
}

.profile-view-more-btn {
  align-self: flex-end;
  background: none;
  border: none;
  color: var(--profile-accent);
  cursor: pointer;
  font-family: inherit;
  font-size: 14px;
  padding: 5px;
  transition: color 0.2s;
}

.profile-view-more-btn:hover {
  color: var(--profile-accent-glow);
  text-decoration: underline;
}

.profile-empty-message {
  color: var(--profile-text-secondary);
  font-size: 14px;
  text-align: center;
  padding: 20px;
}

.profile-overview-stats {
  margin-top: 20px;
}

.profile-stats-card {
  background: var(--profile-bg-card);
  border-radius: 12px;
  padding: 20px;
  box-shadow: var(--profile-shadow);
  border: 1px solid var(--profile-border);
}

.profile-stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 15px;
  margin-top: 10px;
}

.profile-stat-card {
  background: rgba(255, 255, 255, 0.03);
  border-radius: 10px;
  padding: 15px;
  text-align: center;
  transition: transform 0.2s;
}

.profile-stat-card:hover {
  transform: translateY(-5px);
  background: rgba(255, 255, 255, 0.05);
}

.profile-stat-header {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 5px;
  margin-bottom: 10px;
  color: var(--profile-text-secondary);
  font-size: 14px;
}

.profile-stat-header-icon {
  color: var(--profile-accent);
}

.profile-stat-number {
  font-size: 26px;
  font-weight: 700;
  background: var(--profile-gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

/* =================== */
/* ACHIEVEMENTS TAB    */
/* =================== */

.profile-achievements-tab {
  padding: 10px;
}

.profile-achievements-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
}

.profile-achievement-card {
  background: var(--profile-bg-card);
  border-radius: 12px;
  padding: 20px;
  display: flex;
  align-items: flex-start;
  gap: 15px;
  border: 1px solid var(--profile-border);
  transition: transform 0.2s, box-shadow 0.2s;
}

.profile-achievement-card:hover {
  transform: translateY(-5px);
  box-shadow: var(--profile-shadow), var(--profile-glow);
}

.profile-achievement-icon {
  font-size: 32px;
  flex-shrink: 0;
  width: 50px;
  height: 50px;
  background: rgba(255, 255, 255, 0.05);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
}

.profile-achievement-emoji {
  font-size: 28px;
}

.profile-achievement-content {
  flex-grow: 1;
}

.profile-achievement-title {
  font-size: 16px;
  margin: 0 0 8px 0;
  font-weight: 600;
  color: var(--profile-text);
}

.profile-achievement-description {
  font-size: 14px;
  margin: 0;
  color: var(--profile-text-secondary);
  line-height: 1.4;
}

/* Empty state for no achievements */
.profile-empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  text-align: center;
  gap: 15px;
  color: var(--profile-text-secondary);
}

.profile-empty-icon {
  font-size: 48px;
  opacity: 0.3;
}

.profile-empty-state p {
  margin: 0;
  font-size: 16px;
}

.profile-empty-state p:last-child {
  font-size: 14px;
  opacity: 0.7;
}

/* =================== */
/* ITEMS TAB           */
/* =================== */

.profile-items-tab {
  padding: 10px;
}

.profile-items-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 20px;
}

.profile-item-card {
  background: var(--profile-bg-card);
  border-radius: 12px;
  padding: 20px;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--profile-border);
  transition: transform 0.2s, box-shadow 0.2s;
  gap: 15px;
}

.profile-item-card:hover {
  transform: translateY(-5px);
  box-shadow: var(--profile-shadow), var(--profile-glow);
}

.profile-item-image-container {
  display: flex;
  justify-content: center;
  align-items: center;
  width: 100%;
  height: 100px;
}

.profile-item-image {
  max-width: 100%;
  max-height: 100%;
  object-fit: contain;
  border-radius: 8px;
}

.profile-item-content {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.profile-item-title {
  font-size: 16px;
  margin: 0;
  font-weight: 600;
  color: var(--profile-text);
}

.profile-item-description {
  font-size: 14px;
  margin: 0;
  color: var(--profile-text-secondary);
}

.profile-item-status {
  margin-top: auto;
}

.profile-item-equipped {
  display: inline-block;
  background: var(--profile-gradient-primary);
  color: white;
  font-size: 12px;
  padding: 4px 8px;
  border-radius: 4px;
  font-weight: 600;
}

.profile-item-owned {
  display: inline-block;
  background: rgba(255, 255, 255, 0.05);
  color: var(--profile-text-secondary);
  font-size: 12px;
  padding: 4px 8px;
  border-radius: 4px;
  font-weight: 600;
}

/* =================== */
/* SETTINGS TAB        */
/* =================== */

.profile-settings-tab {
  padding: 10px;
}

.profile-settings-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
}

.profile-setting-card {
  background: var(--profile-bg-card);
  border-radius: 12px;
  padding: 20px;
  box-shadow: var(--profile-shadow);
  border: 1px solid var(--profile-border);
}

.profile-setting-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 15px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--profile-border);
}

.profile-setting-icon {
  color: var(--profile-accent);
  font-size: 18px;
}

.profile-setting-title {
  font-size: 18px;
  margin: 0;
  color: var(--profile-text);
}

.profile-setting-content {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.profile-setting-current {
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: var(--profile-text-secondary);
  font-size: 14px;
  margin: 0;
}

.profile-setting-current span {
  color: var(--profile-text);
  font-weight: 500;
}

.profile-setting-action-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid var(--profile-border);
  color: var(--profile-text);
  border-radius: 8px;
  padding: 10px;
  width: 100%;
  cursor: pointer;
  font-family: inherit;
  font-size: 14px;
  transition: all 0.2s;
}

.profile-setting-action-btn:hover {
  background: var(--profile-accent);
  color: white;
}

.profile-setting-danger-btn {
  color: var(--profile-error);
  border-color: rgba(255, 78, 78, 0.3);
}

.profile-setting-danger-btn:hover {
  background: var(--profile-error);
  color: white;
}

.profile-setting-form {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.profile-setting-input-group {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.profile-setting-input {
  width: 100%;
  background: rgba(0, 0, 0, 0.2);
  border: 1px solid var(--profile-border);
  border-radius: 8px;
  padding: 10px 15px;
  color: var(--profile-text);
  font-family: inherit;
  font-size: 14px;
  transition: border-color 0.2s;
}

.profile-setting-input:focus {
  outline: none;
  border-color: var(--profile-accent);
}

.profile-setting-password-field {
  position: relative;
  width: 100%;
}

.profile-setting-password-toggle {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--profile-text-secondary);
  cursor: pointer;
  padding: 5px;
  font-size: 14px;
  transition: color 0.2s;
}

.profile-setting-password-toggle:hover {
  color: var(--profile-text);
}

.profile-password-requirements {
  background: rgba(0, 0, 0, 0.2);
  border-radius: 8px;
  padding: 10px;
  font-size: 12px;
}

.profile-setting-buttons {
  display: flex;
  gap: 10px;
  margin-top: 10px;
}

.profile-setting-submit-btn,
.profile-setting-cancel-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 5px;
  padding: 10px 15px;
  border-radius: 8px;
  font-family: inherit;
  font-size: 14px;
  cursor: pointer;
  flex: 1;
  transition: all 0.2s;
}

.profile-setting-submit-btn {
  background: var(--profile-accent);
  color: white;
  border: none;
}

.profile-setting-submit-btn:hover {
  background: var(--profile-accent-glow);
}

.profile-setting-cancel-btn {
  background: transparent;
  color: var(--profile-text-secondary);
  border: 1px solid var(--profile-border);
}

.profile-setting-cancel-btn:hover {
  background: rgba(255, 255, 255, 0.05);
  color: var(--profile-text);
}

/* =================== */
/* SUBSCRIPTION STATUS */
/* =================== */

.subscription-active {
  color: var(--profile-success);
  font-weight: 600;
}

.subscription-inactive {
  color: var(--profile-error);
  font-weight: 600;
}

/* =================== */
/* RESPONSIVE STYLES   */
/* =================== */

/* Tablet styles */
@media (max-width: 992px) {
  .profile-wrapper {
    padding: 15px;
  }
  
  .profile-header-content {
    gap: 20px;
  }
  
  .profile-avatar {
    width: 100px;
    height: 100px;
  }
  
  .profile-username {
    font-size: 24px;
  }
  
  .profile-overview-cards {
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  }
  
  .profile-achievements-grid,
  .profile-items-grid,
  .profile-settings-grid {
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  }
}

/* Mobile styles */
@media (max-width: 768px) {
  .profile-wrapper {
    padding: 10px;
  }
  
  .profile-header-section {
    padding: 15px;
  }
  
  .profile-header-content {
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: 15px;
  }
  
  .profile-header-info {
    width: 100%;
  }
  
  .profile-stats {
    justify-content: center;
  }
  
  .profile-level-container {
    flex-direction: column;
    gap: 10px;
  }
  
  .profile-actions {
    margin-left: 0;
    margin-top: 10px;
    width: 100%;
    align-items: center;
  }
  
  .profile-tabs {
    flex-wrap: nowrap;
    overflow-x: auto;
    padding-bottom: 10px;
  }
  
  .profile-tab {
    padding: 10px 15px;
    font-size: 13px;
    min-width: 80px;
    flex: 1;
  }
  
  .profile-overview-cards,
  .profile-achievements-grid,
  .profile-items-grid,
  .profile-settings-grid {
    grid-template-columns: 1fr;
  }
  
  .profile-stats-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .profile-detail-item {
    flex-direction: column;
    align-items: flex-start;
    gap: 5px;
  }
  
  .profile-setting-buttons {
    flex-direction: column;
  }
}

/* Small mobile styles */
@media (max-width: 480px) {
  .profile-username {
    font-size: 20px;
  }
  
  .profile-avatar {
    width: 80px;
    height: 80px;
  }
  
  .profile-notification {
    min-width: auto;
    left: 10px;
    right: 10px;
    max-width: none;
    font-size: 13px;
  }
  
  .profile-card-title,
  .profile-setting-title {
    font-size: 16px;
  }
  
  .profile-stats-grid {
    grid-template-columns: 1fr;
  }
  
  .profile-section-title {
    font-size: 18px;
  }
  
  .profile-achievement-card {
    padding: 15px;
  }
  
  .profile-achievement-icon {
    width: 40px;
    height: 40px;
    font-size: 24px;
  }
  
  .profile-achievement-emoji {
    font-size: 22px;
  }
  
  .profile-mini-achievement,
  .profile-mini-item {
    padding: 8px;
  }
}

/* iPhone SE and other small devices */
@media (max-width: 375px) {
  .profile-wrapper {
    padding: 8px;
  }
  
  .profile-header-section {
    padding: 12px;
  }
  
  .profile-username {
    font-size: 18px;
  }
  
  .profile-avatar {
    width: 70px;
    height: 70px;
  }
  
  .profile-tab {
    padding: 8px 12px;
    font-size: 12px;
    min-width: 70px;
  }
  
  .profile-card {
    padding: 12px;
  }
  
  .profile-stat-number {
    font-size: 22px;
  }
  
  .profile-setting-input {
    padding: 8px 12px;
    font-size: 13px;
  }
}
// src/components/pages/store/LeaderboardPage.js
import React, { useEffect, useState, useRef, useCallback } from 'react';
import './LeaderboardPage.css';
import { 
  FaTrophy, 
  FaMedal, 
  FaStar, 
  FaCrown, 
  FaUserAlt,
  FaSearch,
  FaSyncAlt,
  FaChevronDown,
  FaAngleDoubleDown,
  FaExclamationTriangle,
  FaChevronUp,
  FaSpinner
} from 'react-icons/fa';

// Skeleton component for loading state
const SkeletonItem = ({ index }) => {
  return (
    <div className="leaderboard-item skeleton">
      <div className="leaderboard-rank">
        <div className="skeleton-pulse rank-number"></div>
      </div>
      <div className="leaderboard-avatar-container">
        <div className="skeleton-pulse avatar-circle"></div>
      </div>
      <div className="leaderboard-user-info">
        <div className="skeleton-pulse username-line"></div>
        <div className="leaderboard-user-stats">
          <div className="skeleton-pulse stat-line"></div>
          <div className="skeleton-pulse stat-line shorter"></div>
        </div>
      </div>
    </div>
  );
};

const LeaderboardPage = () => {
  const [leaders, setLeaders] = useState([]);
  const [total, setTotal] = useState(0);
  const [skip, setSkip] = useState(0);
  const [limit, setLimit] = useState(50); // Load 50 at a time
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showScrollToTop, setShowScrollToTop] = useState(false);
  
  // Reference to the leaderboard container for scrolling functionality
  const leaderboardRef = useRef(null);
  
  // Function to fetch leaderboard data
  const fetchLeaderboard = useCallback(async (skipCount = 0, replace = true) => {
    try {
      const url = `/api/test/leaderboard?skip=${skipCount}&limit=${limit}`;
      const response = await fetch(url);
      
      if (!response.ok) {
        throw new Error('Failed to load leaderboard data');
      }
      
      const data = await response.json();
      
      if (replace) {
        setLeaders(data.data);
      } else {
        setLeaders(prev => [...prev, ...data.data]);
      }
      
      setTotal(data.total);
      return data;
    } catch (err) {
      setError(err.message);
      return null;
    }
  }, [limit]);

  // Initial data fetch
  useEffect(() => {
    const loadInitialData = async () => {
      setLoading(true);
      setError(null);
      await fetchLeaderboard(skip);
      setLoading(false);
    };
    
    loadInitialData();
  }, [fetchLeaderboard, skip]);

  // Handle scroll event to show/hide scroll-to-top button
  useEffect(() => {
    const handleScroll = () => {
      if (leaderboardRef.current) {
        const { scrollTop } = leaderboardRef.current;
        setShowScrollToTop(scrollTop > 300);
      }
    };
    
    const currentRef = leaderboardRef.current;
    if (currentRef) {
      currentRef.addEventListener('scroll', handleScroll);
    }
    
    return () => {
      if (currentRef) {
        currentRef.removeEventListener('scroll', handleScroll);
      }
    };
  }, []);

  // Load more data
  const handleLoadMore = async () => {
    if (loadingMore) return;
    
    setLoadingMore(true);
    const newSkip = leaders.length;
    const data = await fetchLeaderboard(newSkip, false);
    setLoadingMore(false);
  };

  // Filter leaders by username
  const filteredLeaders = searchTerm.trim() === '' 
    ? leaders 
    : leaders.filter(user => 
        user.username.toLowerCase().includes(searchTerm.toLowerCase())
      );

  // Scroll to top function
  const scrollToTop = () => {
    if (leaderboardRef.current) {
      leaderboardRef.current.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
    }
  };

  // Determine if we should show more results
  const hasMoreResults = leaders.length < total;

  // Render trophy icon based on rank
  const renderRankIcon = (rank) => {
    if (rank === 1) return <FaTrophy className="rank-icon gold" />;
    if (rank === 2) return <FaTrophy className="rank-icon silver" />;
    if (rank === 3) return <FaTrophy className="rank-icon bronze" />;
    if (rank <= 10) return <FaStar className="rank-icon top-ten" />;
    return null;
  };

  // Loading state with skeletons
  if (loading) {
    return (
      <div className="leaderboard-container">
        <div className="leaderboard-header">
          <div className="leaderboard-title">
            <h1>Leaderboard</h1>
            <p>See where you rank against other players!</p>
          </div>
        </div>
        
        <div className="leaderboard-content">
          <div className="leaderboard-loading">
            <FaSpinner className="loading-spinner" />
            <p>Loading leaderboard data...</p>
          </div>
          
          <div className="leaderboard-list">
            {Array.from({ length: 5 }).map((_, idx) => (
              <SkeletonItem key={idx} index={idx} />
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="leaderboard-container">
        <div className="leaderboard-header">
          <div className="leaderboard-title">
            <h1>Leaderboard</h1>
            <p>See where you rank against other players!</p>
          </div>
        </div>
        
        <div className="leaderboard-error">
          <FaExclamationTriangle className="error-icon" />
          <p>Error loading leaderboard: {error}</p>
          <button 
            className="leaderboard-retry-btn"
            onClick={() => {
              setLoading(true);
              setError(null);
              fetchLeaderboard(0)
                .then(() => setLoading(false))
                .catch(() => setLoading(false));
            }}
          >
            <FaSyncAlt /> Try Again
          </button>
        </div>
      </div>
    );
  }

  // Main render - the leaderboard
  return (
    <div className="leaderboard-container">
      <div className="leaderboard-header">
        <div className="leaderboard-title">
          <h1>Leaderboard</h1>
          <p>See where you rank against other players!</p>
        </div>
        
        <div className="leaderboard-stats">
          <div className="leaderboard-stat">
            <FaCrown className="leaderboard-stat-icon" />
            <div className="leaderboard-stat-text">
              <span className="leaderboard-stat-value">{total}</span>
              <span className="leaderboard-stat-label">Players</span>
            </div>
          </div>
        </div>
      </div>
      
      <div className="leaderboard-controls">
        <div className="leaderboard-search">
          <FaSearch className="search-icon" />
          <input 
            type="text"
            placeholder="Search by username..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="leaderboard-search-input"
          />
          {searchTerm && (
            <button 
              className="leaderboard-search-clear"
              onClick={() => setSearchTerm('')}
            >
              &times;
            </button>
          )}
        </div>
      </div>
      
      <div className="leaderboard-content" ref={leaderboardRef}>
        {filteredLeaders.length === 0 ? (
          <div className="leaderboard-empty">
            <FaUserAlt className="empty-icon" />
            <p>No players found matching "{searchTerm}"</p>
            <button 
              className="leaderboard-reset-btn"
              onClick={() => setSearchTerm('')}
            >
              Clear Search
            </button>
          </div>
        ) : (
          <div className="leaderboard-list">
            {filteredLeaders.map((user) => {
              const rankClass = 
                user.rank === 1 ? 'gold-rank' : 
                user.rank === 2 ? 'silver-rank' : 
                user.rank === 3 ? 'bronze-rank' : 
                user.rank <= 10 ? 'top-rank' : '';
              
              return (
                <div key={user.rank} className={`leaderboard-item ${rankClass}`}>
                  <div className="leaderboard-rank">
                    <span className="rank-number">{user.rank}</span>
                    {renderRankIcon(user.rank)}
                  </div>
                  
                  <div className="leaderboard-avatar-container">
                    {user.avatarUrl ? (
                      <img
                        src={user.avatarUrl}
                        alt={`${user.username}'s avatar`}
                        className="leaderboard-avatar"
                      />
                    ) : (
                      <div className="leaderboard-avatar default">
                        <FaUserAlt />
                      </div>
                    )}
                  </div>
                  
                  <div className="leaderboard-user-info">
                    <h3 className="leaderboard-username">{user.username}</h3>
                    <div className="leaderboard-user-stats">
                      <div className="leaderboard-user-level">
                        <span className="level-label">Level</span>
                        <span className="level-value">{user.level}</span>
                      </div>
                      <div className="leaderboard-user-xp">
                        <span className="xp-label">XP</span>
                        <span className="xp-value">{user.xp.toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
            
            {hasMoreResults && !searchTerm && (
              <div className="leaderboard-load-more">
                <button 
                  className="load-more-btn"
                  onClick={handleLoadMore}
                  disabled={loadingMore}
                >
                  {loadingMore ? (
                    <>
                      <FaSpinner className="loading-spinner" />
                      <span>Loading...</span>
                    </>
                  ) : (
                    <>
                      <FaAngleDoubleDown />
                      <span>Load More</span>
                    </>
                  )}
                </button>
              </div>
            )}
          </div>
        )}
        
        {showScrollToTop && (
          <button 
            className="scroll-to-top"
            onClick={scrollToTop}
            aria-label="Scroll to top"
          >
            <FaChevronUp />
          </button>
        )}
      </div>
    </div>
  );
};

export default LeaderboardPage;
/* LeaderboardPage.css - Gamified Leaderboard */

:root {
  --leaderboard-bg-dark: #0b0c15;
  --leaderboard-bg-card: #171a23;
  --leaderboard-accent: #6543cc;
  --leaderboard-accent-glow: #8a58fc;
  --leaderboard-accent-secondary: #ff4c8b;
  --leaderboard-success: #2ebb77;
  --leaderboard-error: #ff4e4e;
  --leaderboard-warning: #ffc107;
  --leaderboard-text: #e2e2e2;
  --leaderboard-text-secondary: #9da8b9;
  --leaderboard-border: #2a2c3d;
  --leaderboard-input-bg: rgba(0, 0, 0, 0.2);
  --leaderboard-gradient-primary: linear-gradient(135deg, #6543cc, #8a58fc);
  --leaderboard-gradient-secondary: linear-gradient(135deg, #ff4c8b, #ff7950);
  --leaderboard-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  --leaderboard-glow: 0 0 15px rgba(134, 88, 252, 0.5);
  
  /* Rank colors */
  --rank-gold: #ffd700;
  --rank-silver: #c0c0c0;
  --rank-bronze: #cd7f32;
  --rank-top: #00ccff;
}

/* Main Container */
.leaderboard-container {
  font-family: 'Orbitron', 'Roboto', sans-serif;
  color: var(--leaderboard-text);
  margin: 0;
  padding: 0;
  min-height: 100vh;
  width: 100%;
  background-color: var(--leaderboard-bg-dark);
  background-image: 
    radial-gradient(circle at 15% 25%, rgba(26, 20, 64, 0.4) 0%, transparent 45%),
    radial-gradient(circle at 75% 65%, rgba(42, 26, 89, 0.3) 0%, transparent 40%),
    repeating-linear-gradient(rgba(0, 0, 0, 0.05) 0px, rgba(0, 0, 0, 0.05) 1px, transparent 1px, transparent 10px);
  position: relative;
  display: flex;
  flex-direction: column;
  padding: 20px;
  box-sizing: border-box;
}

/* =================== */
/* HEADER SECTION      */
/* =================== */

.leaderboard-header {
  background: var(--leaderboard-bg-card);
  border-radius: 15px;
  margin-bottom: 20px;
  padding: 25px;
  box-shadow: var(--leaderboard-shadow);
  border: 1px solid var(--leaderboard-border);
  position: relative;
  overflow: hidden;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 20px;
}

.leaderboard-header::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 4px;
  background: var(--leaderboard-gradient-primary);
}

.leaderboard-title {
  flex: 1;
  min-width: 250px;
}

.leaderboard-title h1 {
  font-size: 28px;
  margin: 0 0 10px 0;
  background: var(--leaderboard-gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-shadow: 0 0 2px rgba(0, 0, 0, 0.5);
  font-weight: 700;
}

.leaderboard-title p {
  font-size: 16px;
  color: var(--leaderboard-text-secondary);
  margin: 0;
}

.leaderboard-stats {
  display: flex;
  gap: 20px;
}

.leaderboard-stat {
  display: flex;
  align-items: center;
  gap: 12px;
  background: var(--leaderboard-input-bg);
  border: 1px solid var(--leaderboard-border);
  border-radius: 10px;
  padding: 10px 15px;
}

.leaderboard-stat-icon {
  font-size: 24px;
  color: var(--rank-gold);
}

.leaderboard-stat-text {
  display: flex;
  flex-direction: column;
}

.leaderboard-stat-value {
  font-size: 18px;
  font-weight: 600;
}

.leaderboard-stat-label {
  font-size: 12px;
  color: var(--leaderboard-text-secondary);
}

/* =================== */
/* CONTROLS SECTION    */
/* =================== */

.leaderboard-controls {
  margin-bottom: 20px;
}

.leaderboard-search {
  position: relative;
  max-width: 500px;
}

.search-icon {
  position: absolute;
  left: 15px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--leaderboard-text-secondary);
}

.leaderboard-search-input {
  width: 100%;
  background: var(--leaderboard-bg-card);
  border: 1px solid var(--leaderboard-border);
  border-radius: 10px;
  padding: 12px 40px 12px 45px;
  color: var(--leaderboard-text);
  font-family: inherit;
  font-size: 14px;
  transition: all 0.2s;
}

.leaderboard-search-input:focus {
  outline: none;
  border-color: var(--leaderboard-accent);
  box-shadow: var(--leaderboard-glow);
}

.leaderboard-search-clear {
  position: absolute;
  right: 15px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--leaderboard-text-secondary);
  font-size: 18px;
  cursor: pointer;
  padding: 0;
  transition: color 0.2s;
}

.leaderboard-search-clear:hover {
  color: var(--leaderboard-text);
}

/* =================== */
/* CONTENT SECTION     */
/* =================== */

.leaderboard-content {
  flex: 1;
  position: relative;
  max-height: calc(100vh - 220px);
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: var(--leaderboard-accent) var(--leaderboard-bg-dark);
}

.leaderboard-content::-webkit-scrollbar {
  width: 8px;
}

.leaderboard-content::-webkit-scrollbar-track {
  background: var(--leaderboard-bg-dark);
  border-radius: 4px;
}

.leaderboard-content::-webkit-scrollbar-thumb {
  background-color: var(--leaderboard-accent);
  border-radius: 4px;
}

.leaderboard-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.leaderboard-item {
  display: flex;
  align-items: center;
  background: var(--leaderboard-bg-card);
  border: 1px solid var(--leaderboard-border);
  border-radius: 12px;
  padding: 15px;
  transition: transform 0.2s, box-shadow 0.2s;
  position: relative;
  overflow: hidden;
}

.leaderboard-item:hover {
  transform: translateY(-2px);
  box-shadow: var(--leaderboard-shadow);
}

/* Special ranks styling */
.leaderboard-item.gold-rank {
  border-color: var(--rank-gold);
  box-shadow: 0 0 15px rgba(255, 215, 0, 0.3);
}

.leaderboard-item.gold-rank::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: linear-gradient(90deg, #ffd700, #ffeb7a, #ffd700);
}

.leaderboard-item.silver-rank {
  border-color: var(--rank-silver);
  box-shadow: 0 0 15px rgba(192, 192, 192, 0.3);
}

.leaderboard-item.silver-rank::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: linear-gradient(90deg, #c0c0c0, #e6e6e6, #c0c0c0);
}

.leaderboard-item.bronze-rank {
  border-color: var(--rank-bronze);
  box-shadow: 0 0 15px rgba(205, 127, 50, 0.3);
}

.leaderboard-item.bronze-rank::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: linear-gradient(90deg, #cd7f32, #e8bb85, #cd7f32);
}

.leaderboard-item.top-rank {
  border-color: var(--rank-top);
}

.leaderboard-item.top-rank::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: linear-gradient(90deg, #00ccff, #80e6ff, #00ccff);
}

.leaderboard-rank {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-width: 50px;
  position: relative;
}

.rank-number {
  font-size: 20px;
  font-weight: 700;
}

.leaderboard-item.gold-rank .rank-number {
  color: var(--rank-gold);
}

.leaderboard-item.silver-rank .rank-number {
  color: var(--rank-silver);
}

.leaderboard-item.bronze-rank .rank-number {
  color: var(--rank-bronze);
}

.leaderboard-item.top-rank .rank-number {
  color: var(--rank-top);
}

.rank-icon {
  margin-top: 5px;
  font-size: 16px;
}

.rank-icon.gold {
  color: var(--rank-gold);
}

.rank-icon.silver {
  color: var(--rank-silver);
}

.rank-icon.bronze {
  color: var(--rank-bronze);
}

.rank-icon.top-ten {
  color: var(--rank-top);
}

.leaderboard-avatar-container {
  margin: 0 15px;
}

.leaderboard-avatar {
  width: 60px;
  height: 60px;
  border-radius: 50%;
  border: 2px solid var(--leaderboard-border);
  object-fit: cover;
}

.leaderboard-avatar.default {
  background: var(--leaderboard-input-bg);
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--leaderboard-text-secondary);
  font-size: 24px;
}

.leaderboard-user-info {
  flex: 1;
  min-width: 0; /* Enable text truncation */
}

.leaderboard-username {
  font-size: 16px;
  font-weight: 600;
  margin: 0 0 8px 0;
  display: -webkit-box;
  -webkit-line-clamp: 1;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.leaderboard-item.gold-rank .leaderboard-username {
  color: var(--rank-gold);
}

.leaderboard-item.silver-rank .leaderboard-username {
  color: var(--rank-silver);
}

.leaderboard-item.bronze-rank .leaderboard-username {
  color: var(--rank-bronze);
}

.leaderboard-user-stats {
  display: flex;
  gap: 15px;
}

.leaderboard-user-level,
.leaderboard-user-xp {
  display: flex;
  align-items: center;
  gap: 8px;
}

.level-label,
.xp-label {
  color: var(--leaderboard-text-secondary);
  font-size: 13px;
}

.level-value,
.xp-value {
  font-weight: 600;
  font-size: 14px;
}

/* Load More Button */
.leaderboard-load-more {
  display: flex;
  justify-content: center;
  margin: 20px 0;
}

.load-more-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  background: var(--leaderboard-gradient-primary);
  color: white;
  border: none;
  border-radius: 30px;
  padding: 12px 25px;
  font-family: inherit;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: 0 4px 15px rgba(101, 67, 204, 0.3);
}

.load-more-btn:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(101, 67, 204, 0.4);
}

.load-more-btn:active:not(:disabled) {
  transform: translateY(1px);
}

.load-more-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.loading-spinner {
  animation: spin 1.5s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* Scroll to Top Button */
.scroll-to-top {
  position: fixed;
  bottom: 20px;
  right: 20px;
  width: 40px;
  height: 40px;
  background: var(--leaderboard-bg-card);
  border: 1px solid var(--leaderboard-border);
  color: var(--leaderboard-text);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  z-index: 10;
  box-shadow: var(--leaderboard-shadow);
  transition: all 0.2s;
}

.scroll-to-top:hover {
  background: var(--leaderboard-accent);
  color: white;
  transform: translateY(-3px);
}

/* =================== */
/* EMPTY STATE         */
/* =================== */

.leaderboard-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  background: var(--leaderboard-bg-card);
  border: 1px solid var(--leaderboard-border);
  border-radius: 12px;
  gap: 15px;
  text-align: center;
}

.empty-icon {
  font-size: 40px;
  color: var(--leaderboard-text-secondary);
  opacity: 0.6;
}

.leaderboard-empty p {
  font-size: 18px;
  margin: 0;
  color: var(--leaderboard-text-secondary);
}

.leaderboard-reset-btn {
  background: var(--leaderboard-accent);
  color: white;
  border: none;
  border-radius: 8px;
  padding: 10px 20px;
  font-family: inherit;
  font-size: 14px;
  cursor: pointer;
  transition: background 0.2s;
}

.leaderboard-reset-btn:hover {
  background: var(--leaderboard-accent-glow);
}

/* =================== */
/* LOADING STATE       */
/* =================== */

.leaderboard-loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  background: var(--leaderboard-bg-card);
  border: 1px solid var(--leaderboard-border);
  border-radius: 12px;
  margin-bottom: 20px;
  gap: 15px;
}

.leaderboard-loading .loading-spinner {
  font-size: 40px;
  color: var(--leaderboard-accent);
}

.leaderboard-loading p {
  font-size: 18px;
  margin: 0;
  color: var(--leaderboard-text-secondary);
}

/* =================== */
/* ERROR STATE         */
/* =================== */

.leaderboard-error {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  background: var(--leaderboard-bg-card);
  border: 1px solid var(--leaderboard-error);
  border-radius: 12px;
  gap: 15px;
  text-align: center;
}

.error-icon {
  font-size: 40px;
  color: var(--leaderboard-error);
}

.leaderboard-error p {
  font-size: 18px;
  margin: 0;
  color: var(--leaderboard-text);
}

.leaderboard-retry-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--leaderboard-bg-dark);
  color: var(--leaderboard-text);
  border: 1px solid var(--leaderboard-border);
  border-radius: 8px;
  padding: 10px 20px;
  font-family: inherit;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.2s;
}

.leaderboard-retry-btn:hover {
  background: var(--leaderboard-accent);
  color: white;
  border-color: transparent;
}

/* =================== */
/* SKELETON LOADERS    */
/* =================== */

.skeleton {
  position: relative;
  overflow: hidden;
}

.skeleton-pulse {
  background: linear-gradient(90deg, var(--leaderboard-input-bg) 0%, rgba(49, 49, 63, 0.5) 50%, var(--leaderboard-input-bg) 100%);
  background-size: 200% 100%;
  animation: pulse 1.5s ease-in-out infinite;
  border-radius: 4px;
}

@keyframes pulse {
  0% { background-position: 0% 0%; }
  100% { background-position: -200% 0%; }
}

.rank-number.skeleton-pulse {
  width: 20px;
  height: 20px;
  border-radius: 50%;
}

.avatar-circle.skeleton-pulse {
  width: 60px;
  height: 60px;
  border-radius: 50%;
}

.username-line.skeleton-pulse {
  width: 150px;
  height: 18px;
  margin-bottom: 10px;
}

.stat-line.skeleton-pulse {
  width: 100px;
  height: 14px;
}

.stat-line.shorter.skeleton-pulse {
  width: 70px;
}

/* =================== */
/* RESPONSIVE STYLES   */
/* =================== */

/* Tablet Styles */
@media (max-width: 992px) {
  .leaderboard-container {
    padding: 15px;
  }
  
  .leaderboard-header {
    padding: 20px;
  }
  
  .leaderboard-title h1 {
    font-size: 24px;
  }
  
  .leaderboard-title p {
    font-size: 14px;
  }
  
  .leaderboard-stat {
    padding: 8px 12px;
  }
  
  .leaderboard-stat-icon {
    font-size: 20px;
  }
  
  .leaderboard-stat-value {
    font-size: 16px;
  }
  
  .leaderboard-content {
    max-height: calc(100vh - 200px);
  }
  
  .leaderboard-avatar {
    width: 50px;
    height: 50px;
  }
  
  .rank-number {
    font-size: 18px;
  }
}

/* Mobile Styles */
@media (max-width: 768px) {
  .leaderboard-container {
    padding: 10px;
  }
  
  .leaderboard-header {
    padding: 15px;
    flex-direction: column;
    align-items: flex-start;
  }
  
  .leaderboard-title h1 {
    font-size: 22px;
  }
  
  .leaderboard-stats {
    width: 100%;
    justify-content: flex-start;
  }
  
  .leaderboard-item {
    padding: 12px;
  }
  
  .leaderboard-username {
    font-size: 15px;
  }
  
  .leaderboard-user-stats {
    flex-direction: column;
    gap: 5px;
  }
  
  .level-label,
  .xp-label,
  .level-value,
  .xp-value {
    font-size: 12px;
  }
  
  .load-more-btn {
    padding: 10px 20px;
    font-size: 14px;
  }
  
  .leaderboard-avatar-container {
    margin: 0 10px;
  }
  
  .leaderboard-avatar {
    width: 45px;
    height: 45px;
  }
}

/* Small Mobile Styles */
@media (max-width: 480px) {
  .leaderboard-title h1 {
    font-size: 20px;
  }
  
  .leaderboard-title p {
    font-size: 12px;
  }
  
  .leaderboard-rank {
    min-width: 30px;
  }
  
  .rank-number {
    font-size: 16px;
  }
  
  .rank-icon {
    font-size: 14px;
  }
  
  .leaderboard-avatar {
    width: 40px;
    height: 40px;
  }
  
  .leaderboard-username {
    font-size: 14px;
    margin-bottom: 5px;
  }
  
  .load-more-btn {
    width: 100%;
  }
  
  .leaderboard-avatar-container {
    margin: 0 8px;
  }
  
  .leaderboard-search-input {
    padding: 10px 35px 10px 35px;
    font-size: 13px;
  }
  
  .leaderboard-empty p,
  .leaderboard-loading p,
  .leaderboard-error p {
    font-size: 15px;
  }
}

/* iPhone SE and other small devices */
@media (max-width: 375px) {
  .leaderboard-rank {
    min-width: 25px;
  }
  
  .rank-number {
    font-size: 14px;
  }
  
  .rank-icon {
    font-size: 12px;
  }
  
  .leaderboard-avatar {
    width: 35px;
    height: 35px;
    border-width: 1px;
  }
  
  .leaderboard-username {
    font-size: 13px;
  }
  
  .level-label,
  .xp-label,
  .level-value,
  .xp-value {
    font-size: 11px;
  }
}
// src/components/pages/store/AchievementPage.js
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { fetchAchievements } from '../store/achievementsSlice';
import { 
  FaTrophy, 
  FaMedal, 
  FaStar, 
  FaCrown, 
  FaBolt, 
  FaBook, 
  FaBrain, 
  FaCheckCircle, 
  FaMagic,
  FaFilter,
  FaTimes,
  FaCoins,
  FaLevelUpAlt,
  FaCheck,
  FaLock,
  FaInfoCircle,
  FaChevronDown,
  FaChevronUp,
  FaSearch,
  FaSyncAlt
} from 'react-icons/fa';
import { showAchievementToast } from './AchievementToast';
import './AchievementPage.css';

// Mapping achievement IDs to icon components.
const iconMapping = {
  "test_rookie": FaTrophy,
  "accuracy_king": FaMedal,
  "bronze_grinder": FaBook,
  "silver_scholar": FaStar,
  "gold_god": FaCrown,
  "platinum_pro": FaMagic,
  "walking_encyclopedia": FaBrain,
  "redemption_arc": FaBolt,
  "coin_collector_5000": FaBook,
  "coin_hoarder_10000": FaBook,
  "coin_tycoon_50000": FaBook,
  "perfectionist_1": FaCheckCircle,
  "double_trouble_2": FaCheckCircle,
  "error404_failure_not_found": FaCheckCircle,
  "level_up_5": FaTrophy,
  "mid_tier_grinder_25": FaMedal,
  "elite_scholar_50": FaStar,
  "ultimate_master_100": FaCrown,
  "answer_machine_1000": FaBook,
  "knowledge_beast_5000": FaBrain,
  "question_terminator": FaBrain,
  "test_finisher": FaCheckCircle,
};

// Mapping achievement IDs to colors.
const colorMapping = {
  "test_rookie": "#ff5555",
  "accuracy_king": "#ffa500",
  "bronze_grinder": "#cd7f32",
  "silver_scholar": "#c0c0c0",
  "gold_god": "#ffd700",
  "platinum_pro": "#e5e4e2",
  "walking_encyclopedia": "#00fa9a",
  "redemption_arc": "#ff4500",
  "coin_collector_5000": "#ff69b4",
  "coin_hoarder_10000": "#ff1493",
  "coin_tycoon_50000": "#ff0000",
  "perfectionist_1": "#adff2f",
  "double_trouble_2": "#7fff00",
  "error404_failure_not_found": "#00ffff",
  "level_up_5": "#f08080",
  "mid_tier_grinder_25": "#ff8c00",
  "elite_scholar_50": "#ffd700",
  "ultimate_master_100": "#ff4500",
  "answer_machine_1000": "#ff69b4",
  "knowledge_beast_5000": "#00fa9a",
  "question_terminator": "#ff1493",
  "test_finisher": "#adff2f",
};

// Achievement categories
const categories = {
  "test": "Test Completion",
  "score": "Score & Accuracy",
  "coins": "Coin Collection",
  "level": "Leveling Up",
  "questions": "Question Mastery",
  "all": "All Achievements"
};

// Function to determine the category of an achievement
const getAchievementCategory = (achievementId) => {
  if (achievementId.includes('level') || achievementId.includes('grinder') || 
      achievementId.includes('scholar') || achievementId.includes('master')) {
    return "level";
  } else if (achievementId.includes('coin')) {
    return "coins";
  } else if (achievementId.includes('accuracy') || achievementId.includes('perfectionist') || 
             achievementId.includes('redemption')) {
    return "score";
  } else if (achievementId.includes('answer') || achievementId.includes('question') || 
             achievementId.includes('encyclopedia')) {
    return "questions";
  } else if (achievementId.includes('rookie') || achievementId.includes('test') || 
             achievementId.includes('trouble')) {
    return "test";
  }
  return "all";
};

const AchievementPage = () => {
  const dispatch = useDispatch();
  const achievements = useSelector((state) => state.achievements.all);
  const userAchievements = useSelector((state) => state.user.achievements) || [];
  const { username, level, xp } = useSelector((state) => state.user);
  const loadingStatus = useSelector((state) => state.achievements.status);

  // State for filtering and sorting
  const [activeCategory, setActiveCategory] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [showOnlyUnlocked, setShowOnlyUnlocked] = useState(false);
  const [showOnlyLocked, setShowOnlyLocked] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState({});
  const [sortBy, setSortBy] = useState('default'); // default, name, unlocked
  
  // State for tracking achievement stats
  const [totalAchievements, setTotalAchievements] = useState(0);
  const [unlockedAchievements, setUnlockedAchievements] = useState(0);
  const [percentComplete, setPercentComplete] = useState(0);

  useEffect(() => {
    if (!achievements || achievements.length === 0) {
      dispatch(fetchAchievements());
    }
  }, [dispatch, achievements]);

  useEffect(() => {
    if (achievements && achievements.length > 0) {
      setTotalAchievements(achievements.length);
      setUnlockedAchievements(userAchievements.length);
      setPercentComplete((userAchievements.length / achievements.length) * 100);
    }
  }, [achievements, userAchievements]);

  // Filter achievements based on selected criteria
  const filteredAchievements = achievements.filter(achievement => {
    // Category filter
    const categoryMatch = activeCategory === 'all' || 
                        getAchievementCategory(achievement.achievementId) === activeCategory;
    
    // Unlock status filter
    const isUnlocked = userAchievements.includes(achievement.achievementId);
    const statusMatch = (showOnlyUnlocked && isUnlocked) || 
                      (showOnlyLocked && !isUnlocked) || 
                      (!showOnlyUnlocked && !showOnlyLocked);
    
    // Search filter
    const searchMatch = !searchTerm || 
                      achievement.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
                      achievement.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    return categoryMatch && statusMatch && searchMatch;
  });

  // Sort achievements
  const sortedAchievements = [...filteredAchievements].sort((a, b) => {
    const aUnlocked = userAchievements.includes(a.achievementId);
    const bUnlocked = userAchievements.includes(b.achievementId);
    
    if (sortBy === 'name') {
      return a.title.localeCompare(b.title);
    } else if (sortBy === 'unlocked') {
      return bUnlocked - aUnlocked; // Show unlocked first
    } else if (sortBy === 'locked') {
      return aUnlocked - bUnlocked; // Show locked first
    }
    
    // Default sorting
    return 0;
  });

  const toggleDetails = (achievementId) => {
    setDetailsOpen(prev => ({
      ...prev,
      [achievementId]: !prev[achievementId]
    }));
  };

  // Reset all filters
  const resetFilters = () => {
    setActiveCategory('all');
    setSearchTerm('');
    setShowOnlyUnlocked(false);
    setShowOnlyLocked(false);
    setSortBy('default');
  };

  // This function remains if you ever want to trigger a test popup programmatically
  const testPopup = (achievementId) => {
    const achievement = achievements.find((ach) => ach.achievementId === achievementId);
    if (achievement) {
      const IconComponent = iconMapping[achievement.achievementId] || null;
      const color = colorMapping[achievement.achievementId] || "#fff";
      showAchievementToast({
        title: achievement.title,
        description: achievement.description,
        icon: IconComponent ? <IconComponent /> : null,
        color: color
      });
    }
  };

  return (
    <div className="achievement-page-container">
      {/* Header Section with Stats */}
      <div className="achievement-header">
        <div className="achievement-header-content">
          <div className="achievement-header-titles">
            <h1>Achievement Gallery</h1>
            <p>Track your progress and unlock achievements as you master the platform!</p>
          </div>
          
          {username && (
            <div className="achievement-player-stats">
              <div className="achievement-player-name">
                <span>{username}'s Progress</span>
              </div>
              <div className="achievement-progress-container">
                <div className="achievement-progress-stats">
                  <div className="achievement-stat">
                    <FaTrophy className="achievement-stat-icon" />
                    <div className="achievement-stat-numbers">
                      <span className="achievement-stat-value">{unlockedAchievements} / {totalAchievements}</span>
                      <span className="achievement-stat-label">Achievements</span>
                    </div>
                  </div>
                  <div className="achievement-stat">
                    <FaLevelUpAlt className="achievement-stat-icon" />
                    <div className="achievement-stat-numbers">
                      <span className="achievement-stat-value">{level}</span>
                      <span className="achievement-stat-label">Level</span>
                    </div>
                  </div>
                </div>
                <div className="achievement-progress-bar-container">
                  <div className="achievement-progress-bar">
                    <div 
                      className="achievement-progress-fill" 
                      style={{ width: `${percentComplete}%` }}
                    ></div>
                  </div>
                  <span className="achievement-progress-percent">{Math.round(percentComplete)}% Complete</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Filter and Search Section */}
      <div className="achievement-controls">
        <div className="achievement-categories">
          {Object.entries(categories).map(([key, value]) => (
            <button
              key={key}
              className={`achievement-category-btn ${activeCategory === key ? 'active' : ''}`}
              onClick={() => setActiveCategory(key)}
            >
              {value}
            </button>
          ))}
        </div>
        
        <div className="achievement-filters">
          <div className="achievement-search">
            <FaSearch className="achievement-search-icon" />
            <input
              type="text"
              placeholder="Search achievements..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="achievement-search-input"
            />
            {searchTerm && (
              <button 
                className="achievement-search-clear" 
                onClick={() => setSearchTerm('')}
              >
                <FaTimes />
              </button>
            )}
          </div>
          
          <div className="achievement-filter-options">
            <button 
              className={`achievement-filter-btn ${showOnlyUnlocked ? 'active' : ''}`}
              onClick={() => {
                setShowOnlyUnlocked(!showOnlyUnlocked);
                setShowOnlyLocked(false);
              }}
            >
              <FaCheck />
              <span>Unlocked</span>
            </button>
            
            <button 
              className={`achievement-filter-btn ${showOnlyLocked ? 'active' : ''}`}
              onClick={() => {
                setShowOnlyLocked(!showOnlyLocked);
                setShowOnlyUnlocked(false);
              }}
            >
              <FaLock />
              <span>Locked</span>
            </button>
            
            <div className="achievement-sort-dropdown">
              <select 
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="achievement-sort-select"
              >
                <option value="default">Default Sort</option>
                <option value="name">Sort by Name</option>
                <option value="unlocked">Unlocked First</option>
                <option value="locked">Locked First</option>
              </select>
            </div>
            
            <button 
              className="achievement-filter-reset" 
              onClick={resetFilters}
              title="Reset all filters"
            >
              <FaSyncAlt />
            </button>
          </div>
        </div>
      </div>

      {/* Main Achievement Grid */}
      {loadingStatus === 'loading' ? (
        <div className="achievement-loading">
          <FaSyncAlt className="achievement-loading-icon" />
          <p>Loading achievements...</p>
        </div>
      ) : sortedAchievements.length > 0 ? (
        <div className="achievement-grid">
          {sortedAchievements.map((ach) => {
            const isUnlocked = userAchievements.includes(ach.achievementId);
            const IconComponent = iconMapping[ach.achievementId] || FaTrophy;
            const iconColor = colorMapping[ach.achievementId] || "#ffffff";
            const isDetailsOpen = detailsOpen[ach.achievementId] || false;
            
            return (
              <div
                key={ach.achievementId}
                className={`achievement-card ${isUnlocked ? 'unlocked' : 'locked'}`}
                onClick={() => toggleDetails(ach.achievementId)}
              >
                <div className="achievement-card-content">
                  <div className="achievement-icon-container">
                    <div className="achievement-icon" style={{ color: iconColor }}>
                      <IconComponent />
                    </div>
                    {isUnlocked && <div className="achievement-completed-badge"><FaCheck /></div>}
                  </div>
                  
                  <div className="achievement-info">
                    <h3 className="achievement-title">{ach.title}</h3>
                    <p className="achievement-description">{ach.description}</p>
                  </div>
                  
                  <button 
                    className="achievement-details-toggle"
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleDetails(ach.achievementId);
                    }}
                  >
                    {isDetailsOpen ? <FaChevronUp /> : <FaChevronDown />}
                  </button>
                </div>
                
                {isDetailsOpen && (
                  <div className="achievement-details">
                    <div className="achievement-details-content">
                      <div className="achievement-details-header">
                        <FaInfoCircle className="achievement-details-icon" />
                        <h4>Achievement Details</h4>
                      </div>
                      
                      <div className="achievement-details-info">
                        <div className="achievement-details-item">
                          <span className="achievement-details-label">Category:</span>
                          <span className="achievement-details-value">
                            {categories[getAchievementCategory(ach.achievementId)]}
                          </span>
                        </div>
                        
                        <div className="achievement-details-item">
                          <span className="achievement-details-label">Status:</span>
                          <span className={`achievement-details-value ${isUnlocked ? 'unlocked' : 'locked'}`}>
                            {isUnlocked ? 'Unlocked' : 'Locked'}
                          </span>
                        </div>
                        
                        {/* Add more achievement details as needed */}
                      </div>
                    </div>
                  </div>
                )}
                
                {!isUnlocked && (
                  <div className="achievement-locked-overlay">
                    <FaLock className="achievement-locked-icon" />
                    <span>Locked</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="achievement-empty">
          <FaFilter className="achievement-empty-icon" />
          <p>No achievements match your current filters.</p>
          <button className="achievement-reset-btn" onClick={resetFilters}>
            Reset Filters
          </button>
        </div>
      )}
    </div>
  );
};
/* AchievementPage.css - Gamified Achievement Page */

:root {
  --achievement-bg-dark: #0b0c15;
  --achievement-bg-card: #171a23;
  --achievement-accent: #6543cc;
  --achievement-accent-glow: #8a58fc;
  --achievement-accent-secondary: #ff4c8b;
  --achievement-success: #2ebb77;
  --achievement-error: #ff4e4e;
  --achievement-warning: #ffc107;
  --achievement-text: #e2e2e2;
  --achievement-text-secondary: #9da8b9;
  --achievement-border: #2a2c3d;
  --achievement-input-bg: rgba(0, 0, 0, 0.2);
  --achievement-gradient-primary: linear-gradient(135deg, #6543cc, #8a58fc);
  --achievement-gradient-secondary: linear-gradient(135deg, #ff4c8b, #ff7950);
  --achievement-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  --achievement-glow: 0 0 15px rgba(134, 88, 252, 0.5);
}

/* Main Container */
.achievement-page-container {
  font-family: 'Orbitron', 'Roboto', sans-serif;
  color: var(--achievement-text);
  margin: 0;
  padding: 0;
  min-height: 100vh;
  width: 100%;
  background-color: var(--achievement-bg-dark);
  background-image: 
    radial-gradient(circle at 15% 25%, rgba(26, 20, 64, 0.4) 0%, transparent 45%),
    radial-gradient(circle at 75% 65%, rgba(42, 26, 89, 0.3) 0%, transparent 40%),
    repeating-linear-gradient(rgba(0, 0, 0, 0.05) 0px, rgba(0, 0, 0, 0.05) 1px, transparent 1px, transparent 10px);
  position: relative;
  display: flex;
  flex-direction: column;
  padding: 20px;
  box-sizing: border-box;
}

/* =================== */
/* HEADER SECTION      */
/* =================== */

.achievement-header {
  background: var(--achievement-bg-card);
  border-radius: 15px;
  margin-bottom: 30px;
  padding: 25px;
  box-shadow: var(--achievement-shadow);
  border: 1px solid var(--achievement-border);
  position: relative;
  overflow: hidden;
}

.achievement-header::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 4px;
  background: var(--achievement-gradient-primary);
}

.achievement-header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 20px;
}

.achievement-header-titles {
  flex: 1;
  min-width: 300px;
}

.achievement-header-titles h1 {
  font-size: 28px;
  margin: 0 0 10px 0;
  background: var(--achievement-gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-shadow: 0 0 2px rgba(0, 0, 0, 0.5);
  font-weight: 700;
}

.achievement-header-titles p {
  font-size: 16px;
  color: var(--achievement-text-secondary);
  margin: 0;
}

.achievement-player-stats {
  min-width: 300px;
  flex: 1;
  background: var(--achievement-input-bg);
  border-radius: 12px;
  padding: 15px;
  border: 1px solid var(--achievement-border);
}

.achievement-player-name {
  margin-bottom: 15px;
  font-size: 18px;
  font-weight: 600;
  text-align: center;
}

.achievement-progress-container {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.achievement-progress-stats {
  display: flex;
  justify-content: space-around;
}

.achievement-stat {
  display: flex;
  align-items: center;
  gap: 10px;
}

.achievement-stat-icon {
  font-size: 24px;
  color: var(--achievement-accent);
}

.achievement-stat-numbers {
  display: flex;
  flex-direction: column;
}

.achievement-stat-value {
  font-size: 18px;
  font-weight: 600;
}

.achievement-stat-label {
  font-size: 12px;
  color: var(--achievement-text-secondary);
}

.achievement-progress-bar-container {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.achievement-progress-bar {
  height: 8px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 4px;
  overflow: hidden;
}

.achievement-progress-fill {
  height: 100%;
  background: var(--achievement-gradient-secondary);
  transition: width 1s ease;
}

.achievement-progress-percent {
  font-size: 12px;
  text-align: right;
  color: var(--achievement-text-secondary);
}

/* =================== */
/* CONTROLS SECTION    */
/* =================== */

.achievement-controls {
  margin-bottom: 30px;
}

.achievement-categories {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 20px;
  overflow-x: auto;
  padding-bottom: 5px;
  scrollbar-width: thin;
  scrollbar-color: var(--achievement-accent) var(--achievement-bg-dark);
}

.achievement-categories::-webkit-scrollbar {
  height: 5px;
}

.achievement-categories::-webkit-scrollbar-track {
  background: var(--achievement-bg-dark);
}

.achievement-categories::-webkit-scrollbar-thumb {
  background-color: var(--achievement-accent);
  border-radius: 10px;
}

.achievement-category-btn {
  background: var(--achievement-bg-card);
  border: 1px solid var(--achievement-border);
  color: var(--achievement-text-secondary);
  padding: 10px 20px;
  border-radius: 8px;
  cursor: pointer;
  font-family: inherit;
  font-size: 14px;
  font-weight: 500;
  transition: all 0.2s;
  min-width: max-content;
}

.achievement-category-btn:hover {
  background: rgba(255, 255, 255, 0.05);
  color: var(--achievement-text);
}

.achievement-category-btn.active {
  background: var(--achievement-gradient-primary);
  color: white;
  border-color: transparent;
  box-shadow: var(--achievement-glow);
}

.achievement-filters {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
  align-items: center;
}

.achievement-search {
  position: relative;
  flex: 1;
  min-width: 250px;
}

.achievement-search-icon {
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--achievement-text-secondary);
  font-size: 16px;
}

.achievement-search-input {
  background: var(--achievement-input-bg);
  border: 1px solid var(--achievement-border);
  border-radius: 8px;
  padding: 12px 40px 12px 40px;
  color: var(--achievement-text);
  font-family: inherit;
  font-size: 14px;
  width: 100%;
  transition: border-color 0.2s;
}

.achievement-search-input:focus {
  outline: none;
  border-color: var(--achievement-accent);
}

.achievement-search-clear {
  position: absolute;
  right: 12px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--achievement-text-secondary);
  cursor: pointer;
  padding: 0;
  font-size: 14px;
  transition: color 0.2s;
}

.achievement-search-clear:hover {
  color: var(--achievement-text);
}

.achievement-filter-options {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}

.achievement-filter-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--achievement-bg-card);
  border: 1px solid var(--achievement-border);
  color: var(--achievement-text-secondary);
  padding: 10px 15px;
  border-radius: 8px;
  cursor: pointer;
  font-family: inherit;
  font-size: 14px;
  transition: all 0.2s;
}

.achievement-filter-btn:hover {
  background: rgba(255, 255, 255, 0.05);
  color: var(--achievement-text);
}

.achievement-filter-btn.active {
  background: var(--achievement-accent);
  color: white;
  border-color: transparent;
}

.achievement-sort-dropdown select {
  background: var(--achievement-bg-card);
  border: 1px solid var(--achievement-border);
  color: var(--achievement-text);
  padding: 10px 15px;
  border-radius: 8px;
  font-family: inherit;
  font-size: 14px;
  cursor: pointer;
  appearance: none;
  -webkit-appearance: none;
  -moz-appearance: none;
  background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%239da8b9' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
  background-repeat: no-repeat;
  background-position: right 10px center;
  background-size: 16px;
  padding-right: 30px;
  min-width: 160px;
}

.achievement-sort-dropdown select:focus {
  outline: none;
  border-color: var(--achievement-accent);
}

.achievement-filter-reset {
  background: var(--achievement-bg-card);
  border: 1px solid var(--achievement-border);
  color: var(--achievement-text-secondary);
  width: 38px;
  height: 38px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all 0.2s;
}

.achievement-filter-reset:hover {
  background: rgba(255, 255, 255, 0.05);
  color: var(--achievement-text);
}

/* =================== */
/* GRID SECTION        */
/* =================== */

.achievement-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 20px;
  margin-top: 20px;
}

.achievement-card {
  position: relative;
  background: var(--achievement-bg-card);
  border-radius: 12px;
  border: 1px solid var(--achievement-border);
  overflow: hidden;
  box-shadow: var(--achievement-shadow);
  transition: transform 0.3s, box-shadow 0.3s;
  cursor: pointer;
}

.achievement-card:hover {
  transform: translateY(-5px);
  box-shadow: var(--achievement-shadow), var(--achievement-glow);
}

.achievement-card.unlocked {
  border-color: var(--achievement-accent);
}

.achievement-card.unlocked::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: var(--achievement-gradient-primary);
}

.achievement-card-content {
  display: flex;
  padding: 20px;
  gap: 15px;
}

.achievement-icon-container {
  position: relative;
  min-width: 50px;
}

.achievement-icon {
  width: 50px;
  height: 50px;
  background: rgba(255, 255, 255, 0.05);
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
}

.achievement-completed-badge {
  position: absolute;
  top: -8px;
  right: -8px;
  width: 20px;
  height: 20px;
  background: var(--achievement-success);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-size: 10px;
  border: 2px solid var(--achievement-bg-card);
}

.achievement-info {
  flex: 1;
  min-width: 0; /* For text truncation to work */
}

.achievement-title {
  font-size: 16px;
  font-weight: 600;
  margin: 0 0 8px 0;
  color: var(--achievement-text);
  display: -webkit-box;
  -webkit-line-clamp: 1;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.achievement-description {
  font-size: 14px;
  color: var(--achievement-text-secondary);
  margin: 0;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
  line-height: 1.4;
}

.achievement-details-toggle {
  background: none;
  border: none;
  color: var(--achievement-text-secondary);
  font-size: 16px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 5px;
  transition: color 0.2s;
}

.achievement-details-toggle:hover {
  color: var(--achievement-text);
}

.achievement-details {
  background: var(--achievement-input-bg);
  border-top: 1px solid var(--achievement-border);
  padding: 15px 20px;
}

.achievement-details-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
}

.achievement-details-icon {
  color: var(--achievement-accent);
  font-size: 16px;
}

.achievement-details-header h4 {
  font-size: 14px;
  margin: 0;
}

.achievement-details-info {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.achievement-details-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.achievement-details-label {
  font-size: 12px;
  color: var(--achievement-text-secondary);
}

.achievement-details-value {
  font-size: 12px;
  font-weight: 500;
}

.achievement-details-value.unlocked {
  color: var(--achievement-success);
}

.achievement-details-value.locked {
  color: var(--achievement-text-secondary);
}

.achievement-locked-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  z-index: 1;
}

.achievement-locked-icon {
  font-size: 24px;
  color: var(--achievement-text);
  margin-bottom: 5px;
}

/* =================== */
/* LOADING & EMPTY     */
/* =================== */

.achievement-loading,
.achievement-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  text-align: center;
  background: var(--achievement-bg-card);
  border-radius: 12px;
  border: 1px solid var(--achievement-border);
  box-shadow: var(--achievement-shadow);
  margin-top: 20px;
  gap: 15px;
}

.achievement-loading-icon,
.achievement-empty-icon {
  font-size: 40px;
  color: var(--achievement-accent);
  margin-bottom: 15px;
}

.achievement-loading-icon {
  animation: spin 2s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.achievement-loading p,
.achievement-empty p {
  font-size: 18px;
  color: var(--achievement-text-secondary);
  margin: 0;
}

.achievement-reset-btn {
  background: var(--achievement-accent);
  color: white;
  border: none;
  padding: 10px 20px;
  border-radius: 8px;
  font-family: inherit;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  margin-top: 15px;
  transition: background 0.2s;
}

.achievement-reset-btn:hover {
  background: var(--achievement-accent-glow);
}

/* =================== */
/* RESPONSIVE STYLES   */
/* =================== */

/* Tablet Styles */
@media (max-width: 992px) {
  .achievement-page-container {
    padding: 15px;
  }
  
  .achievement-header {
    padding: 20px;
    margin-bottom: 20px;
  }
  
  .achievement-header-titles h1 {
    font-size: 24px;
  }
  
  .achievement-header-titles p {
    font-size: 14px;
  }
  
  .achievement-grid {
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 15px;
  }
  
  .achievement-card-content {
    padding: 15px;
  }
  
  .achievement-category-btn {
    padding: 8px 15px;
    font-size: 13px;
  }
  
  .achievement-filter-btn {
    padding: 8px 12px;
    font-size: 13px;
  }
  
  .achievement-sort-dropdown select {
    padding: 8px 12px;
    font-size: 13px;
    min-width: 140px;
  }
  
  .achievement-filter-reset {
    width: 34px;
    height: 34px;
  }
}

/* Mobile Styles */
@media (max-width: 768px) {
  .achievement-page-container {
    padding: 10px;
  }
  
  .achievement-header {
    padding: 15px;
    margin-bottom: 15px;
  }
  
  .achievement-header-content {
    flex-direction: column;
  }
  
  .achievement-header-titles h1 {
    font-size: 22px;
    text-align: center;
  }
  
  .achievement-header-titles p {
    font-size: 13px;
    text-align: center;
  }
  
  .achievement-player-stats {
    width: 100%;
  }
  
  .achievement-grid {
    grid-template-columns: 1fr;
    gap: 15px;
  }
  
  .achievement-controls {
    margin-bottom: 20px;
  }
  
  .achievement-filter-options {
    flex-direction: column;
    align-items: stretch;
    width: 100%;
  }
  
  .achievement-sort-dropdown,
  .achievement-search {
    width: 100%;
  }
  
  .achievement-sort-dropdown select {
    width: 100%;
  }
  
  .achievement-filter-btn {
    justify-content: center;
  }
  
  .achievement-filter-reset {
    align-self: center;
  }
  
  .achievement-icon {
    width: 40px;
    height: 40px;
    font-size: 20px;
  }
  
  .achievement-title {
    font-size: 15px;
  }
  
  .achievement-description {
    font-size: 13px;
  }
}

/* Small Mobile Styles */
@media (max-width: 480px) {
  .achievement-header-titles h1 {
    font-size: 20px;
  }
  
  .achievement-header-titles p {
    font-size: 12px;
  }
  
  .achievement-stat-icon {
    font-size: 20px;
  }
  
  .achievement-stat-value {
    font-size: 16px;
  }
  
  .achievement-search-input {
    padding: 10px 35px 10px 35px;
    font-size: 13px;
  }
  
  .achievement-card-content {
    padding: 12px;
    gap: 12px;
  }
  
  .achievement-details {
    padding: 12px 15px;
  }
  
  .achievement-details-header h4 {
    font-size: 13px;
  }
  
  .achievement-details-label,
  .achievement-details-value {
    font-size: 11px;
  }
  
  .achievement-loading p,
  .achievement-empty p {
    font-size: 16px;
  }
}

/* iPhone SE and other small devices */
@media (max-width: 375px) {
  .achievement-header-titles h1 {
    font-size: 18px;
  }
  
  .achievement-player-name {
    font-size: 16px;
  }
  
  .achievement-stat-value {
    font-size: 14px;
  }
  
  .achievement-stat-label {
    font-size: 11px;
  }
  
  .achievement-category-btn {
    padding: 6px 12px;
    font-size: 12px;
  }
  
  .achievement-icon {
    width: 35px;
    height: 35px;
    font-size: 18px;
  }
  
  .achievement-title {
    font-size: 14px;
  }
  
  .achievement-description {
    font-size: 12px;
  }
}
export default AchievementPage;

aalso heres oem conext for what my revious designer has been doing ( provided an emaple of some of the pages teh designer did perviously, of he page it id which was teh userpofile, and shop page, it did other pages aswell but provided two examples
modern, gamified experience
# Comprehensive Project Summary: Gamified UI Component Redesign

## Design Approach Overview
We created a cohesive, modern, gamified UI design system for multiple components of your application, maintaining functionality while significantly enhancing visual appeal. The design follows a dark-themed, neon-accented gaming aesthetic with consistent styling across all components.

## Core Design Elements
- **Color Scheme**: Dark backgrounds (#0b0c15, #171a23) with purple/pink accent gradients
- **Typography**: 'Orbitron' font for headings, modern sans-serif for content
- **Visual Effects**: Subtle glows, shadows, hover animations, and micro-interactions
- **Layout**: Card-based designs with clear content hierarchy
- **Interactions**: Animated transitions, feedback indicators, and interactive elements

## Components Redesigned
1. **User Profile** - Complete redesign with tabbed interface, level display, and achievement showcases
2. **Daily Station** - Gamified daily rewards center with animations and clear countdowns
3. **Achievement Page** - Interactive achievement gallery with filtering capabilities
4. **Leaderboard** - Enhanced leaderboard with rank styling and optimized performance
5. **Shop Page** - Modern storefront with preview features and intuitive purchase flow
6. **Sidebar** - Refined navigation with better mobile experience and less intrusive toggle

## Technical Implementation
- Used CSS variables for consistency and maintainability
- Created responsive designs for all screen sizes including iPhone SE
- Organized class naming to avoid conflicts with other components
- Added performance optimizations for smoother animations
- Implemented accessibility improvements for better usability

## Component-Specific Enhancements

### User Profile
- Tabbed interface (Overview, Achievements, Items, Settings)
- XP progress visualization with level badge
- Modernized forms for username/email/password changes
- Organized display of achievements and purchased items

### Daily Station
- Countdown visualizations for bonus and questions
- Animated reward celebrations
- Redesigned question interface with better feedback
- Clear visual states for available/claimed rewards

### Achievement Gallery
- Filtering system by category and completion status
- Interactive cards with expandable details
- Progress tracking with completion percentage
- Search functionality and sorting options

### Leaderboard
- Special styling for top ranks (gold, silver, bronze)
- Optimized loading with skeleton placeholders
- Virtualized scrolling for better performance
- User search functionality

### Shop Page
- Tabbed navigation between item categories
- Avatar preview functionality
- Clear visual indicators for item requirements
- Enhanced purchase and equip flow

### Sidebar
- Improved toggle button to prevent content overlap
- Enhanced navigation with icons and better hover states
- Smoother animations for collapsible sections
- Maintained original logo and core functionality

## Implementation Approach
We created each component with:
1. A React component (JS/JSX) with proper state management
2. A corresponding CSS file with responsive styling
3. Attention to all screen sizes and device types
4. Performance considerations for animations and transitions


ok so the above text is what deisgned ravamping we are doing.

so nwo is the a really complciated page

so we haev 13 test categroies, so we have 13 test pages aswell. they all are gonan look and fucntion the same, however the tests are different obviolsy.

sicne they all look and fcuntion the same we have a globabltestpage that has all the global fucntions and design and stuff, aswell as a global test css.

so they each have their own unique testlist js file which is the saem fucntion and deisgn but it their won it defined teh category and what test categroy it is and stuff

and then they al have their wown "testpage" file even tho its absicaly just getting teh test category aswell

so the main revamp of design will be the compnents in the global testpage and their repsetive test lists. 
so we will do the revamping of design weve been doing to the testlist and then just copy the contnets to all teh toehr ones then edit the unique parts in it for each
and for the global test page i want to do the saem deisgn revamp weve been doing aswell inclduing teh review mode and testview


however a very veyr veyr important thing is we MUST NOT alter teh fucnionality of any components/fcuntions or features, we must maintain all features and fcuntionlity whiel doing this though becaue it took me a very very long time to make it all work. you may add features but cannot remove any or alter any (on how they actually fucntion).

ok so ill strat off with giving you the backedn routes just so you have some context, then ill give you the global test page, then ill give you one of teh testlist files, and alsofor context ill give you one of the unique "testpage" files.

so give me the testlist file first updated and ill verify its good, then give me the full entire global test page updated in when i tell you too, when i tell you too- DO NOT OMITT OR REMOVE ANY FUCNTIONALITY AND MAKE SURE TEH UPDATED FILE IS IN FULL

then after you give me the full entire global test page ill verify it adn ask for teh full test.css which encapuslates both testlist and globlatestpage compoenenst/design

ok here are teh files

starting with backedn routes fro conext, and il also give you my userslice file for context

# ================================
# test_routes.py
# ================================

from flask import Blueprint, request, jsonify, session, g  # <-- Added g here for DB time measurement
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import pytz
import time
from mongodb.database import db

# Mongo collections
from mongodb.database import (
    mainusers_collection,
    shop_collection,
    achievements_collection,
    tests_collection,
    testAttempts_collection,
    correctAnswers_collection,
    dailyQuestions_collection,
    dailyAnswers_collection
)

# Models
from models.test import (
    get_user_by_identifier,
    create_user,
    get_user_by_id,
    update_user_coins,
    update_user_xp,
    apply_daily_bonus,
    get_shop_items,
    purchase_item,
    get_achievements,
    get_test_by_id_and_category,
    validate_username,
    validate_email,
    validate_password,
    update_user_fields,
    get_user_by_id,
    award_correct_answers_in_bulk
)

api_bp = Blueprint('test', __name__)

#############################################
# Leaderboard Caching Setup (15-second TTL)
#############################################
leaderboard_cache = []
leaderboard_cache_timestamp = 0
LEADERBOARD_CACHE_DURATION_MS = 15000  # 15 seconds

def serialize_user(user):
    """Helper to convert _id, etc. to strings if needed."""
    if not user:
        return None
    user['_id'] = str(user['_id'])
    if 'currentAvatar' in user and user['currentAvatar']:
        user['currentAvatar'] = str(user['currentAvatar'])
    if 'purchasedItems' in user and isinstance(user['purchasedItems'], list):
        user['purchasedItems'] = [str(item) for item in user['purchasedItems']]
    return user

def serialize_datetime(dt):
    """Helper: convert a datetime to an ISO string (or return None)."""
    return dt.isoformat() if dt else None



def check_and_unlock_achievements(user_id):
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return []

    counters = user.get("achievement_counters", {})
    unlocked = set(user.get("achievements", []))
    newly_unlocked = []

    start_db = time.time()
    all_ach = list(achievements_collection.find({}))  # or get_achievements()
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    for ach in all_ach:
        aid = ach["achievementId"]
        # If already unlocked, skip
        if aid in unlocked:
            continue

        crit = ach.get("criteria", {})

        # 1) testCount => total_tests_completed
        test_count_req = crit.get("testCount")
        if test_count_req is not None:
            if counters.get("total_tests_completed", 0) >= test_count_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 2) minScore => e.g. "accuracy_king" with 90
        min_score_req = crit.get("minScore")
        if min_score_req is not None:
            if counters.get("highest_score_ever", 0) >= min_score_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 3) perfectTests => e.g. "perfectionist_1", "double_trouble_2", etc.
        perfect_req = crit.get("perfectTests")
        if perfect_req is not None:
            if counters.get("perfect_tests_count", 0) >= perfect_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 4) coins => coin achievements
        coin_req = crit.get("coins")
        if coin_req is not None:
            if user.get("coins", 0) >= coin_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 5) level => e.g. "level_up_5", "mid_tier_grinder_25", etc.
        level_req = crit.get("level")
        if level_req is not None:
            if user.get("level", 1) >= level_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 6) totalQuestions => e.g. "answer_machine_1000"
        total_q_req = crit.get("totalQuestions")
        if total_q_req is not None:
            if counters.get("total_questions_answered", 0) >= total_q_req:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 7) perfectTestsInCategory => "category_perfectionist"
        perfect_in_cat_req = crit.get("perfectTestsInCategory")
        if perfect_in_cat_req is not None:
            perfect_by_cat = counters.get("perfect_tests_by_category", {})
            for cat_name, cat_count in perfect_by_cat.items():
                if cat_count >= perfect_in_cat_req:
                    unlocked.add(aid)
                    newly_unlocked.append(aid)
                    break
            continue

        # 8) redemption_arc => minScoreBefore + minScoreAfter
        min_before = crit.get("minScoreBefore")
        min_after = crit.get("minScoreAfter")
        if min_before is not None and min_after is not None:
            if (counters.get("lowest_score_ever", 100) <= min_before and
                counters.get("highest_score_ever", 0) >= min_after):
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

        # 9) testsCompletedInCategory => "subject_finisher"
        cat_required = crit.get("testsCompletedInCategory")
        if cat_required is not None:
            tcbc = counters.get("tests_completed_by_category", {})
            for cat_name, test_set in tcbc.items():
                if len(test_set) >= cat_required:
                    unlocked.add(aid)
                    newly_unlocked.append(aid)
                    break
            continue

        # 10) allTestsCompleted => "test_finisher"
        if crit.get("allTestsCompleted"):
            user_completed_tests = counters.get("tests_completed_set", set())
            TOTAL_TESTS = 130
            if len(user_completed_tests) >= TOTAL_TESTS:
                unlocked.add(aid)
                newly_unlocked.append(aid)
                continue

    if newly_unlocked:
        start_db = time.time()
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"achievements": list(unlocked)}}
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    return newly_unlocked


# -------------------------------------------------------------------
# USER ROUTES
# -------------------------------------------------------------------
@api_bp.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404
    user = serialize_user(user)
    if "password" not in user:
        user["password"] = user.get("password")
    return jsonify(user), 200

@api_bp.route('/user', methods=['POST'])
def register_user():
    """
    Registration: /api/user
    Expects {username, email, password, confirmPassword} in JSON
    Calls create_user, returns {message, user_id} or error.
    """
    user_data = request.json or {}
    try:
        user_data.setdefault("achievement_counters", {
            "total_tests_completed": 0,
            "perfect_tests_count": 0,
            "perfect_tests_by_category": {},
            "highest_score_ever": 0.0,
            "lowest_score_ever": 100.0,
            "total_questions_answered": 0,
        })

        start_db = time.time()
        user_id = create_user(user_data)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"message": "User created", "user_id": str(user_id)}), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@api_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        start_db = time.time()
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": None,
            "ip": request.remote_addr or "unknown",
            "success": False,
            "reason": "No JSON data provided"
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"error": "No JSON data provided"}), 400

    identifier = data.get("usernameOrEmail")
    password = data.get("password")
    if not identifier or not password:
        start_db = time.time()
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": None,
            "ip": request.remote_addr or "unknown",
            "success": False,
            "reason": "Missing username/password"
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"error": "Username (or Email) and password are required"}), 400

    start_db = time.time()
    user = get_user_by_identifier(identifier)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user or user.get("password") != password:
        start_db = time.time()
        db.auditLogs.insert_one({
            "timestamp": datetime.utcnow(),
            "userId": None,
            "ip": request.remote_addr or "unknown",
            "success": False,
            "reason": "Invalid username or password"
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({"error": "Invalid username or password"}), 401

    session['userId'] = str(user["_id"])

    start_db = time.time()
    db.auditLogs.insert_one({
        "timestamp": datetime.utcnow(),
        "userId": user["_id"],
        "ip": request.remote_addr or "unknown",
        "success": True
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    user = serialize_user(user)

    return jsonify({
        "user_id": user["_id"],
        "username": user["username"],
        "email": user.get("email", ""),
        "coins": user.get("coins", 0),
        "xp": user.get("xp", 0),
        "level": user.get("level", 1),
        "achievements": user.get("achievements", []),
        "xpBoost": user.get("xpBoost", 1.0),
        "currentAvatar": user.get("currentAvatar"),
        "nameColor": user.get("nameColor"),
        "purchasedItems": user.get("purchasedItems", []),
        "subscriptionActive": user.get("subscriptionActive", False),
        "password": user.get("password")
    }), 200

@api_bp.route('/user/<user_id>/add-xp', methods=['POST'])
def add_xp_route(user_id):
    data = request.json or {}
    xp_to_add = data.get("xp", 0)

    start_db = time.time()
    updated = update_user_xp(user_id, xp_to_add)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not updated:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    new_achievements = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    updated["newAchievements"] = new_achievements
    return jsonify(updated), 200

@api_bp.route('/user/<user_id>/add-coins', methods=['POST'])
def add_coins_route(user_id):
    data = request.json or {}
    coins_to_add = data.get("coins", 0)

    start_db = time.time()
    update_user_coins(user_id, coins_to_add)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    newly_unlocked = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({
        "message": "Coins updated",
        "newlyUnlocked": newly_unlocked
    }), 200

# -------------------------------------------------------------------
# SHOP ROUTES
# -------------------------------------------------------------------
@api_bp.route('/shop', methods=['GET'])
def fetch_shop():
    start_db = time.time()
    items = get_shop_items()
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    for item in items:
        item["_id"] = str(item["_id"])
    return jsonify(items), 200

@api_bp.route('/shop/purchase/<item_id>', methods=['POST'])
def purchase_item_route(item_id):
    data = request.json or {}
    user_id = data.get("userId")
    if not user_id:
        return jsonify({"success": False, "message": "userId is required"}), 400

    start_db = time.time()
    result = purchase_item(user_id, item_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if result["success"]:
        start_db = time.time()
        newly_unlocked = check_and_unlock_achievements(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        result["newly_unlocked"] = newly_unlocked
        return jsonify(result), 200
    else:
        return jsonify(result), 400

@api_bp.route('/shop/equip', methods=['POST'])
def equip_item_route():
    data = request.json or {}
    user_id = data.get("userId")
    item_id = data.get("itemId")

    if not user_id or not item_id:
        return jsonify({"success": False, "message": "userId and itemId are required"}), 400

    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    try:
        oid = ObjectId(item_id)
    except Exception:
        return jsonify({"success": False, "message": "Invalid item ID"}), 400

    start_db = time.time()
    item_doc = shop_collection.find_one({"_id": oid})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not item_doc:
        return jsonify({"success": False, "message": "Item not found in shop"}), 404

    if oid not in user.get("purchasedItems", []):
        if user.get("level", 1) < item_doc.get("unlockLevel", 1):
            return jsonify({"success": False, "message": "Item not unlocked"}), 400

    start_db = time.time()
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"currentAvatar": oid}}
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"success": True, "message": "Avatar equipped"}), 200

# -------------------------------------------------------------------
# TESTS ROUTES
# -------------------------------------------------------------------
@api_bp.route('/tests/<test_id>', methods=['GET'])
def fetch_test_by_id_route(test_id):
    start_db = time.time()
    test_doc = get_test_by_id_and_category(test_id, None)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not test_doc:
        return jsonify({"error": "Test not found"}), 404
    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200

@api_bp.route('/tests/<category>/<test_id>', methods=['GET'])
def fetch_test_by_category_and_id(category, test_id):
    try:
        test_id_int = int(test_id)
    except Exception:
        return jsonify({"error": "Invalid test ID"}), 400

    start_db = time.time()
    test_doc = tests_collection.find_one({
        "testId": test_id_int,
        "category": category
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not test_doc:
        return jsonify({"error": "Test not found"}), 404

    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200

# -------------------------------------------------------------------
# PROGRESS / ATTEMPTS ROUTES
# -------------------------------------------------------------------
@api_bp.route('/attempts/<user_id>/<test_id>', methods=['GET'])
def get_test_attempt(user_id, test_id):
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = None
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    query = {"userId": user_oid, "finished": False}
    if test_id_int is not None:
        query["$or"] = [{"testId": test_id_int}, {"testId": test_id}]
    else:
        query["testId"] = test_id

    start_db = time.time()
    attempt = testAttempts_collection.find_one(query)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt:
        query_finished = {"userId": user_oid, "finished": True}
        if test_id_int is not None:
            query_finished["$or"] = [{"testId": test_id_int}, {"testId": test_id}]
        else:
            query_finished["testId"] = test_id

        start_db = time.time()
        attempt = testAttempts_collection.find_one(query_finished, sort=[("finishedAt", -1)])
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    if not attempt:
        return jsonify({"attempt": None}), 200

    attempt["_id"] = str(attempt["_id"])
    attempt["userId"] = str(attempt["userId"])
    return jsonify({"attempt": attempt}), 200

@api_bp.route('/attempts/<user_id>/<test_id>', methods=['POST'])
def update_test_attempt(user_id, test_id):
    data = request.json or {}
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    exam_mode_val = data.get("examMode", False)
    selected_length = data.get("selectedLength", data.get("totalQuestions", 0))

    filter_ = {
        "userId": user_oid,
        "$or": [{"testId": test_id_int}, {"testId": test_id}]
    }
    update_doc = {
        "$set": {
            "userId": user_oid,
            "testId": test_id_int if isinstance(test_id_int, int) else test_id,
            "category": data.get("category", "global"),
            "answers": data.get("answers", []),
            "score": data.get("score", 0),
            "totalQuestions": data.get("totalQuestions", 0),
            "selectedLength": selected_length,
            "currentQuestionIndex": data.get("currentQuestionIndex", 0),
            "shuffleOrder": data.get("shuffleOrder", []),
            "answerOrder": data.get("answerOrder", []),
            "finished": data.get("finished", False),
            "examMode": exam_mode_val
        }
    }
    if update_doc["$set"]["finished"] is True:
        update_doc["$set"]["finishedAt"] = datetime.utcnow()

    start_db = time.time()
    testAttempts_collection.update_one(filter_, update_doc, upsert=True)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({
        "message": "Progress updated (examMode=%s, selectedLength=%s)" % (exam_mode_val, selected_length)
    }), 200

@api_bp.route('/attempts/<user_id>/<test_id>/finish', methods=['POST'])
def finish_test_attempt(user_id, test_id):
    data = request.json or {}
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    filter_ = {
        "userId": user_oid,
        "finished": False,
        "$or": [{"testId": test_id_int}, {"testId": test_id}]
    }
    update_doc = {
        "$set": {
            "finished": True,
            "finishedAt": datetime.utcnow(),
            "score": data.get("score", 0),
            "totalQuestions": data.get("totalQuestions", 0)
        }
    }

    start_db = time.time()
    testAttempts_collection.update_one(filter_, update_doc)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    attempt_doc = testAttempts_collection.find_one({
        "userId": user_oid,
        "$or": [{"testId": test_id_int}, {"testId": test_id}],
        "finished": True
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt_doc:
        return jsonify({"error": "Attempt not found after finishing."}), 404

    exam_mode = attempt_doc.get("examMode", False)
    selected_length = attempt_doc.get("selectedLength", attempt_doc.get("totalQuestions", 0))
    score = attempt_doc.get("score", 0)
    total_questions = attempt_doc.get("totalQuestions", 0)
    category = attempt_doc.get("category", "global")

    if exam_mode:
        start_db = time.time()
        award_correct_answers_in_bulk(
            user_id=user_id,
            attempt_doc=attempt_doc,
            xp_per_correct=10,
            coins_per_correct=5
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404

    counters = user.get("achievement_counters", {})
    percentage = 0
    if total_questions > 0:
        percentage = (score / total_questions) * 100

    update_ops = {"$inc": {"achievement_counters.total_tests_completed": 1}}

    if score == total_questions and total_questions > 0 and selected_length == 100:
        update_ops["$inc"]["achievement_counters.perfect_tests_count"] = 1
        catKey = f"achievement_counters.perfect_tests_by_category.{category}"
        update_ops["$inc"][catKey] = 1

    if selected_length == 100:
        highest_so_far = counters.get("highest_score_ever", 0.0)
        lowest_so_far = counters.get("lowest_score_ever", 100.0)
        set_ops = {}
        if percentage > highest_so_far:
            set_ops["achievement_counters.highest_score_ever"] = percentage
        if percentage < lowest_so_far:
            set_ops["achievement_counters.lowest_score_ever"] = percentage
        if set_ops:
            update_ops.setdefault("$set", {}).update(set_ops)

    update_ops["$inc"]["achievement_counters.total_questions_answered"] = selected_length

    start_db = time.time()
    mainusers_collection.update_one({"_id": user_oid}, update_ops)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    newly_unlocked = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    updated_user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({
        "message": "Test attempt finished",
        "examMode": exam_mode,
        "selectedLength": selected_length,
        "newlyUnlocked": newly_unlocked,
        "newXP": updated_user.get("xp", 0),
        "newCoins": updated_user.get("coins", 0)
    }), 200

@api_bp.route('/attempts/<user_id>/list', methods=['GET'])
def list_test_attempts(user_id):
    try:
        user_oid = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user ID"}), 400

    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=50, type=int)
    skip_count = (page - 1) * page_size

    start_db = time.time()
    cursor = testAttempts_collection.find(
        {"userId": user_oid}
    ).sort("finishedAt", -1).skip(skip_count).limit(page_size)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    attempts = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        doc["userId"] = str(doc["userId"])
        attempts.append(doc)

    return jsonify({
        "page": page,
        "page_size": page_size,
        "attempts": attempts
    }), 200

# -------------------------------------------------------------------
# FIRST-TIME-CORRECT ANSWERS
# -------------------------------------------------------------------
@api_bp.route('/user/<user_id>/submit-answer', methods=['POST'])
def submit_answer(user_id):
    data = request.json or {}
    test_id = str(data.get("testId"))
    question_id = data.get("questionId")
    selected_index = data.get("selectedIndex")
    correct_index = data.get("correctAnswerIndex")
    xp_per_correct = data.get("xpPerCorrect", 10)
    coins_per_correct = data.get("coinsPerCorrect", 5)

    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    attempt_doc = testAttempts_collection.find_one({
        "userId": user["_id"],
        "finished": False,
        "$or": [
            {"testId": int(test_id)} if test_id.isdigit() else {"testId": test_id},
            {"testId": test_id}
        ]
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt_doc:
        return jsonify({"error": "No unfinished attempt doc found"}), 404

    exam_mode = attempt_doc.get("examMode", False)
    is_correct = (selected_index == correct_index)

    existing_answer_index = None
    for i, ans in enumerate(attempt_doc.get("answers", [])):
        if ans.get("questionId") == question_id:
            existing_answer_index = i
            break

    new_score = attempt_doc.get("score", 0)
    if existing_answer_index is not None:
        update_payload = {
            "answers.$.userAnswerIndex": selected_index,
            "answers.$.correctAnswerIndex": correct_index
        }
        if exam_mode is False and is_correct:
            new_score += 1
            update_payload["score"] = new_score

        start_db = time.time()
        testAttempts_collection.update_one(
            {
                "_id": attempt_doc["_id"],
                "answers.questionId": question_id
            },
            {"$set": update_payload}
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    else:
        new_answer_doc = {
            "questionId": question_id,
            "userAnswerIndex": selected_index,
            "correctAnswerIndex": correct_index
        }
        if exam_mode is False and is_correct:
            new_score += 1
        push_update = {"$push": {"answers": new_answer_doc}}
        if exam_mode is False and is_correct:
            push_update["$set"] = {"score": new_score}

        start_db = time.time()
        testAttempts_collection.update_one(
            {"_id": attempt_doc["_id"]},
            push_update
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    awarded_xp = 0
    awarded_coins = 0
    if exam_mode is False:
        start_db = time.time()
        already_correct = correctAnswers_collection.find_one({
            "userId": user["_id"],
            "testId": test_id,
            "questionId": question_id
        })
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        if is_correct and not already_correct:
            start_db = time.time()
            correctAnswers_collection.insert_one({
                "userId": user["_id"],
                "testId": test_id,
                "questionId": question_id
            })
            duration = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration

            start_db = time.time()
            update_user_xp(user_id, xp_per_correct)
            duration2 = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration2

            start_db = time.time()
            update_user_coins(user_id, coins_per_correct)
            duration3 = time.time() - start_db
            if not hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator = 0.0
            g.db_time_accumulator += duration3

            awarded_xp = xp_per_correct
            awarded_coins = coins_per_correct

        start_db = time.time()
        updated_user = get_user_by_id(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({
            "examMode": False,
            "isCorrect": is_correct,
            "alreadyCorrect": bool(already_correct),
            "awardedXP": awarded_xp,
            "awardedCoins": awarded_coins,
            "newXP": updated_user.get("xp", 0),
            "newCoins": updated_user.get("coins", 0)
        }), 200
    else:
        return jsonify({
            "examMode": True,
            "message": "Answer stored. No immediate feedback in exam mode."
        }), 200

# -------------------------------------------------------------------
# ACHIEVEMENTS
# -------------------------------------------------------------------
@api_bp.route('/achievements', methods=['GET'])
def fetch_achievements_route():
    start_db = time.time()
    ach_list = list(achievements_collection.find({}))
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    for ach in ach_list:
        ach["_id"] = str(ach["_id"])
    return jsonify(ach_list), 200

# -------------------------------------------------------------------
# Leaderboard Route with Lazy Loading & Pagination
# -------------------------------------------------------------------
@api_bp.route('/leaderboard', methods=['GET'])
def get_leaderboard():
    global leaderboard_cache
    global leaderboard_cache_timestamp

    now_ms = int(time.time() * 1000)
    if now_ms - leaderboard_cache_timestamp > LEADERBOARD_CACHE_DURATION_MS:
        start_db = time.time()
        cursor = mainusers_collection.find(
            {},
            {"username": 1, "level": 1, "xp": 1, "currentAvatar": 1}
        ).sort("level", -1).limit(1000)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        new_results = []
        rank = 1
        for user in cursor:
            user_data = {
                "username": user.get("username", "unknown"),
                "level": user.get("level", 1),
                "xp": user.get("xp", 0),
                "rank": rank,
                "avatarUrl": None
            }
            if user.get("currentAvatar"):
                start_db = time.time()
                avatar_item = shop_collection.find_one({"_id": user["currentAvatar"]})
                duration = time.time() - start_db
                if not hasattr(g, 'db_time_accumulator'):
                    g.db_time_accumulator = 0.0
                g.db_time_accumulator += duration

                if avatar_item and "imageUrl" in avatar_item:
                    user_data["avatarUrl"] = avatar_item["imageUrl"]
            new_results.append(user_data)
            rank += 1

        leaderboard_cache = new_results
        leaderboard_cache_timestamp = now_ms

    try:
        skip = int(request.args.get("skip", 0))
        limit = int(request.args.get("limit", 50))
    except:
        skip, limit = 0, 50

    total_entries = len(leaderboard_cache)
    end_index = skip + limit
    if skip > total_entries:
        sliced_data = []
    else:
        sliced_data = leaderboard_cache[skip:end_index]

    return jsonify({
        "data": sliced_data,
        "total": total_entries
    }), 200

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# USERNAME/EMAIL/PASSWORD CHANGES
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
@api_bp.route('/user/change-username', methods=['POST'])
def change_username():
    data = request.json or {}
    user_id = data.get("userId")
    new_username = data.get("newUsername")
    if not user_id or not new_username:
        return jsonify({"error": "Missing userId or newUsername"}), 400

    valid, errors = validate_username(new_username)
    if not valid:
        return jsonify({"error": "Invalid new username", "details": errors}), 400

    start_db = time.time()
    existing = mainusers_collection.find_one({"username": new_username})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if existing:
        return jsonify({"error": "Username already taken"}), 400

    start_db = time.time()
    doc = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not doc:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    update_user_fields(user_id, {"username": new_username})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"message": "Username updated"}), 200

@api_bp.route('/user/change-email', methods=['POST'])
def change_email():
    data = request.json or {}
    user_id = data.get("userId")
    new_email = data.get("newEmail")
    if not user_id or not new_email:
        return jsonify({"error": "Missing userId or newEmail"}), 400

    valid, errors = validate_email(new_email)
    if not valid:
        return jsonify({"error": "Invalid email", "details": errors}), 400

    start_db = time.time()
    existing = mainusers_collection.find_one({"email": new_email})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if existing:
        return jsonify({"error": "Email already in use"}), 400

    start_db = time.time()
    doc = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not doc:
        return jsonify({"error": "User not found"}), 404

    start_db = time.time()
    update_user_fields(user_id, {"email": new_email})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"message": "Email updated"}), 200

@api_bp.route('/user/change-password', methods=['POST'])
def change_password():
    data = request.json or {}
    user_id = data.get("userId")
    old_password = data.get("oldPassword")
    new_password = data.get("newPassword")
    confirm = data.get("confirmPassword")

    if not user_id or not old_password or not new_password or not confirm:
        return jsonify({"error": "All fields are required"}), 400
    if new_password != confirm:
        return jsonify({"error": "New passwords do not match"}), 400

    valid, errors = validate_password(new_password)
    if not valid:
        return jsonify({"error": "Invalid new password", "details": errors}), 400

    start_db = time.time()
    user_doc = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user_doc:
        return jsonify({"error": "User not found"}), 404

    if user_doc.get("password") != old_password:
        return jsonify({"error": "Old password is incorrect"}), 401

    start_db = time.time()
    update_user_fields(user_id, {"password": new_password})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"message": "Password updated"}), 200

@api_bp.route('/subscription/cancel', methods=['POST'])
def cancel_subscription():
    return jsonify({"message": "Cancel subscription placeholder"}), 200

# For single answer updates
@api_bp.route('/attempts/<user_id>/<test_id>/answer', methods=['POST'])
def update_single_answer(user_id, test_id):
    data = request.json or {}
    question_id = data.get("questionId")
    user_answer_index = data.get("userAnswerIndex")
    correct_answer_index = data.get("correctAnswerIndex")

    try:
        user_oid = ObjectId(user_id)
        test_id_int = int(test_id) if test_id.isdigit() else test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    start_db = time.time()
    attempt = testAttempts_collection.find_one({
        "userId": user_oid,
        "finished": False,
        "$or": [{"testId": test_id_int}, {"testId": test_id}]
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not attempt:
        return jsonify({"error": "Attempt not found"}), 404

    existing_answer_index = None
    for i, ans in enumerate(attempt.get("answers", [])):
        if ans.get("questionId") == question_id:
            existing_answer_index = i
            break

    if existing_answer_index is not None:
        start_db = time.time()
        testAttempts_collection.update_one(
            {
                "userId": user_oid,
                "finished": False,
                "$or": [{"testId": test_id_int}, {"testId": test_id}],
                "answers.questionId": question_id
            },
            {"$set": {
                "answers.$.userAnswerIndex": user_answer_index,
                "answers.$.correctAnswerIndex": correct_answer_index,
                "score": data.get("score", 0)
            }}
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    else:
        start_db = time.time()
        testAttempts_collection.update_one(
            {
                "userId": user_oid,
                "finished": False,
                "$or": [{"testId": test_id_int}, {"testId": test_id}]
            },
            {
                "$push": {
                    "answers": {
                        "questionId": question_id,
                        "userAnswerIndex": user_answer_index,
                        "correctAnswerIndex": correct_answer_index
                    }
                },
                "$set": {"score": data.get("score", 0)}
            }
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

    return jsonify({"message": "Answer updated"}), 200

# For updating the current question position only
@api_bp.route('/attempts/<user_id>/<test_id>/position', methods=['POST'])
def update_position(user_id, test_id):
    data = request.json or {}
    current_index = data.get("currentQuestionIndex", 0)

    try:
        user_oid = ObjectId(user_id)
        test_id_int = int(test_id) if test_id.isdigit() else test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    start_db = time.time()
    testAttempts_collection.update_one(
        {
            "userId": user_oid,
            "finished": False,
            "$or": [{"testId": test_id_int}, {"testId": test_id}]
        },
        {"$set": {
            "currentQuestionIndex": current_index,
            "finished": data.get("finished", False)
        }}
    )
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({"message": "Position updated"}), 200

##############################################
# DAILY QUESTION ENDPOINTS
##############################################
@api_bp.route('/user/<user_id>/daily-bonus', methods=['POST'])
def daily_bonus(user_id):
    user = None
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404

    now = datetime.utcnow()
    last_claim = user.get("lastDailyClaim")
    if last_claim and (now - last_claim) < timedelta(hours=24):
        seconds_left = int(24 * 3600 - (now - last_claim).total_seconds())
        return jsonify({
            "success": False,
            "message": f"Already claimed. Next bonus in: {seconds_left} seconds",
            "newCoins": user.get("coins", 0),
            "newXP": user.get("xp", 0),
            "newLastDailyClaim": serialize_datetime(last_claim)
        }), 200
    else:
        start_db = time.time()
        update_user_coins(user_id, 1000)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        start_db = time.time()
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"lastDailyClaim": now}}
        )
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        start_db = time.time()
        updated_user = get_user_by_id(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        start_db = time.time()
        newly_unlocked = check_and_unlock_achievements(user_id)
        duration = time.time() - start_db
        if not hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator = 0.0
        g.db_time_accumulator += duration

        return jsonify({
            "success": True,
            "message": "Daily bonus applied",
            "newCoins": updated_user.get("coins", 0),
            "newXP": updated_user.get("xp", 0),
            "newLastDailyClaim": serialize_datetime(updated_user.get("lastDailyClaim")),
            "newlyUnlocked": newly_unlocked
        }), 200

@api_bp.route('/daily-question', methods=['GET'])
def get_daily_question():
    user_id = request.args.get("userId")
    if not user_id:
        return jsonify({"error": "No userId provided"}), 400

    try:
        user_oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    day_index = 0

    start_db = time.time()
    daily_doc = dailyQuestions_collection.find_one({"dayIndex": day_index})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not daily_doc:
        return jsonify({"error": f"No daily question for dayIndex={day_index}"}), 404

    start_db = time.time()
    existing_answer = dailyAnswers_collection.find_one({
        "userId": user_oid,
        "dayIndex": day_index
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    response = {
        "dayIndex": day_index,
        "prompt": daily_doc.get("prompt"),
        "options": daily_doc.get("options"),
        "alreadyAnswered": bool(existing_answer)
    }
    return jsonify(response), 200

@api_bp.route('/daily-question/answer', methods=['POST'])
def submit_daily_question():
    data = request.json or {}
    user_id = data.get("userId")
    day_index = data.get("dayIndex")
    selected_index = data.get("selectedIndex")

    if not user_id or day_index is None or selected_index is None:
        return jsonify({"error": "Missing userId, dayIndex, or selectedIndex"}), 400

    try:
        user_oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    start_db = time.time()
    daily_doc = dailyQuestions_collection.find_one({"dayIndex": day_index})
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if not daily_doc:
        return jsonify({"error": f"No daily question for dayIndex={day_index}"}), 404

    start_db = time.time()
    existing = dailyAnswers_collection.find_one({
        "userId": user_oid,
        "dayIndex": day_index
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    if existing:
        return jsonify({"error": "You already answered today's question"}), 400

    correct_index = daily_doc.get("correctIndex", 0)
    is_correct = (selected_index == correct_index)
    awarded_coins = 250 if is_correct else 50

    start_db = time.time()
    dailyAnswers_collection.insert_one({
        "userId": user_oid,
        "dayIndex": day_index,
        "answeredAt": datetime.utcnow(),
        "userAnswerIndex": selected_index,
        "isCorrect": is_correct
    })
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    update_user_coins(str(user_oid), awarded_coins)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    updated_user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    start_db = time.time()
    newly_unlocked = check_and_unlock_achievements(user_id)
    duration = time.time() - start_db
    if not hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator = 0.0
    g.db_time_accumulator += duration

    return jsonify({
        "message": "Answer submitted",
        "correct": is_correct,
        "awardedCoins": awarded_coins,
        "newCoins": updated_user.get("coins", 0),
        "newXP": updated_user.get("xp", 0),
        "newLastDailyClaim": serialize_datetime(updated_user.get("lastDailyClaim")),
        "newlyUnlocked": newly_unlocked
    }), 200

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { showAchievementToast } from './AchievementToast';
import {
  FaTrophy, FaMedal, FaStar, FaCrown, FaBolt, FaBook, FaBrain,
  FaCheckCircle, FaRegSmile, FaMagic
} from 'react-icons/fa';

// Import the thunks to fetch achievements and shop items
import { fetchAchievements } from './achievementsSlice';
import { fetchShopItems } from './shopSlice';

// Updated icon mapping: removed memory_master, category_perfectionist, subject_specialist,
// subject_finisher, absolute_perfectionist, exam_conqueror. Keep only those we still have:
const iconMapping = {
  test_rookie: FaTrophy,
  accuracy_king: FaMedal,
  bronze_grinder: FaBook,
  silver_scholar: FaStar,
  gold_god: FaCrown,
  platinum_pro: FaMagic,
  walking_encyclopedia: FaBrain,
  redemption_arc: FaBolt,
  coin_collector_5000: FaBook,
  coin_hoarder_10000: FaBook,
  coin_tycoon_50000: FaBook,
  perfectionist_1: FaCheckCircle,
  double_trouble_2: FaCheckCircle,
  error404_failure_not_found: FaCheckCircle,
  level_up_5: FaTrophy,
  mid_tier_grinder_25: FaMedal,
  elite_scholar_50: FaStar,
  ultimate_master_100: FaCrown,
  answer_machine_1000: FaBook,
  knowledge_beast_5000: FaBrain,
  question_terminator: FaBrain,
  test_finisher: FaCheckCircle
};

// Matching color mapping (remove same IDs):
const colorMapping = {
  test_rookie: "#ff5555",
  accuracy_king: "#ffa500",
  bronze_grinder: "#cd7f32",
  silver_scholar: "#c0c0c0",
  gold_god: "#ffd700",
  platinum_pro: "#e5e4e2",
  walking_encyclopedia: "#00fa9a",
  redemption_arc: "#ff4500",
  coin_collector_5000: "#ff69b4",
  coin_hoarder_10000: "#ff1493",
  coin_tycoon_50000: "#ff0000",
  perfectionist_1: "#adff2f",
  double_trouble_2: "#7fff00",
  error404_failure_not_found: "#00ffff",
  level_up_5: "#f08080",
  mid_tier_grinder_25: "#ff8c00",
  elite_scholar_50: "#ffd700",
  ultimate_master_100: "#ff4500",
  answer_machine_1000: "#ff69b4",
  knowledge_beast_5000: "#00fa9a",
  question_terminator: "#ff1493",
  test_finisher: "#adff2f"
};

// Utility function to show toast for newlyUnlocked achievements:
function showNewlyUnlockedAchievements(newlyUnlocked, allAchievements) {
  if (!newlyUnlocked || newlyUnlocked.length === 0) return;
  newlyUnlocked.forEach((achId) => {
    const Icon = iconMapping[achId] ? iconMapping[achId] : FaTrophy;
    const color = colorMapping[achId] || "#fff";

    const foundAch = allAchievements?.find(a => a.achievementId === achId);
    const title = foundAch?.title || `Unlocked ${achId}`;
    const desc = foundAch?.description || 'Achievement Unlocked!';

    showAchievementToast({
      title,
      description: desc,
      icon: Icon ? <Icon /> : null,
      color
    });
  });
}

const initialUserId = localStorage.getItem('userId');

const initialState = {
  userId: initialUserId ? initialUserId : null,
  username: '',
  email: '',
  xp: 0,
  level: 1,
  coins: 0,
  achievements: [],
  xpBoost: 1.0,
  currentAvatar: null,
  nameColor: null,
  purchasedItems: [],
  subscriptionActive: false,

  status: 'idle',
  loading: false,
  error: null,
};

// REGISTER
export const registerUser = createAsyncThunk(
  'user/registerUser',
  async (formData, { rejectWithValue, dispatch, getState }) => {
    try {
      const response = await fetch('/api/test/user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Registration failed');
      }
      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// LOGIN
export const loginUser = createAsyncThunk(
  'user/loginUser',
  async (credentials, { rejectWithValue, dispatch, getState }) => {
    try {
      const response = await fetch('/api/test/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }
      // Immediately fetch achievements + shop data after successful login
      dispatch(fetchAchievements());
      dispatch(fetchShopItems());

      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// FETCH USER DATA
export const fetchUserData = createAsyncThunk(
  'user/fetchUserData',
  async (userId, { rejectWithValue, dispatch }) => {
    try {
      const response = await fetch(`/api/test/user/${userId}`);
      if (!response.ok) {
        throw new Error('Failed to fetch user data');
      }
      const data = await response.json();

      // Also fetch achievements + shop items to ensure they're loaded
      dispatch(fetchAchievements());
      dispatch(fetchShopItems());

      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Example of a daily bonus thunk:
export const claimDailyBonus = createAsyncThunk(
  'user/claimDailyBonus',
  async (userId, { rejectWithValue, dispatch, getState }) => {
    try {
      const response = await fetch(`/api/test/user/${userId}/daily-bonus`, {
        method: 'POST'
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || data.error || 'Daily bonus error');
      }
      // If new achievements came back, display them
      if (data.newlyUnlocked && data.newlyUnlocked.length > 0) {
        const allAchs = getState().achievements.all;
        showNewlyUnlockedAchievements(data.newlyUnlocked, allAchs);
      }
      return data; 
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// If you have an "addCoins" route, likewise
export const addCoins = createAsyncThunk(
  'user/addCoins',
  async ({ userId, amount }, { rejectWithValue, dispatch, getState }) => {
    try {
      const res = await fetch(`/api/test/user/${userId}/add-coins`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ coins: amount })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to add coins');
      }
      // Show newly unlocked achievements
      if (data.newlyUnlocked && data.newlyUnlocked.length > 0) {
        const allAchs = getState().achievements.all;
        showNewlyUnlockedAchievements(data.newlyUnlocked, allAchs);
      }
      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

const userSlice = createSlice({
  name: 'user',
  initialState,
  reducers: {
    setCurrentUserId(state, action) {
      state.userId = action.payload;
    },
    logout(state) {
      state.userId = null;
      state.username = '';
      state.email = '';
      state.xp = 0;
      state.level = 1;
      state.coins = 0;
      state.achievements = [];
      state.xpBoost = 1.0;
      state.currentAvatar = null;
      state.nameColor = null;
      state.purchasedItems = [];
      state.subscriptionActive = false;
      state.status = 'idle';
      localStorage.removeItem('userId');
    },
    setXPAndCoins(state, action) {
      const { xp, coins } = action.payload;
      state.xp = xp;
      state.coins = coins;
    }
  },
  extraReducers: (builder) => {
    builder
      // REGISTER
      .addCase(registerUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(registerUser.fulfilled, (state) => {
        state.loading = false;
        state.error = null;
      })
      .addCase(registerUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // LOGIN
      .addCase(loginUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loginUser.fulfilled, (state, action) => {
        state.loading = false;
        state.error = null;

        const {
          user_id,
          username,
          email,
          coins,
          xp,
          level,
          achievements,
          xpBoost,
          currentAvatar,
          nameColor,
          purchasedItems,
          subscriptionActive,
          password
        } = action.payload;

        state.userId = user_id;
        state.username = username;
        state.email = email || '';
        state.coins = coins || 0;
        state.xp = xp || 0;
        state.level = level || 1;
        state.achievements = achievements || [];
        state.xpBoost = xpBoost !== undefined ? xpBoost : 1.0;
        state.currentAvatar = currentAvatar || null;
        state.nameColor = nameColor || null;
        state.purchasedItems = purchasedItems || [];
        state.subscriptionActive = subscriptionActive || false;

        localStorage.setItem('userId', user_id);
      })
      .addCase(loginUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // FETCH USER DATA
      .addCase(fetchUserData.pending, (state) => {
        state.status = 'loading';
      })
      .addCase(fetchUserData.fulfilled, (state, action) => {
        state.status = 'succeeded';
        state.error = null;
        const userDoc = action.payload;

        state.userId = userDoc._id;
        state.username = userDoc.username;
        state.email = userDoc.email || '';
        state.xp = userDoc.xp || 0;
        state.level = userDoc.level || 1;
        state.coins = userDoc.coins || 0;
        state.achievements = userDoc.achievements || [];
        state.xpBoost = userDoc.xpBoost !== undefined ? userDoc.xpBoost : 1.0;
        state.currentAvatar = userDoc.currentAvatar || null;
        state.nameColor = userDoc.nameColor || null;
        state.purchasedItems = userDoc.purchasedItems || [];
        state.subscriptionActive = userDoc.subscriptionActive || false;
      })
      .addCase(fetchUserData.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      })

      // DAILY BONUS
      .addCase(claimDailyBonus.pending, (state) => {
        state.loading = true;
      })
      .addCase(claimDailyBonus.fulfilled, (state, action) => {
        state.loading = false;
        // Update local user coins/xp if success
        if (action.payload.success) {
          state.coins = action.payload.newCoins;
          state.xp = action.payload.newXP;
        }
      })
      .addCase(claimDailyBonus.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // ADD COINS
      .addCase(addCoins.fulfilled, (state, action) => {
        // If route succeeded, you could do local updates here or re-fetch user
        // For example:
        // state.coins += ...
      });
  },
});

export const { setCurrentUserId, logout, setXPAndCoins } = userSlice.actions;
export default userSlice.reducer;


import React, {
  useState,
  useEffect,
  useCallback,
  useMemo,
  useRef
} from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useSelector, useDispatch } from "react-redux";
import { setXPAndCoins } from "./pages/store/userSlice";
import { fetchShopItems } from "./pages/store/shopSlice";
import ConfettiAnimation from "./ConfettiAnimation";
import { showAchievementToast } from "./pages/store/AchievementToast";
import "./test.css";
import iconMapping from "./iconMapping";
import colorMapping from "./colorMapping";
import {
  FaTrophy,
  FaMedal,
  FaStar,
  FaCrown,
  FaBolt,
  FaBook,
  FaBrain,
  FaCheckCircle,
  FaRegSmile,
  FaMagic
} from "react-icons/fa";

// Helper functions
function shuffleArray(arr) {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

function shuffleIndices(length) {
  const indices = Array.from({ length }, (_, i) => i);
  return shuffleArray(indices);
}

// Reusable QuestionDropdown component
const QuestionDropdown = ({
  totalQuestions,
  currentQuestionIndex,
  onQuestionSelect,
  answers,
  flaggedQuestions,
  testData,
  shuffleOrder,
  examMode
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const getQuestionStatus = (index) => {
    const realIndex = shuffleOrder[index];
    const question = testData.questions[realIndex];
    const answer = answers.find((a) => a.questionId === question.id);
    const isFlagged = flaggedQuestions.includes(question.id);
    const isAnswered = answer?.userAnswerIndex !== undefined;
    const isSkipped = answer?.userAnswerIndex === null;
    const isCorrect =
      answer && answer.userAnswerIndex === question.correctAnswerIndex;
    return { isAnswered, isSkipped, isCorrect, isFlagged };
  };

  return (
    <div className="question-dropdown" ref={dropdownRef}>
      <button onClick={() => setIsOpen(!isOpen)} className="dropdown-button">
        Question {currentQuestionIndex + 1}
      </button>
      {isOpen && (
        <div className="dropdown-content">
          {Array.from({ length: totalQuestions }, (_, i) => {
            const status = getQuestionStatus(i);
            return (
              <button
                key={i}
                onClick={() => {
                  onQuestionSelect(i);
                  setIsOpen(false);
                }}
                className="dropdown-item"
              >
                <span>Question {i + 1}</span>
                <div className="status-indicators">
                  {status.isSkipped && <span className="skip-indicator">⏭️</span>}
                  {status.isFlagged && <span className="flag-indicator">🚩</span>}
                  {!examMode && status.isAnswered && !status.isSkipped && (
                    <span
                      className={
                        status.isCorrect
                          ? "answer-indicator correct"
                          : "answer-indicator incorrect"
                      }
                    >
                      {status.isCorrect ? "✓" : "✗"}
                    </span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};

const GlobalTestPage = ({
  testId,
  category,
  backToListPath
}) => {
  const location = useLocation();
  const navigate = useNavigate();
  const dispatch = useDispatch();

  // Redux user data
  const { xp, level, coins, userId, xpBoost, currentAvatar } = useSelector(
    (state) => state.user
  );
  const achievements = useSelector((state) => state.achievements.all);
  const { items: shopItems, status: shopStatus } = useSelector(
    (state) => state.shop
  );

  // Local states for test logic
  const [testData, setTestData] = useState(null);
  const [shuffleOrder, setShuffleOrder] = useState([]);
  const [answerOrder, setAnswerOrder] = useState([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [answers, setAnswers] = useState([]);
  const [score, setScore] = useState(0);
  const [loadingTest, setLoadingTest] = useState(true);
  const [error, setError] = useState(null);
  const [isAnswered, setIsAnswered] = useState(false);
  const [selectedOptionIndex, setSelectedOptionIndex] = useState(null);
  const [isFinished, setIsFinished] = useState(false);

  // Overlays
  const [showScoreOverlay, setShowScoreOverlay] = useState(false);
  const [showReviewMode, setShowReviewMode] = useState(false);

  // Confetti on level-up
  const [localLevel, setLocalLevel] = useState(level);
  const [showLevelUpOverlay, setShowLevelUpOverlay] = useState(false);

  // Flags
  const [flaggedQuestions, setFlaggedQuestions] = useState([]);

  // Confirmation popups
  const [showRestartPopup, setShowRestartPopup] = useState(false);
  const [showFinishPopup, setShowFinishPopup] = useState(false);
  const [showNextPopup, setShowNextPopup] = useState(false);

  // Exam mode
  const [examMode, setExamMode] = useState(false);

  // New: Test length selection state
  const allowedTestLengths = [25, 50, 75, 100];
  const [selectedLength, setSelectedLength] = useState(100);
  const [activeTestLength, setActiveTestLength] = useState(null);
  const [showTestLengthSelector, setShowTestLengthSelector] = useState(false);

  useEffect(() => {
    if (shopStatus === "idle") {
      dispatch(fetchShopItems());
    }
  }, [shopStatus, dispatch]);

  const fetchTestAndAttempt = async () => {
    setLoadingTest(true);
    try {
      let attemptDoc = null;
      if (userId) {
        const attemptRes = await fetch(`/api/test/attempts/${userId}/${testId}`);
        const attemptData = await attemptRes.json();
        attemptDoc = attemptData.attempt || null;
      }
      const testRes = await fetch(`/api/test/tests/${category}/${testId}`);
      if (!testRes.ok) {
        const errData = await testRes.json().catch(() => ({}));
        throw new Error(errData.error || "Failed to fetch test data");
      }
      const testDoc = await testRes.json();
      setTestData(testDoc);

      const totalQ = testDoc.questions.length;

      // Check if attempt exists
      if (attemptDoc) {
        // If the test is already finished, we keep the data but also mark isFinished
        setAnswers(attemptDoc.answers || []);
        setScore(attemptDoc.score || 0);
        setIsFinished(attemptDoc.finished === true);

        const attemptExam = attemptDoc.examMode || false;
        setExamMode(attemptExam);

        // Use the chosen length if available
        const chosenLength = attemptDoc.selectedLength || totalQ;

        if (
          attemptDoc.shuffleOrder &&
          attemptDoc.shuffleOrder.length === chosenLength
        ) {
          setShuffleOrder(attemptDoc.shuffleOrder);
        } else {
          const newQOrder = shuffleIndices(chosenLength);
          setShuffleOrder(newQOrder);
        }

        if (
          attemptDoc.answerOrder &&
          attemptDoc.answerOrder.length === chosenLength
        ) {
          setAnswerOrder(attemptDoc.answerOrder);
        } else {
          const generatedAnswerOrder = testDoc.questions
            .slice(0, chosenLength)
            .map((q) => {
              const numOptions = q.options.length;
              return shuffleArray([...Array(numOptions).keys()]);
            });
          setAnswerOrder(generatedAnswerOrder);
        }

        setCurrentQuestionIndex(attemptDoc.currentQuestionIndex || 0);
        setActiveTestLength(chosenLength);
      } else {
        // No attempt doc exists: show the test length selector UI
        setActiveTestLength(null);
        setShowTestLengthSelector(true);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingTest(false);
    }
  };

  useEffect(() => {
    fetchTestAndAttempt();
  }, [testId, userId]);

  useEffect(() => {
    if (level > localLevel) {
      setLocalLevel(level);
      setShowLevelUpOverlay(true);
      const t = setTimeout(() => setShowLevelUpOverlay(false), 3000);
      return () => clearTimeout(t);
    }
  }, [level, localLevel]);

  useEffect(() => {
    if (location.state?.review && isFinished) {
      setShowReviewMode(true);
    }
  }, [location.state, isFinished]);

  const getShuffledIndex = useCallback(
    (i) => {
      if (!shuffleOrder || shuffleOrder.length === 0) return i;
      return shuffleOrder[i];
    },
    [shuffleOrder]
  );

  const effectiveTotal =
    activeTestLength || (testData ? testData.questions.length : 0);

  const realIndex = getShuffledIndex(currentQuestionIndex);
  const questionObject =
    testData && testData.questions && testData.questions.length > 0
      ? testData.questions[realIndex]
      : null;

  useEffect(() => {
    if (!questionObject) return;
    const existing = answers.find((a) => a.questionId === questionObject.id);
    if (existing) {
      setSelectedOptionIndex(null);
      if (
        existing.userAnswerIndex !== null &&
        existing.userAnswerIndex !== undefined
      ) {
        const displayIndex = answerOrder[realIndex].indexOf(
          existing.userAnswerIndex
        );
        if (displayIndex >= 0) {
          setSelectedOptionIndex(displayIndex);
          setIsAnswered(true);
        } else {
          setIsAnswered(false);
        }
      } else {
        setIsAnswered(false);
      }
    } else {
      setSelectedOptionIndex(null);
      setIsAnswered(false);
    }
  }, [questionObject, answers, realIndex, answerOrder]);

  const updateServerProgress = useCallback(
    async (updatedAnswers, updatedScore, finished = false, singleAnswer = null) => {
      if (!userId) return;
      try {
        if (singleAnswer) {
          const res = await fetch(`/api/test/user/${userId}/submit-answer`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              testId,
              questionId: singleAnswer.questionId,
              correctAnswerIndex: singleAnswer.correctAnswerIndex,
              selectedIndex: singleAnswer.userAnswerIndex,
              xpPerCorrect: (testData?.xpPerCorrect || 10) * xpBoost,
              coinsPerCorrect: 5
            })
          });
          const data = await res.json();
          return data;
        }
        await fetch(`/api/test/attempts/${userId}/${testId}/position`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            currentQuestionIndex,
            finished
          })
        });
      } catch (err) {
        console.error("Failed to update test attempt on backend", err);
      }
    },
    [userId, testId, testData, xpBoost, currentQuestionIndex]
  );

  // UPDATED: In exam mode, allow answer switching; in non–exam mode, lock answer selection once chosen.
  const handleOptionClick = useCallback(
    async (displayOptionIndex) => {
      if (!questionObject) return;
      if (!examMode && isAnswered) return; // Only block if exam mode is off.
      const actualAnswerIndex = answerOrder[realIndex][displayOptionIndex];
      setSelectedOptionIndex(displayOptionIndex);

      // For non–exam mode, lock the answer; for exam mode, allow changes.
      if (!examMode) {
        setIsAnswered(true);
      }
      try {
        const newAnswerObj = {
          questionId: questionObject.id,
          userAnswerIndex: actualAnswerIndex,
          correctAnswerIndex: questionObject.correctAnswerIndex
        };
        const updatedAnswers = [...answers];
        const idx = updatedAnswers.findIndex(
          (a) => a.questionId === questionObject.id
        );
        if (idx >= 0) {
          updatedAnswers[idx] = newAnswerObj;
        } else {
          updatedAnswers.push(newAnswerObj);
        }
        setAnswers(updatedAnswers);

        const awardData = await updateServerProgress(
          updatedAnswers,
          score,
          false,
          newAnswerObj
        );
        if (!examMode && awardData && awardData.examMode === false) {
          if (awardData.isCorrect) {
            setScore((prev) => prev + 1);
          }
          if (awardData.isCorrect && !awardData.alreadyCorrect && awardData.awardedXP) {
            dispatch(
              setXPAndCoins({
                xp: awardData.newXP,
                coins: awardData.newCoins
              })
            );
          }
        }
      } catch (err) {
        console.error("Failed to submit answer to backend", err);
      }
    },
    [
      isAnswered,
      questionObject,
      examMode,
      testData,
      xpBoost,
      userId,
      testId,
      dispatch,
      score,
      answers,
      updateServerProgress,
      realIndex,
      answerOrder
    ]
  );

  const finishTestProcess = useCallback(async () => {
    let finalScore = 0;
    answers.forEach((ans) => {
      if (ans.userAnswerIndex === ans.correctAnswerIndex) {
        finalScore++;
      }
    });
    setScore(finalScore);
    try {
      const res = await fetch(`/api/test/attempts/${userId}/${testId}/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          score: finalScore,
          totalQuestions: effectiveTotal
        })
      });
      const finishData = await res.json();

      if (finishData.newlyUnlocked && finishData.newlyUnlocked.length > 0) {
        finishData.newlyUnlocked.forEach((achievementId) => {
          const achievement = achievements.find(
            (a) => a.achievementId === achievementId
          );
          if (achievement) {
            const IconComp = iconMapping[achievement.achievementId] || null;
            const color = colorMapping[achievement.achievementId] || "#fff";
            showAchievementToast({
              title: achievement.title,
              description: achievement.description,
              icon: IconComp ? <IconComp /> : null,
              color
            });
          }
        });
      }

      if (
        typeof finishData.newXP !== "undefined" &&
        typeof finishData.newCoins !== "undefined"
      ) {
        dispatch(
          setXPAndCoins({
            xp: finishData.newXP,
            coins: finishData.newCoins
          })
        );
      }
    } catch (err) {
      console.error("Failed to finish test attempt:", err);
    }
    setIsFinished(true);
    setShowScoreOverlay(true);
    setShowReviewMode(true);
  }, [answers, userId, testId, effectiveTotal, achievements, dispatch]);

  const handleNextQuestion = useCallback(() => {
    if (!isAnswered && !examMode) {
      setShowNextPopup(true);
      return;
    }
    if (currentQuestionIndex === effectiveTotal - 1) {
      finishTestProcess();
      return;
    }
    const nextIndex = currentQuestionIndex + 1;
    setCurrentQuestionIndex(nextIndex);
    updateServerProgress(answers, score, false);
  }, [
    isAnswered,
    examMode,
    currentQuestionIndex,
    effectiveTotal,
    finishTestProcess,
    updateServerProgress,
    answers,
    score
  ]);

  const handlePreviousQuestion = useCallback(() => {
    if (currentQuestionIndex > 0) {
      const prevIndex = currentQuestionIndex - 1;
      setCurrentQuestionIndex(prevIndex);
      updateServerProgress(answers, score, false);
    }
  }, [currentQuestionIndex, updateServerProgress, answers, score]);

  const handleSkipQuestion = () => {
    if (!questionObject) return;
    const updatedAnswers = [...answers];
    const idx = updatedAnswers.findIndex(
      (a) => a.questionId === questionObject.id
    );
    const skipObj = {
      questionId: questionObject.id,
      userAnswerIndex: null,
      correctAnswerIndex: questionObject.correctAnswerIndex
    };
    if (idx >= 0) {
      updatedAnswers[idx] = skipObj;
    } else {
      updatedAnswers.push(skipObj);
    }
    setAnswers(updatedAnswers);
    setIsAnswered(false);
    setSelectedOptionIndex(null);
    updateServerProgress(updatedAnswers, score, false, skipObj);
    if (currentQuestionIndex === effectiveTotal - 1) {
      finishTestProcess();
      return;
    }
    setCurrentQuestionIndex(currentQuestionIndex + 1);
  };

  const handleFlagQuestion = () => {
    if (!questionObject) return;
    const qId = questionObject.id;
    if (flaggedQuestions.includes(qId)) {
      setFlaggedQuestions(flaggedQuestions.filter((x) => x !== qId));
    } else {
      setFlaggedQuestions([...flaggedQuestions, qId]);
    }
  };

  const handleRestartTest = useCallback(async () => {
    setCurrentQuestionIndex(0);
    setSelectedOptionIndex(null);
    setIsAnswered(false);
    setScore(0);
    setAnswers([]);
    setFlaggedQuestions([]);
    setIsFinished(false);
    setShowReviewMode(false);
    setShowScoreOverlay(false);

    if (testData?.questions?.length && activeTestLength) {
      const newQOrder = shuffleIndices(activeTestLength);
      setShuffleOrder(newQOrder);
      const newAnswerOrder = testData.questions
        .slice(0, activeTestLength)
        .map((q) => {
          const numOpts = q.options.length;
          return shuffleArray([...Array(numOpts).keys()]);
        });
      setAnswerOrder(newAnswerOrder);

      if (userId && testId) {
        await fetch(`/api/test/attempts/${userId}/${testId}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            answers: [],
            score: 0,
            totalQuestions: testData.questions.length,
            selectedLength: activeTestLength,
            category: testData.category || category,
            currentQuestionIndex: 0,
            shuffleOrder: newQOrder,
            answerOrder: newAnswerOrder,
            finished: false,
            examMode
          })
        });
      }
    }
  }, [
    testData,
    userId,
    testId,
    category,
    examMode,
    activeTestLength
  ]);

  const handleFinishTest = () => {
    finishTestProcess();
  };

  const [reviewFilter, setReviewFilter] = useState("all");
  const handleReviewAnswers = () => {
    setShowReviewMode(true);
    setReviewFilter("all");
  };
  const handleCloseReview = () => {
    if (!isFinished) setShowReviewMode(false);
  };

  const filteredQuestions = useMemo(() => {
    if (!testData || !testData.questions) return [];
    return testData.questions.slice(0, effectiveTotal).filter((q) => {
      const userAns = answers.find((a) => a.questionId === q.id);
      const isFlagged = flaggedQuestions.includes(q.id);

      if (!userAns) {
        // Not answered => count it as "skipped" or "all"
        return reviewFilter === "skipped" || reviewFilter === "all";
      }

      const isSkipped = userAns.userAnswerIndex === null;
      const isCorrect = userAns.userAnswerIndex === q.correctAnswerIndex;

      if (reviewFilter === "all") return true;
      if (reviewFilter === "skipped" && isSkipped) return true;
      if (reviewFilter === "flagged" && isFlagged) return true;
      if (reviewFilter === "incorrect" && !isCorrect && !isSkipped) return true;
      if (reviewFilter === "correct" && isCorrect && !isSkipped) return true;

      return false;
    });
  }, [testData, answers, flaggedQuestions, reviewFilter, effectiveTotal]);

  const NextQuestionAlert = ({ message, onOk }) => (
    <div className="confirm-popup-overlay">
      <div className="confirm-popup-content">
        <p>{message}</p>
        <div className="confirm-popup-buttons">
          <button className="confirm-popup-ok" onClick={onOk}>
            OK
          </button>
        </div>
      </div>
    </div>
  );

  const renderNextPopup = () => {
    if (!showNextPopup) return null;
    return (
      <NextQuestionAlert
        message="You haven't answered. Please answer or skip question.🤪"
        onOk={() => {
          setShowNextPopup(false);
        }}
      />
    );
  };

  const ConfirmPopup = ({ message, onConfirm, onCancel }) => (
    <div className="confirm-popup-overlay">
      <div className="confirm-popup-content">
        <p>{message}</p>
        <div className="confirm-popup-buttons">
          <button className="confirm-popup-yes" onClick={onConfirm}>
            Yes
          </button>
          <button className="confirm-popup-no" onClick={onCancel}>
            No
          </button>
        </div>
      </div>
    </div>
  );

  const renderRestartPopup = () => {
    if (!showRestartPopup) return null;
    return (
      <ConfirmPopup
        message="Are you sure you want to restart the test? All progress will be lost!😱"
        onConfirm={() => {
          handleRestartTest();
          setShowRestartPopup(false);
        }}
        onCancel={() => setShowRestartPopup(false)}
      />
    );
  };

  const renderFinishPopup = () => {
    if (!showFinishPopup) return null;
    return (
      <ConfirmPopup
        message="Are you sure you want to finish the test now?😥"
        onConfirm={() => {
          handleFinishTest();
          setShowFinishPopup(false);
        }}
        onCancel={() => setShowFinishPopup(false)}
      />
    );
  };

  // -----
  // MAIN FIX: We add a small block in the score overlay that allows the user
  // to select a new test length if they've finished, before clicking Restart.
  // -----
  const renderScoreOverlay = () => {
    if (!showScoreOverlay) return null;
    const percentage = effectiveTotal
      ? Math.round((score / effectiveTotal) * 100)
      : 0;
    return (
      <div className="score-overlay">
        <div className="score-content">
          <h2 className="score-title">Test Complete!</h2>
          <p className="score-details">
            Your score: <strong>{percentage}%</strong> ({score}/{effectiveTotal})
          </p>

          {/* NEW: Test Length selection after finishing */}
          <div className="length-selection" style={{ margin: "1rem 0" }}>
            <p style={{ marginBottom: "0.5rem" }}>Select New Test Length:</p>
            {allowedTestLengths.map((length) => (
              <label
                key={length}
                style={{
                  marginRight: "1rem",
                  display: "inline-block"
                }}
              >
                <input
                  type="radio"
                  name="finishedTestLength"
                  value={length}
                  checked={selectedLength === length}
                  onChange={(e) => {
                    const newLen = Number(e.target.value);
                    setSelectedLength(newLen);
                    setActiveTestLength(newLen);
                  }}
                />
                {length}
              </label>
            ))}
          </div>

          <div className="overlay-buttons">
            <button
              className="restart-button"
              onClick={() => setShowRestartPopup(true)}
            >
              Restart Test
            </button>
            <button className="review-button" onClick={handleReviewAnswers}>
              View Review
            </button>
            <button className="back-btn" onClick={() => navigate(backToListPath)}>
              Back to Test List
            </button>
            {Number(testId) < 9999 && (
              <button
                className="next-test-button"
                onClick={() => navigate(`${backToListPath}/${Number(testId) + 1}`)}
              >
                Next Test
              </button>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderReviewMode = () => {
    if (!showReviewMode) return null;
    return (
      <div className="score-overlay review-overlay">
        <div className="score-content review-content">
          {isFinished ? (
            <button
              className="back-to-list-btn"
              onClick={() => navigate(backToListPath)}
            >
              Go Back to Test List
            </button>
          ) : (
            <button className="close-review-x" onClick={handleCloseReview}>
              X
            </button>
          )}
          <h2 className="score-title">Review Mode</h2>
          {isFinished && (
            <p className="review-score-line">
              Your final score: {score}/{effectiveTotal} (
              {effectiveTotal ? Math.round((score / effectiveTotal) * 100) : 0}
              %)
            </p>
          )}
          <div className="review-filter-buttons">
            <button
              className={reviewFilter === "all" ? "active-filter" : ""}
              onClick={() => setReviewFilter("all")}
            >
              All
            </button>
            <button
              className={reviewFilter === "skipped" ? "active-filter" : ""}
              onClick={() => setReviewFilter("skipped")}
            >
              Skipped
            </button>
            <button
              className={reviewFilter === "flagged" ? "active-filter" : ""}
              onClick={() => setReviewFilter("flagged")}
            >
              Flagged
            </button>
            <button
              className={reviewFilter === "incorrect" ? "active-filter" : ""}
              onClick={() => setReviewFilter("incorrect")}
            >
              Incorrect
            </button>
            <button
              className={reviewFilter === "correct" ? "active-filter" : ""}
              onClick={() => setReviewFilter("correct")}
            >
              Correct
            </button>
          </div>
          <p className="score-details">
            Questions shown: {filteredQuestions.length}
          </p>
          <div className="review-mode-container">
            {filteredQuestions.map((q) => {
              const userAns = answers.find((a) => a.questionId === q.id);
              const isFlagged = flaggedQuestions.includes(q.id);

              if (!userAns) {
                return (
                  <div key={q.id} className="review-question-card">
                    <h3>
                      Q{q.id}: {q.question}{" "}
                      {isFlagged && <span className="flagged-icon">🚩</span>}
                    </h3>
                    <p>
                      <strong>Your Answer:</strong> Unanswered
                    </p>
                    <p>
                      <strong>Correct Answer:</strong>{" "}
                      {q.options[q.correctAnswerIndex]}
                    </p>
                    <p style={{ color: "#F44336" }}>No Answer</p>
                    <p>{q.explanation}</p>
                  </div>
                );
              }

              const isSkipped = userAns.userAnswerIndex === null;
              const isCorrect = userAns.userAnswerIndex === q.correctAnswerIndex;

              return (
                <div key={q.id} className="review-question-card">
                  <h3>
                    Q{q.id}: {q.question}{" "}
                    {isFlagged && <span className="flagged-icon">🚩</span>}
                  </h3>
                  <p>
                    <strong>Your Answer:</strong>{" "}
                    {isSkipped ? (
                      <span style={{ color: "orange" }}>Skipped</span>
                    ) : (
                      q.options[userAns.userAnswerIndex]
                    )}
                  </p>
                  <p>
                    <strong>Correct Answer:</strong>{" "}
                    {q.options[q.correctAnswerIndex]}
                  </p>
                  {!isSkipped && (
                    <p
                      style={{
                        color: isCorrect ? "#8BC34A" : "#F44336"
                      }}
                    >
                      {isCorrect ? "Correct!" : "Incorrect!"}
                    </p>
                  )}
                  <p>{q.explanation}</p>
                </div>
              );
            })}
          </div>
          {!isFinished && (
            <button
              className="review-button close-review-btn"
              onClick={handleCloseReview}
            >
              Close Review
            </button>
          )}
        </div>
      </div>
    );
  };

  const handleNextQuestionButtonClick = () => {
    if (!isAnswered && !examMode) {
      setShowNextPopup(true);
    } else {
      handleNextQuestion();
    }
  };

  // If no attempt doc was found (on first load), show test length UI:
  if (showTestLengthSelector) {
    return (
      <div className="test-length-selector">
        <h2>Select Test Length</h2>
        <p>Please select how many questions you want to answer:</p>
        <div className="test-length-options">
          {allowedTestLengths.map((length) => (
            <label key={length}>
              <input
                type="radio"
                name="testLength"
                value={length}
                checked={selectedLength === length}
                onChange={(e) => setSelectedLength(Number(e.target.value))}
              />
              {length}
            </label>
          ))}
        </div>
        <button
          onClick={async () => {
            setActiveTestLength(selectedLength);
            if (testData) {
              const totalQ = testData.questions.length;
              const newQOrder = shuffleIndices(selectedLength);
              setShuffleOrder(newQOrder);
              const newAnswerOrder = testData.questions
                .slice(0, selectedLength)
                .map((q) => {
                  const numOpts = q.options.length;
                  return shuffleArray([...Array(numOpts).keys()]);
                });
              setAnswerOrder(newAnswerOrder);
              try {
                await fetch(`/api/test/attempts/${userId}/${testId}`, {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({
                    answers: [],
                    score: 0,
                    totalQuestions: totalQ,
                    selectedLength: selectedLength,
                    category: testData.category || category,
                    currentQuestionIndex: 0,
                    shuffleOrder: newQOrder,
                    answerOrder: newAnswerOrder,
                    finished: false,
                    examMode: location.state?.examMode || false
                  })
                });
                setShowTestLengthSelector(false);
                fetchTestAndAttempt();
              } catch (err) {
                console.error("Failed to start new attempt", err);
              }
            }
          }}
        >
          Start Test
        </button>
      </div>
    );
  }

  if (error) {
    return <div style={{ color: "#fff" }}>Error: {error}</div>;
  }

  if (loadingTest) {
    return <div style={{ color: "#fff" }}>Loading test...</div>;
  }

  if (!testData || !testData.questions || testData.questions.length === 0) {
    return <div style={{ color: "#fff" }}>No questions found.</div>;
  }

  let avatarUrl = "https://via.placeholder.com/60";
  if (currentAvatar && shopItems && shopItems.length > 0) {
    const avatarItem = shopItems.find((item) => item._id === currentAvatar);
    if (avatarItem && avatarItem.imageUrl) {
      avatarUrl = avatarItem.imageUrl;
    }
  }

  const progressPercentage = effectiveTotal
    ? Math.round(((currentQuestionIndex + 1) / effectiveTotal) * 100)
    : 0;
  const progressColorHue = (progressPercentage * 120) / 100;
  const progressColor = `hsl(${progressColorHue}, 100%, 50%)`;

  let displayedOptions = [];
  if (questionObject && answerOrder[realIndex]) {
    displayedOptions = answerOrder[realIndex].map(
      (optionIdx) => questionObject.options[optionIdx]
    );
  }

  return (
    <div className="aplus-test-container">
      <ConfettiAnimation trigger={showLevelUpOverlay} level={level} />

      {renderRestartPopup()}
      {renderFinishPopup()}
      {renderNextPopup()}
      {renderScoreOverlay()}
      {renderReviewMode()}

      <div className="top-control-bar">
        <button className="flag-btn" onClick={handleFlagQuestion}>
          {questionObject && flaggedQuestions.includes(questionObject.id)
            ? "Unflag"
            : "Flag"}
        </button>
        <QuestionDropdown
          totalQuestions={effectiveTotal}
          currentQuestionIndex={currentQuestionIndex}
          onQuestionSelect={(index) => {
            setCurrentQuestionIndex(index);
            updateServerProgress(answers, score, false);
          }}
          answers={answers}
          flaggedQuestions={flaggedQuestions}
          testData={testData}
          shuffleOrder={shuffleOrder}
          examMode={examMode}
        />
        <button
          className="finish-test-btn"
          onClick={() => setShowFinishPopup(true)}
        >
          Finish Test
        </button>
      </div>

      <div className="upper-control-bar">
        <button
          className="restart-test-btn"
          onClick={() => setShowRestartPopup(true)}
        >
          Restart Test
        </button>
        <button className="back-btn" onClick={() => navigate(backToListPath)}>
          Back to Test List
        </button>
      </div>

      <h1 className="aplus-title">{testData.testName}</h1>

      <div className="top-bar">
        <div className="avatar-section">
          <div
            className="avatar-image"
            style={{ backgroundImage: `url(${avatarUrl})` }}
          />
          <div className="avatar-level">Lvl {level}</div>
        </div>
        <div className="xp-level-display">XP: {xp}</div>
        <div className="coins-display">Coins: {coins}</div>
      </div>

      <div className="progress-container">
        <div
          className="progress-fill"
          style={{ width: `${progressPercentage}%`, background: progressColor }}
        >
          {currentQuestionIndex + 1} / {effectiveTotal} ({progressPercentage}%)
        </div>
      </div>

      {!showScoreOverlay && !showReviewMode && !isFinished && (
        <div className="question-card">
          <div className="question-text">
            {questionObject && questionObject.question}
          </div>

          <ul className="options-list">
            {displayedOptions.map((option, displayIdx) => {
              let optionClass = "option-button";

              if (!examMode) {
                if (isAnswered && questionObject) {
                  const correctIndex = questionObject.correctAnswerIndex;
                  const actualIndex = answerOrder[realIndex][displayIdx];

                  if (actualIndex === correctIndex) {
                    optionClass += " correct-option";
                  } else if (
                    displayIdx === selectedOptionIndex &&
                    actualIndex !== correctIndex
                  ) {
                    optionClass += " incorrect-option";
                  }
                }
              } else {
                if (isAnswered && displayIdx === selectedOptionIndex) {
                  optionClass += " chosen-option";
                }
              }

              return (
                <li className="option-item" key={displayIdx}>
                  <button
                    className={optionClass}
                    onClick={() => handleOptionClick(displayIdx)}
                    disabled={examMode ? false : isAnswered}
                  >
                    {option}
                  </button>
                </li>
              );
            })}
          </ul>

          {isAnswered && questionObject && !examMode && (
            <div className="explanation">
              <strong>
                {selectedOptionIndex !== null &&
                answerOrder[realIndex][selectedOptionIndex] ===
                  questionObject.correctAnswerIndex
                  ? "Correct!"
                  : "Incorrect!"}
              </strong>
              <p>{questionObject.explanation}</p>
            </div>
          )}

          <div className="bottom-control-bar">
            <div className="bottom-control-row">
              <button
                className="prev-question-btn"
                onClick={handlePreviousQuestion}
                disabled={currentQuestionIndex === 0}
              >
                Previous Question
              </button>
              {currentQuestionIndex === effectiveTotal - 1 ? (
                <button
                  className="next-question-btn"
                  onClick={handleNextQuestionButtonClick}
                >
                  Finish Test
                </button>
              ) : (
                <button
                  className="next-question-btn"
                  onClick={handleNextQuestionButtonClick}
                >
                  Next Question
                </button>
              )}
            </div>

            <div className="bottom-control-row skip-row">
              <button className="skip-question-btn" onClick={handleSkipQuestion}>
                Skip Question
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default GlobalTestPage;

import React, { useEffect, useState } from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import "../../test.css"; // Updated below, be sure to include our new styles

const APlusTestList = () => {
  const navigate = useNavigate();
  const { userId } = useSelector((state) => state.user);
  const totalQuestionsPerTest = 100;
  const category = "aplus";

  const [attemptData, setAttemptData] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Persist examMode in localStorage
  const [examMode, setExamMode] = useState(() => {
    const stored = localStorage.getItem("examMode");
    return stored === "true";
  });

  // Show/hide tooltip for the info icon
  const [showExamInfo, setShowExamInfo] = useState(false);

  // Restart popup on the test list page (holds test number)
  const [restartPopupTest, setRestartPopupTest] = useState(null);

  // Choose test length
  const allowedTestLengths = [25, 50, 75, 100];
  const [selectedLengths, setSelectedLengths] = useState({});

  useEffect(() => {
    if (!userId) return;
    setLoading(true);

    const fetchAttempts = async () => {
      try {
        const res = await fetch(`/api/test/attempts/${userId}/list`);
        if (!res.ok) {
          throw new Error("Failed to fetch attempts for user");
        }
        const data = await res.json();
        const attemptList = data.attempts || [];

        // Filter attempts for this category
        const relevant = attemptList.filter((a) => a.category === category);

        // For each testId, pick the best attempt doc:
        const bestAttempts = {};
        for (let att of relevant) {
          const testKey = att.testId;
          if (!bestAttempts[testKey]) {
            bestAttempts[testKey] = att;
          } else {
            const existing = bestAttempts[testKey];
            // Prefer an unfinished attempt if it exists; otherwise latest finished
            if (!existing.finished && att.finished) {
              // Keep existing
            } else if (existing.finished && !att.finished) {
              bestAttempts[testKey] = att;
            } else {
              // Both finished or both unfinished => pick newest
              const existingTime = new Date(existing.finishedAt || 0).getTime();
              const newTime = new Date(att.finishedAt || 0).getTime();
              if (newTime > existingTime) {
                bestAttempts[testKey] = att;
              }
            }
          }
        }

        setAttemptData(bestAttempts);
        setLoading(false);
      } catch (err) {
        console.error(err);
        setError(err.message);
        setLoading(false);
      }
    };

    fetchAttempts();
  }, [userId, category]);

  // Save examMode to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem("examMode", examMode ? "true" : "false");
  }, [examMode]);

  if (!userId) {
    return <div className="tests-list-container">Please log in.</div>;
  }

  if (loading) {
    return <div className="tests-list-container">Loading attempts...</div>;
  }
  if (error) {
    return <div className="tests-list-container">Error: {error}</div>;
  }

  const getAttemptDoc = (testNumber) => {
    return attemptData[testNumber] || null;
  };

  const getProgressDisplay = (attemptDoc) => {
    if (!attemptDoc) return "No progress yet";
    const { finished, score, totalQuestions, currentQuestionIndex } = attemptDoc;
    if (finished) {
      const pct = Math.round(
        (score / (totalQuestions || totalQuestionsPerTest)) * 100
      );
      return `Final Score: ${pct}% (${score}/${
        totalQuestions || totalQuestionsPerTest
      })`;
    } else {
      if (typeof currentQuestionIndex === "number") {
        return `Progress: ${currentQuestionIndex + 1} / ${
          totalQuestions || totalQuestionsPerTest
        }`;
      }
      return "No progress yet";
    }
  };

  const difficultyColors = [
    { label: "Normal", color: "hsl(0, 0%, 100%)" },
    { label: "Very Easy", color: "hsl(120, 100%, 80%)" },
    { label: "Easy", color: "hsl(120, 100%, 70%)" },
    { label: "Moderate", color: "hsl(120, 100%, 60%)" },
    { label: "Intermediate", color: "hsl(120, 100%, 50%)" },
    { label: "Formidable", color: "hsl(120, 100%, 40%)" },
    { label: "Challenging", color: "hsl(120, 100%, 30%)" },
    { label: "Very Challenging", color: "hsl(120, 100%, 20%)" },
    { label: "Ruthless", color: "hsl(120, 100%, 10%)" },
    { label: "Ultra Level", color: "#000" }
  ];

  const startTest = (testNumber, doRestart = false, existingAttempt = null) => {
    if (existingAttempt && !doRestart) {
      // Resume test
      navigate(`/practice-tests/a-plus/${testNumber}`);
    } else {
      // New or forced restart
      const lengthToUse = selectedLengths[testNumber] || totalQuestionsPerTest;
      fetch(`/api/test/attempts/${userId}/${testNumber}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          category,
          answers: [],
          score: 0,
          totalQuestions: totalQuestionsPerTest,
          selectedLength: lengthToUse,
          currentQuestionIndex: 0,
          shuffleOrder: [],
          answerOrder: [],
          finished: false,
          examMode
        })
      })
        .then(() => {
          navigate(`/practice-tests/a-plus/${testNumber}`, {
            state: { examMode }
          });
        })
        .catch((err) => {
          console.error("Failed to create new attempt doc:", err);
        });
    }
  };

  const examInfoText = `Replicate a real exam experience—answers and explanations stay hidden until the test is completed🤪`;

  return (
    <div className="tests-list-container">
      <h1 className="tests-list-title">CompTIA A+ Core 1 Practice Tests</h1>

      <div className="centered-toggle-container">
        <div className="toggle-with-text">
          <label className="toggle-switch">
            <input
              type="checkbox"
              checked={examMode}
              onChange={(e) => setExamMode(e.target.checked)}
            />
            <span className="slider">{examMode ? "ON" : "OFF"}</span>
          </label>
          <span className="toggle-label">Exam Mode</span>
          <div
            className="info-icon-container"
            onMouseEnter={() => setShowExamInfo(true)}
            onMouseLeave={() => setShowExamInfo(false)}
            onClick={() => setShowExamInfo((prev) => !prev)}
          >
            <div className="info-icon">ⓘ</div>
            {showExamInfo && (
              <div className="info-tooltip">
                {examInfoText}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="tests-list-grid">
        {Array.from({ length: 10 }, (_, i) => {
          const testNumber = i + 1;
          const attemptDoc = getAttemptDoc(testNumber);
          const progressDisplay = getProgressDisplay(attemptDoc);
          const difficulty = difficultyColors[i] || { label: "", color: "#fff" };

          const isFinished = attemptDoc?.finished;
          const noAttempt = !attemptDoc;

          return (
            <div key={testNumber} className="test-card">
              <div className="test-badge">Test {testNumber}</div>
              <div
                className="difficulty-label"
                style={{ color: difficulty.color }}
              >
                {difficulty.label}
              </div>
              <p className="test-progress">{progressDisplay}</p>

              {/* If no attempt or finished => show length selector */}
              {(noAttempt || isFinished) && (
                <div className="test-length-selector-card">
                  <p>Select Test Length:</p>
                  <div className="test-length-options">
                    {allowedTestLengths.map((length) => (
                      <label key={length} className="test-length-option">
                        <input
                          type="radio"
                          name={`testLength-${testNumber}`}
                          value={length}
                          checked={
                            (selectedLengths[testNumber] ||
                              totalQuestionsPerTest) === length
                          }
                          onChange={(e) =>
                            setSelectedLengths((prev) => ({
                              ...prev,
                              [testNumber]: Number(e.target.value)
                            }))
                          }
                        />
                        <span>{length}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}

              {/* Start / Resume / Restart */}
              {noAttempt && (
                <button
                  className="start-button"
                  onClick={() => startTest(testNumber, false, null)}
                >
                  Start
                </button>
              )}
              {attemptDoc && !attemptDoc.finished && (
                <div className="test-card-buttons">
                  <button
                    className="resume-button"
                    onClick={() => startTest(testNumber, false, attemptDoc)}
                  >
                    Resume
                  </button>
                  <button
                    className="restart-button-testlist"
                    onClick={() => setRestartPopupTest(testNumber)}
                  >
                    Restart
                  </button>
                </div>
              )}
              {attemptDoc && attemptDoc.finished && (
                <div className="test-card-buttons">
                  <button
                    className="resume-button"
                    onClick={() =>
                      navigate(`/practice-tests/a-plus/${testNumber}`, {
                        state: { review: true }
                      })
                    }
                  >
                    View Review
                  </button>
                  <button
                    className="restart-button-testlist"
                    onClick={() => startTest(testNumber, true, attemptDoc)}
                  >
                    Restart
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Popup for partial restarts */}
      {restartPopupTest !== null && (
        <div className="popup-overlay">
          <div className="popup-content">
            <p>
              You are currently in progress on this test, are you sure you want to restart!?😱 
              Also, if you want to change the test length, please finish your current attempt.
              Restarting now will use your currently selected test length and reset your progress🧙‍♂️.
            </p>
            <div className="popup-buttons">
              <button
                onClick={() => {
                  const attemptDoc = getAttemptDoc(restartPopupTest);
                  startTest(restartPopupTest, true, attemptDoc);
                  setRestartPopupTest(null);
                }}
              >
                Yes, Restart!😎
              </button>
              <button onClick={() => setRestartPopupTest(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default APlusTestList;

// APlusTestPage.js
import React from "react";
import { useParams } from "react-router-dom";
import APlusTestList from "./APlusTestList";  // your existing test list component
import GlobalTestPage from "../../GlobalTestPage"; // the new universal logic
import "../../test.css";

const APlusTestPage = () => {
  const { testId } = useParams();

  // If no testId in URL, show the test list
  if (!testId) {
    return <APlusTestList />;
  }

  // Otherwise, show the universal test runner
  return (
    <GlobalTestPage
      testId={testId}
      category="aplus"
      backToListPath="/practice-tests/a-plus"
    />
  );
};

export default APlusTestPage;

ok go
