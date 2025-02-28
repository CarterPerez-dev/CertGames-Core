import React, { useState, useRef, useEffect } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import './Sidebar.css';
import sidebarLogo from './sidebarlogo.png'; 
import { FaChevronDown, FaChevronUp } from 'react-icons/fa';

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

  return (
    <>
      {/* Sidebar Toggle Button */}
      <button
        ref={toggleButtonRef}
        className="sidebar-toggle"
        onClick={toggleSidebar}
      >
        {collapsed ? '≣' : '⛌ '}
      </button>

      <div ref={sidebarRef} className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
        <h2 className="sidebar-title">root@</h2>
        <ul className="sidebar-list">
          <li>
            <NavLink to="/profile" className={({ isActive }) => isActive ? 'active-link' : ''}>
              /Profile
            </NavLink>
            <ul className="sublist">
              <li>
                <NavLink
                  to="/my-support"
                  className={({ isActive }) => isActive ? 'active-subtab' : ''}
                >
                  Questions
                </NavLink>
              </li>
            </ul>
          </li>
          <li>
            <NavLink to="/achievements" className={({ isActive }) => isActive ? 'active-link' : ''}>
              /Achievements
            </NavLink>
          </li>
          <li>
            <NavLink to="/shop" className={({ isActive }) => isActive ? 'active-link' : ''}>
              /Shop
            </NavLink>
          </li>
          <li>
            <NavLink to="/daily" className={({ isActive }) => isActive ? 'active-link' : ''}>
              /Bonus
            </NavLink>
          </li>
          <li>
            <NavLink to="/leaderboard" className={({ isActive }) => isActive ? 'active-link' : ''}>
              /Leaderboard
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
              <span>/Tools</span>
              {toolsOpen ? <FaChevronUp /> : <FaChevronDown />}
            </div>
            {toolsOpen && (
              <ul className="group-sublist">
                <li>
                  <NavLink to="/xploitcraft" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    Xploitcraft
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/scenariosphere" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    Scenario Sphere
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/analogyhub" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    Analogy Hub
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/grc" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    GRC Wizard
                  </NavLink>
                </li>
              </ul>
            )}
          </li>

          {/* Daily CyberBrief */}
          <li>
            <NavLink to="/dailycyberbrief" className={({ isActive }) => isActive ? 'active-link' : ''}>
              /Daily CyberBrief
            </NavLink>
          </li>

          {/* Study Resources */}
          <li>
            <NavLink to="/resources" className={({ isActive }) => isActive ? 'active-link' : ''}>
              /Study Resources
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
              <span>/Practice Tests</span>
              {practiceTestsOpen ? <FaChevronUp /> : <FaChevronDown />}
            </div>
            {practiceTestsOpen && (
              <ul className="group-sublist">
                <li>
                  <NavLink to="/practice-tests/a-plus" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    A+ Core 1
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/aplus-core2" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    A+ Core 2
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/network-plus" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    Network+
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/security-plus" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    Security+
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/cysa-plus" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    CySa+
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/pen-plus" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    Pentest+
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/casp-plus" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    CASP+
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/linux-plus" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    Linux+
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/cloud-plus" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    Cloud+
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/data-plus" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    Data+
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/server-plus" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    Server+
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/cissp" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    CISSP
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/practice-tests/aws-cloud" className={({ isActive }) => isActive ? 'active-subtab' : ''}>
                    AWS Cloud Practitioner
                  </NavLink>
                </li>
              </ul>
            )}
          </li>
        </ul>

        <div className="sidebar-logo-container">
          <img src={sidebarLogo} alt="Sidebar Logo" className="sidebar-logo" />
        </div>
      </div>
    </>
  );
};

export default Sidebar;

