import React, { useState, useRef, useEffect } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import './Sidebar.css';
import sidebarLogo from './sidebarlogo.png'; 
import { 
  FaChevronDown, 
  FaChevronUp, 
  FaBars, 
  FaTimes,
  FaUserSecret,
  FaTrophy, 
  FaStore, 
  FaGift, 
  FaChartBar,
  FaQuestion,
  FaTools,
  FaNewspaper,
  FaBook,
  FaLaptopCode,
  FaChessKnight,
  FaGamepad,
  FaAward,
  FaAmazon,
  FaShieldAlt,
  FaCrown,
  FaGithub
} from 'react-icons/fa';

const Sidebar = () => {
  const [collapsed, setCollapsed] = useState(true);
  const [toolsOpen, setToolsOpen] = useState(false);
  const [comptiaTestsOpen, setComptiaTestsOpen] = useState(false);
  const [isc2TestsOpen, setIsc2TestsOpen] = useState(false);
  const [awsTestsOpen, setAwsTestsOpen] = useState(false);
  const [gamesOpen, setGamesOpen] = useState(false);
  const [gameHubOpen, setGameHubOpen] = useState(false);

  const navigate = useNavigate();
  const sidebarRef = useRef(null);
  const toggleButtonRef = useRef(null);

  const toggleSidebar = () => {
    setCollapsed(!collapsed);
  };

  const toggleTools = () => {
    setToolsOpen(!toolsOpen);
  };

  const toggleComptiaTests = () => {
    setComptiaTestsOpen(!comptiaTestsOpen);
  };

  const toggleIsc2Tests = () => {
    setIsc2TestsOpen(!isc2TestsOpen);
  };

  const toggleAwsTests = () => {
    setAwsTestsOpen(!awsTestsOpen);
  };
  
  const toggleGames = () => {
    setGamesOpen(!gamesOpen);
  };  
  
  const toggleGameHub = () => {
    setGameHubOpen(!gameHubOpen);
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
      case '/profile': return <FaUserSecret className="sidebar-icon" />;
      case '/achievements': return <FaTrophy className="sidebar-icon" />;
      case '/shop': return <FaStore className="sidebar-icon" />;
      case '/daily': return <FaGift className="sidebar-icon" />;
      case '/leaderboard': return <FaChartBar className="sidebar-icon" />;
      case '/my-support': return <FaQuestion className="sidebar-icon" />;
      case '/dailycyberbrief': return <FaNewspaper className="sidebar-icon" />;
      case '/portfolio': return <FaGithub className="sidebar-icon" />;
      case '/resources': return <FaBook className="sidebar-icon" />;
      case '/performance': return <FaChessKnight className="sidebar-icon" />;
      default: return null;
    }
  };

  // Premium feature check
  const isPremiumFeature = (path) => {
    const premiumPaths = [
      '/xploitcraft',
      '/scenariosphere',
      '/grc',
      '/games/threat-hunter',
      '/games/cipher-challenge'
    ];
    return premiumPaths.includes(path);
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
        {collapsed ? "☰" : "✕"}
      </button>

      <div ref={sidebarRef} className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
        <div className="sidebar-content">
          <h2 className="sidebar-title">root@</h2>
          
          <nav className="sidebar-nav">
            <ul className="sidebar-list">
              {/* Profile */}
              <li>
                <NavLink to="/profile" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/profile')}
                  <span className="sidebar-link-text">>> Profile</span>
                </NavLink>
              </li>
              
              {/* Stats/Performance Dashboard */}
              <li>
                <NavLink to="/performance" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/performance')}
                  <span className="sidebar-link-text">∼Stats</span>
                </NavLink>
              </li>
              
              {/* Support (renamed from Questions) */}
              <li>
                <NavLink to="/my-support" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/my-support')}
                  <span className="sidebar-link-text">-Support</span>
                </NavLink>
              </li>
              
              {/* Games group */}
              <li className="sidebar-group">
                <div
                  className="group-header"
                  onClick={toggleGames}
                  role="button"
                  tabIndex={0}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') toggleGames();
                  }}
                >
                  <div className="group-header-content">
                    <FaGamepad className="sidebar-icon" />
                    <span className="sidebar-link-text">/Games</span>
                  </div>
                  {gamesOpen ? <FaChevronUp className="group-icon" /> : <FaChevronDown className="group-icon" />}
                </div>
                <ul className={`group-sublist ${gamesOpen ? 'expanded' : ''}`}>
                  <li>
                    <NavLink to="/games/threat-hunter" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Threat Hunter</span>
                      <FaCrown className="premium-crown" />
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/games/incident-responder" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Xploit Responder</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/games/phishing-phrenzy" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Phishing Phrenzy</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/games/cipher-challenge" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Cipher Challenge</span>
                      <FaCrown className="premium-crown" />
                    </NavLink>
                  </li>
                  {/* Added Daily PBQ (renamed from Bonus) into Games dropdown */}
                  <li>
                    <NavLink to="/daily" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Daily PBQ</span>
                    </NavLink>
                  </li>
                </ul>
              </li>
              
              {/* Game Hub group - moved below Games */}
              <li className="sidebar-group">
                <div
                  className="group-header"
                  onClick={toggleGameHub}
                  role="button"
                  tabIndex={0}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') toggleGameHub();
                  }}
                >
                  <div className="group-header-content">
                    <FaAward className="sidebar-icon" />
                    <span className="sidebar-link-text">/Game Hub</span>
                  </div>
                  {gameHubOpen ? <FaChevronUp className="group-icon" /> : <FaChevronDown className="group-icon" />}
                </div>
                <ul className={`group-sublist ${gameHubOpen ? 'expanded' : ''}`}>
                  <li>
                    <NavLink to="/shop" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Shop</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/achievements" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Achievements</span>
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/leaderboard" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Leaderboard</span>
                    </NavLink>
                  </li>
                </ul>
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
                      <FaCrown className="premium-crown" />
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/scenariosphere" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Scenario Sphere</span>
                      <FaCrown className="premium-crown" />
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
                      <FaCrown className="premium-crown" />
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/cybercards" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Cyber Cards</span>
                      <FaCrown className="premium-crown" />
                    </NavLink>
                  </li>
                  <li>
                    <NavLink to="/resources" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">Study Resources</span>
                    </NavLink>
                  </li>
                </ul>
              </li>
              
              {/* CompTIA Tests group */}
              <li className="sidebar-group">
                <div
                  className="group-header"
                  onClick={toggleComptiaTests}
                  role="button"
                  tabIndex={0}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') toggleComptiaTests();
                  }}
                >
                  <div className="group-header-content">
                    <FaLaptopCode className="sidebar-icon" />
                    <span className="sidebar-link-text">/CompTIA Tests</span>
                  </div>
                  {comptiaTestsOpen ? <FaChevronUp className="group-icon" /> : <FaChevronDown className="group-icon" />}
                </div>
                <ul className={`group-sublist ${comptiaTestsOpen ? 'expanded' : ''}`}>
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
                      <span className="sidebar-link-text">Security-X</span>
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
                </ul>
              </li>
              
              {/* ISC2 Tests group */}
              <li className="sidebar-group">
                <div
                  className="group-header"
                  onClick={toggleIsc2Tests}
                  role="button"
                  tabIndex={0}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') toggleIsc2Tests();
                  }}
                >
                  <div className="group-header-content">
                    <FaShieldAlt className="sidebar-icon" />
                    <span className="sidebar-link-text">/ISC2 Tests</span>
                  </div>
                  {isc2TestsOpen ? <FaChevronUp className="group-icon" /> : <FaChevronDown className="group-icon" />}
                </div>
                <ul className={`group-sublist ${isc2TestsOpen ? 'expanded' : ''}`}>
                  <li>
                    <NavLink to="/practice-tests/cissp" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">CISSP</span>
                    </NavLink>
                  </li>
                </ul>
              </li>
              
              {/* AWS Tests group */}
              <li className="sidebar-group">
                <div
                  className="group-header"
                  onClick={toggleAwsTests}
                  role="button"
                  tabIndex={0}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') toggleAwsTests();
                  }}
                >
                  <div className="group-header-content">
                    <FaAmazon className="sidebar-icon" />
                    <span className="sidebar-link-text">/AWS Tests</span>
                  </div>
                  {awsTestsOpen ? <FaChevronUp className="group-icon" /> : <FaChevronDown className="group-icon" />}
                </div>
                <ul className={`group-sublist ${awsTestsOpen ? 'expanded' : ''}`}>
                  <li>
                    <NavLink to="/practice-tests/aws-cloud" className={({ isActive }) => `sidebar-sublink ${isActive ? 'active-subtab' : ''}`}>
                      <span className="sidebar-link-text">AWS Cloud Practitioner</span>
                    </NavLink>
                  </li>
                </ul>
              </li>
              
              {/* Daily CyberBrief */}
              <li>
                <NavLink to="/dailycyberbrief" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/dailycyberbrief')}
                  <span className="sidebar-link-text">-CyberBrief</span>
                </NavLink>
              </li>
              <li>
                <NavLink to="/portfolio" className={({ isActive }) => `sidebar-link ${isActive ? 'active-link' : ''}`}>
                  {getIcon('/portfolio')}
                  <span className="sidebar-link-text">-Portfolio Creator</span>
                </NavLink>
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
