// src/components/pages/DevChronicle/DevChronicle.js
import React, { useEffect } from 'react';
import './DevChronicle.css';
import { 
  FaBug, 
  FaGithubAlt, 
  FaStar, 
  FaCalendarAlt, 
  FaLock, 
  FaChartLine, 
  FaClock, 
  FaTools, 
  FaGamepad, 
  FaFlask, 
  FaClipboardCheck,
  FaTasks,
  FaCheckCircle,
  FaReact,
  FaAws,
  FaShieldAlt,
  FaBook
} from 'react-icons/fa';

const DevChronicle = () => {
  // Theme detection on component mount
  useEffect(() => {
    // This ensures the component respects the current theme
    const savedTheme = localStorage.getItem('selectedTheme') || 'default';
    document.documentElement.setAttribute('data-theme', savedTheme);
  }, []);

  return (
    <div className="devchronicle-container">
      {/* Background elements, similar to login/register pages */}
      <div className="devchronicle-background">
        <div className="devchronicle-grid"></div>
        <div className="devchronicle-particles">
          {[...Array(20)].map((_, i) => (
            <div key={i} className="devchronicle-particle"></div>
          ))}
        </div>
        <div className="devchronicle-glow"></div>
      </div>

      <header className="devchronicle-header">
        <div className="devchronicle-title-container">
          <h1 className="devchronicle-title">Git Commits</h1>
          <p className="devchronicle-subtitle">Updates, Improvements & Roadmap</p>
        </div>
        <div className="devchronicle-graphic">
          <div className="devchronicle-pulse"></div>
        </div>
      </header>

      <main className="devchronicle-content">
        <div className="devchronicle-timeline">
          {/* Future month */}
          <div className="devchronicle-period future">
            <div className="devchronicle-period-header">
              <div className="devchronicle-period-icon">
                <FaGithubAlt/>
              </div>
              <h2 className="devchronicle-period-title">End of May - June 2025</h2>
              <div className="devchronicle-period-badge">Coming Soon</div>
            </div>

            <div className="devchronicle-section">
              <div className="devchronicle-section-header">
                <FaStar className="devchronicle-section-icon" />
                <h3 className="devchronicle-section-title">Major Additions</h3>
              </div>
              <div className="devchronicle-section-content">
                <ul className="devchronicle-list">
                  <li className="devchronicle-item">
                    <FaGamepad className="devchronicle-item-icon" />
                    <span>New games and interactive challenges</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaShieldAlt className="devchronicle-item-icon" />
                    <span>Additional ISC2 exam tests: SSCP, CCSP, CSSLP, and CC</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaAws className="devchronicle-item-icon" />
                    <span>Expanded AWS certification tests: DevOps Engineer, Solutions Architect (Associate & Professional), SysOps Administrator, Security, and Developer</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaClipboardCheck className="devchronicle-item-icon" />
                    <span>More CompTIA certifications: ITF+, Data+, Project+</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaBook className="devchronicle-item-icon" />
                    <span>Additional study resources and reference materials</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaTasks className="devchronicle-item-icon" />
                    <span>New achievement categories and badges</span>
                  </li>
                </ul>
              </div>
            </div>

            <div className="devchronicle-section">
              <div className="devchronicle-section-header">
                <FaTools className="devchronicle-section-icon" />
                <h3 className="devchronicle-section-title">Enhancements & Improvements</h3>
              </div>
              <div className="devchronicle-section-content">
                <ul className="devchronicle-list">
                  <li className="devchronicle-item">
                    <FaBug className="devchronicle-item-icon" />
                    <span>Comprehensive bug fixes for existing features</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaLock className="devchronicle-item-icon" />
                    <span>Advanced security enhancements across the platform</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaChartLine className="devchronicle-item-icon" />
                    <span>Performance optimizations</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>

          {/* Current month */}
          <div className="devchronicle-period current">
            <div className="devchronicle-period-header">
              <div className="devchronicle-period-icon">
                <FaCalendarAlt />
              </div>
              <h2 className="devchronicle-period-title">May 2025</h2>
              <div className="devchronicle-period-badge">Current</div>
            </div>

            <div className="devchronicle-section">
              <div className="devchronicle-section-header">
                <FaStar className="devchronicle-section-icon" />
                <h3 className="devchronicle-section-title">Major Additions</h3>
              </div>
              <div className="devchronicle-section-content">
                <ul className="devchronicle-list">
                  <li className="devchronicle-item highlight">
                    <FaReact className="devchronicle-item-icon" />
                    <span>Portfolio Creator Beta – Create and showcase your professional portfolio</span>
                  </li>
                  <li className="devchronicle-item highlight">
                    <FaBook className="devchronicle-item-icon" />
                    <span>Cyber Flashcards – New interactive study tool</span>
                  </li>
                  <li className="devchronicle-item highlight">
                    <FaChartLine className="devchronicle-item-icon" />
                    <span>Stats Page – Track your progress and achievements</span>
                  </li>
                </ul>
              </div>
            </div>

            <div className="devchronicle-section">
              <div className="devchronicle-section-header">
                <FaTools className="devchronicle-section-icon" />
                <h3 className="devchronicle-section-title">Improvements & Bug Fixes</h3>
              </div>
              <div className="devchronicle-section-content">
                <ul className="devchronicle-list">
                  <li className="devchronicle-item">
                    <FaFlask className="devchronicle-item-icon" />
                    <span>Enhanced loading animations</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaBug className="devchronicle-item-icon" />
                    <span>Fixed "Unauthenticated" message on Support page during first login</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaCheckCircle className="devchronicle-item-icon" />
                    <span>Improved test screen with automatic scrolling to explanations after answering</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaCheckCircle className="devchronicle-item-icon" />
                    <span>Added automatic scroll to top when navigating between screens</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaCheckCircle className="devchronicle-item-icon" />
                    <span>Updated sidebar logo with theme color support</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>

          {/* Past month */}
          <div className="devchronicle-period past">
            <div className="devchronicle-period-header">
              <div className="devchronicle-period-icon">
                <FaClock />
              </div>
              <h2 className="devchronicle-period-title">April 2025</h2>
              <div className="devchronicle-period-badge">Complete</div>
            </div>

            <div className="devchronicle-section">
              <div className="devchronicle-section-header">
                <FaStar className="devchronicle-section-icon" />
                <h3 className="devchronicle-section-title">Major Additions</h3>
              </div>
              <div className="devchronicle-section-content">
                <div className="devchronicle-games-grid">
                  <div className="devchronicle-game-card">
                    <div className="devchronicle-game-icon">
                      <FaGamepad />
                    </div>
                    <h4 className="devchronicle-game-title">Incident Responder</h4>
                    <p className="devchronicle-game-desc">Test your incident response skills in realistic scenarios</p>
                  </div>
                  <div className="devchronicle-game-card">
                    <div className="devchronicle-game-icon">
                      <FaGamepad />
                    </div>
                    <h4 className="devchronicle-game-title">Phishing Phrenzy</h4>
                    <p className="devchronicle-game-desc">Identify and avoid sophisticated phishing attempts</p>
                  </div>
                  <div className="devchronicle-game-card">
                    <div className="devchronicle-game-icon">
                      <FaGamepad />
                    </div>
                    <h4 className="devchronicle-game-title">Cipher Challenge</h4>
                    <p className="devchronicle-game-desc">Crack codes and solve encryption puzzles</p>
                  </div>
                  <div className="devchronicle-game-card">
                    <div className="devchronicle-game-icon">
                      <FaGamepad />
                    </div>
                    <h4 className="devchronicle-game-title">Threat Hunter</h4>
                    <p className="devchronicle-game-desc">Identify and neutralize security threats</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="devchronicle-section">
              <div className="devchronicle-section-header">
                <FaTools className="devchronicle-section-icon" />
                <h3 className="devchronicle-section-title">Improvements & Bug Fixes</h3>
              </div>
              <div className="devchronicle-section-content">
                <ul className="devchronicle-list">
                  <li className="devchronicle-item highlight">
                    <FaLock className="devchronicle-item-icon" />
                    <span>Freemium model implemented, replacing strict paywall</span>
                  </li>
                  <li className="devchronicle-item highlight">
                    <FaShieldAlt className="devchronicle-item-icon" />
                    <span>Drastically improved security across the platform</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaChartLine className="devchronicle-item-icon" />
                    <span>Cached leaderboard (updates every 30 minutes) for faster loading times</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaCheckCircle className="devchronicle-item-icon" />
                    <span>Refined profile styling adjustments</span>
                  </li>
                  <li className="devchronicle-item">
                    <FaCheckCircle className="devchronicle-item-icon" />
                    <span>Reorganized sidebar navigation for better usability</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </main>
      
      <div className="devchronicle-footer">
        <div className="devchronicle-pulse-small"></div>
        <p>Have suggestions for future updates? <a href="/my-support" className="devchronicle-link">Let us know!</a></p>
      </div>
    </div>
  );
};

export default DevChronicle;
