// src/components/pages/games/ThreatHunter/GameInstructions.js
import React from 'react';
import { 
  FaTimes, 
  FaFlag, 
  FaSearch, 
  FaExclamationTriangle, 
  FaCheck, 
  FaNetworkWired, 
  FaShieldAlt, 
  FaVirus, 
  FaUserSecret
} from 'react-icons/fa';
import './GameInstructions.css';

const GameInstructions = ({ onClose }) => {
  return (
    <div className="threathunter-instructions-overlay">
      <div className="threathunter-instructions-container">
        <div className="threathunter-instructions-header">
          <h2>How to Play: Threat Hunter</h2>
          <button className="threathunter-instructions-close" onClick={onClose}>
            <FaTimes />
          </button>
        </div>
        
        <div className="threathunter-instructions-content">
          <div className="threathunter-instructions-section">
            <h3>Game Overview</h3>
            <p>
              Threat Hunter simulates the role of a security analyst reviewing logs for suspicious activity. 
              Your goal is to analyze log files, identify malicious patterns, and detect security threats 
              before time runs out.
            </p>
          </div>
          
          <div className="threathunter-instructions-section">
            <h3>Game Flow</h3>
            <ol className="threathunter-instructions-steps">
              <li>
                <span className="step-number">1</span>
                <div className="step-content">
                  <h4>Select a Scenario</h4>
                  <p>Choose a threat type and difficulty level, then select a scenario to analyze.</p>
                </div>
              </li>
              <li>
                <span className="step-number">2</span>
                <div className="step-content">
                  <h4>Review Logs</h4>
                  <p>Examine the log files for suspicious patterns or unusual activity.</p>
                </div>
              </li>
              <li>
                <span className="step-number">3</span>
                <div className="step-content">
                  <h4>Flag Suspicious Lines</h4>
                  <p>Click the <FaFlag /> icon to flag suspicious log lines as evidence.</p>
                </div>
              </li>
              <li>
                <span className="step-number">4</span>
                <div className="step-content">
                  <h4>Identify Threats</h4>
                  <p>Use the Analysis Tools to document the threats you've identified.</p>
                </div>
              </li>
              <li>
                <span className="step-number">5</span>
                <div className="step-content">
                  <h4>Submit Your Analysis</h4>
                  <p>Submit your findings for scoring before time runs out.</p>
                </div>
              </li>
            </ol>
          </div>
          
          <div className="threathunter-instructions-section">
            <h3>Key Tools & Features</h3>
            
            <div className="threathunter-instructions-tools">
              <div className="tool-item">
                <div className="tool-icon log-icon">
                  <FaSearch />
                </div>
                <div className="tool-description">
                  <h4>Log Viewer</h4>
                  <p>Review different log files, search for keywords, and flag suspicious lines.</p>
                </div>
              </div>
              
              <div className="tool-item">
                <div className="tool-icon analysis-icon">
                  <FaExclamationTriangle />
                </div>
                <div className="tool-description">
                  <h4>Analysis Tools</h4>
                  <p>Document threats you've detected with type, description, and source information.</p>
                </div>
              </div>
              
              <div className="tool-item">
                <div className="tool-icon timer-icon">
                  <FaCheck />
                </div>
                <div className="tool-description">
                  <h4>Submit Analysis</h4>
                  <p>Submit your findings once you've identified all threats you can find.</p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="threathunter-instructions-section">
            <h3>Common Threat Types</h3>
            
            <div className="threathunter-instructions-threats">
              <div className="threat-type">
                <FaVirus className="threat-icon malware" />
                <div className="threat-info">
                  <h4>Malware Activity</h4>
                  <p>Look for suspicious processes, file creation in unusual locations, encoded commands.</p>
                </div>
              </div>
              
              <div className="threat-type">
                <FaShieldAlt className="threat-icon intrusion" />
                <div className="threat-info">
                  <h4>Intrusion Attempts</h4>
                  <p>Look for SQL injection, brute force logins, path traversal attempts.</p>
                </div>
              </div>
              
              <div className="threat-type">
                <FaNetworkWired className="threat-icon exfiltration" />
                <div className="threat-info">
                  <h4>Data Exfiltration</h4>
                  <p>Look for large outbound file transfers, unusual connections to external domains.</p>
                </div>
              </div>
              
              <div className="threat-type">
                <FaUserSecret className="threat-icon credential" />
                <div className="threat-info">
                  <h4>Credential Theft</h4>
                  <p>Look for password attacks, unusual logins, privilege escalation.</p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="threathunter-instructions-section">
            <h3>Scoring</h3>
            <p>Your score is based on:</p>
            <ul className="scoring-list">
              <li>Correctly identified threats (+70%)</li>
              <li>Correctly flagged suspicious lines (+20%)</li>
              <li>Time remaining bonus (up to +10%)</li>
              <li>Penalty for false positives (-5% each)</li>
            </ul>
            <p>The higher your score, the better your security analyst rating!</p>
          </div>
        </div>
        
        <div className="threathunter-instructions-footer">
          <button className="threathunter-instructions-start-button" onClick={onClose}>
            I'm Ready to Hunt Threats
          </button>
        </div>
      </div>
    </div>
  );
};

export default GameInstructions;
