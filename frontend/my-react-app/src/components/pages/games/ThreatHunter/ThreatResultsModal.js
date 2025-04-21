// src/components/pages/games/ThreatHunter/ThreatResultsModal.js
import React from 'react';
import { 
  FaTrophy, FaRedo, FaHome, FaCheck, FaTimes, 
  FaClock, FaExclamationTriangle, FaLinkedin, 
  FaFlag
} from 'react-icons/fa';

import { 
  FaXTwitter,  
} from 'react-icons/fa6';

import './ThreatHunter.css';

const ThreatResultsModal = ({ results, scenario, onClose, onRestart }) => {
  if (!results || !scenario) return null;
  
  const { 
    score,
    maxScore,
    correctThreats,
    missedThreats,
    falsePositives,
    timeBonus,
    coinsAwarded,
    xpAwarded,
    feedback,
    newAchievements,
    correctlyFlaggedLines = [], // New prop for correctly flagged lines
    missedFlaggedLines = []    // New prop for missed lines that should have been flagged
  } = results;
  
  // Calculate score percentage and round to whole number
  const scorePercentage = Math.round((score / maxScore) * 100);
  
  // Determine rating based on score percentage
  const getRating = () => {
    if (scorePercentage >= 90) return 'Expert Analyst';
    if (scorePercentage >= 75) return 'Senior Analyst';
    if (scorePercentage >= 60) return 'Security Analyst';
    if (scorePercentage >= 40) return 'Junior Analyst';
    return 'Trainee';
  };
  
  const getRatingClass = () => {
    if (scorePercentage >= 90) return 'expert';
    if (scorePercentage >= 75) return 'senior';
    if (scorePercentage >= 60) return 'analyst';
    if (scorePercentage >= 40) return 'junior';
    return 'trainee';
  };

  // Calculate points breakdown
  const threatPoints = correctThreats.length > 0 ? 
    Math.round((correctThreats.length / (correctThreats.length + missedThreats.length)) * 70) : 0;
  
  const evidencePoints = correctlyFlaggedLines.length > 0 ?
    Math.min(20, Math.round((correctlyFlaggedLines.length / (correctlyFlaggedLines.length + missedFlaggedLines.length)) * 20)) : 0;
  
  const penaltyPoints = Math.min(30, (falsePositives.length * 5));
  
  return (
    <div className="threathunter_resultsmodal_overlay">
      <div className="threathunter_resultsmodal_container">
        <div className="threathunter_resultsmodal_header">
          <h2>Analysis Complete</h2>
          <h3>{scenario.title}</h3>
        </div>
        
        <div className="threathunter_resultsmodal_overview">
          <div className="threathunter_resultsmodal_score_container">
            <div className="threathunter_resultsmodal_score_circle">
              <div className="threathunter_resultsmodal_score_percentage">{scorePercentage}%</div>
              <div className="threathunter_resultsmodal_score_points">{score}/{maxScore}</div>
            </div>
            
            <div className={`threathunter_resultsmodal_rating_container ${getRatingClass()}`}>
              <FaTrophy className="threathunter_resultsmodal_rating_icon" />
              <div className="threathunter_resultsmodal_rating_value">{getRating()}</div>
            </div>
          </div>
          
          <div className="threathunter_resultsmodal_threat_stats">
            <div className="threathunter_resultsmodal_stat_row correct">
              <div className="threathunter_resultsmodal_stat_icon"><FaCheck /></div>
              <div className="threathunter_resultsmodal_stat_label">Threats Correctly Identified:</div>
              <div className="threathunter_resultsmodal_stat_value">{correctThreats.length}</div>
            </div>
            
            <div className="threathunter_resultsmodal_stat_row missed">
              <div className="threathunter_resultsmodal_stat_icon"><FaTimes /></div>
              <div className="threathunter_resultsmodal_stat_label">Threats Missed:</div>
              <div className="threathunter_resultsmodal_stat_value">{missedThreats.length}</div>
            </div>
            
            <div className="threathunter_resultsmodal_stat_row false">
              <div className="threathunter_resultsmodal_stat_icon"><FaExclamationTriangle /></div>
              <div className="threathunter_resultsmodal_stat_label">False Positives:</div>
              <div className="threathunter_resultsmodal_stat_value">{falsePositives.length}</div>
            </div>
            
            <div className="threathunter_resultsmodal_stat_row time">
              <div className="threathunter_resultsmodal_stat_icon"><FaClock /></div>
              <div className="threathunter_resultsmodal_stat_label">Time Bonus:</div>
              <div className="threathunter_resultsmodal_stat_value">+{timeBonus}</div>
            </div>
          </div>
        </div>

        {/* New section for score breakdown */}
        <div className="threathunter_resultsmodal_score_breakdown">
          <h3>Points Breakdown</h3>
          <div className="threathunter_resultsmodal_breakdown_container">
            <div className="threathunter_resultsmodal_breakdown_item">
              <div className="threathunter_resultsmodal_breakdown_label">Threat Detection</div>
              <div className="threathunter_resultsmodal_breakdown_bar">
                <div 
                  className="threathunter_resultsmodal_breakdown_progress" 
                  style={{ width: `${threatPoints / 0.7}%`, backgroundColor: '#4caf50' }}
                ></div>
              </div>
              <div className="threathunter_resultsmodal_breakdown_value">+{threatPoints}</div>
            </div>
            
            <div className="threathunter_resultsmodal_breakdown_item">
              <div className="threathunter_resultsmodal_breakdown_label">Evidence Quality</div>
              <div className="threathunter_resultsmodal_breakdown_bar">
                <div 
                  className="threathunter_resultsmodal_breakdown_progress" 
                  style={{ width: `${evidencePoints * 5}%`, backgroundColor: '#2196f3' }}
                ></div>
              </div>
              <div className="threathunter_resultsmodal_breakdown_value">+{evidencePoints}</div>
            </div>
            
            <div className="threathunter_resultsmodal_breakdown_item">
              <div className="threathunter_resultsmodal_breakdown_label">Time Bonus</div>
              <div className="threathunter_resultsmodal_breakdown_bar">
                <div 
                  className="threathunter_resultsmodal_breakdown_progress" 
                  style={{ width: `${timeBonus * 10}%`, backgroundColor: '#9c27b0' }}
                ></div>
              </div>
              <div className="threathunter_resultsmodal_breakdown_value">+{timeBonus}</div>
            </div>
            
            <div className="threathunter_resultsmodal_breakdown_item">
              <div className="threathunter_resultsmodal_breakdown_label">False Positives Penalty</div>
              <div className="threathunter_resultsmodal_breakdown_bar">
                <div 
                  className="threathunter_resultsmodal_breakdown_progress" 
                  style={{ width: `${penaltyPoints / 0.3}%`, backgroundColor: '#f44336' }}
                ></div>
              </div>
              <div className="threathunter_resultsmodal_breakdown_value">-{penaltyPoints}</div>
            </div>
            
            <div className="threathunter_resultsmodal_breakdown_total">
              <div className="threathunter_resultsmodal_breakdown_label">Total Score</div>
              <div className="threathunter_resultsmodal_breakdown_value">{score}</div>
            </div>
          </div>
        </div>
        
        <div className="threathunter_resultsmodal_rewards_summary">
          <div className="threathunter_resultsmodal_reward_item">
            <div className="threathunter_resultsmodal_reward_value">+{xpAwarded}</div>
            <div className="threathunter_resultsmodal_reward_label">XP</div>
          </div>
          <div className="threathunter_resultsmodal_reward_item">
            <div className="threathunter_resultsmodal_reward_value">+{coinsAwarded}</div>
            <div className="threathunter_resultsmodal_reward_label">Coins</div>
          </div>
        </div>
        
        {/* New section for evidence details */}
        <div className="threathunter_resultsmodal_evidence_details">
          <h3>Evidence Details</h3>
          <div className="threathunter_resultsmodal_evidence_container">
            {correctlyFlaggedLines.length > 0 ? (
              <div className="threathunter_resultsmodal_evidence_section">
                <h4>Correctly Flagged Log Lines</h4>
                <div className="threathunter_resultsmodal_evidence_list">
                  {correctlyFlaggedLines.map((line, index) => (
                    <div key={`correct-${index}`} className="threathunter_resultsmodal_evidence_item correct">
                      <FaFlag className="threathunter_resultsmodal_evidence_icon" />
                      <div className="threathunter_resultsmodal_evidence_details">
                        <span className="threathunter_resultsmodal_evidence_source">
                          {line.logName || `Log ${line.logId}`} - Line {line.lineIndex + 1}
                        </span>
                        <span className="threathunter_resultsmodal_evidence_content">
                          {line.content}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
            
            {missedFlaggedLines.length > 0 ? (
              <div className="threathunter_resultsmodal_evidence_section">
                <h4>Missed Suspicious Lines</h4>
                <div className="threathunter_resultsmodal_evidence_list">
                  {missedFlaggedLines.map((line, index) => (
                    <div key={`missed-${index}`} className="threathunter_resultsmodal_evidence_item missed">
                      <FaTimes className="threathunter_resultsmodal_evidence_icon" />
                      <div className="threathunter_resultsmodal_evidence_details">
                        <span className="threathunter_resultsmodal_evidence_source">
                          {line.logName || `Log ${line.logId}`} - Line {line.lineIndex + 1}
                        </span>
                        <span className="threathunter_resultsmodal_evidence_content">
                          {line.content}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        </div>
        
        {newAchievements && newAchievements.length > 0 && (
          <div className="threathunter_resultsmodal_new_achievements">
            <h3>Achievements Unlocked!</h3>
            
            <div className="threathunter_resultsmodal_achievements_list">
              {newAchievements.map((achievement, index) => (
                <div key={index} className="threathunter_resultsmodal_achievement_item">
                  <div className="threathunter_resultsmodal_achievement_icon">
                    <FaTrophy />
                  </div>
                  <div className="threathunter_resultsmodal_achievement_details">
                    <div className="threathunter_resultsmodal_achievement_name">{achievement.name}</div>
                    <div className="threathunter_resultsmodal_achievement_description">{achievement.description}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
        
        <div className="threathunter_resultsmodal_detection_details">
          <div className="threathunter_resultsmodal_details_section">
            <h3>Correctly Identified Threats</h3>
            {correctThreats.length > 0 ? (
              <ul className="threathunter_resultsmodal_threats_list correct">
                {correctThreats.map((threat, index) => (
                  <li key={index} className="threathunter_resultsmodal_threat_item">
                    <FaCheck className="threathunter_resultsmodal_threat_icon correct" />
                    <div className="threathunter_resultsmodal_threat_info">
                      <div className="threathunter_resultsmodal_threat_name">{threat.name}</div>
                      <div className="threathunter_resultsmodal_threat_description">{threat.description}</div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="threathunter_resultsmodal_no_threats">No threats were correctly identified.</p>
            )}
          </div>
          
          {missedThreats.length > 0 && (
            <div className="threathunter_resultsmodal_details_section">
              <h3>Missed Threats</h3>
              <ul className="threathunter_resultsmodal_threats_list missed">
                {missedThreats.map((threat, index) => (
                  <li key={index} className="threathunter_resultsmodal_threat_item">
                    <FaTimes className="threathunter_resultsmodal_threat_icon missed" />
                    <div className="threathunter_resultsmodal_threat_info">
                      <div className="threathunter_resultsmodal_threat_name">{threat.name}</div>
                      <div className="threathunter_resultsmodal_threat_description">{threat.description}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {falsePositives.length > 0 && (
            <div className="threathunter_resultsmodal_details_section">
              <h3>False Positives</h3>
              <ul className="threathunter_resultsmodal_threats_list false">
                {falsePositives.map((threat, index) => (
                  <li key={index} className="threathunter_resultsmodal_threat_item">
                    <FaExclamationTriangle className="threathunter_resultsmodal_threat_icon false" />
                    <div className="threathunter_resultsmodal_threat_info">
                      <div className="threathunter_resultsmodal_threat_name">{threat.name || threat.type}</div>
                      <div className="threathunter_resultsmodal_threat_description">{threat.description}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
        
        <div className="threathunter_resultsmodal_feedback_section">
          <h3>Analysis Feedback</h3>
          <p>{feedback}</p>
        </div>
        
        <div className="threathunter_resultsmodal_actions">
          <button className="threathunter_resultsmodal_restart_button" onClick={onRestart}>
            <FaRedo /> Try Again
          </button>
          <button className="threathunter_resultsmodal_home_button" onClick={onClose}>
            <FaHome /> Choose New Scenario
          </button>
          
          <div className="threathunter_resultsmodal_share_container">
            <span>Share your results:</span>
            <a 
              href="https://twitter.com" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="threathunter_resultsmodal_twitter_share"
            >
              <FaXTwitter />
            </a>
            <a 
              href="https://linkedin.com" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="threathunter_resultsmodal_linkedin_share"
            >
              <FaLinkedin />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};  
export default ThreatResultsModal;
