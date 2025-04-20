// src/components/pages/games/ThreatHunter/ThreatControls.js
import React, { useState, useEffect } from 'react';
import { FaFlag, FaExclamationTriangle, FaClock, FaCheck, FaInfoCircle } from 'react-icons/fa';
import './ThreatHunter.css';

const ThreatControls = ({ timeLeft, flaggedLines, detectedThreats, onSubmit }) => {
  const [timerDisplay, setTimerDisplay] = useState('00:00');
  const [submitEnabled, setSubmitEnabled] = useState(true); // FIXED: Always enable submit
  const [warningMessage, setWarningMessage] = useState('');
  const [tooltipVisible, setTooltipVisible] = useState(false);
  
  // Format time left for display
  useEffect(() => {
    if (timeLeft !== null && timeLeft !== undefined) {
      const minutes = Math.floor(timeLeft / 60);
      const seconds = timeLeft % 60;
      setTimerDisplay(`${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`);
    }
  }, [timeLeft]);
  
  // Check if submission is enabled and set warning message
  useEffect(() => {
    // Show warning if no threats detected, but still enable submission
    if (detectedThreats.length === 0) {
      setWarningMessage('No threats detected yet. You can still submit your analysis, but you may miss points.');
    } else {
      // Reset warning if conditions are met
      setWarningMessage('');
    }
  }, [flaggedLines, detectedThreats]);
  
  const handleSubmitAnalysis = () => {
    if (onSubmit) {
      onSubmit();
    }
  };
  
  const toggleTooltip = () => {
    setTooltipVisible(!tooltipVisible);
  };
  
  return (
    <div className="threathunter_threatcontrols_container">
      <div className="threathunter_threatcontrols_header">
        <h3>Investigation Controls</h3>
        <div className="threathunter_threatcontrols_info">
          <FaInfoCircle 
            onMouseEnter={toggleTooltip}
            onMouseLeave={toggleTooltip}
          />
          {tooltipVisible && (
            <div className="threathunter_threatcontrols_tooltip">
              <p>Flag suspicious log lines and identify threats, then submit your analysis for scoring.</p>
            </div>
          )}
        </div>
      </div>
      
      <div className="threathunter_threatcontrols_content">
        <div className="threathunter_threatcontrols_analysis_status">
          <div className="threathunter_threatcontrols_status_item">
            <div className="threathunter_threatcontrols_status_icon threathunter_threatcontrols_flag_icon">
              <FaFlag />
            </div>
            <div className="threathunter_threatcontrols_status_details">
              <div className="threathunter_threatcontrols_status_value">{flaggedLines.length}</div>
              <div className="threathunter_threatcontrols_status_label">Flagged Lines</div>
            </div>
          </div>
          
          <div className="threathunter_threatcontrols_status_item">
            <div className="threathunter_threatcontrols_status_icon threathunter_threatcontrols_threat_icon">
              <FaExclamationTriangle />
            </div>
            <div className="threathunter_threatcontrols_status_details">
              <div className="threathunter_threatcontrols_status_value">{detectedThreats.length}</div>
              <div className="threathunter_threatcontrols_status_label">Threats Detected</div>
            </div>
          </div>
        </div>
        
        {warningMessage && (
          <div className="threathunter_threatcontrols_submission_warning">
            <FaExclamationTriangle />
            <span>{warningMessage}</span>
          </div>
        )}
        
        <button 
          className="threathunter_threatcontrols_submit_analysis_button"
          onClick={handleSubmitAnalysis}
          disabled={false} // FIXED: Never disable the button
        >
          <FaCheck />
          <span>Submit Analysis</span>
        </button>
        
        <div className="threathunter_threatcontrols_submission_note">
          <p>Submit your analysis when you've identified all threats. Your score will be based on correctly identified threats, evidence quality, and time remaining.</p>
        </div>
      </div>
    </div>
  );
};

export default ThreatControls;
