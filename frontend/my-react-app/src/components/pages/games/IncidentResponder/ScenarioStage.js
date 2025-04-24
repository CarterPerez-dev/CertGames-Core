// src/components/pages/games/IncidentResponder/ScenarioStage.js
import React, { useState, useEffect } from 'react';
import { useSelector } from 'react-redux';
import { FaClipboardCheck, FaExclamationCircle, FaClock, FaTrophy, FaInfoCircle } from 'react-icons/fa';
import './IncidentResponder.css';

const ScenarioStage = ({ 
  stage, 
  scenarioTitle,
  selectedActions,
  onSelectAction,
  score,
  difficulty
}) => {
  const [timeLeft, setTimeLeft] = useState(null);
  const [selectedActionId, setSelectedActionId] = useState(null);
  // Get the showExplanation state from the Redux store
  const showExplanation = useSelector(state => state.incidentResponder.showExplanation);
  
  useEffect(() => {
    // Reset state when stage changes
    setSelectedActionId(null);
    
    // Set timer based on difficulty if this stage has a time limit
    if (stage?.timeLimit) {
      const timeLimits = {
        easy: stage.timeLimit * 1.5,
        medium: stage.timeLimit,
        hard: stage.timeLimit * 0.7
      };
      
      setTimeLeft(Math.round(timeLimits[difficulty] || timeLimits.medium));
    } else {
      setTimeLeft(null);
    }
  }, [stage, difficulty]);
  
  // Timer countdown logic
  useEffect(() => {
    if (timeLeft === null || timeLeft <= 0 || showExplanation) return;
    
    const timer = setTimeout(() => {
      setTimeLeft(timeLeft - 1);
      
      // Auto-select worst action if time runs out
      if (timeLeft === 1) {
        const worstAction = stage.actions.reduce(
          (worst, current) => current.points < worst.points ? current : worst, 
          stage.actions[0]
        );
        handleSelectAction(worstAction.id);
      }
    }, 1000);
    
    return () => clearTimeout(timer);
  }, [timeLeft, showExplanation, stage, onSelectAction]);
  
  if (!stage) return null;
  
  const handleSelectAction = (actionId) => {
    setSelectedActionId(actionId);
    onSelectAction(actionId);
  };
  
  const getActionById = (actionId) => {
    return stage.actions.find(action => action.id === actionId);
  };
  
  const getActionQuality = (points) => {
    const maxPoints = Math.max(...stage.actions.map(action => action.points));
    
    if (points === maxPoints) return 'best';
    if (points >= maxPoints * 0.7) return 'good';
    if (points >= maxPoints * 0.4) return 'fair';
    return 'poor';
  };
  
  // Calculate progress percentage for the progress bar
  const calculateProgress = () => {
    if (!stage || !stage.order || !stage.totalSteps) return 0;
    return (stage.order / stage.totalSteps) * 100;
  };
  
  return (
    <div className="incidentresponder_stage_container">
      <div className="incidentresponder_stage_header">
        <h2>{scenarioTitle}</h2>
        <div className="incidentresponder_stage_meta">
          <div className="incidentresponder_stage_step">
            <FaClipboardCheck />
            <span>Step {stage.order} of {stage.totalSteps}</span>
          </div>
          <div className="incidentresponder_stage_score">
            <FaTrophy />
            <span>Score: {score}</span>
          </div>
          {timeLeft !== null && (
            <div className={`incidentresponder_stage_timer ${timeLeft < 10 ? 'urgent' : ''}`}>
              <FaClock />
              <span>Time: {timeLeft}s</span>
            </div>
          )}
        </div>
      </div>
      
      {/* New Progress Bar */}
      <div className="incidentresponder_progress_container">
        <div 
          className="incidentresponder_progress_bar"
          style={{ width: `${calculateProgress()}%` }}
        />
      </div>
      
      <div className="incidentresponder_stage_situation">
        <div className="incidentresponder_situation_header">
          <FaExclamationCircle />
          <h3>Current Situation</h3>
        </div>
        <p>{stage.situation}</p>
        
        {stage.additionalInfo && (
          <div className="incidentresponder_additional_info">
            <h4><FaInfoCircle /> Additional Information</h4>
            <p>{stage.additionalInfo}</p>
          </div>
        )}
      </div>
      
      {!showExplanation ? (
        <div className="incidentresponder_action_selection">
          <h3>Choose Your Response</h3>
          <div className="incidentresponder_actions_container">
            {stage.actions.map(action => (
              <button
                key={action.id}
                className="incidentresponder_action_button"
                onClick={() => handleSelectAction(action.id)}
                disabled={showExplanation}
              >
                {action.text}
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="incidentresponder_action_explanation">
          {(() => {
            // If selectedActionId is not set but we have selectedActions data for this stage
            // Use that as the fallback
            const effectiveActionId = selectedActionId || selectedActions[stage.id];
            const selectedAction = getActionById(effectiveActionId);
            
            if (!selectedAction) {
              return <div>Error: Could not find selected action.</div>;
            }
            
            const quality = getActionQuality(selectedAction.points);
            
            return (
              <>
                <div className={`incidentresponder_selected_action ${quality}`}>
                  <h3>Your Response:</h3>
                  <p>{selectedAction.text}</p>
                  <div className="incidentresponder_action_result">
                    <div className="incidentresponder_points_awarded">
                      <span className="incidentresponder_points_label">Points:</span>
                      <span className="incidentresponder_points_value">+{selectedAction.points}</span>
                    </div>
                    <div className={`incidentresponder_quality_indicator ${quality}`}>
                      {quality === 'best' && 'EXCELLENT CHOICE'}
                      {quality === 'good' && 'GOOD CHOICE'}
                      {quality === 'fair' && 'ACCEPTABLE'}
                      {quality === 'poor' && 'NEEDS IMPROVEMENT'}
                    </div>
                  </div>
                </div>
                
                <div className="incidentresponder_explanation_container">
                  <h3>Outcome & Explanation</h3>
                  <p>{selectedAction.outcome}</p>
                  <div className="incidentresponder_explanation">
                    <h4>Why this matters:</h4>
                    <p>{selectedAction.explanation}</p>
                  </div>
                  
                  <div className="incidentresponder_best_practice">
                    <h4>Best Practice:</h4>
                    <p>{selectedAction.bestPractice}</p>
                  </div>
                </div>
                
                <div className="incidentresponder_continue_actions">
                  <button 
                    className="incidentresponder_continue_button"
                    onClick={() => onSelectAction('continue')}
                  >
                    Continue
                  </button>
                </div>
              </>
            );
          })()}
        </div>
      )}
    </div>
  );
};

export default ScenarioStage;
