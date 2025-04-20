// src/components/pages/games/ThreatHunter/ThreatHunter.js
import React, { useState, useEffect, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { 
  fetchLogScenarios, 
  startScenario, 
  submitAnalysis,
  resetGame
} from '../../store/slice/threatHunterSlice';
import { 
  FaSearch, 
  FaFileAlt, 
  FaChartLine, 
  FaExclamationTriangle, 
  FaInfoCircle, 
  FaTrophy,
  FaArrowLeft,
  FaHourglassHalf,
  FaTimesCircle 
} from 'react-icons/fa';
import LogViewer from './LogViewer';
import AnalysisTools from './AnalysisTools';
import ThreatControls from './ThreatControls';
import ScenarioSelector from './ScenarioSelector';
import ThreatResultsModal from './ThreatResultsModal';
import GameInstructions from './GameInstructions';
import './ThreatHunter.css';

const ThreatHunter = () => {
  const dispatch = useDispatch();
  const { 
    scenarios, 
    currentScenario,
    gameStatus,
    selectedLog,
    timeLeft,
    score,
    results,
    loading, 
    error 
  } = useSelector(state => state.threatHunter);
  const { userId } = useSelector(state => state.user);
  
  const [selectedThreatType, setSelectedThreatType] = useState('all');
  const [selectedDifficulty, setSelectedDifficulty] = useState('medium');
  const [showResults, setShowResults] = useState(false);
  const [showInstructions, setShowInstructions] = useState(false);
  const [flaggedLines, setFlaggedLines] = useState([]);
  const [detectedThreats, setDetectedThreats] = useState([]);
  const [currentTimeLeft, setCurrentTimeLeft] = useState(null);
  const [timerRunning, setTimerRunning] = useState(false);
  
  // Debug logs - for development only
  useEffect(() => {
    if (currentScenario && currentScenario.logs) {
      console.log('Current scenario logs:', currentScenario.logs);
    }
  }, [currentScenario]);
  
  // Fetch log scenarios when component mounts
  useEffect(() => {
    if (scenarios.length === 0) {
      dispatch(fetchLogScenarios());
    }
  }, [dispatch, scenarios.length]);
  
  // Show results modal when game is completed
  useEffect(() => {
    if (gameStatus === 'completed' && results) {
      setShowResults(true);
      setTimerRunning(false);
    }
  }, [gameStatus, results]);
  
  // Timer functionality
  useEffect(() => {
    if (timeLeft !== null && timeLeft !== undefined) {
      setCurrentTimeLeft(timeLeft);
      setTimerRunning(true);
    }
  }, [timeLeft]);
  
  // Timer countdown
  useEffect(() => {
    let timer;
    if (timerRunning && currentTimeLeft > 0) {
      timer = setTimeout(() => {
        setCurrentTimeLeft(prevTime => {
          if (prevTime <= 1) {
            // Auto-submit when time runs out
            handleSubmitAnalysis();
            return 0;
          }
          return prevTime - 1;
        });
      }, 1000);
    } else if (currentTimeLeft <= 0 && timerRunning) {
      setTimerRunning(false);
      handleSubmitAnalysis();
    }
    
    return () => {
      clearTimeout(timer);
    };
  }, [timerRunning, currentTimeLeft]);
  
  const handleStartScenario = (scenarioId) => {
    dispatch(startScenario({ 
      scenarioId, 
      userId,
      difficulty: selectedDifficulty
    }));
    
    // Reset state for new game
    setFlaggedLines([]);
    setDetectedThreats([]);
    setCurrentTimeLeft(null);
  };
  
  const handleLogSelection = (logId) => {
    // If we need to track which log file is being viewed
    // This would be implemented in the Redux slice
  };
  
  const handleLineFlagging = (lineNumber) => {
    // Toggle flagging for this line
    if (flaggedLines.includes(lineNumber)) {
      setFlaggedLines(flaggedLines.filter(line => line !== lineNumber));
    } else {
      setFlaggedLines([...flaggedLines, lineNumber]);
    }
  };
  
  const handleThreatDetection = (threat) => {
    // Either add or update a threat
    const existingIndex = detectedThreats.findIndex(t => t.id === threat.id);
    
    if (existingIndex >= 0) {
      const updatedThreats = [...detectedThreats];
      updatedThreats[existingIndex] = threat;
      setDetectedThreats(updatedThreats);
    } else {
      setDetectedThreats([...detectedThreats, threat]);
    }
  };
  
  const handleThreatRemoval = (threatId) => {
    setDetectedThreats(detectedThreats.filter(t => t.id !== threatId));
  };
  
  const handleSubmitAnalysis = useCallback(() => {
    // FIXED: Remove this check to allow submission even with no threats
    // if (detectedThreats.length === 0) return;
    
    dispatch(submitAnalysis({
      userId,
      scenarioId: currentScenario.id,
      flaggedLines,
      detectedThreats,
      timeLeft: currentTimeLeft
    }));
  }, [dispatch, userId, currentScenario, flaggedLines, detectedThreats, currentTimeLeft]);
  
  const handleDifficultyChange = (difficulty) => {
    setSelectedDifficulty(difficulty);
  };
  
  const handleThreatTypeChange = (type) => {
    setSelectedThreatType(type);
  };
  
  const handleRestart = () => {
    dispatch(resetGame());
    setShowResults(false);
    // Clear local state to ensure clean restart
    setFlaggedLines([]);
    setDetectedThreats([]);
  };
  
  const handleEarlyEnd = () => {
    if (window.confirm('Are you sure you want to end the analysis early? Your current findings will be submitted.')) {
      handleSubmitAnalysis();
    }
  };
  
  const handleReturnToSelector = () => {
    if (window.confirm('Are you sure you want to return to the scenario selection? Your current progress will be lost.')) {
      dispatch(resetGame());
      // Clear local state as well
      setFlaggedLines([]);
      setDetectedThreats([]);
    }
  };
  
  // Filter scenarios based on selected threat type
  const filteredScenarios = selectedThreatType === 'all' 
    ? scenarios 
    : scenarios.filter(scenario => scenario.threatType === selectedThreatType);
  
  // Ensure the logs have content arrays
  const getScenarioLogs = () => {
    if (!currentScenario || !currentScenario.logs) {
      return [];
    }
    
    // Return logs with verified content arrays
    return currentScenario.logs.map(log => {
      if (!log.content || !Array.isArray(log.content)) {
        // If content is missing or not an array, create an empty array
        return { ...log, content: [] };
      }
      return log;
    });
  };
  
  // Render different views based on game status
  const renderGameContent = () => {
    switch (gameStatus) {
      case 'selecting':
        return (
          <>
            <div className="threat-hunter-toolbar">
              <button 
                className="threat-hunter-help-button"
                onClick={() => setShowInstructions(true)}
              >
                <FaInfoCircle /> How to Play
              </button>
            </div>
            
            <ScenarioSelector 
              scenarios={filteredScenarios}
              selectedType={selectedThreatType}
              selectedDifficulty={selectedDifficulty}
              onThreatTypeChange={handleThreatTypeChange}
              onDifficultyChange={handleDifficultyChange}
              onSelectScenario={handleStartScenario}
              threatTypes={['all', 'malware', 'intrusion', 'data_exfiltration', 'credential_theft', 'ddos']}
            />
          </>
        );
        
      case 'playing':
        const scenarioLogs = getScenarioLogs();
        
        return (
          <div className="threat-hunter-gameplay">
            <div className="threat-hunter-toolbar">
              <button 
                className="threat-hunter-back-button"
                onClick={handleReturnToSelector}
              >
                <FaArrowLeft /> Back to Scenarios
              </button>
              
              <div className="threat-hunter-timer">
                <FaHourglassHalf />
                <span className={currentTimeLeft < 60 ? 'urgent' : ''}>
                  {Math.floor(currentTimeLeft / 60)}:
                  {(currentTimeLeft % 60).toString().padStart(2, '0')}
                </span>
              </div>
              
              <button 
                className="threat-hunter-help-button"
                onClick={() => setShowInstructions(true)}
              >
                <FaInfoCircle /> How to Play
              </button>
              
              <button 
                className="threat-hunter-end-button"
                onClick={handleEarlyEnd}
              >
                <FaTimesCircle /> End Analysis
              </button>
            </div>
            
            <div className="log-analysis-container">
              <LogViewer 
                logs={scenarioLogs}
                selectedLog={selectedLog}
                flaggedLines={flaggedLines}
                onSelectLog={handleLogSelection}
                onFlagLine={handleLineFlagging}
              />
              
              <div className="analysis-panel">
                <AnalysisTools 
                  scenario={currentScenario}
                  detectedThreats={detectedThreats}
                  onDetectThreat={handleThreatDetection}
                  onRemoveThreat={handleThreatRemoval}
                />
                
                <ThreatControls 
                  timeLeft={currentTimeLeft}
                  flaggedLines={flaggedLines}
                  detectedThreats={detectedThreats}
                  onSubmit={handleSubmitAnalysis}
                />
              </div>
            </div>
          </div>
        );
        
      default:
        return null;
    }
  };
  
  if (loading && scenarios.length === 0) {
    return <div className="threat-hunter-loading">Loading log scenarios...</div>;
  }
  
  if (error) {
    return <div className="threat-hunter-error">Error: {error}</div>;
  }
  
  return (
    <div className="threat-hunter-container">
      <div className="threat-hunter-header">
        <h1><FaSearch /> Threat Hunter</h1>
        <p>Analyze logs, detect suspicious patterns, and identify security threats.</p>
      </div>
      
      <div className="threat-hunter-content">
        {renderGameContent()}
      </div>
      
      {showResults && (
        <ThreatResultsModal 
          results={results}
          scenario={currentScenario}
          onClose={() => {
            setShowResults(false);
            dispatch(resetGame());
          }}
          onRestart={handleRestart}
        />
      )}
      
      {showInstructions && (
        <GameInstructions
          onClose={() => setShowInstructions(false)}
        />
      )}
    </div>
  );
};

export default ThreatHunter;
