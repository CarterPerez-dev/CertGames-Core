// src/components/pages/games/ThreatHunter/ThreatHunter.js
import React, { useState, useEffect, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { 
  fetchLogScenarios, 
  startScenario, 
  submitAnalysis,
  resetGame
} from '../../store/slice/threatHunterSlice';
import SubscriptionErrorHandler from '../../../SubscriptionErrorHandler';
import { 
  FaSearch, 
  FaFileAlt, 
  FaChartLine, 
  FaExclamationTriangle, 
  FaInfoCircle, 
  FaTrophy,
  FaArrowLeft,
  FaHourglassHalf,
  FaTimesCircle,
  FaCoins,
  FaStar
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
  const { userId, coins, xp } = useSelector(state => state.user);
  
  const subscriptionErrorHandler = SubscriptionErrorHandler();
  
  const [selectedThreatType, setSelectedThreatType] = useState('all');
  const [selectedDifficulty, setSelectedDifficulty] = useState('all'); // Changed from 'medium' to 'all'
  const [showResults, setShowResults] = useState(false);
  const [showInstructions, setShowInstructions] = useState(false);
  const [flaggedLines, setFlaggedLines] = useState({});
  const [detectedThreats, setDetectedThreats] = useState([]);
  const [currentTimeLeft, setCurrentTimeLeft] = useState(null);
  const [timerRunning, setTimerRunning] = useState(false);
  const [shuffledThreatOptions, setShuffledThreatOptions] = useState([]); // New state for shuffled threats
  const [localLoading, setLoading] = useState(false);
  const [localError, setError] = useState(null);
  
  // Utility function to shuffle arrays
  const shuffleArray = (array) => {
    const arrayCopy = [...array];
    for (let i = arrayCopy.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arrayCopy[i], arrayCopy[j]] = [arrayCopy[j], arrayCopy[i]];
    }
    return arrayCopy;
  };
  
  // Debug logs - for development only
  useEffect(() => {
    if (currentScenario && currentScenario.logs) {
      console.log('Current scenario logs:', currentScenario.logs);
    }
  }, [currentScenario]);
  
  // Fetch log scenarios when component mounts
  useEffect(() => {
    if (scenarios.length === 0) {
      setLoading(true); // You should have a local loading state in your component
      dispatch(fetchLogScenarios())
        .unwrap() // This converts the Redux promise to a regular promise
        .then((data) => {
          // Success handling if needed
          setLoading(false);
        })
        .catch((error) => {
          // Check if this is a subscription error
          if (!subscriptionErrorHandler.handleApiError(error, 'threat-hunter')) {
            // Only set error state if not a subscription error
            setError("Failed to fetch scenarios. Please try again.");
          }
          setLoading(false);
        });
    }
  }, [dispatch, scenarios.length, subscriptionErrorHandler]);
  
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
  
  // Shuffle threat options when scenario changes
  useEffect(() => {
    if (currentScenario && currentScenario.threatOptions) {
      setShuffledThreatOptions(shuffleArray(currentScenario.threatOptions));
    }
  }, [currentScenario?.id]);
  
  const handleStartScenario = (scenarioId) => {
    dispatch(startScenario({ 
      scenarioId, 
      userId,
      difficulty: selectedDifficulty
    }));
    
    // Reset state for new game
    setFlaggedLines({});
    setDetectedThreats([]);
    setCurrentTimeLeft(null);
  };
  
  const handleLogSelection = (logId) => {
    // If we need to track which log file is being viewed
    // This would be implemented in the Redux slice
  };
  
  const handleLineFlagging = (logId, lineNumber) => {
    setFlaggedLines(prevState => {
      const logLines = prevState[logId] || [];
      
      if (logLines.includes(lineNumber)) {
        // Remove the line if already flagged
        return {
          ...prevState,
          [logId]: logLines.filter(line => line !== lineNumber)
        };
      } else {
        // Add the line if not flagged
        return {
          ...prevState,
          [logId]: [...(logLines || []), lineNumber]
        };
      }
    });
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
    // Add null check for currentScenario
    if (!currentScenario) {
      console.warn('Cannot submit analysis: currentScenario is null');
      return;
    }
    
    // Create a flattened array of flagged lines with log IDs for the backend
    const flattenedFlaggedLines = [];
    Object.entries(flaggedLines).forEach(([logId, lines]) => {
      lines.forEach(lineIndex => {
        flattenedFlaggedLines.push({ logId, lineIndex });
      });
    });
    
    dispatch(submitAnalysis({
      userId,
      scenarioId: currentScenario.id,
      flaggedLines: flattenedFlaggedLines,
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
    // First clear local state
    setFlaggedLines({});
    setDetectedThreats([]);
    setShowResults(false);
  
    // Then reset the redux store state
    dispatch(resetGame());
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
      setFlaggedLines({});
      setDetectedThreats([]);
    }
  };
  
  // Define difficulty mapping
  const difficultyMapping = {
    'easy': 1,
    'medium': 2,
    'hard': 3
  };
  
  // Apply both filters: threat type and difficulty
  let filteredScenarios = scenarios;
  
  // Filter by threat type if not 'all'
  if (selectedThreatType !== 'all') {
    filteredScenarios = filteredScenarios.filter(scenario => scenario.threatType === selectedThreatType);
  }
  
  // Filter by difficulty if not 'all'
  if (selectedDifficulty !== 'all') {
    const difficultyValue = difficultyMapping[selectedDifficulty];
    filteredScenarios = filteredScenarios.filter(scenario => scenario.difficulty === difficultyValue);
  }
  
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
              
              {/* User stats display */}
              <div className="threat-hunter-user-stats">
                <div className="threat-hunter-stat">
                  <FaCoins className="threat-hunter-stat-icon" />
                  <span>{coins}</span>
                </div>
                <div className="threat-hunter-stat">
                  <FaStar className="threat-hunter-stat-icon" />
                  <span>{xp}</span>
                </div>
              </div>
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
              
              {/* User stats display */}
              <div className="threat-hunter-user-stats">
                <div className="threat-hunter-stat">
                  <FaCoins className="threat-hunter-stat-icon" />
                  <span>{coins}</span>
                </div>
                <div className="threat-hunter-stat">
                  <FaStar className="threat-hunter-stat-icon" />
                  <span>{xp}</span>
                </div>
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
                logs={scenarioLogs || []}
                selectedLog={selectedLog}
                flaggedLines={flaggedLines || {}}
                onSelectLog={handleLogSelection}
                onFlagLine={handleLineFlagging}
              />
              
              <div className="analysis-panel">
                <AnalysisTools 
                  scenario={{
                    ...currentScenario,
                    threatOptions: shuffledThreatOptions // Use shuffled threat options
                  }}
                  detectedThreats={detectedThreats}
                  onDetectThreat={handleThreatDetection}
                  onRemoveThreat={handleThreatRemoval}
                />
                
                <ThreatControls 
                  timeLeft={currentTimeLeft || 0}
                  flaggedLines={Object.values(flaggedLines).flat() || []}
                  detectedThreats={detectedThreats || []}
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
      {subscriptionErrorHandler.render()}
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
            setFlaggedLines({});
            setDetectedThreats([]);
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
