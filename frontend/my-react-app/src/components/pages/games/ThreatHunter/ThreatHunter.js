// src/components/pages/games/ThreatHunter/ThreatHunter.js
import React, { useState, useEffect, useCallback, useMemo } from 'react';
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
  FaArrowLeft,
  FaHourglassHalf,
  FaTimesCircle,
  FaCoins,
  FaStar,
  FaInfoCircle
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
  
  // Safely access redux state with fallbacks
  const threatHunterState = useSelector(state => state.threatHunter) || {};
  const scenarios = threatHunterState.scenarios || [];
  const currentScenario = threatHunterState.currentScenario || null;
  const gameStatus = threatHunterState.gameStatus || 'selecting';
  const selectedLog = threatHunterState.selectedLog || null;
  const timeLeft = threatHunterState.timeLeft || null;
  const results = threatHunterState.results || null;
  const loadingState = threatHunterState.loading || false;
  const errorState = threatHunterState.error || null;
  
  const userState = useSelector(state => state.user) || {};
  const userId = userState.userId || null;
  const coins = userState.coins || 0;
  const xp = userState.xp || 0;
  
  // Using useMemo to ensure memoizedErrorHandler is stable across renders
  const memoizedErrorHandler = useMemo(() => SubscriptionErrorHandler(), []);
  
  // Local state
  const [selectedThreatType, setSelectedThreatType] = useState('all');
  const [selectedDifficulty, setSelectedDifficulty] = useState('all');
  const [showResults, setShowResults] = useState(false);
  const [showInstructions, setShowInstructions] = useState(false);
  const [flaggedLines, setFlaggedLines] = useState({});
  const [detectedThreats, setDetectedThreats] = useState([]);
  const [currentTimeLeft, setCurrentTimeLeft] = useState(null);
  const [timerRunning, setTimerRunning] = useState(false);
  const [shuffledThreatOptions, setShuffledThreatOptions] = useState([]);
  const [localLoading, setLocalLoading] = useState(false);
  const [localError, setLocalError] = useState(null);
  
  // Safe array shuffle that handles undefined/null values
  const shuffleArray = useCallback((array) => {
    if (!array || !Array.isArray(array) || array.length === 0) {
      return [];
    }
    
    const arrayCopy = [...array];
    for (let i = arrayCopy.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arrayCopy[i], arrayCopy[j]] = [arrayCopy[j], arrayCopy[i]];
    }
    return arrayCopy;
  }, []);
  
  // Safely memoized submit analysis function
  const handleSubmitAnalysis = useCallback(() => {
    // Skip if not ready to submit
    if (!currentScenario || !userId) {
      console.warn('Cannot submit analysis: missing currentScenario or userId');
      return;
    }
    
    // Create a flattened array of flagged lines with log IDs for the backend
    const flattenedFlaggedLines = [];
    Object.entries(flaggedLines || {}).forEach(([logId, lines]) => {
      if (Array.isArray(lines)) {
        lines.forEach(lineIndex => {
          flattenedFlaggedLines.push({ logId, lineIndex });
        });
      }
    });
    
    dispatch(submitAnalysis({
      userId,
      scenarioId: currentScenario.id,
      flaggedLines: flattenedFlaggedLines,
      detectedThreats: detectedThreats || [],
      timeLeft: currentTimeLeft !== null ? currentTimeLeft : 0
    }));
  }, [dispatch, userId, currentScenario, flaggedLines, detectedThreats, currentTimeLeft]);
  
  // Fetch scenarios only once at mount
  useEffect(() => {
    let mounted = true;
    const shouldFetch = scenarios.length === 0 && !localLoading;
    
    if (shouldFetch) {
      setLocalLoading(true);
      
      dispatch(fetchLogScenarios())
        .unwrap()
        .then(() => {
          if (mounted) setLocalLoading(false);
        })
        .catch((error) => {
          if (mounted) {
            const wasHandled = memoizedErrorHandler && memoizedErrorHandler.handleApiError && 
                              memoizedErrorHandler.handleApiError(error, 'threat-hunter');
            
            if (!wasHandled) {
              setLocalError("Failed to fetch scenarios. Please try again.");
            }
            setLocalLoading(false);
          }
        });
    }
    
    return () => {
      mounted = false;
    };
  }, []); // Empty dependency array to run only once at mount
  
  // Show results modal when game is completed
  useEffect(() => {
    if (gameStatus === 'completed' && results) {
      setShowResults(true);
      setTimerRunning(false);
    }
  }, [gameStatus, results]);
  
  // Timer initialization
  useEffect(() => {
    if (timeLeft !== null && timeLeft !== undefined) {
      setCurrentTimeLeft(timeLeft);
      setTimerRunning(true);
    }
  }, [timeLeft]);
  
  // Timer countdown effect - completely separated from other logic
  useEffect(() => {
    let timer = null;
    
    const runTimer = () => {
      if (timerRunning && currentTimeLeft > 0) {
        timer = setTimeout(() => {
          setCurrentTimeLeft(prev => {
            const newTime = (prev <= 1) ? 0 : prev - 1;
            
            // If time is up, handle submission in the next effect
            if (newTime === 0) {
              setTimerRunning(false);
            }
            
            return newTime;
          });
        }, 1000);
      }
    };
    
    runTimer();
    
    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [timerRunning, currentTimeLeft]);
  
  // Separate effect for handling timer completion
  useEffect(() => {
    if (currentTimeLeft === 0 && !timerRunning && gameStatus === 'playing') {
      // Only call handleSubmitAnalysis if we need to
      handleSubmitAnalysis();
    }
  }, [currentTimeLeft, timerRunning, gameStatus, handleSubmitAnalysis]);
  
  // Safe handling of threat options when scenario changes
  useEffect(() => {
    // Safe access to currentScenario and its properties
    if (currentScenario && 
        currentScenario.threatOptions && 
        Array.isArray(currentScenario.threatOptions)) {
      setShuffledThreatOptions(shuffleArray(currentScenario.threatOptions));
    } else {
      setShuffledThreatOptions([]);
    }
  }, [currentScenario, shuffleArray]);
  
  const handleStartScenario = useCallback((scenarioId) => {
    if (!scenarioId || !userId) return;
    
    dispatch(startScenario({ 
      scenarioId, 
      userId,
      difficulty: selectedDifficulty || 'medium'
    }));
    
    // Reset state for new game
    setFlaggedLines({});
    setDetectedThreats([]);
    setCurrentTimeLeft(null);
  }, [dispatch, userId, selectedDifficulty]);
  
  const handleLogSelection = useCallback((logId) => {
    // If we need to track which log file is being viewed
    // This would be implemented in the Redux slice
  }, []);
  
  const handleLineFlagging = useCallback((logId, lineNumber) => {
    if (!logId || lineNumber === undefined) return;
    
    setFlaggedLines(prevState => {
      const prevLines = prevState[logId] || [];
      
      if (prevLines.includes(lineNumber)) {
        // Remove the line if already flagged
        return {
          ...prevState,
          [logId]: prevLines.filter(line => line !== lineNumber)
        };
      } else {
        // Add the line if not flagged
        return {
          ...prevState,
          [logId]: [...prevLines, lineNumber]
        };
      }
    });
  }, []);
  
  const handleThreatDetection = useCallback((threat) => {
    if (!threat || !threat.id) return;
    
    setDetectedThreats(prevThreats => {
      const existingIndex = prevThreats.findIndex(t => t.id === threat.id);
      
      if (existingIndex >= 0) {
        // Update existing threat
        const updatedThreats = [...prevThreats];
        updatedThreats[existingIndex] = threat;
        return updatedThreats;
      } else {
        // Add new threat
        return [...prevThreats, threat];
      }
    });
  }, []);
  
  const handleThreatRemoval = useCallback((threatId) => {
    if (!threatId) return;
    
    setDetectedThreats(prevThreats => 
      prevThreats.filter(t => t.id !== threatId)
    );
  }, []);
  
  const handleDifficultyChange = useCallback((difficulty) => {
    setSelectedDifficulty(difficulty || 'all');
  }, []);
  
  const handleThreatTypeChange = useCallback((type) => {
    setSelectedThreatType(type || 'all');
  }, []);
  
  const handleRestart = useCallback(() => {
    // First clear local state
    setFlaggedLines({});
    setDetectedThreats([]);
    setShowResults(false);
  
    // Then reset the redux store state
    dispatch(resetGame());
  }, [dispatch]);
  
  const handleEarlyEnd = useCallback(() => {
    if (window.confirm('Are you sure you want to end the analysis early? Your current findings will be submitted.')) {
      handleSubmitAnalysis();
    }
  }, [handleSubmitAnalysis]);
  
  const handleReturnToSelector = useCallback(() => {
    if (window.confirm('Are you sure you want to return to the scenario selection? Your current progress will be lost.')) {
      dispatch(resetGame());
      // Clear local state as well
      setFlaggedLines({});
      setDetectedThreats([]);
    }
  }, [dispatch]);
  
  // Define difficulty mapping
  const difficultyMapping = {
    'easy': 1,
    'medium': 2,
    'hard': 3
  };
  
  // Apply both filters: threat type and difficulty - this logic happens during render
  // so we don't need useEffect or useMemo
  const getFilteredScenarios = () => {
    if (!scenarios || !Array.isArray(scenarios)) return [];
    
    let filtered = [...scenarios];
    
    // Filter by threat type if not 'all'
    if (selectedThreatType && selectedThreatType !== 'all') {
      filtered = filtered.filter(scenario => scenario && scenario.threatType === selectedThreatType);
    }
    
    // Filter by difficulty if not 'all'
    if (selectedDifficulty && selectedDifficulty !== 'all') {
      const difficultyValue = difficultyMapping[selectedDifficulty];
      filtered = filtered.filter(scenario => scenario && scenario.difficulty === difficultyValue);
    }
    
    return filtered;
  };
  
  // Ensure logs have content arrays - computed during render
  const getScenarioLogs = () => {
    if (!currentScenario || !currentScenario.logs || !Array.isArray(currentScenario.logs)) {
      return [];
    }
    
    // Return logs with verified content arrays
    return currentScenario.logs.map(log => {
      if (!log) return { id: 'invalid', content: [] };
      
      if (!log.content || !Array.isArray(log.content)) {
        // If content is missing or not an array, create an empty array
        return { ...log, content: [] };
      }
      return log;
    });
  };
  
  // Safe flattening of flagged lines
  const getFlatFlaggedLines = () => {
    try {
      return Object.values(flaggedLines || {}).flat() || [];
    } catch (error) {
      console.error("Error flattening flagged lines:", error);
      return [];
    }
  };
  
  // Render different views based on game status
  const renderGameContent = () => {
    const filteredScenarios = getFilteredScenarios();
    
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
        const flatFlaggedLines = getFlatFlaggedLines();
        
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
                logs={scenarioLogs}
                selectedLog={selectedLog}
                flaggedLines={flaggedLines || {}}
                onSelectLog={handleLogSelection}
                onFlagLine={handleLineFlagging}
              />
              
              <div className="analysis-panel">
                <AnalysisTools 
                  scenario={currentScenario ? {
                    ...currentScenario,
                    threatOptions: shuffledThreatOptions
                  } : null}
                  detectedThreats={detectedThreats}
                  onDetectThreat={handleThreatDetection}
                  onRemoveThreat={handleThreatRemoval}
                />
                
                <ThreatControls 
                  timeLeft={currentTimeLeft || 0}
                  flaggedLines={flatFlaggedLines}
                  detectedThreats={detectedThreats}
                  onSubmit={handleSubmitAnalysis}
                />
              </div>
            </div>
          </div>
        );
        
      default:
        return (
          <div className="threat-hunter-error">
            <p>Unknown game status: {gameStatus}</p>
            <button onClick={() => dispatch(resetGame())}>Reset Game</button>
          </div>
        );
    }
  };
  
  // Loading state
  if ((loadingState || localLoading) && (!scenarios || scenarios.length === 0)) {
    return <div className="threat-hunter-loading">Loading log scenarios...</div>;
  }
  
  // Error state
  if (errorState || localError) {
    return (
      <div className="threat-hunter-error">
        <p>Error: {errorState || localError}</p>
        <button onClick={() => dispatch(resetGame())}>Try Again</button>
      </div>
    );
  }
  
  return (
    <div className="threat-hunter-container">
      {memoizedErrorHandler && memoizedErrorHandler.render && memoizedErrorHandler.render()}
      
      <div className="threat-hunter-header">
        <h1><FaSearch /> Threat Hunter</h1>
        <p>Analyze logs, detect suspicious patterns, and identify security threats.</p>
      </div>
      
      <div className="threat-hunter-content">
        {renderGameContent()}
      </div>
      
      {showResults && results && (
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
