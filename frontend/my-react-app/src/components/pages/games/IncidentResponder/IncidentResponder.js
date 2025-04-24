// src/components/pages/games/IncidentResponder/IncidentResponder.js
import React, { useState, useEffect, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { 
  fetchScenarios,
  startScenario,
  selectAction,
  resetGame,
  fetchBookmarks,
  toggleBookmark,
} from '../../store/slice/incidentResponderSlice';
import { FaShieldAlt, FaBug, FaExclamationTriangle, FaAward, FaClipboardCheck, FaStar, FaCoins, FaArrowLeft, FaTimes, FaVolumeUp, FaVolumeMute, FaBookmark, FaInfoCircle, FaRegBookmark } from 'react-icons/fa';
import ScenarioIntro from './ScenarioIntro';
import ScenarioStage from './ScenarioStage';
import ScenarioResults from './ScenarioResults';
import DifficultySelector from './DifficultySelector';
import './IncidentResponder.css';

import themeMusic from '../../theme.mp3';

const IncidentResponder = () => {
  const dispatch = useDispatch();
  const { 
    scenarios, 
    currentScenario,
    currentStage,
    selectedActions,
    gameStatus,
    score,
    results,
    loading, 
    error,
    bookmarkedScenarios = [] // Get bookmarked scenarios from redux store
  } = useSelector(state => state.incidentResponder);
  
  const { userId, coins, xp } = useSelector(state => state.user);
  
  const [scenarioTypes, setScenarioTypes] = useState([]);
  const [selectedType, setSelectedType] = useState('all');
  const [selectedDifficulty, setSelectedDifficulty] = useState('all');
  const [showBookmarked, setShowBookmarked] = useState(false);
  const [showInstructions, setShowInstructions] = useState(false);
  
  // Audio state
  const [isMuted, setIsMuted] = useState(false);
  const audioRef = useRef(null);
  
  // Fetch scenarios when component mounts
  useEffect(() => {
    if (scenarios.length === 0) {
      dispatch(fetchScenarios());
    }
  }, [dispatch, scenarios.length]);
  
  // Extract unique scenario types when scenarios are loaded
  useEffect(() => {
    if (scenarios.length > 0) {
      const types = ['all', ...new Set(scenarios.map(scenario => scenario.type))];
      setScenarioTypes(types);
    }
  }, [scenarios]);
  
  // Music control based on game status
  useEffect(() => {
    // Create audio element if it doesn't exist
    if (!audioRef.current) {
      audioRef.current = new Audio(themeMusic);
      audioRef.current.loop = true;
    }
    
    // Play music when game status is 'playing' or 'intro'
    if (gameStatus === 'playing' || gameStatus === 'intro') {
      if (!isMuted && audioRef.current) {
        audioRef.current.play().catch(error => {
          console.log('Audio play failed:', error);
        });
      }
    } else {
      // Add a safety check before trying to pause
      if (audioRef.current) {
        audioRef.current.pause();
        audioRef.current.currentTime = 0;
      }
    }
    
    // Cleanup function
    return () => {
      if (audioRef.current) {
        audioRef.current.pause();
        audioRef.current.currentTime = 0;
      }
    };
  }, [gameStatus, isMuted]);
  
  // Fetch bookmarks when user ID changes
  useEffect(() => {
    if (userId) {
      dispatch(fetchBookmarks(userId));
    }
  }, [dispatch, userId]);
  
  // Handle mute/unmute
  const toggleMute = () => {
    setIsMuted(!isMuted);
    if (audioRef.current) {
      if (isMuted) {
        // Unmuting
        if (gameStatus === 'playing' || gameStatus === 'intro') {
          audioRef.current.play().catch(error => {
            console.log('Audio play failed:', error);
          });
        }
      } else {
        // Muting
        audioRef.current.pause();
      }
    }
  };

  const handleToggleBookmark = (scenarioId, e) => {
    e.stopPropagation();
    dispatch(toggleBookmark({ userId, scenarioId }));
  };
  
  const handleStartScenario = (scenarioId) => {
    console.log("Starting scenario with ID:", scenarioId);
    dispatch(startScenario({ 
      scenarioId, 
      userId,
      difficulty: selectedDifficulty === 'all' ? 'medium' : selectedDifficulty
    }));
  };
  
  const handleSelectAction = (actionId) => {
    dispatch(selectAction({ 
      actionId, 
      stageId: currentStage.id,
      userId 
    }));
  };
  
  const handleRestart = () => {
    dispatch(resetGame());
  };
  
  const handleTypeChange = (type) => {
    setSelectedType(type);
  };
  
  const handleDifficultyChange = (difficulty) => {
    setSelectedDifficulty(difficulty);
  };
  
  const handleBackToMenu = () => {
    if (window.confirm('Are you sure you want to abandon this incident response? Your progress will be lost.')) {
      dispatch(resetGame());
    }
  };
   
  // Define difficulty mapping
  const difficultyMapping = {
    'easy': 1,
    'medium': 2,
    'hard': 3
  };
  
  // Filter scenarios based on all criteria
  let filteredScenarios = scenarios;
 
  // Filter by bookmarked if enabled
  if (showBookmarked) {
    filteredScenarios = filteredScenarios.filter(scenario => 
      bookmarkedScenarios.includes(scenario.id)
    );
  }
  
  // Filter by type if not 'all'
  if (selectedType !== 'all') {
    filteredScenarios = filteredScenarios.filter(scenario => scenario.type === selectedType);
  }
  
  // Filter by difficulty if not 'all'
  if (selectedDifficulty !== 'all') {
    const difficultyValue = difficultyMapping[selectedDifficulty];
    filteredScenarios = filteredScenarios.filter(scenario => scenario.difficulty === difficultyValue);
  }
  
  // Render different views based on game status
  const renderGameContent = () => {
    switch (gameStatus) {
      case 'selecting':
        return (
          <>
            <div className="incidentresponder_scenario_selection_container">
              <div className="incidentresponder_selection_header_block">
                <h2>Select an Incident Scenario</h2>
                <p>Test your incident response skills by handling various security incidents.</p>
              </div>
              
              <div className="incidentresponder_scenario_filters_section">
                <div className="incidentresponder_type_filter_group">
                  <h3>Incident Type</h3>
                  <div className="incidentresponder_type_buttons_row">
                    {scenarioTypes.map(type => (
                      <button
                        key={type}
                        className={selectedType === type ? 'active' : ''}
                        onClick={() => handleTypeChange(type)}
                      >
                        {type.charAt(0).toUpperCase() + type.slice(1)}
                      </button>
                    ))}
                  </div>
                </div>
                
                {/* Bookmark filter */}
                <div className="incidentresponder_bookmark_filter">
                  <button
                    className={`incidentresponder_bookmark_filter_button ${showBookmarked ? 'active' : ''}`}
                    onClick={() => setShowBookmarked(!showBookmarked)}
                  >
                    <FaBookmark /> {showBookmarked ? 'Show All Scenarios' : 'Show Bookmarked Only'}
                  </button>
                </div>
                
                <DifficultySelector 
                  selectedDifficulty={selectedDifficulty}
                  onDifficultyChange={handleDifficultyChange}
                />
              </div>
              
              <div className="incidentresponder_scenarios_grid">
                {filteredScenarios.length > 0 ? (
                  filteredScenarios.map(scenario => (
                    <div
                      key={scenario.id}
                      className="incidentresponder_scenario_card"
                      onClick={() => handleStartScenario(scenario.id)}
                    >
                      <div className="incidentresponder_scenario_icon_wrapper">
                        {scenario.type === 'malware' && <FaBug />}
                        {scenario.type === 'breach' && <FaExclamationTriangle />}
                        {scenario.type === 'phishing' && <FaShieldAlt />}
                        {!['malware', 'breach', 'phishing'].includes(scenario.type) && <FaClipboardCheck />}
                        
                        {/* Bookmark button */}
                        <button
                          className="incidentresponder_bookmark_button"
                          onClick={(e) => handleToggleBookmark(scenario.id, e)}
                          title={bookmarkedScenarios.includes(scenario.id) ? "Remove bookmark" : "Bookmark this scenario"}
                        >
                          {bookmarkedScenarios.includes(scenario.id) ? <FaBookmark /> : <FaRegBookmark />}
                        </button>
                      </div>
                      <div className="incidentresponder_scenario_info_section">
                        <h3>{scenario.title}</h3>
                        <div className="incidentresponder_scenario_meta_data">
                          <span className="incidentresponder_scenario_type_label">{scenario.type}</span>
                          <span className="incidentresponder_scenario_difficulty_rating">
                            {Array(scenario.difficulty).fill('★').join('')}
                          </span>
                        </div>
                        <p>{scenario.shortDescription}</p>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="incidentresponder_no_scenarios">
                    <p>No scenarios match your selected filters. Try different criteria.</p>
                  </div>
                )}
              </div>
            </div>
          </>
        );
        
      case 'intro':
        return (
          <>
            <div className="incidentresponder_back_button_container">
              <button 
                className="incidentresponder_back_button" 
                onClick={handleBackToMenu}
              >
                <FaArrowLeft /> Back to Scenarios
              </button>
              
              {/* Mute button */}
              <button 
                className="incidentresponder_mute_button" 
                onClick={toggleMute}
                title={isMuted ? "Unmute" : "Mute"}
              >
                {isMuted ? <FaVolumeMute /> : <FaVolumeUp />}
              </button>
            </div>
            <ScenarioIntro 
              scenario={currentScenario} 
              onStart={() => dispatch(selectAction({ actionId: 'start', stageId: 'intro', userId }))}
            />
          </>
        );
        
      case 'playing':
        return (
          <>
            <div className="incidentresponder_back_button_container">
              <button 
                className="incidentresponder_back_button" 
                onClick={handleBackToMenu}
              >
                <FaArrowLeft /> Back to Scenarios
              </button>
              
              {/* Mute button */}
              <button 
                className="incidentresponder_mute_button" 
                onClick={toggleMute}
                title={isMuted ? "Unmute" : "Mute"}
              >
                {isMuted ? <FaVolumeMute /> : <FaVolumeUp />}
              </button>
            </div>
            <ScenarioStage 
              stage={currentStage}
              scenarioTitle={currentScenario?.title}
              selectedActions={selectedActions}
              onSelectAction={handleSelectAction}
              score={score}
              difficulty={selectedDifficulty === 'all' ? 'medium' : selectedDifficulty}
            />
          </>
        );
        
      case 'completed':
        return (
          <ScenarioResults 
            results={results}
            scenario={currentScenario}
            selectedActions={selectedActions}
            score={score}
            onRestart={handleRestart}
          />
        );
        
      default:
        return null;
    }
  };
  
  if (loading && scenarios.length === 0) {
    return <div className="incidentresponder_loading_state">Loading incident scenarios...</div>;
  }
  
  if (error) {
    return <div className="incidentresponder_error_state">Error: {error}</div>;
  }
  
  return (
    <div className="incidentresponder_main_container">
      <div className="incidentresponder_header_section">
        <div className="incidentresponder_header_main">
          <h1><FaShieldAlt /> Incident Responder</h1>
          <p>Test your cybersecurity incident response skills in realistic scenarios</p>
        </div>
        
        {/* User stats display */}
        {userId && (
          <div className="incidentresponder_user_stats">
            <div className="incidentresponder_stat">
              <FaCoins className="incidentresponder_stat_icon coins" />
              <span className="incidentresponder_stat_value">{coins}</span>
            </div>
            <div className="incidentresponder_stat">
              <FaStar className="incidentresponder_stat_icon xp" />
              <span className="incidentresponder_stat_value">{xp}</span>
            </div>
          </div>
        )}
        
      </div>
      
      <div className="incidentresponder_content_area">
        {renderGameContent()}
      </div>
    </div>
  );
};

export default IncidentResponder;
