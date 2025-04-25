// src/components/pages/games/CipherChallenge/CipherChallenge.js
import React, { useState, useEffect, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { 
  fetchCipherChallenges, 
  submitSolution, 
  resetCurrentChallenge,
  unlockNextLevel
} from '../../store/slice/cipherChallengeSlice';
import { fetchUserData } from '../../store/slice/userSlice';
import SubscriptionErrorHandler from '../../../SubscriptionErrorHandler';
import { 
  FaLock, 
  FaLockOpen, 
  FaKey, 
  FaQuestionCircle, 
  FaBrain, 
  FaMedal,
  FaArrowLeft, 
  FaCoins,      
  FaStar        
} from 'react-icons/fa';
import CipherDisplay from './CipherDisplay';
import CipherInput from './CipherInput';
import CipherHints from './CipherHints';
import CipherTools from './CipherTools';
import LevelSelector from './LevelSelector';
import CipherInfoModal from './CipherInfoModal';
import CongratulationsModal from './CongratulationsModal';
import './CipherChallenge.css';

const CipherChallenge = () => {
  const subscriptionErrorHandler = SubscriptionErrorHandler();
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { 
    challenges, 
    currentChallenge, 
    completedChallenges, 
    maxUnlockedLevel,
    loading, 
    error,
    hintUsed
  } = useSelector(state => state.cipherChallenge);
  const { userId, coins, xp } = useSelector(state => state.user);

  // Ref to keep track if challenges have been loaded
  const challengesLoaded = useRef(false);
  // Ref to track retry count
  const retryCount = useRef(0);
  
  const [userSolution, setUserSolution] = useState('');
  const [feedbackMessage, setFeedbackMessage] = useState(null);
  const [showInfo, setShowInfo] = useState(false);
  const [activeTool, setActiveTool] = useState(null);
  const [showCongratulations, setShowCongratulations] = useState(false);
  const [congratsData, setCongratsData] = useState(null);
  const [dataRefreshed, setDataRefreshed] = useState(false);
  
  // Load challenges when component mounts
  useEffect(() => {
    if (userId && !challengesLoaded.current) {
      // Set the flag to true immediately to prevent multiple calls
      challengesLoaded.current = true;
      
      const fetchData = () => {
        if (retryCount.current >= 3) {
          console.error("Max retries reached for fetching challenges");
          return;
        }
        
        dispatch(fetchCipherChallenges(userId))
          .then(() => {
            retryCount.current = 0; // Reset retry count on success
            setDataRefreshed(true);
          })
          .catch((error) => {
            if (!subscriptionErrorHandler.handleApiError(error, 'cipher')) {
              console.error("Error fetching challenges:", error);
              retryCount.current += 1;
              // Only reset if we haven't exceeded max retries
              if (retryCount.current < 3) {
                challengesLoaded.current = false;
              }
            }
          });
      };
      
      fetchData();
    }
  }, [dispatch, userId, subscriptionErrorHandler]);
  
  // Reset user solution when current challenge changes
  useEffect(() => {
    setUserSolution('');
    setFeedbackMessage(null);
  }, [currentChallenge]);
  
  // Improved selectNextChallenge function with logging
  const selectNextChallenge = () => {
    if (!currentChallenge || !challenges || challenges.length === 0) {
      console.log("Cannot select next challenge: No current challenge or challenges");
      return false;
    }
    
    // Get all challenges in the current level
    const currentLevelChallenges = challenges
      .filter(c => c.levelId === currentChallenge.levelId)
      .sort((a, b) => a.id - b.id);
    
    // Find the index of the current challenge
    const currentIndex = currentLevelChallenges.findIndex(c => c.id === currentChallenge.id);
    
    // If this is not the last challenge in the level, select the next one
    if (currentIndex < currentLevelChallenges.length - 1) {
      const nextChallenge = currentLevelChallenges[currentIndex + 1];
      dispatch(resetCurrentChallenge(nextChallenge));
      return true;
    }
    
    // If this is the last challenge in the level but not the last level
    if (currentChallenge.levelId < maxUnlockedLevel) {
      // Get the first challenge of the next level
      const nextLevelChallenges = challenges
        .filter(c => c.levelId === currentChallenge.levelId + 1)
        .sort((a, b) => a.id - b.id);
      
      if (nextLevelChallenges.length > 0) {
        const nextChallenge = nextLevelChallenges[0];
        dispatch(resetCurrentChallenge(nextChallenge));
        return true;
      }
    }
    
    return false;
  };
  
  const handleSolutionChange = (value) => {
    setUserSolution(value);
    
    // Clear feedback when user types
    if (feedbackMessage) {
      setFeedbackMessage(null);
    }
  };
  
  const handleSubmitSolution = () => {
    if (!currentChallenge) return;
    
    // Normalize both strings for comparison
    const normalizedUserSolution = userSolution.trim().toLowerCase();
    const normalizedCorrectSolution = currentChallenge.solution.trim().toLowerCase();
    
    if (normalizedUserSolution === normalizedCorrectSolution) {
      // Solution is correct
      const wasAlreadyCompleted = completedChallenges.includes(currentChallenge.id);
      
      // If already completed, don't submit again
      if (wasAlreadyCompleted) {
        setFeedbackMessage({
          type: 'success',
          message: 'Challenge already completed. No additional rewards.'
        });
        return;
      }
      
      // Dispatch action to mark challenge as completed
      dispatch(submitSolution({
        userId,
        challengeId: currentChallenge.id,
        levelId: currentChallenge.levelId,
        hintUsed,
        timeSpent: 0, // TODO: Add timer functionality
      })).then((resultAction) => {
        if (submitSolution.fulfilled.match(resultAction)) {
          // Show success message
          setFeedbackMessage({
            type: 'success',
            message: 'Correct! You\'ve cracked the cipher.'
          });
          
          // Check if this unlocks a new level
          const allChallengesInLevelCompleted = challenges
            .filter(challenge => challenge.levelId === currentChallenge.levelId)
            .every(challenge => 
              completedChallenges.includes(challenge.id) || challenge.id === currentChallenge.id
            );
          
          if (allChallengesInLevelCompleted && currentChallenge.levelId < 5) {
            // Unlock next level
            dispatch(unlockNextLevel(currentChallenge.levelId + 1));
            
            // Show congratulations modal
            setCongratsData({
              levelCompleted: currentChallenge.levelId,
              newLevelUnlocked: currentChallenge.levelId + 1,
              xpEarned: wasAlreadyCompleted ? 0 : currentChallenge.levelId * 50,
              coinsEarned: wasAlreadyCompleted ? 0 : currentChallenge.levelId * 20
            });
            setShowCongratulations(true);
          }
          
          // Refresh challenges list to update completion status
          // Only do this if we haven't already refreshed recently
          if (!dataRefreshed) {
            dispatch(fetchCipherChallenges(userId));
            setDataRefreshed(true);
          }
        }
      });
    } else {
      // Solution is incorrect
      setFeedbackMessage({
        type: 'error',
        message: 'Incorrect solution. Try again!'
      });
    }
  };
  
  const handleSelectLevel = (levelId) => {
    // Find the first uncompleted challenge in the selected level
    const uncompletedChallenge = challenges
      .filter(challenge => challenge.levelId === levelId)
      .find(challenge => !completedChallenges.includes(challenge.id));
    
    if (uncompletedChallenge) {
      dispatch(resetCurrentChallenge(uncompletedChallenge));
    } else {
      // If all challenges in the level are completed, select the first one
      const firstChallengeInLevel = challenges
        .filter(challenge => challenge.levelId === levelId)
        .sort((a, b) => a.id - b.id)[0];
      
      if (firstChallengeInLevel) {
        dispatch(resetCurrentChallenge(firstChallengeInLevel));
      }
    }
  };
  
  const handleSelectChallenge = (challengeId) => {
    const challenge = challenges.find(c => c.id === challengeId);
    if (challenge) {
      dispatch(resetCurrentChallenge(challenge));
    }
  };
  
  const handleToolSelect = (toolName) => {
    setActiveTool(activeTool === toolName ? null : toolName);
  };
  
  const handleCongratulationsClose = () => {
    setShowCongratulations(false);
    selectNextChallenge();
  };
  
  const handleNextChallenge = () => {
    const result = selectNextChallenge();
    
    // Don't fetch again if we've just selected a new challenge
    if (!result && !dataRefreshed) {
      setDataRefreshed(true);
      dispatch(fetchCipherChallenges(userId));
    }
  };
  
  if (loading && challenges.length === 0) {
    return <div className="cipher-loading">Loading cipher challenges...</div>;
  }
  
  if (error) {
    return <div className="cipher-error">Error: {error}</div>;
  }
  
  return (
    <div className="cipher-challenge-container">
      {subscriptionErrorHandler.render()}
      <div className="cipher-header">
        
        <div className="cipher-header-main">
          <h1><FaKey /> Cipher Challenge</h1>
          <p>Decode cryptographic messages and unlock the secrets!</p>
        </div>
        
        {/* User stats display */}
        {userId && (
          <div className="cipher-user-stats">
            <div className="cipher-stat">
              <FaCoins className="cipher-stat-icon coins" />
              <span className="cipher-stat-value">{coins}</span>
            </div>
            <div className="cipher-stat">
              <FaStar className="cipher-stat-icon xp" />
              <span className="cipher-stat-value">{xp}</span>
            </div>
          </div>
        )}
        
        <button 
          className="cipher-info-button"
          onClick={() => setShowInfo(true)}
          aria-label="Show information about cipher types"
        >
          <FaQuestionCircle /> About Ciphers
        </button>
      </div>
      
      <div className="cipher-content">
        <div className="cipher-sidebar">
          <LevelSelector 
            levels={[1, 2, 3, 4, 5]}
            maxUnlockedLevel={maxUnlockedLevel}
            challenges={challenges}
            completedChallenges={completedChallenges}
            currentChallenge={currentChallenge}
            onSelectLevel={handleSelectLevel}
            onSelectChallenge={handleSelectChallenge}
          />
          
          <div className="cipher-tools-container">
            <h3><FaBrain /> Cipher Tools</h3>
            <CipherTools 
              activeTool={activeTool}
              onToolSelect={handleToolSelect}
              cipherType={currentChallenge?.cipherType}
              ciphertext={currentChallenge?.ciphertext || ''}
            />
          </div>
        </div>
        
        <div className="cipher-main">
          {currentChallenge ? (
            <>
              <div className="challenge-header">
                <h2>
                  {completedChallenges.includes(currentChallenge.id) ? (
                    <><FaLockOpen className="unlocked-icon" /> </>
                  ) : (
                    <><FaLock className="locked-icon" /> </>
                  )}
                  {currentChallenge.title}
                </h2>
                <div className="challenge-metadata">
                  <span className="challenge-type">
                    Cipher Type: {currentChallenge.cipherType}
                  </span>
                  <span className="challenge-difficulty">
                    Difficulty: {Array(currentChallenge.difficulty).fill('★').join('')}
                  </span>
                </div>
              </div>
              
              <div className="challenge-description">
                {currentChallenge.description}
              </div>
              
              <CipherDisplay 
                ciphertext={currentChallenge.ciphertext}
                cipherType={currentChallenge.cipherType}
              />
              
              <CipherHints 
                hints={currentChallenge.hints}
                challengeId={currentChallenge.id}
              />
              
              <CipherInput
                value={userSolution}
                onChange={handleSolutionChange}
                onSubmit={handleSubmitSolution}
                onNextChallenge={handleNextChallenge}
                feedback={feedbackMessage}
                isCompleted={completedChallenges.includes(currentChallenge.id)}
              />
              
              {activeTool && (
                <div className="active-tool-display">
                  <h3>{activeTool} Analysis</h3>
                  {/* Tool-specific content rendered by CipherTools component */}
                </div>
              )}
            </>
          ) : (
            <div className="no-challenge-selected">
              <h2>Select a Challenge</h2>
              <p>Choose a cipher challenge from the menu on the left to begin.</p>
              <div className="cipher-introduction">
                <h3><FaMedal /> How to Play</h3>
                <ul>
                  <li>Each challenge presents you with an encoded message.</li>
                  <li>Your task is to decrypt the message and submit the solution.</li>
                  <li>Start with easier ciphers like Caesar and work your way up to more complex ones.</li>
                  <li>Use the provided tools to help analyze the ciphertext.</li>
                  <li>Unlock higher levels by completing challenges.</li>
                  <li>Earn XP and coins for each solved cipher!</li>
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {showInfo && (
        <CipherInfoModal onClose={() => setShowInfo(false)} />
      )}
      
      {showCongratulations && congratsData && (
        <CongratulationsModal 
          data={congratsData}
          onClose={handleCongratulationsClose}
        />
      )}
    </div>
  );
};

export default CipherChallenge;
