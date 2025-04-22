// Updated src/components/pages/games/PhishingPhrenzy/PhishingPhrenzy.js
// Modifications to track seen examples for the game over modal
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { FaShieldAlt, FaSkullCrossbones, FaClock, FaTrophy, FaArrowLeft, FaTimesCircle, FaCoins, FaStar } from 'react-icons/fa';
import { 
  startGame, 
  incrementScore, 
  decrementScore, 
  resetGame,
  fetchPhishingData,
  submitGameResults
} from '../../store/slice/phishingPhrenzySlice';
import { fetchUserData } from '../../store/slice/userSlice';
import PhishingCard from './PhishingCard';
import GameOverModal from './GameOverModal';
import './PhishingPhrenzy.css';

const difficultySettings = {
  easy: { 
    timeLimit: 60, 
    penaltyTime: 2,
    bonusTime: 3,
    pointsPerCorrect: 10
  },
  medium: { 
    timeLimit: 45, 
    penaltyTime: 3,
    bonusTime: 2,
    pointsPerCorrect: 15
  },
  hard: { 
    timeLimit: 30, 
    penaltyTime: 5,
    bonusTime: 1,
    pointsPerCorrect: 20
  }
};

const PhishingPhrenzy = () => {
  const dispatch = useDispatch();
  const { phishingItems, score, highScore, loading, error } = useSelector(state => state.phishingPhrenzy);
  const { userId, coins, xp } = useSelector(state => state.user);
  
  // Define distinct game states
  const [gameState, setGameState] = useState('idle'); // 'idle', 'playing', 'gameOver'
  const [currentItem, setCurrentItem] = useState(null);
  const [itemIndex, setItemIndex] = useState(0);
  const [timeLeft, setTimeLeft] = useState(null);
  const [difficulty, setDifficulty] = useState('medium');
  const [feedback, setFeedback] = useState(null);
  const [answered, setAnswered] = useState(false);
  const [streak, setStreak] = useState(0);
  const [showGameOverModal, setShowGameOverModal] = useState(false); // NEW: explicit modal display state
  
  // Track examples the user has seen during the game
  const [seenExamples, setSeenExamples] = useState([]);
  
  // Refs to prevent multiple calls
  const timerRef = useRef(null);
  const scoreSubmittedRef = useRef(false);
  const isEndingGameRef = useRef(false); // NEW: ref to track if game ending is in progress
  
  const settings = difficultySettings[difficulty];
  
  // Load phishing examples when component mounts
  useEffect(() => {
    if (phishingItems.length === 0) {
      dispatch(fetchPhishingData());
    }
    
    // Clean up on unmount
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, [dispatch, phishingItems.length]);
  
  // SIMPLIFIED game over handling - the core fix
  const handleGameOver = useCallback(() => {
    if (isEndingGameRef.current) return; // Prevent duplicate calls
    
    isEndingGameRef.current = true; // Lock to prevent duplicate calls
    
    // First stop the timer
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    
    // Set game state to game over
    setGameState('gameOver');
    
    // Explicitly show the game over modal
    setShowGameOverModal(true);
    
    // Submit score if needed (don't reset anything here)
    if (!scoreSubmittedRef.current && userId) {
      scoreSubmittedRef.current = true;
      
      dispatch(submitGameResults({
        userId,
        score,
        timestamp: new Date().toISOString()
      }));
    }
  }, [dispatch, score, userId]);
  
  // FIXED Timer effect with improved handling
  useEffect(() => {
    if (gameState === 'playing' && timeLeft > 0) {
      // Set up the timer
      timerRef.current = setInterval(() => {
        setTimeLeft(prevTime => {
          if (prevTime <= 1) {
            // Clear interval immediately
            clearInterval(timerRef.current);
            timerRef.current = null;
            
            // Use setTimeout to ensure state updates have settled
            setTimeout(() => {
              handleGameOver();
            }, 50);
            
            return 0;
          }
          return prevTime - 1;
        });
      }, 1000);
    } else if (gameState === 'playing' && timeLeft <= 0) {
      // Explicit check in case we already hit zero
      if (!isEndingGameRef.current) {
        handleGameOver();
      }
    }
    
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, [gameState, timeLeft, handleGameOver]);
  
  // Handle starting a new game
  const startNewGame = useCallback(() => {
    // Reset local state
    setGameState('playing');
    setTimeLeft(settings.timeLimit);
    setItemIndex(0);
    setStreak(0);
    setFeedback(null);
    setAnswered(false);
    setShowGameOverModal(false); // Hide modal
    scoreSubmittedRef.current = false;
    isEndingGameRef.current = false; // Reset lock
    setSeenExamples([]); // Reset seen examples
    
    // Reset Redux state
    dispatch(resetGame());
    
    // Start the game
    dispatch(startGame());
    
    // Set the first item
    if (phishingItems.length > 0) {
      setCurrentItem(phishingItems[0]);
    }
  }, [dispatch, settings.timeLimit, phishingItems]);
  
  // REVISED: Handle manual end game
  const handleEndEarly = useCallback(() => {
    if (isEndingGameRef.current) return;
    
    if (window.confirm('Are you sure you want to end the game? Your current score will be submitted.')) {
      handleGameOver();
    }
  }, [handleGameOver]);
  
  // REVISED: Return to menu
  const handleReturnToMenu = useCallback(() => {
    if (isEndingGameRef.current && gameState !== 'gameOver') return;
    
    if (gameState === 'playing' && !isEndingGameRef.current) {
      if (window.confirm('Are you sure you want to return to the menu? Your progress will be lost.')) {
        // Clean up
        if (timerRef.current) {
          clearInterval(timerRef.current);
          timerRef.current = null;
        }
        
        // Reset state with delay to ensure clean transition
        setTimeout(() => {
          setGameState('idle');
          setShowGameOverModal(false);
          scoreSubmittedRef.current = false;
          isEndingGameRef.current = false;
          setSeenExamples([]); // Clear seen examples
          dispatch(resetGame());
        }, 50);
      }
    } else if (gameState === 'gameOver') {
      // From game over screen, just go back to start
      setTimeout(() => {
        setGameState('idle');
        setShowGameOverModal(false);
        scoreSubmittedRef.current = false;
        isEndingGameRef.current = false;
        setSeenExamples([]); // Clear seen examples
        dispatch(resetGame());
      }, 50);
    }
  }, [gameState, dispatch]);
  
  // REVISED: Play again handler for the game over modal
  const handlePlayAgain = useCallback(() => {
    startNewGame();
  }, [startNewGame]);
  
  // Handle answering a question
  const handleAnswer = useCallback((answer) => {
    if (answered || !currentItem || gameState !== 'playing') return;
    
    setAnswered(true);
    const isCorrect = answer === currentItem.isPhishing;
    
    // Add current item to seen examples for end-game summary
    if (currentItem.name && currentItem.reason) {
      setSeenExamples(prev => [...prev, {
        name: currentItem.name,
        reason: currentItem.reason,
        isPhishing: currentItem.isPhishing,
        userCorrect: isCorrect
      }]);
    }
    
    if (isCorrect) {
      dispatch(incrementScore(settings.pointsPerCorrect));
      setFeedback({
        type: 'correct',
        message: `+${settings.pointsPerCorrect} points! ${currentItem.isPhishing ? 'This was phishing!' : 'This was legitimate!'}`
      });
      
      // Handle streak
      setStreak(prev => {
        const newStreak = prev + 1;
        
        // Add bonus time if on a streak
        if (newStreak >= 2) {
          const bonusTime = Math.min(newStreak, 5) * settings.bonusTime;
          setTimeLeft(prevTime => prevTime + bonusTime);
          setFeedback(prevFeedback => ({
            ...prevFeedback,
            message: `${prevFeedback.message} Streak bonus: +${bonusTime}s!`
          }));
        }
        
        return newStreak;
      });
    } else {
      dispatch(decrementScore(Math.floor(settings.pointsPerCorrect / 2)));
      setTimeLeft(prev => Math.max(1, prev - settings.penaltyTime));
      setFeedback({
        type: 'incorrect',
        message: `Incorrect! -${settings.penaltyTime}s penalty. ${currentItem.isPhishing ? 'This was phishing!' : 'This was legitimate!'}`
      });
      setStreak(0);
    }
    
    // Wait to show the next item
    setTimeout(() => {
      if (gameState !== 'playing') return;
      
      if (itemIndex < phishingItems.length - 1) {
        setItemIndex(prev => prev + 1);
        setCurrentItem(phishingItems[itemIndex + 1]);
        setAnswered(false);
        setFeedback(null);
      } else {
        // Ran out of items, end the game
        handleGameOver();
      }
    }, 1500);
  }, [answered, currentItem, gameState, itemIndex, phishingItems, dispatch, settings, handleGameOver]);
  
  const getTimerColor = () => {
    if (timeLeft > settings.timeLimit * 0.6) return 'green';
    if (timeLeft > settings.timeLimit * 0.3) return 'orange';
    return 'red';
  };
  
  if (loading && phishingItems.length === 0) {
    return <div className="phishingphrenzy_loading">Loading game data...</div>;
  }

  if (error) {
    return <div className="phishingphrenzy_error">Error loading game: {error}</div>;
  }
  
  // Determine what to render based on game state
  const renderGameContent = () => {
    if (gameState === 'idle') {
      // Render the start screen
      return (
        <div className="phishingphrenzy_start_screen">
          <h2>Ready to test your phishing detection skills?</h2>
          <p>You'll be shown various emails, messages, and websites. Quickly decide if they're legitimate or phishing attempts.</p>
          
          <div className="phishingphrenzy_difficulty_selector">
            <h3>Select Difficulty:</h3>
            <div className="phishingphrenzy_difficulty_buttons">
              <button 
                className={difficulty === 'easy' ? 'active' : ''} 
                onClick={() => setDifficulty('easy')}
              >
                Easy
              </button>
              <button 
                className={difficulty === 'medium' ? 'active' : ''} 
                onClick={() => setDifficulty('medium')}
              >
                Medium
              </button>
              <button 
                className={difficulty === 'hard' ? 'active' : ''} 
                onClick={() => setDifficulty('hard')}
              >
                Hard
              </button>
            </div>
            <div className="phishingphrenzy_difficulty_details">
              <p>Time Limit: {difficultySettings[difficulty].timeLimit} seconds</p>
              <p>Points Per Correct: {difficultySettings[difficulty].pointsPerCorrect}</p>
              <p>Time Penalty: -{difficultySettings[difficulty].penaltyTime} seconds</p>
            </div>
          </div>
          
          <button className="phishingphrenzy_start_game_button" onClick={startNewGame}>
            Start Game
          </button>
          
          <div className="phishingphrenzy_high_score_display">
            <FaTrophy /> Your High Score: {highScore}
          </div>
        </div>
      );
    } else {
      // Render the gameplay screen for both 'playing' and 'gameOver' states
      return (
        <div className="phishingphrenzy_gameplay">
          <div className="phishingphrenzy_game_controls">
            <button 
              className="phishingphrenzy_back_button"
              onClick={handleReturnToMenu}
              disabled={isEndingGameRef.current}
            >
              <FaArrowLeft /> Return to Menu
            </button>
            
            {gameState === 'playing' && (
              <button 
                className="phishingphrenzy_end_button"
                onClick={handleEndEarly}
                disabled={isEndingGameRef.current}
              >
                <FaTimesCircle /> End Game
              </button>
            )}
          </div>
          
          <div className="phishingphrenzy_game_stats">
            <div className="phishingphrenzy_timer">
              <FaClock /> Time: <span style={{ color: getTimerColor() }}>{timeLeft}</span>
            </div>
            <div className="phishingphrenzy_score">
              Score: {score}
            </div>
            <div className="phishingphrenzy_streak">
              Streak: {streak > 0 ? `${streak} 🔥` : '0'}
            </div>
          </div>
          
          {currentItem && (
            <>
              <PhishingCard item={currentItem} />
              
              <div className="phishingphrenzy_answer_buttons">
                <button 
                  className="phishingphrenzy_legitimate_button"
                  onClick={() => handleAnswer(false)}
                  disabled={answered || gameState !== 'playing'}
                >
                  Legitimate
                </button>
                <button 
                  className="phishingphrenzy_phishing_button"
                  onClick={() => handleAnswer(true)}
                  disabled={answered || gameState !== 'playing'}
                >
                  <FaSkullCrossbones /> Phishing
                </button>
              </div>
              
              {feedback && (
                <div className={`phishingphrenzy_feedback ${feedback.type}`}>
                  {feedback.message}
                </div>
              )}
            </>
          )}
        </div>
      );
    }
  };

  return (
    <div className="phishingphrenzy_main_container">
      <div className="phishingphrenzy_header_section">
        <h1><FaShieldAlt /> Phishing Phrenzy</h1>
        <p>Quickly identify phishing attempts before time runs out!</p>
        
        {/* User stats display */}
        <div className="phishingphrenzy_user_stats">
          <div className="phishingphrenzy_stat">
            <FaCoins className="phishingphrenzy_stat_icon" />
            <span>{coins}</span>
          </div>
          <div className="phishingphrenzy_stat">
            <FaStar className="phishingphrenzy_stat_icon" />
            <span>{xp}</span>
          </div>
        </div>
      </div>
      
      {/* Main content area */}
      {renderGameContent()}
      
      {/* Game Over Modal - use explicit state for showing */}
      {gameState === 'gameOver' && showGameOverModal && (
        <GameOverModal 
          score={score} 
          highScore={highScore}
          onClose={handleReturnToMenu}
          onPlayAgain={handlePlayAgain}
          seenExamples={seenExamples} // Pass the examples the user has seen
        />
      )}
    </div>
  );
};

export default PhishingPhrenzy;
