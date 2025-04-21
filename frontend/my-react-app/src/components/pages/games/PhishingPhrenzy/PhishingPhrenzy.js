// src/components/pages/games/PhishingPhrenzy/PhishingPhrenzy.js
import React, { useState, useEffect, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { FaShieldAlt, FaSkullCrossbones, FaClock, FaTrophy, FaArrowLeft, FaTimesCircle, FaCoins, FaStar } from 'react-icons/fa';
import { 
  startGame, 
  endGame, 
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
  const { phishingItems, gameStatus, score, highScore, loading, error } = useSelector(state => state.phishingPhrenzy);
  const { userId, coins, xp } = useSelector(state => state.user);
  
  const [currentItem, setCurrentItem] = useState(null);
  const [itemIndex, setItemIndex] = useState(0);
  const [timeLeft, setTimeLeft] = useState(null);
  const [difficulty, setDifficulty] = useState('medium');
  const [showModal, setShowModal] = useState(false);
  const [feedback, setFeedback] = useState(null);
  const [answered, setAnswered] = useState(false);
  const [streak, setStreak] = useState(0);
  const [localGameStatus, setLocalGameStatus] = useState('idle'); // Local game status to prevent loops
  
  const timerRef = useRef(null);
  const gameOverRef = useRef(false); // Reference to track if game over has been handled
  const settings = difficultySettings[difficulty];
  
  // Load phishing examples when component mounts
  useEffect(() => {
    dispatch(fetchPhishingData());
    
    // Clean up on unmount
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [dispatch]);

  // Sync Redux game status with local state, but prevent loops
  useEffect(() => {
    if (gameStatus === 'playing' && localGameStatus !== 'playing') {
      setLocalGameStatus('playing');
      gameOverRef.current = false;
      
      // Initialize game when it starts
      setTimeLeft(settings.timeLimit);
      setItemIndex(0);
      setStreak(0);
      setShowModal(false);
      
      if (phishingItems.length > 0) {
        setCurrentItem(phishingItems[0]);
      }
    } 
    else if (gameStatus === 'finished' && !showModal && !gameOverRef.current) {
      // Only show modal once when game finishes
      gameOverRef.current = true;
      setShowModal(true);
      setLocalGameStatus('finished');
      
      // Submit score
      if (userId) {
        dispatch(submitGameResults({
          userId,
          score,
          timestamp: new Date().toISOString()
        })).then(() => {
          dispatch(fetchUserData(userId));
        });
      }
    }
    else if (gameStatus === 'idle' && localGameStatus !== 'idle') {
      setLocalGameStatus('idle');
      // Reset when going back to idle
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
      setShowModal(false);
    }
  }, [gameStatus, localGameStatus, phishingItems, settings.timeLimit, userId, score, dispatch, showModal]);

  // Timer logic
  useEffect(() => {
    // Clear any existing timer first
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    
    // Only start timer if game is actively playing
    if (localGameStatus === 'playing' && timeLeft > 0) {
      timerRef.current = setInterval(() => {
        setTimeLeft(prevTime => {
          if (prevTime <= 1) {
            // Time's up - only call handleGameOver if we haven't already
            if (!gameOverRef.current) {
              handleGameOver();
            }
            return 0;
          }
          return prevTime - 1;
        });
      }, 1000);
    } 
    else if (timeLeft <= 0 && localGameStatus === 'playing' && !gameOverRef.current) {
      // Double check that handleGameOver is called when time runs out
      handleGameOver();
    }

    // Clean up timer on effect cleanup
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [localGameStatus, timeLeft]);

  const startNewGame = () => {
    // Clear any existing timer
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    
    // Reset all local state
    setShowModal(false);
    setFeedback(null);
    setAnswered(false);
    setTimeLeft(null);
    gameOverRef.current = false;
    
    // Reset game state and start new game with delay
    dispatch(resetGame());
    
    // Delay starting a new game to ensure state is reset
    setTimeout(() => {
      dispatch(startGame());
    }, 50);
  };

  const handleGameOver = () => {
    // Prevent multiple calls to handleGameOver
    if (gameOverRef.current) return;
    gameOverRef.current = true;
    
    // Clear timer
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    
    // Update game status
    setLocalGameStatus('finished');
    dispatch(endGame(userId));
  };

  const handleAnswer = (answer) => {
    if (answered || !currentItem || localGameStatus !== 'playing') return;
    
    setAnswered(true);
    const isCorrect = answer === currentItem.isPhishing;
    
    if (isCorrect) {
      dispatch(incrementScore(settings.pointsPerCorrect));
      setFeedback({
        type: 'correct',
        message: `+${settings.pointsPerCorrect} points! ${currentItem.isPhishing ? 'This was phishing!' : 'This was legitimate!'}`
      });
      
      // Handle streak
      setStreak(prev => prev + 1);
      
      // Add bonus time if on a streak
      if (streak >= 2) {
        const bonusTime = Math.min(streak, 5) * settings.bonusTime;
        setTimeLeft(prev => prev + bonusTime);
        setFeedback(prev => ({
          ...prev,
          message: `${prev.message} Streak bonus: +${bonusTime}s!`
        }));
      }
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
      if (localGameStatus !== 'playing') return;
      
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
  };

  const getTimerColor = () => {
    if (timeLeft > settings.timeLimit * 0.6) return 'green';
    if (timeLeft > settings.timeLimit * 0.3) return 'orange';
    return 'red';
  };
  
  const handleEndEarly = () => {
    if (window.confirm('Are you sure you want to end the game? Your current score will be submitted.')) {
      handleGameOver();
    }
  };
  
  const handleReturnToMenu = () => {
    if (localGameStatus === 'playing' && window.confirm('Are you sure you want to return to the menu? Your progress will be lost.')) {
      // Clear timer
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
      
      // Reset all state
      setShowModal(false);
      setLocalGameStatus('idle');
      gameOverRef.current = false;
      dispatch(resetGame());
    } else if (localGameStatus !== 'playing') {
      // Just reset everything
      setShowModal(false);
      setLocalGameStatus('idle');
      gameOverRef.current = false;
      dispatch(resetGame());
    }
  };

  if (loading && phishingItems.length === 0) {
    return <div className="phishingphrenzy_loading">Loading game data...</div>;
  }

  if (error) {
    return <div className="phishingphrenzy_error">Error loading game: {error}</div>;
  }

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
      
      {localGameStatus === 'idle' ? (
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
      ) : (
        <div className="phishingphrenzy_gameplay">
          <div className="phishingphrenzy_game_controls">
            <button 
              className="phishingphrenzy_back_button"
              onClick={handleReturnToMenu}
            >
              <FaArrowLeft /> Return to Menu
            </button>
            
            {localGameStatus === 'playing' && (
              <button 
                className="phishingphrenzy_end_button"
                onClick={handleEndEarly}
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
                  disabled={answered || localGameStatus !== 'playing'}
                >
                  Legitimate
                </button>
                <button 
                  className="phishingphrenzy_phishing_button"
                  onClick={() => handleAnswer(true)}
                  disabled={answered || localGameStatus !== 'playing'}
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
      )}
      
      {showModal && (
        <GameOverModal 
          score={score} 
          highScore={highScore}
          onClose={handleReturnToMenu}
          onPlayAgain={startNewGame}
        />
      )}
    </div>
  );
};

export default PhishingPhrenzy;
