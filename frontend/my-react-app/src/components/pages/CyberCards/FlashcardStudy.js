// frontend/my-react-app/src/components/pages/CyberCards/FlashcardStudy.js
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';
import axios from 'axios';
import { 
  FaArrowLeft, 
  FaRandom, 
  FaBookmark, 
  FaRegBookmark, 
  FaChevronLeft, 
  FaChevronRight,
  FaEye,
  FaTerminal,
  FaSync,
  FaCheck,
  FaSpinner,
  FaExclamationTriangle,
  FaVolumeUp,
  FaExchangeAlt,
  FaStar,
  FaRegStar,
  FaKeyboard,
  FaTimes,
  FaQuestionCircle,
  FaCheckCircle,
  FaTimesCircle,
  FaInfoCircle
} from 'react-icons/fa';
import './CyberCards.css';

const LOCAL_STORAGE_PREFIX = 'cyberCards_';

// Tooltip content explaining difficulty ratings
const DIFFICULTY_EXPLANATIONS = {
  easy: "You know this well. It will appear less frequently.",
  medium: "You're familiar with this. It will appear at regular intervals.",
  hard: "You need to practice this more. It will appear more frequently."
};

const FlashcardStudy = () => {
  const { categoryId } = useParams();
  const [flashcards, setFlashcards] = useState([]);
  const [categoryInfo, setCategoryInfo] = useState(null);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [flipped, setFlipped] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingAction, setLoadingAction] = useState(false);
  const [error, setError] = useState(null);
  const [savedCards, setSavedCards] = useState({});
  const [mode, setMode] = useState(() => {
    return localStorage.getItem(`${LOCAL_STORAGE_PREFIX}mode`) || 'study';
  });
  const [streak, setStreak] = useState(0);
  const [progress, setProgress] = useState(0);
  const [isReversed, setIsReversed] = useState(() => {
    return localStorage.getItem(`${LOCAL_STORAGE_PREFIX}isReversed_${categoryId}`) === 'true';
  });
  const [difficulty, setDifficulty] = useState({});
  const [showKeyboardShortcuts, setShowKeyboardShortcuts] = useState(false);
  const [showDifficultyTooltip, setShowDifficultyTooltip] = useState(false);
  const [isAnimating, setIsAnimating] = useState(false);
  const [sessionStats, setSessionStats] = useState({
    started: new Date(),
    cardsReviewed: 0,
    correct: 0,
    incorrect: 0
  });
  const [lastInteractionTime, setLastInteractionTime] = useState(Date.now());
  
  const { userId } = useSelector((state) => state.user);
  const navigate = useNavigate();
  
  const cardRef = useRef(null);
  const flipTimeoutRef = useRef(null);
  const speechSynthesisRef = useRef(null);
  const debounceTimeoutRef = useRef(null);
  
  const DEBUG = true; // Set to false in production

  const logDebug = (message, data = null) => {
    if (!DEBUG) return;
    if (data) {
      console.log(`[FlashcardStudy] ${message}`, data);
    } else {
      console.log(`[FlashcardStudy] ${message}`);
    }
  };
  
  // Load flashcards and saved state
  useEffect(() => {
    const fetchFlashcards = async () => {
      try {
        setLoading(true);
        setError(null);
        logDebug(`Fetching flashcards for category: ${categoryId}`);
        
        // Fetch the flashcards for this category
        const response = await axios.get(`/api/test/flashcards/category/${categoryId}`);
        
        if (response.data.flashcards && response.data.flashcards.length > 0) {
          logDebug(`Received ${response.data.flashcards.length} flashcards`);
          
          // Load saved progress from localStorage
          const savedIndex = localStorage.getItem(`${LOCAL_STORAGE_PREFIX}currentIndex_${categoryId}`);
          const savedProgress = localStorage.getItem(`${LOCAL_STORAGE_PREFIX}progress_${categoryId}`);
          const savedDifficulty = localStorage.getItem(`${LOCAL_STORAGE_PREFIX}difficulty_${categoryId}`);
          
          // Load or initialize data
          setFlashcards(response.data.flashcards);
          setCurrentIndex(savedIndex ? parseInt(savedIndex, 10) : 0);
          setProgress(savedProgress ? parseFloat(savedProgress) : 0);
          
          // Safely parse saved difficulty
          if (savedDifficulty) {
            try {
              const parsedDifficulty = JSON.parse(savedDifficulty);
              setDifficulty(parsedDifficulty || {});
            } catch (e) {
              logDebug("Error parsing saved difficulty", e);
              setDifficulty({});
            }
          }
          
          // Find the category info from the first flashcard
          const firstCard = response.data.flashcards[0];
          if (firstCard.categoryName) {
            setCategoryInfo({
              title: firstCard.categoryName,
              description: firstCard.categoryDescription || 'Study flashcards for this certification.'
            });
          }
          
          // Record this interaction
          if (userId) {
            try {
              await axios.post('/api/test/flashcards/record-progress', {
                userId,
                categoryId,
                interactionType: 'viewed'
              });
              logDebug("Recorded 'viewed' interaction");
            } catch (err) {
              logDebug("Error recording view interaction", err);
            }
          }
          
          // Fetch saved cards
          if (userId) {
            try {
              const savedResponse = await axios.get(`/api/test/flashcards/saved/${userId}`);
              const savedMap = {};
              savedResponse.data.forEach(card => {
                savedMap[card._id] = true;
              });
              setSavedCards(savedMap);
              logDebug(`Loaded ${Object.keys(savedMap).length} saved cards`);
            } catch (err) {
              logDebug("Error fetching saved cards", err);
            }
          }
        } else {
          setError('No flashcards found for this category.');
          logDebug("No flashcards found for category");
        }
      } catch (err) {
        console.error('Error fetching flashcards:', err);
        setError('Failed to load flashcards. Please try again later.');
        logDebug("Error in fetchFlashcards", err);
      } finally {
        setLoading(false);
      }
    };
    
    fetchFlashcards();
    
    // Setup keyboard shortcuts
    const handleKeyPress = (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      
      // Debounce key presses to prevent rapid-firing
      if (Date.now() - lastInteractionTime < 300) {
        return;
      }
      setLastInteractionTime(Date.now());
      
      switch (e.key) {
        case ' ':
          handleFlip(e);
          break;
        case 'ArrowRight':
          handleNextCard();
          break;
        case 'ArrowLeft':
          handlePreviousCard();
          break;
        case 's':
          handleSaveCard();
          break;
        case 'r':
          handleShuffle();
          break;
        case 'f':
          toggleReverseCards();
          break;
        case '1':
          if (flipped && mode !== 'study') handleCorrectAnswer();
          break;
        case '2':
          if (flipped && mode !== 'study') handleIncorrectAnswer();
          break;
        case 'k':
          setShowKeyboardShortcuts(prev => !prev);
          break;
        case 'Escape':
          // Close any open modals
          setShowKeyboardShortcuts(false);
          setShowDifficultyTooltip(false);
          if (flipped) {
            setFlipped(false);
          }
          break;
        default:
          break;
      }
    };
    
    window.addEventListener('keydown', handleKeyPress);
    
    return () => {
      window.removeEventListener('keydown', handleKeyPress);
      // Clear any pending timeouts
      if (flipTimeoutRef.current) {
        clearTimeout(flipTimeoutRef.current);
      }
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
      // Stop any speech synthesis
      if (speechSynthesisRef.current && window.speechSynthesis) {
        window.speechSynthesis.cancel();
      }
    };
  }, [categoryId, userId, mode, flipped, lastInteractionTime]);
  
  // Reset flipped state when changing cards (with proper timing)
  useEffect(() => {
    setFlipped(false);
    setIsAnimating(false);
    
    // Save current index to localStorage
    localStorage.setItem(`${LOCAL_STORAGE_PREFIX}currentIndex_${categoryId}`, currentIndex.toString());
    
    // Calculate and save progress
    if (flashcards.length > 0) {
      const newProgress = (currentIndex / flashcards.length) * 100;
      setProgress(newProgress);
      localStorage.setItem(`${LOCAL_STORAGE_PREFIX}progress_${categoryId}`, newProgress.toString());
    }
    
    // Update session stats
    setSessionStats(prev => ({
      ...prev,
      cardsReviewed: Math.min(prev.cardsReviewed + 1, flashcards.length)
    }));

    logDebug(`Changed to card index ${currentIndex}`);
  }, [currentIndex, categoryId, flashcards.length]);
  
  // Save mode preference when it changes
  useEffect(() => {
    localStorage.setItem(`${LOCAL_STORAGE_PREFIX}mode`, mode);
    logDebug(`Mode changed to ${mode}`);
  }, [mode]);
  
  // Save reversed state preference
  useEffect(() => {
    localStorage.setItem(`${LOCAL_STORAGE_PREFIX}isReversed_${categoryId}`, isReversed.toString());
    logDebug(`Reversed state changed to ${isReversed}`);
  }, [isReversed, categoryId]);
  
  // Save difficulty ratings when they change
  useEffect(() => {
    if (Object.keys(difficulty).length > 0) {
      try {
        localStorage.setItem(`${LOCAL_STORAGE_PREFIX}difficulty_${categoryId}`, JSON.stringify(difficulty));
        logDebug(`Saved ${Object.keys(difficulty).length} difficulty ratings`);
      } catch (err) {
        logDebug("Error saving difficulty ratings", err);
      }
    }
  }, [difficulty, categoryId]);
  
  // Handle card navigation with debouncing
  const handleNextCard = useCallback(() => {
    if (flashcards.length === 0 || isAnimating) return;
    
    // Prevent rapid clicking
    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }
    
    setIsAnimating(true);
    
    debounceTimeoutRef.current = setTimeout(() => {
      if (currentIndex < flashcards.length - 1) {
        setCurrentIndex(currentIndex + 1);
      } else {
        // Loop back to the first card
        setCurrentIndex(0);
      }
      setIsAnimating(false);
      logDebug("Next card");
    }, 300);
  }, [currentIndex, flashcards.length, isAnimating]);
  
  const handlePreviousCard = useCallback(() => {
    if (flashcards.length === 0 || isAnimating) return;
    
    // Prevent rapid clicking
    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }
    
    setIsAnimating(true);
    
    debounceTimeoutRef.current = setTimeout(() => {
      if (currentIndex > 0) {
        setCurrentIndex(currentIndex - 1);
      } else {
        // Loop to the last card
        setCurrentIndex(flashcards.length - 1);
      }
      setIsAnimating(false);
      logDebug("Previous card");
    }, 300);
  }, [currentIndex, flashcards.length, isAnimating]);
  
  // Improved flip handling with better event management
  const handleFlip = useCallback((e) => {
    // If an event was passed, stop propagation to prevent double-handling
    if (e) {
      e.stopPropagation();
    }
    
    // Don't allow rapid flipping that might cause animation issues
    if (flipTimeoutRef.current || isAnimating) {
      logDebug("Flip prevented - animation in progress");
      return;
    }
    
    setIsAnimating(true);
    setFlipped(prev => !prev);
    logDebug(`Card flipped to ${!flipped ? 'back' : 'front'}`);
    
    // Set a timeout to prevent rapid flipping and allow animations to complete
    flipTimeoutRef.current = setTimeout(() => {
      flipTimeoutRef.current = null;
      setIsAnimating(false);
    }, 600); // Slightly longer than animation duration
    
    // If flipping to show answer, record this interaction
    if (!flipped && userId) {
      try {
        axios.post('/api/test/flashcards/record-progress', {
          userId,
          categoryId,
          interactionType: 'answered'
        })
        .then(() => logDebug("Recorded 'answered' interaction"))
        .catch(err => logDebug("Error recording answer interaction", err));
      } catch (err) {
        logDebug("Error initiating record progress", err);
      }
    }
  }, [flipped, userId, categoryId, isAnimating]);
  
  const handleSaveCard = async (e) => {
    if (e) e.stopPropagation();
    if (!userId || flashcards.length === 0 || loadingAction) return;
    
    try {
      setLoadingAction(true);
      const cardId = flashcards[currentIndex]._id;
      logDebug(`Saving/unsaving card ${cardId}`);
      
      const response = await axios.post('/api/test/flashcards/save', {
        userId,
        flashcardId: cardId
      });
      
      if (response.data.saved) {
        setSavedCards(prev => ({...prev, [cardId]: true}));
        logDebug("Card saved");
      } else {
        setSavedCards(prev => {
          const updated = {...prev};
          delete updated[cardId];
          return updated;
        });
        logDebug("Card unsaved");
      }
    } catch (err) {
      console.error('Error saving flashcard:', err);
      logDebug("Error in handleSaveCard", err);
    } finally {
      setLoadingAction(false);
    }
  };
  
  const handleShuffle = (e) => {
    if (e) e.stopPropagation();
    if (flashcards.length <= 1 || isAnimating) return;
    
    logDebug("Shuffling cards");
    const shuffled = [...flashcards].sort(() => Math.random() - 0.5);
    setFlashcards(shuffled);
    setCurrentIndex(0);
  };
  
  const handleModeChange = (newMode) => {
    if (newMode === mode) return;
    
    logDebug(`Changing mode from ${mode} to ${newMode}`);
    setMode(newMode);
    setCurrentIndex(0);
    setStreak(0);
    setSessionStats({
      started: new Date(),
      cardsReviewed: 0,
      correct: 0,
      incorrect: 0
    });
  };
  
  const handleCorrectAnswer = async (e) => {
    if (e) e.stopPropagation();
    if (isAnimating) return;
    
    // Increment streak, award XP/coins for streaks
    const newStreak = streak + 1;
    setStreak(newStreak);
    logDebug(`Correct answer, new streak: ${newStreak}`);
    
    // Update session stats
    setSessionStats(prev => ({
      ...prev,
      correct: prev.correct + 1
    }));
    
    // Update difficulty (mark as easy)
    if (flashcards[currentIndex]) {
      const cardId = flashcards[currentIndex]._id;
      setDifficulty(prev => ({
        ...prev,
        [cardId]: 'easy'
      }));
      
      // Also update difficulty on server if logged in
      if (userId) {
        try {
          axios.post('/api/test/flashcards/difficulty', {
            userId,
            flashcardId: cardId,
            categoryId,
            difficulty: 'easy'
          })
          .then(() => logDebug("Saved 'easy' difficulty rating"))
          .catch(err => logDebug("Error saving difficulty rating", err));
        } catch (err) {
          logDebug("Error initiating difficulty save", err);
        }
      }
    }
    
    if (newStreak % 5 === 0 && userId) {
      // Award bonus for every 5 card streak
      try {
        axios.post('/api/test/flashcards/record-progress', {
          userId,
          categoryId,
          interactionType: 'streak'
        })
        .then(() => logDebug("Recorded streak achievement"))
        .catch(err => logDebug("Error recording streak", err));
      } catch (err) {
        logDebug("Error initiating streak record", err);
      }
    }
    
    // Add a small delay before moving to next card for better UX
    setTimeout(() => handleNextCard(), 300);
  };
  
  const handleIncorrectAnswer = (e) => {
    if (e) e.stopPropagation();
    if (isAnimating) return;
    
    // Reset streak
    logDebug("Incorrect answer, streak reset");
    setStreak(0);
    
    // Update session stats
    setSessionStats(prev => ({
      ...prev,
      incorrect: prev.incorrect + 1
    }));
    
    // Update difficulty (mark as hard)
    if (flashcards[currentIndex]) {
      const cardId = flashcards[currentIndex]._id;
      setDifficulty(prev => ({
        ...prev,
        [cardId]: 'hard'
      }));
      
      // Also update difficulty on server if logged in
      if (userId) {
        try {
          axios.post('/api/test/flashcards/difficulty', {
            userId,
            flashcardId: cardId,
            categoryId,
            difficulty: 'hard'
          })
          .then(() => logDebug("Saved 'hard' difficulty rating"))
          .catch(err => logDebug("Error saving difficulty rating", err));
        } catch (err) {
          logDebug("Error initiating difficulty save", err);
        }
      }
    }
    
    // Add a small delay before moving to next card for better UX
    setTimeout(() => handleNextCard(), 300);
  };
  
  const toggleReverseCards = (e) => {
    if (e) e.stopPropagation();
    setIsReversed(prev => !prev);
  };
  
  const handleCompleteSession = async (e) => {
    if (e) e.stopPropagation();
    if (!userId) return;
    
    logDebug("Completing session", sessionStats);
    
    try {
      setLoadingAction(true);
      await axios.post('/api/test/flashcards/record-progress', {
        userId,
        categoryId,
        interactionType: 'completed',
        sessionStats: {
          duration: Math.floor((new Date() - new Date(sessionStats.started)) / 1000),
          cardsReviewed: sessionStats.cardsReviewed,
          correct: sessionStats.correct,
          incorrect: sessionStats.incorrect
        }
      });
      
      // Small delay before navigating away for better UX
      setTimeout(() => navigate('/cybercards'), 300);
    } catch (err) {
      console.error('Error recording session completion:', err);
      logDebug("Error in handleCompleteSession", err);
      // Still navigate away even if there was an error
      navigate('/cybercards');
    } finally {
      setLoadingAction(false);
    }
  };
  
  // Speech synthesis with error handling
  const speakText = (text, e) => {
    if (e) e.stopPropagation();
    
    // Check if speech synthesis is available
    if (!window.speechSynthesis) {
      logDebug("Speech synthesis not available");
      return;
    }
    
    try {
      // Cancel any ongoing speech
      window.speechSynthesis.cancel();
      
      // Create new utterance
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = 0.9; // Slightly slower than default
      
      // Store reference to cancel if needed
      speechSynthesisRef.current = utterance;
      
      // Speak the text
      window.speechSynthesis.speak(utterance);
      logDebug("Speaking text", { textLength: text.length });
    } catch (err) {
      console.error("Error with speech synthesis:", err);
      logDebug("Speech synthesis error", err);
    }
  };
  
  // Improved difficulty handling with better event isolation
  const setCardDifficulty = (difficultyLevel, e) => {
    if (e) e.stopPropagation();
    
    if (flashcards[currentIndex]) {
      const cardId = flashcards[currentIndex]._id;
      setDifficulty(prev => ({
        ...prev,
        [cardId]: difficultyLevel
      }));
      
      logDebug(`Set card ${cardId} difficulty to ${difficultyLevel}`);
      
      // Also update difficulty on server if logged in
      if (userId) {
        try {
          axios.post('/api/test/flashcards/difficulty', {
            userId,
            flashcardId: cardId,
            categoryId,
            difficulty: difficultyLevel
          })
          .then(() => logDebug(`Saved '${difficultyLevel}' difficulty rating`))
          .catch(err => logDebug("Error saving difficulty rating", err));
        } catch (err) {
          logDebug("Error initiating difficulty save", err);
        }
      }
    }
  };
  
  // Close difficulty tooltip helper
  const closeDifficultyTooltip = (e) => {
    if (e) e.stopPropagation();
    setShowDifficultyTooltip(false);
  };
  
  if (loading) {
    return (
      <div className="cybercards-container">
        <div className="cybercards-loading">
          <FaSpinner className="cybercards-spinner" />
          <p>Loading flashcards...</p>
        </div>
      </div>
    );
  }
  
  if (error) {
    return (
      <div className="cybercards-container">
        <div className="cybercards-error">
          <FaExclamationTriangle className="cybercards-error-icon" />
          <p>{error}</p>
          <button 
            className="cybercards-button" 
            onClick={() => navigate('/cybercards')}
          >
            <FaArrowLeft /> Back to Vaults
          </button>
        </div>
      </div>
    );
  }
  
  if (flashcards.length === 0) {
    return (
      <div className="cybercards-container">
        <div className="cybercards-empty">
          <h2>No flashcards found</h2>
          <p>This vault appears to be empty.</p>
          <button 
            className="cybercards-button" 
            onClick={() => navigate('/cybercards')}
          >
            <FaArrowLeft /> Back to Vaults
          </button>
        </div>
      </div>
    );
  }
  
  const currentCard = flashcards[currentIndex];
  const isSaved = currentCard && savedCards[currentCard._id];
  const currentDifficulty = currentCard ? difficulty[currentCard._id] : null;
  
  // Determine question and answer based on isReversed state
  const question = isReversed ? currentCard.answer : currentCard.question;
  const answer = isReversed ? currentCard.question : currentCard.answer;
  
  return (
    <div className="cybercards-container">
      <div className="cybercards-background">
        <div className="cybercards-grid"></div>
        <div className="cybercards-glow"></div>
      </div>
      
      {/* Keyboard shortcuts modal */}
      {showKeyboardShortcuts && (
        <div className="cybercards-keyboard-shortcuts">
          <div className="cybercards-keyboard-shortcuts-header">
            <h3><FaKeyboard /> Keyboard Shortcuts</h3>
            <button onClick={(e) => {
              e.stopPropagation();
              setShowKeyboardShortcuts(false);
            }}>×</button>
          </div>
          <ul>
            <li><strong>Space</strong> - Flip card</li>
            <li><strong>←/→</strong> - Previous/Next card</li>
            <li><strong>S</strong> - Save/Bookmark card</li>
            <li><strong>R</strong> - Shuffle cards</li>
            <li><strong>F</strong> - Flip front/back</li>
            <li><strong>1</strong> - Mark as correct (quiz mode)</li>
            <li><strong>2</strong> - Mark as incorrect (quiz mode)</li>
            <li><strong>K</strong> - Show/hide shortcuts</li>
            <li><strong>Esc</strong> - Close popups/flip back</li>
          </ul>
        </div>
      )}
      
      {/* Difficulty tooltip */}
      {showDifficultyTooltip && (
        <div className="cybercards-keyboard-shortcuts cybercards-difficulty-help">
          <div className="cybercards-keyboard-shortcuts-header">
            <h3><FaInfoCircle /> Difficulty Ratings</h3>
            <button onClick={closeDifficultyTooltip}>×</button>
          </div>
          <ul>
            <li><strong className="difficulty-hard">Hard</strong> - {DIFFICULTY_EXPLANATIONS.hard}</li>
            <li><strong className="difficulty-medium">Medium</strong> - {DIFFICULTY_EXPLANATIONS.medium}</li>
            <li><strong className="difficulty-easy">Easy</strong> - {DIFFICULTY_EXPLANATIONS.easy}</li>
          </ul>
          <p className="cybercards-difficulty-note">Rating helps our system prioritize cards you need to practice more.</p>
        </div>
      )}
      
      <div className="cybercards-study-header">
        <button 
          className="cybercards-back-button" 
          onClick={(e) => {
            e.stopPropagation();
            navigate('/cybercards');
          }}
        >
          <FaArrowLeft /> Back to Vaults
        </button>
        <h2 className="cybercards-study-title">
          <FaTerminal className="cybercards-title-icon" />
          {categoryInfo?.title || 'Flashcards'}
          {isReversed && <span className="cybercards-reversed-indicator">(Reversed)</span>}
        </h2>
        <div className="cybercards-study-controls">
          <button 
            className="cybercards-control-button"
            onClick={toggleReverseCards}
            title="Swap question/answer"
          >
            <FaExchangeAlt />
          </button>
          <button 
            className="cybercards-control-button" 
            onClick={handleShuffle}
            title="Shuffle cards"
          >
            <FaRandom />
          </button>
          <button
            className="cybercards-control-button"
            onClick={(e) => {
              e.stopPropagation();
              setShowKeyboardShortcuts(true);
            }}
            title="Show keyboard shortcuts"
          >
            <FaKeyboard />
          </button>
          <div className="cybercards-mode-selector">
            <button 
              className={`cybercards-mode-button ${mode === 'study' ? 'active' : ''}`}
              onClick={(e) => {
                e.stopPropagation();
                handleModeChange('study');
              }}
            >
              Study
            </button>
            <button 
              className={`cybercards-mode-button ${mode === 'quiz' ? 'active' : ''}`}
              onClick={(e) => {
                e.stopPropagation();
                handleModeChange('quiz');
              }}
            >
              Quiz
            </button>
            <button 
              className={`cybercards-mode-button ${mode === 'challenge' ? 'active' : ''}`}
              onClick={(e) => {
                e.stopPropagation();
                handleModeChange('challenge');
              }}
            >
              Challenge
            </button>
          </div>
        </div>
      </div>
      
      <div className="cybercards-session-stats">
        <div className="cybercards-stat-item">
          <span className="cybercards-stat-label">Cards Reviewed:</span>
          <span className="cybercards-stat-value">{sessionStats.cardsReviewed}</span>
        </div>
        {mode !== 'study' && (
          <>
            <div className="cybercards-stat-item">
              <span className="cybercards-stat-label">Correct:</span>
              <span className="cybercards-stat-value cybercards-stat-correct">{sessionStats.correct}</span>
            </div>
            <div className="cybercards-stat-item">
              <span className="cybercards-stat-label">Incorrect:</span>
              <span className="cybercards-stat-value cybercards-stat-incorrect">{sessionStats.incorrect}</span>
            </div>
            <div className="cybercards-stat-item">
              <span className="cybercards-stat-label">Success Rate:</span>
              <span className="cybercards-stat-value">
                {sessionStats.cardsReviewed > 0 
                  ? `${Math.round((sessionStats.correct / (sessionStats.correct + sessionStats.incorrect)) * 100) || 0}%` 
                  : '0%'}
              </span>
            </div>
          </>
        )}
      </div>
      
      <div className="cybercards-study-content">
        <div className="cybercards-progress">
          <div className="cybercards-progress-bar">
            <div 
              className="cybercards-progress-fill"
              style={{ width: `${((currentIndex + 1) / flashcards.length) * 100}%` }}
            ></div>
          </div>
          <span className="cybercards-progress-text">
            {currentIndex + 1} / {flashcards.length}
          </span>
        </div>
        
        <div className="cybercards-flashcard-wrapper">
          <div 
            ref={cardRef}
            className={`cybercards-flashcard ${flipped ? 'flipped' : ''} ${currentDifficulty ? `difficulty-${currentDifficulty}` : ''} ${isAnimating ? 'animating' : ''}`}
            onClick={mode === 'study' && !isAnimating ? handleFlip : undefined}
          >
            <div className="cybercards-flashcard-front">
              <div className="cybercards-flashcard-content">
                <p>{question || 'Question not available'}</p>
              </div>
              <div className="cybercards-flashcard-footer">
                <span className="cybercards-card-hint">
                  {mode === 'study' ? (
                    <>
                      <FaEye /> {isAnimating ? 'Please wait...' : 'Click to reveal answer'}
                    </>
                  ) : (
                    <>
                      Think about your answer before revealing
                    </>
                  )}
                </span>
                <button
                  className="cybercards-audio-button"
                  onClick={(e) => speakText(question, e)}
                  title="Read question aloud"
                >
                  <FaVolumeUp />
                </button>
              </div>
            </div>
            <div className="cybercards-flashcard-back">
              <div className="cybercards-flashcard-content">
                <p>{answer || 'Answer not available'}</p>
              </div>
              <div className="cybercards-flashcard-footer">
                {mode === 'study' ? (
                  <div className="cybercards-rating-buttons">
                    <button 
                      className={`cybercards-difficulty-button ${currentDifficulty === 'hard' ? 'active' : ''}`} 
                      onClick={(e) => setCardDifficulty('hard', e)}
                      title="Mark as difficult"
                    >
                      Hard
                    </button>
                    <button 
                      className={`cybercards-difficulty-button ${currentDifficulty === 'medium' ? 'active' : ''}`} 
                      onClick={(e) => setCardDifficulty('medium', e)}
                      title="Mark as medium"
                    >
                      Medium
                    </button>
                    <button 
                      className={`cybercards-difficulty-button ${currentDifficulty === 'easy' ? 'active' : ''}`} 
                      onClick={(e) => setCardDifficulty('easy', e)}
                      title="Mark as easy"
                    >
                      Easy
                    </button>
                    <button
                      className="cybercards-help-button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setShowDifficultyTooltip(!showDifficultyTooltip);
                      }}
                      title="What's this?"
                    >
                      <FaQuestionCircle />
                    </button>
                    <button
                      className="cybercards-audio-button"
                      onClick={(e) => speakText(answer, e)}
                      title="Read answer aloud"
                    >
                      <FaVolumeUp />
                    </button>
                  </div>
                ) : (
                  <div className="cybercards-quiz-buttons">
                    <button 
                      className="cybercards-quiz-button correct"
                      onClick={handleCorrectAnswer}
                    >
                      <FaCheckCircle /> Correct (1)
                    </button>
                    <button 
                      className="cybercards-quiz-button incorrect"
                      onClick={handleIncorrectAnswer}
                    >
                      <FaTimesCircle /> Wrong (2)
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
          
          <div className="cybercards-flashcard-actions">
            <button 
              className="cybercards-action-button"
              onClick={handlePreviousCard}
              title="Previous card"
              disabled={isAnimating}
            >
              <FaChevronLeft />
            </button>
            
            <button 
              className={`cybercards-action-button save ${loadingAction ? 'loading' : ''}`}
              onClick={handleSaveCard}
              disabled={loadingAction || isAnimating}
              title="Save/bookmark card"
            >
              {loadingAction ? <FaSpinner className="cybercards-spinner" /> : 
                (isSaved ? <FaBookmark /> : <FaRegBookmark />)}
            </button>
            
            {mode !== 'study' && (
              <span className="cybercards-streak-counter" title="Current streak of correct answers">
                Streak: {streak}
              </span>
            )}
            
            <button 
              className="cybercards-action-button"
              onClick={handleNextCard}
              title="Next card"
              disabled={isAnimating}
            >
              <FaChevronRight />
            </button>
            
            {/* Show appropriate button based on state */}
            {!flipped && (
              <button 
                className="cybercards-reveal-button"
                onClick={handleFlip}
                disabled={isAnimating}
              >
                {isAnimating ? 'Please wait...' : 'Reveal Answer'}
              </button>
            )}
            
            {flipped && mode === 'study' && (
              <button 
                className="cybercards-reveal-button"
                onClick={handleFlip}
                disabled={isAnimating}
              >
                {isAnimating ? 'Please wait...' : 'Show Question'}
              </button>
            )}
          </div>
        </div>
      </div>
      
      <div className="cybercards-session-controls">
        <div className="cybercards-session-progress">
          <div className="cybercards-progress-circle">
            <svg viewBox="0 0 36 36">
              <path
                className="cybercards-progress-circle-bg"
                d="M18 2.0845
                  a 15.9155 15.9155 0 0 1 0 31.831
                  a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                className="cybercards-progress-circle-fill"
                strokeDasharray={`${progress}, 100`}
                d="M18 2.0845
                  a 15.9155 15.9155 0 0 1 0 31.831
                  a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <span className="cybercards-progress-percent">{Math.round(progress)}%</span>
          </div>
          <span className="cybercards-progress-label">Completion</span>
        </div>
        <button 
          className="cybercards-complete-button"
          onClick={handleCompleteSession}
          disabled={loadingAction || isAnimating}
        >
          {loadingAction ? <FaSpinner className="cybercards-spinner" /> : 'Complete Session'}
        </button>
      </div>
    </div>
  );
};

export default FlashcardStudy;
