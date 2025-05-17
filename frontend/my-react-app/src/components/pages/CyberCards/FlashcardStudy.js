// frontend/my-react-app/src/components/pages/CyberCards/FlashcardStudy.js
import React, { useState, useEffect } from 'react';
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
  FaSpinner,
  FaExclamationTriangle,
  FaVolumeUp,
  FaExchangeAlt,
  FaKeyboard 
} from 'react-icons/fa';
import './CyberCards.css';

const LOCAL_STORAGE_PREFIX = 'cyberCards_';

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
  const [showKeyboardShortcuts, setShowKeyboardShortcuts] = useState(false);
  const [sessionStats, setSessionStats] = useState({
    started: new Date(),
    cardsReviewed: 0,
    correct: 0,
    incorrect: 0
  });
  
  const { userId } = useSelector((state) => state.user);
  const navigate = useNavigate();
  
  // Load flashcards and saved state
  useEffect(() => {
    const fetchFlashcards = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Fetch the flashcards for this category
        const response = await axios.get(`/api/test/flashcards/category/${categoryId}`);
        
        if (response.data.flashcards && response.data.flashcards.length > 0) {
          // Load saved progress from localStorage
          const savedIndex = localStorage.getItem(`${LOCAL_STORAGE_PREFIX}currentIndex_${categoryId}`);
          
          // Load or initialize data
          setFlashcards(response.data.flashcards);
          setCurrentIndex(savedIndex ? parseInt(savedIndex, 10) : 0);
          
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
            axios.post('/api/test/flashcards/record-progress', {
              userId,
              categoryId,
              interactionType: 'viewed'
            }).catch(() => {});
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
            } catch (err) {
              // Continue even if this fails
            }
          }
        } else {
          setError('No flashcards found for this category.');
        }
      } catch (err) {
        console.error('Error fetching flashcards:', err);
        setError('Failed to load flashcards. Please try again later.');
      } finally {
        setLoading(false);
      }
    };
    
    fetchFlashcards();
    
    // Setup keyboard shortcuts
    const handleKeyPress = (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      
      switch (e.key) {
        case ' ':
          handleFlip();
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
      // Ensure speech synthesis is cancelled if active
      if (window.speechSynthesis) {
        window.speechSynthesis.cancel();
      }
    };
  }, [categoryId, userId, mode, flipped]);
  
  // Update progress when changing cards
  useEffect(() => {
    // Save current index to localStorage
    localStorage.setItem(`${LOCAL_STORAGE_PREFIX}currentIndex_${categoryId}`, currentIndex.toString());
    
    // Calculate and save progress
    if (flashcards.length > 0) {
      const newProgress = ((currentIndex + 1) / flashcards.length) * 100;
      setProgress(newProgress);
    }
    
    // Update session stats
    setSessionStats(prev => ({
      ...prev,
      cardsReviewed: Math.min(prev.cardsReviewed + 1, flashcards.length)
    }));
  }, [currentIndex, categoryId, flashcards.length]);
  
  // Save mode preference
  useEffect(() => {
    localStorage.setItem(`${LOCAL_STORAGE_PREFIX}mode`, mode);
  }, [mode]);
  
  // Save reversed state preference
  useEffect(() => {
    localStorage.setItem(`${LOCAL_STORAGE_PREFIX}isReversed_${categoryId}`, isReversed.toString());
  }, [isReversed, categoryId]);
  
  // Simplified card navigation
  const handleNextCard = () => {
    if (flashcards.length === 0) return;
    
    setFlipped(false);
    
    if (currentIndex < flashcards.length - 1) {
      setCurrentIndex(currentIndex + 1);
    } else {
      // Loop back to the first card
      setCurrentIndex(0);
    }
  };
  
  const handlePreviousCard = () => {
    if (flashcards.length === 0) return;
    
    setFlipped(false);
    
    if (currentIndex > 0) {
      setCurrentIndex(currentIndex - 1);
    } else {
      // Loop to the last card
      setCurrentIndex(flashcards.length - 1);
    }
  };
  
  // Simple flip handling
  const handleFlip = () => {
    setFlipped(!flipped);
    
    // If flipping to show answer, record this interaction
    if (!flipped && userId) {
      axios.post('/api/test/flashcards/record-progress', {
        userId,
        categoryId,
        interactionType: 'answered'
      }).catch(() => {});
    }
  };
  
  const handleSaveCard = async () => {
    if (!userId || flashcards.length === 0 || loadingAction) return;
    
    try {
      setLoadingAction(true);
      const cardId = flashcards[currentIndex]._id;
      
      const response = await axios.post('/api/test/flashcards/save', {
        userId,
        flashcardId: cardId
      });
      
      if (response.data.saved) {
        setSavedCards(prev => ({...prev, [cardId]: true}));
      } else {
        setSavedCards(prev => {
          const updated = {...prev};
          delete updated[cardId];
          return updated;
        });
      }
    } catch (err) {
      console.error('Error saving flashcard:', err);
    } finally {
      setLoadingAction(false);
    }
  };
  
  const handleShuffle = () => {
    if (flashcards.length <= 1) return;
    
    const shuffled = [...flashcards].sort(() => Math.random() - 0.5);
    setFlashcards(shuffled);
    setCurrentIndex(0);
    setFlipped(false);
  };
  
  const handleModeChange = (newMode) => {
    if (newMode === mode) return;
    
    setMode(newMode);
    setCurrentIndex(0);
    setFlipped(false);
    setStreak(0);
    setSessionStats({
      started: new Date(),
      cardsReviewed: 0,
      correct: 0,
      incorrect: 0
    });
  };
  
  const handleCorrectAnswer = () => {
    // Increment streak
    const newStreak = streak + 1;
    setStreak(newStreak);
    
    // Update session stats
    setSessionStats(prev => ({
      ...prev,
      correct: prev.correct + 1
    }));
    
    // Move to next card
    handleNextCard();
  };
  
  const handleIncorrectAnswer = () => {
    // Reset streak
    setStreak(0);
    
    // Update session stats
    setSessionStats(prev => ({
      ...prev,
      incorrect: prev.incorrect + 1
    }));
    
    // Move to next card
    handleNextCard();
  };
  
  const toggleReverseCards = () => {
    setIsReversed(prev => !prev);
  };
  
  const handleCompleteSession = () => {
    if (!userId) return;
    
    try {
      axios.post('/api/test/flashcards/record-progress', {
        userId,
        categoryId,
        interactionType: 'completed',
        sessionStats: {
          duration: Math.floor((new Date() - new Date(sessionStats.started)) / 1000),
          cardsReviewed: sessionStats.cardsReviewed,
          correct: sessionStats.correct,
          incorrect: sessionStats.incorrect
        }
      }).catch(() => {});
      
      navigate('/cybercards');
    } catch (err) {
      // Still navigate away even if there was an error
      navigate('/cybercards');
    }
  };
  
  // Simple speech synthesis
  const speakText = (text) => {
    if (!window.speechSynthesis) return;
    
    try {
      window.speechSynthesis.cancel();
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = 0.9;
      window.speechSynthesis.speak(utterance);
    } catch (err) {
      console.error("Error with speech synthesis:", err);
    }
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
            <button onClick={() => setShowKeyboardShortcuts(false)}>×</button>
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
      
      <div className="cybercards-study-header">
        <button 
          className="cybercards-back-button" 
          onClick={() => navigate('/cybercards')}
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
            onClick={() => setShowKeyboardShortcuts(true)}
            title="Show keyboard shortcuts"
          >
            <FaKeyboard />
          </button>
          <div className="cybercards-mode-selector">
            <button 
              className={`cybercards-mode-button ${mode === 'study' ? 'active' : ''}`}
              onClick={() => handleModeChange('study')}
            >
              Study
            </button>
            <button 
              className={`cybercards-mode-button ${mode === 'quiz' ? 'active' : ''}`}
              onClick={() => handleModeChange('quiz')}
            >
              Quiz
            </button>
            <button 
              className={`cybercards-mode-button ${mode === 'challenge' ? 'active' : ''}`}
              onClick={() => handleModeChange('challenge')}
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
            className={`cybercards-flashcard ${flipped ? 'flipped' : ''}`}
            onClick={mode === 'study' ? handleFlip : undefined}
          >
            <div className="cybercards-flashcard-front">
              <div className="cybercards-flashcard-content">
                <p>{question || 'Question not available'}</p>
              </div>
              <div className="cybercards-flashcard-footer">
                <span className="cybercards-card-hint">
                  {mode === 'study' ? (
                    <>
                      <FaEye /> Click to reveal answer
                    </>
                  ) : (
                    <>
                      Think about your answer before revealing
                    </>
                  )}
                </span>
                <button
                  className="cybercards-audio-button"
                  onClick={() => speakText(question)}
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
                {mode !== 'study' ? (
                  <div className="cybercards-quiz-buttons">
                    <button 
                      className="cybercards-quiz-button correct"
                      onClick={handleCorrectAnswer}
                    >
                      Correct (1)
                    </button>
                    <button 
                      className="cybercards-quiz-button incorrect"
                      onClick={handleIncorrectAnswer}
                    >
                      Wrong (2)
                    </button>
                  </div>
                ) : (
                  <button
                    className="cybercards-audio-button"
                    onClick={() => speakText(answer)}
                    title="Read answer aloud"
                  >
                    <FaVolumeUp />
                  </button>
                )}
              </div>
            </div>
          </div>
          
          <div className="cybercards-flashcard-actions">
            <button 
              className="cybercards-action-button"
              onClick={handlePreviousCard}
              title="Previous card"
            >
              <FaChevronLeft />
            </button>
            
            <button 
              className={`cybercards-action-button save ${loadingAction ? 'loading' : ''}`}
              onClick={handleSaveCard}
              disabled={loadingAction}
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
            >
              <FaChevronRight />
            </button>
            
            {/* Show appropriate button based on state */}
            {!flipped && (
              <button 
                className="cybercards-reveal-button"
                onClick={handleFlip}
              >
                Reveal Answer
              </button>
            )}
            
            {flipped && mode === 'study' && (
              <button 
                className="cybercards-reveal-button"
                onClick={handleFlip}
              >
                Show Question
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
        >
          Complete Session
        </button>
      </div>
    </div>
  );
};

export default FlashcardStudy;
