// frontend/my-react-app/src/components/pages/CyberCards/FlashcardStudy.js
import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
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
  FaExclamationTriangle
} from 'react-icons/fa';
import './CyberCards.css';

const FlashcardStudy = () => {
  const { categoryId } = useParams();
  const [flashcards, setFlashcards] = useState([]);
  const [categoryInfo, setCategoryInfo] = useState(null);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [flipped, setFlipped] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [savedCards, setSavedCards] = useState({});
  const [mode, setMode] = useState('study'); // 'study', 'quiz', 'challenge'
  const [streak, setStreak] = useState(0);
  
  const { userId } = useSelector((state) => state.user);
  const navigate = useNavigate();
  const dispatch = useDispatch();
  
  const cardRef = useRef(null);
  
  useEffect(() => {
    const fetchFlashcards = async () => {
      try {
        setLoading(true);
        
        // Fetch the flashcards for this category
        const response = await axios.get(`/api/test/flashcards/category/${categoryId}`);
        
        if (response.data.flashcards && response.data.flashcards.length > 0) {
          setFlashcards(response.data.flashcards);
          
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
            await axios.post('/api/test/flashcards/record-progress', {
              userId,
              categoryId,
              interactionType: 'viewed'
            });
          }
          
          // Fetch saved cards
          if (userId) {
            const savedResponse = await axios.get(`/api/test/flashcards/saved/${userId}`);
            const savedMap = {};
            savedResponse.data.forEach(card => {
              savedMap[card._id] = true;
            });
            setSavedCards(savedMap);
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
  }, [categoryId, userId]);
  
  // Reset flipped state when changing cards
  useEffect(() => {
    setFlipped(false);
  }, [currentIndex]);
  
  const handleNextCard = () => {
    if (currentIndex < flashcards.length - 1) {
      setCurrentIndex(currentIndex + 1);
    } else {
      // Loop back to the first card
      setCurrentIndex(0);
    }
  };
  
  const handlePreviousCard = () => {
    if (currentIndex > 0) {
      setCurrentIndex(currentIndex - 1);
    } else {
      // Loop to the last card
      setCurrentIndex(flashcards.length - 1);
    }
  };
  
  const handleFlip = async () => {
    setFlipped(!flipped);
    
    // If flipping to show answer, record this interaction
    if (!flipped && userId) {
      try {
        await axios.post('/api/test/flashcards/record-progress', {
          userId,
          categoryId,
          interactionType: 'answered'
        });
      } catch (err) {
        console.error('Error recording flashcard progress:', err);
      }
    }
  };
  
  const handleSaveCard = async () => {
    if (!userId) return;
    
    try {
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
    }
  };
  
  const handleShuffle = () => {
    const shuffled = [...flashcards].sort(() => Math.random() - 0.5);
    setFlashcards(shuffled);
    setCurrentIndex(0);
  };
  
  const handleModeChange = (newMode) => {
    setMode(newMode);
    setCurrentIndex(0);
    setStreak(0);
  };
  
  const handleCorrectAnswer = async () => {
    // Increment streak, award XP/coins for streaks
    const newStreak = streak + 1;
    setStreak(newStreak);
    
    if (newStreak % 5 === 0 && userId) {
      // Award bonus for every 5 card streak
      try {
        await axios.post('/api/test/flashcards/record-progress', {
          userId,
          categoryId,
          interactionType: 'streak'
        });
      } catch (err) {
        console.error('Error recording streak progress:', err);
      }
    }
    
    handleNextCard();
  };
  
  const handleCompleteSession = async () => {
    if (!userId) return;
    
    try {
      await axios.post('/api/test/flashcards/record-progress', {
        userId,
        categoryId,
        interactionType: 'completed'
      });
      
      navigate('/cybercards');
    } catch (err) {
      console.error('Error recording session completion:', err);
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
          <button className="cybercards-button" onClick={() => navigate('/cybercards')}>
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
          <button className="cybercards-button" onClick={() => navigate('/cybercards')}>
            <FaArrowLeft /> Back to Vaults
          </button>
        </div>
      </div>
    );
  }
  
  const currentCard = flashcards[currentIndex];
  const isSaved = currentCard && savedCards[currentCard._id];
  
  return (
    <div className="cybercards-container">
      <div className="cybercards-background">
        <div className="cybercards-grid"></div>
        <div className="cybercards-glow"></div>
      </div>
      
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
        </h2>
        <div className="cybercards-study-controls">
          <button 
            className="cybercards-control-button" 
            onClick={handleShuffle}
            title="Shuffle cards"
          >
            <FaRandom />
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
            className={`cybercards-flashcard ${flipped ? 'flipped' : ''}`}
            onClick={mode === 'study' ? handleFlip : undefined}
          >
            <div className="cybercards-flashcard-front">
              <div className="cybercards-flashcard-content">
                <p>{currentCard?.question || 'Question not available'}</p>
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
              </div>
            </div>
            <div className="cybercards-flashcard-back">
              <div className="cybercards-flashcard-content">
                <p>{currentCard?.answer || 'Answer not available'}</p>
              </div>
              <div className="cybercards-flashcard-footer">
                {mode === 'study' ? (
                  <span className="cybercards-card-hint">
                    <FaEye /> Click to see question again
                  </span>
                ) : (
                  <div className="cybercards-quiz-buttons">
                    <button 
                      className="cybercards-quiz-button correct"
                      onClick={handleCorrectAnswer}
                    >
                      <FaCheck /> Correct
                    </button>
                    <button 
                      className="cybercards-quiz-button incorrect"
                      onClick={handleNextCard}
                    >
                      Wrong
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
            >
              <FaChevronLeft />
            </button>
            
            {mode === 'study' && (
              <button 
                className="cybercards-action-button save"
                onClick={handleSaveCard}
              >
                {isSaved ? <FaBookmark /> : <FaRegBookmark />}
              </button>
            )}
            
            {mode !== 'study' && (
              <span className="cybercards-streak-counter">
                Streak: {streak}
              </span>
            )}
            
            <button 
              className="cybercards-action-button"
              onClick={handleNextCard}
            >
              <FaChevronRight />
            </button>
            
            {mode === 'study' && !flipped && (
              <button 
                className="cybercards-reveal-button"
                onClick={handleFlip}
              >
                Reveal Answer
              </button>
            )}
            
            {mode === 'study' && flipped && (
              <button 
                className="cybercards-reveal-button"
                onClick={handleFlip}
              >
                Show Question
              </button>
            )}
            
            {mode !== 'study' && !flipped && (
              <button 
                className="cybercards-reveal-button"
                onClick={handleFlip}
              >
                Show Answer
              </button>
            )}
          </div>
        </div>
      </div>
      
      <div className="cybercards-session-controls">
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
