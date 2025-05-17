// frontend/my-react-app/src/components/pages/CyberCards/FlashcardStudy.js
import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';
import axios from 'axios';
import { 
  FaArrowLeft, 
  FaBookmark, 
  FaRegBookmark, 
  FaChevronLeft, 
  FaChevronRight,
  FaEye,
  FaTerminal,
  FaSpinner,
  FaExclamationTriangle,
  FaVolumeUp,
  FaFlagCheckered,
  FaTags
} from 'react-icons/fa';
import './CyberCards.css';

const LOCAL_STORAGE_PREFIX = 'cyberCards_';

const FlashcardStudy = () => {
  const { categoryId } = useParams();
  const [flashcards, setFlashcards] = useState([]);
  const [categoryInfo, setCategoryInfo] = useState(null);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [flipped, setFlipped] = useState(false);
  const [loading, setLoading] = useState(true); // For initial page load
  const [loadingAction, setLoadingAction] = useState(false); // For API calls or truly blocking actions
  const [error, setError] = useState(null);
  const [savedCards, setSavedCards] = useState({});
  
  const { userId } = useSelector((state) => state.user);
  const navigate = useNavigate();
  
  useEffect(() => {
    const fetchFlashcards = async () => {
      setLoading(true);
      setError(null);
      try {
        if (!categoryId) {
          setError('No category selected');
          return;
        }
        const response = await axios.get(`/api/test/flashcards/category/${categoryId}`);
        if (response.data.flashcards && response.data.flashcards.length > 0) {
          const savedIndex = localStorage.getItem(`${LOCAL_STORAGE_PREFIX}currentIndex_${categoryId}`);
          const initialIndex = savedIndex ? parseInt(savedIndex, 10) : 0;
          
          setFlashcards(response.data.flashcards);
          setCurrentIndex(initialIndex);

          const firstCard = response.data.flashcards[0];
          if (firstCard.categoryName) {
            setCategoryInfo({
              title: firstCard.categoryName,
              description: firstCard.categoryDescription || 'Study flashcards for this certification.'
            });
          }
          
          if (userId) {
            axios.post('/api/test/flashcards/record-progress', { userId, categoryId, interactionType: 'viewed' })
              .catch(err => console.error('Failed to record view progress:', err));
            
            axios.get(`/api/test/flashcards/saved/${userId}`)
              .then(savedResponse => {
                const savedMap = {};
                if (savedResponse.data && Array.isArray(savedResponse.data)) {
                  savedResponse.data.forEach(card => { if (card._id) savedMap[card._id] = true; });
                }
                setSavedCards(savedMap);
              })
              .catch(err => console.error('Failed to fetch saved cards:', err));
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
  
  useEffect(() => {
    if (categoryId && currentIndex !== undefined && flashcards.length > 0) {
      localStorage.setItem(`${LOCAL_STORAGE_PREFIX}currentIndex_${categoryId}`, currentIndex.toString());
    }
  }, [currentIndex, categoryId, flashcards.length]);

  // Navigate to the next card
  const handleNextCard = useCallback(() => {
    if (loadingAction || flashcards.length === 0) return;
    setFlipped(false);
    setCurrentIndex(prevIndex => (prevIndex < flashcards.length - 1 ? prevIndex + 1 : 0));
  }, [flashcards.length, loadingAction]);

  // Navigate to the previous card
  const handlePreviousCard = useCallback(() => {
    if (loadingAction || flashcards.length === 0) return;
    setFlipped(false);
    setCurrentIndex(prevIndex => (prevIndex > 0 ? prevIndex - 1 : flashcards.length - 1));
  }, [flashcards.length, loadingAction]);
  
  // Flip the card
  const handleFlip = useCallback(() => {
    if (loadingAction) return; // Respect global loading state for API calls
    
    const newFlippedState = !flipped;
    setFlipped(newFlippedState);
    
    if (newFlippedState && userId) { // Flipped to show answer
      axios.post('/api/test/flashcards/record-progress', { userId, categoryId, interactionType: 'answered' })
          .catch(err => console.error('Failed to record answer progress:', err));
    }
  }, [flipped, userId, categoryId, loadingAction]);
  
  // Save or unsave the card
  const handleSaveCard = useCallback(async () => {
    if (!userId || flashcards.length === 0 || loadingAction || !flashcards[currentIndex]) return;
    setLoadingAction(true); // This is an API call, so use loadingAction
    try {
      const cardId = flashcards[currentIndex]._id;
      const response = await axios.post('/api/test/flashcards/save', { userId, flashcardId: cardId });
      if (response.data.saved) {
        setSavedCards(prev => ({...prev, [cardId]: true}));
      } else {
        setSavedCards(prev => { const updated = {...prev}; delete updated[cardId]; return updated; });
      }
    } catch (err) { console.error('Error saving flashcard:', err); }
    finally { setLoadingAction(false); }
  }, [userId, flashcards, currentIndex, loadingAction]);
  
  // Complete the study session
  const handleCompleteSession = useCallback(async () => {
    if (!userId || loadingAction) return;
    setLoadingAction(true); // API call
    try {
      // For simplicity, we're not sending detailed correct/incorrect stats from the frontend anymore.
      // The backend could infer reviewed cards based on 'answered' interactions if needed, or client sends total.
      const reviewedCount = Math.min(currentIndex + 1, flashcards.length); 
      await axios.post('/api/test/flashcards/record-progress', {
        userId, categoryId, interactionType: 'completed',
        sessionStats: {
          // duration can be calculated if `sessionStats.started` was maintained, or simply by backend
          cardsReviewed: reviewedCount 
        }
      });
    } catch (err) { console.error('Error recording session completion:', err); }
    finally { setLoadingAction(false); navigate('/cybercards'); }
  }, [userId, categoryId, loadingAction, navigate, currentIndex, flashcards.length]);
  
  // Speak text
  const speakText = (text) => {
    if (!window.speechSynthesis || !text) return;
    try {
      window.speechSynthesis.cancel();
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = 0.9;
      window.speechSynthesis.speak(utterance);
    } catch (err) { console.error("Error with speech synthesis:", err); }
  };

  // Render states
  if (loading) return <div className="cybercards-container"><div className="cybercards-loading"><FaSpinner className="cybercards-spinner" /><p>Loading flashcards...</p></div></div>;
  if (error) return <div className="cybercards-container"><div className="cybercards-error"><FaExclamationTriangle className="cybercards-error-icon" /><p>{error}</p><button className="cybercards-button" onClick={() => navigate('/cybercards')}><FaArrowLeft /> Back to Vaults</button></div></div>;
  if (flashcards.length === 0) return <div className="cybercards-container"><div className="cybercards-empty"><h2>No flashcards found</h2><p>This vault appears to be empty.</p><button className="cybercards-button" onClick={() => navigate('/cybercards')}><FaArrowLeft /> Back to Vaults</button></div></div>;

  const currentCard = flashcards[currentIndex];
  const isSaved = currentCard && savedCards[currentCard._id];
  const question = currentCard ? currentCard.question : 'Card data not available';
  const answer = currentCard ? currentCard.answer : 'Card data not available';
  const progressPercent = flashcards.length > 0 ? ((currentIndex + 1) / flashcards.length) * 100 : 0;

  return (
    <div className="cybercards-container">
      <div className="cybercards-background"><div className="cybercards-grid"></div><div className="cybercards-glow"></div></div>
      
      <div className="cybercards-study-header">
        <button className="cybercards-back-button" onClick={() => navigate('/cybercards')} disabled={loadingAction}><FaArrowLeft /> Back to Vaults</button>
        <h2 className="cybercards-study-title"><FaTerminal className="cybercards-title-icon" />{categoryInfo?.title || 'Flashcards'}</h2>
        {/* Controls like shuffle, reverse, mode selector are removed */}
      </div>
      
      {/* Simplified session stats - only progress indication */}
      <div className="cybercards-progress simplified-progress-bar">
          <div className="cybercards-progress-bar">
            <div 
              className="cybercards-progress-fill"
              style={{ width: `${progressPercent}%` }}
            ></div>
          </div>
          <span className="cybercards-progress-text">
            Card {currentIndex + 1} of {flashcards.length}
          </span>
        </div>
      
      <div className="cybercards-study-content">
        {currentCard ? (<div className="cybercards-flashcard-wrapper">
          <div 
            className={`cybercards-flashcard ${flipped ? 'flipped' : ''} ${loadingAction ? 'disabled-visual-only' : ''}`} // Use a different class if loadingAction should not disable click
            onClick={!flipped ? handleFlip : undefined} // Only allow flip on front if not already flipped
          >
            <div className="cybercards-flashcard-front">
              <div className="cybercards-card-category"><FaTags className="cybercards-card-category-icon" /><span>{currentCard.categoryName || 'Flashcard'}</span></div>
              <div className="cybercards-flashcard-content"><p>{question}</p></div>
              <div className="cybercards-flashcard-footer">
                {!flipped && <span className="cybercards-card-hint"><FaEye /> Click card to reveal</span>}
                <button className="cybercards-audio-button" onClick={(e) => { e.stopPropagation(); speakText(question); }} title="Read question aloud" disabled={loadingAction}><FaVolumeUp /></button>
              </div>
            </div>
            <div className="cybercards-flashcard-back">
              <div className="cybercards-card-category"><FaTags className="cybercards-card-category-icon" /><span>{currentCard.categoryName || 'Flashcard'}</span></div>
              <div className="cybercards-flashcard-content"><p>{answer}</p></div>
              <div className="cybercards-flashcard-footer">
                 <button className="cybercards-audio-button" onClick={(e) => { e.stopPropagation(); speakText(answer); }} title="Read answer aloud" disabled={loadingAction}><FaVolumeUp /></button>
              </div>
            </div>
          </div>
          
          <div className="cybercards-flashcard-actions">
            <button className="cybercards-action-button" onClick={handlePreviousCard} title="Previous card" disabled={loadingAction || currentIndex === 0}><FaChevronLeft /></button>
            <button 
                className={`cybercards-action-button save ${isSaved ? 'saved' : ''} ${loadingAction && currentCard && (savedCards[currentCard._id] || !isSaved) ? 'loading' : ''}`}
                onClick={handleSaveCard} 
                disabled={loadingAction} 
                title={isSaved ? "Remove from saved" : "Save card"}
            >
                {/* Conditional spinner only if this specific action is causing loading */}
                {loadingAction && currentCard && (savedCards[currentCard._id] === undefined ? 'saving_process_indicator' : 'unsaving_process_indicator') ? 
                  <FaSpinner className="cybercards-spinner" /> : (isSaved ? <FaBookmark /> : <FaRegBookmark />)
                }
            </button>
            <button className="cybercards-action-button" onClick={handleNextCard} title="Next card" disabled={loadingAction || currentIndex === flashcards.length - 1}><FaChevronRight /></button>
          </div>
          
          <div className="cybercards-card-controls">
            {!flipped ? (
              <button className="cybercards-reveal-button" onClick={handleFlip} disabled={loadingAction}>
                {loadingAction ? <FaSpinner className="cybercards-spinner" /> : 'Reveal Answer'}
              </button>
            ) : (
              <button className="cybercards-reveal-button" onClick={handleNextCard} disabled={loadingAction || currentIndex === flashcards.length - 1}>
                {loadingAction ? <FaSpinner className="cybercards-spinner" /> : 'Next Card'}
              </button>
            )}
          </div>
        </div>) : (<div className="cybercards-empty"><p>Current card data is unavailable.</p></div>)}
      </div>
    </div>
  );
};

export default FlashcardStudy;
