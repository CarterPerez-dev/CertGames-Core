// frontend/my-react-app/src/components/pages/CyberCards/SavedFlashcards.js
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';
import axios from 'axios';
import { 
  FaArrowLeft, 
  FaBookmark, 
  FaSpinner,
  FaExclamationTriangle,
  FaTerminal,
  FaFilter,
  FaSortAmountDown
} from 'react-icons/fa';
import './CyberCards.css';

const SavedFlashcards = () => {
  const [savedCards, setSavedCards] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [sortOrder, setSortOrder] = useState('newest');
  
  const { userId } = useSelector((state) => state.user);
  const navigate = useNavigate();
  
  useEffect(() => {
    const fetchSavedCards = async () => {
      if (!userId) {
        setLoading(false);
        return;
      }
      
      try {
        setLoading(true);
        const response = await axios.get(`/api/test/flashcards/saved/${userId}`);
        setSavedCards(response.data);
      } catch (err) {
        console.error('Error fetching saved flashcards:', err);
        setError('Failed to load saved flashcards. Please try again later.');
      } finally {
        setLoading(false);
      }
    };
    
    fetchSavedCards();
  }, [userId]);
  
  const handleRemoveSaved = async (cardId) => {
    try {
      await axios.post('/api/test/flashcards/save', {
        userId,
        flashcardId: cardId
      });
      
      // Remove the card from the local state
      setSavedCards(prev => prev.filter(card => card._id !== cardId));
    } catch (err) {
      console.error('Error removing saved flashcard:', err);
    }
  };
  
  const handleFilterChange = (newFilter) => {
    setFilter(newFilter);
  };
  
  const handleSortChange = (newSort) => {
    setSortOrder(newSort);
  };
  
  // Apply filters and sorting
  const filteredCards = filter === 'all' 
    ? savedCards 
    : savedCards.filter(card => card.categoryCode === filter);
    
  const sortedCards = [...filteredCards].sort((a, b) => {
    if (sortOrder === 'newest') {
      return new Date(b.savedAt || 0) - new Date(a.savedAt || 0);
    } else {
      return a.categoryName?.localeCompare(b.categoryName || '');
    }
  });
  
  if (loading) {
    return (
      <div className="cybercards-container">
        <div className="cybercards-loading">
          <FaSpinner className="cybercards-spinner" />
          <p>Loading saved flashcards...</p>
        </div>
      </div>
    );
  }
  
  if (!userId) {
    return (
      <div className="cybercards-container">
        <div className="cybercards-error">
          <p>You need to be logged in to view saved flashcards.</p>
          <button 
            className="cybercards-button"
            onClick={() => navigate('/login')}
          >
            Log In
          </button>
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
  
  return (
    <div className="cybercards-container">
      <div className="cybercards-background">
        <div className="cybercards-grid"></div>
        <div className="cybercards-glow"></div>
      </div>
      
      <div className="cybercards-saved-header">
        <button 
          className="cybercards-back-button" 
          onClick={() => navigate('/cybercards')}
        >
          <FaArrowLeft /> Back to Vaults
        </button>
        <h2 className="cybercards-saved-title">
          <FaTerminal className="cybercards-title-icon" />
          <FaBookmark className="cybercards-title-icon" style={{ marginLeft: '8px' }} />
          Saved Flashcards
        </h2>
      </div>
      
      <div className="cybercards-saved-filters">
        <div className="cybercards-filter-group">
          <FaFilter className="cybercards-filter-icon" />
          <select 
            className="cybercards-select"
            value={filter}
            onChange={(e) => handleFilterChange(e.target.value)}
          >
            <option value="all">All Categories</option>
            {/* Add options for each category */}
            <option value="aplus">CompTIA A+</option>
            <option value="nplus">CompTIA Network+</option>
            <option value="secplus">CompTIA Security+</option>
            {/* Add more options based on your categories */}
          </select>
        </div>
        
        <div className="cybercards-filter-group">
          <FaSortAmountDown className="cybercards-filter-icon" />
          <select 
            className="cybercards-select"
            value={sortOrder}
            onChange={(e) => handleSortChange(e.target.value)}
          >
            <option value="newest">Newest First</option>
            <option value="category">By Category</option>
          </select>
        </div>
      </div>
      
      {sortedCards.length === 0 ? (
        <div className="cybercards-empty-saved">
          <FaBookmark className="cybercards-empty-icon" />
          <h3>No saved flashcards</h3>
          <p>Cards you save while studying will appear here for quick review.</p>
          <button 
            className="cybercards-button"
            onClick={() => navigate('/cybercards')}
          >
            Start Studying
          </button>
        </div>
      ) : (
        <div className="cybercards-saved-grid">
          {sortedCards.map((card) => (
            <div key={card._id} className="cybercards-saved-card">
              <div className="cybercards-saved-card-header">
                <span className="cybercards-saved-card-category">
                  {card.categoryName || 'Unknown Category'}
                </span>
                <button 
                  className="cybercards-saved-remove"
                  onClick={() => handleRemoveSaved(card._id)}
                >
                  <FaBookmark />
                </button>
              </div>
              <div className="cybercards-saved-card-content">
                <div className="cybercards-saved-question">
                  <h4>Question:</h4>
                  <p>{card.question}</p>
                </div>
                <div className="cybercards-saved-answer">
                  <h4>Answer:</h4>
                  <p>{card.answer}</p>
                </div>
              </div>
              <div className="cybercards-saved-card-footer">
                <button 
                  className="cybercards-button small"
                  onClick={() => navigate(`/cybercards/vault/${card.categoryId}`)}
                >
                  Study This Category
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default SavedFlashcards;
