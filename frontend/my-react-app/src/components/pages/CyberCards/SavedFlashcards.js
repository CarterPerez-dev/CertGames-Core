// frontend/my-react-app/src/components/pages/CyberCards/SavedFlashcards.js
import React, { useState, useEffect, useCallback } from 'react';
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
  FaSortAmountDown,
  FaSearch,
  FaSyncAlt,
  FaTrash,
  FaTags
} from 'react-icons/fa';
import './CyberCards.css';

const SavedFlashcards = () => {
  const [savedCards, setSavedCards] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [sortOrder, setSortOrder] = useState('newest');
  const [searchQuery, setSearchQuery] = useState('');
  const [categories, setCategories] = useState([]);
  const [bulkDeleteMode, setBulkDeleteMode] = useState(false);
  const [selectedCards, setSelectedCards] = useState([]);
  
  const { userId } = useSelector((state) => state.user);
  const navigate = useNavigate();
  
  const fetchSavedCards = useCallback(async () => {
    if (!userId) {
      setLoading(false);
      return;
    }
    
    try {
      setLoading(true);
      
      // Fetch categories for filter dropdown
      const categoriesResponse = await axios.get('/api/test/flashcards/categories');
      setCategories(categoriesResponse.data);
      
      // Fetch saved cards
      const response = await axios.get(`/api/test/flashcards/saved/${userId}`);
      setSavedCards(response.data);
      setError(null);
    } catch (err) {
      console.error('Error fetching saved flashcards:', err);
      setError('Failed to load saved flashcards. Please try again later.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [userId]);
  
  useEffect(() => {
    fetchSavedCards();
  }, [fetchSavedCards]);
  
  const handleRefresh = () => {
    setRefreshing(true);
    fetchSavedCards();
  };
  
  const handleRemoveSaved = async (cardId, event) => {
    // Prevent triggering parent click handlers
    if (event) {
      event.stopPropagation();
    }
    
    try {
      await axios.post('/api/test/flashcards/save', {
        userId,
        flashcardId: cardId
      });
      
      // Remove the card from the local state
      setSavedCards(prev => prev.filter(card => card._id !== cardId));
      
      // Remove from selected cards if in bulk delete mode
      if (bulkDeleteMode) {
        setSelectedCards(prev => prev.filter(id => id !== cardId));
      }
    } catch (err) {
      console.error('Error removing saved flashcard:', err);
    }
  };
  
  const handleBulkDelete = async () => {
    if (selectedCards.length === 0) return;
    
    // Confirm before deleting
    if (!window.confirm(`Remove ${selectedCards.length} selected flashcards from your saved collection?`)) {
      return;
    }
    
    try {
      // Process deletion one by one
      for (const cardId of selectedCards) {
        await axios.post('/api/test/flashcards/save', {
          userId,
          flashcardId: cardId
        });
      }
      
      // Update local state
      setSavedCards(prev => prev.filter(card => !selectedCards.includes(card._id)));
      setSelectedCards([]);
      
      // Exit bulk delete mode
      setBulkDeleteMode(false);
    } catch (err) {
      console.error('Error performing bulk delete:', err);
    }
  };
  
  const handleCardClick = (card) => {
    if (bulkDeleteMode) {
      // Toggle selection
      setSelectedCards(prev => {
        if (prev.includes(card._id)) {
          return prev.filter(id => id !== card._id);
        } else {
          return [...prev, card._id];
        }
      });
    } else {
      // Navigate to study this category
      navigate(`/cybercards/vault/${card.categoryId}`);
    }
  };
  
  const handleFilterChange = (newFilter) => {
    setFilter(newFilter);
  };
  
  const handleSortChange = (newSort) => {
    setSortOrder(newSort);
  };
  
  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };
  
  const toggleBulkDeleteMode = () => {
    setBulkDeleteMode(prev => !prev);
    setSelectedCards([]);
  };
  
  // Apply filters, search, and sorting
  const filteredCards = savedCards.filter(card => {
    // Category filter
    if (filter !== 'all' && card.categoryCode !== filter) {
      return false;
    }
    
    // Search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      const questionMatches = card.question?.toLowerCase().includes(query);
      const answerMatches = card.answer?.toLowerCase().includes(query);
      const categoryMatches = card.categoryName?.toLowerCase().includes(query);
      
      return questionMatches || answerMatches || categoryMatches;
    }
    
    return true;
  });
    
  const sortedCards = [...filteredCards].sort((a, b) => {
    if (sortOrder === 'newest') {
      return new Date(b.savedAt || 0) - new Date(a.savedAt || 0);
    } else if (sortOrder === 'oldest') {
      return new Date(a.savedAt || 0) - new Date(b.savedAt || 0);
    } else if (sortOrder === 'category') {
      return a.categoryName?.localeCompare(b.categoryName || '');
    } else if (sortOrder === 'alphabetical') {
      return a.question?.localeCompare(b.question || '');
    }
    return 0;
  });
  
  if (loading && !refreshing) {
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
        <div className="cybercards-saved-actions">
          <button
            className={`cybercards-action-button ${refreshing ? 'loading' : ''}`}
            onClick={handleRefresh}
            disabled={refreshing}
            title="Refresh saved cards"
          >
            {refreshing ? <FaSpinner className="cybercards-spinner" /> : <FaSyncAlt />}
          </button>
          <button
            className={`cybercards-action-button ${bulkDeleteMode ? 'active' : ''}`}
            onClick={toggleBulkDeleteMode}
            title={bulkDeleteMode ? "Exit selection mode" : "Enter selection mode"}
          >
            <FaTrash />
          </button>
        </div>
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
            {categories.map(category => (
              <option key={category._id} value={category.code}>
                {category.title}
              </option>
            ))}
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
            <option value="oldest">Oldest First</option>
            <option value="category">By Category</option>
            <option value="alphabetical">Alphabetical</option>
          </select>
        </div>
        
        <div className="cybercards-search-group">
          <input
            type="text"
            className="cybercards-search-input"
            placeholder="Search saved cards..."
            value={searchQuery}
            onChange={handleSearchChange}
          />
        </div>
      </div>
      
      {bulkDeleteMode && (
        <div className="cybercards-bulk-actions">
          <span className="cybercards-selection-count">
            {selectedCards.length} cards selected
          </span>
          <button
            className="cybercards-button delete"
            onClick={handleBulkDelete}
            disabled={selectedCards.length === 0}
          >
            <FaTrash /> Remove Selected
          </button>
          <button
            className="cybercards-button cancel"
            onClick={toggleBulkDeleteMode}
          >
            Cancel
          </button>
        </div>
      )}
      
      {sortedCards.length === 0 ? (
        <div className="cybercards-empty-saved">
          <FaBookmark className="cybercards-empty-icon" />
          <h3>No saved flashcards{filter !== 'all' || searchQuery ? ' matching your criteria' : ''}</h3>
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
            <div 
              key={card._id} 
              className={`cybercards-saved-card ${bulkDeleteMode ? 'selectable' : ''} ${selectedCards.includes(card._id) ? 'selected' : ''}`}
              onClick={() => handleCardClick(card)}
            >
              <div className="cybercards-saved-card-header">
                <span className="cybercards-saved-card-category">
                  <FaTags className="cybercards-category-icon" />
                  {card.categoryName || 'Unknown Category'}
                </span>
                <button 
                  className="cybercards-saved-remove"
                  onClick={(e) => handleRemoveSaved(card._id, e)}
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
                {bulkDeleteMode ? (
                  <div className="cybercards-card-checkbox">
                    <input 
                      type="checkbox" 
                      checked={selectedCards.includes(card._id)}
                      onChange={() => {
                        // Handled by the card click event
                      }}
                      onClick={(e) => e.stopPropagation()}
                    />
                    <span className="cybercards-checkbox-text">Select</span>
                  </div>
                ) : (
                  <button 
                    className="cybercards-button small"
                    onClick={() => navigate(`/cybercards/vault/${card.categoryId}`)}
                  >
                    Study This Category
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default SavedFlashcards;
