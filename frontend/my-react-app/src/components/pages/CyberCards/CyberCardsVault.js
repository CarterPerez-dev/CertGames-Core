// frontend/my-react-app/src/components/pages/CyberCards/CyberCardsVault.js
import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';
import axios from 'axios';
import { 
  FaLock, 
  FaUnlock, 
  FaInfoCircle, 
  FaChevronRight, 
  FaSpinner,
  FaTerminal,
  FaCertificate,
  FaSearch,
  FaBookmark,
  FaChartPie,
  FaStar,
  FaFilter,
  FaSortAmountDown
} from 'react-icons/fa';
import './CyberCards.css';

const CyberCardsVault = () => {
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [hoveredVault, setHoveredVault] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filteredCategories, setFilteredCategories] = useState([]);
  const [sortOrder, setSortOrder] = useState('alphabetical');
  const [difficulty, setDifficulty] = useState('all');
  const [userStats, setUserStats] = useState(null);
  const [statsLoading, setStatsLoading] = useState(false);
  
  const { userId } = useSelector((state) => state.user);
  const navigate = useNavigate();
  
  const fetchCategories = useCallback(async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/test/flashcards/categories');
      setCategories(response.data);
      setFilteredCategories(response.data);
      setError(null);
    } catch (err) {
      console.error('Error fetching flashcard categories:', err);
      setError('Failed to load flashcard categories. Please try again later.');
    } finally {
      setLoading(false);
    }
  }, []);
  
  const fetchUserStats = useCallback(async () => {
    if (!userId) return;
    
    try {
      setStatsLoading(true);
      const response = await axios.get(`/api/test/flashcards/stats/${userId}`);
      setUserStats(response.data);
    } catch (err) {
      console.error('Error fetching user stats:', err);
    } finally {
      setStatsLoading(false);
    }
  }, [userId]);
  
  useEffect(() => {
    fetchCategories();
    fetchUserStats();
  }, [fetchCategories, fetchUserStats]);
  
  // Apply filters and sorting whenever relevant state changes
  useEffect(() => {
    let result = [...categories];
    
    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(category => 
        category.title.toLowerCase().includes(query) ||
        category.description?.toLowerCase().includes(query)
      );
    }
    
    // Apply difficulty filter
    if (difficulty !== 'all') {
      result = result.filter(category => 
        category.difficulty?.toLowerCase() === difficulty.toLowerCase()
      );
    }
    
    // Apply sorting
    if (sortOrder === 'alphabetical') {
      result.sort((a, b) => a.title.localeCompare(b.title));
    } else if (sortOrder === 'cardCount') {
      result.sort((a, b) => (b.cardCount || 0) - (a.cardCount || 0));
    } else if (sortOrder === 'difficulty') {
      // Custom difficulty order: Beginner, Intermediate, Advanced
      const difficultyOrder = { 'beginner': 1, 'intermediate': 2, 'advanced': 3 };
      result.sort((a, b) => {
        const diffA = a.difficulty?.toLowerCase() || '';
        const diffB = b.difficulty?.toLowerCase() || '';
        return (difficultyOrder[diffA] || 0) - (difficultyOrder[diffB] || 0);
      });
    } else if (sortOrder === 'recent') {
      // If we have user stats, sort by most recently viewed
      if (userStats) {
        result.sort((a, b) => {
          const lastViewedA = userStats[a._id]?.lastViewed || 0;
          const lastViewedB = userStats[b._id]?.lastViewed || 0;
          return lastViewedB - lastViewedA;
        });
      }
    }
    
    setFilteredCategories(result);
  }, [categories, searchQuery, difficulty, sortOrder, userStats]);
  
  const handleVaultClick = (categoryId) => {
    navigate(`/cybercards/vault/${categoryId}`);
  };
  
  const getCategoryProgress = (categoryId) => {
    if (!userStats || !userStats[categoryId]) return 0;
    
    const categoryStats = userStats[categoryId];
    if (!categoryStats.answered) return 0;
    
    const totalCards = categories.find(c => c._id === categoryId)?.cardCount || 0;
    if (totalCards === 0) return 0;
    
    return Math.min(Math.round((categoryStats.answered / totalCards) * 100), 100);
  };
  
  const getVaultStatus = (categoryId) => {
    const progress = getCategoryProgress(categoryId);
    
    if (progress >= 95) return 'mastered';
    if (progress >= 50) return 'learning';
    if (progress > 0) return 'started';
    return 'unopened';
  };
  
  return (
    <div className="cybercards-container">
      <div className="cybercards-background">
        <div className="cybercards-grid"></div>
        <div className="cybercards-glow"></div>
      </div>
      
      <div className="cybercards-header">
        <h1 className="cybercards-title">
          <FaTerminal className="cybercards-title-icon" />
          The Cyber Vault
        </h1>
        <p className="cybercards-subtitle">Unlock your potential with interactive flashcards for cybersecurity certifications</p>
        
        <div className="cybercards-actions">
          <button 
            className="cybercards-action-button"
            onClick={() => navigate('/cybercards/saved')}
            title="View saved flashcards"
          >
            <FaBookmark /> Saved Flashcards
          </button>
          
          <div className="cybercards-search-container">
            <FaSearch className="cybercards-search-icon" />
            <input 
              type="text" 
              className="cybercards-search-input" 
              placeholder="Search certifications..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
        
        <div className="cybercards-filter-bar">
          <div className="cybercards-filter-group">
            <FaFilter className="cybercards-filter-icon" />
            <select
              className="cybercards-select"
              value={difficulty}
              onChange={(e) => setDifficulty(e.target.value)}
            >
              <option value="all">All Difficulties</option>
              <option value="beginner">Beginner</option>
              <option value="intermediate">Intermediate</option>
              <option value="advanced">Advanced</option>
            </select>
          </div>
          
          <div className="cybercards-filter-group">
            <FaSortAmountDown className="cybercards-filter-icon" />
            <select
              className="cybercards-select"
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value)}
            >
              <option value="alphabetical">Alphabetical</option>
              <option value="cardCount">Card Count</option>
              <option value="difficulty">Difficulty Level</option>
              <option value="recent">Recently Viewed</option>
            </select>
          </div>
        </div>
      </div>
      
      {loading ? (
        <div className="cybercards-loading">
          <FaSpinner className="cybercards-spinner" />
          <p>Decrypting vault contents...</p>
        </div>
      ) : error ? (
        <div className="cybercards-error">
          <p>{error}</p>
          <button className="cybercards-button" onClick={() => window.location.reload()}>Try Again</button>
        </div>
      ) : filteredCategories.length === 0 ? (
        <div className="cybercards-empty">
          <p>No flashcard vaults match your search criteria.</p>
          <button 
            className="cybercards-button"
            onClick={() => {
              setSearchQuery('');
              setDifficulty('all');
              setSortOrder('alphabetical');
            }}
          >
            Clear Filters
          </button>
        </div>
      ) : (
        <>
          <div className="cybercards-vaults-grid">
            {filteredCategories.map((category) => {
              const vaultStatus = getVaultStatus(category._id);
              const progressPercent = getCategoryProgress(category._id);
              
              return (
                <div 
                  key={category._id} 
                  className={`cybercards-vault ${vaultStatus}`}
                  onClick={() => handleVaultClick(category._id)}
                  onMouseEnter={() => setHoveredVault(category._id)}
                  onMouseLeave={() => setHoveredVault(null)}
                >
                  <div className="cybercards-vault-icon">
                    {category.locked ? <FaLock /> : <FaUnlock />}
                  </div>
                  <div className="cybercards-vault-content">
                    <h3 className="cybercards-vault-title">
                      <FaCertificate className="cybercards-vault-cert-icon" />
                      {category.title}
                    </h3>
                    <p className="cybercards-vault-count">{category.cardCount || 0} Cards</p>
                    <div className="cybercards-vault-footer">
                      <span className="cybercards-vault-difficulty">
                        {category.difficulty || 'Mixed'}
                      </span>
                      {progressPercent > 0 && (
                        <div className="cybercards-vault-progress">
                          <div className="cybercards-vault-progress-bar">
                            <div 
                              className="cybercards-vault-progress-fill"
                              style={{ width: `${progressPercent}%` }}
                            ></div>
                          </div>
                          <span className="cybercards-vault-progress-text">
                            {progressPercent}%
                          </span>
                        </div>
                      )}
                      <FaChevronRight className="cybercards-vault-arrow" />
                    </div>
                  </div>
                  
                  {hoveredVault === category._id && (
                    <div className="cybercards-vault-tooltip">
                      <p>{category.description || 'Master the concepts for this certification.'}</p>
                      {userStats && userStats[category._id] && (
                        <div className="cybercards-vault-stats">
                          <div className="cybercards-vault-stat">
                            <span>Viewed:</span> 
                            <span>{userStats[category._id].viewed || 0} times</span>
                          </div>
                          <div className="cybercards-vault-stat">
                            <span>Answered:</span> 
                            <span>{userStats[category._id].answered || 0} cards</span>
                          </div>
                          <div className="cybercards-vault-stat">
                            <span>Completion:</span> 
                            <span>{progressPercent}%</span>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                  
                  <div className="cybercards-vault-overlay"></div>
                  <div className="cybercards-vault-scanning-line"></div>
                  
                  {vaultStatus === 'mastered' && (
                    <div className="cybercards-vault-mastered">
                      <FaStar />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          
          {userId && !statsLoading && userStats && (
            <div className="cybercards-stats-overview">
              <h3><FaChartPie /> Your Progress</h3>
              <div className="cybercards-stats-grid">
                <div className="cybercards-stat-card">
                  <div className="cybercards-stat-title">Total Cards Viewed</div>
                  <div className="cybercards-stat-value">
                    {Object.values(userStats).reduce((sum, cat) => sum + (cat.viewed || 0), 0)}
                  </div>
                </div>
                <div className="cybercards-stat-card">
                  <div className="cybercards-stat-title">Total Cards Answered</div>
                  <div className="cybercards-stat-value">
                    {Object.values(userStats).reduce((sum, cat) => sum + (cat.answered || 0), 0)}
                  </div>
                </div>
                <div className="cybercards-stat-card">
                  <div className="cybercards-stat-title">Mastered Categories</div>
                  <div className="cybercards-stat-value">
                    {filteredCategories.filter(cat => getVaultStatus(cat._id) === 'mastered').length}
                  </div>
                </div>
                <div className="cybercards-stat-card">
                  <div className="cybercards-stat-title">Average Completion</div>
                  <div className="cybercards-stat-value">
                    {Math.round(
                      filteredCategories.reduce((sum, cat) => sum + getCategoryProgress(cat._id), 0) / 
                      filteredCategories.length
                    )}%
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}
      
      <div className="cybercards-info-section">
        <div className="cybercards-info-card">
          <div className="cybercards-info-header">
            <FaInfoCircle className="cybercards-info-icon" />
            <h3>About Cyber Cards</h3>
          </div>
          <p>Interactive flashcards to help you master cybersecurity concepts and prepare for certification exams. Flip through cards, save your favorites, and track your progress.</p>
          <ul className="cybercards-features-list">
            <li>Review key concepts for 13 popular certifications</li>
            <li>Save challenging cards for focused study sessions</li>
            <li>Terminal-style interface for an authentic cyber experience</li>
            <li>Track your progress and master difficult concepts</li>
            <li>Multiple study modes including quiz and challenge</li>
            <li>Customize your learning with card reversing and difficulty tracking</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default CyberCardsVault;
