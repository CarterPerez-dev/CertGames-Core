// src/components/pages/store/AchievementPage.js
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { fetchAchievements } from '../store/achievementsSlice';
import { 
  FaTrophy, 
  FaMedal, 
  FaStar, 
  FaCrown, 
  FaBolt, 
  FaBook, 
  FaBrain, 
  FaCheckCircle, 
  FaMagic,
  FaFilter,
  FaTimes,
  FaCoins,
  FaLevelUpAlt,
  FaCheck,
  FaLock,
  FaInfoCircle,
  FaChevronDown,
  FaChevronUp,
  FaSearch,
  FaSyncAlt
} from 'react-icons/fa';
import { showAchievementToast } from './AchievementToast';
import './AchievementPage.css';

// Mapping achievement IDs to icon components.
const iconMapping = {
  "test_rookie": FaTrophy,
  "accuracy_king": FaMedal,
  "bronze_grinder": FaBook,
  "silver_scholar": FaStar,
  "gold_god": FaCrown,
  "platinum_pro": FaMagic,
  "walking_encyclopedia": FaBrain,
  "redemption_arc": FaBolt,
  "coin_collector_5000": FaBook,
  "coin_hoarder_10000": FaBook,
  "coin_tycoon_50000": FaBook,
  "perfectionist_1": FaCheckCircle,
  "double_trouble_2": FaCheckCircle,
  "error404_failure_not_found": FaCheckCircle,
  "level_up_5": FaTrophy,
  "mid_tier_grinder_25": FaMedal,
  "elite_scholar_50": FaStar,
  "ultimate_master_100": FaCrown,
  "answer_machine_1000": FaBook,
  "knowledge_beast_5000": FaBrain,
  "question_terminator": FaBrain,
  "test_finisher": FaCheckCircle,
};

// Mapping achievement IDs to colors.
const colorMapping = {
  "test_rookie": "#ff5555",
  "accuracy_king": "#ffa500",
  "bronze_grinder": "#cd7f32",
  "silver_scholar": "#c0c0c0",
  "gold_god": "#ffd700",
  "platinum_pro": "#e5e4e2",
  "walking_encyclopedia": "#00fa9a",
  "redemption_arc": "#ff4500",
  "coin_collector_5000": "#ff69b4",
  "coin_hoarder_10000": "#ff1493",
  "coin_tycoon_50000": "#ff0000",
  "perfectionist_1": "#adff2f",
  "double_trouble_2": "#7fff00",
  "error404_failure_not_found": "#00ffff",
  "level_up_5": "#f08080",
  "mid_tier_grinder_25": "#ff8c00",
  "elite_scholar_50": "#ffd700",
  "ultimate_master_100": "#ff4500",
  "answer_machine_1000": "#ff69b4",
  "knowledge_beast_5000": "#00fa9a",
  "question_terminator": "#ff1493",
  "test_finisher": "#adff2f",
};

// Achievement categories
const categories = {
  "test": "Test Completion",
  "score": "Score & Accuracy",
  "coins": "Coin Collection",
  "level": "Leveling Up",
  "questions": "Question Mastery",
  "all": "All Achievements"
};

// Function to determine the category of an achievement
const getAchievementCategory = (achievementId) => {
  if (achievementId.includes('level') || achievementId.includes('grinder') || 
      achievementId.includes('scholar') || achievementId.includes('master')) {
    return "level";
  } else if (achievementId.includes('coin')) {
    return "coins";
  } else if (achievementId.includes('accuracy') || achievementId.includes('perfectionist') || 
             achievementId.includes('redemption')) {
    return "score";
  } else if (achievementId.includes('answer') || achievementId.includes('question') || 
             achievementId.includes('encyclopedia')) {
    return "questions";
  } else if (achievementId.includes('rookie') || achievementId.includes('test') || 
             achievementId.includes('trouble')) {
    return "test";
  }
  return "all";
};

const AchievementPage = () => {
  const dispatch = useDispatch();
  const achievements = useSelector((state) => state.achievements.all);
  const userAchievements = useSelector((state) => state.user.achievements) || [];
  const { username, level, xp } = useSelector((state) => state.user);
  const loadingStatus = useSelector((state) => state.achievements.status);

  // State for filtering and sorting
  const [activeCategory, setActiveCategory] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [showOnlyUnlocked, setShowOnlyUnlocked] = useState(false);
  const [showOnlyLocked, setShowOnlyLocked] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState({});
  const [sortBy, setSortBy] = useState('default'); // default, name, unlocked
  
  // State for tracking achievement stats
  const [totalAchievements, setTotalAchievements] = useState(0);
  const [unlockedAchievements, setUnlockedAchievements] = useState(0);
  const [percentComplete, setPercentComplete] = useState(0);

  useEffect(() => {
    if (!achievements || achievements.length === 0) {
      dispatch(fetchAchievements());
    }
  }, [dispatch, achievements]);

  useEffect(() => {
    if (achievements && achievements.length > 0) {
      setTotalAchievements(achievements.length);
      setUnlockedAchievements(userAchievements.length);
      setPercentComplete((userAchievements.length / achievements.length) * 100);
    }
  }, [achievements, userAchievements]);

  // Filter achievements based on selected criteria
  const filteredAchievements = achievements.filter(achievement => {
    // Category filter
    const categoryMatch = activeCategory === 'all' || 
                        getAchievementCategory(achievement.achievementId) === activeCategory;
    
    // Unlock status filter
    const isUnlocked = userAchievements.includes(achievement.achievementId);
    const statusMatch = (showOnlyUnlocked && isUnlocked) || 
                      (showOnlyLocked && !isUnlocked) || 
                      (!showOnlyUnlocked && !showOnlyLocked);
    
    // Search filter
    const searchMatch = !searchTerm || 
                      achievement.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
                      achievement.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    return categoryMatch && statusMatch && searchMatch;
  });

  // Sort achievements
  const sortedAchievements = [...filteredAchievements].sort((a, b) => {
    const aUnlocked = userAchievements.includes(a.achievementId);
    const bUnlocked = userAchievements.includes(b.achievementId);
    
    if (sortBy === 'name') {
      return a.title.localeCompare(b.title);
    } else if (sortBy === 'unlocked') {
      return bUnlocked - aUnlocked; // Show unlocked first
    } else if (sortBy === 'locked') {
      return aUnlocked - bUnlocked; // Show locked first
    }
    
    // Default sorting
    return 0;
  });

  const toggleDetails = (achievementId) => {
    setDetailsOpen(prev => ({
      ...prev,
      [achievementId]: !prev[achievementId]
    }));
  };

  // Reset all filters
  const resetFilters = () => {
    setActiveCategory('all');
    setSearchTerm('');
    setShowOnlyUnlocked(false);
    setShowOnlyLocked(false);
    setSortBy('default');
  };

  // This function remains if you ever want to trigger a test popup programmatically
  const testPopup = (achievementId) => {
    const achievement = achievements.find((ach) => ach.achievementId === achievementId);
    if (achievement) {
      const IconComponent = iconMapping[achievement.achievementId] || null;
      const color = colorMapping[achievement.achievementId] || "#fff";
      showAchievementToast({
        title: achievement.title,
        description: achievement.description,
        icon: IconComponent ? <IconComponent /> : null,
        color: color
      });
    }
  };

  return (
    <div className="achievement-page-container">
      {/* Header Section with Stats */}
      <div className="achievement-header">
        <div className="achievement-header-content">
          <div className="achievement-header-titles">
            <h1>Achievement Gallery</h1>
            <p>Track your progress and unlock achievements as you master the platform!</p>
          </div>
          
          {username && (
            <div className="achievement-player-stats">
              <div className="achievement-player-name">
                <span>{username}'s Progress</span>
              </div>
              <div className="achievement-progress-container">
                <div className="achievement-progress-stats">
                  <div className="achievement-stat">
                    <FaTrophy className="achievement-stat-icon" />
                    <div className="achievement-stat-numbers">
                      <span className="achievement-stat-value">{unlockedAchievements} / {totalAchievements}</span>
                      <span className="achievement-stat-label">Achievements</span>
                    </div>
                  </div>
                  <div className="achievement-stat">
                    <FaLevelUpAlt className="achievement-stat-icon" />
                    <div className="achievement-stat-numbers">
                      <span className="achievement-stat-value">{level}</span>
                      <span className="achievement-stat-label">Level</span>
                    </div>
                  </div>
                </div>
                <div className="achievement-progress-bar-container">
                  <div className="achievement-progress-bar">
                    <div 
                      className="achievement-progress-fill" 
                      style={{ width: `${percentComplete}%` }}
                    ></div>
                  </div>
                  <span className="achievement-progress-percent">{Math.round(percentComplete)}% Complete</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Filter and Search Section */}
      <div className="achievement-controls">
        <div className="achievement-categories">
          {Object.entries(categories).map(([key, value]) => (
            <button
              key={key}
              className={`achievement-category-btn ${activeCategory === key ? 'active' : ''}`}
              onClick={() => setActiveCategory(key)}
            >
              {value}
            </button>
          ))}
        </div>
        
        <div className="achievement-filters">
          <div className="achievement-search">
            <FaSearch className="achievement-search-icon" />
            <input
              type="text"
              placeholder="Search achievements..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="achievement-search-input"
            />
            {searchTerm && (
              <button 
                className="achievement-search-clear" 
                onClick={() => setSearchTerm('')}
              >
                <FaTimes />
              </button>
            )}
          </div>
          
          <div className="achievement-filter-options">
            <button 
              className={`achievement-filter-btn ${showOnlyUnlocked ? 'active' : ''}`}
              onClick={() => {
                setShowOnlyUnlocked(!showOnlyUnlocked);
                setShowOnlyLocked(false);
              }}
            >
              <FaCheck />
              <span>Unlocked</span>
            </button>
            
            <button 
              className={`achievement-filter-btn ${showOnlyLocked ? 'active' : ''}`}
              onClick={() => {
                setShowOnlyLocked(!showOnlyLocked);
                setShowOnlyUnlocked(false);
              }}
            >
              <FaLock />
              <span>Locked</span>
            </button>
            
            <div className="achievement-sort-dropdown">
              <select 
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="achievement-sort-select"
              >
                <option value="default">Default Sort</option>
                <option value="name">Sort by Name</option>
                <option value="unlocked">Unlocked First</option>
                <option value="locked">Locked First</option>
              </select>
            </div>
            
            <button 
              className="achievement-filter-reset" 
              onClick={resetFilters}
              title="Reset all filters"
            >
              <FaSyncAlt />
            </button>
          </div>
        </div>
      </div>

      {/* Main Achievement Grid */}
      {loadingStatus === 'loading' ? (
        <div className="achievement-loading">
          <FaSyncAlt className="achievement-loading-icon" />
          <p>Loading achievements...</p>
        </div>
      ) : sortedAchievements.length > 0 ? (
        <div className="achievement-grid">
          {sortedAchievements.map((ach) => {
            const isUnlocked = userAchievements.includes(ach.achievementId);
            const IconComponent = iconMapping[ach.achievementId] || FaTrophy;
            const iconColor = colorMapping[ach.achievementId] || "#ffffff";
            const isDetailsOpen = detailsOpen[ach.achievementId] || false;
            
            return (
              <div
                key={ach.achievementId}
                className={`achievement-card ${isUnlocked ? 'unlocked' : 'locked'}`}
                onClick={() => toggleDetails(ach.achievementId)}
              >
                <div className="achievement-card-content">
                  <div className="achievement-icon-container">
                    <div className="achievement-icon" style={{ color: iconColor }}>
                      <IconComponent />
                    </div>
                    {isUnlocked && <div className="achievement-completed-badge"><FaCheck /></div>}
                  </div>
                  
                  <div className="achievement-info">
                    <h3 className="achievement-title">{ach.title}</h3>
                    <p className="achievement-description">{ach.description}</p>
                  </div>
                  
                  <button 
                    className="achievement-details-toggle"
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleDetails(ach.achievementId);
                    }}
                  >
                    {isDetailsOpen ? <FaChevronUp /> : <FaChevronDown />}
                  </button>
                </div>
                
                {isDetailsOpen && (
                  <div className="achievement-details">
                    <div className="achievement-details-content">
                      <div className="achievement-details-header">
                        <FaInfoCircle className="achievement-details-icon" />
                        <h4>Achievement Details</h4>
                      </div>
                      
                      <div className="achievement-details-info">
                        <div className="achievement-details-item">
                          <span className="achievement-details-label">Category:</span>
                          <span className="achievement-details-value">
                            {categories[getAchievementCategory(ach.achievementId)]}
                          </span>
                        </div>
                        
                        <div className="achievement-details-item">
                          <span className="achievement-details-label">Status:</span>
                          <span className={`achievement-details-value ${isUnlocked ? 'unlocked' : 'locked'}`}>
                            {isUnlocked ? 'Unlocked' : 'Locked'}
                          </span>
                        </div>
                        
                        {/* Add more achievement details as needed */}
                      </div>
                    </div>
                  </div>
                )}
                
                {!isUnlocked && (
                  <div className="achievement-locked-overlay">
                    <FaLock className="achievement-locked-icon" />
                    <span>Locked</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="achievement-empty">
          <FaFilter className="achievement-empty-icon" />
          <p>No achievements match your current filters.</p>
          <button className="achievement-reset-btn" onClick={resetFilters}>
            Reset Filters
          </button>
        </div>
      )}
    </div>
  );
};

export default AchievementPage;
