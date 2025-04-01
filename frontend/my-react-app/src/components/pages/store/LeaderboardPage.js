// src/components/pages/store/LeaderboardPage.js
import React, { useEffect, useState, useRef, useCallback } from 'react';
import './css/LeaderboardPage.css';
import { 
  FaTrophy, 
  FaMedal, 
  FaStar, 
  FaCrown, 
  FaUserAlt,
  FaSearch,
  FaSyncAlt,
  FaChevronDown,
  FaAngleDoubleDown,
  FaExclamationTriangle,
  FaChevronUp,
  FaSpinner
} from 'react-icons/fa';

// Skeleton component for loading state
const SkeletonItem = ({ index }) => {
  return (
    <div className="leaderboard-item skeleton">
      <div className="leaderboard-rank">
        <div className="skeleton-pulse rank-number"></div>
      </div>
      <div className="leaderboard-avatar-container">
        <div className="skeleton-pulse avatar-circle"></div>
      </div>
      <div className="leaderboard-user-info">
        <div className="skeleton-pulse username-line"></div>
        <div className="leaderboard-user-stats">
          <div className="skeleton-pulse stat-line"></div>
          <div className="skeleton-pulse stat-line shorter"></div>
        </div>
      </div>
    </div>
  );
};

const LeaderboardPage = () => {
  const [leaders, setLeaders] = useState([]);
  const [total, setTotal] = useState(0);
  const [skip, setSkip] = useState(0);
  const [limit, setLimit] = useState(50); // Load 50 at a time
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showScrollToTop, setShowScrollToTop] = useState(false);
  
  // Reference to the leaderboard container for scrolling functionality
  const leaderboardRef = useRef(null);
  
  // Function to fetch leaderboard data
  const fetchLeaderboard = useCallback(async (skipCount = 0, replace = true) => {
    try {
      const url = `/api/test/leaderboard?skip=${skipCount}&limit=${limit}`;
      const response = await fetch(url);
      
      if (!response.ok) {
        throw new Error('Failed to load leaderboard data');
      }
      
      const data = await response.json();
      
      if (replace) {
        setLeaders(data.data);
      } else {
        setLeaders(prev => [...prev, ...data.data]);
      }
      
      setTotal(data.total);
      return data;
    } catch (err) {
      setError(err.message);
      return null;
    }
  }, [limit]);

  // Initial data fetch
  useEffect(() => {
    const loadInitialData = async () => {
      setLoading(true);
      setError(null);
      await fetchLeaderboard(skip);
      setLoading(false);
    };
    
    loadInitialData();
  }, [fetchLeaderboard, skip]);

  // Handle scroll event to show/hide scroll-to-top button
  useEffect(() => {
    const handleScroll = () => {
      if (leaderboardRef.current) {
        const { scrollTop } = leaderboardRef.current;
        setShowScrollToTop(scrollTop > 300);
      }
    };
    
    const currentRef = leaderboardRef.current;
    if (currentRef) {
      currentRef.addEventListener('scroll', handleScroll);
    }
    
    return () => {
      if (currentRef) {
        currentRef.removeEventListener('scroll', handleScroll);
      }
    };
  }, []);

  // Load more data
  const handleLoadMore = async () => {
    if (loadingMore) return;
    
    setLoadingMore(true);
    const newSkip = leaders.length;
    const data = await fetchLeaderboard(newSkip, false);
    setLoadingMore(false);
  };

  // Filter leaders by username
  const filteredLeaders = searchTerm.trim() === '' 
    ? leaders 
    : leaders.filter(user => 
        user.username.toLowerCase().includes(searchTerm.toLowerCase())
      );

  // Scroll to top function
  const scrollToTop = () => {
    if (leaderboardRef.current) {
      leaderboardRef.current.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
    }
  };

  // Determine if we should show more results
  const hasMoreResults = leaders.length < total;

  // Render trophy icon based on rank
  const renderRankIcon = (rank) => {
    if (rank === 1) return <FaTrophy className="rank-icon gold" />;
    if (rank === 2) return <FaTrophy className="rank-icon silver" />;
    if (rank === 3) return <FaTrophy className="rank-icon bronze" />;
    if (rank <= 10) return <FaStar className="rank-icon top-ten" />;
    return null;
  };

  // Loading state with skeletons
  if (loading) {
    return (
      <div className="leaderboard-container">
        <div className="leaderboard-header">
          <div className="leaderboard-title">
            <h1>Leaderboard</h1>
            <p>See where you rank against other players!</p>
          </div>
        </div>
        
        <div className="leaderboard-content">
          <div className="leaderboard-loading">
            <FaSpinner className="loading-spinner" />
            <p>Loading leaderboard data...</p>
          </div>
          
          <div className="leaderboard-list">
            {Array.from({ length: 5 }).map((_, idx) => (
              <SkeletonItem key={idx} index={idx} />
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="leaderboard-container">
        <div className="leaderboard-header">
          <div className="leaderboard-title">
            <h1>Leaderboard</h1>
            <p>See where you rank against other players!</p>
          </div>
        </div>
        
        <div className="leaderboard-error">
          <FaExclamationTriangle className="error-icon" />
          <p>Error loading leaderboard: {error}</p>
          <button 
            className="leaderboard-retry-btn"
            onClick={() => {
              setLoading(true);
              setError(null);
              fetchLeaderboard(0)
                .then(() => setLoading(false))
                .catch(() => setLoading(false));
            }}
          >
            <FaSyncAlt /> Try Again
          </button>
        </div>
      </div>
    );
  }

  // Main render - the leaderboard
  return (
    <div className="leaderboard-container">
      <div className="leaderboard-header">
        <div className="leaderboard-title">
          <h1>Leaderboard</h1>
          <p>See where you rank against other players!</p>
        </div>
        
        <div className="leaderboard-stats">
          <div className="leaderboard-stat">
            <FaCrown className="leaderboard-stat-icon" />
            <div className="leaderboard-stat-text">
              <span className="leaderboard-stat-value">{total}</span>
              <span className="leaderboard-stat-label">Players</span>
            </div>
          </div>
        </div>
      </div>
      
      <div className="leaderboard-controls">
        <div className="leaderboard-search">
          <FaSearch className="search-icon" />
          <input 
            type="text"
            placeholder="Search by username..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="leaderboard-search-input"
          />
          {searchTerm && (
            <button 
              className="leaderboard-search-clear"
              onClick={() => setSearchTerm('')}
            >
              &times;
            </button>
          )}
        </div>
      </div>
      
      <div className="leaderboard-content" ref={leaderboardRef}>
        {filteredLeaders.length === 0 ? (
          <div className="leaderboard-empty">
            <FaUserAlt className="empty-icon" />
            <p>No players found matching "{searchTerm}"</p>
            <button 
              className="leaderboard-reset-btn"
              onClick={() => setSearchTerm('')}
            >
              Clear Search
            </button>
          </div>
        ) : (
          <div className="leaderboard-list">
            {filteredLeaders.map((user) => {
              const rankClass = 
                user.rank === 1 ? 'gold-rank' : 
                user.rank === 2 ? 'silver-rank' : 
                user.rank === 3 ? 'bronze-rank' : 
                user.rank <= 10 ? 'top-rank' : '';
              
              return (
                <div key={user.rank} className={`leaderboard-item ${rankClass}`}>
                  <div className="leaderboard-rank">
                    <span className="rank-number">{user.rank}</span>
                    {renderRankIcon(user.rank)}
                  </div>
                  
                  <div className="leaderboard-avatar-container">
                    {user.avatarUrl ? (
                      <img
                        src={user.avatarUrl}
                        alt={`${user.username}'s avatar`}
                        className="leaderboard-avatar"
                      />
                    ) : (
                      <div className="leaderboard-avatar default">
                        <FaUserAlt />
                      </div>
                    )}
                  </div>
                  
                  <div className="leaderboard-user-info">
                    <h3 className="leaderboard-username">{user.username}</h3>
                    <div className="leaderboard-user-stats">
                      <div className="leaderboard-user-level">
                        <span className="level-label">Level</span>
                        <span className="level-value">{user.level}</span>
                      </div>
                      <div className="leaderboard-user-xp">
                        <span className="xp-label">XP</span>
                        <span className="xp-value">{user.xp.toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
            
            {hasMoreResults && !searchTerm && (
              <div className="leaderboard-load-more">
                <button 
                  className="load-more-btn"
                  onClick={handleLoadMore}
                  disabled={loadingMore}
                >
                  {loadingMore ? (
                    <>
                      <FaSpinner className="loading-spinner" />
                      <span>Loading...</span>
                    </>
                  ) : (
                    <>
                      <FaAngleDoubleDown />
                      <span>Load More</span>
                    </>
                  )}
                </button>
              </div>
            )}
          </div>
        )}
        
        {showScrollToTop && (
          <button 
            className="scroll-to-top"
            onClick={scrollToTop}
            aria-label="Scroll to top"
          >
            <FaChevronUp />
          </button>
        )}
      </div>
    </div>
  );
};

export default LeaderboardPage;
