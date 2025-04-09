// src/components/pages/Info/PublicLeaderboardPage.js
import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { 
  FaTrophy, 
  FaMedal, 
  FaStar, 
  FaUserAlt,
  FaSearch,
  FaSyncAlt,
  FaChevronUp,
  FaSpinner,
  FaExclamationTriangle,
  FaChevronDown,
  FaCode
} from 'react-icons/fa';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import SEOHelmet from '../../SEOHelmet';
import StructuredData from '../../StructuredData';
import './css/PublicLeaderboardPage.css';

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

// Top player card component
const TopPlayerCard = ({ player, position }) => {
  const positionClass = position === 1 ? 'gold' : position === 2 ? 'silver' : 'bronze';
  
  return (
    <div className={`top-player-card ${positionClass}`}>
      <div className="position-badge">
        {position === 1 ? (
          <FaTrophy className="position-icon" aria-hidden="true" />
        ) : position === 2 ? (
          <FaMedal className="position-icon" aria-hidden="true" />
        ) : (
          <FaMedal className="position-icon" aria-hidden="true" />
        )}
        <span>{position}</span>
      </div>
      
      <div className="player-avatar">
        {player.avatarUrl ? (
          <img src={player.avatarUrl} alt={`${player.username}'s avatar`} />
        ) : (
          <FaUserAlt aria-hidden="true" />
        )}
      </div>
      
      <div className="player-info">
        <h3>{player.username}</h3>
        <div className="player-stats">
          <div className="player-level">
            <span className="stat-label">Level</span>
            <span className="stat-value">{player.level}</span>
          </div>
          <div className="player-xp">
            <span className="stat-label">XP</span>
            <span className="stat-value">{player.xp.toLocaleString()}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

const PublicLeaderboardPage = () => {
  const [leaders, setLeaders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showScrollToTop, setShowScrollToTop] = useState(false);
  const [codeVisible, setCodeVisible] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(true);

  // Breadcrumb schema for SEO
  const breadcrumbSchema = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    "itemListElement": [
      {
        "@type": "ListItem",
        "position": 1,
        "name": "Home",
        "item": "https://certgames.com/"
      },
      {
        "@type": "ListItem",
        "position": 2,
        "name": "Leaderboard",
        "item": "https://certgames.com/public-leaderboard"
      }
    ]
  };

  // Reference to the leaderboard container for scrolling functionality
  const leaderboardRef = useRef(null);

  useEffect(() => {
    fetchLeaderboardData();
  }, []);

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

  const fetchLeaderboardData = async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Using the new public leaderboard endpoint with longer cache time
      const response = await fetch('/api/public-leaderboard/board?skip=0&limit=1000');
      
      if (!response.ok) {
        throw new Error('Failed to fetch leaderboard data');
      }
      
      const data = await response.json();
      setLeaders(data.data);
      setHasMore(data.data.length < data.total);
      setLoading(false);
    } catch (err) {
      setError('Failed to load leaderboard. Please try again.');
      setLoading(false);
    }
  };

  const loadMoreLeaders = async () => {
    if (isLoadingMore || !hasMore) return;
    
    setIsLoadingMore(true);
    
    try {
      const response = await fetch(`/api/public-leaderboard/board?skip=${leaders.length}&limit=20`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch more leaderboard data');
      }
      
      const data = await response.json();
      setLeaders(prevLeaders => [...prevLeaders, ...data.data]);
      setHasMore(leaders.length + data.data.length < data.total);
    } catch (err) {
      console.error('Error loading more leaders:', err);
      // Don't set the main error state, just log it
    } finally {
      setIsLoadingMore(false);
    }
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

  // Render trophy icon based on rank
  const renderRankIcon = (rank) => {
    if (rank === 1) return <FaTrophy className="rank-icon gold" aria-hidden="true" />;
    if (rank === 2) return <FaTrophy className="rank-icon silver" aria-hidden="true" />;
    if (rank === 3) return <FaTrophy className="rank-icon bronze" aria-hidden="true" />;
    if (rank <= 10) return <FaStar className="rank-icon top-ten" aria-hidden="true" />;
    return null;
  };

  // Get top 3 players
  const topPlayers = leaders.slice(0, 3);

  return (
    <>
      <SEOHelmet 
        title="Cybersecurity Training Leaderboard | CertGames"
        description="See who's leading the cybersecurity learning race at CertGames. Our gamified learning platform rewards knowledge with XP, levels, and achievements."
        canonicalUrl="/public-leaderboard"
      />
      <StructuredData data={breadcrumbSchema} />
      <div className="public-leaderboard-container">
        <InfoNavbar />
        
        <main className="public-leaderboard-content">
          <header className="public-leaderboard-header">
            <h1 className="public-leaderboard-title">
              <FaTrophy className="title-icon" aria-hidden="true" />
              CertGames Leaderboard
            </h1>
            <p className="public-leaderboard-subtitle">See who's leading the cybersecurity learning race!</p>
          </header>
          
          {loading ? (
            <div className="loading-container" aria-live="polite">
              <FaSpinner className="loading-spinner" aria-hidden="true" />
              <p>Loading top cybersecurity learners...</p>
            </div>
          ) : error ? (
            <div className="error-container" aria-live="assertive">
              <FaExclamationTriangle className="error-icon" aria-hidden="true" />
              <p>{error}</p>
              <button className="refresh-button" onClick={fetchLeaderboardData}>
                <FaSyncAlt aria-hidden="true" /> Refresh
              </button>
            </div>
          ) : (
            <>
              {/* Top Players Podium */}
              {topPlayers.length > 0 && (
                <section className="top-players-podium" aria-label="Top 3 players">
                  {topPlayers.map((player, index) => (
                    <TopPlayerCard 
                      key={player.rank} 
                      player={player} 
                      position={index + 1} 
                    />
                  ))}
                </section>
              )}
              
              {/* Search Bar */}
              <div className="leaderboard-search-container">
                <div className="search-box">
                  <FaSearch className="search-icon" aria-hidden="true" />
                  <input 
                    type="text" 
                    placeholder="Search by username..." 
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="search-input"
                    aria-label="Search leaderboard by username"
                  />
                  {searchTerm && (
                    <button 
                      className="clear-search"
                      onClick={() => setSearchTerm('')}
                      aria-label="Clear search"
                    >
                      &times;
                    </button>
                  )}
                </div>
                
                <div className="leaderboard-stats">
                  <div className="stat-pill">
                    <span className="stat-value">{leaders.length}</span>
                    <span className="stat-label">Players</span>
                  </div>
                </div>
              </div>
              
              {/* Leaderboard List */}
              <div className="leaderboard-list-container" ref={leaderboardRef}>
                {filteredLeaders.length === 0 ? (
                  <div className="no-results" aria-live="polite">
                    <FaUserAlt className="no-results-icon" aria-hidden="true" />
                    <p>No players found matching "{searchTerm}"</p>
                    <button 
                      className="clear-button"
                      onClick={() => setSearchTerm('')}
                    >
                      Clear Search
                    </button>
                  </div>
                ) : (
                  <>
                    <div className="leaderboard-list" role="list">
                      {filteredLeaders.map((player) => {
                        const rankClass = 
                          player.rank === 1 ? 'gold-rank' : 
                          player.rank === 2 ? 'silver-rank' : 
                          player.rank === 3 ? 'bronze-rank' : 
                          player.rank <= 10 ? 'top-rank' : '';
                        
                        return (
                          <div key={player.rank} className={`leaderboard-item ${rankClass}`} role="listitem">
                            <div className="leaderboard-rank">
                              <span className="rank-number">{player.rank}</span>
                              {renderRankIcon(player.rank)}
                            </div>
                            
                            <div className="leaderboard-avatar-container">
                              {player.avatarUrl ? (
                                <img 
                                  src={player.avatarUrl} 
                                  alt={`${player.username}'s avatar`} 
                                  className="leaderboard-avatar" 
                                />
                              ) : (
                                <div className="leaderboard-avatar default">
                                  <FaUserAlt aria-hidden="true" />
                                </div>
                              )}
                            </div>
                            
                            <div className="leaderboard-user-info">
                              <h3 className="leaderboard-username">{player.username}</h3>
                              <div className="leaderboard-user-stats">
                                <div className="leaderboard-user-level">
                                  <span className="level-label">Level</span>
                                  <span className="level-value">{player.level}</span>
                                </div>
                                <div className="leaderboard-user-xp">
                                  <span className="xp-label">XP</span>
                                  <span className="xp-value">{player.xp.toLocaleString()}</span>
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    
                    {hasMore && !searchTerm && (
                      <div className="load-more-container">
                        <button 
                          className="load-more-button"
                          onClick={loadMoreLeaders}
                          disabled={isLoadingMore}
                          aria-busy={isLoadingMore ? "true" : "false"}
                        >
                          {isLoadingMore ? (
                            <>
                              <FaSpinner className="spinner-icon" aria-hidden="true" />
                              Loading more players...
                            </>
                          ) : (
                            <>
                              <FaChevronDown className="down-icon" aria-hidden="true" />
                              Load More Players
                            </>
                          )}
                        </button>
                      </div>
                    )}
                  </>
                )}
                
                {showScrollToTop && (
                  <button 
                    className="scroll-top-button"
                    onClick={scrollToTop}
                    title="Scroll to top"
                    aria-label="Scroll to top"
                  >
                    <FaChevronUp aria-hidden="true" />
                  </button>
                )}
              </div>
              
              {/* Join CTA */}
              <section className="join-cta">
                <div className="cta-content">
                  <h2>Want to be on this leaderboard?</h2>
                  <p>Create your account today and start climbing the ranks!</p>
                  <div className="cta-buttons">
                    <Link to="/register" className="register-button">
                      Start Your Free Trial
                    </Link>
                  </div>
                </div>
                
                <div className="code-snippet-container">
                  <div className="code-header">
                    <span>How it works</span>
                    <button 
                      className="toggle-code-button"
                      onClick={() => setCodeVisible(!codeVisible)}
                      aria-expanded={codeVisible}
                    >
                      <FaCode aria-hidden="true" />
                      {codeVisible ? 'Hide Code' : 'Show Code'}
                    </button>
                  </div>
                  {codeVisible && (
                    <div className="code-snippet">
                      <pre>
                        <code>
{`// XP System Example
function awardXP(user, correctAnswer) {
  // Base XP for correct answer
  const baseXP = 10;
  
  // Apply any XP boosts the user might have
  const xpMultiplier = user.xpBoost || 1.0;
  const xpAwarded = baseXP * xpMultiplier;
  
  // Update user's total XP
  user.xp += xpAwarded;
  
  // Check if user leveled up
  const newLevel = calculateLevel(user.xp);
  if (newLevel > user.level) {
    user.level = newLevel;
    console.log(\`Level up! You are now level \${newLevel}\`);
  }
  
  return xpAwarded;
}

// Calculate level based on total XP
function calculateLevel(totalXP) {
  // Simple level calculation - each level requires more XP
  return Math.floor(Math.sqrt(totalXP / 100)) + 1;
}`}
                        </code>
                      </pre>
                    </div>
                  )}
                </div>
              </section>
            </>
          )}
        </main>
        
        <Footer />
      </div>
    </>
  );
};

export default PublicLeaderboardPage;
