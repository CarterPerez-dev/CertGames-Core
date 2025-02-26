// =====================================
// Updated LeaderboardPage.js (FULL FILE)
// Implements:
// 1) Lazy loading/pagination
// 2) Skeleton placeholders while loading
// =====================================
import React, { useEffect, useState } from 'react';
import './LeaderboardPage.css';

const SkeletonItem = () => {
  // Simple skeleton loader placeholder
  return (
    <div className="leaderboard-item skeleton">
      <span className="rank-label skeleton-rank">--</span>
      <div className="avatar-wrapper">
        <div className="leaderboard-avatar skeleton-avatar" />
      </div>
      <div className="user-info">
        <span className="username skeleton-username">Loading...</span>
        <span className="user-level skeleton-level">Loading...</span>
        <span className="user-xp skeleton-xp">Loading...</span>
      </div>
    </div>
  );
};

const LeaderboardPage = () => {
  const [leaders, setLeaders] = useState([]);
  const [total, setTotal] = useState(0);
  const [skip, setSkip] = useState(0);
  const [limit] = useState(50); // We load 50 at a time
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(null);

  // Fetch the initial batch of leaderboard data
  useEffect(() => {
    const fetchInitial = async () => {
      setLoading(true);
      setError(null);
      try {
        const url = `/api/test/leaderboard?skip=${skip}&limit=${limit}`;
        const response = await fetch(url);
        if (!response.ok) {
          throw new Error('Failed to load leaderboard');
        }
        const data = await response.json();
        setLeaders(data.data);
        setTotal(data.total);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchInitial();
  }, [skip, limit]);

  // Lazy load next 50
  const handleLoadMore = async () => {
    if (loadingMore) return; // Prevent double-clicks
    setLoadingMore(true);
    try {
      const newSkip = leaders.length; 
      const url = `/api/test/leaderboard?skip=${newSkip}&limit=${limit}`;
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error('Failed to load more leaderboard data');
      }
      const data = await response.json();
      // Append new data
      setLeaders(prev => [...prev, ...data.data]);
      setTotal(data.total);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingMore(false);
    }
  };

  // If loading, show a skeleton list
  if (loading) {
    return (
      <div className="leaderboard-container">
        <h1 className="leaderboard-title">Top Leaderboard</h1>
        <div className="leaderboard-list">
          {Array.from({ length: 5 }).map((_, idx) => (
            <SkeletonItem key={idx} />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return <div className="leaderboard-error">Error: {error}</div>;
  }

  // If not loading, display the loaded users
  return (
    <div className="leaderboard-container">
      <h1 className="leaderboard-title">Top Leaderboard</h1>
      <div className="leaderboard-list">
        {leaders.map((user, idx) => {
          const rankClass =
            user.rank === 1
              ? 'gold-rank'
              : user.rank === 2
              ? 'silver-rank'
              : user.rank === 3
              ? 'bronze-rank'
              : '';

          return (
            <div key={user.rank} className={`leaderboard-item ${rankClass}`}>
              <span className="rank-label">{user.rank}</span>
              <div className="avatar-wrapper">
                {user.avatarUrl ? (
                  <img
                    src={user.avatarUrl}
                    alt="avatar"
                    className="leaderboard-avatar"
                  />
                ) : (
                  <img
                    src="/avatars/default.png"
                    alt="default avatar"
                    className="leaderboard-avatar"
                  />
                )}
              </div>
              <div className="user-info">
                <span className="username">{user.username}</span>
                <span className="user-level">Level: {user.level}</span>
                <span className="user-xp">XP: {user.xp}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* "Load More" button if we haven't reached total yet */}
      {leaders.length < total && (
        <div className="load-more-container">
          <button onClick={handleLoadMore} disabled={loadingMore}>
            {loadingMore ? 'Loading...' : 'Load More'}
          </button>
        </div>
      )}
    </div>
  );
};

export default LeaderboardPage;
