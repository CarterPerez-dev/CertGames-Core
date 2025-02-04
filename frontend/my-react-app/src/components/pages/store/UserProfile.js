// src/components/pages/store/UserProfile.js
import React from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { registerUser, loginUser, dailyLoginBonus, addXP, addCoins, fetchUserData, logout, setCurrentUserId } from '../store/userSlice';

import { useNavigate } from 'react-router-dom';
import './UserProfile.css';

const UserProfile = () => {
  const { userId, username, xp, level, coins, achievements: userAchievements = [] } = useSelector((state) => state.user);
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const handleLogout = () => {
    dispatch(logout());
    localStorage.removeItem('userId');
    navigate('/login');
  };

  // We assume that your achievements slice holds the full list of achievements.
  const allAchievements = useSelector((state) => state.achievements.all);

  // Filter for unlocked achievements.
  const unlockedAchievements = allAchievements.filter(ach => userAchievements.includes(ach.achievementId));

  return (
    <div className="profile-container">
      <div className="profile-header">
        <h1 className="profile-title">User Profile</h1>
        <button className="logout-button" onClick={handleLogout}>
          Logout
        </button>
      </div>
      
      <div className="profile-overview">
        <div className="profile-card">
          <h2>Overview</h2>
          <div className="profile-details">
            <p><span className="detail-label">Username:</span> {username}</p>
            <p><span className="detail-label">User ID:</span> {userId}</p>
            <p><span className="detail-label">Level:</span> {level}</p>
            <p><span className="detail-label">XP:</span> {xp}</p>
            <p><span className="detail-label">Coins:</span> {coins}</p>
          </div>
        </div>
      </div>
      
      <div className="profile-actions">
        <div className="action-card">
          <h2>Account Settings</h2>
          <div className="action-buttons">
            <button className="profile-btn">Change Username</button>
            <button className="profile-btn">Change Email</button>
            <button className="profile-btn">Change Password</button>
            <button className="profile-btn">Cancel Subscription</button>
          </div>
          {/* Placeholder: Integrate Stripe API for subscription cancellation */}
        </div>
      </div>
      
      <div className="profile-extra">
        <div className="extra-card">
          <h2>Your Achievements</h2>
          <div className="extra-content">
            {unlockedAchievements.length > 0 ? (
              unlockedAchievements.map(ach => (
                <div key={ach.achievementId} className="achievement-item">
                  <h3>{ach.title}</h3>
                  <p>{ach.description}</p>
                </div>
              ))
            ) : (
              <p>You haven't unlocked any achievements yet.</p>
            )}
          </div>
        </div>
        <div className="extra-card">
          <h2>Purchased Items</h2>
          <div className="extra-content">
            <p>(Purchased items will be listed here.)</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserProfile;

