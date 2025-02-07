// src/components/pages/store/UserProfile.js
import React from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { logout, fetchUserData } from '../store/userSlice';
import { useNavigate } from 'react-router-dom';
import './UserProfile.css';

const UserProfile = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();

  // Retrieve user data from the user slice
  const { 
    userId, 
    username, 
    xp, 
    level, 
    coins, 
    achievements: userAchievements = [],
    currentAvatar 
  } = useSelector((state) => state.user);

  // Retrieve shop items from the shop slice (to look up avatar image URL)
  const { items: shopItems } = useSelector((state) => state.shop);

  // Determine the profile picture URL.
  // If currentAvatar is set and we can find the matching shop item,
  // use its imageUrl; otherwise, fall back to a default image.
  let profilePicUrl = '/avatars/avatar1.png'; // fallback default
  if (currentAvatar && shopItems && shopItems.length > 0) {
    const avatarItem = shopItems.find(item => item._id === currentAvatar);
    if (avatarItem && avatarItem.imageUrl) {
      profilePicUrl = avatarItem.imageUrl;
    }
  }

  const handleLogout = () => {
    dispatch(logout());
    localStorage.removeItem('userId');
    navigate('/login');
  };

  return (
    <div className="profile-container">
      <div className="profile-header">
        <div className="profile-picture">
          <img src={profilePicUrl} alt="Profile Avatar" />
        </div>
        <h1 className="profile-title">{username}'s Profile</h1>
        <button className="logout-button" onClick={handleLogout}>
          Logout
        </button>
      </div>
      
      <div className="profile-overview">
        <div className="profile-card">
          <h2>Overview</h2>
          <div className="profile-details">
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
            {userAchievements.length > 0 ? (
              userAchievements.map((ach) => (
                <div key={ach} className="achievement-item">
                  <h3>{ach}</h3>
                  {/* You can expand to show description if needed */}
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

