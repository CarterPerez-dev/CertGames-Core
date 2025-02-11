// src/components/pages/store/UserProfile.js
import React from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { logout } from '../store/userSlice';
import { useNavigate } from 'react-router-dom';
import './UserProfile.css';

import {
  FaTrophy,
  FaMedal,
  FaStar,
  FaCrown,
  FaBolt,
  FaBook,
  FaBrain,
  FaCheckCircle,
  FaRegSmile,
  FaMagic
} from 'react-icons/fa';

// Map achievementId -> icon
const iconMapping = {
  test_rookie: FaTrophy,
  accuracy_king: FaMedal,
  bronze_grinder: FaBook,
  silver_scholar: FaStar,
  gold_god: FaCrown,
  platinum_pro: FaMagic,
  walking_encyclopedia: FaBrain,
  redemption_arc: FaBolt,
  memory_master: FaRegSmile,
  coin_collector_5000: FaBook,
  coin_hoarder_10000: FaBook,
  coin_tycoon_50000: FaBook,
  perfectionist_1: FaCheckCircle,
  double_trouble_2: FaCheckCircle,
  error404_failure_not_found: FaCheckCircle,
  level_up_5: FaTrophy,
  mid_tier_grinder_25: FaMedal,
  elite_scholar_50: FaStar,
  ultimate_master_100: FaCrown,
  category_perfectionist: FaBolt,
  absolute_perfectionist: FaBolt,
  exam_conqueror: FaMedal,
  subject_specialist: FaMedal,
  answer_machine_1000: FaBook,
  knowledge_beast_5000: FaBrain,
  question_terminator: FaBrain,
  test_finisher: FaCheckCircle,
  subject_finisher: FaCheckCircle
};

const UserProfile = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();

  // Pull everything from user slice
  const {
    userId,
    username,
    xp,
    level,
    coins,
    achievements: userAchievements = [],
    currentAvatar,
    purchasedItems
  } = useSelector((state) => state.user);

  // Pull all achievements from store, to find title/desc
  const allAchievements = useSelector((state) => state.achievements.all);

  // Shop items for listing purchased items & avatar
  const { items: shopItems } = useSelector((state) => state.shop);

  // Determine default/fallback avatar
  let profilePicUrl = '/avatars/avatar1.png'; 
  if (currentAvatar && shopItems && shopItems.length > 0) {
    const avatarItem = shopItems.find(item => item._id === currentAvatar);
    if (avatarItem && avatarItem.imageUrl) {
      profilePicUrl = avatarItem.imageUrl;
    }
  }

  // Filter purchased items (excluding avatars)
  const purchasedItemsDetail = (shopItems || []).filter(
    (shopItem) => purchasedItems.includes(shopItem._id) && shopItem.type !== 'avatar'
  );

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
        </div>
      </div>
      
      <div className="profile-extra">
        <div className="extra-card">
          <h2>Your Achievements</h2>
          <div className="achievements-list">
            {userAchievements.length > 0 ? (
              userAchievements.map((achId) => {
                // Find the full achievement doc in allAchievements
                const achievementDoc = allAchievements.find(
                  (ach) => ach.achievementId === achId
                );

                // Fallback if not found
                const displayTitle = achievementDoc ? achievementDoc.title : achId;
                const IconComp = iconMapping[achId] || FaTrophy;

                return (
                  <div key={achId} className="achievement-display">
                    <span className="achievement-icon">
                      <IconComp />
                    </span>
                    <span className="achievement-title">
                      {displayTitle}
                    </span>
                  </div>
                );
              })
            ) : (
              <p>You haven't unlocked any achievements yet.</p>
            )}
          </div>
        </div>

        <div className="extra-card">
          <h2>Purchased Items</h2>
          <div className="purchased-items-list">
            {purchasedItemsDetail.length > 0 ? (
              purchasedItemsDetail.map((item) => (
                <div key={item._id} className="purchased-item-display">
                  <div className="purchased-item-title">{item.title}</div>
                  <div className="purchased-item-type">Type: {item.type}</div>
                </div>
              ))
            ) : (
              <p>No purchased items yet (besides avatars).</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserProfile;
