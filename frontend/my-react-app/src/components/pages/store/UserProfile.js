// src/components/pages/store/UserProfile.js
import React, { useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { logout, fetchUserData } from '../store/userSlice'; // fetchUserData
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
  FaMagic,
  FaEye,
  FaEyeSlash
} from 'react-icons/fa';

// Basic client check
function hasInvalidChars(str) {
  if (!str) return false;
  if (/\s/.test(str)) return true;   // no spaces
  if (/[<>]/.test(str)) return true; // no < or >
  return false;
}

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

  const {
    userId,
    username,
    email,
    xp,
    level,
    coins,
    achievements = [],
    currentAvatar,
    purchasedItems,
    subscriptionActive
  } = useSelector((state) => state.user);

  const [showChangeUsername, setShowChangeUsername] = useState(false);
  const [newUsername, setNewUsername] = useState('');

  const [showChangeEmail, setShowChangeEmail] = useState(false);
  const [newEmail, setNewEmail] = useState('');

  const [showChangePassword, setShowChangePassword] = useState(false);
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [statusMessage, setStatusMessage] = useState('');

  let profilePicUrl = '/avatars/avatar1.png'; 
  // or logic for currentAvatar

  const handleLogout = () => {
    dispatch(logout());
    localStorage.removeItem('userId');
    navigate('/login');
  };

  const refetchUser = () => {
    if (userId) {
      dispatch(fetchUserData(userId));
    }
  };

  // CHANGE USERNAME
  const handleChangeUsername = async () => {
    if (!newUsername) {
      setStatusMessage('Please enter a new username');
      return;
    }
    if (hasInvalidChars(newUsername)) {
      setStatusMessage('New username has invalid chars');
      return;
    }
    try {
      const res = await fetch('/api/test/user/change-username', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, newUsername })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to change username');
      }
      setStatusMessage('Username updated successfully!');
      setShowChangeUsername(false);
      setNewUsername('');
      refetchUser();
    } catch (err) {
      setStatusMessage('Error changing username: ' + err.message);
    }
  };

  // CHANGE EMAIL
  const handleChangeEmail = async () => {
    if (!newEmail) {
      setStatusMessage('Please enter a new email');
      return;
    }
    if (!newEmail.includes('@')) {
      setStatusMessage('Invalid email');
      return;
    }
    try {
      const res = await fetch('/api/test/user/change-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, newEmail })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to change email');
      }
      setStatusMessage('Email updated successfully!');
      setShowChangeEmail(false);
      setNewEmail('');
      refetchUser();
    } catch (err) {
      setStatusMessage('Error changing email: ' + err.message);
    }
  };

  // CHANGE PASSWORD
  const handleChangePassword = async () => {
    if (!oldPassword || !newPassword || !confirmPassword) {
      setStatusMessage('All password fields are required');
      return;
    }
    if (newPassword !== confirmPassword) {
      setStatusMessage('New passwords do not match');
      return;
    }
    if (hasInvalidChars(newPassword)) {
      setStatusMessage('New password has invalid chars');
      return;
    }
    try {
      const res = await fetch('/api/test/user/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          oldPassword,
          newPassword,
          confirmPassword
        })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to change password');
      }
      setStatusMessage('Password changed successfully!');
      setShowChangePassword(false);
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setStatusMessage('Error changing password: ' + err.message);
    }
  };

  // CANCEL SUBSCRIPTION
  const handleCancelSubscription = async () => {
    try {
      const res = await fetch('/api/test/subscription/cancel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to cancel subscription');
      }
      setStatusMessage('Subscription cancelled (placeholder)');
      refetchUser();
    } catch (err) {
      setStatusMessage('Error cancelling subscription: ' + err.message);
    }
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
            <p><span className="detail-label">Email:</span> {email}</p>
            <p><span className="detail-label">Subscription Active:</span> {subscriptionActive ? 'Yes' : 'No'}</p>
          </div>
        </div>
      </div>

      <div className="profile-actions">
        <div className="action-card">
          <h2>Account Settings</h2>
          <div className="action-buttons">
            {/* Change username */}
            {!showChangeUsername ? (
              <button className="profile-btn" onClick={() => setShowChangeUsername(true)}>
                Change Username
              </button>
            ) : (
              <div className="change-section">
                <input 
                  type="text"
                  placeholder="New username"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                />
                <div className="change-section-buttons">
                  <button onClick={handleChangeUsername}>Submit</button>
                  <button onClick={() => {
                    setShowChangeUsername(false);
                    setNewUsername('');
                  }}>Cancel</button>
                </div>
              </div>
            )}

            {/* Change email */}
            {!showChangeEmail ? (
              <button className="profile-btn" onClick={() => setShowChangeEmail(true)}>
                Change Email
              </button>
            ) : (
              <div className="change-section">
                <input 
                  type="email"
                  placeholder="New email"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                />
                <div className="change-section-buttons">
                  <button onClick={handleChangeEmail}>Submit</button>
                  <button onClick={() => {
                    setShowChangeEmail(false);
                    setNewEmail('');
                  }}>Cancel</button>
                </div>
              </div>
            )}

            {/* Change password */}
            {!showChangePassword ? (
              <button className="profile-btn" onClick={() => setShowChangePassword(true)}>
                Change Password
              </button>
            ) : (
              <div className="change-section change-password-section">
                <input 
                  type="password"
                  placeholder="Old password"
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                />

                <div className="password-row">
                  <input 
                    type={showNewPassword ? 'text' : 'password'}
                    placeholder="New password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                  />
                  <span
                    className="eye-icon"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                  >
                    {showNewPassword ? <FaEyeSlash /> : <FaEye />}
                  </span>
                </div>

                <div className="password-row">
                  <input 
                    type={showConfirmPassword ? 'text' : 'password'}
                    placeholder="Confirm new password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                  />
                  <span
                    className="eye-icon"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  >
                    {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
                  </span>
                </div>

                <div className="change-section-buttons">
                  <button onClick={handleChangePassword}>Submit</button>
                  <button onClick={() => {
                    setShowChangePassword(false);
                    setOldPassword('');
                    setNewPassword('');
                    setConfirmPassword('');
                  }}>Cancel</button>
                </div>
              </div>
            )}

            {/* Cancel Subscription Placeholder */}
            <button className="profile-btn" onClick={handleCancelSubscription}>
              Cancel Subscription (placeholder)
            </button>
          </div>
        </div>
      </div>

      <div className="profile-extra">
        <div className="extra-card">
          <h2>Your Achievements</h2>
          <div className="achievements-list">
            {achievements.length > 0 ? (
              achievements.map((achId) => {
                // find achievement doc if needed...
                return (
                  <div key={achId} className="achievement-display">
                    {achId}
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
            {purchasedItems && purchasedItems.length > 0 ? (
              purchasedItems.map((itemId) => (
                <div key={itemId} className="purchased-item-display">
                  <div>Item ID: {itemId}</div>
                </div>
              ))
            ) : (
              <p>No purchased items yet (besides avatars).</p>
            )}
          </div>
        </div>
      </div>

      {statusMessage && (
        <div className="status-message">
          {statusMessage}
        </div>
      )}
    </div>
  );
};

export default UserProfile;
