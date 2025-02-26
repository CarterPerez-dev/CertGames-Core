// src/components/pages/store/UserProfile.js
import React, { useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { logout, fetchUserData } from '../store/userSlice';
import { useNavigate } from 'react-router-dom';
import './UserProfile.css'; // Our updated CSS with the unique eye icon

import '../auth/auth.css';
import '../auth/AuthToast.css'; 
import PasswordRequirements from '../auth/PasswordRequirements';

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

// ====================================
// FRONTEND VALIDATION HELPERS
// (Approximating your Python rules)
// ====================================

// Example small dictionary of very common passwords
const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "qwerty", "letmein", "welcome"
]);

// Private Use / Surrogates ranges (approx in JS)
const PRIVATE_USE_RANGES = [
  [0xE000, 0xF8FF],
  [0xF0000, 0xFFFFD],
  [0x100000, 0x10FFFD]
];
const SURROGATES_RANGE = [0xD800, 0xDFFF];

// Basic check for private use / surrogate codepoints
function hasForbiddenUnicodeScripts(str) {
  for (let i = 0; i < str.length; i++) {
    const cp = str.codePointAt(i);
    // Surrogates
    if (cp >= SURROGATES_RANGE[0] && cp <= SURROGATES_RANGE[1]) {
      return true;
    }
    // Private use
    for (const [start, end] of PRIVATE_USE_RANGES) {
      if (cp >= start && cp <= end) {
        return true;
      }
    }
  }
  return false;
}

// Disallow mixing major scripts (Latin, Greek, Cyrillic) -- simplistic approach
function disallowMixedScripts(str) {
  const scriptSets = new Set();
  for (let i = 0; i < str.length; i++) {
    const cp = str.codePointAt(i);
    // Basic Latin & extended
    if (cp >= 0x0041 && cp <= 0x024F) {
      scriptSets.add("Latin");
    }
    // Greek
    else if (cp >= 0x0370 && cp <= 0x03FF) {
      scriptSets.add("Greek");
    }
    // Cyrillic
    else if (cp >= 0x0400 && cp <= 0x04FF) {
      scriptSets.add("Cyrillic");
    }
    if (scriptSets.size > 1) {
      return true;
    }
  }
  return false;
}

// ========================
// FRONTEND: Validate Username
// ========================
function frontValidateUsername(username) {
  const errors = [];
  const name = username.normalize("NFC");

  // 1) Length
  if (name.length < 3 || name.length > 30) {
    errors.push("Username must be between 3 and 30 characters long.");
  }

  // 2) Forbidden Unicode script checks
  if (hasForbiddenUnicodeScripts(name)) {
    errors.push("Username contains forbidden Unicode blocks (private use or surrogates).");
  }

  // 3) Disallow mixing multiple major scripts
  if (disallowMixedScripts(name)) {
    errors.push("Username cannot mix multiple Unicode scripts (e.g., Latin & Cyrillic).");
  }

  // 4) Forbid control chars [0..31, 127] + suspicious punctuation
  const forbiddenRanges = [[0, 31], [127, 127]];
  const forbiddenChars = new Set(['<', '>', '\\', '/', '"', "'", ';', '`',' ', '\t', '\r', '\n']);
  for (let i = 0; i < name.length; i++) {
    const cp = name.charCodeAt(i);
    // Check ranges
    if (forbiddenRanges.some(([start, end]) => cp >= start && cp <= end)) {
      errors.push("Username contains forbidden control characters (ASCII 0-31 or 127).");
      break;
    }
    if (forbiddenChars.has(name[i])) {
      errors.push("Username contains forbidden characters like <, >, or whitespace.");
      break;
    }
  }

  // 5) Strict allowlist pattern
  const pattern = /^[A-Za-z0-9._-]+$/;
  if (!pattern.test(name)) {
    errors.push("Username can only contain letters, digits, underscores, dashes, or dots.");
  }

  // 6) Disallow triple identical consecutive characters
  if (/(.)\1{2,}/.test(name)) {
    errors.push("Username cannot contain three identical consecutive characters.");
  }

  // 7) Disallow leading or trailing punctuation
  if (/^[._-]|[._-]$/.test(name)) {
    errors.push("Username cannot start or end with . - or _.");
  }

  return errors;
}

// ========================
// FRONTEND: Validate Email
// ========================
function frontValidateEmail(email) {
  const errors = [];
  const e = email.normalize("NFC").trim();

  // 1) Length
  if (e.length < 5 || e.length > 128) {
    errors.push("Email length must be between 5 and 128 characters.");
  }

  // 3) Forbid suspicious ASCII
  const forbiddenAscii = new Set(['<','>','`',';',' ', '\t','\r','\n','"',"'", '\\']);
  for (let i = 0; i < e.length; i++) {
    if (forbiddenAscii.has(e[i])) {
      errors.push("Email contains forbidden characters like <, >, or whitespace.");
      break;
    }
  }

  // 4) Must have exactly one @
  const atCount = (e.match(/@/g) || []).length;
  if (atCount !== 1) {
    errors.push("Email must contain exactly one '@' symbol.");
  }

  return errors;
}

// ========================
// FRONTEND: Validate Password
// ========================
function frontValidatePassword(password, username, email) {
  const errors = [];
  const pwd = password;

  // 1) Length
  if (pwd.length < 6 || pwd.length > 64) {
    errors.push("Password must be between 6 and 64 characters long.");
  }

  // 2) Disallow whitespace or < >
  if (/[ \t\r\n<>]/.test(pwd)) {
    errors.push("Password cannot contain whitespace or < or > characters.");
  }

  // 3) Complexity
  if (!/[A-Z]/.test(pwd)) {
    errors.push("Password must contain at least one uppercase letter.");
  }
  if (!/[a-z]/.test(pwd)) {
    errors.push("Password must contain at least one lowercase letter.");
  }
  if (!/\d/.test(pwd)) {
    errors.push("Password must contain at least one digit.");
  }
  const specialPattern = /[!@#$%^&*()\-_=+\[\]{}|;:'",<.>\/?`~\\]/;
  if (!specialPattern.test(pwd)) {
    errors.push("Password must contain at least one special character.");
  }

  // 4) Disallow triple identical consecutive characters
  if (/(.)\1{2,}/.test(pwd)) {
    errors.push("Password must not contain three identical consecutive characters.");
  }

  // 5) Check common password list
  const lowerPwd = pwd.toLowerCase();
  if (COMMON_PASSWORDS.has(lowerPwd)) {
    errors.push("Password is too common. Please choose a stronger password.");
  }

  // 6) Disallow certain dictionary words
  const dictionaryPatterns = ['password', 'qwerty', 'abcdef', 'letmein', 'welcome', 'admin'];
  for (const pat of dictionaryPatterns) {
    if (lowerPwd.includes(pat)) {
      errors.push(`Password must not contain the word '${pat}'.`);
    }
  }

  // 7) Disallow if password contains username or local part of email
  if (username && lowerPwd.includes(username.toLowerCase())) {
    errors.push("Password must not contain your username.");
  }
  if (email) {
    const emailLocalPart = email.split('@')[0].toLowerCase();
    if (lowerPwd.includes(emailLocalPart)) {
      errors.push("Password must not contain the local part of your email address.");
    }
  }

  return errors;
}

// ====================================
// (Optional) Achievement Icons
// ====================================
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
    subscriptionActive,
    password
  } = useSelector((state) => state.user);

  // Toggles for showing/hiding different forms
  const [showChangeUsername, setShowChangeUsername] = useState(false);
  const [newUsername, setNewUsername] = useState('');

  const [showChangeEmail, setShowChangeEmail] = useState(false);
  const [newEmail, setNewEmail] = useState('');

  const [showChangePassword, setShowChangePassword] = useState(false);

  // Toggles for showing/hiding password text
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [oldPassword, setOldPassword] = useState('');

  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [showRequirements, setShowRequirements] = useState(false);

  // The "current password" in the overview
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);

  // For success/error messages
  const [statusMessage, setStatusMessage] = useState('');

  let profilePicUrl = '/avatars/avatar1.png'; 
  // or logic if you have stored 'currentAvatar'

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

  // =======================
  // CHANGE USERNAME
  // =======================
  const handleChangeUsername = async () => {
    setStatusMessage('');
    const errors = frontValidateUsername(newUsername);
    if (errors.length > 0) {
      setStatusMessage(errors.join(' '));
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
        let errorMsg = data.error || 'Failed to change username';
        if (data.details && data.details.length > 0) {
          errorMsg += ': ' + data.details.join(', ');
        }
        throw new Error(errorMsg);
      }
      setStatusMessage('Username updated successfully!');
      setShowChangeUsername(false);
      setNewUsername('');
      refetchUser();
    } catch (err) {
      setStatusMessage('Error changing username: ' + err.message);
    }
  };

  // =======================
  // CHANGE EMAIL
  // =======================
  const handleChangeEmail = async () => {
    setStatusMessage('');
    const errors = frontValidateEmail(newEmail);
    if (errors.length > 0) {
      setStatusMessage(errors.join(' '));
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
        let errorMsg = data.error || 'Failed to change email';
        if (data.details && data.details.length > 0) {
          errorMsg += ': ' + data.details.join(', ');
        }
        throw new Error(errorMsg);
      }
      setStatusMessage('Email updated successfully!');
      setShowChangeEmail(false);
      setNewEmail('');
      refetchUser();
    } catch (err) {
      setStatusMessage('Error changing email: ' + err.message);
    }
  };

  // =======================
  // CHANGE PASSWORD
  // =======================
  const handleChangePassword = async () => {
    setStatusMessage('');

    if (!oldPassword || !newPassword || !confirmPassword) {
      setStatusMessage('All password fields are required');
      return;
    }
    if (newPassword !== confirmPassword) {
      setStatusMessage('New passwords do not match');
      return;
    }

    const errors = frontValidatePassword(newPassword, username, email);
    if (errors.length > 0) {
      setStatusMessage(errors.join(' '));
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
        let errorMsg = data.error || 'Failed to change password';
        if (data.details && data.details.length > 0) {
          errorMsg += ': ' + data.details.join(', ');
        }
        throw new Error(errorMsg);
      }

      setStatusMessage('Password changed successfully!');
      setShowChangePassword(false);
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setShowRequirements(false);
    } catch (err) {
      setStatusMessage('Error changing password: ' + err.message);
    }
  };

  // CANCEL SUBSCRIPTION (placeholder)
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

            <div className="password-display-row">
              <span className="detail-label">Password:</span>
              <div className="password-value-container">
                <span>{showCurrentPassword ? password : '••••••••'}</span>
                <button 
                  className="profile-eye-icon"
                  onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                >
                  {showCurrentPassword ? <FaEyeSlash /> : <FaEye />}
                </button>
              </div>
            </div>
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
                <h3>Change Password</h3>
                <div className="password-row">
                  <div className="password-input-container">
                    <input 
                      type={showOldPassword ? 'text' : 'password'}
                      placeholder="Old password"
                      value={oldPassword}
                      onChange={(e) => setOldPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      className="profile-eye-icon"
                      onClick={() => setShowOldPassword(!showOldPassword)}
                    >
                      {showOldPassword ? <FaEyeSlash /> : <FaEye />}
                    </button>
                  </div>
                </div>
                
                <div className="password-row">
                  <div className="password-input-container">
                    <input 
                      type={showNewPassword ? 'text' : 'password'}
                      placeholder="New password"
                      value={newPassword}
                      onFocus={() => setShowRequirements(true)} 
                      onChange={(e) => setNewPassword(e.target.value)}
                      onBlur={() => {
                        if (!newPassword) {
                          setShowRequirements(false);
                        }
                      }}
                    />
                    <button
                      type="button"
                      className="profile-eye-icon"
                      onClick={() => setShowNewPassword(!showNewPassword)}
                    >
                      {showNewPassword ? <FaEyeSlash /> : <FaEye />}
                    </button>
                  </div>
                </div>

                {showRequirements && (
                  <PasswordRequirements password={newPassword} />
                )}

                <div className="password-row">
                  <div className="password-input-container">
                    <input 
                      type={showConfirmPassword ? 'text' : 'password'}
                      placeholder="Confirm new password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      className="profile-eye-icon"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    >
                      {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
                    </button>
                  </div>
                </div>

                <div className="change-section-buttons">
                  <button onClick={handleChangePassword}>Submit</button>
                  <button onClick={() => {
                    setShowChangePassword(false);
                    setOldPassword('');
                    setNewPassword('');
                    setConfirmPassword('');
                    setShowRequirements(false);
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
              achievements.map((achId) => (
                <div key={achId} className="achievement-display">
                  {achId}
                </div>
              ))
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

