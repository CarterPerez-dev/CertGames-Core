// src/components/pages/store/UserProfile.js
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { logout, fetchUserData } from '../store/userSlice';
import { useNavigate } from 'react-router-dom';
import './UserProfile.css';

// Icons import
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
  FaEyeSlash,
  FaCoins,
  FaEdit,
  FaUserAlt,
  FaEnvelope,
  FaKey,
  FaSignOutAlt,
  FaChevronRight,
  FaChevronDown,
  FaChevronUp,
  FaStore,
  FaTimes,
  FaCheck,
  FaUserCircle,
  FaLevelUpAlt,
  FaPalette
} from 'react-icons/fa';

// Requirements component for password validation
import PasswordRequirements from '../auth/PasswordRequirements';

// Theme options for the application
const themeOptions = [

  // Neutral/Grays
  { id: 'silver', name: 'Silver', color: '#71717a' },
  { id: 'dark', name: 'Dark', color: '#334155' },
  // Reds/Pinks
  { id: 'red', name: 'Red', color: '#dc2626' },
  { id: 'crimson', name: 'Crimson', color: '#be123c' },
  { id: 'pink', name: 'Pink', color: '#db2777' },
  { id: 'magenta', name: 'Magenta', color: '#c026d3' },
  
  // Purples
  { id: 'violet', name: 'Violet', color: '#7c3aed' },
  { id: 'default', name: 'Purple (Default)', color: '#6543cc' },
  { id: 'indigo', name: 'Indigo', color: '#4f46e5' },
  { id: 'midnight', name: 'Midnight', color: '#312e81' },
  
  // Blues
  { id: 'blue', name: 'Blue', color: '#2563eb' },
  { id: 'navy', name: 'Navy', color: '#1e3a8a' },
  { id: 'sky', name: 'Sky', color: '#0284c7' },
  { id: 'cyan', name: 'Cyan', color: '#0891b2' },
  
  // Teals/Greens
  { id: 'teal', name: 'Teal', color: '#0891b2' },
  { id: 'turquoise', name: 'Turquoise', color: '#0d9488' },
  { id: 'emerald', name: 'Emerald', color: '#047857' },
  { id: 'green', name: 'Green', color: '#059669' },
  { id: 'neon', name: 'Neon', color: '#10b981' },
  { id: 'lime', name: 'Lime', color: '#65a30d' },
  
  // Browns/Yellows/Oranges
  { id: 'chocolate', name: 'Chocolate', color: '#854d0e' },
  { id: 'gold', name: 'Gold', color: '#ca8a04' },
  { id: 'amber', name: 'Amber', color: '#d97706' },
  { id: 'orange', name: 'Orange', color: '#ea580c' },
];
// ==========================
// FRONTEND VALIDATION HELPERS
// ==========================

// Example small dictionary of very common passwords
const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "qwerty", "letmein", "welcome"
]);

// Private Use / Surrogates ranges
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

// Disallow mixing major scripts
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
  const trimmedName = username.trim();

  // Disallow any internal spaces
  if (/\s/.test(trimmedName)) {
    errors.push("Username cannot contain spaces.");
  }

  const name = trimmedName.normalize("NFC");

  // 1) Length
  if (name.length < 3 || name.length > 30) {
    errors.push("Username must be between 3 and 30 characters long.");
  }

  // 2) Forbidden Unicode script checks
  if (hasForbiddenUnicodeScripts(name)) {
    errors.push("Username contains forbidden Unicode blocks.");
  }

  // 3) Disallow mixing multiple major scripts
  if (disallowMixedScripts(name)) {
    errors.push("Username cannot mix multiple Unicode scripts.");
  }

  // 4) Forbid control chars [0..31, 127] + suspicious punctuation
  const forbiddenRanges = [[0, 31], [127, 127]];
  const forbiddenChars = new Set(['<', '>', '\\', '/', '"', "'", ';', '`',' ', '\t', '\r', '\n']);
  for (let i = 0; i < name.length; i++) {
    const cp = name.charCodeAt(i);
    // Check ranges
    if (forbiddenRanges.some(([start, end]) => cp >= start && cp <= end)) {
      errors.push("Username contains forbidden control characters.");
      break;
    }
    if (forbiddenChars.has(name[i])) {
      errors.push("Username contains forbidden characters.");
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

  // Disallow any internal spaces
  if (/\s/.test(e)) {
    errors.push("Email cannot contain spaces.");
  }

  // 1) Length
  if (e.length < 5 || e.length > 128) {
    errors.push("Email length must be between 5 and 128 characters.");
  }

  // 3) Forbid suspicious ASCII
  const forbiddenAscii = new Set(['<','>','`',';',' ', '\t','\r','\n','"',"'", '\\']);
  for (let i = 0; i < e.length; i++) {
    if (forbiddenAscii.has(e[i])) {
      errors.push("Email contains forbidden characters.");
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
  const pwd = password.trim();

  // Disallow any internal spaces
  if (/\s/.test(pwd)) {
    errors.push("Spaces are not allowed in the password.");
  }

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

// ============================
// ACHIEVEMENT ICON MAPPING
// ============================
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
  "test_finisher": FaCheckCircle
};

// ============================
// COLOR MAPPING FOR ACHIEVEMENTS
// ============================
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
  "test_finisher": "#adff2f"
};

// Main UserProfile Component
const UserProfile = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();

  // Get user data from Redux store
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
    subscriptionPlatform,
    subscriptionStatus
  } = useSelector((state) => state.user);

  // Get achievements and shop items data
  const allAchievements = useSelector((state) => state.achievements.all);
  const allShopItems = useSelector((state) => state.shop.items);

  // Tabs state management
  const [activeTab, setActiveTab] = useState('overview');

  // Toggles for showing/hiding different forms
  const [showChangeUsername, setShowChangeUsername] = useState(false);
  const [newUsername, setNewUsername] = useState('');

  const [showChangeEmail, setShowChangeEmail] = useState(false);
  const [newEmail, setNewEmail] = useState('');

  const [showChangePassword, setShowChangePassword] = useState(false);

  // Password form states
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [oldPassword, setOldPassword] = useState('');

  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [showRequirements, setShowRequirements] = useState(false);

  // Status message
  const [statusMessage, setStatusMessage] = useState('');
  const [statusType, setStatusType] = useState(''); // 'success', 'error'

  // Stats display toggles
  const [showMoreAchievements, setShowMoreAchievements] = useState(false);
  const [showMoreItems, setShowMoreItems] = useState(false);

  // Theme state
  const [currentTheme, setCurrentTheme] = useState(() => {
    return localStorage.getItem('selectedTheme') || 'default';
  });

  // Calculate the percentage of XP to next level matching backend XP requirements
  const xpRequiredForLevel = (level) => {
    if (level < 1) return 0;
    if (level === 1) return 0;
    
    if (level <= 30) {
      return 500 * (level - 1);
    } else if (level <= 60) {
      const base = 500 * 29; // XP for levels up to 30
      return base + 750 * (level - 30);
    } else if (level <= 100) {
      const base = 500 * 29 + 750 * 30; // XP for levels up to 60
      return base + 1000 * (level - 60);
    } else {
      const base = 500 * 29 + 750 * 30 + 1000 * 40; // XP for levels up to 100
      return base + 1500 * (level - 100);
    }
  };
  
  const calculateXpPercentage = () => {
    // Get XP required for current level and next level
    const currentLevelXp = xpRequiredForLevel(level);
    const nextLevelXp = xpRequiredForLevel(level + 1);
    
    // Calculate how much XP we've earned in the current level
    const xpInCurrentLevel = xp - currentLevelXp;
    
    // Calculate how much XP is needed to reach the next level
    const xpRequiredForNextLevel = nextLevelXp - currentLevelXp;
    
    // Calculate percentage (capped at 100%)
    return Math.min(100, (xpInCurrentLevel / xpRequiredForNextLevel) * 100);
  };

  // XP progress percentage
  const xpPercentage = calculateXpPercentage();

  // Get user avatar from shop items
  let profilePicUrl = '/avatars/default-avatar.png'; // Default avatar
  if (currentAvatar) {
    const foundAvatar = allShopItems.find(item => item._id === currentAvatar);
    if (foundAvatar && foundAvatar.imageUrl) {
      profilePicUrl = foundAvatar.imageUrl;
    }
  }

  // Handle logout
  const handleLogout = () => {
    dispatch(logout());
    localStorage.removeItem('userId');
    navigate('/login');
  };

  // Refresh user data
  const refetchUser = () => {
    if (userId) {
      dispatch(fetchUserData(userId));
    }
  };

  // Clear status message after 5 seconds
  useEffect(() => {
    if (statusMessage) {
      const timer = setTimeout(() => {
        setStatusMessage('');
        setStatusType('');
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [statusMessage]);

  // Apply the theme on component mount
  useEffect(() => {
    // Apply the current theme when component mounts
    const savedTheme = localStorage.getItem('selectedTheme') || 'default';
    document.documentElement.setAttribute('data-theme', savedTheme);
    setCurrentTheme(savedTheme);
  }, []);

  // Handle theme change
  const handleThemeChange = (themeId) => {
    // Save to localStorage
    localStorage.setItem('selectedTheme', themeId);
    // Update state
    setCurrentTheme(themeId);
    // Apply the theme to the document
    document.documentElement.setAttribute('data-theme', themeId);
    
    setStatusMessage(`Theme changed to ${themeOptions.find(t => t.id === themeId).name}`);
    setStatusType('success');
  };

  // =======================
  // CHANGE USERNAME
  // =======================
  const handleChangeUsername = async () => {
    setStatusMessage('');
    setStatusType('');
    
    const errors = frontValidateUsername(newUsername);
    if (errors.length > 0) {
      setStatusMessage(errors.join(' '));
      setStatusType('error');
      return;
    }

    try {
      const res = await fetch('/api/test/user/change-username', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, newUsername: newUsername.trim() })
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
      setStatusType('success');
      setShowChangeUsername(false);
      setNewUsername('');
      refetchUser();
    } catch (err) {
      setStatusMessage('Error: ' + err.message);
      setStatusType('error');
    }
  };

  // =======================
  // CHANGE EMAIL
  // =======================
  const handleChangeEmail = async () => {
    setStatusMessage('');
    setStatusType('');
    
    const errors = frontValidateEmail(newEmail);
    if (errors.length > 0) {
      setStatusMessage(errors.join(' '));
      setStatusType('error');
      return;
    }

    try {
      const res = await fetch('/api/test/user/change-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, newEmail: newEmail.trim() })
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
      setStatusType('success');
      setShowChangeEmail(false);
      setNewEmail('');
      refetchUser();
    } catch (err) {
      setStatusMessage('Error: ' + err.message);
      setStatusType('error');
    }
  };

  // =======================
  // CHANGE PASSWORD
  // =======================
  const handleChangePassword = async () => {
    setStatusMessage('');
    setStatusType('');

    if (!oldPassword || !newPassword || !confirmPassword) {
      setStatusMessage('All password fields are required');
      setStatusType('error');
      return;
    }
    if (newPassword !== confirmPassword) {
      setStatusMessage('New passwords do not match');
      setStatusType('error');
      return;
    }

    const errors = frontValidatePassword(newPassword, username, email);
    if (errors.length > 0) {
      setStatusMessage(errors.join(' '));
      setStatusType('error');
      return;
    }

    try {
      const res = await fetch('/api/test/user/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          oldPassword: oldPassword.trim(),
          newPassword: newPassword.trim(),
          confirmPassword: confirmPassword.trim()
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
      setStatusType('success');
      setShowChangePassword(false);
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setShowRequirements(false);
    } catch (err) {
      setStatusMessage('Error: ' + err.message);
      setStatusType('error');
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
      setStatusMessage('Subscription cancelled successfully');
      setStatusType('success');
      refetchUser();
    } catch (err) {
      setStatusMessage('Error: ' + err.message);
      setStatusType('error');
    }
  };

  // Map user achievements IDs to full achievement data
  const userAchievementsData = achievements
    .map(achId => allAchievements.find(a => a.achievementId === achId))
    .filter(Boolean);

  // Map user purchased item IDs to full shop item data
  const userPurchasedItems = purchasedItems
    .map(itemId => allShopItems.find(item => item._id === itemId))
    .filter(Boolean);

  return (
    <div className="user-profile-container">
      {/* Notification */}
      {statusMessage && (
        <div className={`profile-notification ${statusType === 'success' ? 'profile-notification-success' : 'profile-notification-error'}`}>
          <span>{statusMessage}</span>
          <button onClick={() => setStatusMessage('')} className="profile-notification-close">
            <FaTimes />
          </button>
        </div>
      )}

      {/* Main wrapper */}
      <div className="profile-wrapper">
        {/* Header section with profile info */}
        <div className="profile-header-section">
          <div className="profile-header-content">
            <div className="profile-avatar-wrapper">
              <img src={profilePicUrl} alt={`${username}'s avatar`} className="profile-avatar" />
            </div>
            
            <div className="profile-header-info">
              <h1 className="profile-username">{username}</h1>
              
              <div className="profile-level-container">
                <div className="profile-level-badge">
                  <span className="profile-level-number">{level}</span>
                  <FaLevelUpAlt className="profile-level-icon" />
                </div>
                
                <div className="profile-xp-container">
                  <div className="profile-xp-bar">
                    <div 
                      className="profile-xp-progress" 
                      style={{ width: `${xpPercentage}%` }}
                    ></div>
                  </div>
                  <span className="profile-xp-text">{xp} XP</span>
                </div>
              </div>
              
              <div className="profile-stats">
                <div className="profile-stat-item">
                  <FaCoins className="profile-stat-icon" />
                  <span className="profile-stat-value">{coins}</span>
                </div>
                <div className="profile-stat-item">
                  <FaTrophy className="profile-stat-icon" />
                  <span className="profile-stat-value">{achievements.length}</span>
                </div>
                <div className="profile-stat-item">
                  <FaStore className="profile-stat-icon" />
                  <span className="profile-stat-value">{purchasedItems.length}</span>
                </div>
              </div>
            </div>
            
            <div className="profile-actions">
              <button className="profile-logout-btn" onClick={handleLogout}>
                <FaSignOutAlt />
                <span>Logout</span>
              </button>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="profile-tabs">
          <button 
            className={`profile-tab ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </button>
          <button 
            className={`profile-tab ${activeTab === 'achievements' ? 'active' : ''}`}
            onClick={() => setActiveTab('achievements')}
          >
            Achievements
          </button>
          <button 
            className={`profile-tab ${activeTab === 'items' ? 'active' : ''}`}
            onClick={() => setActiveTab('items')}
          >
            Items
          </button>
          <button 
            className={`profile-tab ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveTab('settings')}
          >
            Settings
          </button>
        </div>

        {/* Content section based on active tab */}
        <div className="profile-content">
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="profile-overview-tab">
              {/* Theme Switcher in Overview Tab */}
              <div className="profile-overview-theme-switcher">
                <h3 className="profile-theme-switcher-title">
                  <FaPalette className="profile-setting-icon" />
                  Change Theme
                </h3>
                <div className="profile-theme-options">
                  {themeOptions.map(theme => (
                    <button
                      key={theme.id}
                      className={`profile-theme-option ${currentTheme === theme.id ? 'active' : ''}`}
                      style={{ backgroundColor: theme.color }}
                      onClick={() => handleThemeChange(theme.id)}
                      aria-label={`Select ${theme.name} theme`}
                    >
                      {currentTheme === theme.id && <FaCheck className="profile-theme-check" />}
                    </button>
                  ))}
                </div>
              </div>
              
              <div className="profile-overview-cards">
                <div className="profile-card">
                  <h2 className="profile-card-title">
                    <FaUserAlt className="profile-card-icon" />
                    User Info
                  </h2>
                  <div className="profile-card-content">
                    <div className="profile-detail-item">
                      <span className="profile-detail-label">ID:</span>
                      <span className="profile-detail-value">{userId}</span>
                    </div>
                    <div className="profile-detail-item">
                      <span className="profile-detail-label">Username:</span>
                      <span className="profile-detail-value">{username}</span>
                    </div>
                    <div className="profile-detail-item">
                      <span className="profile-detail-label">Email:</span>
                      <span className="profile-detail-value">{email}</span>
                    </div>
                    <div className="profile-detail-item">
                      <span className="profile-detail-label">Subscription:</span>
                      <span className="profile-detail-value">
                        {subscriptionActive ? (
                          <span className="profile-subscription-active">Active</span>
                        ) : (
                          <span className="profile-subscription-inactive">Inactive</span>
                        )}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="profile-card">
                  <h2 className="profile-card-title">
                    <FaTrophy className="profile-card-icon" />
                    Latest Achievements
                  </h2>
                  <div className="profile-card-content">
                    {userAchievementsData.length > 0 ? (
                      <div className="profile-mini-achievements">
                        {userAchievementsData.slice(0, 3).map((ach) => {
                          const AchIcon = iconMapping[ach.achievementId] || FaTrophy;
                          const achColor = colorMapping[ach.achievementId] || "#ffffff";
                          
                          return (
                            <div key={ach.achievementId} className="profile-mini-achievement">
                              <div className="profile-mini-achievement-icon" style={{ color: achColor }}>
                                <AchIcon />
                              </div>
                              <div className="profile-mini-achievement-info">
                                <span className="profile-mini-achievement-title">{ach.title}</span>
                              </div>
                            </div>
                          );
                        })}
                        {userAchievementsData.length > 3 && (
                          <button 
                            className="profile-view-more-btn"
                            onClick={() => setActiveTab('achievements')}
                          >
                            View All ({userAchievementsData.length})
                          </button>
                        )}
                      </div>
                    ) : (
                      <p className="profile-empty-message">No achievements yet. Start completing tests!</p>
                    )}
                  </div>
                </div>

                <div className="profile-card">
                  <h2 className="profile-card-title">
                    <FaStore className="profile-card-icon" />
                    Latest Items
                  </h2>
                  <div className="profile-card-content">
                    {userPurchasedItems && userPurchasedItems.length > 0 ? (
                      <div className="profile-mini-items">
                        {userPurchasedItems.slice(0, 3).map((item) => (
                          <div key={item._id} className="profile-mini-item">
                            <img
                              src={item.imageUrl}
                              alt={item.title}
                              className="profile-mini-item-image"
                            />
                            <span className="profile-mini-item-title">{item.title}</span>
                          </div>
                        ))}
                        {userPurchasedItems.length > 3 && (
                          <button 
                            className="profile-view-more-btn"
                            onClick={() => setActiveTab('items')}
                          >
                            View All ({userPurchasedItems.length})
                          </button>
                        )}
                      </div>
                    ) : (
                      <p className="profile-empty-message">No items purchased yet. Visit the shop!</p>
                    )}
                  </div>
                </div>
              </div>

              <div className="profile-overview-stats">
                <div className="profile-stats-card">
                  <h2 className="profile-card-title">Player Stats</h2>
                  <div className="profile-stats-grid">
                    <div className="profile-stat-card">
                      <div className="profile-stat-header">
                        <FaLevelUpAlt className="profile-stat-header-icon" />
                        <span>Level</span>
                      </div>
                      <div className="profile-stat-number">{level}</div>
                    </div>

                    <div className="profile-stat-card">
                      <div className="profile-stat-header">
                        <FaStar className="profile-stat-header-icon" />
                        <span>XP</span>
                      </div>
                      <div className="profile-stat-number">{xp}</div>
                    </div>

                    <div className="profile-stat-card">
                      <div className="profile-stat-header">
                        <FaCoins className="profile-stat-header-icon" />
                        <span>Coins</span>
                      </div>
                      <div className="profile-stat-number">{coins}</div>
                    </div>

                    <div className="profile-stat-card">
                      <div className="profile-stat-header">
                        <FaTrophy className="profile-stat-header-icon" />
                        <span>Achievements</span>
                      </div>
                      <div className="profile-stat-number">{achievements.length}</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Achievements Tab */}
          {activeTab === 'achievements' && (
            <div className="profile-achievements-tab">
              <h2 className="profile-section-title">Your Achievements</h2>
              
              {userAchievementsData.length > 0 ? (
                <div className="profile-achievements-grid">
                  {userAchievementsData.map((ach) => {
                    const AchIcon = iconMapping[ach.achievementId] || FaTrophy;
                    const achColor = colorMapping[ach.achievementId] || "#ffffff";
                    
                    return (
                      <div key={ach.achievementId} className="profile-achievement-card">
                        <div className="profile-achievement-icon" style={{ color: achColor }}>
                          {ach.title.includes('🏆') ? (
                            <span className="profile-achievement-emoji">{ach.title.split(' ')[0]}</span>
                          ) : (
                            <AchIcon />
                          )}
                        </div>
                        <div className="profile-achievement-content">
                          <h3 className="profile-achievement-title">
                            {ach.title.includes('🏆') ? ach.title.split(' ').slice(1).join(' ') : ach.title}
                          </h3>
                          <p className="profile-achievement-description">{ach.description}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="profile-empty-state">
                  <FaTrophy className="profile-empty-icon" />
                  <p>You haven't unlocked any achievements yet.</p>
                  <p>Complete tests and challenges to earn achievements!</p>
                </div>
              )}
            </div>
          )}

          {/* Items Tab */}
          {activeTab === 'items' && (
            <div className="profile-items-tab">
              <h2 className="profile-section-title">Your Items</h2>
              
              {userPurchasedItems && userPurchasedItems.length > 0 ? (
                <div className="profile-items-grid">
                  {userPurchasedItems.map((item) => (
                    <div key={item._id} className="profile-item-card">
                      <div className="profile-item-image-container">
                        <img
                          src={item.imageUrl}
                          alt={item.title}
                          className="profile-item-image"
                        />
                      </div>
                      <div className="profile-item-content">
                        <h3 className="profile-item-title">{item.title}</h3>
                        {item.description && (
                          <p className="profile-item-description">{item.description}</p>
                        )}
                        <div className="profile-item-status">
                          {item._id === currentAvatar ? (
                            <span className="profile-item-equipped">Equipped</span>
                          ) : (
                            <span className="profile-item-owned">Owned</span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="profile-empty-state">
                  <FaStore className="profile-empty-icon" />
                  <p>You haven't purchased any items yet.</p>
                  <p>Visit the shop to buy avatars and other items!</p>
                </div>
              )}
            </div>
          )}

          {/* Settings Tab */}
          {activeTab === 'settings' && (
            <div className="profile-settings-tab">
              <h2 className="profile-section-title">Account Settings</h2>
              
              <div className="profile-settings-grid">
                {/* Change Username */}
                <div className="profile-setting-card">
                  <div className="profile-setting-header">
                    <FaUserAlt className="profile-setting-icon" />
                    <h3 className="profile-setting-title">Username</h3>
                  </div>
                  
                  <div className="profile-setting-content">
                    <p className="profile-setting-current">Current: <span>{username}</span></p>
                    
                    {!showChangeUsername ? (
                      <button 
                        className="profile-setting-action-btn"
                        onClick={() => setShowChangeUsername(true)}
                      >
                        <FaEdit />
                        <span>Change Username</span>
                      </button>
                    ) : (
                      <div className="profile-setting-form">
                        <div className="profile-setting-input-group">
                          <input
                            type="text"
                            className="profile-setting-input"
                            placeholder="New username"
                            value={newUsername}
                            onChange={(e) => setNewUsername(e.target.value)}
                          />
                        </div>
                        <div className="profile-setting-buttons">
                          <button 
                            className="profile-setting-submit-btn"
                            onClick={handleChangeUsername}
                          >
                            <FaCheck />
                            <span>Save</span>
                          </button>
                          <button 
                            className="profile-setting-cancel-btn"
                            onClick={() => {
                              setShowChangeUsername(false);
                              setNewUsername('');
                            }}
                          >
                            <FaTimes />
                            <span>Cancel</span>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Change Email */}
                <div className="profile-setting-card">
                  <div className="profile-setting-header">
                    <FaEnvelope className="profile-setting-icon" />
                    <h3 className="profile-setting-title">Email</h3>
                  </div>
                  
                  <div className="profile-setting-content">
                    <p className="profile-setting-current">Current: <span>{email}</span></p>
                    
                    {!showChangeEmail ? (
                      <button 
                        className="profile-setting-action-btn"
                        onClick={() => setShowChangeEmail(true)}
                      >
                        <FaEdit />
                        <span>Change Email</span>
                      </button>
                    ) : (
                      <div className="profile-setting-form">
                        <div className="profile-setting-input-group">
                          <input
                            type="email"
                            className="profile-setting-input"
                            placeholder="New email address"
                            value={newEmail}
                            onChange={(e) => setNewEmail(e.target.value)}
                          />
                        </div>
                        <div className="profile-setting-buttons">
                          <button 
                            className="profile-setting-submit-btn"
                            onClick={handleChangeEmail}
                          >
                            <FaCheck />
                            <span>Save</span>
                          </button>
                          <button 
                            className="profile-setting-cancel-btn"
                            onClick={() => {
                              setShowChangeEmail(false);
                              setNewEmail('');
                            }}
                          >
                            <FaTimes />
                            <span>Cancel</span>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Change Password */}
                <div className="profile-setting-card">
                  <div className="profile-setting-header">
                    <FaKey className="profile-setting-icon" />
                    <h3 className="profile-setting-title">Password</h3>
                  </div>
                  
                  <div className="profile-setting-content">
                    <p className="profile-setting-current">Status: <span>*********</span></p>
                    
                    {!showChangePassword ? (
                      <button 
                        className="profile-setting-action-btn"
                        onClick={() => setShowChangePassword(true)}
                      >
                        <FaEdit />
                        <span>Change Password</span>
                      </button>
                    ) : (
                      <div className="profile-setting-form">
                        {/* Old Password */}
                        <div className="profile-setting-input-group">
                          <div className="profile-setting-password-field">
                            <input
                              type={showOldPassword ? 'text' : 'password'}
                              className="profile-setting-input"
                              placeholder="Current password"
                              value={oldPassword}
                              onChange={(e) => setOldPassword(e.target.value)}
                            />
                            <button
                              type="button"
                              className="profile-setting-password-toggle"
                              onClick={() => setShowOldPassword(!showOldPassword)}
                            >
                              {showOldPassword ? <FaEyeSlash /> : <FaEye />}
                            </button>
                          </div>
                        </div>
                        
                        {/* New Password */}
                        <div className="profile-setting-input-group">
                          <div className="profile-setting-password-field">
                            <input
                              type={showNewPassword ? 'text' : 'password'}
                              className="profile-setting-input"
                              placeholder="New password"
                              value={newPassword}
                              onChange={(e) => setNewPassword(e.target.value)}
                              onFocus={() => setShowRequirements(true)}
                              onBlur={() => {
                                if (!newPassword) {
                                  setShowRequirements(false);
                                }
                              }}
                            />
                            <button
                              type="button"
                              className="profile-setting-password-toggle"
                              onClick={() => setShowNewPassword(!showNewPassword)}
                            >
                              {showNewPassword ? <FaEyeSlash /> : <FaEye />}
                            </button>
                          </div>
                        </div>
                        
                        {/* Password Requirements */}
                        {showRequirements && (
                          <div className="profile-password-requirements">
                            <PasswordRequirements password={newPassword} />
                          </div>
                        )}
                        
                        {/* Confirm Password */}
                        <div className="profile-setting-input-group">
                          <div className="profile-setting-password-field">
                            <input
                              type={showConfirmPassword ? 'text' : 'password'}
                              className="profile-setting-input"
                              placeholder="Confirm new password"
                              value={confirmPassword}
                              onChange={(e) => setConfirmPassword(e.target.value)}
                            />
                            <button
                              type="button"
                              className="profile-setting-password-toggle"
                              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                            >
                              {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
                            </button>
                          </div>
                        </div>
                        
                        <div className="profile-setting-buttons">
                          <button 
                            className="profile-setting-submit-btn"
                            onClick={handleChangePassword}
                          >
                            <FaCheck />
                            <span>Save</span>
                          </button>
                          <button 
                            className="profile-setting-cancel-btn"
                            onClick={() => {
                              setShowChangePassword(false);
                              setOldPassword('');
                              setNewPassword('');
                              setConfirmPassword('');
                              setShowRequirements(false);
                            }}
                          >
                            <FaTimes />
                            <span>Cancel</span>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Subscription Management */}
                <div className="profile-setting-card">
                  <div className="profile-setting-header">
                    <FaUserCircle className="profile-setting-icon" />
                    <h3 className="profile-setting-title">Subscription</h3>
                  </div>
                  
                  <div className="profile-setting-content">
                    <div className="profile-setting-subscription-details">
                      <div className="profile-setting-subscription-row">
                        <span className="profile-setting-subscription-label">Status:</span>
                        <span className={`profile-setting-subscription-value ${subscriptionActive ? "subscription-active" : "subscription-inactive"}`}>
                          {subscriptionActive ? "Active" : "Inactive"}
                        </span>
                      </div>
                      
                      {subscriptionActive && (
                        <>
                          <div className="profile-setting-subscription-row">
                            <span className="profile-setting-subscription-label">Plan:</span>
                            <span className="profile-setting-subscription-value">
                              Premium
                            </span>
                          </div>
                          
                          <div className="profile-setting-subscription-row">
                            <span className="profile-setting-subscription-label">Platform:</span>
                            <span className="profile-setting-subscription-value">
                              {subscriptionPlatform ? subscriptionPlatform.charAt(0).toUpperCase() + subscriptionPlatform.slice(1) : 'N/A'}
                            </span>
                          </div>
                          
                          <div className="profile-setting-subscription-row">
                            <span className="profile-setting-subscription-label">Status:</span>
                            <span className="profile-setting-subscription-value">
                              {subscriptionStatus ? subscriptionStatus.charAt(0).toUpperCase() + subscriptionStatus.slice(1) : 'N/A'}
                            </span>
                          </div>
                        </>
                      )}
                    </div>
                    
                    {subscriptionActive && subscriptionStatus !== 'canceling' && (
                      <button 
                        className="profile-setting-action-btn profile-setting-danger-btn"
                        onClick={handleCancelSubscription}
                      >
                        <FaTimes />
                        <span>Cancel Subscription</span>
                      </button>
                    )}
                    
                    {subscriptionActive && subscriptionStatus === 'canceling' && (
                      <div className="profile-setting-subscription-canceling">
                        <p>Your subscription will remain active until the end of the current billing period.</p>
                      </div>
                    )}
                    
                    {!subscriptionActive && (
                      <button 
                        className="profile-setting-action-btn"
                        onClick={() => navigate('/subscription')}
                      >
                        <FaCheck />
                        <span>Subscribe Now</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UserProfile;
