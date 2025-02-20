// src/components/pages/auth/Register.js
import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { registerUser, loginUser } from '../store/userSlice';
import { useNavigate, Link } from 'react-router-dom';
import { FaEye, FaEyeSlash } from 'react-icons/fa';
import { toast } from 'react-toastify';
import PasswordRequirements from './PasswordRequirements';

import './Register.css';
import './auth.css';
import './AuthToast.css'; // optional custom styling

// =============================
// FRONT-END VALIDATION HELPERS
// (Mirroring your Python logic)
// =============================

const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "qwerty", "letmein", "welcome"
]);

const PRIVATE_USE_RANGES = [
  [0xE000, 0xF8FF],
  [0xF0000, 0xFFFFD],
  [0x100000, 0x10FFFD]
];
const SURROGATES_RANGE = [0xD800, 0xDFFF];

function hasForbiddenUnicodeScripts(str) {
  for (let i = 0; i < str.length; i++) {
    const cp = str.codePointAt(i);
    if (cp >= SURROGATES_RANGE[0] && cp <= SURROGATES_RANGE[1]) {
      return true;
    }
    for (const [start, end] of PRIVATE_USE_RANGES) {
      if (cp >= start && cp <= end) {
        return true;
      }
    }
  }
  return false;
}

function disallowMixedScripts(str) {
  const scriptSets = new Set();
  for (let i = 0; i < str.length; i++) {
    const cp = str.codePointAt(i);
    if (cp >= 0x0041 && cp <= 0x024F) {
      scriptSets.add("Latin");
    } else if (cp >= 0x0370 && cp <= 0x03FF) {
      scriptSets.add("Greek");
    } else if (cp >= 0x0400 && cp <= 0x04FF) {
      scriptSets.add("Cyrillic");
    }
    if (scriptSets.size > 1) {
      return true;
    }
  }
  return false;
}

// Validate username
function validateUsername(username) {
  const errors = [];
  const name = username.normalize("NFC");

  if (name.length < 3 || name.length > 30) {
    errors.push("Username must be between 3 and 30 characters long.");
  }
  if (hasForbiddenUnicodeScripts(name)) {
    errors.push("Username contains forbidden Unicode blocks.");
  }
  if (disallowMixedScripts(name)) {
    errors.push("Username cannot mix multiple Unicode scripts (Latin & Cyrillic, etc.).");
  }
  // Basic allowlist
  if (!/^[A-Za-z0-9._-]+$/.test(name)) {
    errors.push("Username can only contain letters, digits, underscores, dashes, or dots.");
  }
  // Triple consecutive identical
  if (/(.)\1{2,}/.test(name)) {
    errors.push("Username cannot contain three identical consecutive characters.");
  }
  // Leading/trailing punctuation
  if (/^[._-]|[._-]$/.test(name)) {
    errors.push("Username cannot start or end with . - or _.");
  }
  return errors;
}

// Validate email
function validateEmail(email) {
  const errors = [];
  const e = email.normalize("NFC").trim();

  if (e.length < 5 || e.length > 128) {
    errors.push("Email length must be 5–128 characters.");
  }
  if (hasForbiddenUnicodeScripts(e)) {
    errors.push("Email contains forbidden Unicode blocks.");
  }
  // Only one '@'
  if ((e.match(/@/g) || []).length !== 1) {
    errors.push("Email must contain exactly one '@' symbol.");
  }
  
  return errors;
}

// Validate password
function validatePassword(password, username, email) {
  const errors = [];
  if (password.length < 6 || password.length > 69) {
    errors.push("Password must be between 6 and 69 characters long.");
  }
  if (/[ \t\r\n<>]/.test(password)) {
    errors.push("Password cannot contain whitespace or < or > characters.");
  }
  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter.");
  }
  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter.");
  }
  if (!/\d/.test(password)) {
    errors.push("Password must contain at least one digit.");
  }
  // special chars
  if (!/[!@#$%^&*()\-_=+\[\]{}|;:'",<.>\/?`~\\]/.test(password)) {
    errors.push("Password must contain at least one special character.");
  }

  // triple consecutive
  if (/(.)\1{2,}/.test(password)) {
    errors.push("Password must not contain three identical consecutive characters.");
  }

  // common password
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    errors.push("Password is too common. Please choose a stronger password.");
  }

  // dictionary
  const dictionaryPatterns = ['password', 'qwerty', 'abcdef', 'letmein', 'welcome', 'admin'];
  const lowerPwd = password.toLowerCase();
  for (const pat of dictionaryPatterns) {
    if (lowerPwd.includes(pat)) {
      errors.push(`Password must not contain '${pat}'.`);
    }
  }

  // If we want to forbid using username or email local-part
  if (username && lowerPwd.includes(username.toLowerCase())) {
    errors.push("Password must not contain your username.");
  }
  if (email) {
    const emailLocalPart = email.split('@')[0].toLowerCase();
    if (lowerPwd.includes(emailLocalPart)) {
      errors.push("Password must not contain the local part of your email.");
    }
  }

  return errors;
}

/**************************************************************
 * REGISTER COMPONENT
 **************************************************************/
const Register = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { loading, error, userId } = useSelector((state) => state.user);

  const [username, setUsername] = useState('');
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  // Add local state to conditionally display PasswordRequirements
  const [showRequirements, setShowRequirements] = useState(false);

  useEffect(() => {
    if (userId) {
      localStorage.setItem('userId', userId);
      navigate('/profile');
    }
  }, [userId, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();

    // 1) client-side checks
    let allErrors = [];
    allErrors.push(...validateUsername(username));
    allErrors.push(...validateEmail(email));
    allErrors.push(...validatePassword(password, username, email));
    if (password !== confirmPassword) {
      allErrors.push("Passwords do not match.");
    }

    if (allErrors.length > 0) {
      allErrors.forEach((errMsg) => {
        toast.error(errMsg, { className: 'auth-error-toast' });
      });
      return;
    }

    // 2) If passes, attempt registration
    try {
      const result = await dispatch(
        registerUser({ username, email, password, confirmPassword })
      );

      if (registerUser.fulfilled.match(result)) {
        toast.success("Registration successful!", { className: 'auth-success-toast' });

        // Optionally auto-login
        const loginRes = await dispatch(loginUser({ usernameOrEmail: username, password }));
        if (loginUser.fulfilled.match(loginRes)) {
          toast.success("Auto-login successful!", { className: 'auth-success-toast' });
        } else {
          toast.error("Auto-login failed. Please log in manually.", { className: 'auth-error-toast' });
        }
      } else {
        const payload = result.payload || "Server error occurred.";
        toast.error(payload, { className: 'auth-error-toast' });
      }
    } catch (err) {
      console.error('Registration error:', err);
      toast.error("An unexpected error occurred.", { className: 'auth-error-toast' });
    }
  };

  return (
    <div className="register-container">
      <Link to="/" className="back-to-info">Back to Info Page</Link>
      <div className="register-card">
        <h2 className="register-title">Create Your Account</h2>

        {error && <p className="error-msg">{error}</p>}

        <form className="register-form" onSubmit={handleSubmit}>
          <label htmlFor="username">Username</label>
          <input 
            id="username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />

          <label htmlFor="email">Email</label>
          <input 
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />

          <label htmlFor="password">Password</label>
          <div className="input-with-icon">
            <input 
              id="password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onFocus={() => setShowRequirements(true)}
              onBlur={() => {
                // If user leaves password field & hasn't typed anything, hide
                if (!password) {
                  setShowRequirements(false);
                }
              }}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <span
              className="eye-icon"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? <FaEyeSlash /> : <FaEye />}
            </span>
          </div>

          {/* Conditionally show the PasswordRequirements only if user focuses or typed something */}
          {showRequirements && (
            <PasswordRequirements password={password} />
          )}

          <label htmlFor="confirmPassword">Confirm Password</label>
          <div className="input-with-icon">
            <input 
              id="confirmPassword"
              type={showConfirmPassword ? 'text' : 'password'}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
            <span
              className="eye-icon"
              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
            >
              {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
            </span>
          </div>

          <button 
            type="submit"
            disabled={loading}
            className="register-btn"
          >
            {loading ? 'Registering...' : 'Register'}
          </button>
        </form>

        <p className="register-switch">
          Already have an account? <Link to="/login">Login</Link>
        </p>
      </div>
    </div>
  );
};

export default Register;
