// src/components/pages/auth/Login.js
import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { loginUser } from '../store/userSlice';
import { useNavigate, Link } from 'react-router-dom';
import { FaEye, FaEyeSlash } from 'react-icons/fa';
import { toast } from 'react-toastify';

import './Login.css';
import './auth.css';
import './AuthToast.css'; // Optional custom Toastify styling

/***************************************************************
 * FRONT-END VALIDATION HELPERS
 * (Mirroring your Python logic)
 ***************************************************************/

// Example dictionary of common passwords
const COMMON_PASSWORDS = new Set([
  'password', '123456', '12345678', 'qwerty', 'letmein', 'welcome'
]);

// Private Use / Surrogates
const PRIVATE_USE_RANGES = [
  [0xE000, 0xF8FF],
  [0xF0000, 0xFFFFD],
  [0x100000, 0x10FFFD]
];
const SURROGATES_RANGE = [0xD800, 0xDFFF];

function hasForbiddenUnicode(str) {
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

// Basic check to differentiate "username" vs "email"
function validateLoginIdentifier(value) {
  const errors = [];
  const val = value.trim();
  if (!val) {
    errors.push("Username/Email cannot be empty.");
    return errors;
  }

  // If it has '@', treat as email (simplified logic)
  if (val.includes('@')) {
    // minimal checks
    if (!val.includes('.')) {
      errors.push("Email must contain '.' for domain part.");
    }
    if (val.length < 6 || val.length > 254) {
      errors.push("Email length must be 6–254 characters.");
    }
    if (hasForbiddenUnicode(val)) {
      errors.push("Email contains forbidden Unicode blocks.");
    }
  } else {
    // treat as username
    if (val.length < 3 || val.length > 30) {
      errors.push("Username must be 3–30 characters.");
    }
    if (hasForbiddenUnicode(val)) {
      errors.push("Username contains forbidden Unicode blocks.");
    }
  }
  return errors;
}

function validatePassword(pwd) {
  const errors = [];
  if (!pwd) {
    errors.push("Password cannot be empty.");
    return errors;
  }
  if (pwd.length < 6) {
    errors.push("Password must be at least 6 characters.");
  }
  // Checking if too common
  if (COMMON_PASSWORDS.has(pwd.toLowerCase())) {
    errors.push("Password is too common. Please choose a stronger one.");
  }
  return errors;
}

/***************************************************************
 * LOGIN COMPONENT
 ***************************************************************/
const Login = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { loading, error, userId } = useSelector((state) => state.user);

  const [usernameOrEmail, setUsernameOrEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // If user is already logged in, redirect
  useEffect(() => {
    if (userId) {
      localStorage.setItem('userId', userId);
      navigate('/profile');
    }
  }, [userId, navigate]);

  const handleSubmit = (e) => {
    e.preventDefault();

    // 1) Client-side checks
    const errors = [];
    errors.push(...validateLoginIdentifier(usernameOrEmail));
    errors.push(...validatePassword(password));

    if (errors.length > 0) {
      errors.forEach((err) => {
        toast.error(err, { className: 'auth-error-toast' });
      });
      return;
    }

    // 2) If passes, attempt login
    dispatch(loginUser({ usernameOrEmail, password }))
      .unwrap()
      .then(() => {
        toast.success("Login successful!", { className: 'auth-success-toast' });
      })
      .catch((errMsg) => {
        // If server rejects, errMsg is from userSlice or backend
        toast.error(errMsg, { className: 'auth-error-toast' });
      });
  };

  return (
    <div className="login-container">
      <Link to="/" className="back-to-info">Back to Info Page</Link>
      <div className="login-card">
        <h2 className="login-title">Welcome Back</h2>

        {/* If Redux error, optional inline */}
        {error && <p className="error-msg">{error}</p>}

        <form className="login-form" onSubmit={handleSubmit}>
          <label htmlFor="usernameOrEmail">Username or Email</label>
          <input 
            id="usernameOrEmail"
            type="text"
            value={usernameOrEmail}
            onChange={(e) => setUsernameOrEmail(e.target.value)}
            required
          />

          <label htmlFor="password">Password</label>
          <div className="input-with-icon">
            <input 
              id="password"
              type={showPassword ? 'text' : 'password'}
              value={password}
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

          <button 
            type="submit" 
            className="login-btn"
            disabled={loading}
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>

        <p className="login-forgot">
          <Link to="/forgot-password">Forgot Password?</Link>
        </p>
        <p className="login-switch">
          Don't have an account? <Link to="/register">Register</Link>
        </p>
      </div>
    </div>
  );
};

export default Login;
