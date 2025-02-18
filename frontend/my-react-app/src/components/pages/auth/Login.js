import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { loginUser } from '../store/userSlice';
import { useNavigate, Link } from 'react-router-dom';
import { FaEye, FaEyeSlash } from 'react-icons/fa';
import { toast } from 'react-toastify';
import './Login.css';
import './auth.css';
import './AuthToast.css';

import PasswordRequirements from './PasswordRequirements';
import ErrorDisplay from './ErrorDisplay';
// ==================================================
// FRONT-END VALIDATION HELPERS
// (Mirroring your Python logic, same as Register)
// ==================================================

// Example dictionary of common passwords
const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "qwerty", "letmein", "welcome"
]);

// Private Use / Surrogates (approx in JS)
const PRIVATE_USE_RANGES = [
  [0xE000, 0xF8FF],
  [0xF0000, 0xFFFFD],
  [0x100000, 0x10FFFD]
];
const SURROGATES_RANGE = [0xD800, 0xDFFF];

// Check for private-use or surrogate blocks
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

// Disallow mixing major scripts (Latin, Greek, Cyrillic)
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

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Validate Username (front-end)
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
function frontValidateUsername(username) {
  const errors = [];
  const name = username.normalize("NFC");

  // 1) Length 3..30
  if (name.length < 3 || name.length > 30) {
    errors.push("Username must be between 3 and 30 characters long.");
  }

  // 2) Forbidden Unicode
  if (hasForbiddenUnicodeScripts(name)) {
    errors.push("Username contains forbidden Unicode blocks (private use or surrogates).");
  }

  // 3) Disallow mixed scripts
  if (disallowMixedScripts(name)) {
    errors.push("Username cannot mix multiple Unicode scripts (e.g., Latin & Cyrillic).");
  }

  // 4) Control chars + suspicious punctuation
  const forbiddenRanges = [[0, 31], [127, 127]];
  const forbiddenChars = new Set(['<', '>', '\\', '/', '"', "'", ';', '`', ' ', '\t', '\r', '\n']);
  for (let i = 0; i < name.length; i++) {
    const cp = name.charCodeAt(i);
    if (forbiddenRanges.some(([start, end]) => cp >= start && cp <= end)) {
      errors.push("Username contains forbidden control characters (ASCII 0-31 or 127).");
      break;
    }
    if (forbiddenChars.has(name[i])) {
      errors.push("Username contains forbidden characters like <, >, or whitespace.");
      break;
    }
  }

  // 5) Strict allowlist
  if (!/^[A-Za-z0-9._-]+$/.test(name)) {
    errors.push("Username can only contain letters, digits, underscores, dashes, or dots.");
  }

  // 6) Triple consecutive identical chars
  if (/(.)\1{2,}/.test(name)) {
    errors.push("Username cannot contain three identical consecutive characters.");
  }

  // 7) Leading/trailing punctuation
  if (/^[._-]|[._-]$/.test(name)) {
    errors.push("Username cannot start or end with . - or _.");
  }

  return errors;
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Validate Email (front-end)
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
function frontValidateEmail(email) {
  const errors = [];
  const e = email.normalize("NFC").trim();

  // 1) 6..254
  if (e.length < 6 || e.length > 254) {
    errors.push("Email length must be between 6 and 254 characters.");
  }

  // 2) Forbidden Unicode
  if (hasForbiddenUnicodeScripts(e)) {
    errors.push("Email contains forbidden Unicode blocks (private use or surrogates).");
  }

  // 3) Forbid suspicious ASCII
  const forbiddenAscii = new Set(['<','>','`',';',' ', '\t','\r','\n','"',"'", '\\']);
  for (let i = 0; i < e.length; i++) {
    if (forbiddenAscii.has(e[i])) {
      errors.push("Email contains forbidden characters like <, >, or whitespace.");
      break;
    }
  }

  // 4) Exactly one @
  if ((e.match(/@/g) || []).length !== 1) {
    errors.push("Email must contain exactly one '@' symbol.");
  }

  // 5) No consecutive dots, domain subparts, TLD 2..20
  const emailPattern = new RegExp(
    '^(?!.*\\.\\.)' +
    '([A-Za-z0-9._%+\\-]{1,64})' +
    '@' +
    '([A-Za-z0-9\\-]{1,63}(\\.[A-Za-z0-9\\-]{1,63})+)' +
    '\\.[A-Za-z]{2,20}$'
  );
  if (!emailPattern.test(e)) {
    errors.push("Email format is invalid (check local part, domain, consecutive dots, or TLD length).");
  }

  // 6) Disallow punycode domain
  if (e.includes('@')) {
    const domainPart = e.split('@')[1].toLowerCase();
    if (domainPart.startsWith("xn--")) {
      errors.push("Email domain uses punycode (xn--), which is not allowed in this system.");
    }
  }

  return errors;
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Validate Password (front-end)
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
function frontValidatePassword(password) {
  const errors = [];
  const pwd = password;

  // 1) 12..128
  if (pwd.length < 12 || pwd.length > 128) {
    errors.push("Password must be between 12 and 128 characters long.");
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

  // 4) Triple consecutive identical
  if (/(.)\1{2,}/.test(pwd)) {
    errors.push("Password must not contain three identical consecutive characters.");
  }

  // 5) Common password check
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

  // For login, we typically don’t block if the password has the username or email local part, 
  // but you can add that check if you prefer.  
  // (frontValidatePassword could accept a username/email param, just like in Register.)

  return errors;
}

// ===================================
// LOGIN COMPONENT (Updated)
// ===================================
const Login = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { loading, error, userId } = useSelector((state) => state.user);

  const [usernameOrEmail, setUsernameOrEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

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
      // Show them in a Toast (or you can do an inline display)
      errors.forEach((err) => toast.error(err));
      return;
    }

    // 2) If passes, dispatch login
    dispatch(loginUser({ usernameOrEmail, password }))
      .unwrap() // to handle the promise result
      .then(() => {
        toast.success("Login successful!");
      })
      .catch((errMsg) => {
        // If server rejects, errMsg is from the backend or userSlice
        toast.error(errMsg);
      });
  };

  return (
    <div className="login-container">
      <Link to="/" className="back-to-info">Back to Info Page</Link>
      <div className="login-card">
        <h2 className="login-title">Welcome Back</h2>

        {/* Show any server-side error inline if you prefer */}
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

          <button type="submit" className="login-btn" disabled={loading}>
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
