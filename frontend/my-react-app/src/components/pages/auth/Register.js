import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { registerUser, loginUser } from '../store/userSlice';
import { useNavigate, Link } from 'react-router-dom';
import { FaEye, FaEyeSlash } from 'react-icons/fa';
import './Register.css';
import './auth.css';
import './AuthToast.css';

import PasswordRequirements from './PasswordRequirements';
import ErrorDisplay from './ErrorDisplay';
// ===============================
// FRONT-END VALIDATION HELPERS
// (Mirroring your Python logic)
// ===============================

// Small dictionary of very common passwords
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

// Check for private-use or surrogate blocks
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

// Disallow mixing major scripts (Latin, Greek, Cyrillic)
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

// ~~~~~~~~~~~~~~~~~~~~~~
// FRONT: Validate Username
// ~~~~~~~~~~~~~~~~~~~~~~
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

  // 3) Disallow mixing scripts
  if (disallowMixedScripts(name)) {
    errors.push("Username cannot mix multiple Unicode scripts (e.g., Latin & Cyrillic).");
  }

  // 4) Forbid control chars [0..31, 127] + suspicious punctuation
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

  // 5) Strict allowlist pattern
  if (!/^[A-Za-z0-9._-]+$/.test(name)) {
    errors.push("Username can only contain letters, digits, underscores, dashes, or dots.");
  }

  // 6) Disallow triple consecutive identical chars
  if (/(.)\1{2,}/.test(name)) {
    errors.push("Username cannot contain three identical consecutive characters.");
  }

  // 7) Disallow leading/trailing punctuation
  if (/^[._-]|[._-]$/.test(name)) {
    errors.push("Username cannot start or end with . - or _.");
  }

  return errors;
}

// ~~~~~~~~~~~~~~~~~~~~~~
// FRONT: Validate Email
// ~~~~~~~~~~~~~~~~~~~~~~
function frontValidateEmail(email) {
  const errors = [];
  const e = email.normalize("NFC").trim();

  // 1) 6..254 length
  if (e.length < 6 || e.length > 254) {
    errors.push("Email length must be between 6 and 254 characters.");
  }

  // 2) Forbidden Unicode
  if (hasForbiddenUnicodeScripts(e)) {
    errors.push("Email contains forbidden Unicode blocks (private use or surrogates).");
  }

  // 3) Forbid suspicious ASCII <, >, etc.
  const forbiddenAscii = new Set(['<','>','`',';',' ', '\t','\r','\n','"',"'", '\\']);
  for (let i = 0; i < e.length; i++) {
    if (forbiddenAscii.has(e[i])) {
      errors.push("Email contains forbidden characters like <, >, or whitespace.");
      break;
    }
  }

  // 4) Must have exactly one @
  if ((e.match(/@/g) || []).length !== 1) {
    errors.push("Email must contain exactly one '@' symbol.");
  }

  // 5) Regex check: no consecutive dots, domain parts, TLD 2..20
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

// ~~~~~~~~~~~~~~~~~~~~~~
// FRONT: Validate Password
// ~~~~~~~~~~~~~~~~~~~~~~
function frontValidatePassword(password, username, email) {
  const errors = [];
  const pwd = password;

  // 1) 12..128 length
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

  // 4) Disallow triple consecutive identical characters
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

  // 7) Disallow if password contains username or email local-part
  if (username) {
    if (lowerPwd.includes(username.toLowerCase())) {
      errors.push("Password must not contain your username.");
    }
  }
  if (email) {
    const emailLocalPart = email.split('@')[0].toLowerCase();
    if (lowerPwd.includes(emailLocalPart)) {
      errors.push("Password must not contain the local part of your email address.");
    }
  }

  return errors;
}

// ======================================
// REGISTER COMPONENT (Updated)
// ======================================
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

  useEffect(() => {
    if (userId) {
      localStorage.setItem('userId', userId);
      navigate('/profile');
    }
  }, [userId, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();

    // 1) Client-side validation
    let errors = [];
    errors.push(...validateUsername(username));
    errors.push(...validateEmail(email));
    errors.push(...validatePassword(password, username, email));
    if (password !== confirmPassword) {
      errors.push("Passwords do not match.");
    }

    if (errors.length > 0) {
      // Show each error as a toast
      errors.forEach((errMsg) => {
        toast.error(errMsg, { className: 'auth-error-toast' });
      });
      return;
    }

    // 2) Attempt registration
    try {
      const result = await dispatch(registerUser({ 
        username, 
        email, 
        password, 
        confirmPassword
      }));

      if (registerUser.fulfilled.match(result)) {
        // Registration success
        toast.success("Registration successful!", { className: 'auth-success-toast' });

        // Optionally auto-login
        const loginRes = await dispatch(loginUser({ usernameOrEmail: username, password }));
        if (loginUser.fulfilled.match(loginRes)) {
          toast.success("Auto-login successful!", { className: 'auth-success-toast' });
        } else {
          toast.error("Auto-login failed. Please log in manually.", { className: 'auth-error-toast' });
        }
      } else {
        // If server responded with an error
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

        {/* If there's a redux error, show it inline or as a toast */}
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
