import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { loginUser } from '../store/userSlice';
import { useNavigate, Link } from 'react-router-dom';
import { FaEye, FaEyeSlash } from 'react-icons/fa';
import './Login.css';
import './auth.css';

function hasSpacesOrInvalidChars(str) {
  if (/\s/.test(str)) return true;
  if (/[<>]/.test(str)) return true;
  return false;
}

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
    if (hasSpacesOrInvalidChars(usernameOrEmail)) {
      alert('Username/Email cannot contain spaces or < >');
      return;
    }
    if (hasSpacesOrInvalidChars(password)) {
      alert('Password cannot contain spaces or < >');
      return;
    }
    dispatch(loginUser({ usernameOrEmail, password }));
  };

  return (
    <div className="login-container">
      <Link to="/" className="back-to-info">Back to Info Page</Link>
      <div className="login-card">
        <h2 className="login-title">Welcome Back</h2>
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

          {error && <p className="error-msg">{error}</p>}

          <button type="submit" disabled={loading} className="login-btn">
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
