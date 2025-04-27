import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { FaLock, FaGoogle, FaShieldAlt, FaKey, FaUserSecret, FaEye, FaEyeSlash, FaExclamationCircle, FaLaptopCode } from "react-icons/fa";
import "./styles/CrackedAdminLogin.css";

import { adminFetch, setCsrfToken } from './csrfHelper';

function CrackedAdminLoginPage() {
  const navigate = useNavigate();


  const [adminKey, setAdminKey] = useState("");
  const [role, setRole] = useState("basic");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [oauthLoading, setOauthLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);
  const [showEasterEgg, setShowEasterEgg] = useState(false); 

  useEffect(() => {

    if (loginAttempts >= 10) {
      setShowEasterEgg(true);
    }
  }, [loginAttempts]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
  
    try {
      // First, get a CSRF token
      const tokenResponse = await fetch('/api/cracked/csrf-token', {
        credentials: 'include'
      });
      
      if (tokenResponse.ok) {
        const tokenData = await tokenResponse.json();
        setCsrfToken(tokenData.csrf_token);
      }
      
      // Now login with CSRF protection
      const response = await adminFetch('/api/cracked/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ adminKey, role })
      });
  
      const data = await response.json();
      if (!response.ok) {
        setLoginAttempts(prev => prev + 1);
        

        setError("NO, You're BANNED from Google, IP added to every blocklist EVER, and EXACT location is LOGGED 💀");
        

        console.debug("Actual error:", data.error);
      } else {
        navigate('/cracked/dashboard');
      }
    } catch (err) {
      console.error('Admin login error:', err);
      setLoginAttempts(prev => prev + 1);
      setError('Connection error. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    setOauthLoading(true);
    setError(null);
    // Redirect to Google OAuth for admin
    window.location.href = "/api/oauth/admin-login/google";
  };

  return (
    <div className="cracked-admin-login-wrapper">
      <div className="cracked-admin-login-container">
        <div className="admin-login-background">
          <div className="admin-login-grid"></div>
          <div className="admin-login-particles">
            {[...Array(15)].map((_, i) => (
              <div key={i} className="admin-login-particle"></div>
            ))}
          </div>
        </div>

        <div className="cracked-admin-login-card">
          <div className="admin-login-logo">
            <FaUserSecret className="admin-login-logo-icon" />
          </div>
          <h1 className="cracked-admin-login-title">Admin Access</h1>
          <p className="admin-login-subtitle">
            Authorized personnel only
          </p>

          {error && (
            <div className="admin-error-message">
              <FaExclamationCircle />
              <span>{error}</span>
            </div>
          )}

          {showEasterEgg && (
            <div className="admin-easter-egg">
              <p>🤮 You’re out here “hacking” like a brain-dead troll humping a router in a Wi-Fi-less void. Your dreams are in witness protection, hiding from your sorry ass. Give up, you monumental clusterfuck, before you crash the internet out of sheer stupidity!</p>
              <p>Maybe try "hunter2" as the password? Everyone knows that works!</p>
            </div>
          )}

          <form className="cracked-admin-login-form" onSubmit={handleLogin}>
            <div className="admin-input-row">
              <label htmlFor="adminKey">
                <FaKey className="admin-input-icon" /> Admin Key:
              </label>
              <div className="admin-password-wrapper">
                <input
                  type={showPassword ? "text" : "password"}
                  id="adminKey"
                  value={adminKey}
                  onChange={(e) => setAdminKey(e.target.value)}
                  placeholder="Enter admin key"
                />
                <button 
                  type="button" 
                  className="admin-toggle-password"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <FaEyeSlash /> : <FaEye />}
                </button>
              </div>
            </div>

            <div className="admin-input-row">
              <label htmlFor="role">
                <FaLaptopCode className="admin-input-icon" /> Role:
              </label>
              <select
                id="role"
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                <option value="basic">Basic</option>
                <option value="supervisor">Supervisor</option>
                <option value="superadmin">Superadmin</option>
              </select>
            </div>

            <div className="admin-login-buttons">
              <button
                type="submit"
                className="cracked-admin-login-button"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <span className="admin-spinner"></span>
                    <span>Verifying...</span>
                  </>
                ) : (
                  <>
                    <FaLock /> Login with Key
                  </>
                )}
              </button>

              <div className="admin-separator">
                <span>or</span>
              </div>

              <button
                type="button"
                className="admin-google-button"
                onClick={handleGoogleLogin}
                disabled={oauthLoading}
              >
                {oauthLoading ? (
                  <>
                    <span className="admin-spinner"></span>
                    <span>Connecting...</span>
                  </>
                ) : (
                  <>
                    <FaGoogle /> Sign in with Google
                  </>
                )}
              </button>
            </div>
          </form>

          <div className="admin-login-footer">
            <p>
              This area is restricted to authorized personnel. Unauthorized access attempts are logged.
            </p>
            <div className="admin-protected-badge">
              <FaShieldAlt /> Protected Area
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CrackedAdminLoginPage;
