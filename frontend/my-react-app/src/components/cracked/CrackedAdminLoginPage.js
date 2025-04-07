import React, { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { 
  FaLock, FaGoogle, FaShieldAlt, FaKey, FaUserSecret, FaEye, FaEyeSlash, 
  FaExclamationCircle, FaLaptopCode, FaChess, FaSpider, FaFighterJet, 
  FaCoffee, FaRobot, FaUserAstronaut, FaServer, FaDatabase, FaSatellite,
  FaRedhat, FaKeyboard, FaFingerprint, FaLockOpen, FaNetworkWired
} from "react-icons/fa";
import "./styles/CrackedAdminLogin.css";


import captchaImage1 from './images/image1.jpg';
import captchaImage2 from './images/image2.jpg';
import captchaImage3 from './images/image3.jpg';
import captchaImage4 from './images/image4.jpg';
import captchaImage5 from './images/image5.jpg';
import captchaImage6 from './images/image6.jpg';
import captchaImage7 from './images/image7.jpg';
import captchaImage8 from './images/image8.jpg';
import captchaImage9 from './images/image9.jpg';

import elevatorMusic from './music/elevator-music.mp3';


const loadingMessages = [
  "Establishing Secure Connection...",
  "Verifying Quantum Entanglement...",
  "Reticulating Splines...",
  "Injecting Security Hamsters...",
  "Warming Up The Flux Capacitor...",
  "Downloading More RAM...",
  "Charging Defensive Lasers...",
  "Reinventing The Wheel...",
  "Emulating Human Emotions...",
  "Generating Excessive Jargon...",
  "Accelerating Cyber Particles...",
  "Converting Coffee To Code...",
  "Calculating Pi To Final Digit...",
  "Encrypting Your Thoughts...",
  "Decrypting Admin Consciousness...",
  "Searching For Lost Semicolons...",
  "Mining For Security Tokens...",
  "Brewing Authentication Potion...",
  "Unleashing The Cyber Kraken...",
  "Performing Virtual Rituals...",
  "Validating Your Life Choices...",
  "Upgrading Blockchain Hamsters...",
  "Initializing NSA Backdoor...",
  "Contacting Elder Gods For Verification...",
];

// Array of ridiculous username suggestions
const usernameSuggestions = [
  "DefinitelyNotAdmin",
  "PasswordIsPassword",
  "MrSnuggles",
  "TheRealBoss",
  "HackerSlayer9000",
  "AdminMcAdminFace",
  "TotallyLegitUser",
  "NotASuspiciousLogin",
  "CEO_Undercover",
  "SuperSecretAgent",
  "BobFromAccounting",
  "1337_h4x0r",
  "HoneyPotInspector",
  "SQLInjectorExpert",
  "ImNotWearingPants",
  "IForgotMyPassword",
];

// Password strength feedback messages
const strengthFeedback = [
  "Weaker than wet toilet paper",
  "A toddler could crack this",
  "Is that even a password?",
  "My grandmother uses stronger passwords",
  "Dangerously Spicy!",
  "Quantum computers are laughing",
  "Barely better than '12345'",
  "Wow, Very Secure, Much Complex",
  "Fort Knox level (if Knox was made of paper)",
  "NSA has entered the chat",
];

// Impossible CAPTCHA challenges
const impossibleCaptchas = [
  "Select all images containing existential dread",
  "Type the sound a dial-up modem makes",
  "Draw a perfect circle using only your keyboard",
  "Identify which images contain birds that can't fly",
  "Click on all pixels that represent prime numbers",
  "Type the 42nd digit of pi without looking it up",
  "Select all images where someone is thinking about cheese",
  "Describe the color blue to a colorblind AI",
  "Count the number of security vulnerabilities in this page",
  "Type your password backwards while standing on one foot",
];

function CrackedAdminLoginPage() {
  const navigate = useNavigate();
  
  // Regular login state
  const [adminKey, setAdminKey] = useState("");
  const [role, setRole] = useState("basic");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [oauthLoading, setOauthLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);
  const [showEasterEgg, setShowEasterEgg] = useState(false);
  
  // Honeypot features
  const [showDramaticLoading, setShowDramaticLoading] = useState(true);
  const [currentLoadingMessage, setCurrentLoadingMessage] = useState(0);
  const [showRealLoginForm, setShowRealLoginForm] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState("");
  const [showImpossibleCaptcha, setShowImpossibleCaptcha] = useState(false);
  const [currentCaptcha, setCurrentCaptcha] = useState("");
  const [captchaInput, setCaptchaInput] = useState("");
  const [activeCSSTheme, setActiveCSSTheme] = useState(0);
  
  // References
  const audioRef = useRef(null);
  const secretButtonRef = useRef(null);
  
  // Easter egg messages
  useEffect(() => {
    if (loginAttempts >= 3) {
      setShowEasterEgg(true);
    }
  }, [loginAttempts]);
  
  // Dramatic loading message cycle
  useEffect(() => {
    if (showDramaticLoading) {
      const interval = setInterval(() => {
        setCurrentLoadingMessage(prev => (prev + 1) % loadingMessages.length);
      }, 4000);
      
      return () => clearInterval(interval);
    }
  }, [showDramaticLoading]);
  
  // Randomly change CSS theme every 20 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      setActiveCSSTheme(Math.floor(Math.random() * 4)); // 0-3 for different themes
    }, 20000);
    
    return () => clearInterval(interval);
  }, []);
  
  // Start playing muzak on component mount
  useEffect(() => {
    if (audioRef.current) {
      audioRef.current.volume = 0.2;
      audioRef.current.play().catch(e => {
        // Auto-play blocked by browser, that's okay
        console.log("Audio autoplay blocked by browser. User needs to interact first.");
      });
    }
    
    // Set a random initial CSS theme
    setActiveCSSTheme(Math.floor(Math.random() * 4));
    
    // Set initial CAPTCHA
    setCurrentCaptcha(impossibleCaptchas[Math.floor(Math.random() * impossibleCaptchas.length)]);
    
  }, []);
  
  // Handle real login submission (this is the actual functionality)
  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await fetch("/api/cracked/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminKey, role }),
        credentials: "include",
      });

      const data = await response.json();
      if (!response.ok) {
        setLoginAttempts(prev => prev + 1);
        setError(data.error || "Unable to log in");
      } else {
        // On success, navigate to the admin dashboard
        navigate("/cracked/dashboard");
      }
    } catch (err) {
      console.error("Admin login error:", err);
      setLoginAttempts(prev => prev + 1);
      setError("Network error or server unavailable");
    } finally {
      setLoading(false);
    }
  };

  // Handle Google OAuth (this is the actual functionality)
  const handleGoogleLogin = () => {
    setOauthLoading(true);
    setError(null);
    // Redirect to Google OAuth for admin
    window.location.href = "/api/oauth/admin-login/google";
  };
  
  // NEW: Separate handler for the loading screen close button - shows FAKE login
  const handleLoadingClose = () => {
    setShowDramaticLoading(false);
    setShowRealLoginForm(false); // Show FAKE login form
    
    // Try to play the audio again after user interaction
    if (audioRef.current) {
      audioRef.current.play().catch(e => console.log("Audio still blocked"));
    }
  };
  
  // For tracking if the "speed up" button was clicked
  const [speedUpClicked, setSpeedUpClicked] = useState(false);
  
  // Secret handler to show REAL login (used by coffee icon)
  const handleSecretClose = () => {
    setShowDramaticLoading(false);
    setShowRealLoginForm(true); // Show REAL login form
    
    // Try to play the audio again after user interaction
    if (audioRef.current) {
      audioRef.current.play().catch(e => console.log("Audio still blocked"));
    }
  };
  
  // Fake password strength meter
  const updatePasswordStrength = (password) => {
    setAdminKey(password);
    
    if (password.length > 0) {
      const randomIndex = Math.floor(password.length % strengthFeedback.length);
      setPasswordStrength(strengthFeedback[randomIndex]);
    } else {
      setPasswordStrength("");
    }
  };
  
  // Fake form submission that shows CAPTCHA
  const handleFakeSubmit = (e) => {
    e.preventDefault();
    setShowImpossibleCaptcha(true);
    setCurrentCaptcha(impossibleCaptchas[Math.floor(Math.random() * impossibleCaptchas.length)]);
  };
  
  // Get current CSS theme class
  const getThemeClass = () => {
    const themes = ["default-theme", "neon-theme", "corporate-theme", "retro-theme"];
    return themes[activeCSSTheme];
  };
  
  return (
    <div className={`cracked-admin-login-wrapper ${getThemeClass()}`}>
      {/* Background audio */}
      <audio ref={audioRef} loop>
        <source src={elevatorMusic} type="audio/mpeg" />
        Your browser does not support the audio element.
      </audio>
      
      {/* Dramatic loading overlay */}
      {showDramaticLoading && (
        <div className="dramatic-loading-overlay">
          <div className="loading-content">
            <div className="loading-spinner"></div>
            <h2 className="loading-message">{loadingMessages[currentLoadingMessage]}</h2>
            <div className="loading-progress">
              <div className="loading-bar"></div>
            </div>
            
            {/* "Speed up loading" button that just triggers audio */}
            <button 
              className="speed-up-button"
              onClick={() => {
                setSpeedUpClicked(true);
                if (audioRef.current) {
                  audioRef.current.play().catch(e => console.log("Audio still blocked"));
                }
              }}
              disabled={speedUpClicked}
            >
              {speedUpClicked ? "Optimization in Progress..." : "Speed Up Loading Process"}
            </button>
            
            {/* Hidden close button in bottom right corner - CHANGED to use handleLoadingClose */}
            <button 
              ref={secretButtonRef}
              className="secret-close-button" 
              onClick={handleLoadingClose}
              aria-label="Close loading screen"
            />
          </div>
        </div>
      )}
      
      <div className="cracked-admin-login-container">
        <div className="admin-login-background">
          <div className="admin-login-grid"></div>
          <div className="admin-login-particles">
            {[...Array(15)].map((_, i) => (
              <div key={i} className="admin-login-particle"></div>
            ))}
          </div>
        </div>

        {/* Fake login card */}
        {!showRealLoginForm && !showDramaticLoading && (
          <div className="cracked-admin-login-card fake-card">
            <div className="admin-login-logo">
              <FaUserSecret className="admin-login-logo-icon" />
            </div>
            <h1 className="cracked-admin-login-title wobble-text">Admin Access</h1>
            <p className="admin-login-subtitle blink-text">
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
                <p>👾 Nice try! But this isn't where you upload SQL injections...</p>
                <p>Maybe try "hunter2" as the password? Everyone knows that works!</p>
              </div>
            )}

            {showImpossibleCaptcha ? (
              <div className="impossible-captcha">
                <h3>Please verify you are human</h3>
                <div className="captcha-challenge">
                  <p>{currentCaptcha}</p>
                  <div className="captcha-images">
                    {[
                      captchaImage1,
                      captchaImage2,
                      captchaImage3,
                      captchaImage4,
                      captchaImage5,
                      captchaImage6,
                      captchaImage7,
                      captchaImage8,
                      captchaImage9
                    ].map((image, i) => (
                      <div key={i} className="captcha-image">
                        <img src={image} alt={`Captcha image ${i+1}`} />
                      </div>
                    ))}
                  </div>
                  <input
                    type="text"
                    value={captchaInput}
                    onChange={(e) => setCaptchaInput(e.target.value)}
                    placeholder="Enter your answer..."
                    className="wobble-input"
                  />
                  <button 
                    className="captcha-submit-button"
                    onClick={() => {
                      setCaptchaInput("");
                      setCurrentCaptcha(impossibleCaptchas[Math.floor(Math.random() * impossibleCaptchas.length)]);
                    }}
                  >
                    Verify
                  </button>
                </div>
              </div>
            ) : (
              <form className="cracked-admin-login-form" onSubmit={handleFakeSubmit}>
                <div className="admin-input-row">
                  <label htmlFor="fakeUsername">
                    <FaKey className="admin-input-icon" /> Username:
                  </label>
                  <div className="admin-password-wrapper">
                    <input
                      type="text"
                      id="fakeUsername"
                      list="usernameSuggestions"
                      placeholder="Enter admin username"
                      className="wobble-input"
                    />
                    <datalist id="usernameSuggestions">
                      {usernameSuggestions.map((suggestion, index) => (
                        <option key={index} value={suggestion} />
                      ))}
                    </datalist>
                  </div>
                </div>

                <div className="admin-input-row">
                  <label htmlFor="fakePassword">
                    <FaLock className="admin-input-icon" /> Password:
                  </label>
                  <div className="admin-password-wrapper">
                    <input
                      type={showPassword ? "text" : "password"}
                      id="fakePassword"
                      placeholder="Enter admin password"
                      className="wobble-input"
                      onChange={(e) => updatePasswordStrength(e.target.value)}
                    />
                    <button 
                      type="button" 
                      className="admin-toggle-password"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? <FaEyeSlash /> : <FaEye />}
                    </button>
                  </div>
                  
                  {passwordStrength && (
                    <div className="password-strength">
                      <div className="strength-meter">
                        <div 
                          className="strength-meter-fill" 
                          style={{ width: `${Math.random() * 100}%`, transition: 'width 0.3s ease-in-out' }}
                        ></div>
                      </div>
                      <span className="strength-text">{passwordStrength}</span>
                    </div>
                  )}
                </div>

                <div className="admin-login-buttons">
                  <button
                    type="submit"
                    className="cracked-admin-login-button wobble-button"
                  >
                    <FaLock /> Access Mainframe
                  </button>
                </div>
              </form>
            )}
          </div>
        )}
        
        {/* Real login card (hidden by default) */}
        {showRealLoginForm && !showDramaticLoading && (
          <div className="cracked-admin-login-card real-card">
            <div className="admin-login-logo">
              <FaUserSecret className="admin-login-logo-icon" />
            </div>
            <h1 className="cracked-admin-login-title">Secure Admin Access</h1>
            <p className="admin-login-subtitle">
              Welcome back
            </p>

            {error && (
              <div className="admin-error-message">
                <FaExclamationCircle />
                <span>{error}</span>
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
          </div>
        )}
        
        {/* Random icons that hide real login functionality */}
        <div className="random-icons-container">
          <FaChess className="random-icon" />
          <FaSpider className="random-icon" />
          <FaFighterJet className="random-icon" />
          <FaCoffee className="random-icon" onClick={handleSecretClose} /> {/* This one reveals the real login */}
          <FaRobot className="random-icon" />
          <FaUserAstronaut className="random-icon" />
          <FaServer className="random-icon" />
          <FaDatabase className="random-icon" />
          <FaSatellite className="random-icon" />
          <FaRedhat className="random-icon" />
          <FaKeyboard className="random-icon" />
          <FaFingerprint className="random-icon" onClick={handleGoogleLogin} /> {/* This one triggers Google login */}
          <FaLockOpen className="random-icon" />
          <FaNetworkWired className="random-icon" />
        </div>
      </div>
    </div>
  );
}

export default CrackedAdminLoginPage;
