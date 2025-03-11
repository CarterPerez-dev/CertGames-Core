// src/components/pages/store/DailyStationPage.js
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { claimDailyBonus, setXPAndCoins, fetchUserData } from './userSlice';
import './DailyStation.css';

// Icon imports
import {
  FaCoins,
  FaStar,
  FaTrophy,
  FaCalendarCheck,
  FaHourglassHalf,
  FaCheckCircle,
  FaTimesCircle,
  FaLightbulb,
  FaChevronRight,
  FaSyncAlt,
  FaGift
} from 'react-icons/fa';

// Helper to format seconds as HH:MM:SS
function formatCountdown(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return [h, m, s].map((x) => String(x).padStart(2, '0')).join(':');
}

const DailyStationPage = () => {
  const dispatch = useDispatch();
  const { userId, username, coins, xp, lastDailyClaim, loading: userLoading } = useSelector((state) => state.user);

  // Local states
  const [bonusError, setBonusError] = useState(null);
  const [bonusSuccess, setBonusSuccess] = useState(false);
  const [loadingBonus, setLoadingBonus] = useState(false);
  const [canClaim, setCanClaim] = useState(false);
  const [bonusCountdown, setBonusCountdown] = useState(0);
  const [localLastDailyClaim, setLocalLastDailyClaim] = useState(lastDailyClaim);

  const [loadingQ, setLoadingQ] = useState(true);
  const [qError, setQError] = useState(null);
  const [questionData, setQuestionData] = useState(null);
  const [selectedAnswer, setSelectedAnswer] = useState(null);
  const [submitResult, setSubmitResult] = useState(null);

  const [questionCountdown, setQuestionCountdown] = useState(0);

  // Animations
  const [showBonusAnimation, setShowBonusAnimation] = useState(false);
  const [showCorrectAnimation, setShowCorrectAnimation] = useState(false);
  const [showWrongAnimation, setShowWrongAnimation] = useState(false);

  // Sync local lastDailyClaim whenever Redux store changes
  useEffect(() => {
    if (lastDailyClaim) {
      setLocalLastDailyClaim(lastDailyClaim);
    }
  }, [lastDailyClaim]);

  // Check if user can claim bonus on initial load
  useEffect(() => {
    if (!localLastDailyClaim) {
      setCanClaim(true);
    } else {
      const lastClaimTime = new Date(localLastDailyClaim).getTime();
      const now = Date.now();
      const diff = lastClaimTime + 24 * 3600 * 1000 - now; // 24h window
      if (diff <= 0) {
        setCanClaim(true);
      } else {
        setCanClaim(false);
        setBonusCountdown(Math.floor(diff / 1000));
      }
    }
  }, [localLastDailyClaim]);

  // Bonus countdown logic (runs every second)
  useEffect(() => {
    if (!localLastDailyClaim) {
      // If we have no known claim, show "canClaim" right away
      setBonusCountdown(0);
      setCanClaim(true);
      return;
    }

    const lastClaimTime = new Date(localLastDailyClaim).getTime();
    
    function tickBonus() {
      const now = Date.now();
      const diff = lastClaimTime + 24 * 3600 * 1000 - now; // 24h window
      if (diff <= 0) {
        setBonusCountdown(0);
        setCanClaim(true);
      } else {
        setBonusCountdown(Math.floor(diff / 1000));
        setCanClaim(false);
      }
    }
    
    tickBonus(); // Run immediately
    const bonusInterval = setInterval(tickBonus, 1000);
    return () => clearInterval(bonusInterval);
  }, [localLastDailyClaim]);

  // Daily question refresh countdown logic (resets at midnight UTC)
  useEffect(() => {
    function tickQuestion() {
      const now = new Date();
      const nextMidnightUTC = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
      const diff = Math.floor((nextMidnightUTC - now) / 1000);
      setQuestionCountdown(diff);
    }
    
    tickQuestion(); // Run immediately
    const questionInterval = setInterval(tickQuestion, 1000);
    return () => clearInterval(questionInterval);
  }, []);

  // Fetch daily question if user is logged in
  useEffect(() => {
    if (userId) {
      fetchDailyQuestion();
    } else {
      setLoadingQ(false);
    }
  }, [userId]);

  // Claim daily bonus
  const handleClaimDailyBonus = async () => {
    if (!userId) {
      setBonusError('Please log in first.');
      return;
    }
    
    setLoadingBonus(true);
    setBonusError(null);
    
    try {
      const res = await fetch(`/api/test/user/${userId}/daily-bonus`, {
        method: 'POST'
      });
      const data = await res.json();
      
      if (!res.ok) {
        // Hard error, e.g. 404 user not found
        setBonusError(data.error || 'Error claiming daily bonus');
        setLoadingBonus(false);
        return;
      }
      
      if (data.success) {
        // Claimed successfully
        setShowBonusAnimation(true);
        setTimeout(() => setShowBonusAnimation(false), 3000);
        setBonusSuccess(true);
        
        // Update state immediately to show countdown
        const now = new Date();
        setLocalLastDailyClaim(now.toISOString());
        setCanClaim(false);
        setBonusCountdown(86400); // Initialize with 24 hours in seconds
        
        // Refresh user data to update coins/xp
        dispatch(fetchUserData(userId));
      } else {
        // Already claimed case
        setBonusError(data.message);
        
        // Parse seconds left from message if available
        const match = data.message && data.message.match(/(\d+)/);
        if (match) {
          const secondsLeft = parseInt(match[1], 10);
          if (!isNaN(secondsLeft) && secondsLeft > 0) {
            // Calculate the last claim time based on seconds left
            const nowMs = Date.now();
            const msLeft = secondsLeft * 1000;
            const lastClaimTime = nowMs - (86400000 - msLeft);
            setLocalLastDailyClaim(new Date(lastClaimTime).toISOString());
            setCanClaim(false);
            setBonusCountdown(secondsLeft); // Set countdown to exactly what the server returned
          }
        }
      }
      
      setLoadingBonus(false);
    } catch (err) {
      setBonusError('Error: ' + err.message);
      setLoadingBonus(false);
    }
  };

  // Fetch daily question
  const fetchDailyQuestion = async () => {
    setLoadingQ(true);
    setQError(null);
    
    try {
      const res = await fetch(`/api/test/daily-question?userId=${userId}`);
      const data = await res.json();
      
      if (!res.ok) {
        setQError(data.error || 'Failed to fetch daily question');
      } else {
        setQuestionData(data);
      }
      
      setLoadingQ(false);
    } catch (err) {
      setQError('Error fetching daily question: ' + err.message);
      setLoadingQ(false);
    }
  };

  // Submit daily answer
  const submitDailyAnswer = async () => {
    if (!questionData || questionData.alreadyAnswered) {
      setQError("You've already answered today's question!");
      return;
    }
    
    if (selectedAnswer === null) {
      setQError('Please select an answer first.');
      return;
    }
    
    setQError(null);
    
    try {
      const body = {
        userId,
        dayIndex: questionData.dayIndex,
        selectedIndex: selectedAnswer
      };
      
      const res = await fetch('/api/test/daily-question/answer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      
      const ansData = await res.json();
      
      if (!res.ok) {
        setQError(ansData.error || 'Error submitting answer.');
      } else {
        setSubmitResult(ansData);
        
        dispatch(
          setXPAndCoins({
            xp: ansData.newXP || xp,
            coins: ansData.newCoins || coins
          })
        );
        
        setQuestionData((prev) => ({
          ...prev,
          alreadyAnswered: true
        }));

        if (ansData.correct) {
          setShowCorrectAnimation(true);
          setTimeout(() => setShowCorrectAnimation(false), 2000);
        } else {
          setShowWrongAnimation(true);
          setTimeout(() => setShowWrongAnimation(false), 2000);
        }
      }
    } catch (err) {
      setQError('Error: ' + err.message);
    }
  };

  return (
    <div className="daily-station-container">
      {/* HEADER SECTION */}
      <div className="daily-station-header">
        <div className="daily-station-title">
          <h1>Daily Station</h1>
          <p>Claim your daily rewards and answer the challenge</p>
        </div>
        
        {userId && (
          <div className="daily-station-user-stats">
            <div className="daily-station-stat">
              <FaCoins className="daily-station-stat-icon coins" />
              <span className="daily-station-stat-value">{coins}</span>
            </div>
            <div className="daily-station-stat">
              <FaStar className="daily-station-stat-icon xp" />
              <span className="daily-station-stat-value">{xp}</span>
            </div>
          </div>
        )}
      </div>

      {/* MAIN CONTENT */}
      <div className="daily-station-content">
        {!userId ? (
          <div className="daily-station-login-required">
            <div className="daily-station-login-message">
              <FaLightbulb className="daily-station-login-icon" />
              <h2>Login Required</h2>
              <p>Please log in to claim daily rewards and participate in daily challenges.</p>
            </div>
          </div>
        ) : (
          <>
            {/* DAILY BONUS SECTION */}
            <div className="daily-station-card bonus-card">
              <div className="daily-station-card-header">
                <FaGift className="daily-station-card-icon" />
                <h2>Daily Bonus</h2>
              </div>
              
              <div className="daily-station-card-content">
                <div className="daily-station-bonus-info">
                  <div className="daily-station-bonus-value">
                    <FaCoins className="daily-station-bonus-coin-icon" />
                    <span>1000</span>
                  </div>
                  <p>Claim your free coins every 24 hours!</p>
                </div>
                
                {/* Show error if any */}
                {bonusError && !bonusError.includes("Next bonus in") && (
                  <div className="daily-station-error">
                    <p>{bonusError}</p>
                  </div>
                )}
                
                {/* Claim Button or Countdown */}
                <div className="daily-station-bonus-action">
                  {canClaim ? (
                    <button 
                      className="daily-station-claim-btn"
                      onClick={handleClaimDailyBonus}
                      disabled={loadingBonus}
                    >
                      {loadingBonus ? (
                        <>
                          <FaSyncAlt className="loading-icon" />
                          <span>Claiming...</span>
                        </>
                      ) : (
                        <>
                          <FaCoins />
                          <span>Claim Bonus</span>
                        </>
                      )}
                    </button>
                  ) : (
                    <div className="daily-station-countdown">
                      <FaHourglassHalf className="daily-station-countdown-icon" />
                      <div className="daily-station-countdown-info">
                        <span className="daily-station-countdown-label">Next bonus in:</span>
                        <span className="daily-station-countdown-time">{formatCountdown(bonusCountdown)}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
            
            {/* DAILY QUESTION SECTION */}
            <div className="daily-station-card question-card">
              <div className="daily-station-card-header">
                <FaLightbulb className="daily-station-card-icon" />
                <h2>Daily Challenge</h2>
              </div>
              
              <div className="daily-station-card-content">
                {loadingQ ? (
                  <div className="daily-station-loading">
                    <FaSyncAlt className="loading-icon" />
                    <p>Loading challenge...</p>
                  </div>
                ) : qError ? (
                  <div className="daily-station-error">
                    <p>{qError}</p>
                  </div>
                ) : !questionData ? (
                  <div className="daily-station-empty">
                    <p>No challenges available today. Check back tomorrow!</p>
                  </div>
                ) : (
                  <div className={`daily-station-question ${showCorrectAnimation ? 'correct-animation' : ''} ${showWrongAnimation ? 'wrong-animation' : ''}`}>
                    <div className="daily-station-question-prompt">
                      <p>{questionData.prompt}</p>
                    </div>
                    
                    {questionData.alreadyAnswered ? (
                      <div className="daily-station-question-answered">
                        {submitResult && (
                          <div className={`daily-station-result ${submitResult.correct ? 'correct' : 'incorrect'}`}>
                            {submitResult.correct ? (
                              <>
                                <FaCheckCircle className="daily-station-result-icon" />
                                <p>Correct! You earned {submitResult.awardedCoins} coins.</p>
                              </>
                            ) : (
                              <>
                                <FaTimesCircle className="daily-station-result-icon" />
                                <p>Not quite, but you still got {submitResult.awardedCoins} coins.</p>
                              </>
                            )}
                          </div>
                        )}
                        
                        <div className="daily-station-next-question">
                          <div className="daily-station-countdown">
                            <FaCalendarCheck className="daily-station-countdown-icon" />
                            <div className="daily-station-countdown-info">
                              <span className="daily-station-countdown-label">Next challenge in:</span>
                              <span className="daily-station-countdown-time">{formatCountdown(questionCountdown)}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="daily-station-question-options">
                        <div className="daily-station-options-list">
                          {questionData.options.map((option, index) => (
                            <label 
                              key={index} 
                              className={`daily-station-option ${selectedAnswer === index ? 'selected' : ''}`}
                            >
                              <input
                                type="radio"
                                name="dailyQuestion"
                                value={index}
                                checked={selectedAnswer === index}
                                onChange={() => setSelectedAnswer(index)}
                                className="daily-station-option-input"
                              />
                              <span className="daily-station-option-text">{option}</span>
                              {selectedAnswer === index && (
                                <FaChevronRight className="daily-station-option-indicator" />
                              )}
                            </label>
                          ))}
                        </div>
                        
                        <button 
                          className="daily-station-submit-btn"
                          onClick={submitDailyAnswer}
                          disabled={selectedAnswer === null}
                        >
                          Submit Answer
                        </button>
                        
                        <div className="daily-station-next-question">
                          <div className="daily-station-countdown">
                            <FaCalendarCheck className="daily-station-countdown-icon" />
                            <div className="daily-station-countdown-info">
                              <span className="daily-station-countdown-label">Challenge refreshes in:</span>
                              <span className="daily-station-countdown-time">{formatCountdown(questionCountdown)}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>
      
      {/* BONUS CLAIM ANIMATION OVERLAY */}
      {showBonusAnimation && (
        <div className="daily-station-overlay">
          <div className="daily-station-bonus-animation">
            <FaCoins className="daily-station-bonus-icon" />
            <div className="daily-station-bonus-text">
              <h3>Daily Bonus Claimed!</h3>
              <p>+1000 coins added to your account</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DailyStationPage;
