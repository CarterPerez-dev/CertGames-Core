// src/components/pages/store/DailyStationPage.js
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { setXPAndCoins, fetchUserData } from './userSlice';
import './DailyStation.css'; // Updated CSS import

// Helper to format seconds as HH:MM:SS
function formatCountdown(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return [h, m, s].map((x) => String(x).padStart(2, '0')).join(':');
}

const DailyStationPage = () => {
  const dispatch = useDispatch();
  const { userId, username, coins, xp, lastDailyClaim } = useSelector((state) => state.user);

  // Local states
  const [bonusError, setBonusError] = useState(null);
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
    setLocalLastDailyClaim(lastDailyClaim);
  }, [lastDailyClaim]);

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
    tickBonus();
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
    tickQuestion();
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

  // Claim daily bonus (direct fetch, not a thunk)
  async function claimDailyBonus() {
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
      setLoadingBonus(false);

      if (!res.ok) {
        // Hard error, e.g. 404 user not found
        setBonusError(data.error || 'Error claiming daily bonus');
        return;
      }

      if (data.success) {
        // Claimed for the first time or after 24h
        setShowBonusAnimation(true);
        setTimeout(() => setShowBonusAnimation(false), 3000);

        // Mark localLastDailyClaim as "now" so the countdown begins
        setLocalLastDailyClaim(new Date().toISOString());
        dispatch(fetchUserData(userId)); // refresh coins/xp
      } else {
        // "Already claimed" case => parse how many seconds left from data.message if you want
        // e.g. "Already claimed. Next bonus in: 51085 seconds"
        // We'll do a quick check to see if there's a number
        const match = data.message && data.message.match(/(\d+)/);
        if (match) {
          const secondsLeft = parseInt(match[1], 10);
          if (!isNaN(secondsLeft) && secondsLeft > 0) {
            // We'll artificially set lastDailyClaim so the local effect sees we have "secondsLeft"
            const nowMs = Date.now();
            const msLeft = secondsLeft * 1000;
            // So lastClaimTime = now - (24h - msLeft)
            const lastClaimTime = nowMs - (86400000 - msLeft);
            setLocalLastDailyClaim(new Date(lastClaimTime).toISOString());
          }
        }
        // Optionally set a small note, but not an "error" that kills the countdown UI
        // We can store it in bonusError if we want a small text note:
        setBonusError(data.message);
      }
    } catch (err) {
      setBonusError('Error: ' + err.message);
      setLoadingBonus(false);
    }
  }

  // Fetch daily question
  async function fetchDailyQuestion() {
    setLoadingQ(true);
    setQError(null);
    try {
      const res = await fetch(`/api/test/daily-question?userId=${userId}`);
      const data = await res.json();
      setLoadingQ(false);
      if (!res.ok) {
        setQError(data.error || 'Failed to fetch daily question');
      } else {
        setQuestionData(data);
      }
    } catch (err) {
      setLoadingQ(false);
      setQError('Error fetching daily question: ' + err.message);
    }
  }

  // Submit daily answer
  async function submitDailyAnswer() {
    if (!questionData || questionData.alreadyAnswered) {
      setQError("You've already answered today's question!");
      return;
    }
    if (selectedAnswer === null) {
      setQError('Please pick an answer first.');
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
        setQError(ansData.error || 'Error submitting daily answer.');
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
          setTimeout(() => setShowCorrectAnimation(false), 1500);
        } else {
          setShowWrongAnimation(true);
          setTimeout(() => setShowWrongAnimation(false), 1500);
        }
      }
    } catch (err) {
      setQError('Error: ' + err.message);
    }
  }

  // Daily bonus UI logic
  let dailyBonusContent;
  if (!userId) {
    // If not logged in
    dailyBonusContent = <p>Please log in first.</p>;
  } else if (bonusError && !bonusError.startsWith('Already claimed')) {
    // A genuine error, not the "already claimed" note
    dailyBonusContent = <p className="daily-error-msg">{bonusError}</p>;
  } else if (!canClaim) {
    // We rely on local countdown for the user
    dailyBonusContent = (
      <>
        {bonusError && bonusError.startsWith('Already claimed') && (
          <p className="claimed-msg">{bonusError}</p>
        )}
        <p className="bonus-countdown">
          Next bonus in:{' '}
          <span className="cool-countdown">{formatCountdown(bonusCountdown)}</span>
        </p>
      </>
    );
  } else {
    // They can claim now
    dailyBonusContent = (
      <button
        onClick={claimDailyBonus}
        disabled={loadingBonus}
        className="claim-bonus-button"
      >
        {loadingBonus ? 'Claiming...' : 'Claim 1000 coins'}
      </button>
    );
  }

  // Daily question UI
  function renderDailyQuestion() {
    if (!userId) {
      return <p className="login-reminder">Please log in to see the daily question.</p>;
    }
    if (loadingQ) {
      return <p className="loading-text">Loading daily question...</p>;
    }
    if (qError) {
      return <p className="daily-error-msg">{qError}</p>;
    }
    if (!questionData) {
      return <p className="no-question-text">No daily question found.</p>;
    }

    const { prompt, options, alreadyAnswered } = questionData;
    return (
      <div
        className={`daily-question-box 
                    ${showCorrectAnimation ? 'correct-answer-animate' : ''} 
                    ${showWrongAnimation ? 'wrong-answer-animate' : ''}`}
      >
        <h2 className="section-title">Daily PBQ Challenge</h2>
        <p className="question-prompt">{prompt}</p>
        {alreadyAnswered ? (
          <div className="already-answered-container">
            {submitResult && (
              <p
                className={
                  submitResult.correct
                    ? 'answer-feedback correct-answer'
                    : 'answer-feedback not-correct-answer'
                }
              >
                {submitResult.correct
                  ? `Correct! You earned ${submitResult.awardedCoins} coins.`
                  : `Not quite, but you still got ${submitResult.awardedCoins} coins.`}
              </p>
            )}
            <p className="next-question-countdown">
              Next question in:{' '}
              <span className="cool-countdown">{formatCountdown(questionCountdown)}</span>
            </p>
          </div>
        ) : (
          <div className="question-input-section">
            <ul className="option-list">
              {options.map((opt, idx) => (
                <li key={idx} className="option-item">
                  <label className="option-label">
                    <input
                      type="radio"
                      name="dailyQuestion"
                      value={idx}
                      checked={selectedAnswer === idx}
                      onChange={() => setSelectedAnswer(idx)}
                      className="option-input"
                    />
                    {opt}
                  </label>
                </li>
              ))}
            </ul>
            <button className="submit-answer-button" onClick={submitDailyAnswer}>
              Submit
            </button>
            <p className="next-question-countdown">
              Time until next question:{' '}
              <span className="cool-countdown">{formatCountdown(questionCountdown)}</span>
            </p>
          </div>
        )}
      </div>
    );
  }

  // Main render
  return (
    <div className="bonus-page-container">
      <div className="gradient-background" />

      {/* "In-your-face" bonus claim overlay */}
      {showBonusAnimation && (
        <div className="bonus-popup-overlay">
          <div className="bonus-popup-content">+1000 Coins Claimed!</div>
        </div>
      )}

      {/* Centered title row */}
      <div className="top-bar-daily">
        <div className="app-title">Daily Station</div>
      </div>

      {/* If user is logged in, show user info in a separate bar */}
      {userId && (
        <div className="player-info-bar">
          <div className="player-info">
            <span className="player-greeting">Welcome, {username}!</span>
            <span className="player-coins">Coins: {coins}</span>
            <span className="player-xp">XP: {xp}</span>
          </div>
        </div>
      )}

      <div className="content-wrapper">
        {!userId ? (
          <p className="login-reminder">Please log in to see daily content.</p>
        ) : (
          <>
            <div className="bonus-section">
              <h2 className="section-title">Daily Bonus</h2>
              {dailyBonusContent}
            </div>
            {renderDailyQuestion()}
          </>
        )}
      </div>
    </div>
  );
};

export default DailyStationPage;
