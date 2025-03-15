// src/components/pages/serverplus/ServerPlusTestList.js
import React, { useEffect, useState } from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import "../../test.css";
import {
  FaPlay,
  FaPause,
  FaRedo,
  FaEye,
  FaInfoCircle,
  FaChevronRight,
  FaLock,
  FaTrophy,
  FaCog,
  FaCheck,
  FaTimes,
  FaExclamationTriangle
} from "react-icons/fa";

const ServerPlusTestList = () => {
  const navigate = useNavigate();
  const { userId } = useSelector((state) => state.user);
  const totalQuestionsPerTest = 100;
  const category = "serverplus";

  const [attemptData, setAttemptData] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Persist examMode in localStorage
  const [examMode, setExamMode] = useState(() => {
    const stored = localStorage.getItem("examMode");
    return stored === "true";
  });

  // Show/hide tooltip for the info icon
  const [showExamInfo, setShowExamInfo] = useState(false);

  // Restart popup on the test list page (holds test number)
  const [restartPopupTest, setRestartPopupTest] = useState(null);

  // Choose test length
  const allowedTestLengths = [25, 50, 75, 100];
  const [selectedLengths, setSelectedLengths] = useState({});

  useEffect(() => {
    if (!userId) return;
    setLoading(true);

    const fetchAttempts = async () => {
      try {
        const res = await fetch(`/api/test/attempts/${userId}/list`);
        if (!res.ok) {
          throw new Error("Failed to fetch attempts for user");
        }
        const data = await res.json();
        const attemptList = data.attempts || [];

        // Filter attempts for this category
        const relevant = attemptList.filter((a) => a.category === category);

        // IMPORTANT FIX: Improved handling of attempts per test
        const bestAttempts = {};
        for (let att of relevant) {
          const testKey = att.testId;
          
          // Skip attempts that don't have a valid testId
          if (testKey === undefined || testKey === null) continue;
          
          if (!bestAttempts[testKey]) {
            bestAttempts[testKey] = att;
          } else {
            const existing = bestAttempts[testKey];
            
            // If existing is finished and new is unfinished, keep finished
            if (existing.finished && !att.finished) {
              // Keep existing (finished beats unfinished)
            } 
            // If existing is unfinished and new is finished, use new
            else if (!existing.finished && att.finished) {
              bestAttempts[testKey] = att;
            }
            // If both are finished or both are unfinished, pick newest
            else {
              const existingTime = new Date(existing.finishedAt || existing.updatedAt || 0).getTime();
              const newTime = new Date(att.finishedAt || att.updatedAt || 0).getTime();
              
              if (newTime > existingTime) {
                bestAttempts[testKey] = att;
              }
            }
          }
        }

        setAttemptData(bestAttempts);
        setLoading(false);
      } catch (err) {
        console.error(err);
        setError(err.message);
        setLoading(false);
      }
    };

    fetchAttempts();
  }, [userId, category]);

  // Save examMode to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem("examMode", examMode ? "true" : "false");
  }, [examMode]);

  if (!userId) {
    return (
      <div className="testlist-container">
        <div className="testlist-auth-message">
          <FaLock className="testlist-auth-icon" />
          <h2>Please log in to access the practice tests</h2>
          <button 
            className="testlist-login-button"
            onClick={() => navigate('/login')}
          >
            Go to Login
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="testlist-container">
        <div className="testlist-loading">
          <div className="testlist-loading-spinner"></div>
          <p>Loading your test progress...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="testlist-container">
        <div className="testlist-error">
          <FaExclamationTriangle className="testlist-error-icon" />
          <h2>Error Loading Tests</h2>
          <p>{error}</p>
          <button 
            className="testlist-retry-button"
            onClick={() => window.location.reload()}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const getAttemptDoc = (testNumber) => {
    return attemptData[testNumber] || null;
  };

  const getProgressDisplay = (attemptDoc) => {
    if (!attemptDoc) return { text: "Not started", percentage: 0 };
    
    const { finished, score, totalQuestions, currentQuestionIndex, examMode } = attemptDoc;
    
    // Improved display of exam mode tests in the list
    if (finished === true) {
      const pct = Math.round((score / (totalQuestions || totalQuestionsPerTest)) * 100);
      return { 
        text: `Score: ${score}/${totalQuestions || totalQuestionsPerTest} (${pct}%)${examMode ? ' (Exam Mode)' : ''}`, 
        percentage: pct,
        isFinished: true,
        isExamMode: examMode === true
      };
    } else {
      if (typeof currentQuestionIndex === "number") {
        const progressPct = Math.round(((currentQuestionIndex + 1) / (totalQuestions || totalQuestionsPerTest)) * 100);
        return { 
          text: `Progress: ${currentQuestionIndex + 1}/${totalQuestions || totalQuestionsPerTest}${examMode ? ' (Exam Mode)' : ''}`, 
          percentage: progressPct,
          isFinished: false,
          isExamMode: examMode === true
        };
      }
      return { text: "Not started", percentage: 0 };
    }
  };

  const startTest = (testNumber, doRestart = false, existingAttempt = null) => {
    if (existingAttempt && !doRestart) {
      // When resuming a test, preserve its original exam mode setting
      const attemptExamMode = existingAttempt.examMode === true;
      
      // Store the current exam mode from the attempt in localStorage
      localStorage.setItem("examMode", attemptExamMode ? "true" : "false");
      
      // Navigate with clear indication that we're resuming
      navigate(`/practice-tests/server-plus/${testNumber}`, {
        state: { 
          examMode: attemptExamMode,
          resuming: true // Add flag to indicate we're resuming
        }
      });
    } else {
      // New test or forced restart
      const lengthToUse = selectedLengths[testNumber] || totalQuestionsPerTest;
      
      // IMPORTANT FIX: For restart, ensure we create a completely new attempt
      const createNewAttempt = async () => {
        try {
          const response = await fetch(`/api/test/attempts/${userId}/${testNumber}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              category,
              answers: [],
              score: 0,
              totalQuestions: totalQuestionsPerTest,
              selectedLength: lengthToUse,
              currentQuestionIndex: 0,
              shuffleOrder: [], // Let the test page generate this
              answerOrder: [],  // Let the test page generate this
              finished: false,
              examMode,
            })
          });
          
          if (!response.ok) {
            throw new Error("Failed to create attempt document");
          }
          
          // Navigate to test page with fresh state
          navigate(`/practice-tests/server-plus/${testNumber}`, {
            state: { 
              examMode,
              restarting: true // Add flag to indicate we're starting fresh
            }
          });
        } catch (err) {
          console.error("Failed to create new attempt doc:", err);
        }
      };
      
      createNewAttempt();
    }
  };

  const difficultyCategories = [
    { label: "Normal", color: "#fff9e6", textColor: "#4a4a4a" },             // Cream
    { label: "Very Easy", color: "#adebad", textColor: "#0b3800" },          // Soft green
    { label: "Easy", color: "#87cefa", textColor: "#000000" },               // Light sky blue
    { label: "Moderate", color: "#ffc765", textColor: "#4a2700" },           // Warm orange
    { label: "Intermediate", color: "#ff5959", textColor: "#ffffff" },       // Coral red
    { label: "Formidable", color: "#dc3545", textColor: "#ffffff" },         // Bootstrap red
    { label: "Challenging", color: "#b108f6", textColor: "#ffffff" },        // Bright purple
    { label: "Very Challenging", color: "#4b0082", textColor: "#ffffff" },   // Indigo
    { label: "Ruthless", color: "#370031", textColor: "#ffffff" },           // Very dark purple
    { label: "Ultra Level", color: "#000000", textColor: "#00ffff" }         // Black with neon cyan text
  ];

  const examInfoText = "Exam Mode simulates a real certification exam environment by hiding answer feedback and explanations until after you complete the entire test. This helps you prepare for the pressure and pace of an actual exam.";

  return (
    <div className="testlist-container">
      <div className="testlist-header">
        <div className="testlist-title-section">
          <h1 className="testlist-title">CompTIA Server+</h1>
          <p className="testlist-subtitle">Practice Test Collection</p>
        </div>
        
        <div className="testlist-mode-toggle">
          <div className="testlist-mode-label">
            <FaCog className="testlist-mode-icon" />
            <span>Exam Mode</span>
            
            <div className="testlist-info-container">
              <FaInfoCircle 
                className="testlist-info-icon"
                onMouseEnter={() => setShowExamInfo(true)}
                onMouseLeave={() => setShowExamInfo(false)}
                onClick={() => setShowExamInfo(!showExamInfo)}
              />
              
              {showExamInfo && (
                <div className="testlist-info-tooltip">
                  {examInfoText}
                </div>
              )}
            </div>
          </div>
          
          <label className="testlist-toggle">
            <input
              type="checkbox"
              checked={examMode}
              onChange={(e) => setExamMode(e.target.checked)}
            />
            <span className="testlist-toggle-slider">
              <span className="testlist-toggle-text">
                {examMode ? "ON" : "OFF"}
              </span>
            </span>
          </label>
        </div>
      </div>

      <div className="testlist-grid">
        {Array.from({ length: 10 }, (_, i) => {
          const testNumber = i + 1;
          const attemptDoc = getAttemptDoc(testNumber);
          const progress = getProgressDisplay(attemptDoc);
          const difficulty = difficultyCategories[i] || difficultyCategories[0];

          const isFinished = attemptDoc?.finished;
          const noAttempt = !attemptDoc;
          const inProgress = attemptDoc && !isFinished;

          return (
            <div key={testNumber} className={`testlist-card ${isFinished ? 'testlist-card-completed' : inProgress ? 'testlist-card-progress' : ''}`}>
              <div className="testlist-card-header">
                <div className="testlist-card-number">Test {testNumber}</div>
                <div 
                  className="testlist-difficulty" 
                  style={{ backgroundColor: difficulty.color, color: difficulty.textColor }}
                >
                  {difficulty.label}
                </div>
              </div>
              
              <div className="testlist-card-content">
                <div className="testlist-progress-section">
                  <div className="testlist-progress-text">{progress.text}</div>
                  <div className="testlist-progress-bar-container">
                    <div 
                      className={`testlist-progress-bar ${isFinished ? 'testlist-progress-complete' : ''}`}
                      style={{ width: `${progress.percentage}%` }}
                    ></div>
                  </div>
                </div>
                
                {/* Length Selector */}
                {(noAttempt || isFinished) && (
                  <div className="testlist-length-selector">
                    <div className="testlist-length-label">Select question count:</div>
                    <div className="testlist-length-options">
                      {allowedTestLengths.map((length) => (
                        <label 
                          key={length} 
                          className={`testlist-length-option ${(selectedLengths[testNumber] || totalQuestionsPerTest) === length ? 'selected' : ''}`}
                        >
                          <input
                            type="radio"
                            name={`testLength-${testNumber}`}
                            value={length}
                            checked={(selectedLengths[testNumber] || totalQuestionsPerTest) === length}
                            onChange={(e) => 
                              setSelectedLengths((prev) => ({
                                ...prev,
                                [testNumber]: Number(e.target.value)
                              }))
                            }
                          />
                          <span>{length}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* Action Buttons */}
                <div className={`testlist-card-actions ${inProgress ? 'two-buttons' : ''}`}>
                  {noAttempt && (
                    <button
                      className="testlist-action-button testlist-start-button"
                      onClick={() => startTest(testNumber, false, null)}
                    >
                      <FaPlay className="testlist-action-icon" />
                      <span>Start Test</span>
                    </button>
                  )}
                  
                  {inProgress && (
                    <>
                      <button
                        className="testlist-action-button testlist-resume-button"
                        onClick={() => startTest(testNumber, false, attemptDoc)}
                      >
                        <FaPlay className="testlist-action-icon" />
                        <span>{attemptDoc?.examMode ? "Resume Exam" : "Resume"}</span>
                      </button>
                      
                      <button
                        className="testlist-action-button testlist-restart-button"
                        onClick={() => setRestartPopupTest(testNumber)}
                      >
                        <FaRedo className="testlist-action-icon" />
                        <span>Restart</span>
                      </button>
                    </>
                  )}
                  
                  {isFinished && (
                    <>
                      <button
                        className="testlist-action-button testlist-review-button"
                        onClick={() => 
                          navigate(`/practice-tests/server-plus/${testNumber}`, {
                            state: { review: true }
                          })
                        }
                      >
                        <FaEye className="testlist-action-icon" />
                        <span>View Results</span>
                      </button>
                      
                      <button
                        className="testlist-action-button testlist-restart-button"
                        onClick={() => startTest(testNumber, true, attemptDoc)}
                      >
                        <FaRedo className="testlist-action-icon" />
                        <span>Restart</span>
                      </button>
                    </>
                  )}
                </div>
              </div>
              
              {isFinished && progress.percentage >= 80 && (
                <div className="testlist-achievement-badge">
                  <FaTrophy className="testlist-achievement-icon" />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Restart Confirmation Popup */}
      {restartPopupTest !== null && (
        <div className="testlist-popup-overlay">
          <div className="testlist-popup">
            <div className="testlist-popup-header">
              <FaExclamationTriangle className="testlist-popup-icon" />
              <h3>Confirm Restart</h3>
            </div>
            
            <div className="testlist-popup-content">
              <p>You're currently in progress on Test {restartPopupTest}. Are you sure you want to restart?</p>
              <p>All current progress will be lost, and your test will begin with your selected length.</p>
            </div>
            
            <div className="testlist-popup-actions">
              <button
                className="testlist-popup-button testlist-popup-confirm"
                onClick={() => {
                  const attemptDoc = getAttemptDoc(restartPopupTest);
                  startTest(restartPopupTest, true, attemptDoc);
                  setRestartPopupTest(null);
                }}
              >
                <FaCheck className="testlist-popup-button-icon" />
                <span>Yes, Restart</span>
              </button>
              
              <button 
                className="testlist-popup-button testlist-popup-cancel"
                onClick={() => setRestartPopupTest(null)}
              >
                <FaTimes className="testlist-popup-button-icon" />
                <span>Cancel</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ServerPlusTestList;
