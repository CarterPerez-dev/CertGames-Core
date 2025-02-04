// src/components/pages/testpage/APlusTestPage.js
import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom"; 
import { useSelector, useDispatch } from "react-redux";
import { dailyLoginBonus, addXP, addCoins } from "../store/userSlice";
import ConfettiAnimation from "./ConfettiAnimation";
import { showAchievementToast } from "../store/AchievementToast";
import "./APlusStyles.css";
import { 
  FaTrophy, 
  FaMedal, 
  FaStar, 
  FaCrown, 
  FaBolt, 
  FaBook, 
  FaBrain, 
  FaCheckCircle, 
  FaRegSmile, 
  FaMagic 
} from 'react-icons/fa';

/* -------------------------
   Define Icon and Color Mappings
   ------------------------- */
const iconMapping = {
  "test_rookie": FaTrophy,
  "accuracy_king": FaMedal,
  "bronze_grinder": FaBook,
  "silver_scholar": FaStar,
  "gold_god": FaCrown,
  "platinum_pro": FaMagic,
  "walking_encyclopedia": FaBrain,
  "redemption_arc": FaBolt,
  "memory_master": FaRegSmile,
  "coin_collector_5000": FaBook,
  "coin_hoarder_10000": FaBook,
  "coin_tycoon_50000": FaBook,
  "perfectionist_1": FaCheckCircle,
  "double_trouble_2": FaCheckCircle,
  "error404_failure_not_found": FaCheckCircle,
  "level_up_5": FaTrophy,
  "mid_tier_grinder_25": FaMedal,
  "elite_scholar_50": FaStar,
  "ultimate_master_100": FaCrown,
  "category_perfectionist": FaBolt,
  "absolute_perfectionist": FaBolt,
  "exam_conqueror": FaMedal,
  "subject_specialist": FaMedal,
  "answer_machine_1000": FaBook,
  "knowledge_beast_5000": FaBrain,
  "question_terminator": FaBrain,
  "test_finisher": FaCheckCircle,
  "subject_finisher": FaCheckCircle
};

const colorMapping = {
  "test_rookie": "#ff5555",
  "accuracy_king": "#ffa500",
  "bronze_grinder": "#cd7f32",
  "silver_scholar": "#c0c0c0",
  "gold_god": "#ffd700",
  "platinum_pro": "#e5e4e2",
  "walking_encyclopedia": "#00fa9a",
  "redemption_arc": "#ff4500",
  "memory_master": "#8a2be2",
  "coin_collector_5000": "#ff69b4",
  "coin_hoarder_10000": "#ff1493",
  "coin_tycoon_50000": "#ff0000",
  "perfectionist_1": "#adff2f",
  "double_trouble_2": "#7fff00",
  "error404_failure_not_found": "#00ffff",
  "level_up_5": "#f08080",
  "mid_tier_grinder_25": "#ff8c00",
  "elite_scholar_50": "#ffd700",
  "ultimate_master_100": "#ff4500",
  "category_perfectionist": "#00ced1",
  "absolute_perfectionist": "#32cd32",
  "exam_conqueror": "#1e90ff",
  "subject_specialist": "#8a2be2",
  "answer_machine_1000": "#ff69b4",
  "knowledge_beast_5000": "#00fa9a",
  "question_terminator": "#ff1493",
  "test_finisher": "#adff2f",
  "subject_finisher": "#7fff00"
};

/* ----- Custom Confirmation Popup Component ----- */
const ConfirmPopup = ({ message, onConfirm, onCancel }) => {
  return (
    <div className="confirm-popup-overlay">
      <div className="confirm-popup-content">
        <p>{message}</p>
        <div className="confirm-popup-buttons">
          <button className="confirm-popup-yes" onClick={onConfirm}>Yes</button>
          <button className="confirm-popup-no" onClick={onCancel}>No</button>
        </div>
      </div>
    </div>
  );
};

const APlusTestPage = () => {
  const { testId } = useParams();
  return testId ? <TestView testId={testId} /> : <TestListView />;
};

/* ============================
   Test List View Component
   ============================ */
const TestListView = () => {
  const navigate = useNavigate();
  const totalQuestions = 100; // For demo purposes
  const { userId } = useSelector((state) => state.user);

  const getProgressData = (id) => {
    if (!userId) return null;
    const key = `testProgress_${userId}_${id}`;
    const saved = localStorage.getItem(key);
    if (!saved) return null;
    try {
      return JSON.parse(saved);
    } catch (e) {
      console.error("Error parsing progress", e);
      return null;
    }
  };

  const getProgressDisplay = (id) => {
    const progressData = getProgressData(id);
    if (progressData) {
      if (progressData.finished) {
        const percentage = Math.round((progressData.score / totalQuestions) * 100);
        return `Final Score: ${percentage}% (${progressData.score}/${totalQuestions})`;
      } else if (typeof progressData.currentQuestionIndex === "number") {
        return `Progress: ${progressData.currentQuestionIndex + 1} / ${totalQuestions}`;
      }
    }
    return "No progress yet";
  };

  const getDifficultyData = (id) => {
    const data = {
      1: { label: "Normal", color: "hsl(0, 0%, 100%)" },
      2: { label: "Very Easy", color: "hsl(120, 100%, 80%)" },
      3: { label: "Easy", color: "hsl(120, 100%, 70%)" },
      4: { label: "Moderate", color: "hsl(120, 100%, 60%)" },
      5: { label: "Intermediate", color: "hsl(120, 100%, 50%)" },
      6: { label: "Formidable", color: "hsl(120, 100%, 40%)" },
      7: { label: "Challenging", color: "hsl(120, 100%, 30%)" },
      8: { label: "Very Challenging", color: "hsl(120, 100%, 20%)" },
      9: { label: "Ruthless", color: "hsl(120, 100%, 10%)" },
      10: { label: "Ultra Level", color: "#000" }
    };
    return data[id] || { label: "", color: "#fff" };
  };

  return (
    <div className="tests-list-container">
      <h1 className="tests-list-title">CompTIA A+ Practice Tests</h1>
      <div className="tests-list-grid">
        {Array.from({ length: 10 }, (_, i) => {
          const id = i + 1;
          const difficulty = getDifficultyData(id);
          const progressData = getProgressData(id);
          const progressDisplay = getProgressDisplay(id);
          return (
            <div key={id} className="test-card">
              <div className="test-badge">Test {id}</div>
              <div className="difficulty-label" style={{ color: difficulty.color }}>
                {difficulty.label}
              </div>
              <p className="test-progress">{progressDisplay}</p>
              {progressData ? (
                <div className="test-card-buttons">
                  {progressData.finished ? (
                    <>
                      <button
                        className="resume-button"
                        onClick={() => navigate(`/practice-tests/a-plus/${id}`)}
                      >
                        View Review
                      </button>
                      <button
                        className="restart-button-testlist"
                        onClick={() => {
                          const key = `testProgress_${userId}_${id}`;
                          localStorage.removeItem(key);
                          navigate(`/practice-tests/a-plus/${id}`);
                        }}
                      >
                        Restart Test
                      </button>
                    </>
                  ) : (
                    <>
                      <button
                        className="resume-button"
                        onClick={() => navigate(`/practice-tests/a-plus/${id}`)}
                      >
                        Resume Test
                      </button>
                      <button
                        className="restart-button-testlist"
                        onClick={() => {
                          const key = `testProgress_${userId}_${id}`;
                          localStorage.removeItem(key);
                          navigate(`/practice-tests/a-plus/${id}`);
                        }}
                      >
                        Restart Test
                      </button>
                    </>
                  )}
                </div>
              ) : (
                <button
                  className="start-button"
                  onClick={() => navigate(`/practice-tests/a-plus/${id}`)}
                >
                  Click to Start
                </button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

/* ============================
   Test View Component
   ============================ */
const TestView = ({ testId }) => {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { xp, level, coins, userId } = useSelector((state) => state.user);
  const achievements = useSelector((state) => state.achievements.all);

  const [currentTest, setCurrentTest] = useState(null);
  const [loadingTest, setLoadingTest] = useState(true);
  const [error, setError] = useState(null);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedOptionIndex, setSelectedOptionIndex] = useState(null);
  const [isAnswered, setIsAnswered] = useState(false);
  const [score, setScore] = useState(0);
  const [answers, setAnswers] = useState([]);
  const [showScoreOverlay, setShowScoreOverlay] = useState(false);
  const [showReviewMode, setShowReviewMode] = useState(false);
  const [flaggedQuestions, setFlaggedQuestions] = useState([]);
  const [localLevel, setLocalLevel] = useState(level);
  const [showLevelUpOverlay, setShowLevelUpOverlay] = useState(false);
  const [isFinished, setIsFinished] = useState(false);
  const [showRestartPopup, setShowRestartPopup] = useState(false);
  const [showFinishPopup, setShowFinishPopup] = useState(false);
  const [showNextPopup, setShowNextPopup] = useState(false);
  const [progressLoaded, setProgressLoaded] = useState(false);

  // Use a user-specific key for saving progress.
  const progressKey = `testProgress_${userId}_${testId}`;

  // ---------- Fetch Test Data ----------
  useEffect(() => {
    const fetchTestData = async () => {
      setLoadingTest(true);
      try {
        const response = await fetch(`/api/test/tests/${testId}`);
        if (!response.ok) {
          let errorData;
          try {
            errorData = await response.json();
          } catch (e) {
            errorData = { error: "Unknown error from server." };
          }
          throw new Error(errorData.error || "Failed to fetch test data");
        }
        const data = await response.json();
        setCurrentTest(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoadingTest(false);
      }
    };
    fetchTestData();
  }, [testId]);

  // ---------- Daily Login Bonus ----------
  useEffect(() => {
    if (userId) {
      dispatch(dailyLoginBonus(userId));
    }
  }, [dispatch, userId]);

  // ---------- Level-Up Check ----------
  useEffect(() => {
    if (level > localLevel) {
      setLocalLevel(level);
      setShowLevelUpOverlay(true);
      const timer = setTimeout(() => setShowLevelUpOverlay(false), 3000);
      return () => clearTimeout(timer);
    }
  }, [level, localLevel]);

  // ---------- Load Saved Progress ----------
  useEffect(() => {
    const savedProgress = localStorage.getItem(progressKey);
    if (savedProgress) {
      try {
        const progress = JSON.parse(savedProgress);
        if (typeof progress.currentQuestionIndex === "number") {
          setCurrentQuestionIndex(progress.currentQuestionIndex);
        }
        if (Array.isArray(progress.answers)) {
          setAnswers(progress.answers);
        }
        if (typeof progress.score === "number") {
          setScore(progress.score);
        }
        if (progress.finished) {
          setIsFinished(true);
          setShowReviewMode(true);
        }
      } catch (e) {
        console.error("Failed to parse saved test progress", e);
      }
    }
    setProgressLoaded(true);
  }, [progressKey]);

  // ---------- Save Test Progress ----------
  useEffect(() => {
    if (!progressLoaded) return;
    if (isFinished) return;
    const progress = { currentQuestionIndex, answers, score };
    localStorage.setItem(progressKey, JSON.stringify(progress));
    if (userId) {
      fetch(`/api/test/user/${userId}/test-progress/${testId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(progress)
      }).catch((err) =>
        console.error("Failed to update test progress on backend", err)
      );
    }
  }, [currentQuestionIndex, answers, score, testId, userId, progressLoaded, isFinished]);

  // ---------- Early Returns ----------
  if (loadingTest) {
    return <div style={{ color: "#fff" }}>Loading test...</div>;
  }
  if (error) {
    return (
      <div style={{ color: "#fff" }}>
        <h2>Error: {error}</h2>
      </div>
    );
  }
  if (!currentTest) {
    return (
      <div style={{ color: "#fff", textAlign: "center", marginTop: "2rem" }}>
        <h2>This test is not yet available!</h2>
        <button style={{ marginTop: "1rem" }} onClick={() => navigate("/practice-tests/a-plus")}>
          Back to Test List
        </button>
      </div>
    );
  }

  const totalQuestions = currentTest.questions.length;
  const questionData = currentTest.questions[currentQuestionIndex];

  // ---------- Dynamic Progress Color ----------
  const progressPercentage = Math.round(((currentQuestionIndex + 1) / totalQuestions) * 100);
  const progressColorHue = (progressPercentage * 120) / 100;
  const progressColor = `hsl(${progressColorHue}, 100%, 50%)`;

  // ---------- Test Handlers ----------
  const handleOptionClick = (optionIndex) => {
    if (isAnswered) return;
    setSelectedOptionIndex(optionIndex);
    const isCorrect = optionIndex === questionData.correctAnswerIndex;
    if (isCorrect) {
      setScore((prev) => prev + 1);
      if (userId) {
        dispatch(addXP({ userId, xp: currentTest.xpPerCorrect }))
          .unwrap()
          .then((data) => {
            if (data.newAchievements && data.newAchievements.length > 0) {
              data.newAchievements.forEach((achievementId) => {
                const achievement = achievements.find(a => a.achievementId === achievementId);
                if (achievement) {
                  const IconComponent = iconMapping[achievement.achievementId] || null;
                  const color = colorMapping[achievement.achievementId] || "#fff";
                  showAchievementToast({
                    title: achievement.title,
                    description: achievement.description,
                    icon: IconComponent ? <IconComponent /> : null,
                    color: color
                  });
                }
              });
            }
          })
          .catch((err) => console.error(err));
        dispatch(addCoins({ userId, coins: 5 }));
      }
    }
    setAnswers((prev) => [
      ...prev,
      {
        questionId: questionData.id,
        userAnswerIndex: optionIndex,
        correctAnswerIndex: questionData.correctAnswerIndex,
      },
    ]);
    setIsAnswered(true);
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex === totalQuestions - 1) {
      const finishedProgress = { currentQuestionIndex, answers, score, finished: true };
      localStorage.setItem(progressKey, JSON.stringify(finishedProgress));
      setIsFinished(true);
      setShowReviewMode(true);
      return;
    }
    setCurrentQuestionIndex((prev) => prev + 1);
    setSelectedOptionIndex(null);
    setIsAnswered(false);
  };

  const handlePreviousQuestion = () => {
    if (currentQuestionIndex > 0) {
      setCurrentQuestionIndex((prev) => prev - 1);
      setSelectedOptionIndex(null);
      setIsAnswered(false);
    }
  };

  const handleRestartTest = () => {
    setCurrentQuestionIndex(0);
    setSelectedOptionIndex(null);
    setIsAnswered(false);
    setScore(0);
    setShowScoreOverlay(false);
    setAnswers([]);
    setFlaggedQuestions([]);
    setIsFinished(false);
    setShowReviewMode(false);
    localStorage.removeItem(progressKey);
  };

  const handleFinishTest = () => {
    const finishedProgress = { currentQuestionIndex, answers, score, finished: true };
    localStorage.setItem(progressKey, JSON.stringify(finishedProgress));
    setIsFinished(true);
    setShowScoreOverlay(true);
    setShowReviewMode(true);
  };

  const handleReviewAnswers = () => setShowReviewMode(true);
  const handleCloseReview = () => {
    if (isFinished) return;
    setShowReviewMode(false);
  };

  const handleSkipQuestion = () => {
    setAnswers((prev) => [
      ...prev,
      {
        questionId: questionData.id,
        userAnswerIndex: null,
        correctAnswerIndex: questionData.correctAnswerIndex,
      },
    ]);
    setIsAnswered(true);
    handleNextQuestion();
  };

  const handleFlagQuestion = () => {
    const qId = questionData.id;
    if (flaggedQuestions.includes(qId)) {
      setFlaggedQuestions(flaggedQuestions.filter((id) => id !== qId));
    } else {
      setFlaggedQuestions([...flaggedQuestions, qId]);
    }
  };

  const onNextClick = () => {
    if (!isAnswered) {
      setShowNextPopup(true);
    } else {
      handleNextQuestion();
    }
  };

  // ---------- Render Overlays and Popups ----------
  const renderScoreOverlay = () => {
    if (!showScoreOverlay) return null;
    const percentage = Math.round((score / totalQuestions) * 100);
    return (
      <div className="score-overlay">
        <div className="score-content">
          <h2 className="score-title">Test Complete!</h2>
          <p className="score-details">
            Your score: <strong>{percentage}%</strong> ({score}/{totalQuestions})
          </p>
          <div className="overlay-buttons">
            <button className="restart-button" onClick={handleRestartTest}>
              Restart Test
            </button>
            <button className="review-button" onClick={handleReviewAnswers}>
              Review Answers
            </button>
            <button className="back-btn" onClick={() => navigate("/practice-tests/a-plus")}>
              Back to Test List
            </button>
            {Number(testId) < 9999 && (
              <button
                className="next-test-button"
                onClick={() => navigate(`/practice-tests/a-plus/${Number(testId) + 1}`)}
              >
                Next Test
              </button>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderReviewMode = () => {
    if (!showReviewMode) return null;
    return (
      <div className="score-overlay review-overlay">
        <div className="score-content review-content">
          {isFinished ? (
            <button className="back-to-list-btn" onClick={() => navigate("/practice-tests/a-plus")}>
              Go Back to Test List
            </button>
          ) : (
            <button className="close-review-x" onClick={handleCloseReview}>X</button>
          )}
          <h2 className="score-title">Review Mode</h2>
          <p className="score-details">Here are your answers:</p>
          <div className="review-mode-container">
            {currentTest.questions.map((q) => {
              const userAnswer = answers.find((a) => a.questionId === q.id);
              if (!userAnswer) return null;
              const isCorrect = userAnswer.userAnswerIndex === q.correctAnswerIndex;
              const isFlagged = flaggedQuestions.includes(q.id);
              return (
                <div key={q.id} className="review-question-card">
                  <h3>
                    Q{q.id}: {q.question} {isFlagged && <span className="flagged-icon">🚩</span>}
                  </h3>
                  <p>
                    <strong>Your Answer:</strong>{" "}
                    {userAnswer.userAnswerIndex === null ? "Skipped" : q.options[userAnswer.userAnswerIndex]}
                  </p>
                  <p>
                    <strong>Correct Answer:</strong> {q.options[q.correctAnswerIndex]}
                  </p>
                  <p style={{ color: isCorrect ? "#8BC34A" : "#F44336" }}>
                    {isCorrect ? "Correct!" : "Incorrect!"}
                  </p>
                  <p>{q.explanation}</p>
                </div>
              );
            })}
          </div>
          {!isFinished && (
            <button className="review-button close-review-btn" onClick={handleCloseReview}>
              Close Review
            </button>
          )}
        </div>
      </div>
    );
  };

  const renderRestartPopup = () => {
    if (!showRestartPopup) return null;
    return (
      <ConfirmPopup
        message="Are you sure you want to restart the test? Your progress will be lost."
        onConfirm={() => { handleRestartTest(); setShowRestartPopup(false); }}
        onCancel={() => setShowRestartPopup(false)}
      />
    );
  };

  const renderFinishPopup = () => {
    if (!showFinishPopup) return null;
    return (
      <ConfirmPopup
        message="Are you sure you want to finish the test?"
        onConfirm={() => { handleFinishTest(); setShowFinishPopup(false); }}
        onCancel={() => setShowFinishPopup(false)}
      />
    );
  };

  const renderNextPopup = () => {
    if (!showNextPopup) return null;
    return (
      <ConfirmPopup
        message="You haven't answered this question. Do you want to continue without answering?"
        onConfirm={() => { handleNextQuestion(); setShowNextPopup(false); }}
        onCancel={() => setShowNextPopup(false)}
      />
    );
  };

  const avatarUrl =
    level >= 5
      ? "https://via.placeholder.com/60/FF0000/FFFFFF?text=LVL5+Avatar"
      : "https://via.placeholder.com/60";

  return (
    <div className="aplus-test-container">
      {renderRestartPopup()}
      {renderFinishPopup()}
      {renderNextPopup()}

      <div className="top-control-bar">
        <button className="flag-btn" onClick={handleFlagQuestion}>
          {flaggedQuestions.includes(questionData.id) ? "Unflag" : "Flag"}
        </button>
        <button className="finish-test-btn" onClick={() => setShowFinishPopup(true)}>
          Finish Test
        </button>
      </div>

      <div className="upper-control-bar">
        <button className="restart-test-btn" onClick={() => setShowRestartPopup(true)}>
          Restart Test
        </button>
        <button className="back-btn" onClick={() => navigate("/practice-tests/a-plus")}>
          Back to Test List
        </button>
      </div>

      <ConfettiAnimation trigger={showLevelUpOverlay} level={level} />
      {renderScoreOverlay()}
      {renderReviewMode()}

      <h1 className="aplus-title">{currentTest.testName}</h1>
      <div className="top-bar">
        <div className="avatar-section">
          <div className="avatar-image" style={{ backgroundImage: `url(${avatarUrl})` }}></div>
          <div className="avatar-level">Lvl {level}</div>
        </div>
        <div className="xp-level-display">XP: {xp}</div>
        <div className="coins-display">Coins: {coins}</div>
      </div>
      <div className="progress-container">
        <div className="progress-fill" style={{ width: `${progressPercentage}%`, background: progressColor }}>
          {currentQuestionIndex + 1} / {totalQuestions} ({progressPercentage}%)
        </div>
      </div>
      {!showScoreOverlay && !showReviewMode && !isFinished && (
        <div className="question-card">
          <div className="question-text">{questionData.question}</div>
          <ul className="options-list">
            {questionData.options.map((option, idx) => {
              let optionClass = "option-button";
              const correctIndex = questionData.correctAnswerIndex;
              if (isAnswered && idx === correctIndex) {
                optionClass += " correct-option";
              } else if (isAnswered && idx === selectedOptionIndex && idx !== correctIndex) {
                optionClass += " incorrect-option";
              }
              return (
                <li className="option-item" key={idx}>
                  <button
                    className={optionClass}
                    onClick={() => handleOptionClick(idx)}
                    disabled={isAnswered}
                  >
                    {option}
                  </button>
                </li>
              );
            })}
          </ul>
          {isAnswered && (
            <div className="explanation">
              <strong>
                {selectedOptionIndex === questionData.correctAnswerIndex
                  ? "Correct!"
                  : "Incorrect!"}
              </strong>
              <p>{questionData.explanation}</p>
            </div>
          )}
          <div className="bottom-control-bar">
            <div className="bottom-control-row">
              <button 
                className="prev-question-btn" 
                onClick={handlePreviousQuestion} 
                disabled={currentQuestionIndex === 0}
              >
                Previous Question
              </button>
              <button className="next-question-btn" onClick={onNextClick}>
                Next Question
              </button>
            </div>
            <div className="bottom-control-row skip-row">
              <button className="skip-question-btn" onClick={handleSkipQuestion}>
                Skip Question
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default APlusTestPage;

