// src/components/pages/testpage/APlusTestPage.js
import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom"; 
import { useSelector, useDispatch } from "react-redux";
import { dailyLoginBonus, addXP, addCoins } from "../store/userSlice";
import ConfettiAnimation from "./ConfettiAnimation";
import { showAchievementToast } from "../store/AchievementToast";
import APlusTestList from "./APlusTestList"; // <-- Import our new Test List file
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

/* ------------------------------------------------------------------
   Shuffle Options for a Single Question
------------------------------------------------------------------ */
const shuffleOptions = (question) => {
  const originalOptions = question.options.slice();
  const correctIndex = question.correctAnswerIndex;
  const indices = originalOptions.map((_, index) => index);

  for (let i = indices.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [indices[i], indices[j]] = [indices[j], indices[i]];
  }

  const shuffledOptions = indices.map(i => originalOptions[i]);
  const newCorrectIndex = indices.indexOf(correctIndex);

  return {
    ...question,
    options: shuffledOptions,
    correctAnswerIndex: newCorrectIndex
  };
};

/* ------------------------------------------------------------------
   Confirmation Popup
------------------------------------------------------------------ */
const ConfirmPopup = ({ message, onConfirm, onCancel }) => {
  return (
    <div className="confirm-popup-overlay">
      <div className="confirm-popup-content">
        <p>{message}</p>
        <div className="confirm-popup-buttons">
          <button className="confirm-popup-yes" onClick={onConfirm}>
            Yes
          </button>
          <button className="confirm-popup-no" onClick={onCancel}>
            No
          </button>
        </div>
      </div>
    </div>
  );
};

/* ------------------------------------------------------------------
   Main Export: APlusTestPage
   If testId is present, we show the test view; otherwise, show list
------------------------------------------------------------------ */
const APlusTestPage = () => {
  const { testId } = useParams();
  return testId ? <TestView testId={testId} /> : <APlusTestList />;
};

/* ============================
   Test View Component
   ============================ */
const TestView = ({ testId }) => {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { xp, level, coins, userId } = useSelector((state) => state.user);
  const achievements = useSelector((state) => state.achievements.all);

  // Local test states
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

  // Filter for the review mode: 'all', 'skipped', 'flagged', 'incorrect', 'correct'
  const [reviewFilter, setReviewFilter] = useState("all");

  const [progressLoaded, setProgressLoaded] = useState(false);
  const progressKey = `testProgress_${userId}_${testId}`;

  /* 1. Fetch Test Data */
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

        // Attempt to load saved progress
        const savedProgressStr = localStorage.getItem(progressKey);
        if (savedProgressStr) {
          const saved = JSON.parse(savedProgressStr);
          if (saved.shuffledQuestions) {
            data.questions = saved.shuffledQuestions;
          }
        } else {
          // No progress => shuffle
          const shuffled = data.questions.map(q => shuffleOptions(q));
          data.questions = shuffled;
          const initProgress = {
            currentQuestionIndex: 0,
            answers: [],
            score: 0,
            totalQuestions: data.questions.length,
            category: data.category || "aplus",
            shuffledQuestions: shuffled,
            finished: false
          };
          localStorage.setItem(progressKey, JSON.stringify(initProgress));
        }

        setCurrentTest(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoadingTest(false);
      }
    };
    fetchTestData();
  }, [testId, progressKey]);

  /* 2. Daily Login Bonus */
  useEffect(() => {
    if (userId) {
      dispatch(dailyLoginBonus(userId));
    }
  }, [dispatch, userId]);

  /* 3. Level-Up Overlay */
  useEffect(() => {
    if (level > localLevel) {
      setLocalLevel(level);
      setShowLevelUpOverlay(true);
      const t = setTimeout(() => setShowLevelUpOverlay(false), 3000);
      return () => clearTimeout(t);
    }
  }, [level, localLevel]);

  /* 4. Load Saved Progress */
  useEffect(() => {
    if (!currentTest) return;
    const savedProgressStr = localStorage.getItem(progressKey);
    if (!savedProgressStr) {
      setProgressLoaded(true);
      return;
    }

    try {
      const progress = JSON.parse(savedProgressStr);
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
        setShowScoreOverlay(true);
        setShowReviewMode(true);
      }
    } catch (e) {
      console.error("Failed to parse saved test progress", e);
    } finally {
      setProgressLoaded(true);
    }
  }, [currentTest, progressKey]);

  /* 5. Sync local "selectedOptionIndex" & "isAnswered" */
  useEffect(() => {
    if (!currentTest || !progressLoaded) return;
    const question = currentTest.questions[currentQuestionIndex];
    if (!question) return;

    const existingAnswer = answers.find(a => a.questionId === question.id);
    if (existingAnswer) {
      setSelectedOptionIndex(existingAnswer.userAnswerIndex);
      setIsAnswered(true);
    } else {
      setSelectedOptionIndex(null);
      setIsAnswered(false);
    }
  }, [currentQuestionIndex, currentTest, progressLoaded, answers]);

  /* 6. Save Test Progress Effect */
  useEffect(() => {
    if (!progressLoaded) return;
    if (!currentTest) return;
    if (isFinished) return;

    const totalQuestions = currentTest.questions.length;
    const progress = { 
      currentQuestionIndex,
      answers,
      score,
      totalQuestions,
      category: currentTest?.category || "aplus",
      shuffledQuestions: currentTest.questions,
      finished: false
    };

    localStorage.setItem(progressKey, JSON.stringify(progress));
    if (userId) {
      fetch(`/api/test/user/${userId}/test-progress/${testId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(progress)
      }).catch((err) => {
        console.error("Failed to update test progress on backend", err);
      });
    }
  }, [
    currentQuestionIndex,
    answers,
    score,
    testId,
    userId,
    progressLoaded,
    isFinished,
    currentTest,
  ]);

  if (!currentTest) {
    return <div style={{ color: "#fff" }}>Loading test...</div>;
  }
  if (error) {
    return <div style={{ color: "#fff" }}>{error}</div>;
  }

  const totalQuestions = currentTest.questions.length;
  const questionData = currentTest.questions[currentQuestionIndex];

  const progressPercentage = Math.round(((currentQuestionIndex + 1) / totalQuestions) * 100);
  const progressColorHue = (progressPercentage * 120) / 100;
  const progressColor = `hsl(${progressColorHue}, 100%, 50%)`;

  /* Handlers */
  const handleOptionClick = (optionIndex) => {
    if (isAnswered) return;
    setSelectedOptionIndex(optionIndex);

    const isCorrect = (optionIndex === questionData.correctAnswerIndex);
    if (isCorrect && userId) {
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

    // Record answer
    const updatedAnswers = [...answers];
    const existingIndex = updatedAnswers.findIndex(a => a.questionId === questionData.id);
    const newAnswerObj = {
      questionId: questionData.id,
      userAnswerIndex: optionIndex,
      correctAnswerIndex: questionData.correctAnswerIndex,
    };

    if (existingIndex >= 0) {
      updatedAnswers[existingIndex] = newAnswerObj;
    } else {
      updatedAnswers.push(newAnswerObj);
    }
    setAnswers(updatedAnswers);

    // Increment local 'score' if correct
    if (isCorrect) {
      setScore(prev => prev + 1);
    }
    setIsAnswered(true);
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex === totalQuestions - 1) {
      finishTestProcess();
      return;
    }
    setCurrentQuestionIndex((prev) => prev + 1);
  };

  const handlePreviousQuestion = () => {
    if (currentQuestionIndex > 0) {
      setCurrentQuestionIndex((prev) => prev - 1);
    }
  };

  const reShuffleQuestions = () => {
    if (currentTest?.questions) {
      const shuffled = currentTest.questions.map(q => {
        const unshuffledQ = { ...q, options: q.options.slice() };
        return shuffleOptions(unshuffledQ);
      });
      setCurrentTest(prev => ({ ...prev, questions: shuffled }));
    }
  };

  const handleRestartTest = () => {
    localStorage.removeItem(progressKey);
    setCurrentQuestionIndex(0);
    setSelectedOptionIndex(null);
    setIsAnswered(false);
    setScore(0);
    setAnswers([]);
    setFlaggedQuestions([]);
    setIsFinished(false);
    setShowReviewMode(false);
    setShowScoreOverlay(false);

    reShuffleQuestions();
  };

  const finishTestProcess = () => {
    // Recalc final score from answers, to ensure it's correct in localStorage
    const finalScore = answers.reduce((acc, ans) => (
      ans.userAnswerIndex === ans.correctAnswerIndex ? acc + 1 : acc
    ), 0);
    setScore(finalScore);

    const finishedProgress = {
      currentQuestionIndex,
      answers,
      score: finalScore,
      finished: true,
      totalQuestions,
      category: currentTest?.category || "aplus",
      finishedAt: new Date().toISOString(),
      shuffledQuestions: currentTest.questions
    };

    localStorage.setItem(progressKey, JSON.stringify(finishedProgress));
    setIsFinished(true);
    setShowScoreOverlay(true);
    setShowReviewMode(true);
  };

  const handleFinishTest = () => {
    finishTestProcess();
  };

  const handleReviewAnswers = () => {
    setShowReviewMode(true);
    setReviewFilter("all");
  };

  const handleCloseReview = () => {
    if (isFinished) return;
    setShowReviewMode(false);
  };

  const handleSkipQuestion = () => {
    const updatedAnswers = [...answers];
    const existingIndex = updatedAnswers.findIndex(a => a.questionId === questionData.id);
    const skipAnswerObj = {
      questionId: questionData.id,
      userAnswerIndex: null,
      correctAnswerIndex: questionData.correctAnswerIndex,
    };
    if (existingIndex >= 0) {
      updatedAnswers[existingIndex] = skipAnswerObj;
    } else {
      updatedAnswers.push(skipAnswerObj);
    }
    setAnswers(updatedAnswers);

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

  /* Overlays & Popups */
  const renderRestartPopup = () => {
    if (!showRestartPopup) return null;
    return (
      <ConfirmPopup
        message="Are you sure you want to restart the test? Your progress will be lost."
        onConfirm={() => {
          handleRestartTest();
          setShowRestartPopup(false);
        }}
        onCancel={() => setShowRestartPopup(false)}
      />
    );
  };

  const renderFinishPopup = () => {
    if (!showFinishPopup) return null;
    return (
      <ConfirmPopup
        message="Are you sure you want to finish the test?"
        onConfirm={() => {
          handleFinishTest();
          setShowFinishPopup(false);
        }}
        onCancel={() => setShowFinishPopup(false)}
      />
    );
  };

  const renderNextPopup = () => {
    if (!showNextPopup) return null;
    return (
      <ConfirmPopup
        message="You haven't answered this question. Continue without answering?"
        onConfirm={() => {
          handleNextQuestion();
          setShowNextPopup(false);
        }}
        onCancel={() => setShowNextPopup(false)}
      />
    );
  };

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
              View Review
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
    const filteredQuestions = currentTest.questions.filter((q) => {
      const userAnswer = answers.find((a) => a.questionId === q.id);
      const isFlagged = flaggedQuestions.includes(q.id);

      if (!userAnswer) {
        if (reviewFilter === "skipped") return true;
        return reviewFilter === "all";
      }

      const isSkipped = userAnswer.userAnswerIndex === null;
      const isCorrect = (userAnswer.userAnswerIndex === q.correctAnswerIndex);

      if (reviewFilter === "all") return true;
      if (reviewFilter === "skipped" && isSkipped) return true;
      if (reviewFilter === "flagged" && isFlagged) return true;
      if (reviewFilter === "incorrect" && !isCorrect && !isSkipped) return true;
      if (reviewFilter === "correct" && isCorrect && !isSkipped) return true;
      return false;
    });

    const finalPercentage = Math.round((score / totalQuestions) * 100);

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

          {isFinished && (
            <p className="review-score-line">
              Your final score: {score}/{totalQuestions} ({finalPercentage}%)
            </p>
          )}

          <div className="review-filter-buttons">
            <button
              className={reviewFilter === "all" ? "active-filter" : ""}
              onClick={() => setReviewFilter("all")}
            >
              All
            </button>
            <button
              className={reviewFilter === "skipped" ? "active-filter" : ""}
              onClick={() => setReviewFilter("skipped")}
            >
              Skipped
            </button>
            <button
              className={reviewFilter === "flagged" ? "active-filter" : ""}
              onClick={() => setReviewFilter("flagged")}
            >
              Flagged
            </button>
            <button
              className={reviewFilter === "incorrect" ? "active-filter" : ""}
              onClick={() => setReviewFilter("incorrect")}
            >
              Incorrect
            </button>
            <button
              className={reviewFilter === "correct" ? "active-filter" : ""}
              onClick={() => setReviewFilter("correct")}
            >
              Correct
            </button>
          </div>

          <p className="score-details">Questions shown: {filteredQuestions.length}</p>

          <div className="review-mode-container">
            {filteredQuestions.map((q) => {
              const userAnswer = answers.find((a) => a.questionId === q.id);
              const isFlagged = flaggedQuestions.includes(q.id);

              if (!userAnswer) {
                return (
                  <div key={q.id} className="review-question-card">
                    <h3>
                      Q{q.id}: {q.question}{" "}
                      {isFlagged && <span className="flagged-icon">🚩</span>}
                    </h3>
                    <p><strong>Your Answer:</strong> Unanswered</p>
                    <p><strong>Correct Answer:</strong> {q.options[q.correctAnswerIndex]}</p>
                    <p style={{ color: "#F44336" }}>No Answer</p>
                    <p>{q.explanation}</p>
                  </div>
                );
              }

              const isSkipped = userAnswer.userAnswerIndex === null;
              const isCorrect = (userAnswer.userAnswerIndex === q.correctAnswerIndex);

              return (
                <div key={q.id} className="review-question-card">
                  <h3>
                    Q{q.id}: {q.question}{" "}
                    {isFlagged && <span className="flagged-icon">🚩</span>}
                  </h3>
                  <p>
                    <strong>Your Answer:</strong>{" "}
                    {isSkipped ? "Skipped" : q.options[userAnswer.userAnswerIndex]}
                  </p>
                  <p>
                    <strong>Correct Answer:</strong>{" "}
                    {q.options[q.correctAnswerIndex]}
                  </p>
                  {!isSkipped && (
                    <p style={{ color: isCorrect ? "#8BC34A" : "#F44336" }}>
                      {isCorrect ? "Correct!" : "Incorrect!"}
                    </p>
                  )}
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

  /* Achievement Icon & Color Mapping */
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

  /* Render */
  const avatarUrl =
    level >= 5
      ? "https://via.placeholder.com/60/FF0000/FFFFFF?text=LVL5+Avatar"
      : "https://via.placeholder.com/60";

  return (
    <div className="aplus-test-container">
      <ConfettiAnimation trigger={showLevelUpOverlay} level={level} />
      {renderRestartPopup()}
      {renderFinishPopup()}
      {renderNextPopup()}
      {renderScoreOverlay()}
      {renderReviewMode()}

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
        <div
          className="progress-fill"
          style={{ width: `${progressPercentage}%`, background: progressColor }}
        >
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
              {currentQuestionIndex === totalQuestions - 1 ? (
                <button className="next-question-btn" onClick={onNextClick}>
                  Finish Test
                </button>
              ) : (
                <button className="next-question-btn" onClick={onNextClick}>
                  Next Question
                </button>
              )}
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

