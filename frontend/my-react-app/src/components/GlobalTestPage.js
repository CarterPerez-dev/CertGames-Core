import React, {
  useState,
  useEffect,
  useCallback,
  useMemo,
  useRef
} from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useSelector, useDispatch } from "react-redux";
import { setXPAndCoins } from "./pages/store/userSlice";
import { fetchShopItems } from "./pages/store/shopSlice";
import ConfettiAnimation from "./ConfettiAnimation";
import { showAchievementToast } from "./pages/store/AchievementToast";
import "./test.css";
import iconMapping from "./iconMapping";
import colorMapping from "./colorMapping";
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
} from "react-icons/fa";

// Helper functions
function shuffleArray(arr) {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

function shuffleIndices(length) {
  const indices = Array.from({ length }, (_, i) => i);
  return shuffleArray(indices);
}

// Reusable QuestionDropdown component
const QuestionDropdown = ({
  totalQuestions,
  currentQuestionIndex,
  onQuestionSelect,
  answers,
  flaggedQuestions,
  testData,
  shuffleOrder,
  examMode
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const getQuestionStatus = (index) => {
    const realIndex = shuffleOrder[index];
    const question = testData.questions[realIndex];
    const answer = answers.find((a) => a.questionId === question.id);
    const isFlagged = flaggedQuestions.includes(question.id);
    const isAnswered = answer?.userAnswerIndex !== undefined;
    const isSkipped = answer?.userAnswerIndex === null;
    const isCorrect =
      answer && answer.userAnswerIndex === question.correctAnswerIndex;
    return { isAnswered, isSkipped, isCorrect, isFlagged };
  };

  return (
    <div className="question-dropdown" ref={dropdownRef}>
      <button onClick={() => setIsOpen(!isOpen)} className="dropdown-button">
        Question {currentQuestionIndex + 1}
      </button>
      {isOpen && (
        <div className="dropdown-content">
          {Array.from({ length: totalQuestions }, (_, i) => {
            const status = getQuestionStatus(i);
            return (
              <button
                key={i}
                onClick={() => {
                  onQuestionSelect(i);
                  setIsOpen(false);
                }}
                className="dropdown-item"
              >
                <span>Question {i + 1}</span>
                <div className="status-indicators">
                  {status.isSkipped && <span className="skip-indicator">⏭️</span>}
                  {status.isFlagged && <span className="flag-indicator">🚩</span>}
                  {!examMode && status.isAnswered && !status.isSkipped && (
                    <span
                      className={
                        status.isCorrect
                          ? "answer-indicator correct"
                          : "answer-indicator incorrect"
                      }
                    >
                      {status.isCorrect ? "✓" : "✗"}
                    </span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};

const GlobalTestPage = ({
  testId,
  category,
  backToListPath
}) => {
  const location = useLocation();
  const navigate = useNavigate();
  const dispatch = useDispatch();

  // Redux user data
  const { xp, level, coins, userId, xpBoost, currentAvatar } = useSelector(
    (state) => state.user
  );
  const achievements = useSelector((state) => state.achievements.all);
  const { items: shopItems, status: shopStatus } = useSelector(
    (state) => state.shop
  );

  // Local states for test logic
  const [testData, setTestData] = useState(null);
  const [shuffleOrder, setShuffleOrder] = useState([]);
  const [answerOrder, setAnswerOrder] = useState([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [answers, setAnswers] = useState([]);
  const [score, setScore] = useState(0);
  const [loadingTest, setLoadingTest] = useState(true);
  const [error, setError] = useState(null);
  const [isAnswered, setIsAnswered] = useState(false);
  const [selectedOptionIndex, setSelectedOptionIndex] = useState(null);
  const [isFinished, setIsFinished] = useState(false);

  // Overlays
  const [showScoreOverlay, setShowScoreOverlay] = useState(false);
  const [showReviewMode, setShowReviewMode] = useState(false);

  // Confetti on level-up
  const [localLevel, setLocalLevel] = useState(level);
  const [showLevelUpOverlay, setShowLevelUpOverlay] = useState(false);

  // Flags
  const [flaggedQuestions, setFlaggedQuestions] = useState([]);

  // Confirmation popups
  const [showRestartPopup, setShowRestartPopup] = useState(false);
  const [showFinishPopup, setShowFinishPopup] = useState(false);
  const [showNextPopup, setShowNextPopup] = useState(false);

  // Exam mode
  const [examMode, setExamMode] = useState(false);

  // New: Test length selection state
  const allowedTestLengths = [25, 50, 75, 100];
  const [selectedLength, setSelectedLength] = useState(100);
  const [activeTestLength, setActiveTestLength] = useState(null);
  const [showTestLengthSelector, setShowTestLengthSelector] = useState(false);

  useEffect(() => {
    if (shopStatus === "idle") {
      dispatch(fetchShopItems());
    }
  }, [shopStatus, dispatch]);

  const fetchTestAndAttempt = async () => {
    setLoadingTest(true);
    try {
      let attemptDoc = null;
      if (userId) {
        const attemptRes = await fetch(`/api/test/attempts/${userId}/${testId}`);
        const attemptData = await attemptRes.json();
        attemptDoc = attemptData.attempt || null;
      }
      const testRes = await fetch(`/api/test/tests/${category}/${testId}`);
      if (!testRes.ok) {
        const errData = await testRes.json().catch(() => ({}));
        throw new Error(errData.error || "Failed to fetch test data");
      }
      const testDoc = await testRes.json();
      setTestData(testDoc);
      const totalQ = testDoc.questions.length;
      if (attemptDoc) {
        setAnswers(attemptDoc.answers || []);
        setScore(attemptDoc.score || 0);
        setIsFinished(attemptDoc.finished === true);
        const attemptExam = attemptDoc.examMode || false;
        setExamMode(attemptExam);
        // Use the stored selectedLength or default to totalQ
        const effectiveLength = attemptDoc.selectedLength || totalQ;
        setActiveTestLength(effectiveLength);
        if (attemptDoc.shuffleOrder && attemptDoc.shuffleOrder.length > 0) {
          setShuffleOrder(attemptDoc.shuffleOrder);
        } else {
          const newQOrder = shuffleIndices(effectiveLength);
          setShuffleOrder(newQOrder);
        }
        if (attemptDoc.answerOrder && attemptDoc.answerOrder.length === totalQ) {
          setAnswerOrder(attemptDoc.answerOrder);
        } else {
          const generatedAnswerOrder = testDoc.questions
            .slice(0, effectiveLength)
            .map((q) => {
              const numOptions = q.options.length;
              return shuffleArray([...Array(numOptions).keys()]);
            });
          setAnswerOrder(generatedAnswerOrder);
        }
        setCurrentQuestionIndex(attemptDoc.currentQuestionIndex || 0);
      } else {
        // No attempt doc exists: show the test length selector UI
        setActiveTestLength(null);
        setShowTestLengthSelector(true);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingTest(false);
    }
  };

  useEffect(() => {
    fetchTestAndAttempt();
  }, [testId, userId]);

  useEffect(() => {
    if (level > localLevel) {
      setLocalLevel(level);
      setShowLevelUpOverlay(true);
      const t = setTimeout(() => setShowLevelUpOverlay(false), 3000);
      return () => clearTimeout(t);
    }
  }, [level, localLevel]);

  useEffect(() => {
    if (location.state?.review && isFinished) {
      setShowReviewMode(true);
    }
  }, [location.state, isFinished]);

  const getShuffledIndex = useCallback(
    (i) => {
      if (!shuffleOrder || shuffleOrder.length === 0) return i;
      return shuffleOrder[i];
    },
    [shuffleOrder]
  );

  // Determine effective total questions based on chosen test length.
  const effectiveTotal = activeTestLength || (testData ? testData.questions.length : 0);
  const realIndex = getShuffledIndex(currentQuestionIndex);
  const questionObject =
    testData && testData.questions && testData.questions.length > 0
      ? testData.questions[realIndex]
      : null;

  useEffect(() => {
    if (!questionObject) return;
    const existing = answers.find((a) => a.questionId === questionObject.id);
    if (existing) {
      setSelectedOptionIndex(null);
      if (existing.userAnswerIndex !== null && existing.userAnswerIndex !== undefined) {
        const displayIndex = answerOrder[realIndex].indexOf(existing.userAnswerIndex);
        if (displayIndex >= 0) {
          setSelectedOptionIndex(displayIndex);
          setIsAnswered(true);
        } else {
          setIsAnswered(false);
        }
      } else {
        setIsAnswered(false);
      }
    } else {
      setSelectedOptionIndex(null);
      setIsAnswered(false);
    }
  }, [questionObject, answers, realIndex, answerOrder]);

  const updateServerProgress = useCallback(
    async (updatedAnswers, updatedScore, finished = false, singleAnswer = null) => {
      if (!userId) return;
      try {
        if (singleAnswer) {
          const res = await fetch(`/api/test/user/${userId}/submit-answer`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              testId,
              questionId: singleAnswer.questionId,
              correctAnswerIndex: singleAnswer.correctAnswerIndex,
              selectedIndex: singleAnswer.userAnswerIndex,
              xpPerCorrect: (testData?.xpPerCorrect || 10) * xpBoost,
              coinsPerCorrect: 5
            })
          });
          const data = await res.json();
          return data;
        }
        await fetch(`/api/test/attempts/${userId}/${testId}/position`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            currentQuestionIndex,
            finished
          })
        });
      } catch (err) {
        console.error("Failed to update test attempt on backend", err);
      }
    },
    [userId, testId, testData, xpBoost, currentQuestionIndex]
  );

  const handleOptionClick = useCallback(
    async (displayOptionIndex) => {
      if (isAnswered || !questionObject) return;
      const actualAnswerIndex = answerOrder[realIndex][displayOptionIndex];
      setSelectedOptionIndex(displayOptionIndex);
      setIsAnswered(true);
      try {
        const newAnswerObj = {
          questionId: questionObject.id,
          userAnswerIndex: actualAnswerIndex,
          correctAnswerIndex: questionObject.correctAnswerIndex
        };
        const updatedAnswers = [...answers];
        const idx = updatedAnswers.findIndex(a => a.questionId === questionObject.id);
        if (idx >= 0) {
          updatedAnswers[idx] = newAnswerObj;
        } else {
          updatedAnswers.push(newAnswerObj);
        }
        setAnswers(updatedAnswers);
        const awardData = await updateServerProgress(updatedAnswers, score, false, newAnswerObj);
        if (!examMode && awardData && awardData.examMode === false) {
          if (awardData.isCorrect) {
            setScore(prev => prev + 1);
          }
          if (awardData.isCorrect && !awardData.alreadyCorrect && awardData.awardedXP) {
            dispatch(setXPAndCoins({
              xp: awardData.newXP,
              coins: awardData.newCoins
            }));
          }
        }
      } catch (err) {
        console.error("Failed to submit answer to backend", err);
      }
    },
    [
      isAnswered,
      questionObject,
      examMode,
      testData,
      xpBoost,
      userId,
      testId,
      dispatch,
      score,
      answers,
      updateServerProgress,
      realIndex,
      answerOrder
    ]
  );

  const finishTestProcess = useCallback(async () => {
    let finalScore = 0;
    answers.forEach((ans) => {
      if (ans.userAnswerIndex === ans.correctAnswerIndex) {
        finalScore++;
      }
    });
    setScore(finalScore);
    try {
      const res = await fetch(`/api/test/attempts/${userId}/${testId}/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          score: finalScore,
          totalQuestions: effectiveTotal
        })
      });
      const finishData = await res.json();
      if (finishData.newlyUnlocked && finishData.newlyUnlocked.length > 0) {
        finishData.newlyUnlocked.forEach((achievementId) => {
          const achievement = achievements.find(
            (a) => a.achievementId === achievementId
          );
          if (achievement) {
            const IconComp = iconMapping[achievement.achievementId] || null;
            const color = colorMapping[achievement.achievementId] || "#fff";
            showAchievementToast({
              title: achievement.title,
              description: achievement.description,
              icon: IconComp ? <IconComp /> : null,
              color
            });
          }
        });
      }
      if (
        typeof finishData.newXP !== "undefined" &&
        typeof finishData.newCoins !== "undefined"
      ) {
        dispatch(
          setXPAndCoins({
            xp: finishData.newXP,
            coins: finishData.newCoins
          })
        );
      }
    } catch (err) {
      console.error("Failed to finish test attempt:", err);
    }
    setIsFinished(true);
    setShowScoreOverlay(true);
    setShowReviewMode(true);
  }, [answers, userId, testId, effectiveTotal, achievements, dispatch]);

  const handleNextQuestion = useCallback(() => {
    if (!isAnswered && !examMode) {
      setShowNextPopup(true);
      return;
    }
    if (currentQuestionIndex === effectiveTotal - 1) {
      finishTestProcess();
      return;
    }
    const nextIndex = currentQuestionIndex + 1;
    setCurrentQuestionIndex(nextIndex);
    updateServerProgress(answers, score, false);
  }, [
    isAnswered,
    examMode,
    currentQuestionIndex,
    effectiveTotal,
    finishTestProcess,
    updateServerProgress,
    answers,
    score
  ]);

  const handlePreviousQuestion = useCallback(() => {
    if (currentQuestionIndex > 0) {
      const prevIndex = currentQuestionIndex - 1;
      setCurrentQuestionIndex(prevIndex);
      updateServerProgress(answers, score, false);
    }
  }, [currentQuestionIndex, updateServerProgress, answers, score]);

  const handleSkipQuestion = () => {
    if (!questionObject) return;
    const updatedAnswers = [...answers];
    const idx = updatedAnswers.findIndex(
      (a) => a.questionId === questionObject.id
    );
    const skipObj = {
      questionId: questionObject.id,
      userAnswerIndex: null,
      correctAnswerIndex: questionObject.correctAnswerIndex
    };
    if (idx >= 0) {
      updatedAnswers[idx] = skipObj;
    } else {
      updatedAnswers.push(skipObj);
    }
    setAnswers(updatedAnswers);
    setIsAnswered(false);
    setSelectedOptionIndex(null);
    updateServerProgress(updatedAnswers, score, false, skipObj);
    if (currentQuestionIndex === effectiveTotal - 1) {
      finishTestProcess();
      return;
    }
    setCurrentQuestionIndex(currentQuestionIndex + 1);
  };

  const handleFlagQuestion = () => {
    if (!questionObject) return;
    const qId = questionObject.id;
    if (flaggedQuestions.includes(qId)) {
      setFlaggedQuestions(flaggedQuestions.filter((x) => x !== qId));
    } else {
      setFlaggedQuestions([...flaggedQuestions, qId]);
    }
  };

  const handleRestartTest = useCallback(async () => {
    setCurrentQuestionIndex(0);
    setSelectedOptionIndex(null);
    setIsAnswered(false);
    setScore(0);
    setAnswers([]);
    setFlaggedQuestions([]);
    setIsFinished(false);
    setShowReviewMode(false);
    setShowScoreOverlay(false);
    if (testData?.questions?.length && activeTestLength) {
      // Use the activeTestLength to shuffle only that many questions
      const newQOrder = shuffleIndices(activeTestLength);
      setShuffleOrder(newQOrder);
      const newAnswerOrder = testData.questions
        .slice(0, activeTestLength)
        .map((q) => {
          const numOpts = q.options.length;
          return shuffleArray([...Array(numOpts).keys()]);
        });
      setAnswerOrder(newAnswerOrder);
      if (userId && testId) {
        await fetch(`/api/test/attempts/${userId}/${testId}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            answers: [],
            score: 0,
            totalQuestions: testData.questions.length,
            selectedLength: activeTestLength,
            category: testData.category || category,
            currentQuestionIndex: 0,
            shuffleOrder: newQOrder,
            answerOrder: newAnswerOrder,
            finished: false,
            examMode
          })
        });
      }
    }
  }, [testData, userId, testId, category, examMode, activeTestLength]);

  const handleFinishTest = () => {
    finishTestProcess();
  };

  const [reviewFilter, setReviewFilter] = useState("all");
  const handleReviewAnswers = () => {
    setShowReviewMode(true);
    setReviewFilter("all");
  };
  const handleCloseReview = () => {
    if (!isFinished) setShowReviewMode(false);
  };

  const filteredQuestions = useMemo(() => {
    if (!testData || !testData.questions) return [];
    return testData.questions.slice(0, effectiveTotal).filter((q) => {
      const userAns = answers.find((a) => a.questionId === q.id);
      const isFlagged = flaggedQuestions.includes(q.id);
      if (!userAns) {
        return reviewFilter === "skipped" || reviewFilter === "all";
      }
      const isSkipped = userAns.userAnswerIndex === null;
      const isCorrect = userAns.userAnswerIndex === q.correctAnswerIndex;
      if (reviewFilter === "all") return true;
      if (reviewFilter === "skipped" && isSkipped) return true;
      if (reviewFilter === "flagged" && isFlagged) return true;
      if (reviewFilter === "incorrect" && !isCorrect && !isSkipped) return true;
      if (reviewFilter === "correct" && isCorrect && !isSkipped) return true;
      return false;
    });
  }, [testData, answers, flaggedQuestions, reviewFilter, effectiveTotal]);

  const NextQuestionAlert = ({ message, onOk }) => (
    <div className="confirm-popup-overlay">
      <div className="confirm-popup-content">
        <p>{message}</p>
        <div className="confirm-popup-buttons">
          <button className="confirm-popup-ok" onClick={onOk}>
            OK
          </button>
        </div>
      </div>
    </div>
  );

  const renderNextPopup = () => {
    if (!showNextPopup) return null;
    return (
      <NextQuestionAlert
        message="You haven't answered. Please answer or skip question.🤪"
        onOk={() => {
          setShowNextPopup(false);
        }}
      />
    );
  };

  const ConfirmPopup = ({ message, onConfirm, onCancel }) => (
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

  const renderRestartPopup = () => {
    if (!showRestartPopup) return null;
    return (
      <ConfirmPopup
        message="Are you sure you want to restart the test? All progress will be lost!😱"
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
        message="Are you sure you want to finish the test now?😥"
        onConfirm={() => {
          handleFinishTest();
          setShowFinishPopup(false);
        }}
        onCancel={() => setShowFinishPopup(false)}
      />
    );
  };

  const renderScoreOverlay = () => {
    if (!showScoreOverlay) return null;
    const percentage = effectiveTotal
      ? Math.round((score / effectiveTotal) * 100)
      : 0;
    return (
      <div className="score-overlay">
        <div className="score-content">
          <h2 className="score-title">Test Complete!</h2>
          <p className="score-details">
            Your score: <strong>{percentage}%</strong> ({score}/{effectiveTotal})
          </p>
          <div className="overlay-buttons">
            <button
              className="restart-button"
              onClick={() => setShowRestartPopup(true)}
            >
              Restart Test
            </button>
            <button className="review-button" onClick={handleReviewAnswers}>
              View Review
            </button>
            <button className="back-btn" onClick={() => navigate(backToListPath)}>
              Back to Test List
            </button>
            {Number(testId) < 9999 && (
              <button
                className="next-test-button"
                onClick={() => navigate(`${backToListPath}/${Number(testId) + 1}`)}
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
            <button
              className="back-to-list-btn"
              onClick={() => navigate(backToListPath)}
            >
              Go Back to Test List
            </button>
          ) : (
            <button className="close-review-x" onClick={handleCloseReview}>
              X
            </button>
          )}
          <h2 className="score-title">Review Mode</h2>
          {isFinished && (
            <p className="review-score-line">
              Your final score: {score}/{effectiveTotal} (
              {effectiveTotal
                ? Math.round((score / effectiveTotal) * 100)
                : 0
              }%)
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
          <p className="score-details">
            Questions shown: {filteredQuestions.length}
          </p>
          <div className="review-mode-container">
            {filteredQuestions.map((q) => {
              const userAns = answers.find((a) => a.questionId === q.id);
              const isFlagged = flaggedQuestions.includes(q.id);
              if (!userAns) {
                return (
                  <div key={q.id} className="review-question-card">
                    <h3>
                      Q{q.id}: {q.question}{" "}
                      {isFlagged && <span className="flagged-icon">🚩</span>}
                    </h3>
                    <p>
                      <strong>Your Answer:</strong> Unanswered
                    </p>
                    <p>
                      <strong>Correct Answer:</strong> {q.options[q.correctAnswerIndex]}
                    </p>
                    <p style={{ color: "#F44336" }}>No Answer</p>
                    <p>{q.explanation}</p>
                  </div>
                );
              }
              const isSkipped = userAns.userAnswerIndex === null;
              const isCorrect = userAns.userAnswerIndex === q.correctAnswerIndex;
              return (
                <div key={q.id} className="review-question-card">
                  <h3>
                    Q{q.id}: {q.question}{" "}
                    {isFlagged && <span className="flagged-icon">🚩</span>}
                  </h3>
                  <p>
                    <strong>Your Answer:</strong>{" "}
                    {isSkipped ? (
                      <span style={{ color: "orange" }}>Skipped</span>
                    ) : (
                      q.options[userAns.userAnswerIndex]
                    )}
                  </p>
                  <p>
                    <strong>Correct Answer:</strong>{" "}
                    {q.options[q.correctAnswerIndex]}
                  </p>
                  {!isSkipped && (
                    <p
                      style={{
                        color: isCorrect ? "#8BC34A" : "#F44336"
                      }}
                    >
                      {isCorrect ? "Correct!" : "Incorrect!"}
                    </p>
                  )}
                  <p>{q.explanation}</p>
                </div>
              );
            })}
          </div>
          {!isFinished && (
            <button
              className="review-button close-review-btn"
              onClick={handleCloseReview}
            >
              Close Review
            </button>
          )}
        </div>
      </div>
    );
  };

  const handleNextQuestionButtonClick = () => {
    if (!isAnswered && !examMode) {
      setShowNextPopup(true);
    } else {
      handleNextQuestion();
    }
  };

  // NEW: Render the test length selector UI if no attempt exists.
  if (showTestLengthSelector) {
    return (
      <div className="test-length-selector">
        <h2>Select Test Length</h2>
        <p>Please select how many questions you want to answer:</p>
        <div className="test-length-options">
          {allowedTestLengths.map((length) => (
            <label key={length}>
              <input
                type="radio"
                name="testLength"
                value={length}
                checked={selectedLength === length}
                onChange={(e) => setSelectedLength(Number(e.target.value))}
              />
              {length}
            </label>
          ))}
        </div>
        <button
          onClick={async () => {
            setActiveTestLength(selectedLength);
            if (testData) {
              const totalQ = testData.questions.length;
              // For this feature, take the first 'selectedLength' questions and shuffle them
              const newQOrder = shuffleIndices(selectedLength);
              setShuffleOrder(newQOrder);
              const newAnswerOrder = testData.questions
                .slice(0, selectedLength)
                .map((q) => {
                  const numOpts = q.options.length;
                  return shuffleArray([...Array(numOpts).keys()]);
                });
              setAnswerOrder(newAnswerOrder);
              try {
                await fetch(`/api/test/attempts/${userId}/${testId}`, {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({
                    answers: [],
                    score: 0,
                    totalQuestions: totalQ,
                    selectedLength: selectedLength,
                    category: testData.category || category,
                    currentQuestionIndex: 0,
                    shuffleOrder: newQOrder,
                    answerOrder: newAnswerOrder,
                    finished: false,
                    examMode: location.state?.examMode || false
                  })
                });
                setShowTestLengthSelector(false);
                fetchTestAndAttempt();
              } catch (err) {
                console.error("Failed to start new attempt", err);
              }
            }
          }}
        >
          Start Test
        </button>
      </div>
    );
  }

  if (error) {
    return <div style={{ color: "#fff" }}>Error: {error}</div>;
  }
  if (loadingTest) {
    return <div style={{ color: "#fff" }}>Loading test...</div>;
  }
  if (!testData || !testData.questions || testData.questions.length === 0) {
    return <div style={{ color: "#fff" }}>No questions found.</div>;
  }

  let avatarUrl = "https://via.placeholder.com/60";
  if (currentAvatar && shopItems && shopItems.length > 0) {
    const avatarItem = shopItems.find((item) => item._id === currentAvatar);
    if (avatarItem && avatarItem.imageUrl) {
      avatarUrl = avatarItem.imageUrl;
    }
  }

  const progressPercentage = effectiveTotal
    ? Math.round(((currentQuestionIndex + 1) / effectiveTotal) * 100)
    : 0;
  const progressColorHue = (progressPercentage * 120) / 100;
  const progressColor = `hsl(${progressColorHue}, 100%, 50%)`;

  let displayedOptions = [];
  if (questionObject && answerOrder[realIndex]) {
    displayedOptions = answerOrder[realIndex].map(
      (optionIdx) => questionObject.options[optionIdx]
    );
  }

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
          {questionObject && flaggedQuestions.includes(questionObject.id)
            ? "Unflag"
            : "Flag"}
        </button>
        <QuestionDropdown
          totalQuestions={effectiveTotal}
          currentQuestionIndex={currentQuestionIndex}
          onQuestionSelect={(index) => {
            setCurrentQuestionIndex(index);
            updateServerProgress(answers, score, false);
          }}
          answers={answers}
          flaggedQuestions={flaggedQuestions}
          testData={testData}
          shuffleOrder={shuffleOrder}
          examMode={examMode}
        />
        <button
          className="finish-test-btn"
          onClick={() => setShowFinishPopup(true)}
        >
          Finish Test
        </button>
      </div>
      <div className="upper-control-bar">
        <button
          className="restart-test-btn"
          onClick={() => setShowRestartPopup(true)}
        >
          Restart Test
        </button>
        <button className="back-btn" onClick={() => navigate(backToListPath)}>
          Back to Test List
        </button>
      </div>
      <h1 className="aplus-title">{testData.testName}</h1>
      <div className="top-bar">
        <div className="avatar-section">
          <div
            className="avatar-image"
            style={{ backgroundImage: `url(${avatarUrl})` }}
          />
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
          {currentQuestionIndex + 1} / {effectiveTotal} ({progressPercentage}%)
        </div>
      </div>
      {!showScoreOverlay && !showReviewMode && !isFinished && (
        <div className="question-card">
          <div className="question-text">
            {questionObject && questionObject.question}
          </div>
          <ul className="options-list">
            {displayedOptions.map((option, displayIdx) => {
              let optionClass = "option-button";
              if (!examMode) {
                if (isAnswered && questionObject) {
                  const correctIndex = questionObject.correctAnswerIndex;
                  const actualIndex = answerOrder[realIndex][displayIdx];
                  if (actualIndex === correctIndex) {
                    optionClass += " correct-option";
                  } else if (
                    displayIdx === selectedOptionIndex &&
                    actualIndex !== correctIndex
                  ) {
                    optionClass += " incorrect-option";
                  }
                }
              } else {
                if (isAnswered && displayIdx === selectedOptionIndex) {
                  optionClass += " chosen-option";
                }
              }
              return (
                <li className="option-item" key={displayIdx}>
                  <button
                    className={optionClass}
                    onClick={() => handleOptionClick(displayIdx)}
                    disabled={examMode ? false : isAnswered}
                  >
                    {option}
                  </button>
                </li>
              );
            })}
          </ul>
          {isAnswered && questionObject && !examMode && (
            <div className="explanation">
              <strong>
                {selectedOptionIndex !== null &&
                answerOrder[realIndex][selectedOptionIndex] ===
                  questionObject.correctAnswerIndex
                  ? "Correct!"
                  : "Incorrect!"}
              </strong>
              <p>{questionObject.explanation}</p>
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
              {currentQuestionIndex === effectiveTotal - 1 ? (
                <button
                  className="next-question-btn"
                  onClick={handleNextQuestionButtonClick}
                >
                  Finish Test
                </button>
              ) : (
                <button
                  className="next-question-btn"
                  onClick={handleNextQuestionButtonClick}
                >
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

export default GlobalTestPage;
