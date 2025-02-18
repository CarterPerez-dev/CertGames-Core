// GlobalTestPage.js
import React, {
  useState,
  useEffect,
  useCallback,
  useMemo
} from "react";
import { useNavigate } from "react-router-dom";
import { useSelector, useDispatch } from "react-redux";
import { setXPAndCoins } from "./pages/store/userSlice";
import { fetchShopItems } from "./pages/store/shopSlice";
import ConfettiAnimation from "./ConfettiAnimation";
import { showAchievementToast } from "./pages/store/AchievementToast";
import "./test.css";

// Icon imports for achievements
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

/* ------------------------------------------------------------------
   1) Helper: Shuffle an array of question indices
      We won't store the entire question text in localStorage anymore.
------------------------------------------------------------------ */
function shuffleIndices(length) {
  const indices = Array.from({ length }, (_, i) => i);
  for (let i = indices.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [indices[i], indices[j]] = [indices[j], indices[i]];
  }
  return indices;
}

/* ------------------------------------------------------------------
   2) Icon & Color Mappings for Achievements
------------------------------------------------------------------ */
const iconMapping = {
  test_rookie: FaTrophy,
  accuracy_king: FaMedal,
  bronze_grinder: FaBook,
  silver_scholar: FaStar,
  gold_god: FaCrown,
  platinum_pro: FaMagic,
  walking_encyclopedia: FaBrain,
  redemption_arc: FaBolt,
  memory_master: FaRegSmile,
  coin_collector_5000: FaBook,
  coin_hoarder_10000: FaBook,
  coin_tycoon_50000: FaBook,
  perfectionist_1: FaCheckCircle,
  double_trouble_2: FaCheckCircle,
  error404_failure_not_found: FaCheckCircle,
  level_up_5: FaTrophy,
  mid_tier_grinder_25: FaMedal,
  elite_scholar_50: FaStar,
  ultimate_master_100: FaCrown,
  category_perfectionist: FaBolt,
  absolute_perfectionist: FaBolt,
  exam_conqueror: FaMedal,
  subject_specialist: FaMedal,
  answer_machine_1000: FaBook,
  knowledge_beast_5000: FaBrain,
  question_terminator: FaBrain,
  test_finisher: FaCheckCircle,
  subject_finisher: FaCheckCircle
};

const colorMapping = {
  test_rookie: "#ff5555",
  accuracy_king: "#ffa500",
  bronze_grinder: "#cd7f32",
  silver_scholar: "#c0c0c0",
  gold_god: "#ffd700",
  platinum_pro: "#e5e4e2",
  walking_encyclopedia: "#00fa9a",
  redemption_arc: "#ff4500",
  memory_master: "#8a2be2",
  coin_collector_5000: "#ff69b4",
  coin_hoarder_10000: "#ff1493",
  coin_tycoon_50000: "#ff0000",
  perfectionist_1: "#adff2f",
  double_trouble_2: "#7fff00",
  error404_failure_not_found: "#00ffff",
  level_up_5: "#f08080",
  mid_tier_grinder_25: "#ff8c00",
  elite_scholar_50: "#ffd700",
  ultimate_master_100: "#ff4500",
  category_perfectionist: "#00ced1",
  absolute_perfectionist: "#32cd32",
  exam_conqueror: "#1e90ff",
  subject_specialist: "#8a2be2",
  answer_machine_1000: "#ff69b4",
  knowledge_beast_5000: "#00fa9a",
  question_terminator: "#ff1493",
  test_finisher: "#adff2f",
  subject_finisher: "#7fff00"
};

/* ------------------------------------------------------------------
   3) The Global Test Page (Server-Side Progress Storage)
------------------------------------------------------------------ */
const GlobalTestPage = ({
  testId,           // e.g. "1"
  category,         // e.g. "secplus"
  backToListPath    // e.g. "/practice-tests/security-plus"
}) => {
  const navigate = useNavigate();
  const dispatch = useDispatch();

  // Redux user data
  const {
    xp,
    level,
    coins,
    userId,
    xpBoost,
    currentAvatar
  } = useSelector((state) => state.user);

  const achievements = useSelector((state) => state.achievements.all);
  const { items: shopItems, status: shopStatus } = useSelector((state) => state.shop);

  // State for question data & progress
  const [testData, setTestData] = useState(null);          // Full question text
  const [shuffleOrder, setShuffleOrder] = useState([]);    // Array of indices
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [answers, setAnswers] = useState([]);              // e.g. [{ questionId, userAnswerIndex, correctAnswerIndex }, ...]
  const [score, setScore] = useState(0);

  // Flags
  const [loadingTest, setLoadingTest] = useState(true);
  const [error, setError] = useState(null);
  const [isAnswered, setIsAnswered] = useState(false);
  const [selectedOptionIndex, setSelectedOptionIndex] = useState(null);
  const [isFinished, setIsFinished] = useState(false);

  // Overlays
  const [showScoreOverlay, setShowScoreOverlay] = useState(false);
  const [showReviewMode, setShowReviewMode] = useState(false);
  const [reviewFilter, setReviewFilter] = useState("all");

  // Confetti
  const [localLevel, setLocalLevel] = useState(level);
  const [showLevelUpOverlay, setShowLevelUpOverlay] = useState(false);

  // Flag questions
  const [flaggedQuestions, setFlaggedQuestions] = useState([]);

  // Confirmation popups
  const [showRestartPopup, setShowRestartPopup] = useState(false);
  const [showFinishPopup, setShowFinishPopup] = useState(false);
  const [showNextPopup, setShowNextPopup] = useState(false);

  /* -----------------------------------------------------
     A) On mount: fetch partial attempt, then fetch test
  ----------------------------------------------------- */
  

  useEffect(() => {
    // fetch shop items if needed
    if (shopStatus === "idle") {
      dispatch(fetchShopItems());
    }
  }, [shopStatus, dispatch]);

  // 1) fetch partial attempt from /attempts/<userId>/<testId>
  // 2) fetch test from /api/test/tests/<testId>
  // 3) apply shuffle order to test
  const fetchTestAndAttempt = async () => {
    setLoadingTest(true);
    try {
      // Step 1) Partial attempt:
      let attemptDoc = null;
      if (userId) {
        const attemptRes = await fetch(`/api/test/attempts/${userId}/${testId}`);
        const attemptData = await attemptRes.json();
        attemptDoc = attemptData.attempt; // might be null
      }

      // Step 2) Full test doc
      const testRes = await fetch(`/api/test/tests/${category}/${testId}`);
      if (!testRes.ok) {
        const errData = await testRes.json().catch(() => ({}));
        throw new Error(errData.error || "Failed to fetch test data");
      }
      const testDoc = await testRes.json();

      // We'll keep testDoc.questions as "testData"
      setTestData(testDoc); // question text + answers

      if (attemptDoc) {
        // We have partial data from the server
        setAnswers(attemptDoc.answers || []);
        setScore(attemptDoc.score || 0);
        setIsFinished(attemptDoc.finished === true);

        if (attemptDoc.shuffleOrder && attemptDoc.shuffleOrder.length > 0) {
          setShuffleOrder(attemptDoc.shuffleOrder);
        } else {
          // If no shuffle saved, generate one
          const newOrder = shuffleIndices(testDoc.questions.length);
          setShuffleOrder(newOrder);
        }
        setCurrentQuestionIndex(attemptDoc.currentQuestionIndex || 0);
      } else {
        // No partial attempt => brand new
        const newOrder = shuffleIndices(testDoc.questions.length);
        setShuffleOrder(newOrder);
        setScore(0);
        setAnswers([]);
        setIsFinished(false);
        setCurrentQuestionIndex(0);

        // Create an attempt doc in DB with an upsert call:
        if (userId) {
          await fetch(`/api/test/attempts/${userId}/${testId}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              answers: [],
              score: 0,
              totalQuestions: testDoc.questions.length,
              category: testDoc.category || category,
              currentQuestionIndex: 0,
              shuffleOrder: newOrder,
              finished: false
            })
          });
        }
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingTest(false);
    }
  };

  useEffect(() => {
    fetchTestAndAttempt();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [testId, userId]);

  /* -----------------------------------------------------
     B) Confetti if user levels up
  ----------------------------------------------------- */
  useEffect(() => {
    if (level > localLevel) {
      setLocalLevel(level);
      setShowLevelUpOverlay(true);
      const t = setTimeout(() => setShowLevelUpOverlay(false), 3000);
      return () => clearTimeout(t);
    }
  }, [level, localLevel]);

  /* -----------------------------------------------------
     C) Helper: Get the "real" question index from shuffle
  ----------------------------------------------------- */
  const getShuffledIndex = useCallback((i) => {
    if (!shuffleOrder || shuffleOrder.length === 0) {
      return i;
    }
    return shuffleOrder[i];
  }, [shuffleOrder]);

  /* -----------------------------------------------------
     D) If we have question data + shuffle, figure out Q
  ----------------------------------------------------- */
  const totalQuestions = testData?.questions?.length || 0;
  const realIndex = getShuffledIndex(currentQuestionIndex);
  const questionObject = totalQuestions > 0
    ? testData.questions[realIndex]
    : null;

  // Determine if we have an existing answer for the current question
  useEffect(() => {
    if (!questionObject) return;
    const existing = answers.find((a) => a.questionId === questionObject.id);
    if (existing) {
      setSelectedOptionIndex(existing.userAnswerIndex);
      setIsAnswered(existing.userAnswerIndex !== null && existing.userAnswerIndex !== undefined);
    } else {
      setSelectedOptionIndex(null);
      setIsAnswered(false);
    }
  }, [questionObject, answers]);

  /* -----------------------------------------------------
     E) Send partial updates to server after each action
  ----------------------------------------------------- */
  const updateServerProgress = useCallback(async (updatedAnswers, updatedScore, finished = false) => {
    if (!userId) return;
    try {
      await fetch(`/api/test/attempts/${userId}/${testId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          answers: updatedAnswers,
          score: updatedScore,
          totalQuestions,
          category: testData?.category || category,
          currentQuestionIndex,
          shuffleOrder,
          finished
        })
      });
    } catch (err) {
      console.error("Failed to update test attempt on backend", err);
    }
  }, [testId, userId, totalQuestions, testData, category, currentQuestionIndex, shuffleOrder]);

  /* -----------------------------------------------------
     F) Handle Option Click
  ----------------------------------------------------- */
  const handleOptionClick = useCallback(
    async (optionIndex) => {
      if (isAnswered || !questionObject) return;
      setSelectedOptionIndex(optionIndex);

      try {
        const baseXP = testData?.xpPerCorrect || 10;
        const effectiveXP = baseXP * xpBoost;
        const response = await fetch(`/api/test/user/${userId}/submit-answer`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            testId,
            questionId: questionObject.id,
            correctAnswerIndex: questionObject.correctAnswerIndex,
            selectedIndex: optionIndex,
            xpPerCorrect: effectiveXP,
            coinsPerCorrect: 5
          })
        });
        const result = await response.json();
        if (response.ok) {
          const { isCorrect, alreadyCorrect, awardedXP, newXP, newCoins } = result;
          if (isCorrect && !alreadyCorrect && awardedXP > 0) {
            dispatch(setXPAndCoins({ xp: newXP, coins: newCoins }));
          }
          if (isCorrect) {
            const newScore = score + 1;
            setScore(newScore);

            // Update server partial progress
            const updatedAnswers = [...answers];
            const idx = updatedAnswers.findIndex(a => a.questionId === questionObject.id);
            const newAnswerObj = {
              questionId: questionObject.id,
              userAnswerIndex: optionIndex,
              correctAnswerIndex: questionObject.correctAnswerIndex
            };
            if (idx >= 0) updatedAnswers[idx] = newAnswerObj;
            else updatedAnswers.push(newAnswerObj);
            setAnswers(updatedAnswers);

            // if correct, increment local score
            updateServerProgress(updatedAnswers, newScore, false);
          } else {
            // incorrect or no new xp
            const updatedAnswers = [...answers];
            const idx = updatedAnswers.findIndex(a => a.questionId === questionObject.id);
            const newAnswerObj = {
              questionId: questionObject.id,
              userAnswerIndex: optionIndex,
              correctAnswerIndex: questionObject.correctAnswerIndex
            };
            if (idx >= 0) updatedAnswers[idx] = newAnswerObj;
            else updatedAnswers.push(newAnswerObj);
            setAnswers(updatedAnswers);

            updateServerProgress(updatedAnswers, score, false);
          }
        } else {
          console.error("submit-answer error:", result);
        }
      } catch (err) {
        console.error("Failed to submit answer to backend", err);
      }

      setIsAnswered(true);
    },
    [
      isAnswered,
      questionObject,
      testData,
      xpBoost,
      userId,
      testId,
      dispatch,
      score,
      answers,
      updateServerProgress
    ]
  );

  /* -----------------------------------------------------
     G) Next / Previous
  ----------------------------------------------------- */
  const finishTestProcess = useCallback(async () => {
    // finalize local score
    let finalScore = 0;
    answers.forEach((ans) => {
      if (ans.userAnswerIndex === ans.correctAnswerIndex) {
        finalScore++;
      }
    });
    setScore(finalScore);

    // call /attempts/.../finish
    try {
      const res = await fetch(`/api/test/attempts/${userId}/${testId}/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          score: finalScore,
          totalQuestions
        })
      });
      const finishData = await res.json();
      if (finishData.newlyUnlocked && finishData.newlyUnlocked.length > 0) {
        finishData.newlyUnlocked.forEach((achievementId) => {
          const achievement = achievements.find((a) => a.achievementId === achievementId);
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
    } catch (err) {
      console.error("Failed to finish test attempt:", err);
    }

    // Mark local states
    setIsFinished(true);
    setShowScoreOverlay(true);
    setShowReviewMode(true);
  }, [
    answers,
    userId,
    testId,
    totalQuestions,
    achievements
  ]);

  const handleNextQuestion = useCallback(() => {
    if (currentQuestionIndex === totalQuestions - 1) {
      finishTestProcess();
      return;
    }
    // Move to next
    const nextIndex = currentQuestionIndex + 1;
    setCurrentQuestionIndex(nextIndex);
    // Also update server partial progress
    updateServerProgress(answers, score, false);
  }, [
    currentQuestionIndex,
    totalQuestions,
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

  /* -----------------------------------------------------
     H) Skip / Flag
  ----------------------------------------------------- */
  const handleSkipQuestion = () => {
    if (!questionObject) return;
    // Insert or update an answer with userAnswerIndex = null
    const updatedAnswers = [...answers];
    const idx = updatedAnswers.findIndex((a) => a.questionId === questionObject.id);
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
    setIsAnswered(true);
    updateServerProgress(updatedAnswers, score, false);
    handleNextQuestion();
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

  /* -----------------------------------------------------
     I) Restart
  ----------------------------------------------------- */
  const handleRestartTest = useCallback(async () => {
    // remove the attempt doc or mark it as finished so we can start fresh
    // We'll just do the same approach as "new attempt"
    setCurrentQuestionIndex(0);
    setSelectedOptionIndex(null);
    setIsAnswered(false);
    setScore(0);
    setAnswers([]);
    setFlaggedQuestions([]);
    setIsFinished(false);
    setShowReviewMode(false);
    setShowScoreOverlay(false);

    // generate a new shuffle
    if (testData?.questions?.length) {
      const newOrder = shuffleIndices(testData.questions.length);
      setShuffleOrder(newOrder);

      // upsert attempt doc from scratch
      if (userId && testId) {
        await fetch(`/api/test/attempts/${userId}/${testId}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            answers: [],
            score: 0,
            totalQuestions: testData.questions.length,
            category: testData.category || category,
            currentQuestionIndex: 0,
            shuffleOrder: newOrder,
            finished: false
          })
        });
      }
    }
  }, [testData, userId, testId, category]);

  const handleFinishTest = () => {
    finishTestProcess();
  };

  /* -----------------------------------------------------
     J) Review
  ----------------------------------------------------- */
  const handleReviewAnswers = () => {
    setShowReviewMode(true);
    setReviewFilter("all");
  };

  const handleCloseReview = () => {
    if (!isFinished) setShowReviewMode(false);
  };

  const onNextClick = useCallback(() => {
    // if user hasn't answered => show confirm
    if (!isAnswered) {
      setShowNextPopup(true);
    } else {
      handleNextQuestion();
    }
  }, [isAnswered, handleNextQuestion]);

  /* -----------------------------------------------------
     K) Filter for Review Mode
  ----------------------------------------------------- */
  const filteredQuestions = useMemo(() => {
    if (!testData || !testData.questions) return [];
    return testData.questions.filter((q, realIdx) => {
      const userAns = answers.find((a) => a.questionId === q.id);
      const isFlagged = flaggedQuestions.includes(q.id);
      if (!userAns) {
        // user never answered => skip or "no answer"
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
  }, [testData, answers, flaggedQuestions, reviewFilter]);

  /* -----------------------------------------------------
     Overlays & Confirm Popups
  ----------------------------------------------------- */
  // Confirmation Popup
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
        message="Are you sure you want to restart the test? All progress will be lost."
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
        message="Are you sure you want to finish the test now?"
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
    const percentage = totalQuestions
      ? Math.round((score / totalQuestions) * 100)
      : 0;

    return (
      <div className="score-overlay">
        <div className="score-content">
          <h2 className="score-title">Test Complete!</h2>
          <p className="score-details">
            Your score: <strong>{percentage}%</strong> ({score}/{totalQuestions})
          </p>
          <div className="overlay-buttons">
            <button className="restart-button" onClick={() => setShowRestartPopup(true)}>
              Restart Test
            </button>
            <button className="review-button" onClick={handleReviewAnswers}>
              View Review
            </button>
            <button
              className="back-btn"
              onClick={() => navigate(backToListPath)}
            >
              Back to Test List
            </button>
            {Number(testId) < 9999 && (
              <button
                className="next-test-button"
                onClick={() =>
                  navigate(`${backToListPath}/${Number(testId) + 1}`)
                }
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
              Your final score: {score}/{totalQuestions} (
              {totalQuestions
                ? Math.round((score / totalQuestions) * 100)
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
                // no answer
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
                      <strong>Correct Answer:</strong>{" "}
                      {q.options[q.correctAnswerIndex]}
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
                    {isSkipped
                      ? "Skipped"
                      : q.options[userAns.userAnswerIndex]}
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

  /* -----------------------------------------------------
     L) Final Return
  ----------------------------------------------------- */
  if (error) {
    return <div style={{ color: "#fff" }}>Error: {error}</div>;
  }
  if (loadingTest) {
    return <div style={{ color: "#fff" }}>Loading test...</div>;
  }
  if (!testData || !testData.questions || testData.questions.length === 0) {
    return <div style={{ color: "#fff" }}>No questions found.</div>;
  }

  // Determine avatar URL
  let avatarUrl = "https://via.placeholder.com/60";
  if (currentAvatar && shopItems && shopItems.length > 0) {
    const avatarItem = shopItems.find((item) => item._id === currentAvatar);
    if (avatarItem && avatarItem.imageUrl) {
      avatarUrl = avatarItem.imageUrl;
    }
  }

  const progressPercentage = totalQuestions > 0
    ? Math.round(((currentQuestionIndex + 1) / totalQuestions) * 100)
    : 0;

  const progressColorHue = (progressPercentage * 120) / 100;
  const progressColor = `hsl(${progressColorHue}, 100%, 50%)`;

  return (
    <div className="aplus-test-container">
      <ConfettiAnimation trigger={showLevelUpOverlay} level={level} />

      {renderRestartPopup()}
      {renderFinishPopup()}
      {renderNextPopup()}
      {renderScoreOverlay()}
      {renderReviewMode()}

      {/* Top Controls */}
      <div className="top-control-bar">
        <button className="flag-btn" onClick={handleFlagQuestion}>
          {questionObject && flaggedQuestions.includes(questionObject.id)
            ? "Unflag"
            : "Flag"}
        </button>
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
        <button
          className="back-btn"
          onClick={() => navigate(backToListPath)}
        >
          Back to Test List
        </button>
      </div>

      <h1 className="aplus-title">{testData.testName}</h1>

      {/* Avatar + XP + Coins */}
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

      {/* Progress Bar */}
      <div className="progress-container">
        <div
          className="progress-fill"
          style={{ width: `${progressPercentage}%`, background: progressColor }}
        >
          {currentQuestionIndex + 1} / {totalQuestions} ({progressPercentage}%)
        </div>
      </div>

      {/* Main question UI (if not finished/score overlay/review) */}
      {!showScoreOverlay && !showReviewMode && !isFinished && (
        <div className="question-card">
          <div className="question-text">
            {questionObject && questionObject.question}
          </div>
          <ul className="options-list">
            {questionObject.options.map((option, idx) => {
              let optionClass = "option-button";
              const correctIndex = questionObject.correctAnswerIndex;
              if (isAnswered && idx === correctIndex) {
                optionClass += " correct-option";
              } else if (
                isAnswered &&
                idx === selectedOptionIndex &&
                idx !== correctIndex
              ) {
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

          {isAnswered && questionObject && (
            <div className="explanation">
              <strong>
                {selectedOptionIndex === questionObject.correctAnswerIndex
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

export default GlobalTestPage;

