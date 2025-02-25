// GlobalTestPage.js
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
   1) Helper: Shuffle an array
------------------------------------------------------------------ */
function shuffleArray(arr) {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

/* 
   Helper to generate a shuffle of question indices 
*/
function shuffleIndices(length) {
  const indices = Array.from({ length }, (_, i) => i);
  return shuffleArray(indices);
}

/* ------------------------------------------------------------------
   2) Achievements Icon/Color Mappings
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
   3) Dropdown for jumping to a question
------------------------------------------------------------------ */
const QuestionDropdown = ({
  totalQuestions,
  currentQuestionIndex,
  onQuestionSelect,
  answers,
  flaggedQuestions,
  testData,
  shuffleOrder
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

    return {
      isAnswered: answer?.userAnswerIndex !== undefined,
      isSkipped: answer?.userAnswerIndex === null,
      isCorrect: answer?.userAnswerIndex === question.correctAnswerIndex,
      isFlagged
    };
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
                className={`dropdown-item ${
                  i === currentQuestionIndex ? "active" : ""
                }`}
              >
                <span>Question {i + 1}</span>
                <div className="status-indicators">
                  {status.isSkipped && <span className="skip-indicator">⏭️</span>}
                  {status.isFlagged && <span className="flag-indicator">🚩</span>}
                  {status.isAnswered && !status.isSkipped && (
                    <span
                      className={`answer-indicator ${
                        status.isCorrect ? "correct" : "incorrect"
                      }`}
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

/* ------------------------------------------------------------------
   4) The Main "GlobalTestPage" with both question-shuffle & answer-shuffle
------------------------------------------------------------------ */
const GlobalTestPage = ({
  testId,
  category,
  backToListPath
}) => {
  const location = useLocation();
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

  // Local states for test logic
  const [testData, setTestData] = useState(null);
  const [shuffleOrder, setShuffleOrder] = useState([]); // question shuffle
  const [answerOrder, setAnswerOrder] = useState([]);   // array-of-arrays for answer choices
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

  useEffect(() => {
    if (shopStatus === "idle") {
      dispatch(fetchShopItems());
    }
  }, [shopStatus, dispatch]);

  // This is the main fetch that loads or creates the attempt doc
  const fetchTestAndAttempt = async () => {
    setLoadingTest(true);
    try {
      let attemptDoc = null;
      if (userId) {
        const attemptRes = await fetch(`/api/test/attempts/${userId}/${testId}`);
        const attemptData = await attemptRes.json();
        attemptDoc = attemptData.attempt || null;
      }

      // fetch the actual test doc
      const testRes = await fetch(`/api/test/tests/${category}/${testId}`);
      if (!testRes.ok) {
        const errData = await testRes.json().catch(() => ({}));
        throw new Error(errData.error || "Failed to fetch test data");
      }
      const testDoc = await testRes.json();
      setTestData(testDoc);

      const totalQ = testDoc.questions.length;

      if (attemptDoc) {
        // We have partial or finished attempt
        setAnswers(attemptDoc.answers || []);
        setScore(attemptDoc.score || 0);
        setIsFinished(attemptDoc.finished === true);

        // question shuffle
        if (attemptDoc.shuffleOrder && attemptDoc.shuffleOrder.length > 0) {
          setShuffleOrder(attemptDoc.shuffleOrder);
        } else {
          const newQOrder = shuffleIndices(totalQ);
          setShuffleOrder(newQOrder);
        }

        // ANSWER CHOICES shuffle
        if (attemptDoc.answerOrder && attemptDoc.answerOrder.length === totalQ) {
          // re-use existing
          setAnswerOrder(attemptDoc.answerOrder);
        } else {
          // generate brand-new
          const generatedAnswerOrder = testDoc.questions.map((q) => {
            const numOptions = q.options.length;
            // create an array [0,1,2,3,...], shuffle
            return shuffleArray([...Array(numOptions).keys()]);
          });
          setAnswerOrder(generatedAnswerOrder);
        }

        // current question index
        setCurrentQuestionIndex(attemptDoc.currentQuestionIndex || 0);
      } else {
        // brand new attempt
        setScore(0);
        setAnswers([]);
        setIsFinished(false);
        setCurrentQuestionIndex(0);

        // generate question shuffle
        const newQOrder = shuffleIndices(totalQ);
        setShuffleOrder(newQOrder);

        // generate answer shuffle
        const generatedAnswerOrder = testDoc.questions.map((q) => {
          const numOptions = q.options.length;
          return shuffleArray([...Array(numOptions).keys()]);
        });
        setAnswerOrder(generatedAnswerOrder);

        // upsert attempt doc if user is logged in
        if (userId) {
          await fetch(`/api/test/attempts/${userId}/${testId}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              answers: [],
              score: 0,
              totalQuestions: totalQ,
              category: testDoc.category || category,
              currentQuestionIndex: 0,
              shuffleOrder: newQOrder,
              answerOrder: generatedAnswerOrder, // <-- storing newly generated
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

  // Confetti if user levels up
  useEffect(() => {
    if (level > localLevel) {
      setLocalLevel(level);
      setShowLevelUpOverlay(true);
      const t = setTimeout(() => setShowLevelUpOverlay(false), 3000);
      return () => clearTimeout(t);
    }
  }, [level, localLevel]);

  // If navigated with { state: { review: true } } and test is finished => show review
  useEffect(() => {
    if (location.state?.review && isFinished) {
      setShowReviewMode(true);
    }
  }, [location.state, isFinished]);

  // Basic helper to get the question index from shuffle
  const getShuffledIndex = useCallback(
    (i) => {
      if (!shuffleOrder || shuffleOrder.length === 0) return i;
      return shuffleOrder[i];
    },
    [shuffleOrder]
  );

  // We have totalQuestions, realIndex, questionObject
  const totalQuestions = testData?.questions?.length || 0;
  const realIndex = getShuffledIndex(currentQuestionIndex);
  const questionObject = totalQuestions > 0
    ? testData.questions[realIndex]
    : null;

  // On each new question, figure out if we had answered it
  useEffect(() => {
    if (!questionObject) return;
    const existing = answers.find((a) => a.questionId === questionObject.id);
    if (existing) {
      setSelectedOptionIndex(null);
      if (
        existing.userAnswerIndex !== null &&
        existing.userAnswerIndex !== undefined
      ) {
        // Need to find which "display index" that corresponds to in the shuffled answer array
        const displayIndex = answerOrder[realIndex].indexOf(existing.userAnswerIndex);
        if (displayIndex >= 0) {
          setSelectedOptionIndex(displayIndex);
          setIsAnswered(true);
        } else {
          // Some mismatch
          setIsAnswered(false);
        }
      } else {
        // It's "skipped"
        setIsAnswered(true);
      }
    } else {
      setSelectedOptionIndex(null);
      setIsAnswered(false);
    }
  }, [questionObject, answers, realIndex, answerOrder]);

  // We'll store partial attempt in the server
   const updateServerProgress = useCallback(
     async (updatedAnswers, updatedScore, finished = false, singleAnswer = null) => {
       if (!userId) return;
       try {
         // If we're sending a single answer update
         if (singleAnswer) {
           await fetch(`/api/test/attempts/${userId}/${testId}/answer`, {
             method: "POST",
             headers: { "Content-Type": "application/json" },
             body: JSON.stringify({
               questionId: singleAnswer.questionId,
               userAnswerIndex: singleAnswer.userAnswerIndex,
               correctAnswerIndex: singleAnswer.correctAnswerIndex,
               score: updatedScore
             })
           });
           return;
         }
         
         // For navigation position updates (much smaller payload)
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
     [userId, testId, currentQuestionIndex]
   );

  /* ------------------------------------------------------------------
     5) Handling a user answer
  ------------------------------------------------------------------ */
  const handleOptionClick = useCallback(
    async (displayOptionIndex) => {
      // e.g. user clicked the "2nd" visible choice, 
      // so find the "actual" answer index from answerOrder
      if (isAnswered || !questionObject) return;
      const actualAnswerIndex = answerOrder[realIndex][displayOptionIndex];
      setSelectedOptionIndex(displayOptionIndex);

      try {
        // normal scoring logic
        const baseXP = testData?.xpPerCorrect || 10;
        const effectiveXP = baseXP * xpBoost;
        const response = await fetch(`/api/test/user/${userId}/submit-answer`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            testId,
            questionId: questionObject.id,
            correctAnswerIndex: questionObject.correctAnswerIndex,
            selectedIndex: actualAnswerIndex, // store the "true" index
            xpPerCorrect: effectiveXP,
            coinsPerCorrect: 5
          })
        });
        const result = await response.json();
        if (response.ok) {
          const {
            isCorrect,
            alreadyCorrect,
            awardedXP,
            newXP,
            newCoins
          } = result;
          // if it’s newly correct, update user xp + coins
          if (isCorrect && !alreadyCorrect && awardedXP > 0) {
            dispatch(setXPAndCoins({ xp: newXP, coins: newCoins }));
          }
          // update local score
          let newScore = score;
          if (isCorrect) {
            newScore = score + 1;
            setScore(newScore);
          }

          // update our local "answers"
          const updatedAnswers = [...answers];
          const idx = updatedAnswers.findIndex(a => a.questionId === questionObject.id);
          if (idx >= 0) {
            updatedAnswers[idx] = newAnswerObj;
          } else {
            updatedAnswers.push(newAnswerObj);
          }
          setAnswers(updatedAnswers);
            
            
          );
          const newAnswerObj = {
            questionId: questionObject.id,
            userAnswerIndex: actualAnswerIndex,       // store the real index
            correctAnswerIndex: questionObject.correctAnswerIndex
          };
          if (idx >= 0) {
            updatedAnswers[idx] = newAnswerObj;
          } else {
            updatedAnswers.push(newAnswerObj);
          }
          setAnswers(updatedAnswers);

          // update partial attempt
          updateServerProgress(updatedAnswers, newScore, false);
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
      updateServerProgress,
      realIndex,
      answerOrder
    ]
  );

  /* ------------------------------------------------------------------
     6) Finishing the test
  ------------------------------------------------------------------ */
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
          totalQuestions
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
    } catch (err) {
      console.error("Failed to finish test attempt:", err);
    }

    setIsFinished(true);
    setShowScoreOverlay(true);
    setShowReviewMode(true);
  }, [answers, userId, testId, totalQuestions, achievements]);

  const handleNextQuestion = useCallback(() => {
    if (currentQuestionIndex === totalQuestions - 1) {
      finishTestProcess();
      return;
    }
    const nextIndex = currentQuestionIndex + 1;
    setCurrentQuestionIndex(nextIndex);
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

  /* ------------------------------------------------------------------
     7) Skipping / Flagging
  ------------------------------------------------------------------ */
  const handleSkipQuestion = () => {
    if (!questionObject) return;
    const updatedAnswers = [...answers];
    const idx = updatedAnswers.findIndex(
      (a) => a.questionId === questionObject.id
    );
    // store userAnswerIndex=null to mark “skipped”
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

  /* ------------------------------------------------------------------
     8) Restart
  ------------------------------------------------------------------ */
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

    if (testData?.questions?.length) {
      // new question shuffle
      const newOrder = shuffleIndices(testData.questions.length);
      setShuffleOrder(newOrder);

      // new answer shuffle
      const newAnswerOrder = testData.questions.map((q) => {
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
            category: testData.category || category,
            currentQuestionIndex: 0,
            shuffleOrder: newOrder,
            answerOrder: newAnswerOrder,
            finished: false
          })
        });
      }
    }
  }, [testData, userId, testId, category]);

  const handleFinishTest = () => {
    finishTestProcess();
  };

  /* ------------------------------------------------------------------
     9) Review
  ------------------------------------------------------------------ */
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
    return testData.questions.filter((q) => {
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
  }, [testData, answers, flaggedQuestions, reviewFilter]);

  /* ------------------------------------------------------------------
     10) Confirmation Popups & Overlays
  ------------------------------------------------------------------ */
  const ConfirmPopup = ({ message, onConfirm, onCancel }) => (
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
            <button
              className="restart-button"
              onClick={() => setShowRestartPopup(true)}
            >
              Restart Test
            </button>
            <button
              className="review-button"
              onClick={handleReviewAnswers}
            >
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

  /* ------------------------------------------------------------------
     11) Final Render
  ------------------------------------------------------------------ */
  if (error) {
    return <div style={{ color: "#fff" }}>Error: {error}</div>;
  }
  if (loadingTest) {
    return <div style={{ color: "#fff" }}>Loading test...</div>;
  }
  if (!testData || !testData.questions || testData.questions.length === 0) {
    return <div style={{ color: "#fff" }}>No questions found.</div>;
  }

  // figure out user avatar
  let avatarUrl = "https://via.placeholder.com/60";
  if (currentAvatar && shopItems && shopItems.length > 0) {
    const avatarItem = shopItems.find((item) => item._id === currentAvatar);
    if (avatarItem && avatarItem.imageUrl) {
      avatarUrl = avatarItem.imageUrl;
    }
  }

  // progress bar color
  const progressPercentage = totalQuestions
    ? Math.round(((currentQuestionIndex + 1) / totalQuestions) * 100)
    : 0;
  const progressColorHue = (progressPercentage * 120) / 100;
  const progressColor = `hsl(${progressColorHue}, 100%, 50%)`;

  // build "display" options for the current question from answerOrder
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
          totalQuestions={totalQuestions}
          currentQuestionIndex={currentQuestionIndex}
          onQuestionSelect={(index) => {
            setCurrentQuestionIndex(index);
            updateServerProgress(answers, score, false);
          }}
          answers={answers}
          flaggedQuestions={flaggedQuestions}
          testData={testData}
          shuffleOrder={shuffleOrder}
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
        <button
          className="back-btn"
          onClick={() => navigate(backToListPath)}
        >
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
          {currentQuestionIndex + 1} / {totalQuestions} ({progressPercentage}%)
        </div>
      </div>

      {/* The main question UI if not finished or reviewing */}
      {!showScoreOverlay && !showReviewMode && !isFinished && (
        <div className="question-card">
          <div className="question-text">
            {questionObject && questionObject.question}
          </div>
          <ul className="options-list">
            {displayedOptions.map((option, displayIdx) => {
              let optionClass = "option-button";
              const correctIndex = questionObject.correctAnswerIndex;
              const actualIndex = answerOrder[realIndex][displayIdx];

              if (isAnswered && actualIndex === correctIndex) {
                // highlight the correct option
                optionClass += " correct-option";
              } else if (
                isAnswered &&
                displayIdx === selectedOptionIndex &&
                actualIndex !== correctIndex
              ) {
                // user-chosen is wrong
                optionClass += " incorrect-option";
              }

              return (
                <li className="option-item" key={displayIdx}>
                  <button
                    className={optionClass}
                    onClick={() => handleOptionClick(displayIdx)}
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
              {currentQuestionIndex === totalQuestions - 1 ? (
                <button className="next-question-btn" onClick={handleNextQuestion}>
                  Finish Test
                </button>
              ) : (
                <button className="next-question-btn" onClick={handleNextQuestion}>
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

