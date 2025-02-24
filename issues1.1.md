

i need to add a daily bonus hwere you get 1000 coins. it will have a page on the sdiabr called like daily bonus and says "laim bonus" and if you click the button it give syou 1000 coins, and it resets every 24 hours so everyday yiou can go to the page and claim 1000 coins, obvisolsy it has to be unqiue to the user.

Review button

so if you forgot about my testlist pages here they are but i woudl rathe redit it gloablly through teh gloabl test page if possible that edit all my testlist pages unles thats teh issue on why it doesnt show the progress or finished tests/score with buttons to do the review or restart it. becaus ei really like how it keepsd the users progress and stuff exactly how it is now across all broswers and stuff but only issue is it wont show it for the testlist test boxes- so heres teh testlist if thats absolutly the issue (keep in mind i have 13 testlists but im showing you one as an aexample becasue tehy are all pretty similkar)




import React from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import GlobalTestPage from "../../GlobalTestPage";

import "../../test.css";

const APlusTestList = () => {
  const navigate = useNavigate();
  const totalQuestions = 100; 
  const { userId } = useSelector((state) => state.user);


  const category = "aplus";

  // Retrieve saved progress from localStorage
  const getProgressData = (testNumber) => {
    if (!userId) return null;
    const key = `testProgress_${userId}_${category}_${testNumber}`;
    const saved = localStorage.getItem(key);
    if (!saved) return null;
    try {
      return JSON.parse(saved);
    } catch (e) {
      console.error("Error parsing progress", e);
      return null;
    }
  };

  const getProgressDisplay = (testNumber) => {
    const progressData = getProgressData(testNumber);
    if (progressData) {
      if (progressData.finished) {
        const percentage = Math.round(
          (progressData.score / totalQuestions) * 100
        );
        return `Final Score: ${percentage}% (${progressData.score}/${totalQuestions})`;
      } else if (typeof progressData.currentQuestionIndex === "number") {
        return `Progress: ${
          progressData.currentQuestionIndex + 1
        } / ${totalQuestions}`;
      }
    }
    return "No progress yet";
  };

  // Simple difficulty mapping (optional)
  const getDifficultyData = (testNumber) => {
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
    return data[testNumber] || { label: "", color: "#fff" };
  };

  return (
    <div className="tests-list-container">
      <h1 className="tests-list-title">CompTIA A+ Core 1 Practice Tests</h1>
      <div className="tests-list-grid">
        {Array.from({ length: 10 }, (_, i) => {
          const testNumber = i + 1;
          const difficulty = getDifficultyData(testNumber);
          const progressData = getProgressData(testNumber);
          const progressDisplay = getProgressDisplay(testNumber);

          return (
            <div key={testNumber} className="test-card">
              <div className="test-badge">Test {testNumber}</div>
              <div
                className="difficulty-label"
                style={{ color: difficulty.color }}
              >
                {difficulty.label}
              </div>
              <p className="test-progress">{progressDisplay}</p>

              {progressData ? (
                <div className="test-card-buttons">
                  {progressData.finished ? (
                    <>
                      <button
                        className="resume-button"
                        onClick={() =>
                          navigate(`/practice-tests/a-plus/${testNumber}`)
                        }
                      >
                        View Review
                      </button>
                      <button
                        className="restart-button-testlist"
                        onClick={() => {
                          const key = `testProgress_${userId}_${category}_${testNumber}`;
                          localStorage.removeItem(key);
                          navigate(`/practice-tests/a-plus/${testNumber}`);
                        }}
                      >
                        Restart Test
                      </button>
                    </>
                  ) : (
                    <>
                      <button
                        className="resume-button"
                        onClick={() =>
                          navigate(`/practice-tests/a-plus/${testNumber}`)
                        }
                      >
                        Resume Test
                      </button>
                      <button
                        className="restart-button-testlist"
                        onClick={() => {
                          const key = `testProgress_${userId}_${category}_${testNumber}`;
                          localStorage.removeItem(key);
                          navigate(`/practice-tests/a-plus/${testNumber}`);
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
                  onClick={() =>
                    navigate(`/practice-tests/a-plus/${testNumber}`)
                  }
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

export default APlusTestList;

and heres teh unique test pages for each test
// APlusTestPage.js
import React from "react";
import { useParams } from "react-router-dom";
import APlusTestList from "./APlusTestList";  // your existing test list component
import GlobalTestPage from "../../GlobalTestPage"; // the new universal logic
import "../../test.css";

const APlusTestPage = () => {
  const { testId } = useParams();

  // If no testId in URL, show the test list
  if (!testId) {
    return <APlusTestList />;
  }

  // Otherwise, show the universal test runner
  return (
    <GlobalTestPage
      testId={testId}
      category="aplus"
      backToListPath="/practice-tests/a-plus"
    />
  );
};

export default APlusTestPage;


here is my gloabltestpage

// GlobalTestPage.js
import React, {
  useState,
  useEffect,
  useCallback,
  useMemo,
  useRef
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

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const getQuestionStatus = (index) => {
    const realIndex = shuffleOrder[index];
    const question = testData.questions[realIndex];
    const answer = answers.find(a => a.questionId === question.id);
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
                className={`dropdown-item ${i === currentQuestionIndex ? 'active' : ''}`}
              >
                <span>Question {i + 1}</span>
                <div className="status-indicators">
                  {status.isSkipped && <span className="skip-indicator">⏭️</span>}
                  {status.isFlagged && <span className="flag-indicator">🚩</span>}
                  {status.isAnswered && !status.isSkipped && (
                    <span className={`answer-indicator ${status.isCorrect ? 'correct' : 'incorrect'}`}>
                      {status.isCorrect ? '✓' : '✗'}
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



here is relavant backend files aswell
# database.py
from flask import Flask
from flask_pymongo import PyMongo
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

# MongoDB Connection
app.config["MONGO_URI"] = os.getenv("MONGO_URI")  
mongo = PyMongo(app)

db = mongo.db

# Existing collections
mainusers_collection = db.mainusers
shop_collection = db.shopItems
achievements_collection = db.achievements
tests_collection = db.tests

# NEW collections for attempts and correct answers:
testAttempts_collection = db.testAttempts
correctAnswers_collection = db.correctAnswers




from bson.objectid import ObjectId
from datetime import datetime, timedelta
from collections import defaultdict
import math
import re
import unicodedata

# Import the new collections from database
from mongodb.database import (
    mainusers_collection,
    shop_collection,
    achievements_collection,
    tests_collection,
    testAttempts_collection,
    correctAnswers_collection
)

##############################################
# very complex Input Sanitization Helpers
##############################################

import re
import unicodedata

# Example small dictionary of very common passwords
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "letmein", "welcome"
}

def has_forbidden_unicode_scripts(s):
    """
    Disallow characters from certain Unicode blocks 
    (private use areas, surrogates, etc.).
    """
    private_use_ranges = [
        (0xE000, 0xF8FF),
        (0xF0000, 0xFFFFD),
        (0x100000, 0x10FFFD)
    ]
    surrogates_range = (0xD800, 0xDFFF)

    for ch in s:
        code_point = ord(ch)
        # Surrogates
        if surrogates_range[0] <= code_point <= surrogates_range[1]:
            return True
        # Private use ranges
        for start, end in private_use_ranges:
            if start <= code_point <= end:
                return True
    return False

def disallow_mixed_scripts(s):
    """
    Example check for mixing major scripts (Latin + Cyrillic, etc.).
    Returns True if it detects more than one script in the string.
    """
    script_sets = set()

    for ch in s:
        cp = ord(ch)
        # Basic Latin and extended ranges:
        if 0x0041 <= cp <= 0x024F:
            script_sets.add("Latin")
        # Greek
        elif 0x0370 <= cp <= 0x03FF:
            script_sets.add("Greek")
        # Cyrillic
        elif 0x0400 <= cp <= 0x04FF:
            script_sets.add("Cyrillic")

        # If more than one distinct script is found
        if len(script_sets) > 1:
            return True

    return False

def validate_username(username):
    """
    Validates a username with very strict rules:
      1. Normalize (NFC).
      2. Length 3..30.
      3. No control chars, no private-use/surrogates, no mixing scripts.
      4. Only [A-Za-z0-9._-], no triple repeats, no leading/trailing punctuation.
    Returns: (True, []) if valid, else (False, [list of error messages]).
    """
    errors = []
    username_nfc = unicodedata.normalize("NFC", username)

    # 1) Check length
    if not (3 <= len(username_nfc) <= 30):
        errors.append("Username must be between 3 and 30 characters long.")

    # 2) Forbidden Unicode script checks
    if has_forbidden_unicode_scripts(username_nfc):
        errors.append("Username contains forbidden Unicode blocks (private use or surrogates).")

    # 3) Disallow mixing multiple major scripts
    if disallow_mixed_scripts(username_nfc):
        errors.append("Username cannot mix multiple Unicode scripts (e.g., Latin & Cyrillic).")

    # 4) Forbid control chars [0..31, 127] + suspicious punctuation
    forbidden_ranges = [(0, 31), (127, 127)]
    forbidden_chars = set(['<', '>', '\\', '/', '"', "'", ';', '`',
                           ' ', '\t', '\r', '\n'])
    for ch in username_nfc:
        cp = ord(ch)
        if any(start <= cp <= end for (start, end) in forbidden_ranges):
            errors.append("Username contains forbidden control characters (ASCII 0-31 or 127).")
            break
        if ch in forbidden_chars:
            errors.append("Username contains forbidden characters like <, >, or whitespace.")
            break

    # 5) Strict allowlist pattern
    pattern = r'^[A-Za-z0-9._-]+$'
    if not re.match(pattern, username_nfc):
        errors.append("Username can only contain letters, digits, underscores, dashes, or dots.")

    # 6) Disallow triple identical consecutive characters
    if re.search(r'(.)\1{2,}', username_nfc):
        errors.append("Username cannot contain three identical consecutive characters.")

    # 7) Disallow leading or trailing punctuation
    if re.match(r'^[._-]|[._-]$', username_nfc):
        errors.append("Username cannot start or end with . - or _.")

    if errors:
        return False, errors
    return True, []

def validate_password(password, username=None, email=None):
    """
    Validates a password with very strict rules:
      1. 12..128 length.
      2. Disallow whitespace, <, >.
      3. Require uppercase, lowercase, digit, special char.
      4. Disallow triple repeats.
      5. Check common/breached password list.
      6. Disallow 'password', 'qwerty', etc.
      7. Disallow if username or email local part is in the password.
    Returns: (True, []) if valid, else (False, [list of error messages]).
    """
    errors = []
    length = len(password)

    # 1) Length
    if not (6 <= length <= 69):
        errors.append("Password must be between 6 and 69 characters long.")

    # 2) Disallowed whitespace or < >
    if any(ch in password for ch in [' ', '<', '>', '\t', '\r', '\n']):
        errors.append("Password cannot contain whitespace or < or > characters.")

    # 3) Complexity checks
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit.")

    # We define a broad set of allowed special chars
    special_pattern = r'[!@#$%^&*()\-_=+\[\]{}|;:\'",<.>/?`~\\]'
    if not re.search(special_pattern, password):
        errors.append("Password must contain at least one special character.")

    # 4) Disallow triple identical consecutive characters
    if re.search(r'(.)\1{2,}', password):
        errors.append("Password must not contain three identical consecutive characters.")

    # 5) Convert to lowercase for simplified checks
    password_lower = password.lower()

    # Check against common password list
    if password_lower in COMMON_PASSWORDS:
        errors.append("Password is too common. Please choose a stronger password.")

    # 6) Disallow certain dictionary words
    dictionary_patterns = ['password', 'qwerty', 'abcdef', 'letmein', 'welcome', 'admin']
    for pat in dictionary_patterns:
        if pat in password_lower:
            errors.append(f"Password must not contain the word '{pat}'.")

    # 7) Disallow if password contains username or email local-part
    if username:
        if username.lower() in password_lower:
            errors.append("Password must not contain your username.")

    if email:
        email_local_part = email.split('@')[0].lower()
        if email_local_part in password_lower:
            errors.append("Password must not contain the local part of your email address.")

    if errors:
        return False, errors
    return True, []

def validate_email(email):
    """
    Validates an email with strict rules:
      1. Normalize (NFC), strip whitespace.
      2. 5..69 length.
      3. No control chars, <, >, etc.
      4. Exactly one @.
    Returns: (True, []) if valid, else (False, [list of error messages]).
    """
    errors = []
    email_nfc = unicodedata.normalize("NFC", email.strip())

    # 1) Length check
    if not (5 <= len(email_nfc) <= 69):
        errors.append("Email length must be between 6 and 69 characters.")

    # 3) Forbid suspicious ASCII
    forbidden_ascii = set(['<','>','`',';',' ', '\t','\r','\n','"',"'", '\\'])
    for ch in email_nfc:
        if ch in forbidden_ascii:
            errors.append("Email contains forbidden characters like <, >, or whitespace.")
            break

    # 4) Must have exactly one @
    if email_nfc.count('@') != 1:
        errors.append("Email must contain exactly one '@' symbol.")

    if errors:
        return False, errors
    return True, []

##############################################
# User Retrieval Helpers
##############################################

def get_user_by_username(username):
    return mainusers_collection.find_one({"username": username})

def get_user_by_identifier(identifier):
    if "@" in identifier:
        return mainusers_collection.find_one({"email": identifier})
    else:
        return get_user_by_username(identifier)

def get_user_by_id(user_id):
    """
    Retrieves a user by ID. Returns None if invalid or not found.
    """
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    return mainusers_collection.find_one({"_id": oid})

##############################################
# Create User
##############################################

def create_user(user_data):
    """
    Creates a new user document, setting default fields including coins, xp, level,
    purchasedItems, xpBoost, etc. Also automatically equips a default avatar if found.
    """
    existing_user = mainusers_collection.find_one({
        "$or": [
            {"username": user_data["username"]},
            {"email": user_data["email"]}
        ]
    })
    if existing_user:
        raise ValueError("Username or email is already taken")

    # Set defaults for new user:
    user_data.setdefault("coins", 0)
    user_data.setdefault("xp", 0)
    user_data.setdefault("level", 1)
    user_data.setdefault("achievements", [])
    user_data.setdefault("subscriptionActive", False)
    user_data.setdefault("subscriptionPlan", None)
    user_data.setdefault("lastDailyClaim", None)
    user_data.setdefault("purchasedItems", [])
    user_data.setdefault("xpBoost", 1.0)
    user_data.setdefault("currentAvatar", None)
    user_data.setdefault("nameColor", None)

    # Auto-equip default avatar if cost=null
    default_avatar = shop_collection.find_one({"type": "avatar", "cost": None})
    if default_avatar:
        user_data["currentAvatar"] = default_avatar["_id"]
        if default_avatar["_id"] not in user_data["purchasedItems"]:
            user_data["purchasedItems"].append(default_avatar["_id"])

    result = mainusers_collection.insert_one(user_data)
    return result.inserted_id

##############################################
# Update User Fields (CRITICAL)
##############################################

def update_user_fields(user_id, fields):
    """
    Generic helper to update given `fields` (dict) in mainusers_collection.
    """
    try:
        oid = ObjectId(user_id)
    except:
        return None
    mainusers_collection.update_one(
        {"_id": oid},
        {"$set": fields}
    )
    return True

##############################################
# Update User Coins
##############################################

def update_user_coins(user_id, amount):
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    mainusers_collection.update_one({"_id": oid}, {"$inc": {"coins": amount}})

##############################################
# Leveling System
##############################################
# Levels 2–30: +500 XP each
# Levels 31–60: +750 XP each
# Levels 61–100: +1000 XP each
# Above 100: +1500 XP each

def xp_required_for_level(level):
    """
    Returns total XP required to be at `level`.
    Level 1 starts at 0 XP.
    """
    if level < 1:
        return 0
    if level == 1:
        return 0
    if level <= 30:
        return 500 * (level - 1)
    elif level <= 60:
        base = 500 * 29  # up to level 30
        return base + 750 * (level - 30)
    elif level <= 100:
        base = 500 * 29 + 750 * 30  # up to level 60
        return base + 1000 * (level - 60)
    else:
        base = 500 * 29 + 750 * 30 + 1000 * 40  # up to level 100
        return base + 1500 * (level - 100)

def update_user_xp(user_id, xp_to_add):
    """
    Adds xp_to_add to the user's XP. Then, while the new XP total
    is >= XP required for the next level, increments the level.
    """
    user = get_user_by_id(user_id)
    if not user:
        return None

    old_xp = user.get("xp", 0)
    old_level = user.get("level", 1)
    new_xp = old_xp + xp_to_add
    new_level = old_level

    while new_xp >= xp_required_for_level(new_level + 1):
        new_level += 1

    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"xp": new_xp, "level": new_level}}
    )
    return {"xp": new_xp, "level": new_level}

##############################################
# Daily Bonus
##############################################

def apply_daily_bonus(user_id):
    """
    If the user hasn't claimed daily bonus in the last 24 hours,
    +50 coins, update lastDailyClaim
    """
    user = get_user_by_id(user_id)
    if not user:
        return None

    now = datetime.utcnow()
    last_claimed = user.get("lastDailyClaim")
    if not last_claimed or (now - last_claimed) > timedelta(hours=24):
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$inc": {"coins": 50}, "$set": {"lastDailyClaim": now}}
        )
        return {"success": True, "message": "Daily bonus applied"}
    else:
        return {"success": False, "message": "Already claimed daily bonus"}

##############################################
# Shop Logic
##############################################

def get_shop_items():
    """
    Returns all shop items from shop_collection,
    in ascending order by title (or another field),
    to ensure stable ordering.
    """
    return list(shop_collection.find({}).sort("title", 1))

def purchase_item(user_id, item_id):
    """
    Purchase an item from the shop:
      1) Check user has enough coins
      2) Ensure item not already purchased
      3) Deduct cost, add to purchasedItems
      4) If xpBoost, set user's xpBoost
      5) If avatar or nameColor, optionally set that field
    """
    user = get_user_by_id(user_id)
    if not user:
        return {"success": False, "message": "User not found"}

    try:
        oid = ObjectId(item_id)
    except Exception:
        return {"success": False, "message": "Invalid item ID"}

    item = shop_collection.find_one({"_id": oid})
    if not item:
        return {"success": False, "message": "Item not found"}

    user_coins = user.get("coins", 0)
    cost = item.get("cost", 0) if item.get("cost") is not None else 0
    if user_coins < cost:
        return {"success": False, "message": "Not enough coins"}

    purchased = user.get("purchasedItems", [])
    if oid in purchased:
        return {"success": False, "message": "Item already purchased"}

    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$inc": {"coins": -cost}}
    )
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$addToSet": {"purchasedItems": oid}}
    )

    item_type = item.get("type")
    if item_type == "xpBoost":
        new_boost = item.get("effectValue", 1.0)
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"xpBoost": new_boost}}
        )
    elif item_type == "avatar":
        pass
    elif item_type == "nameColor":
        new_color = item.get("effectValue", None)
        mainusers_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"nameColor": new_color}}
        )

    return {"success": True, "message": "Purchase successful"}

##############################################
# Achievements
##############################################

def get_achievements():
    return list(achievements_collection.find({}))

def get_test_by_id_and_category(test_id, category):
    """
    Fetch a single test doc by integer testId field and category field.
    """
    try:
        test_id_int = int(test_id)
    except:
        return None
    return tests_collection.find_one({
        "testId": test_id_int,
        "category": category
    })

def check_and_unlock_achievements(user_id):
    """
    Checks the user's progress by querying testAttempts_collection to see:
      - How many tests are finished (total_finished)
      - How many are perfect (perfect_tests)
      - Their percentage on each finished test
      - If they've done certain minScores, consecutive perfects, etc.
      - Summation of total questions answered across all finished attempts

    Then unlocks achievements as needed, returning newly_unlocked achievementIds.
    """

    user = get_user_by_id(user_id)
    if not user:
        return []

    user_oid = user["_id"]

    # 1) Count how many finished attempts the user has
    total_finished = testAttempts_collection.count_documents({
        "userId": user_oid,
        "finished": True
    })

    # 2) Count how many are perfect (score == totalQuestions)
    perfect_tests = testAttempts_collection.count_documents({
        "userId": user_oid,
        "finished": True,
        "$expr": {"$eq": ["$score", "$totalQuestions"]}
    })

    # 3) Fetch all finished attempts
    finished_cursor = testAttempts_collection.find(
        {"userId": user_oid, "finished": True}
    )
    finished_tests = []
    for doc in finished_cursor:
        tq = doc.get("totalQuestions", 0)
        sc = doc.get("score", 0)
        pct = (sc / tq) * 100 if tq else 0
        cat = doc.get("category", "global")
        finished_at = doc.get("finishedAt", None)
        finished_tests.append({
            "test_id": doc.get("testId", "0"),
            "score": sc,
            "totalQuestions": tq,
            "percentage": pct,
            "category": cat,
            "finishedAt": finished_at
        })

    from datetime import datetime
    finished_tests.sort(
        key=lambda x: x["finishedAt"] if x["finishedAt"] else datetime(1970,1,1)
    )

    max_consecutive = 0
    current_streak = 0
    for ft in finished_tests:
        if ft["percentage"] == 100:
            current_streak += 1
            if current_streak > max_consecutive:
                max_consecutive = current_streak
        else:
            current_streak = 0

    from collections import defaultdict
    category_groups = defaultdict(list)
    for ft in finished_tests:
        category_groups[ft["category"]].append(ft)

    sum_of_questions = sum(ft["totalQuestions"] for ft in finished_tests)

    TOTAL_TESTS = 130
    TOTAL_QUESTIONS = 10000

    user_coins = user.get("coins", 0)
    user_level = user.get("level", 1)

    unlocked = user.get("achievements", [])
    newly_unlocked = []

    all_ach = get_achievements()

    for ach in all_ach:
        aid = ach["achievementId"]
        criteria = ach.get("criteria", {})

        if aid in unlocked:
            continue

        # testCount
        if "testCount" in criteria:
            if total_finished >= criteria["testCount"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # coins
        if "coins" in criteria:
            if user_coins >= criteria["coins"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # level
        if "level" in criteria:
            if user_level >= criteria["level"]:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # perfectTests
        if "perfectTests" in criteria:
            needed = criteria["perfectTests"]
            if perfect_tests >= needed:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # consecutivePerfects
        if "consecutivePerfects" in criteria:
            needed = criteria["consecutivePerfects"]
            if max_consecutive >= needed:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # allTestsCompleted
        if "allTestsCompleted" in criteria and criteria["allTestsCompleted"] is True:
            if total_finished >= TOTAL_TESTS:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # testsCompletedInCategory
        if "testsCompletedInCategory" in criteria:
            needed = criteria["testsCompletedInCategory"]
            for ccat, attempts in category_groups.items():
                if len(attempts) >= needed:
                    unlocked.append(aid)
                    newly_unlocked.append(aid)
                    break

        # redemption_arc => minScoreBefore & minScoreAfter
        if ("minScoreBefore" in criteria and "minScoreAfter" in criteria
                and aid not in unlocked):
            min_before = criteria["minScoreBefore"]
            min_after = criteria["minScoreAfter"]
            low_test = any(ft["percentage"] <= min_before for ft in finished_tests)
            high_test = any(ft["percentage"] >= min_after for ft in finished_tests)
            if low_test and high_test:
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # minScore => e.g. "accuracy_king"
        if "minScore" in criteria:
            needed = criteria["minScore"]
            if any(ft["percentage"] >= needed for ft in finished_tests):
                unlocked.append(aid)
                newly_unlocked.append(aid)

        # minScoreGlobal => e.g. "exam_conqueror"
        if "minScoreGlobal" in criteria:
            min_g = criteria["minScoreGlobal"]
            if total_finished >= TOTAL_TESTS:
                all_above = all(ft["percentage"] >= min_g for ft in finished_tests)
                if all_above:
                    unlocked.append(aid)
                    newly_unlocked.append(aid)

        # minScoreInCategory => e.g. "subject_specialist"
        if "minScoreInCategory" in criteria:
            min_cat = criteria["minScoreInCategory"]
            for ccat, attempts in category_groups.items():
                if len(attempts) == 10:
                    if all(ft["percentage"] >= min_cat for ft in attempts):
                        unlocked.append(aid)
                        newly_unlocked.append(aid)
                        break

        # perfectTestsInCategory => "category_perfectionist"
        if "perfectTestsInCategory" in criteria:
            needed = criteria["perfectTestsInCategory"]
            for ccat, attempts in category_groups.items():
                perfect_count = sum(1 for ft in attempts if ft["percentage"] == 100)
                if perfect_count >= needed:
                    unlocked.append(aid)
                    newly_unlocked.append(aid)
                    break

        # perfectTestsGlobal => "absolute_perfectionist"
        if "perfectTestsGlobal" in criteria and criteria["perfectTestsGlobal"] is True:
            if total_finished >= TOTAL_TESTS:
                all_perfect = all(ft["percentage"] == 100 for ft in finished_tests)
                if all_perfect:
                    unlocked.append(aid)
                    newly_unlocked.append(aid)

        # totalQuestions => e.g. "answer_machine_1000"
        if "totalQuestions" in criteria:
            needed_q = criteria["totalQuestions"]
            if sum_of_questions >= needed_q:
                unlocked.append(aid)
                newly_unlocked.append(aid)

    if newly_unlocked:
        mainusers_collection.update_one(
            {"_id": user_oid},
            {"$set": {"achievements": unlocked}}
        )

    return newly_unlocked


# src/routes/test_routes.py

from flask import Blueprint, request, jsonify
from bson.objectid import ObjectId
from datetime import datetime

# Mongo collections
from mongodb.database import (
    mainusers_collection,
    shop_collection,
    achievements_collection,
    tests_collection,
    testAttempts_collection,
    correctAnswers_collection
)

# Models
from models.test import (
    get_user_by_identifier,
    create_user,
    get_user_by_id,
    update_user_coins,
    update_user_xp,
    apply_daily_bonus,
    get_shop_items,
    purchase_item,
    get_achievements,
    get_test_by_id_and_category,
    check_and_unlock_achievements,
    validate_username,
    validate_email,
    validate_password,
    update_user_fields,
    get_user_by_id
)

api_bp = Blueprint('test', __name__)

def serialize_user(user):
    """Helper to convert _id, etc. to strings if needed."""
    if not user:
        return None
    user['_id'] = str(user['_id'])
    if 'currentAvatar' in user and user['currentAvatar']:
        user['currentAvatar'] = str(user['currentAvatar'])
    if 'purchasedItems' in user and isinstance(user['purchasedItems'], list):
        user['purchasedItems'] = [str(item) for item in user['purchasedItems']]
    return user

# -------------------------------------------------------------------
# USER ROUTES
# -------------------------------------------------------------------

@api_bp.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user = serialize_user(user)
    # Make sure password is included in the response, if that's desired
    if "password" not in user:
        user["password"] = user.get("password")
    return jsonify(user), 200


@api_bp.route('/user', methods=['POST'])
def register_user():
    """
    Registration: /api/user
    Expects {username, email, password, confirmPassword} in JSON
    Calls create_user, returns {message, user_id} or error.
    """
    user_data = request.json or {}
    try:
        user_id = create_user(user_data)
        return jsonify({"message": "User created", "user_id": str(user_id)}), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@api_bp.route('/login', methods=['POST'])
def login():
    """
    Login: /api/login
    Expects { usernameOrEmail, password } in JSON
    If success => return user doc in JSON (serialized)
    """
    data = request.json
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    identifier = data.get("usernameOrEmail")
    password = data.get("password")
    if not identifier or not password:
        return jsonify({"error": "Username (or Email) and password are required"}), 400

    user = get_user_by_identifier(identifier)
    if not user or user.get("password") != password:
        return jsonify({"error": "Invalid username or password"}), 401

    user = serialize_user(user)
    return jsonify({
        "user_id": user["_id"],
        "username": user["username"],
        "email": user.get("email", ""),
        "coins": user.get("coins", 0),
        "xp": user.get("xp", 0),
        "level": user.get("level", 1),
        "achievements": user.get("achievements", []),
        "xpBoost": user.get("xpBoost", 1.0),
        "currentAvatar": user.get("currentAvatar"),
        "nameColor": user.get("nameColor"),
        "purchasedItems": user.get("purchasedItems", []),
        "subscriptionActive": user.get("subscriptionActive", False),
        "password": user.get("password")
    }), 200


@api_bp.route('/user/<user_id>/daily-bonus', methods=['POST'])
def daily_bonus(user_id):
    result = apply_daily_bonus(user_id)
    if not result:
        return jsonify({"error": "User not found"}), 404
    return jsonify(result), 200


@api_bp.route('/user/<user_id>/add-xp', methods=['POST'])
def add_xp_route(user_id):
    data = request.json or {}
    xp_to_add = data.get("xp", 0)
    updated = update_user_xp(user_id, xp_to_add)
    if not updated:
        return jsonify({"error": "User not found"}), 404
    new_achievements = check_and_unlock_achievements(user_id)
    updated["newAchievements"] = new_achievements
    return jsonify(updated), 200


@api_bp.route('/user/<user_id>/add-coins', methods=['POST'])
def add_coins_route(user_id):
    data = request.json or {}
    coins_to_add = data.get("coins", 0)
    update_user_coins(user_id, coins_to_add)
    return jsonify({"message": "Coins updated"}), 200


# -------------------------------------------------------------------
# SHOP ROUTES
# -------------------------------------------------------------------

@api_bp.route('/shop', methods=['GET'])
def fetch_shop():
    items = get_shop_items()
    for item in items:
        item["_id"] = str(item["_id"])
    return jsonify(items), 200


@api_bp.route('/shop/purchase/<item_id>', methods=['POST'])
def purchase_item_route(item_id):
    data = request.json or {}
    user_id = data.get("userId")
    if not user_id:
        return jsonify({"success": False, "message": "userId is required"}), 400

    result = purchase_item(user_id, item_id)
    if result["success"]:
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@api_bp.route('/shop/equip', methods=['POST'])
def equip_item_route():
    data = request.json or {}
    user_id = data.get("userId")
    item_id = data.get("itemId")

    if not user_id or not item_id:
        return jsonify({"success": False, "message": "userId and itemId are required"}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    try:
        oid = ObjectId(item_id)
    except Exception:
        return jsonify({"success": False, "message": "Invalid item ID"}), 400

    item_doc = shop_collection.find_one({"_id": oid})
    if not item_doc:
        return jsonify({"success": False, "message": "Item not found in shop"}), 404

    # If user hasn't purchased it, check level-based unlock
    if oid not in user.get("purchasedItems", []):
        if user.get("level", 1) < item_doc.get("unlockLevel", 1):
            return jsonify({"success": False, "message": "Item not unlocked"}), 400

    # Equip the avatar
    mainusers_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"currentAvatar": oid}}
    )
    return jsonify({"success": True, "message": "Avatar equipped"}), 200


# -------------------------------------------------------------------
# TESTS ROUTES
# -------------------------------------------------------------------

@api_bp.route('/tests/<test_id>', methods=['GET'])
def fetch_test_by_id_route(test_id):
    # This is your original single-parameter route
    test_doc = get_test_by_id_and_category(test_id, None)  # or your old get_test_by_id
    if not test_doc:
        return jsonify({"error": "Test not found"}), 404
    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200


@api_bp.route('/tests/<category>/<test_id>', methods=['GET'])
def fetch_test_by_category_and_id(category, test_id):
    """
    NEW route that fetches a test doc by both category and testId
    e.g. /tests/aplus/1
    """
    try:
        test_id_int = int(test_id)
    except Exception:
        return jsonify({"error": "Invalid test ID"}), 400

    test_doc = tests_collection.find_one({
        "testId": test_id_int,
        "category": category
    })
    if not test_doc:
        return jsonify({"error": "Test not found"}), 404

    test_doc["_id"] = str(test_doc["_id"])
    return jsonify(test_doc), 200


# -------------------------------------------------------------------
# PROGRESS / ATTEMPTS ROUTES
# -------------------------------------------------------------------

@api_bp.route('/attempts/<user_id>/<test_id>', methods=['GET'])
def get_test_attempt(user_id, test_id):
    """
    Returns either an unfinished attempt if it exists;
    otherwise returns the most recently finished attempt for that user/test.
    This version searches for testId as either an integer or a string.
    """
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = None
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    # Build query with $or for testId
    query = {"userId": user_oid, "finished": False}
    if test_id_int is not None:
        query["$or"] = [{"testId": test_id_int}, {"testId": test_id}]
    else:
        query["testId"] = test_id

    attempt = testAttempts_collection.find_one(query)

    # If no unfinished attempt, check the most recent finished one
    if not attempt:
        query_finished = {"userId": user_oid, "finished": True}
        if test_id_int is not None:
            query_finished["$or"] = [{"testId": test_id_int}, {"testId": test_id}]
        else:
            query_finished["testId"] = test_id
        attempt = testAttempts_collection.find_one(query_finished, sort=[("finishedAt", -1)])

    if not attempt:
        return jsonify({"attempt": None}), 200

    attempt["_id"] = str(attempt["_id"])
    attempt["userId"] = str(attempt["userId"])
    return jsonify({"attempt": attempt}), 200


@api_bp.route('/attempts/<user_id>/<test_id>', methods=['POST'])
def update_test_attempt(user_id, test_id):
    data = request.json or {}
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    filter_ = {"userId": user_oid, "finished": False, "$or": [{"testId": test_id_int}, {"testId": test_id}]}
    update_doc = {
        "$set": {
            "userId": user_oid,
            "testId": test_id_int if isinstance(test_id_int, int) else test_id,
            "category": data.get("category", "global"),
            "answers": data.get("answers", []),
            "score": data.get("score", 0),
            "totalQuestions": data.get("totalQuestions", 0),
            "currentQuestionIndex": data.get("currentQuestionIndex", 0),
            "shuffleOrder": data.get("shuffleOrder", []),
            "finished": data.get("finished", False)
        }
    }
    testAttempts_collection.update_one(filter_, update_doc, upsert=True)
    return jsonify({"message": "Progress updated"}), 200


@api_bp.route('/attempts/<user_id>/<test_id>/finish', methods=['POST'])
def finish_test_attempt(user_id, test_id):
    data = request.json or {}
    try:
        user_oid = ObjectId(user_id)
        try:
            test_id_int = int(test_id)
        except:
            test_id_int = test_id
    except:
        return jsonify({"error": "Invalid user ID or test ID"}), 400

    filter_ = {"userId": user_oid, "finished": False, "$or": [{"testId": test_id_int}, {"testId": test_id}]}
    update_doc = {
        "$set": {
            "finished": True,
            "finishedAt": datetime.utcnow(),
            "score": data.get("score", 0),
            "totalQuestions": data.get("totalQuestions", 0),
        }
    }
    testAttempts_collection.update_one(filter_, update_doc)

    newly_unlocked = check_and_unlock_achievements(user_id)
    return jsonify({
        "message": "Test attempt finished",
        "newlyUnlocked": newly_unlocked
    }), 200


@api_bp.route('/attempts/<user_id>/list', methods=['GET'])
def list_test_attempts(user_id):
    try:
        user_oid = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user ID"}), 400

    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=50, type=int)
    skip_count = (page - 1) * page_size

    cursor = testAttempts_collection.find(
        {"userId": user_oid}
    ).sort("finishedAt", -1).skip(skip_count).limit(page_size)

    attempts = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        doc["userId"] = str(doc["userId"])
        attempts.append(doc)

    return jsonify({
        "page": page,
        "page_size": page_size,
        "attempts": attempts
    }), 200


# -------------------------------------------------------------------
# FIRST-TIME-CORRECT ANSWERS
# -------------------------------------------------------------------
@api_bp.route('/user/<user_id>/submit-answer', methods=['POST'])
def submit_answer(user_id):
    data = request.json or {}
    test_id = str(data.get("testId"))
    question_id = data.get("questionId")
    selected_index = data.get("selectedIndex")
    correct_index = data.get("correctAnswerIndex")
    xp_per_correct = data.get("xpPerCorrect", 10)
    coins_per_correct = data.get("coinsPerCorrect", 5)

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    is_correct = (selected_index == correct_index)
    already_correct = correctAnswers_collection.find_one({
        "userId": user["_id"],
        "testId": test_id,
        "questionId": question_id
    })

    awarded_xp = 0
    awarded_coins = 0
    if is_correct and not already_correct:
        correctAnswers_collection.insert_one({
            "userId": user["_id"],
            "testId": test_id,
            "questionId": question_id
        })
        update_user_xp(user_id, xp_per_correct)
        update_user_coins(user_id, coins_per_correct)
        awarded_xp = xp_per_correct
        awarded_coins = coins_per_correct

    updated_user = get_user_by_id(user_id)
    new_xp = updated_user.get("xp", 0)
    new_coins = updated_user.get("coins", 0)

    return jsonify({
        "isCorrect": is_correct,
        "alreadyCorrect": True if already_correct else False,
        "awardedXP": awarded_xp,
        "awardedCoins": awarded_coins,
        "newXP": new_xp,
        "newCoins": new_coins
    }), 200


# -------------------------------------------------------------------
# ACHIEVEMENTS
# -------------------------------------------------------------------
@api_bp.route('/achievements', methods=['GET'])
def fetch_achievements_route():
    ach_list = get_achievements()
    for ach in ach_list:
        ach["_id"] = str(ach["_id"])
    return jsonify(ach_list), 200


# -------------------------------------------------------------------
# Leaderboard Route
# -------------------------------------------------------------------
@api_bp.route('/leaderboard', methods=['GET'])
def get_leaderboard():
    top_users_cursor = mainusers_collection.find(
        {},
        {"username": 1, "level": 1, "xp": 1, "currentAvatar": 1}
    ).sort("level", -1).limit(100)

    results = []
    rank = 1
    for user in top_users_cursor:
        user_data = {
            "username": user.get("username", "unknown"),
            "level": user.get("level", 1),
            "xp": user.get("xp", 0),
            "rank": rank,
            "avatarUrl": None
        }
        if user.get("currentAvatar"):
            avatar_item = shop_collection.find_one({"_id": user["currentAvatar"]})
            if avatar_item and "imageUrl" in avatar_item:
                user_data["avatarUrl"] = avatar_item["imageUrl"]

        results.append(user_data)
        rank += 1

    return jsonify(results), 200


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# USERNAME/EMAIL/PASSWORD CHANGES
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
@api_bp.route('/user/change-username', methods=['POST'])
def change_username():
    data = request.json or {}
    user_id = data.get("userId")
    new_username = data.get("newUsername")
    if not user_id or not new_username:
        return jsonify({"error": "Missing userId or newUsername"}), 400

    # Validate new username using the new rules.
    valid, errors = validate_username(new_username)
    if not valid:
        return jsonify({"error": "Invalid new username", "details": errors}), 400

    # Check if username is already taken.
    if mainusers_collection.find_one({"username": new_username}):
        return jsonify({"error": "Username already taken"}), 400

    doc = get_user_by_id(user_id)
    if not doc:
        return jsonify({"error": "User not found"}), 404

    update_user_fields(user_id, {"username": new_username})
    return jsonify({"message": "Username updated"}), 200


@api_bp.route('/user/change-email', methods=['POST'])
def change_email():
    data = request.json or {}
    user_id = data.get("userId")
    new_email = data.get("newEmail")
    if not user_id or not new_email:
        return jsonify({"error": "Missing userId or newEmail"}), 400

    # Validate new email using the new rules.
    valid, errors = validate_email(new_email)
    if not valid:
        return jsonify({"error": "Invalid email", "details": errors}), 400

    if mainusers_collection.find_one({"email": new_email}):
        return jsonify({"error": "Email already in use"}), 400

    doc = get_user_by_id(user_id)
    if not doc:
        return jsonify({"error": "User not found"}), 404

    update_user_fields(user_id, {"email": new_email})
    return jsonify({"message": "Email updated"}), 200


@api_bp.route('/user/change-password', methods=['POST'])
def change_password():
    data = request.json or {}
    user_id = data.get("userId")
    old_password = data.get("oldPassword")
    new_password = data.get("newPassword")
    confirm = data.get("confirmPassword")

    if not user_id or not old_password or not new_password or not confirm:
        return jsonify({"error": "All fields are required"}), 400
    if new_password != confirm:
        return jsonify({"error": "New passwords do not match"}), 400

    # Validate the new password using the new rules.
    valid, errors = validate_password(new_password)
    if not valid:
        return jsonify({"error": "Invalid new password", "details": errors}), 400

    user_doc = get_user_by_id(user_id)
    if not user_doc:
        return jsonify({"error": "User not found"}), 404

    # NOTE: This example compares plain-text passwords.
    # In production, ensure you hash passwords and use a proper verification method.
    if user_doc.get("password") != old_password:
        return jsonify({"error": "Old password is incorrect"}), 401

    update_user_fields(user_id, {"password": new_password})
    return jsonify({"message": "Password updated"}), 200


@api_bp.route('/subscription/cancel', methods=['POST'])
def cancel_subscription():
    """
    Placeholder. Possibly set subscriptionActive=False
    """
    return jsonify({"message": "Cancel subscription placeholder"}), 200



