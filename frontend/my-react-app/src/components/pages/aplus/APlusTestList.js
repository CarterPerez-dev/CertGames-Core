// src/components/pages/testpage/APlusTestList.js

import React, { useState, useEffect } from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import "../../test.css";

const APlusTestList = () => {
  const navigate = useNavigate();
  const totalQuestions = 100;
  const { userId } = useSelector((state) => state.user);
  const category = "aplus";

  // Store attempt objects from the backend (keyed by test number)
  const [attempts, setAttempts] = useState({});

  // Fetch the attempt for each test (tests 1 to 10) from the backend
  useEffect(() => {
    if (!userId) return;
    const fetchAttempts = async () => {
      const newAttempts = {};
      for (let testNumber = 1; testNumber <= 10; testNumber++) {
        try {
          const res = await fetch(`/api/test/attempts/${userId}/${testNumber}`);
          if (res.ok) {
            const data = await res.json();
            newAttempts[testNumber] = data.attempt; // either an object or null
          } else {
            newAttempts[testNumber] = null;
          }
        } catch (err) {
          console.error("Error fetching attempt for test", testNumber, err);
          newAttempts[testNumber] = null;
        }
      }
      setAttempts(newAttempts);
    };
    fetchAttempts();
  }, [userId]);

  // Helper: Return display string based on the fetched attempt document
  const getProgressDisplay = (testNumber) => {
    const attempt = attempts[testNumber];
    if (!attempt) {
      return "No progress yet";
    }
    if (attempt.finished) {
      const percentage = Math.round((attempt.score / totalQuestions) * 100);
      return `Final Score: ${percentage}% (${attempt.score}/${totalQuestions})`;
    } else if (typeof attempt.currentQuestionIndex === "number") {
      return `Progress: ${attempt.currentQuestionIndex + 1} / ${totalQuestions}`;
    }
    return "No progress yet";
  };

  // Optional: Difficulty mapping for visual flair
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

  // Handler for restarting a test
  const handleRestartTest = async (testNumber) => {
    if (!userId) return;
    try {
      // Upsert a new (empty) attempt document for the given testNumber
      await fetch(`/api/test/attempts/${userId}/${testNumber}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          answers: [],
          score: 0,
          totalQuestions,
          category,
          currentQuestionIndex: 0,
          shuffleOrder: [],
          finished: false
        })
      });
      // Re-fetch the attempt for this testNumber
      const res = await fetch(`/api/test/attempts/${userId}/${testNumber}`);
      if (res.ok) {
        const data = await res.json();
        setAttempts((prev) => ({ ...prev, [testNumber]: data.attempt }));
      }

      // Immediately navigate so the user starts fresh
      navigate(`/practice-tests/a-plus/${testNumber}`);
    } catch (error) {
      console.error("Error restarting test", testNumber, error);
    }
  };

  return (
    <div className="tests-list-container">
      <h1 className="tests-list-title">CompTIA A+ Core 1 Practice Tests</h1>
      <div className="tests-list-grid">
        {Array.from({ length: 10 }, (_, i) => {
          const testNumber = i + 1;
          const difficulty = getDifficultyData(testNumber);
          const progressDisplay = getProgressDisplay(testNumber);
          const attempt = attempts[testNumber];

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
              {attempt ? (
                <div className="test-card-buttons">
                  {attempt.finished ? (
                    <>
                      {/* 
                        Pass review: true in location.state so
                        GlobalTestPage can decide to show the review.
                      */}
                      <button
                        className="resume-button"
                        onClick={() =>
                          navigate(`/practice-tests/a-plus/${testNumber}`, {
                            state: { review: true },
                          })
                        }
                      >
                        View Review
                      </button>
                      <button
                        className="restart-button-testlist"
                        onClick={() => handleRestartTest(testNumber)}
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
                        onClick={() => handleRestartTest(testNumber)}
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

