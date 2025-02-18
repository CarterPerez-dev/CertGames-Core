// src/components/pages/testpage/APlusCore2TestList.js
import React from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import GlobalTestPage from "../../GlobalTestPage";
import "../../test.css";

const APlusCore2TestList = () => {
  const navigate = useNavigate();
  const totalQuestions = 100; 
  const { userId } = useSelector((state) => state.user);

  // We'll call this category "aplus2"
  const category = "aplus2";

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
      <h1 className="tests-list-title">CompTIA A+ Core 2 Practice Tests</h1>
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
                        // Go to /practice-tests/aplus-core2/<testNumber>
                        onClick={() =>
                          navigate(`/practice-tests/aplus-core2/${testNumber}`)
                        }
                      >
                        View Review
                      </button>
                      <button
                        className="restart-button-testlist"
                        onClick={() => {
                          const key = `testProgress_${userId}_${category}_${testNumber}`;
                          localStorage.removeItem(key);
                          navigate(`/practice-tests/aplus-core2/${testNumber}`);
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
                          navigate(`/practice-tests/aplus-core2/${testNumber}`)
                        }
                      >
                        Resume Test
                      </button>
                      <button
                        className="restart-button-testlist"
                        onClick={() => {
                          const key = `testProgress_${userId}_${category}_${testNumber}`;
                          localStorage.removeItem(key);
                          navigate(`/practice-tests/aplus-core2/${testNumber}`);
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
                    navigate(`/practice-tests/aplus-core2/${testNumber}`)
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

export default APlusCore2TestList;

