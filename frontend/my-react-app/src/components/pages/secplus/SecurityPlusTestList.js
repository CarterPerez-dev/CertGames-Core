// src/components/pages/testpage/SecurityPlusTestList.js
import React from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
// Reuse your existing APlusStyles.css if you want
import "../../test.css";

const SecurityPlusTestList = () => {
  const navigate = useNavigate();
  const totalQuestions = 100; 
  const { userId } = useSelector((state) => state.user);

  // We'll call this category "secplus"
  const category = "secplus";

  // Retrieve saved progress from localStorage
  const getProgressData = (id) => {
    if (!userId) return null;
    const key = `testProgress_${userId}_${category}_${id}`;
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
      <h1 className="tests-list-title">CompTIA Security+ Practice Tests</h1>
      <div className="tests-list-grid">
        {/* Show 10 tests, each with id from 1..10 */}
        {Array.from({ length: 10 }, (_, i) => {
          const id = i + 1;
          const difficulty = getDifficultyData(id);
          const progressData = getProgressData(id);
          const progressDisplay = getProgressDisplay(id);

          return (
            <div key={id} className="test-card">
              <div className="test-badge">Test {id}</div>
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
                        onClick={() => navigate(`/practice-tests/security-plus/${id}`)}
                      >
                        View Review
                      </button>
                      <button
                        className="restart-button-testlist"
                        onClick={() => {
                          const key = `testProgress_${userId}_${category}_${id}`;
                          localStorage.removeItem(key);
                          navigate(`/practice-tests/security-plus/${id}`);
                        }}
                      >
                        Restart Test
                      </button>
                    </>
                  ) : (
                    <>
                      <button
                        className="resume-button"
                        onClick={() => navigate(`/practice-tests/security-plus/${id}`)}
                      >
                        Resume Test
                      </button>
                      <button
                        className="restart-button-testlist"
                        onClick={() => {
                          const key = `testProgress_${userId}_${category}_${id}`;
                          localStorage.removeItem(key);
                          navigate(`/practice-tests/security-plus/${id}`);
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
                  onClick={() => navigate(`/practice-tests/security-plus/${id}`)}
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

export default SecurityPlusTestList;

