// APlusTestList.js
// (Server-based progress version, unchanged except for the new "View Review" navigation state)
import React, { useEffect, useState } from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import "../../test.css";

const APlusTestList = () => {
  const navigate = useNavigate();
  const { userId } = useSelector((state) => state.user);
  const totalQuestionsPerTest = 100;
  const category = "aplus";

  const [attemptData, setAttemptData] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!userId) return;
    setLoading(true);

    // Single fetch for entire user attempt list
    const fetchAttempts = async () => {
      try {
        const res = await fetch(`/api/test/attempts/${userId}/list`);
        if (!res.ok) {
          throw new Error("Failed to fetch attempts for user");
        }
        const data = await res.json();
        const attemptList = data.attempts || [];

        // We only care about A+ attempts
        const relevant = attemptList.filter((a) => a.category === category);

        // For each testId, figure out the best attempt doc to show (unfinished if it exists, otherwise last finished)
        const bestAttempts = {};
        for (let att of relevant) {
          const testKey = att.testId;
          if (!bestAttempts[testKey]) {
            bestAttempts[testKey] = att;
          } else {
            const existing = bestAttempts[testKey];
            // Prefer the unfinished attempt if it exists
            if (!existing.finished && att.finished) {
              // keep existing
            } else if (existing.finished && !att.finished) {
              bestAttempts[testKey] = att;
            } else {
              // both finished or both unfinished => pick whichever is newer
              const existingTime = new Date(existing.finishedAt || 0).getTime();
              const newTime = new Date(att.finishedAt || 0).getTime();
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

  if (!userId) {
    return <div className="tests-list-container">Please log in.</div>;
  }

  if (loading) {
    return <div className="tests-list-container">Loading attempts...</div>;
  }
  if (error) {
    return <div className="tests-list-container">Error: {error}</div>;
  }

  const getAttemptDoc = (testNumber) => {
    return attemptData[testNumber] || null;
  };

  const getProgressDisplay = (attemptDoc) => {
    if (!attemptDoc) return "No progress yet";
    const { finished, score, totalQuestions, currentQuestionIndex } = attemptDoc;
    if (finished) {
      const pct = Math.round((score / (totalQuestions || totalQuestionsPerTest)) * 100);
      return `Final Score: ${pct}% (${score}/${totalQuestions || totalQuestionsPerTest})`;
    } else {
      if (typeof currentQuestionIndex === "number") {
        return `Progress: ${currentQuestionIndex + 1} / ${totalQuestions || totalQuestionsPerTest}`;
      }
    }
    return "No progress yet";
  };

  // This "restart test" upserts a fresh attempt doc
  const handleRestartTest = async (testNumber) => {
    try {
      await fetch(`/api/test/attempts/${userId}/${testNumber}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          category,
          answers: [],
          score: 0,
          totalQuestions: totalQuestionsPerTest,
          currentQuestionIndex: 0,
          shuffleOrder: [],
          finished: false
        })
      });
      // Remove local data so we re-fetch or re-check next time
      const newData = { ...attemptData };
      delete newData[testNumber];
      setAttemptData(newData);

      navigate(`/practice-tests/a-plus/${testNumber}`);
    } catch (err) {
      console.error("Failed to restart test:", err);
    }
  };

  // Simple difficulty labels/colors
  const difficultyColors = [
    { label: "Normal", color: "hsl(0, 0%, 100%)" },
    { label: "Very Easy", color: "hsl(120, 100%, 80%)" },
    { label: "Easy", color: "hsl(120, 100%, 70%)" },
    { label: "Moderate", color: "hsl(120, 100%, 60%)" },
    { label: "Intermediate", color: "hsl(120, 100%, 50%)" },
    { label: "Formidable", color: "hsl(120, 100%, 40%)" },
    { label: "Challenging", color: "hsl(120, 100%, 30%)" },
    { label: "Very Challenging", color: "hsl(120, 100%, 20%)" },
    { label: "Ruthless", color: "hsl(120, 100%, 10%)" },
    { label: "Ultra Level", color: "#000" }
  ];

  return (
    <div className="tests-list-container">
      <h1 className="tests-list-title">CompTIA A+ Core 1 Practice Tests</h1>
      <div className="tests-list-grid">
        {Array.from({ length: 10 }, (_, i) => {
          const testNumber = i + 1;
          const attemptDoc = getAttemptDoc(testNumber);
          const progressDisplay = getProgressDisplay(attemptDoc);
          const difficulty = difficultyColors[i] || { label: "", color: "#fff" };

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

              {!attemptDoc && (
                <button
                  className="start-button"
                  onClick={() => navigate(`/practice-tests/a-plus/${testNumber}`)}
                >
                  Click to Start
                </button>
              )}

              {attemptDoc && !attemptDoc.finished && (
                <div className="test-card-buttons">
                  <button
                    className="resume-button"
                    onClick={() => navigate(`/practice-tests/a-plus/${testNumber}`)}
                  >
                    Resume Test
                  </button>
                  <button
                    className="restart-button-testlist"
                    onClick={() => handleRestartTest(testNumber)}
                  >
                    Restart Test
                  </button>
                </div>
              )}

              {attemptDoc && attemptDoc.finished && (
                <div className="test-card-buttons">
                  <button
                    className="resume-button"
                    onClick={() =>
                      navigate(`/practice-tests/a-plus/${testNumber}`, {
                        state: { review: true }
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
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default APlusTestList;

