

i need to add a daily bonus hwere you get 1000 coins. it will have a page on the sdiabr called like daily bonus and says "laim bonus" and if you click the button it give syou 1000 coins, and it resets every 24 hours so everyday yiou can go to the page and claim 1000 coins, obvisolsy it has to be unqiue to the user.

so the test progress saves in the bakcned databse so it can be baically across all broswers and such and i liek it liek that, howveer like when i go back to the test list it doesnt actually show the prgress frontned eise but if you click teh test then you load back to where you left off, also when you finish a test it doesnt show your score and have buttons to restart or view the review. so esetially the partial progress and finish tests dont appear on the actual test list, how do i fi xtht without doing local storgae/browser storgae but actually keep it all backedn wise and yet still have it show partial porgress and finished tests in the frotnend across different browsers/devices/operating systems/ ip address etc etc- for the user on the test lit test boxes specifically?


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


and you kno wmy backedn files right??? so make sure we dont need to update anythign there either



