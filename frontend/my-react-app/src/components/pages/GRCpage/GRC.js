// GRCWizard.js
import React, { useState, useCallback, useEffect } from "react";
import "./GRC.css";
import { 
  FaRandom, 
  FaShieldAlt, 
  FaBalanceScale, 
  FaClipboardCheck, 
  FaSearch,
  FaUserShield,
  FaChartLine,
  FaFileAlt,
  FaHandshake,
  FaBullseye,
  FaUsers,
  FaSyncAlt,
  FaCopy,
  FaLightbulb,
  FaCheck,
  FaTimes,
  FaChevronRight,
  FaAngleDown,
  FaRegLightbulb,
  FaExclamationTriangle,
  FaRedo,
  FaSpinner,
  FaDatabase,
  FaBrain
} from "react-icons/fa";

const ENDPOINT = "/api";

// Category icon mapping
const categoryIcons = {
  "Regulation": <FaBalanceScale />,
  "Risk Management": <FaShieldAlt />,
  "Compliance": <FaClipboardCheck />,
  "Audit": <FaSearch />,
  "Governance": <FaUserShield />,
  "Management": <FaChartLine />,
  "Policy": <FaFileAlt />,
  "Ethics": <FaHandshake />,
  "Threat Assessment": <FaBullseye />,
  "Leadership": <FaUsers />,
  "Business Continuity": <FaDatabase />,
  "Random": <FaRandom />
};

const difficultyColors = {
  "Easy": "#4CAF50", // Green
  "Medium": "#FF9800", // Orange
  "Hard": "#F44336" // Red
};

const GRCWizard = () => {
  // State management
  const [category, setCategory] = useState("Random");
  const [difficulty, setDifficulty] = useState("Easy");
  const [loading, setLoading] = useState(false);
  const [questionData, setQuestionData] = useState(null);
  const [selectedOption, setSelectedOption] = useState(null);
  const [feedback, setFeedback] = useState("");
  const [error, setError] = useState("");
  const [showTip, setShowTip] = useState(false);
  const [attemptCount, setAttemptCount] = useState(0);
  const [streak, setStreak] = useState(0);
  const [showExplanation, setShowExplanation] = useState(false);
  const [animateQuestion, setAnimateQuestion] = useState(false);

  // Categories and difficulties
  const categories = [
    "Regulation",
    "Risk Management",
    "Compliance",
    "Audit",
    "Governance",
    "Management",
    "Policy",
    "Ethics",
    "Threat Assessment",
    "Leadership",
    "Business Continuity",
    "Random"
  ];
  
  const difficulties = ["Easy", "Medium", "Hard"];

  // Reset animation state when question changes
  useEffect(() => {
    if (questionData) {
      setAnimateQuestion(true);
      const timer = setTimeout(() => setAnimateQuestion(false), 500);
      return () => clearTimeout(timer);
    }
  }, [questionData]);

  // Generate new question
  const fetchQuestion = useCallback(async () => {
    setLoading(true);
    setFeedback("");
    setError("");
    setQuestionData(null);
    setSelectedOption(null);
    setShowExplanation(false);
    setShowTip(false);

    try {
      const response = await fetch(`${ENDPOINT}/grc/generate_question`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ category, difficulty }),
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.error || "Failed to fetch question");
      }

      const data = await response.json();
      setQuestionData(data);
      setAttemptCount(prev => prev + 1);
    } catch (error) {
      console.error("Error fetching question:", error);
      setError("Error fetching question. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [category, difficulty]);

  // Handle answer selection
  const handleAnswer = useCallback(
    (index) => {
      if (!questionData) return;
      
      setSelectedOption(index);
      const correctIndex = questionData.correct_answer_index;
      
      if (index === correctIndex) {
        setStreak(prev => prev + 1);
        setFeedback("correct");
      } else {
        setStreak(0);
        setFeedback("incorrect");
      }
      
      // Automatically show explanation
      setShowExplanation(true);
    },
    [questionData]
  );

  // Copy feedback to clipboard
  const handleCopy = useCallback(() => {
    if (!questionData || !showExplanation) return;
    
    const correctIndex = questionData.correct_answer_index;
    const explanation = questionData.explanations[selectedOption !== null ? selectedOption.toString() : correctIndex.toString()];
    const examTip = questionData.exam_tip;
    
    const textToCopy = `Question: ${questionData.question}\n\nAnswer: ${questionData.options[correctIndex]}\n\nExplanation: ${explanation}\n\nExam Tip: ${examTip}`;
    
    navigator.clipboard
      .writeText(textToCopy)
      .then(() => {
        // Show copied notification
        const copyBtn = document.querySelector('.grc-copy-btn');
        if (copyBtn) {
          copyBtn.classList.add('copied');
          setTimeout(() => copyBtn.classList.remove('copied'), 1500);
        }
      })
      .catch((err) => console.error("Failed to copy:", err));
  }, [questionData, selectedOption, showExplanation]);

  // Try again with current settings
  const handleTryAgain = () => {
    fetchQuestion();
  };

  return (
    <div className="grc-wizard-container">
      <div className="grc-wizard-header">
        <div className="grc-wizard-title-section">
          <h1 className="grc-wizard-title">GRC Wizard</h1>
          <p className="grc-wizard-subtitle">
            Master governance, risk management, and compliance concepts through interactive questions
          </p>
        </div>
        
        {streak > 0 && (
          <div className="grc-streak-badge">
            <FaBrain className="grc-streak-icon" />
            <span className="grc-streak-count">{streak}</span>
            <span className="grc-streak-label">Streak</span>
          </div>
        )}
      </div>

      <div className="grc-wizard-controls">
        <div className="grc-control-group">
          <div className="grc-control">
            <label className="grc-label" htmlFor="category-select">
              Category
            </label>
            <div className="grc-select-wrapper">
              <select
                id="category-select"
                className="grc-select"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                disabled={loading}
              >
                {categories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
              </select>
              <span className="grc-select-icon">
                <FaAngleDown />
              </span>
              <span className="grc-category-icon">
                {categoryIcons[category] || <FaRandom />}
              </span>
            </div>
          </div>

          <div className="grc-control">
            <label className="grc-label" htmlFor="difficulty-select">
              Difficulty
            </label>
            <div className="grc-select-wrapper">
              <select
                id="difficulty-select"
                className="grc-select"
                value={difficulty}
                onChange={(e) => setDifficulty(e.target.value)}
                disabled={loading}
                style={{
                  borderColor: difficultyColors[difficulty]
                }}
              >
                {difficulties.map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </select>
              <span 
                className="grc-select-icon"
                style={{ color: difficultyColors[difficulty] }}
              >
                <FaAngleDown />
              </span>
            </div>
          </div>
        </div>

        <button
          className="grc-generate-btn"
          onClick={fetchQuestion}
          disabled={loading}
        >
          {loading ? (
            <>
              <FaSpinner className="grc-loading-icon" />
              <span>Generating...</span>
            </>
          ) : (
            <>
              {questionData ? <FaSyncAlt /> : <FaChevronRight />}
              <span>{questionData ? "New Question" : "Generate Question"}</span>
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="grc-error-message">
          <FaExclamationTriangle />
          <p>{error}</p>
          <button className="grc-retry-btn" onClick={fetchQuestion}>
            <FaRedo /> Try Again
          </button>
        </div>
      )}

      {questionData && (
        <div className={`grc-question-section ${animateQuestion ? 'animate-in' : ''}`}>
          <div className="grc-question-container">
            <div className="grc-question-header">
              <div className="grc-question-category">
                <span className="grc-category-icon">
                  {categoryIcons[category]}
                </span>
                <span>{category}</span>
              </div>
              <div 
                className="grc-question-difficulty"
                style={{ backgroundColor: difficultyColors[difficulty] }}
              >
                {difficulty}
              </div>
            </div>
            
            <h2 className="grc-question-text">{questionData.question}</h2>

            <div className="grc-options-container">
              {questionData.options.map((option, index) => {
                const correctIndex = questionData.correct_answer_index;
                const isSelected = selectedOption === index;
                const isCorrect = index === correctIndex;
                
                let optionClass = "grc-option";
                if (feedback) {
                  if (isSelected) {
                    optionClass += isCorrect ? " correct" : " incorrect";
                  } else if (isCorrect) {
                    optionClass += " correct-answer";
                  }
                }

                return (
                  <button
                    key={index}
                    className={optionClass}
                    onClick={() => !feedback && handleAnswer(index)}
                    disabled={!!feedback}
                  >
                    <span className="grc-option-letter">
                      {String.fromCharCode(65 + index)}
                    </span>
                    <span className="grc-option-text">{option}</span>
                    {feedback && isCorrect && (
                      <span className="grc-correct-indicator">
                        <FaCheck />
                      </span>
                    )}
                    {feedback && isSelected && !isCorrect && (
                      <span className="grc-incorrect-indicator">
                        <FaTimes />
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {showExplanation && (
            <div className="grc-explanation-section">
              <div className="grc-explanation-header">
                <h3 className="grc-explanation-title">
                  {feedback === "correct" ? (
                    <>
                      <FaCheck className="grc-correct-icon" /> Correct Answer
                    </>
                  ) : (
                    <>
                      <FaTimes className="grc-incorrect-icon" /> Incorrect Answer
                    </>
                  )}
                </h3>
                <div className="grc-explanation-actions">
                  <button className="grc-tip-toggle" onClick={() => setShowTip(!showTip)}>
                    {showTip ? <FaLightbulb /> : <FaRegLightbulb />}
                    <span>{showTip ? "Hide Tip" : "Show Tip"}</span>
                  </button>
                  <button className="grc-copy-btn" onClick={handleCopy}>
                    <FaCopy />
                    <span>Copy</span>
                    <span className="grc-tooltip">Copied!</span>
                  </button>
                </div>
              </div>
              
              <div className="grc-explanation-content">
                <p className="grc-explanation-text">
                  {questionData.explanations[selectedOption !== null 
                    ? selectedOption.toString() 
                    : questionData.correct_answer_index.toString()]}
                </p>
                
                {showTip && (
                  <div className="grc-exam-tip">
                    <div className="grc-tip-header">
                      <FaLightbulb className="grc-tip-icon" />
                      <span>Exam Tip</span>
                    </div>
                    <p className="grc-tip-text">{questionData.exam_tip}</p>
                  </div>
                )}
              </div>
              
              <div className="grc-next-actions">
                <button className="grc-next-btn" onClick={handleTryAgain}>
                  <FaRedo />
                  <span>Try Another Question</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}
      
      {!questionData && !loading && !error && (
        <div className="grc-empty-state">
          <div className="grc-empty-icon">
            <FaShieldAlt />
          </div>
          <h3 className="grc-empty-title">Ready to Test Your GRC Knowledge?</h3>
          <p className="grc-empty-description">
            Select your preferred category and difficulty level, then click "Generate Question" to begin.
          </p>
        </div>
      )}
    </div>
  );
};

export default GRCWizard;
