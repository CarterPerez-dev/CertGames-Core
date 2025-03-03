import React, { useState, useRef, useEffect } from 'react';
import './ScenarioSphere.css';
import { ATTACK_TYPES } from './attacks';
import { 
  FaGlobeAmericas, 
  FaSkull, 
  FaUserNinja, 
  FaThermometerHalf, 
  FaPaperPlane,
  FaCheck,
  FaTimes,
  FaLightbulb,
  FaSpinner,
  FaCaretDown,
  FaSearch,
  FaChevronDown,
  FaChevronUp,
  FaInfoCircle,
  FaQuestionCircle,
  FaExclamationTriangle
} from 'react-icons/fa';

const ENDPOINT = "/api";

const ScenarioSphere = () => {
  // Main state
  const [isGenerating, setIsGenerating] = useState(false);
  const [industry, setIndustry] = useState("Finance");
  const [attackType, setAttackType] = useState("");
  const [skillLevel, setSkillLevel] = useState("Script Kiddie");
  const [threatIntensity, setThreatIntensity] = useState(50);

  // Output state
  const [scenarioText, setScenarioText] = useState("");
  const [interactiveQuestions, setInteractiveQuestions] = useState([]);
  const [userAnswers, setUserAnswers] = useState({});
  const [feedback, setFeedback] = useState({});
  const [generationProgress, setGenerationProgress] = useState(0);
  const [generationStage, setGenerationStage] = useState('');

  // Suggestion system state
  const [suggestions, setSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [activeSuggestionIndex, setActiveSuggestionIndex] = useState(-1);
  const [showAllSuggestions, setShowAllSuggestions] = useState(false);
  
  // Visual state
  const [showScenarioCard, setShowScenarioCard] = useState(false);
  const [fadeInCard, setFadeInCard] = useState(false);
  const [showQuestionsSection, setShowQuestionsSection] = useState(false);
  const [expandedSections, setExpandedSections] = useState({});
  const [errorMessage, setErrorMessage] = useState("");

  // Refs
  const suggestionsRef = useRef(null);
  const outputRef = useRef(null);
  const questionsRef = useRef(null);

  // Section management
  const toggleSectionExpansion = (sectionName) => {
    setExpandedSections(prev => ({
      ...prev,
      [sectionName]: !prev[sectionName]
    }));
  };

  const isSectionExpanded = (sectionName) => {
    return expandedSections[sectionName] !== false;
  };

  // Handle clicks outside the suggestions dropdown
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (suggestionsRef.current && !suggestionsRef.current.contains(event.target)) {
        setShowSuggestions(false);
        setActiveSuggestionIndex(-1);
        setShowAllSuggestions(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  // Scroll to output when scenario is generated
  useEffect(() => {
    if (scenarioText && outputRef.current) {
      outputRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [showScenarioCard]);

  // Scroll to questions when they appear
  useEffect(() => {
    if (interactiveQuestions.length > 0 && questionsRef.current) {
      questionsRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [showQuestionsSection]);

  // Handle attack type input changes and suggestions
  const handleAttackTypeChange = (e) => {
    const userInput = e.target.value;
    setAttackType(userInput);
    setShowAllSuggestions(false);

    if (userInput.length > 0) {
      const filteredSuggestions = ATTACK_TYPES.filter(
        (attack) => attack.toLowerCase().includes(userInput.toLowerCase())
      );
      setSuggestions(filteredSuggestions);
      setShowSuggestions(true);
    } else {
      setSuggestions([]);
      setShowSuggestions(false);
    }
    setActiveSuggestionIndex(-1);
  };

  // Show all suggestions
  const handleShowAllSuggestionsClick = () => {
    setShowAllSuggestions(true);
  };

  // Handle keyboard navigation in suggestion dropdown
  const handleKeyDown = (e) => {
    if (showSuggestions) {
      if (e.key === 'ArrowDown') {
        if (activeSuggestionIndex < (showAllSuggestions
          ? suggestions.length - 1
          : Math.min(suggestions.length, 10) - 1)) {
          setActiveSuggestionIndex(activeSuggestionIndex + 1);
        }
      } else if (e.key === 'ArrowUp') {
        if (activeSuggestionIndex > 0) {
          setActiveSuggestionIndex(activeSuggestionIndex - 1);
        }
      } else if (e.key === 'Enter') {
        if (activeSuggestionIndex >= 0 &&
            activeSuggestionIndex < (showAllSuggestions
              ? suggestions.length
              : Math.min(suggestions.length, 10))) {
          setAttackType(suggestions[activeSuggestionIndex]);
          setSuggestions([]);
          setShowSuggestions(false);
          setActiveSuggestionIndex(-1);
          setShowAllSuggestions(false);
          e.preventDefault();
        }
      } else if (e.key === 'Escape') {
        setShowSuggestions(false);
        setActiveSuggestionIndex(-1);
        setShowAllSuggestions(false);
      }
    }
  };

  // Generate the scenario
  const handleGenerateScenario = () => {
    // Input validation
    if (!attackType.trim()) {
      setErrorMessage("Please enter an Attack Type before generating.");
      setTimeout(() => setErrorMessage(""), 5000);
      return;
    }
    
    // Reset state and start generation
    setIsGenerating(true);
    setScenarioText("");
    setInteractiveQuestions([]);
    setUserAnswers({});
    setFeedback({});
    setGenerationProgress(0);
    setGenerationStage('Initializing scenario...');
    setShowScenarioCard(false);
    setFadeInCard(false);
    setShowQuestionsSection(false);
    setErrorMessage("");
    
    // Start the simulation of progress
    const progressInterval = setInterval(() => {
      setGenerationProgress(prev => {
        const newProgress = prev + (Math.random() * 5);
        
        // Update status messages at different stages
        if (newProgress > 15 && newProgress < 20) {
          setGenerationStage('Analyzing threat vectors...');
        } else if (newProgress > 40 && newProgress < 45) {
          setGenerationStage('Constructing attack narrative...');
        } else if (newProgress > 60 && newProgress < 65) {
          setGenerationStage('Developing technical details...');
        } else if (newProgress > 80 && newProgress < 85) {
          setGenerationStage('Finalizing scenario...');
        }
        
        return Math.min(newProgress, 95); // Cap at 95% until complete
      });
    }, 300);

    // Prepare request data
    const data = {
      industry,
      attack_type: attackType,
      skill_level: skillLevel,
      threat_intensity: threatIntensity,
    };

    // Make the API request
    fetch(`${ENDPOINT}/scenario/stream_scenario`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
      .then((response) => {
        if (!response.ok) {
          setIsGenerating(false);
          clearInterval(progressInterval);
          return response.text().then((text) => {
            setErrorMessage(`Error: ${text}`);
            setTimeout(() => setErrorMessage(""), 7000);
          });
        }
        
        // Set up streaming
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let scenarioAccumulator = "";

        function readChunk() {
          reader.read().then(({ done, value }) => {
            if (done) {
              // Complete generation
              clearInterval(progressInterval);
              setGenerationProgress(100);
              setGenerationStage('Scenario complete!');
              setIsGenerating(false);
              setScenarioText(scenarioAccumulator.trim());
              
              // Trigger animations
              setTimeout(() => {
                setShowScenarioCard(true);
                setTimeout(() => {
                  setFadeInCard(true);
                }, 100);
              }, 500);
              
              // Fetch questions
              fetchQuestions(scenarioAccumulator.trim());
              return;
            }
            
            // Update with new chunk
            const chunk = decoder.decode(value, { stream: true });
            scenarioAccumulator += chunk;
            setScenarioText(scenarioAccumulator);
            readChunk();
          });
        }

        readChunk();
      })
      .catch((err) => {
        console.error(err);
        setErrorMessage("An error occurred while generating the scenario. Please try again.");
        setTimeout(() => setErrorMessage(""), 7000);
        clearInterval(progressInterval);
        setIsGenerating(false);
      });
  };

  // Fetch interactive questions
  const fetchQuestions = (finalScenarioText) => {
    if (!finalScenarioText) return;
    
    setGenerationStage('Generating interactive questions...');

    const data = { scenario_text: finalScenarioText };

    fetch(`${ENDPOINT}/scenario/stream_questions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
      .then((response) => {
        if (!response.ok) {
          console.error("Error fetching questions.");
          setErrorMessage("Failed to generate interactive questions. The scenario is still available.");
          setTimeout(() => setErrorMessage(""), 7000);
          return response.text().then((t) => console.error(t));
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let jsonAccumulator = "";

        function readChunk() {
          reader.read().then(({ done, value }) => {
            if (done) {
              try {
                const parsed = JSON.parse(jsonAccumulator);
                if (Array.isArray(parsed)) {
                  const errorObj = parsed.find(q => q.error);
                  if (errorObj) {
                    console.error("Error in questions generation:", errorObj.error);
                    setErrorMessage(`Error generating questions: ${errorObj.error}`);
                    setTimeout(() => setErrorMessage(""), 7000);
                  } else if (parsed.length === 3) {
                    setInteractiveQuestions(parsed);
                    // Animate questions section appearance
                    setTimeout(() => {
                      setShowQuestionsSection(true);
                    }, 1000);
                  } else {
                    console.error("Expected exactly 3 questions, but received:", parsed);
                    setErrorMessage("Unexpected number of questions received.");
                    setTimeout(() => setErrorMessage(""), 7000);
                  }
                } else {
                  console.error("Parsed questions are not in an array format.");
                  setErrorMessage("Invalid format for interactive questions.");
                  setTimeout(() => setErrorMessage(""), 7000);
                }
              } catch (e) {
                console.error("Failed to parse question JSON:", e);
                console.error("Received text:", jsonAccumulator);
                setErrorMessage("An error occurred while parsing the questions.");
                setTimeout(() => setErrorMessage(""), 7000);
              }
              return;
            }
            const chunk = decoder.decode(value, { stream: true });
            jsonAccumulator += chunk;
            readChunk();
          });
        }
        readChunk();
      })
      .catch((error) => {
        console.error("Error streaming questions:", error);
        setErrorMessage("Failed to load interactive questions.");
        setTimeout(() => setErrorMessage(""), 7000);
      });
  };

  // Handle answer selection
  const handleAnswerSelect = (questionIndex, selectedOption) => {
    const question = interactiveQuestions[questionIndex];
    const isCorrect = selectedOption === question.correct_answer;

    setUserAnswers((prevAnswers) => ({
      ...prevAnswers,
      [questionIndex]: selectedOption,
    }));

    setFeedback((prevFeedback) => ({
      ...prevFeedback,
      [questionIndex]: {
        isCorrect,
        explanation: question.explanation,
      },
    }));
  };

  // Render interactive questions
  const renderQuestions = () => {
    if (!interactiveQuestions || interactiveQuestions.length === 0) return null;
    
    return interactiveQuestions.map((question, index) => (
      <div key={index} className="scenario-question-card">
        <div className="question-header">
          <span className="question-number">Question {index + 1}</span>
          {feedback[index] && (
            <span className={`question-status ${feedback[index].isCorrect ? 'correct' : 'incorrect'}`}>
              {feedback[index].isCorrect ? <FaCheck /> : <FaTimes />}
            </span>
          )}
        </div>
        
        <p className="question-text">{question.question}</p>
        
        <div className="options-container">
          {Object.entries(question.options).map(([optionLetter, optionText]) => {
            const isSelected = userAnswers[index] === optionLetter;
            const showCorrectHighlight = feedback[index] && question.correct_answer === optionLetter;
            const showIncorrectHighlight = feedback[index] && isSelected && !feedback[index].isCorrect;
            
            return (
              <label 
                key={optionLetter} 
                className={`option-label ${isSelected ? 'selected' : ''} 
                           ${showCorrectHighlight ? 'correct' : ''} 
                           ${showIncorrectHighlight ? 'incorrect' : ''}`}
              >
                <input
                  type="radio"
                  name={`question-${index}`}
                  value={optionLetter}
                  checked={isSelected}
                  onChange={() => handleAnswerSelect(index, optionLetter)}
                  disabled={userAnswers.hasOwnProperty(index)}
                  className="option-radio"
                />
                <span className="option-marker">{optionLetter}</span>
                <span className="option-text">{optionText}</span>
                
                {showCorrectHighlight && (
                  <span className="option-icon correct">
                    <FaCheck />
                  </span>
                )}
                
                {showIncorrectHighlight && (
                  <span className="option-icon incorrect">
                    <FaTimes />
                  </span>
                )}
              </label>
            );
          })}
        </div>
        
        {feedback[index] && (
          <div className={`feedback-container ${feedback[index].isCorrect ? 'correct' : 'incorrect'}`}>
            <div className="feedback-header">
              {feedback[index].isCorrect ? (
                <>
                  <FaCheck className="feedback-icon" />
                  <span>Correct Answer!</span>
                </>
              ) : (
                <>
                  <FaTimes className="feedback-icon" />
                  <span>Incorrect Answer</span>
                </>
              )}
            </div>
            <div className="feedback-explanation">
              <FaLightbulb className="explanation-icon" />
              <p>{feedback[index].explanation}</p>
            </div>
          </div>
        )}
      </div>
    ));
  };

  // Get intensity color based on value
  const getIntensityColor = (value) => {
    if (value < 25) return 'low';
    if (value < 50) return 'medium-low';
    if (value < 75) return 'medium-high';
    return 'high';
  };

  // Score calculation
  const calculateScore = () => {
    if (Object.keys(feedback).length === 0) return null;
    
    const totalAnswered = Object.keys(feedback).length;
    const correctCount = Object.values(feedback).filter(f => f.isCorrect).length;
    const percentage = Math.round((correctCount / totalAnswered) * 100);
    
    return {
      answered: totalAnswered,
      correct: correctCount,
      total: interactiveQuestions.length,
      percentage
    };
  };

  const score = calculateScore();

  return (
    <div className="scenario-container">
      {/* Error message popup */}
      {errorMessage && (
        <div className="scenario-error-popup">
          <FaExclamationTriangle className="error-icon" />
          <span>{errorMessage}</span>
          <button onClick={() => setErrorMessage("")}>
            <FaTimes />
          </button>
        </div>
      )}
    
      {/* Header section */}
      <div className="scenario-header">
        <h1 className="scenario-title">Scenario Sphere</h1>
        <p className="scenario-subtitle">Generate realistic cybersecurity attack scenarios and test your knowledge</p>
      </div>
      
      {/* Generator controls card */}
      <div className="scenario-generator-card">
        <div className="scenario-card-header">
          <h2 className="scenario-card-title">Scenario Generator</h2>
        </div>
        
        <div className="scenario-controls-grid">
          {/* Industry selector */}
          <div className="scenario-control">
            <label htmlFor="industry-select" className="scenario-label">
              <FaGlobeAmericas className="scenario-input-icon" />
              <span>Industry</span>
            </label>
            <div className="scenario-select-wrapper">
              <select
                id="industry-select"
                className="scenario-select"
                value={industry}
                onChange={(e) => setIndustry(e.target.value)}
                disabled={isGenerating}
              >
                <option value="Finance">Finance</option>
                <option value="Healthcare">Healthcare</option>
                <option value="Retail">Retail</option>
                <option value="Technology">Technology</option>
                <option value="Energy">Energy</option>
                <option value="Education">Education</option>
                <option value="Supply Chain">Supply Chain</option>
                <option value="Telecommunications">Telecommunications</option>
                <option value="Pharmaceutical">Pharmaceutical</option>
                <option value="Transportation">Transportation</option>
                <option value="Cybersecurity Company">Cybersecurity Company</option>
                <option value="Manufacturing">Manufacturing</option>
                <option value="CYBERPUNK2077">CYBERPUNK2077</option>
              </select>
              <FaCaretDown className="select-icon" />
            </div>
          </div>
          
          {/* Attack type input with suggestions */}
          <div className="scenario-control">
            <label htmlFor="attack-type-input" className="scenario-label">
              <FaSkull className="scenario-input-icon" />
              <span>Attack Type</span>
            </label>
            <div className="scenario-input-wrapper" ref={suggestionsRef}>
              <div className="scenario-search-wrapper">
                <FaSearch className="search-icon" />
                <input
                  id="attack-type-input"
                  type="text"
                  className="scenario-input"
                  placeholder="Enter or select attack type..."
                  value={attackType}
                  onChange={handleAttackTypeChange}
                  onKeyDown={handleKeyDown}
                  onFocus={() => {
                    if (attackType.length > 0 && suggestions.length > 0) {
                      setShowSuggestions(true);
                    }
                  }}
                  disabled={isGenerating}
                />
              </div>
              
              {showSuggestions && suggestions.length > 0 && (
                <ul className="scenario-suggestions-list">
                  {(showAllSuggestions ? suggestions : suggestions.slice(0, 10)).map(
                    (suggestion, index) => (
                      <li
                        key={suggestion}
                        className={`suggestion-item ${index === activeSuggestionIndex ? 'suggestion-active' : ''}`}
                        onClick={() => {
                          setAttackType(suggestion);
                          setSuggestions([]);
                          setShowSuggestions(false);
                          setActiveSuggestionIndex(-1);
                          setShowAllSuggestions(false);
                        }}
                      >
                        {suggestion}
                      </li>
                    )
                  )}
                  {!showAllSuggestions && suggestions.length > 10 && (
                    <li className="suggestion-show-all" onClick={handleShowAllSuggestionsClick}>
                      Show all {suggestions.length} options
                    </li>
                  )}
                </ul>
              )}
            </div>
          </div>
          
          {/* Skill level selector */}
          <div className="scenario-control">
            <label htmlFor="skill-level-select" className="scenario-label">
              <FaUserNinja className="scenario-input-icon" />
              <span>Attacker Skill Level</span>
            </label>
            <div className="scenario-select-wrapper">
              <select
                id="skill-level-select"
                className="scenario-select"
                value={skillLevel}
                onChange={(e) => setSkillLevel(e.target.value)}
                disabled={isGenerating}
              >
                <option value="Script Kiddie">Script Kiddie</option>
                <option value="Intermediate">Intermediate</option>
                <option value="Advanced">Advanced</option>
                <option value="APT">APT (Advanced Persistent Threat)</option>
              </select>
              <FaCaretDown className="select-icon" />
            </div>
          </div>
          
          {/* Threat intensity slider */}
          <div className="scenario-control">
            <label htmlFor="threat-intensity-slider" className="scenario-label">
              <FaThermometerHalf className="scenario-input-icon" />
              <span>Threat Intensity</span>
            </label>
            <div className="scenario-slider-container">
              <input
                id="threat-intensity-slider"
                type="range"
                min="1"
                max="100"
                className={`scenario-slider scenario-slider-${getIntensityColor(threatIntensity)}`}
                value={threatIntensity}
                onChange={(e) => setThreatIntensity(e.target.value)}
                disabled={isGenerating}
              />
              <div className="scenario-slider-labels">
                <span>Low</span>
                <span className="scenario-slider-value">{threatIntensity}</span>
                <span>High</span>
              </div>
            </div>
          </div>
        </div>
        
        {/* Generate button */}
        <div className="scenario-generate-container">
          <button
            className="scenario-generate-button"
            onClick={handleGenerateScenario}
            disabled={isGenerating}
          >
            {isGenerating ? (
              <>
                <FaSpinner className="spin-icon" />
                <span>Generating...</span>
              </>
            ) : (
              <>
                <FaPaperPlane />
                <span>Generate Scenario</span>
              </>
            )}
          </button>
          
          {/* Generation progress */}
          {isGenerating && (
            <div className="scenario-progress-container">
              <div className="scenario-progress-bar">
                <div 
                  className="scenario-progress-fill" 
                  style={{ width: `${generationProgress}%` }}
                ></div>
              </div>
              <div className="scenario-progress-text">
                <span>{generationStage}</span>
                <span>{Math.round(generationProgress)}%</span>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* Scenario output section */}
      {(scenarioText || showScenarioCard) && (
        <div 
          ref={outputRef}
          className={`scenario-output-card ${showScenarioCard ? 'visible' : ''} ${fadeInCard ? 'fade-in' : ''}`}
        >
          <div className="scenario-card-header scenario-output-header">
            <h2 className="scenario-card-title">
              <span>Scenario: {industry} + {attackType}</span>
            </h2>
            <div className="scenario-card-actions">
              <button 
                className="scenario-section-toggle"
                onClick={() => toggleSectionExpansion('scenario')}
                aria-label={isSectionExpanded('scenario') ? 'Collapse scenario' : 'Expand scenario'}
              >
                {isSectionExpanded('scenario') ? <FaChevronUp /> : <FaChevronDown />}
              </button>
            </div>
          </div>
          
          {isSectionExpanded('scenario') !== false && (
            <div className="scenario-output-content">
              <div className="scenario-output-details">
                <div className="scenario-detail">
                  <span className="detail-label">Industry:</span>
                  <span className="detail-value">{industry}</span>
                </div>
                <div className="scenario-detail">
                  <span className="detail-label">Attack:</span>
                  <span className="detail-value">{attackType}</span>
                </div>
                <div className="scenario-detail">
                  <span className="detail-label">Skill Level:</span>
                  <span className="detail-value">{skillLevel}</span>
                </div>
                <div className="scenario-detail">
                  <span className="detail-label">Intensity:</span>
                  <span className={`detail-value intensity-${getIntensityColor(threatIntensity)}`}>
                    {threatIntensity}
                  </span>
                </div>
              </div>
              
              <div className="scenario-text-container">
                {scenarioText.split('\n\n').map((paragraph, index) => (
                  <p key={index} className="scenario-paragraph">
                    {paragraph}
                  </p>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
      
      {/* Interactive questions section */}
      {interactiveQuestions.length > 0 && (
        <div 
          ref={questionsRef}
          className={`scenario-questions-card ${showQuestionsSection ? 'visible' : ''}`}
        >
          <div className="scenario-card-header scenario-questions-header">
            <h2 className="scenario-card-title">Interactive Questions</h2>
            <div className="scenario-card-actions">
              <button 
                className="scenario-section-toggle"
                onClick={() => toggleSectionExpansion('questions')}
                aria-label={isSectionExpanded('questions') ? 'Collapse questions' : 'Expand questions'}
              >
                {isSectionExpanded('questions') ? <FaChevronUp /> : <FaChevronDown />}
              </button>
            </div>
          </div>
          
          {isSectionExpanded('questions') !== false && (
            <div className="scenario-questions-content">
              <div className="scenario-questions-intro">
                <FaQuestionCircle className="question-intro-icon" />
                <p>Test your understanding of the scenario by answering these questions:</p>
              </div>
              
              {/* Score display */}
              {score && (
                <div className="scenario-score-container">
                  <div className="scenario-score-header">
                    <span>Your Score</span>
                    <span className="scenario-score-percentage">
                      {score.percentage}%
                    </span>
                  </div>
                  <div className="scenario-score-details">
                    <div className="score-detail">
                      <span>Answered:</span>
                      <span>{score.answered} of {score.total}</span>
                    </div>
                    <div className="score-detail">
                      <span>Correct:</span>
                      <span>{score.correct} of {score.answered}</span>
                    </div>
                  </div>
                  <div 
                    className={`scenario-score-bar score-${
                      score.percentage < 40 ? 'low' : 
                      score.percentage < 70 ? 'medium' : 'high'
                    }`}
                  >
                    <div 
                      className="scenario-score-fill" 
                      style={{ width: `${score.percentage}%` }}
                    ></div>
                  </div>
                </div>
              )}
              
              <div className="scenario-questions-list">
                {renderQuestions()}
              </div>
            </div>
          )}
        </div>
      )}
      
      {/* Info card section */}
      <div className="scenario-info-card">
        <div className="scenario-info-header">
          <FaInfoCircle className="info-icon" />
          <h3>About Scenario Sphere</h3>
        </div>
        <div className="scenario-info-content">
          <p>
            Scenario Sphere generates realistic cybersecurity attack scenarios based on your selected parameters. 
            Each scenario includes technical details, actors, risks, and mitigation steps to help you understand 
            real-world attack vectors and defensive strategies.
          </p>
          <p>
            Answer the interactive questions to test your knowledge and understanding of the scenario.
            The scenarios are generated using AI and are designed to be educational and thought-provoking.
          </p>
        </div>
      </div>
    </div>
  );
};

export default ScenarioSphere;
