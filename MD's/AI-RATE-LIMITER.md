Ok so i need to make rate limiters for these ai generators. so essentially they generate stff for teh suer. one of them generates a scenerio and 3 test questions, and one of them makes analogies, and another one gernates a test question. so i need to exmpahze you mjust NOT CHNAGE ANY FUCNONILITY OR ANYTHING OF HE SORT, But i need to simply add rate limiters ot them- so tehy shouldnt be gernous rate limiters but not too strict either- a perect amoutn too where if i had alot of usres they wouldnt drain all my toekns really fast. also i want to keep the fucntiolity and how i do teh api call chat-cpleiotn... or whatver becasue its combatible with mine so dont chnage that- i also need ot maintain teh steraing apsect to where it sstreams chunk by chukk so do not remove that aspect eitehr- just add rate limiters and anything else simila rto rate limiters ot mske it a full fledged genrator and ready for porduction. Now i will provid eyou the route files for context aswell as their frontned files but do not chnage any rooute or frontend file becaue they are just for onetxt




context:- this is where i call the openai 
import os
import logging
from openai import OpenAI
from dotenv import load_dotenv


load_dotenv()


logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def load_api_key() -> str:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        logger.error("OpenAI API key is missing. Please ensure it's set in the environment variables.")
        raise ValueError("OpenAI API key is required but not found.")
    return api_key


api_key = load_api_key()
client = OpenAI(api_key=api_key)







conetxt: routes files for their respective files
from flask import Blueprint, request, jsonify, Response
import logging
from helpers.async_tasks import (
    generate_single_analogy_task,
    generate_comparison_analogy_task,
    generate_triple_comparison_analogy_task
)
# New streaming helper
from helpers.analogy_stream_helper import generate_analogy_stream

analogy_bp = Blueprint('analogy_bp', __name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

@analogy_bp.route('/generate_analogy', methods=['POST'])
def generate_analogy():
    """
    OLD route that uses Celery tasks. We keep it so async_tasks or older code won't break,
    but the new front end won't use this route anymore.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request must contain data"}), 400

    analogy_type = data.get("analogy_type")
    category = data.get("category")
    concept1 = data.get("concept1")
    concept2 = data.get("concept2")
    concept3 = data.get("concept3")

    try:
        if analogy_type == "single" and concept1:
            async_result = generate_single_analogy_task.delay(concept1, category)
            analogy_text = async_result.get(timeout=120)
            return jsonify({"analogy": analogy_text}), 200

        elif analogy_type == "comparison" and concept1 and concept2:
            async_result = generate_comparison_analogy_task.delay(concept1, concept2, category)
            analogy_text = async_result.get(timeout=120)
            return jsonify({"analogy": analogy_text}), 200

        elif analogy_type == "triple" and concept1 and concept2 and concept3:
            async_result = generate_triple_comparison_analogy_task.delay(concept1, concept2, concept3, category)
            analogy_text = async_result.get(timeout=180)
            return jsonify({"analogy": analogy_text}), 200

        else:
            logger.error("Invalid parameters provided to /generate_analogy")
            return jsonify({"error": "Invalid parameters"}), 400

    except Exception as e:
        logger.error(f"Error generating analogy (Celery route): {e}")
        return jsonify({"error": "An internal error occurred while generating the analogy."}), 500


@analogy_bp.route('/stream_analogy', methods=['POST'])
def stream_analogy():
    """
    NEW route that streams analogy text. Only used by front-end now.
    """
    data = request.get_json() or {}
    analogy_type = data.get("analogy_type", "single")
    category = data.get("category", "real-world")
    concept1 = data.get("concept1", "")
    concept2 = data.get("concept2", "")
    concept3 = data.get("concept3", "")

    try:
        def generate():
            stream_gen = generate_analogy_stream(analogy_type, concept1, concept2, concept3, category)
            for chunk in stream_gen:
                yield chunk

        return Response(generate(), mimetype='text/plain')

    except Exception as e:
        logger.error(f"Error streaming analogy: {e}")
        return jsonify({"error": "An internal error occurred while streaming the analogy."}), 500

# grc_routes.py

from flask import Blueprint, request, jsonify
import logging
from helpers.async_tasks import generate_grc_question_task

grc_bp = Blueprint('grc', __name__)
logger = logging.getLogger(__name__)

GRC_CATEGORIES = ["Regulation", "Risk Management", "Compliance", "Audit", "Governance", 
                  "Management", "Policy", "Ethics", "Threat Assessment", "Leadership", 
                  "Business Continuity", "Random"]
DIFFICULTY_LEVELS = ["Easy", "Medium", "Hard"]

@grc_bp.route('/generate_question', methods=['POST'])
def generate_question():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request must contain JSON data"}), 400

        category = data.get('category', 'Random')
        difficulty = data.get('difficulty', 'Easy')

        if category not in GRC_CATEGORIES:
            return jsonify({"error": "Invalid category"}), 400
        if difficulty not in DIFFICULTY_LEVELS:
            return jsonify({"error": "Invalid difficulty"}), 400

        # Celery call
        task_result = generate_grc_question_task.delay(category, difficulty)
        question_data = task_result.get(timeout=120)

        return jsonify(question_data), 200

    except Exception as e:
        logger.error(f"Error in /generate_question: {e}")
        return jsonify({"error": "An internal error occurred."}), 500
import logging
import json  
from flask import Blueprint, request, Response, jsonify
from helpers.scenario_helper import (
    generate_scenario,
    generate_interactive_questions,
    break_down_scenario
)

scenario_bp = Blueprint('scenario_bp', __name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

@scenario_bp.route('/stream_scenario', methods=['POST'])
def stream_scenario_endpoint():
    """
    Streams scenario text in real time (token-by-token).
    Expects JSON with { industry, attack_type, skill_level, threat_intensity }
    Returns a text/plain streaming response.
    """
    data = request.get_json() or {}
    required_fields = ["industry", "attack_type", "skill_level", "threat_intensity"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        logger.error(f"Missing required fields: {missing}")
        return jsonify({"error": f"Missing required fields: {missing}"}), 400

    industry = data["industry"]
    attack_type = data["attack_type"]
    skill_level = data["skill_level"]
    threat_intensity = data["threat_intensity"]

    try:
        threat_intensity = int(threat_intensity)
    except ValueError:
        logger.error("Invalid threat_intensity value; must be an integer.")
        return jsonify({"error": "threat_intensity must be an integer"}), 400

    def generate_chunks():
        scenario_generator = generate_scenario(industry, attack_type, skill_level, threat_intensity)
        for chunk in scenario_generator:
            yield chunk

    return Response(generate_chunks(), mimetype='text/plain')


@scenario_bp.route('/stream_questions', methods=['POST'])
def stream_questions_endpoint():
    """
    Streams the interactive questions (in raw JSON form) in real time, token-by-token.
    Expects JSON with { "scenario_text": "..." }
    The front end can accumulate the text and parse once done.
    """
    data = request.get_json() or {}
    scenario_text = data.get("scenario_text", "")
    if not scenario_text:
        logger.error("Missing scenario_text in the request.")
        return jsonify({"error": "Missing scenario_text"}), 400

    logger.debug(f"Received scenario_text: {scenario_text[:100]}...")  

    def generate_json_chunks():
        questions = generate_interactive_questions(scenario_text)
        if isinstance(questions, list):
            logger.debug("Questions are a list. Serializing to JSON.")
            yield json.dumps(questions)
        elif callable(questions):
            logger.debug("Questions are being streamed.")
            for chunk in questions():
                yield chunk
        else:
            logger.error("Unexpected type for questions.")
            yield json.dumps([{"error": "Failed to generate questions."}])

    return Response(generate_json_chunks(), mimetype='application/json')



context: now the frontend files for each reprove file:

import React, { useState, useRef } from 'react';
import './AnalogyHub.css';
import loadingImage from './loading2.png';

const ENDPOINT = "/api"; 

const AnalogyHub = () => {
  const [analogyType, setAnalogyType] = useState('single');
  const [inputValues, setInputValues] = useState(['']);
  const [analogyCategory, setAnalogyCategory] = useState('real-world');
  const [isStreaming, setIsStreaming] = useState(false);
  const [generatedAnalogy, setGeneratedAnalogy] = useState('');

  const analogyRef = useRef(null);

  const handleTypeChange = (e) => {
    const type = e.target.value;
    setAnalogyType(type);

    switch (type) {
      case 'comparison':
        setInputValues(['', '']);
        break;
      case 'triple':
        setInputValues(['', '', '']);
        break;
      default:
        setInputValues(['']);
    }
  };

  const handleInputChange = (index, value) => {
    const newValues = [...inputValues];
    newValues[index] = value;
    setInputValues(newValues);
  };

  const handleGenerateClick = () => {
    setIsStreaming(true);
    setGeneratedAnalogy('');

    const data = {
      analogy_type: analogyType,
      category: analogyCategory,
      concept1: inputValues[0] || '',
      concept2: inputValues[1] || '',
      concept3: inputValues[2] || ''
    };

    fetch(`${ENDPOINT}/analogy/stream_analogy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    .then((res) => {
      if (!res.ok) {
        setIsStreaming(false);
        return res.text().then((text) => {
          console.error('Error from server: ', text);
          setGeneratedAnalogy('An error occurred streaming the analogy.');
        });
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      function readChunk() {
        reader.read().then(({ done, value }) => {
          if (done) {
            setIsStreaming(false);
            return;
          }
          const chunk = decoder.decode(value, { stream: true });
          setGeneratedAnalogy((prev) => prev + chunk);
          readChunk();
        });
      }
      readChunk();
    })
    .catch((err) => {
      console.error('Streaming error:', err);
      setGeneratedAnalogy('An error occurred streaming the analogy.');
      setIsStreaming(false);
    });
  };

  const handleCopyClick = () => {
    if (generatedAnalogy) {
      navigator.clipboard.writeText(generatedAnalogy)
        .then(() => {
          console.log('Copied to clipboard');
        })
        .catch(err => {
          console.error('Could not copy text: ', err);
        });
    }
  };

  return (
    <div className="analogy-hub-container">
      <h1 className="analogy-hub-title">Analogy Hub</h1>
      <p className="analogy-hub-tagline">runtime-error.r00.</p>

      <div className="analogy-hub-form">
        <div className="analogy-type-section">
          <select value={analogyType} onChange={(e) => handleTypeChange(e)} className="analogy-hub-input">
            <option value="single">Single</option>
            <option value="comparison">Comparison</option>
            <option value="triple">Triple Comparison</option>
          </select>
        </div>

        <div className="analogy-input-fields">
          {inputValues.map((value, index) => (
            <input
              key={index}
              type="text"
              className="analogy-hub-input"
              value={value}
              placeholder={`Enter concept ${index + 1}`}
              onChange={(e) => handleInputChange(index, e.target.value)}
            />
          ))}
        </div>

        <div className="analogy-category-section">
          <select
            value={analogyCategory}
            onChange={(e) => setAnalogyCategory(e.target.value)}
            className="analogy-hub-input"
          >
            <option value="real-world">Real World Analogy</option>
            <option value="video-games">Video Games</option>
            <option value="tv-show">TV Show</option>
            <option value="sports">Sports</option>
            <option value="fiction">Fiction</option>
            <option value="food">Food & Cooking</option>
            <option value="relationships">Relationships</option>
            <option value="music">Music & Instruments</option>
            <option value="animals">Animals</option>
            <option value="nature">Nature & Environment</option>
            <option value="travel">Travel & Exploration</option>
            <option value="history">Historical Events</option>
            <option value="technology">Technology</option>
            <option value="mythology">Mythology</option>
            <option value="business">Business & Economics</option>
            <option value="art">Art & Creativity</option>
            <option value="school">School & Education</option>
            <option value="construction">Construction & Engineering</option>
            <option value="space">Space & Astronomy</option>
            <option value="superheroes">Superheroes & Comic Books</option>
            <option value="medieval">Medieval Times</option>
            <option value="movies">Movies & Cinema</option>
            <option value="everyday-life">Everyday Life</option>
            <option value="gardening">Gardening</option>
            <option value="mr-robot">Mr Robot</option>
          </select>
        </div>

        <div className="button-and-loader">
          <button
            className="analogy-generate-button"
            onClick={handleGenerateClick}
            disabled={isStreaming}
          >
            {isStreaming ? "Streaming..." : "Generate Analogy"}
          </button>

          {isStreaming && (
            <img
              src={loadingImage}
              alt="Loading..."
              className="loading-icon"
            />
          )}
        </div>
      </div>

      {generatedAnalogy && (
        <div className="analogy-output-container" ref={analogyRef}>
          <button className="copy-button" onClick={handleCopyClick}>Copy</button>
          <p className="generated-analogy">{generatedAnalogy}</p>
        </div>
      )}
    </div>
  );
};

export default AnalogyHub;
// GRC.js - Redesigned with gamified UI
import React, { useState, useCallback, useEffect } from "react";
import "./GRC.css";
import { 
  FaRandom, 
  FaBalanceScale, 
  FaClipboardCheck, 
  FaSearch,
  FaFileAlt, 
  FaUsers, 
  FaFileContract, 
  FaUserSecret, 
  FaShieldAlt,
  FaUserTie, 
  FaSyncAlt, 
  FaBook,
  FaLock,
  FaCopy,
  FaCheck,
  FaTimes,
  FaLightbulb,
  FaSpinner,
  FaTrophy,
  FaRocket,
  FaRegLightbulb
} from "react-icons/fa";

const ENDPOINT = "/api";

// Icon mapping for categories
const categoryIcons = {
  "Regulation": <FaBalanceScale />,
  "Risk Management": <FaShieldAlt />,
  "Compliance": <FaClipboardCheck />,
  "Audit": <FaSearch />,
  "Governance": <FaUsers />,
  "Management": <FaUserTie />,
  "Policy": <FaFileContract />,
  "Ethics": <FaUserSecret />,
  "Threat Assessment": <FaLock />,
  "Leadership": <FaUserTie />,
  "Business Continuity": <FaSyncAlt />,
  "Random": <FaRandom />
};

// Difficulty level icons and colors
const difficultyIcons = {
  "Easy": <FaRegLightbulb />,
  "Medium": <FaRocket />,
  "Hard": <FaTrophy />
};

const difficultyColors = {
  "Easy": "#2ebb77",
  "Medium": "#ffc107",
  "Hard": "#ff4c8b"
};

const GRC = () => {
  const [category, setCategory] = useState("Random");
  const [difficulty, setDifficulty] = useState("Easy");
  const [loading, setLoading] = useState(false);
  const [questionData, setQuestionData] = useState(null);
  const [selectedOption, setSelectedOption] = useState(null);
  const [feedback, setFeedback] = useState("");
  const [copiedToClipboard, setCopiedToClipboard] = useState(false);
  const [showExplanation, setShowExplanation] = useState(false);

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

  // Reset copy status after 2 seconds
  useEffect(() => {
    if (copiedToClipboard) {
      const timer = setTimeout(() => {
        setCopiedToClipboard(false);
      }, 2000);
      return () => clearTimeout(timer);
    }
  }, [copiedToClipboard]);

  const fetchQuestion = useCallback(async () => {
    setLoading(true);
    setFeedback("");
    setQuestionData(null);
    setSelectedOption(null);
    setShowExplanation(false);

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
    } catch (error) {
      console.error("Error fetching question:", error);
      setFeedback("Error fetching question. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [category, difficulty]);

  const handleAnswer = useCallback(
    (index) => {
      if (!questionData) return;
      setSelectedOption(index);
      const correctIndex = questionData.correct_answer_index;
      const isCorrect = index === correctIndex;
      
      setFeedback(isCorrect ? "Correct!" : "Incorrect");
      setShowExplanation(true);
    },
    [questionData]
  );

  const handleCopy = useCallback(() => {
    if (!questionData || !showExplanation) return;
    
    const correctIndex = questionData.correct_answer_index;
    const correctExplanation = questionData.explanations[correctIndex.toString()];
    const examTip = questionData.exam_tip;
    
    const textToCopy = `Question: ${questionData.question}\n\nOptions:\n${questionData.options.map((opt, i) => `${i + 1}. ${opt}`).join('\n')}\n\nCorrect Answer: ${questionData.options[correctIndex]}\n\nExplanation: ${correctExplanation}\n\nExam Tip: ${examTip}`;
    
    navigator.clipboard
      .writeText(textToCopy)
      .then(() => {
        setCopiedToClipboard(true);
      })
      .catch((err) => console.error("Failed to copy:", err));
  }, [questionData, showExplanation]);

  const getNewQuestion = () => {
    fetchQuestion();
  };

  return (
    <div className="grc-wizard-page">
      <div className="grc-header">
        <div className="grc-title-container">
          <h1 className="grc-title">GRC Wizard</h1>
          <p className="grc-subtitle">Master the art of Governance, Risk, and Compliance</p>
        </div>
      </div>

      <div className="grc-content">
        <div className="grc-wizard-card">
          <div className="grc-card-header">
            <h2>Generate a Question</h2>
            <p>Select a category and difficulty level</p>
          </div>
          
          <div className="grc-controls">
            <div className="grc-control-group">
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
                  {categoryIcons[category] || <FaRandom />}
                </span>
              </div>
            </div>

            <div className="grc-control-group">
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
                >
                  {difficulties.map((level) => (
                    <option key={level} value={level}>
                      {level}
                    </option>
                  ))}
                </select>
                <span className="grc-select-icon" style={{ color: difficultyColors[difficulty] }}>
                  {difficultyIcons[difficulty]}
                </span>
              </div>
            </div>

            <button
              className="grc-generate-btn"
              onClick={fetchQuestion}
              disabled={loading}
            >
              {loading ? (
                <>
                  <FaSpinner className="grc-spinner" />
                  <span>Generating</span>
                </>
              ) : questionData ? (
                <>
                  <FaSyncAlt />
                  <span>New Question</span>
                </>
              ) : (
                <>
                  <FaBook />
                  <span>Generate Question</span>
                </>
              )}
            </button>
          </div>
        </div>

        {questionData && (
          <div className="grc-question-card">
            <div className="grc-question-header">
              <div className="grc-question-meta">
                <span className="grc-question-category">
                  {categoryIcons[category]} {category}
                </span>
                <span className="grc-question-difficulty" style={{ color: difficultyColors[difficulty] }}>
                  {difficultyIcons[difficulty]} {difficulty}
                </span>
              </div>
              <h3 className="grc-question-title">Question</h3>
            </div>

            <div className="grc-question-content">
              <p className="grc-question-text">{questionData.question}</p>
              
              <div className="grc-options-container">
                {questionData.options.map((option, index) => {
                  const isCorrect = index === questionData.correct_answer_index;
                  let optionClass = "grc-option";
                  
                  if (selectedOption !== null) {
                    if (index === selectedOption) {
                      optionClass += " selected";
                    }
                    if (showExplanation) {
                      optionClass += isCorrect ? " correct" : " incorrect";
                    }
                  }
                  
                  return (
                    <button
                      key={index}
                      className={optionClass}
                      onClick={() => handleAnswer(index)}
                      disabled={selectedOption !== null}
                    >
                      <span className="grc-option-letter">{String.fromCharCode(65 + index)}</span>
                      <span className="grc-option-text">{option}</span>
                      {showExplanation && isCorrect && (
                        <span className="grc-option-status">
                          <FaCheck className="grc-status-icon correct" />
                        </span>
                      )}
                      {showExplanation && selectedOption === index && !isCorrect && (
                        <span className="grc-option-status">
                          <FaTimes className="grc-status-icon incorrect" />
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>

            {showExplanation && (
              <div className="grc-explanation-container">
                <div className="grc-explanation-header">
                  <h3>
                    {selectedOption === questionData.correct_answer_index ? (
                      <><FaCheck className="grc-header-icon correct" /> Correct Answer</>
                    ) : (
                      <><FaTimes className="grc-header-icon incorrect" /> Incorrect Answer</>
                    )}
                  </h3>
                  <button 
                    className={`grc-copy-btn ${copiedToClipboard ? 'copied' : ''}`}
                    onClick={handleCopy}
                  >
                    {copiedToClipboard ? (
                      <><FaCheck /> Copied</>
                    ) : (
                      <><FaCopy /> Copy</>
                    )}
                  </button>
                </div>
                
                <div className="grc-explanation-content">
                  <div className="grc-explanation-section">
                    <h4>Explanation</h4>
                    <p>{questionData.explanations[selectedOption.toString()]}</p>
                  </div>
                  
                  <div className="grc-explanation-section">
                    <h4><FaLightbulb className="grc-tip-icon" /> Exam Tip</h4>
                    <p className="grc-tip-text">{questionData.exam_tip}</p>
                  </div>
                </div>
                
                <div className="grc-action-buttons">
                  <button 
                    className="grc-next-btn" 
                    onClick={getNewQuestion}
                  >
                    <FaSyncAlt />
                    <span>New Question</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default GRC;
import React, { useState, useRef, useEffect } from 'react';
import './ScenarioSphere.css';
import { ATTACK_TYPES } from './attacks';
import { 
  FaRandom, 
  FaDatabase, 
  FaUserNinja, 
  FaFire, 
  FaPlay,
  FaCog, 
  FaCheckCircle, 
  FaTimesCircle, 
  FaLightbulb,
  FaChevronDown,
  FaSearch,
  FaBuilding,
  FaSkull,
  FaUserSecret,
  FaThermometerHalf,
  FaSpinner,
  FaChevronUp,
  FaClipboardCheck,
  FaQuestionCircle,
  FaArrowRight,
  FaShieldAlt,
  FaLock,
  FaExclamationTriangle,
  FaTimes
} from 'react-icons/fa';

const ENDPOINT = "/api";

const ScenarioSphere = () => {
  const [isGenerating, setIsGenerating] = useState(false);
  const [industry, setIndustry] = useState("Finance");
  const [attackType, setAttackType] = useState("");
  const [skillLevel, setSkillLevel] = useState("Script Kiddie");
  const [threatIntensity, setThreatIntensity] = useState(50);

  const [scenarioText, setScenarioText] = useState("");
  const [interactiveQuestions, setInteractiveQuestions] = useState([]);
  const [userAnswers, setUserAnswers] = useState({});
  const [feedback, setFeedback] = useState({});

  const [suggestions, setSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [activeSuggestionIndex, setActiveSuggestionIndex] = useState(-1);
  const [showAllSuggestions, setShowAllSuggestions] = useState(false);
  const suggestionsRef = useRef(null);
  const scenarioOutputRef = useRef(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [scoreCounter, setScoreCounter] = useState(0);

  // New state for UI enhancements
  const [outputExpanded, setOutputExpanded] = useState(true);
  const [questionsExpanded, setQuestionsExpanded] = useState(true);
  const [generationComplete, setGenerationComplete] = useState(false);
  const [scenarioGenerated, setScenarioGenerated] = useState(false);

  useEffect(() => {
    // Handle clicking outside the suggestions dropdown
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

  // Scroll to scenario output when it changes
  useEffect(() => {
    if (scenarioText && scenarioOutputRef.current && isGenerating) {
      scenarioOutputRef.current.scrollTop = scenarioOutputRef.current.scrollHeight;
    }
  }, [scenarioText, isGenerating]);

  const handleAttackTypeChange = (e) => {
    const userInput = e.target.value;
    setAttackType(userInput);
    setShowAllSuggestions(false);
    setErrorMessage("");

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

  const handleShowAllSuggestionsClick = () => {
    setShowAllSuggestions(true);
  };

  const handleKeyDown = (e) => {
    if (showSuggestions) {
      if (e.key === 'ArrowDown') {
        if (
          activeSuggestionIndex <
          (showAllSuggestions
            ? suggestions.length - 1
            : Math.min(suggestions.length, 10) - 1)
        ) {
          setActiveSuggestionIndex(activeSuggestionIndex + 1);
        }
      } else if (e.key === 'ArrowUp') {
        if (activeSuggestionIndex > 0) {
          setActiveSuggestionIndex(activeSuggestionIndex - 1);
        }
      } else if (e.key === 'Enter') {
        if (
          activeSuggestionIndex >= 0 &&
          activeSuggestionIndex <
            (showAllSuggestions
              ? suggestions.length
              : Math.min(suggestions.length, 10))
        ) {
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

  const handleGenerateScenario = () => {
    if (!attackType.trim()) {
      setErrorMessage("Please enter the Type of Attack");
      return;
    }

    setErrorMessage("");
    setIsGenerating(true);
    setScenarioText("");
    setInteractiveQuestions([]);
    setUserAnswers({});
    setFeedback({});
    setScoreCounter(0);
    setScenarioGenerated(true);
    setGenerationComplete(false);

    const data = {
      industry,
      attack_type: attackType,
      skill_level: skillLevel,
      threat_intensity: threatIntensity,
    };

    fetch(`${ENDPOINT}/scenario/stream_scenario`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
      .then((response) => {
        if (!response.ok) {
          setIsGenerating(false);
          return response.text().then((text) => {
            setErrorMessage(`Error: ${text}`);
          });
        }
        const reader = response.body.getReader();
        const decoder = new TextDecoder();

        let scenarioAccumulator = "";

        function readChunk() {
          reader.read().then(({ done, value }) => {
            if (done) {
              setIsGenerating(false);
              setGenerationComplete(true);
              setScenarioText(scenarioAccumulator.trim());
              fetchQuestions(scenarioAccumulator.trim());
              return;
            }
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
        setErrorMessage("An error occurred while streaming scenario");
        setIsGenerating(false);
      });
  };

  const fetchQuestions = (finalScenarioText) => {
    if (!finalScenarioText) return;

    const data = { scenario_text: finalScenarioText };

    fetch(`${ENDPOINT}/scenario/stream_questions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
      .then((response) => {
        if (!response.ok) {
          console.error("Error fetching questions.");
          return response.text().then((t) => console.error(t));
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let jsonAccumulator = "";

        function readChunk() {
          reader.read().then(({ done, value }) => {
            if (done) {
              try {
                console.log("Accumulated Questions JSON:", jsonAccumulator); 

                const parsed = JSON.parse(jsonAccumulator);

                if (Array.isArray(parsed)) {
                  const errorObj = parsed.find(q => q.error);
                  if (errorObj) {
                    console.error("Error in questions generation:", errorObj.error);
                    setErrorMessage(`Error generating questions: ${errorObj.error}`);
                  } else if (parsed.length === 3) {
                    setInteractiveQuestions(parsed);
                  } else {
                    console.error("Expected exactly 3 questions, but received:", parsed);
                    setErrorMessage("Unexpected number of questions received");
                  }
                } else {
                  console.error("Parsed questions are not in an array format.");
                  setErrorMessage("Invalid format for interactive questions");
                }
              } catch (e) {
                console.error("Failed to parse question JSON:", e);
                console.error("Received text:", jsonAccumulator);
                setErrorMessage("An error occurred while parsing interactive questions");
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
        setErrorMessage("Error streaming questions");
      });
  };

  const handleAnswerSelect = (questionIndex, selectedOption) => {
    if (userAnswers.hasOwnProperty(questionIndex)) {
      return; // Already answered
    }
    
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
    
    // Update score counter if correct
    if (isCorrect) {
      setScoreCounter(prev => prev + 1);
    }
  };

  const renderQuestions = () => {
    return interactiveQuestions.map((question, index) => (
      <div key={index} className="question-card">
        <div className="question-header">
          <span className="question-number">Question {index + 1}</span>
          {feedback[index] && (
            <span className={`question-status ${feedback[index].isCorrect ? 'correct' : 'incorrect'}`}>
              {feedback[index].isCorrect ? 
                <><FaCheckCircle /> Correct</> : 
                <><FaTimesCircle /> Incorrect</>
              }
            </span>
          )}
        </div>
        
        <p className="question-text">{question.question}</p>
        
        <div className="options-container">
          {Object.entries(question.options).map(([optionLetter, optionText]) => {
            const isSelected = userAnswers[index] === optionLetter;
            const showCorrect = feedback[index] && question.correct_answer === optionLetter;
            const showIncorrect = feedback[index] && isSelected && !feedback[index].isCorrect;
            
            return (
              <button 
                key={optionLetter} 
                className={`option-button ${isSelected ? 'selected' : ''} ${showCorrect ? 'correct' : ''} ${showIncorrect ? 'incorrect' : ''}`}
                onClick={() => handleAnswerSelect(index, optionLetter)}
                disabled={userAnswers.hasOwnProperty(index)}
              >
                <span className="option-letter">{optionLetter}</span>
                <span className="option-text">{optionText}</span>
                {showCorrect && <FaCheckCircle className="option-icon correct" />}
                {showIncorrect && <FaTimesCircle className="option-icon incorrect" />}
              </button>
            );
          })}
        </div>
        
        {feedback[index] && (
          <div className="feedback-container">
            <div className="feedback-icon">
              <FaLightbulb />
            </div>
            <div className="feedback-content">
              <p className="feedback-explanation">{feedback[index].explanation}</p>
            </div>
          </div>
        )}
      </div>
    ));
  };

  // Calculate progress based on number of paragraphs
  const calculateStreamProgress = () => {
    if (!scenarioText) return 0;
    
    // Roughly estimate progress by counting paragraphs
    const paragraphs = scenarioText.split('\n\n').filter(p => p.trim().length > 0);
    // Typical scenario has about 5 paragraphs
    return Math.min(Math.ceil((paragraphs.length / 5) * 100), 90);
  };

  const streamProgress = calculateStreamProgress();

  return (
    <div className="scenario-container">
      <div className="scenario-header">
        <div className="scenario-title-container">
          <h1 className="scenario-title">
            <FaShieldAlt className="scenario-title-icon" />
            Scenario Sphere
          </h1>
          <p className="scenario-subtitle">Immerse yourself in realistic cybersecurity scenarios and test your knowledge</p>
        </div>
        
        {errorMessage && (
          <div className="scenario-error">
            <FaExclamationTriangle className="error-icon" />
            <span>{errorMessage}</span>
            <button 
              className="error-close" 
              onClick={() => setErrorMessage("")}
            >
              <FaTimes />
            </button>
          </div>
        )}
      </div>

      <div className="scenario-content">
        <div className="scenario-params-card">
          <div className="params-header">
            <h2><FaCog className="params-icon" /> Generation Parameters</h2>
            
            <div className="scenario-score-display">
              <div className="score-counter">
                <span>{scoreCounter}</span>
                <span>/3</span>
              </div>
              <span className="score-label">Correct</span>
            </div>
          </div>
          
          <div className="params-content">
            <div className="param-group">
              <label htmlFor="industry-select">
                <FaBuilding className="param-icon" />
                Industry
              </label>
              <div className="select-wrapper">
                <select
                  id="industry-select"
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
                <FaChevronDown className="select-arrow" />
              </div>
            </div>

            <div className="param-group" ref={suggestionsRef}>
              <label htmlFor="attack-type-input">
                <FaSkull className="param-icon" />
                Attack Type
              </label>
              <div className="input-wrapper">
                <FaSearch className="input-icon" />
                <input
                  id="attack-type-input"
                  type="text"
                  placeholder="Search or enter attack type..."
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
                {showSuggestions && suggestions.length > 0 && (
                  <div className="suggestions-dropdown">
                    <ul className="suggestions-list">
                      {(showAllSuggestions ? suggestions : suggestions.slice(0, 10)).map(
                        (suggestion, index) => (
                          <li
                            key={suggestion}
                            className={index === activeSuggestionIndex ? 'active' : ''}
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
                        <li
                          className="show-all-suggestions"
                          onClick={handleShowAllSuggestionsClick}
                        >
                          <FaChevronDown /> Show all options ({suggestions.length})
                        </li>
                      )}
                    </ul>
                  </div>
                )}
              </div>
            </div>

            <div className="param-group">
              <label htmlFor="skill-level-select">
                <FaUserSecret className="param-icon" />
                Attacker Skill Level
              </label>
              <div className="select-wrapper">
                <select
                  id="skill-level-select"
                  value={skillLevel}
                  onChange={(e) => setSkillLevel(e.target.value)}
                  disabled={isGenerating}
                >
                  <option value="Script Kiddie">Script Kiddie</option>
                  <option value="Intermediate">Intermediate</option>
                  <option value="Advanced">Advanced</option>
                  <option value="APT">APT</option>
                </select>
                <FaChevronDown className="select-arrow" />
              </div>
            </div>

            <div className="param-group">
              <label htmlFor="threat-intensity-slider">
                <FaThermometerHalf className="param-icon" />
                Threat Intensity: <span className="intensity-value">{threatIntensity}</span>
              </label>
              <div className="slider-wrapper">
                <input
                  id="threat-intensity-slider"
                  type="range"
                  min="1"
                  max="100"
                  value={threatIntensity}
                  onChange={(e) => setThreatIntensity(e.target.value)}
                  disabled={isGenerating}
                />
                <div className="slider-markers">
                  <span>Low</span>
                  <span>Medium</span>
                  <span>High</span>
                </div>
              </div>
            </div>

            <button
              className="generate-button"
              onClick={handleGenerateScenario}
              disabled={isGenerating}
            >
              {isGenerating ? (
                <>
                  <FaSpinner className="spinner-icon" />
                  <span>Generating...</span>
                </>
              ) : (
                <>
                  <FaPlay className="play-icon" />
                  <span>Generate Scenario</span>
                </>
              )}
            </button>
          </div>
        </div>

        {scenarioGenerated && (
          <div className="scenario-results">
            <div className="scenario-output-card">
              <div 
                className="output-header"
                onClick={() => setOutputExpanded(!outputExpanded)}
              >
                <h2>
                  <FaLock className="output-icon" />
                  Generated Scenario
                </h2>
                <div className="output-controls">
                  {!generationComplete && isGenerating && (
                    <div className="generation-progress">
                      <div className="progress-bar">
                        <div 
                          className="progress-fill" 
                          style={{ width: `${streamProgress}%` }}
                        ></div>
                      </div>
                      <span className="progress-label">Generating...</span>
                    </div>
                  )}
                  <button className="toggle-button">
                    {outputExpanded ? <FaChevronUp /> : <FaChevronDown />}
                  </button>
                </div>
              </div>
              
              {outputExpanded && (
                <div 
                  className="output-content"
                  ref={scenarioOutputRef}
                >
                  {scenarioText ? (
                    <div className="scenario-text">
                      {scenarioText}
                      {isGenerating && (
                        <span className="typing-cursor"></span>
                      )}
                    </div>
                  ) : (
                    <div className="scenario-placeholder">
                      <FaSpinner className={`placeholder-icon ${isGenerating ? 'spinning' : ''}`} />
                      <p>Scenario will appear here...</p>
                    </div>
                  )}
                </div>
              )}
            </div>

            {interactiveQuestions.length > 0 && (
              <div className="scenario-questions-card">
                <div 
                  className="questions-header"
                  onClick={() => setQuestionsExpanded(!questionsExpanded)}
                >
                  <h2>
                    <FaQuestionCircle className="questions-icon" />
                    Knowledge Assessment
                  </h2>
                  <button className="toggle-button">
                    {questionsExpanded ? <FaChevronUp /> : <FaChevronDown />}
                  </button>
                </div>
                
                {questionsExpanded && (
                  <div className="questions-content">
                    {Object.keys(feedback).length === interactiveQuestions.length && (
                      <div className="assessment-complete">
                        <FaClipboardCheck className="complete-icon" />
                        <div className="assessment-results">
                          <p className="completion-message">Assessment Complete</p>
                          <p className="score-message">
                            You scored {scoreCounter} out of {interactiveQuestions.length} correct
                          </p>
                        </div>
                      </div>
                    )}
                    
                    <div className="questions-list">
                      {renderQuestions()}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ScenarioSphere;




ok now here are the files in which teh rate limiter should be in

import os
import json
import logging
import re  
from API.AI import client

logger = logging.getLogger(__name__)

def generate_grc_question(category, difficulty):
    """
    Generates a GRC-related multiple-choice question in JSON format.
    The model returns a JSON object with keys:
      question (string)
      options (array of 4 strings)
      correct_answer_index (int)
      explanations (dict of strings for "0","1","2","3")
      exam_tip (string)
    """

    prompt = f""" 
You are an expert in concepts found in certifications like CISSP, CompTIA Advanced Security Practitioner (CASP+), CISM, CRISC, and others. Your role is to generate 
challenging and diverse test questions using advanced mult-layered reasoning, related to governance, risk management, risk thresholds, types of risk, Audit, Management, Policy, Cyber Security Ethics, Threat Assessment, 
Leadership, Business Continuity, compliance, regulations, incident resposne, Incident Response and more. focusing on preparing for exams like CISSP/ISC2 and CompTIA certifications. Ensure the questions cover a wide range of scenarios,
principles, and concepts, with multiple-choice answers that are nuanced and complex and specific, avoiding repetitive patterns or overly simplified examples.

CONTEXT: The user has selected:
- Category: {category} (e.g., 'Regulation', 'Risk Management', 'Compliance', 'Audit', 'Governance', 'Management', 'Policy', 'Ethics', 'Threat Assessment', 'Leadership', 'Business Continuity', 'Incident Response', 'Random')
- Difficulty: {difficulty} (e.g., 'Easy', 'Medium', 'Hard')

REQUIREMENTS
1. Four options (0, 1, 2, 3) total, one correct answer. The incorrect options should be very plausible but not correct, requiring the test-taker to carefully differentiate.

2. Explanations:
   - For the correct answer: Provide multiple sentences detailing exactly why it’s correct, clearly tying it back to the question’s scenario or concept. Show how it fulfills the requirements asked in the question as well as why the other answer choices are incorrect/not the correct answer..
   - For each incorrect answer: Provide multiple sentences detailing why it is NOT correct aswell as why the other incorrect answer choices are incorrect, and why then tell the user what the correct answer is and why it is correct using advanced multi-layered reasoning. 
     Do not just say it’s incorrect; fully explain why it falls short. 
     Highlight conceptual differences, limitations, or focus areas that differ from the question’s criteria.
   - Regardless of user choice, the generated output must contain full explanations for all answer choices provided. The explanations are produced in advance as part of the JSON object. Each explanation should be at least 3 sentences, rich in detail and conceptual clarity using advanced multi-layered reasoning.

3. Include an "exam_tip" field that provides a short, memorable takeaway or mnemonic to help differentiate the correct concept from the others. The exam tip should help the user recall why the correct answer stands out using advanced multi-layered reasoning.

4. Return ONLY a JSON object with the fields:
   "question", "options", "correct_answer_index", "explanations", and "exam_tip"
   No extra text, no Markdown, no commentary outside the JSON.

5. For each explanation (correct and incorrect):
   - At minimum of 3 sentences for the correct answer.
   - if the user gets the answer correct provide minium 3 senetence answer as to why it is correct, but also why the other answer choices listed are not the correct answer using advanced multi-layered reasoning.
   - Substantial detail.
   - Clearly articulate conceptual reasons, not just factual statements using advanced multi-layered reasoning.

EXAMPLE FORMAT (this is not real content, just structure, make sure to use all topics not just the topic provided in this example):
{{
  "question": "The question",
  "options": ["Option 0","Option 1","Option 2","Option 3"],
  "correct_answer_index": 2,
  "explanations": {{
    "0": "Explain thoroughly why option 0 fails. Mention its scope, focus areas, and why that doesn't meet the question criteria and then explain what the correct answer is and why it is correct aswell as why the other answer choices are incorrect using advanced multi-layered reasoning.",
    "1": "Explain thoroughly why option 1 fails. Mention its scope, focus areas, and why that doesn't meet the question criteria and then explain what the correct answer is and why it is correct aswell as why the other answer choices are incorrect using advanced multi-layered reasoning.",
    "2": "Explain thoroughly why option 2 is correct, linking its characteristics to the question scenario and why the other answer choices are incorrect using advanced multi-layered reasoning",
    "3": "Explain thoroughly why option 3 fails. Mention its scope, focus areas, and why that doesn't meet the question criteria and then explain what the correct answer is and why it is correct aswell as why the other answer choices are incorrect using advanced multi-layered reasoning."
  }},
  "exam_tip": "A short, memorable hint or mnemonic that differentiates the correct approach from others using advanced multi-layered reasoning."
}}

Now generate the JSON object following these instructions.
"""



    try:
        response = client.chat.completions.create(
            model="gpt-4o",  
            messages=[{"role": "user", "content": prompt}],
            max_tokens=900,
            temperature=0.6,
        )

        content = response.choices[0].message.content.strip()

      
        content = re.sub(r'^```.*\n', '', content)
        content = re.sub(r'\n```$', '', content)

        try:
            generated_question = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error("JSON parsing error in generate_grc_question: %s", e)
            logger.error("Model returned: %s", content)
            raise ValueError("Model did not return valid JSON.") from e

        logger.info("Generated GRC question successfully.")
        return generated_question

    except Exception as e:
        logger.error(f"Error generating GRC question: {str(e)}")
        raise


import json
import logging
import re
from API.AI import client  

logger = logging.getLogger(__name__)

def generate_scenario(industry, attack_type, skill_level, threat_intensity):
    """
    Generate a scenario using OpenAI based on the provided inputs,
    returning a generator that yields partial text chunks as soon as they're generated.
    """
    try:
        prompt = (
            f"Imagine a cybersecurity incident involving the {industry} industry. "
            f"The attack is of type {attack_type}, performed by someone with a skill level of {skill_level}, "
            f"and the threat intensity is rated as {threat_intensity} on a scale from 1-100. "
            "Provide enough details and a thorough story/scenario to explain the context/story as well as thoroughly "
            "explain the attack in a technical way and how it works in 3 paragraphs with a minimum of 7 sentences each. "
            "Then output actors in another paragraph (at least 5 sentences), then potential risks in another paragraph (at least 5 sentences), "
            "then mitigation steps in another paragraph (at least 5 sentences). Use paragraph breaks (new lines '\\n') between each section, "
            "so it is easy to read. Each section should be easy to understand but also in depth, technical, and educational."
        )

        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="gpt-4o",
            max_tokens=1200,
            temperature=0.6,
            stream=True
        )

        def generator():
            try:
                for chunk in response:
                    if chunk.choices and chunk.choices[0].delta:
                        content = getattr(chunk.choices[0].delta, "content", None)
                        if content:
                            yield content
            except Exception as e:
                logger.error(f"Error while streaming scenario: {str(e)}")
                yield f"\n[Error occurred during streaming: {str(e)}]\n"

        return generator()

    except Exception as e:
        logger.error(f"Error generating scenario: {str(e)}")
        def err_gen():
            yield f"[Error generating scenario: {str(e)}]"
        return err_gen()

def break_down_scenario(scenario_text):
    """
    Break down the generated scenario into structured components.
    """
    return {
        "context": extract_context(scenario_text),
        "actors": extract_actors(scenario_text),
        "risks": extract_risks(scenario_text),
        "mitigation_steps": extract_mitigation(scenario_text)
    }

def extract_context(scenario_text):
    context_match = re.search(r"(.*?)(?:The attack|The adversary|The threat)", scenario_text, re.IGNORECASE)
    return context_match.group(0).strip() if context_match else "Context not found."

def extract_actors(scenario_text):
    actors_match = re.findall(r"\b(?:threat actor|adversary|attacker|insider)\b.*?", scenario_text, re.IGNORECASE)
    return actors_match if actors_match else ["Actors not found."]

def extract_risks(scenario_text):
    risks_match = re.findall(r"(risk of .*?)(\.|;|:)", scenario_text, re.IGNORECASE)
    risks = [risk[0] for risk in risks_match]
    return risks if risks else ["Risks not found."]

def extract_mitigation(scenario_text):
    mitigation_match = re.findall(r"(mitigation step|to mitigate|response step): (.*?)(\.|;|:)", scenario_text, re.IGNORECASE)
    mitigations = [step[1] for step in mitigation_match]
    return mitigations if mitigations else ["Mitigation steps not found."]

def generate_interactive_questions(scenario_text, retry_count=0):
    """
    Generate interactive multiple-choice questions based on scenario_text, streaming by default.
    Retries up to 2 times if the response doesn't meet the criteria.
    """
    system_instructions = (
        "You are a highly intelligent cybersecurity tutor. You must follow formatting instructions exactly, "
        "with no extra disclaimers or commentary."
    )

    user_prompt = f"""
Below is a detailed cyberattack scenario:

{scenario_text}

Your task:
1) Generate exactly THREE advanced, non-trivial multiple-choice questions based on the scenario, requiring critical thinking or specialized cybersecurity knowledge beyond merely re-reading the text.
2) Each question must have four options labeled 'A', 'B', 'C', and 'D' (no extra letters or symbols).
3) Indicate the correct answer with a key 'correct_answer' whose value is a single letter (e.g., 'B').
4) Provide a concise 'explanation' focusing on why the correct answer is correct (and relevant to the scenario or cybersecurity concepts).
5) Your output MUST be a valid JSON array with exactly three objects. No disclaimers, no extra text, and no surrounding characters.

Example format:

[
  {{
    "question": "Given the company's reliance on AI, which method best defends against membership inference?",
    "options": {{
      "A": "Basic encryption",
      "B": "Differential privacy",
      "C": "Physical access controls",
      "D": "Frequent model re-training"
    }},
    "correct_answer": "B",
    "explanation": "Differential privacy adds noise to the data, making it harder for attackers to infer membership."
  }},
  // ... two more questions
]

Nothing else.
"""

    try:
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_instructions},
                {"role": "user", "content": user_prompt},
            ],
            model="gpt-4o",
            max_tokens=1200,
            temperature=0.3,
            stream=True
        )

        accumulated_response = ""
        try:
            for chunk in response:
                if chunk.choices and chunk.choices[0].delta:
                    content = getattr(chunk.choices[0].delta, "content", None)
                    if content:
                        accumulated_response += content
        except Exception as e:
            logger.error(f"Error streaming interactive questions: {str(e)}")
            if retry_count < 2:
                logger.info(f"Retrying interactive questions generation (Attempt {retry_count + 2})")
                return generate_interactive_questions(scenario_text, retry_count + 1)
            else:
                return [{"error": f"Error occurred: {str(e)}"}]


        try:

            cleaned_response = accumulated_response.strip()


            if cleaned_response.startswith("```"):

                closing_fence = cleaned_response.find("```", 3)
                if closing_fence != -1:
                    cleaned_response = cleaned_response[3:closing_fence].strip()
                else:

                    cleaned_response = cleaned_response[3:].strip()


            if cleaned_response.lower().startswith("json"):
                cleaned_response = cleaned_response[4:].strip()


            parsed = json.loads(cleaned_response)
            if isinstance(parsed, list) and len(parsed) == 3:
                logger.debug("Successfully generated three interactive questions.")
                return parsed
            else:
                logger.error("Model did not generate exactly three questions.")
                if retry_count < 2:
                    logger.info(f"Retrying interactive questions generation (Attempt {retry_count + 2})")
                    return generate_interactive_questions(scenario_text, retry_count + 1)
                else:
                    return [{"error": "Failed to generate exactly three questions."}]
        except json.JSONDecodeError as je:
            logger.error(f"JSON decode error: {je}")
            logger.error(f"Content received: {accumulated_response}")
            if retry_count < 2:
                logger.info(f"Retrying interactive questions generation (Attempt {retry_count + 2})")
                return generate_interactive_questions(scenario_text, retry_count + 1)
            else:
                return [{"error": "JSON decoding failed."}]

    except Exception as e:
        logger.error(f"Error generating interactive questions: {e}")
        if retry_count < 2:
            logger.info(f"Retrying interactive questions generation (Attempt {retry_count + 2})")
            return generate_interactive_questions(scenario_text, retry_count + 1)
        else:
            return [{"error": f"Error generating interactive questions: {str(e)}"}]





alos merge the two grc helpers and keep the streaming
import logging
import json
from API.AI import client

logger = logging.getLogger(__name__)

def generate_grc_questions_stream(category, difficulty):
    """
    Streams EXACTLY THREE advanced GRC questions in a JSON array, but chunk-by-chunk
    rather than word-by-word. This means we yield partial content from GPT as it arrives
    without splitting on spaces. The front end can display partial JSON in real time.
    """

    prompt = f"""
You are an expert in concepts found in certifications like CISSP, CompTIA Advanced Security Practitioner (CASP+), CISM, CRISC, and others. 
Your role is to generate challenging and diverse test questions related to governance, risk management, risk thresholds, types of risk, 
Audit, Management, Policy, Cyber Security Ethics, Threat Assessment, Leadership, Business Continuity, compliance, regulations, 
incident response, and more, focusing on preparing for exams like CISSP and CompTIA certifications. Ensure the questions cover a wide 
range of scenarios, principles, and concepts, with multiple-choice answers that are nuanced, complex, and specific, avoiding repetitive 
patterns or overly simplified examples.

CONTEXT: The user has selected:
- Category: {category}
- Difficulty: {difficulty}

REQUIREMENTS:
1. Generate EXACTLY 3 questions in one JSON array. Each question has:
   - "question": string,
   - "options": array of exactly 4 strings (indexes 0,1,2,3),
   - "correct_answer_index": integer (0,1,2,3),
   - "explanations": object with keys "0","1","2","3" (multi-sentence detail),
   - "exam_tip": short mnemonic/hint.

2. The correct answer's explanation has at least 3 sentences describing precisely why it is correct, 
   and also clarifies why the others are incorrect.

3. Each incorrect answer's explanation has multiple sentences explaining why it is wrong, 
   plus clarifies what the correct choice is and why the other answer choices are also incorrect or less suitable.

4. Provide an "exam_tip" as a short, memorable mnemonic or hint to help the test-taker recall the correct concept.

5. Return ONLY the JSON array with exactly 3 objects. No extra text, disclaimers, or preludes.

6. Each explanation must be at least 3 sentences, offering substantial detail and conceptual clarity.

Now generate the JSON object following these instructions. 
Remember: 3 items in the array, each question shaped as above, nothing else.
"""

    try:
        # Make the streaming request to GPT
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=3000,  # Adjust as needed
            temperature=0.7,  # Adjust as needed
            stream=True
        )

        def generator():
            try:
                for chunk in response:
                    delta = chunk.choices[0].delta
                    if delta:
                        content = getattr(delta, "content", None)
                        if content:
                            # **Chunk-based** streaming (no splitting on spaces):
                            yield content
            except Exception as e:
                logger.error(f"Error streaming GRC questions: {e}")
                yield ""

        return generator()

    except Exception as e:
        logger.error(f"Error generating GRC questions (stream): {e}")

        def err_gen():
            yield ""
        return err_gen()

import os
import json
import logging
import re  
from API.AI import client

logger = logging.getLogger(__name__)

def generate_grc_question(category, difficulty):
    """
    Generates a GRC-related multiple-choice question in JSON format.
    The model returns a JSON object with keys:
      question (string)
      options (array of 4 strings)
      correct_answer_index (int)
      explanations (dict of strings for "0","1","2","3")
      exam_tip (string)
    """

    prompt = f""" 
You are an expert in concepts found in certifications like CISSP, CompTIA Advanced Security Practitioner (CASP+), CISM, CRISC, and others. Your role is to generate 
challenging and diverse test questions using advanced mult-layered reasoning, related to governance, risk management, risk thresholds, types of risk, Audit, Management, Policy, Cyber Security Ethics, Threat Assessment, 
Leadership, Business Continuity, compliance, regulations, incident resposne, Incident Response and more. focusing on preparing for exams like CISSP/ISC2 and CompTIA certifications. Ensure the questions cover a wide range of scenarios,
principles, and concepts, with multiple-choice answers that are nuanced and complex and specific, avoiding repetitive patterns or overly simplified examples.

CONTEXT: The user has selected:
- Category: {category} (e.g., 'Regulation', 'Risk Management', 'Compliance', 'Audit', 'Governance', 'Management', 'Policy', 'Ethics', 'Threat Assessment', 'Leadership', 'Business Continuity', 'Incident Response', 'Random')
- Difficulty: {difficulty} (e.g., 'Easy', 'Medium', 'Hard')

REQUIREMENTS
1. Four options (0, 1, 2, 3) total, one correct answer. The incorrect options should be very plausible but not correct, requiring the test-taker to carefully differentiate.

2. Explanations:
   - For the correct answer: Provide multiple sentences detailing exactly why it’s correct, clearly tying it back to the question’s scenario or concept. Show how it fulfills the requirements asked in the question as well as why the other answer choices are incorrect/not the correct answer..
   - For each incorrect answer: Provide multiple sentences detailing why it is NOT correct aswell as why the other incorrect answer choices are incorrect, and why then tell the user what the correct answer is and why it is correct using advanced multi-layered reasoning. 
     Do not just say it’s incorrect; fully explain why it falls short. 
     Highlight conceptual differences, limitations, or focus areas that differ from the question’s criteria.
   - Regardless of user choice, the generated output must contain full explanations for all answer choices provided. The explanations are produced in advance as part of the JSON object. Each explanation should be at least 3 sentences, rich in detail and conceptual clarity using advanced multi-layered reasoning.

3. Include an "exam_tip" field that provides a short, memorable takeaway or mnemonic to help differentiate the correct concept from the others. The exam tip should help the user recall why the correct answer stands out using advanced multi-layered reasoning.

4. Return ONLY a JSON object with the fields:
   "question", "options", "correct_answer_index", "explanations", and "exam_tip"
   No extra text, no Markdown, no commentary outside the JSON.

5. For each explanation (correct and incorrect):
   - At minimum of 3 sentences for the correct answer.
   - if the user gets the answer correct provide minium 3 senetence answer as to why it is correct, but also why the other answer choices listed are not the correct answer using advanced multi-layered reasoning.
   - Substantial detail.
   - Clearly articulate conceptual reasons, not just factual statements using advanced multi-layered reasoning.

EXAMPLE FORMAT (this is not real content, just structure, make sure to use all topics not just the topic provided in this example):
{{
  "question": "The question",
  "options": ["Option 0","Option 1","Option 2","Option 3"],
  "correct_answer_index": 2,
  "explanations": {{
    "0": "Explain thoroughly why option 0 fails. Mention its scope, focus areas, and why that doesn't meet the question criteria and then explain what the correct answer is and why it is correct aswell as why the other answer choices are incorrect using advanced multi-layered reasoning.",
    "1": "Explain thoroughly why option 1 fails. Mention its scope, focus areas, and why that doesn't meet the question criteria and then explain what the correct answer is and why it is correct aswell as why the other answer choices are incorrect using advanced multi-layered reasoning.",
    "2": "Explain thoroughly why option 2 is correct, linking its characteristics to the question scenario and why the other answer choices are incorrect using advanced multi-layered reasoning",
    "3": "Explain thoroughly why option 3 fails. Mention its scope, focus areas, and why that doesn't meet the question criteria and then explain what the correct answer is and why it is correct aswell as why the other answer choices are incorrect using advanced multi-layered reasoning."
  }},
  "exam_tip": "A short, memorable hint or mnemonic that differentiates the correct approach from others using advanced multi-layered reasoning."
}}

Now generate the JSON object following these instructions.
"""



    try:
        response = client.chat.completions.create(
            model="gpt-4o",  
            messages=[{"role": "user", "content": prompt}],
            max_tokens=900,
            temperature=0.6,
        )

        content = response.choices[0].message.content.strip()

      
        content = re.sub(r'^```.*\n', '', content)
        content = re.sub(r'\n```$', '', content)

        try:
            generated_question = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error("JSON parsing error in generate_grc_question: %s", e)
            logger.error("Model returned: %s", content)
            raise ValueError("Model did not return valid JSON.") from e

        logger.info("Generated GRC question successfully.")
        return generated_question

    except Exception as e:
        logger.error(f"Error generating GRC question: {str(e)}")
        raise



heres anlogy helper
import os
import logging
from API.AI import client


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def generate_single_analogy(concept, category):
    """
    Generate a single analogy for the given concept and category.
    """
    prompt = (
        f"Generate an analogy for the concept '{concept}' using the context of '{category}'. "
        "Make it easy to understand but informative and in a teaching style, concise but in depth, and entertaining,  with one key info at the end to make sure the info is remembered.Do not explicilty say that you will create the analogy just output the analogy/explantion only e.g to not show: Sure! Let's dive into the fascinating world of cybersecurity using an analogy that you might find both informative and entertaining or any other variants"
    )

    try:
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="gpt-4o",
            max_tokens=750,
            temperature=0.7,
        )
        return response.choices[0].message.content.strip()

    except Exception as e:
        logger.error(f"Error generating single analogy: {e}")
        return "An error occurred while generating the analogy."

def generate_comparison_analogy(concept1, concept2, category):
    """
    Generate a comparison analogy between two concepts and a category.
    """
    prompt = (
        f"Compare '{concept1}' and '{concept2}' using an analogy in the context of '{category}'. "
        "Explain how they are similar and different or how they might work in conjunction with each other, in a teaching style, informative, concise but in depth, and entertaining,  with one key info at the end to make sure the info is rememebered. Do not explicilty say that you will create the analogy just output the analogy/explantion only e.g to not show: Sure! Let's dive into the fascinating world of cybersecurity using an analogy that you might find both informative and entertaining or any other variants"
    )

    try:
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="gpt-4o",
            max_tokens=1000,
            temperature=0.7,
        )
        return response.choices[0].message.content.strip()

    except Exception as e:
        logger.error(f"Error generating comparison analogy: {e}")
        return "An error occurred while generating the analogy."

def generate_triple_comparison_analogy(concept1, concept2, concept3, category):
    """
    Generate a comparison analogy among three concepts and a category.
    """
    prompt = (
        f"Compare '{concept1}', '{concept2}', and '{concept3}' using an analogy in the context of '{category}'. "
        "Explain how they are similar and different or how they might work in conjuction with each other, in a teaching style, informative, concise but in depth, and entertaining, with one key info at the end to make sure the info is rememebered.Do not explicilty say that you will create the analogy just output the analogy/explantion only e.g to not show: Sure! Let's dive into the fascinating world of cybersecurity using an analogy that you might find both informative and entertaining or any other variants"
    )

    try:
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="gpt-4o",
            max_tokens=1200,
            temperature=0.7,
        )
        return response.choices[0].message.content.strip()

    except Exception as e:
        logger.error(f"Error generating triple comparison analogy: {e}")
        return "An error occurred while generating the analogy."






ok also and answer me this question

shoud i keep the scenerio/grc/xploit async tasks? what do they imporve/benift?? what do they help wotuh? are they worth aving?? what do they do specifially?? an do rate limiters need to be in here aswell? 
###############################
# helpers/async_tasks.py (UPDATED)
###############################
from celery import shared_task
from datetime import datetime, timedelta
import math
import logging
import requests
from helpers.celery_app import app
from mongodb.database import db

# ---------  AI Generation Imports -----------
from helpers.analogy_helper import (
    generate_single_analogy as _generate_single_analogy,
    generate_comparison_analogy as _generate_comparison_analogy,
    generate_triple_comparison_analogy as _generate_triple_comparison_analogy
)

from helpers.scenario_helper import (
    generate_scenario as _generate_scenario,
    break_down_scenario as _break_down_scenario,
    generate_interactive_questions as _generate_interactive_questions
)

from helpers.xploitcraft_helper import Xploits as _Xploits
from helpers.grc_helper import generate_grc_question as _generate_grc_question

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# -----------------------------
# Celery tasks for analogy
# -----------------------------

@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_single_analogy_task(self, concept, category):
    try:
        return _generate_single_analogy(concept, category)
    except Exception as e:
        logger.error(f"Celery generate_single_analogy_task error: {e}")
        self.retry(exc=e)


@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_comparison_analogy_task(self, concept1, concept2, category):
    try:
        return _generate_comparison_analogy(concept1, concept2, category)
    except Exception as e:
        logger.error(f"Celery generate_comparison_analogy_task error: {e}")
        self.retry(exc=e)


@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_triple_comparison_analogy_task(self, concept1, concept2, concept3, category):
    try:
        return _generate_triple_comparison_analogy(concept1, concept2, concept3, category)
    except Exception as e:
        logger.error(f"Celery generate_triple_comparison_analogy_task error: {e}")
        self.retry(exc=e)


# -----------------------------
# Celery tasks for Scenario
# -----------------------------

@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_scenario_task(self, industry, attack_type, skill_level, threat_intensity):
    """
    If _generate_scenario returns a streaming generator, we join it into one string 
    so that Celery can store/return that as the task result.
    """
    try:
        scenario_gen = _generate_scenario(industry, attack_type, skill_level, threat_intensity)
        scenario_text = "".join(scenario_gen)  # Convert generator of strings into a single string
        return scenario_text
    except Exception as e:
        logger.error(f"Celery generate_scenario_task error: {e}")
        self.retry(exc=e)


@app.task(bind=True, max_retries=3, default_retry_delay=10)
def break_down_scenario_task(self, scenario_text):
    """
    Takes a scenario and 'breaks it down' into context, actors, timeline, etc.
    """
    try:
        return _break_down_scenario(scenario_text)
    except Exception as e:
        logger.error(f"Celery break_down_scenario_task error: {e}")
        self.retry(exc=e)


@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_interactive_questions_task(self, scenario_text):
    """
    Gathers the chunked question output into a final string or JSON object.
    """
    try:
        questions_gen = _generate_interactive_questions(scenario_text)
        questions_text = "".join(questions_gen)
        return questions_text
    except Exception as e:
        logger.error(f"Celery generate_interactive_questions_task error: {e}")
        self.retry(exc=e)


# -----------------------------
# Celery tasks for Xploitcraft
# -----------------------------
_xploit = _Xploits()

@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_exploit_payload_task(self, vulnerability, evasion_technique):
    try:
        return _xploit.generate_exploit_payload(vulnerability, evasion_technique)
    except Exception as e:
        logger.error(f"Celery generate_exploit_payload_task error: {e}")
        self.retry(exc=e)


# -----------------------------
# Celery tasks for GRC
# -----------------------------
@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_grc_question_task(self, category, difficulty):
    try:
        return _generate_grc_question(category, difficulty)
    except Exception as e:
        logger.error(f"Celery generate_grc_question_task error: {e}")
        self.retry(exc=e)


# -----------------------------
# Performance Metrics Aggregator
# -----------------------------
@shared_task
def aggregate_performance_metrics():
    """
    Runs every 3 minutes to gather perfSamples from the past 3 minutes,
    compute average request time, DB query time, data transfer rate, throughput, etc.
    Then store in 'performanceMetrics'. We'll keep the last 20 records in the front end.
    """

    now = datetime.utcnow()
    three_min_ago = now - timedelta(minutes=3)

    samples = list(db.perfSamples.find({"timestamp": {"$gte": three_min_ago}}))
    total_requests = len(samples)
    if total_requests == 0:
        return  # No aggregator doc if no data

    total_duration = 0.0
    total_db_time = 0.0
    total_bytes = 0
    errors = 0

    for s in samples:
        total_duration += s.get("duration_sec", 0.0)
        total_db_time += s.get("db_time_sec", 0.0)
        total_bytes += s.get("response_bytes", 0)
        if s.get("http_status", 200) >= 400:
            errors += 1

    avg_request_time = (total_duration / total_requests) if total_requests else 0
    avg_db_query_time = (total_db_time / total_requests) if total_requests else 0
    error_rate = (errors / total_requests) if total_requests else 0.0

    # data_transfer_rate in MB/s (numeric float)
    data_transfer_rate_mb_s = 0.0
    if total_duration > 0:
        data_transfer_rate_mb_s = (total_bytes / (1024.0 * 1024.0)) / total_duration

    # throughput => requests / 3min => convert to requests/min
    # total_requests / 3.0 => requests per minute if we polled 3-min block.
    throughput = (total_requests / 3.0)

    doc = {
        "avg_request_time": round(avg_request_time, 4),         # in seconds
        "avg_db_query_time": round(avg_db_query_time, 4),       # also in seconds, store raw for now
        "data_transfer_rate": round(data_transfer_rate_mb_s, 3),# float in MB/s, no label text
        "throughput": round(throughput, 2),                     # requests/min
        "error_rate": round(error_rate, 4),                     # fraction: 0.0 -> 1.0
        "timestamp": now
    }
    db.performanceMetrics.insert_one(doc)

    # Optionally remove older perfSamples beyond X minutes to save space
    # e.g. keep only 60 minutes in raw samples:
    sixty_min_ago = now - timedelta(minutes=60)
    db.perfSamples.delete_many({"timestamp": {"$lt": sixty_min_ago}})

    # (Optional) Also remove old performanceMetrics older than 2 hours, if desired:
    two_hours_ago = now - timedelta(hours=2)
    db.performanceMetrics.delete_many({"timestamp": {"$lt": two_hours_ago}})

    return f"Aggregated {total_requests} samples into performanceMetrics."

@app.task(bind=True, max_retries=3, default_retry_delay=10)
def check_api_endpoints(self):
    """
    Ping a small set of always-GET-friendly endpoints to confirm the Flask app is up.
    """
    endpoints = [
        "http://backend:5000/health",
        "http://backend:5000/test/achievements",
        "http://backend:5000/test/leaderboard"
    ]

    results = []
    now = datetime.utcnow()
    for ep in endpoints:
        try:
            r = requests.get(ep, timeout=5)
            status = r.status_code
            ok = (status < 400)
            results.append({"endpoint": ep, "status": status, "ok": ok})
        except Exception as e:
            results.append({"endpoint": ep, "status": "error", "ok": False, "error": str(e)})

    doc = {
        "checkedAt": now,
        "results": results
    }
    db.apiHealth.insert_one(doc)
    return True

# -----------------------------
# NEW: Cleanup logs for auditLogs & apiHealth
# -----------------------------
@shared_task
def cleanup_logs():
    """
    Removes old audit logs and apiHealth docs older than 30 days.
    Runs daily (per the schedule in celery_app).
    """
    now = datetime.utcnow()
    cutoff = now - timedelta(days=3)


    deleted_audit = db.auditLogs.delete_many({"timestamp": {"$lt": cutoff}})


    deleted_health = db.apiHealth.delete_many({"checkedAt": {"$lt": cutoff}})

    logger.info(f"Cleaned logs older than 30 days => auditLogs: {deleted_audit.deleted_count}, "
                f"apiHealth: {deleted_health.deleted_count}")

    return f"Cleanup complete: auditLogs={deleted_audit.deleted_count}, apiHealth={deleted_health.deleted_count}"



ok now add the rate limiters to thri repstive files, merge teh grc helper and grc stream helepr and mkae it so it works the saem but only has teh streaming fucnitolity. -then output each helepr file in full updated

then asnwer me teh async task questions i asked.



ok go.

