// frontend/my-react-app/src/components/pages/angela/components/FeatureSection.js
import React, { useState, useEffect, useRef } from 'react';
import styled from '@emotion/styled';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';
import { getRandomQuote } from '../utils/philosophicalQuotes';
import { 
  FaBrain, 
  FaCogs, 
  FaSearch, 
  FaShieldAlt, 
  FaTerminal, 
  FaCode, 
  FaGlobe, 
  FaLightbulb 
} from 'react-icons/fa';

// Main container for the feature section
const FeatureSectionContainer = styled.section`
  padding: 4rem 2rem;
  position: relative;
  overflow: hidden;
  max-width: 1200px;
  margin: 0 auto;
  
  @media (max-width: ${THEME.breakpoints.md}) {
    padding: 3rem 1rem;
  }
`;

// Section title with 8-bit styling
const SectionTitle = styled.h2`
  font-family: ${THEME.typography.fontFamilySecondary};
  font-size: 3rem;
  color: ${THEME.colors.textPrimary};
  text-align: center;
  margin-bottom: 3rem;
  text-transform: uppercase;
  letter-spacing: ${THEME.typography.spacingWide};
  position: relative;
  
  &::after {
    content: "";
    position: absolute;
    bottom: -1rem;
    left: 50%;
    transform: translateX(-50%);
    width: 80px;
    height: 4px;
    background-color: ${THEME.colors.accentPrimary};
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 2.25rem;
  }
`;

// Container for the feature grid
const FeaturesGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 2rem;
  max-width: 1200px;
  margin: 0 auto;
`;

// Individual feature card with pixel art styling
const FeatureCard = styled.div`
  background-color: ${THEME.colors.bgSecondary};
  border: 2px solid ${THEME.colors.borderPrimary};
  border-radius: 8px;
  padding: 1.5rem;
  transition: all 0.3s ease;
  position: relative;
  transform-style: preserve-3d;
  perspective: 1000px;
  height: 100%;
  display: flex;
  flex-direction: column;
  
  &:hover {
    transform: translateY(-5px);
    border-color: ${THEME.colors.accentPrimary};
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
    
    .feature-icon {
      transform: translateZ(20px) rotateY(10deg);
      color: ${THEME.colors.accentPrimary};
    }
  }
  
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    box-shadow: inset 0 0 20px rgba(0, 0, 0, 0.5);
    pointer-events: none;
    z-index: 0;
    border-radius: 8px;
  }
  
  // Pixelated corners
  &::after {
    content: "";
    position: absolute;
    top: -2px;
    left: -2px;
    right: -2px;
    bottom: -2px;
    z-index: -1;
    border: 2px solid ${THEME.colors.bgSecondary};
    clip-path: polygon(
      0% 8px, 8px 8px, 8px 0%, calc(100% - 8px) 0%, calc(100% - 8px) 8px, 100% 8px, 
      100% calc(100% - 8px), calc(100% - 8px) calc(100% - 8px), calc(100% - 8px) 100%, 
      8px 100%, 8px calc(100% - 8px), 0% calc(100% - 8px)
    );
  }
`;

// Feature icon container 
const FeatureIconContainer = styled.div`
  font-size: 2.5rem;
  color: ${THEME.colors.terminalGreen};
  margin-bottom: 1rem;
  transition: all 0.3s ease;
  transform: translateZ(0);
  display: flex;
  align-items: center;
  justify-content: center;
  
  svg {
    filter: drop-shadow(0 0 5px rgba(51, 255, 51, 0.3));
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 2rem;
  }
`;

// Feature title
const FeatureTitle = styled.h3`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1.5rem;
  color: ${THEME.colors.textPrimary};
  margin-bottom: 1rem;
  font-weight: ${THEME.typography.weightBold};
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 1.25rem;
  }
`;

// Feature description
const FeatureDescription = styled.p`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1rem;
  color: ${THEME.colors.textSecondary};
  line-height: 1.6;
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 0.9rem;
  }
`;

// Philosophical quote display with typing animation
const PhilosophicalQuoteContainer = styled.div`
  margin: 4rem auto;
  max-width: 800px;
  text-align: center;
  padding: 2rem;
  background-color: ${THEME.colors.bgSecondary}80;
  border: 1px solid ${THEME.colors.borderPrimary};
  position: relative;
  border-radius: 8px;
  
  &::before {
    content: """;
    position: absolute;
    top: -1.5rem;
    left: 1rem;
    font-size: 6rem;
    color: ${THEME.colors.accentPrimary}40;
    font-family: ${THEME.typography.fontFamilyPhilosophical};
  }
`;

// Quote text with typing animation
const QuoteText = styled.div`
  font-family: ${THEME.typography.fontFamilyPhilosophical};
  font-style: italic;
  font-size: 1.5rem;
  color: ${THEME.colors.textPrimary};
  margin-bottom: 1rem;
  line-height: 1.6;
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 1.25rem;
  }
`;

// Quote attribution
const QuoteAttribution = styled.div`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1rem;
  color: ${THEME.colors.textSecondary};
  
  &::before {
    content: "— ";
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 0.9rem;
  }
`;

// Interactive terminal example section
const InteractiveExample = styled.div`
  margin: 4rem auto;
  max-width: 800px;
  background-color: ${THEME.colors.bgPrimary};
  border: 2px solid ${THEME.colors.borderPrimary};
  border-radius: 8px;
  overflow: hidden;
  position: relative;
  
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(
      rgba(18, 16, 16, 0) 50%, 
      rgba(0, 0, 0, 0.1) 50%
    );
    background-size: 100% 4px;
    z-index: 0;
    opacity: 0.1;
    pointer-events: none;
  }
`;

// Terminal header with buttons
const ExampleHeader = styled.div`
  height: 36px;
  background-color: ${THEME.colors.bgSecondary};
  display: flex;
  align-items: center;
  padding: 0 12px;
  border-bottom: 1px solid ${THEME.colors.borderPrimary};
  
  .title {
    flex-grow: 1;
    text-align: center;
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 14px;
    color: ${THEME.colors.textSecondary};
  }
  
  .buttons {
    display: flex;
    gap: 8px;
  }
  
  .button {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    
    &.red {
      background-color: ${THEME.colors.errorRed};
    }
    
    &.yellow {
      background-color: ${THEME.colors.terminalYellow};
    }
    
    &.green {
      background-color: ${THEME.colors.terminalGreen};
    }
  }
`;

// Terminal content area
const ExampleContent = styled.div`
  padding: 16px;
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 14px;
  line-height: 1.6;
  color: ${THEME.colors.textPrimary};
  max-height: 400px;
  overflow-y: auto;
  white-space: pre-wrap;
  
  .input {
    color: ${THEME.colors.textPrimary};
    margin-bottom: 8px;
    display: flex;
    
    .prompt {
      color: ${THEME.colors.terminalGreen};
      margin-right: 8px;
    }
  }
  
  .output {
    color: ${THEME.colors.textSecondary};
    margin-bottom: 16px;
  }
  
  .angela-output {
    color: ${THEME.colors.accentPrimary};
    margin-bottom: 16px;
  }
  
  .error {
    color: ${THEME.colors.errorRed};
    margin-bottom: 16px;
  }
  
  .code-block {
    background-color: ${THEME.colors.bgTertiary};
    padding: 8px;
    border-radius: 4px;
    margin: 8px 0;
    overflow-x: auto;
  }
`;

// Terminal input area
const ExampleInput = styled.div`
  display: flex;
  align-items: center;
  padding: 8px 16px 16px;
  border-top: 1px solid ${THEME.colors.borderPrimary};
  
  .prompt {
    color: ${THEME.colors.terminalGreen};
    margin-right: 8px;
    font-family: ${THEME.typography.fontFamilyPrimary};
  }
  
  input {
    flex-grow: 1;
    background: transparent;
    border: none;
    color: ${THEME.colors.textPrimary};
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 14px;
    outline: none;
    
    &::placeholder {
      color: ${THEME.colors.textTertiary};
    }
  }
`;

// Example buttons for predefined commands
const ExampleButtons = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 1rem;
  justify-content: center;
  
  button {
    background-color: ${THEME.colors.bgSecondary};
    border: 1px solid ${THEME.colors.borderPrimary};
    color: ${THEME.colors.textSecondary};
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 0.9rem;
    padding: 0.5rem 1rem;
    cursor: pointer;
    transition: all 0.2s ease;
    border-radius: 4px;
    
    &:hover {
      background-color: ${THEME.colors.bgTertiary};
      border-color: ${THEME.colors.accentPrimary};
      color: ${THEME.colors.textPrimary};
    }
  }
`;

/**
 * Feature data with icons, titles, and descriptions
 */
const FEATURES = [
  {
    icon: <FaBrain />,
    title: "Natural Language Understanding",
    description: "Angela interprets human language to extract intent, parameters, and goals, allowing you to use plain English instead of complex command syntax."
  },
  {
    icon: <FaCogs />,
    title: "Multi-Step Operation Planning",
    description: "Decomposes complex requests into coherent sequences of steps with dependencies and error handling, automating sophisticated workflows."
  },
  {
    icon: <FaSearch />,
    title: "Project Context Awareness",
    description: "Automatically detects project types, dependencies, and frameworks to provide intelligent suggestions and accurate command generation."
  },
  {
    icon: <FaShieldAlt />,
    title: "Built-in Safety Mechanisms",
    description: "Comprehensive safety features including command previews, risk assessment, impact analysis, and transaction-based rollback capabilities."
  },
  {
    icon: <FaTerminal />,
    title: "Enhanced Shell Integration",
    description: "Deeply integrates with Bash, Zsh, and Tmux for a seamless experience with keybindings, status indicators, and auto-completion."
  },
  {
    icon: <FaCode />,
    title: "Semantic Code Understanding",
    description: "Analyzes your codebase to understand functions, classes, and APIs, providing context-aware assistance and refactoring suggestions."
  },
  {
    icon: <FaGlobe />,
    title: "Cross-Tool Orchestration",
    description: "Coordinates complex sequences across multiple development tools (Git, Docker, cloud CLIs) maintaining context and data flow between steps."
  },
  {
    icon: <FaLightbulb />,
    title: "Proactive Suggestions",
    description: "Monitors command errors, Git state, and file changes to offer timely advice and automated fixes when appropriate."
  }
];

/**
 * Example commands and their responses
 */
const EXAMPLE_RESPONSES = {
  "find all JavaScript files modified in the last week": [
    { type: "angela-output", text: "I'll find all JavaScript files that have been modified in the last week." },
    { type: "output", text: "Generating command based on your request...\nExecuting: find . -name \"*.js\" -mtime -7 -type f" },
    { type: "output", text: "./src/components/Auth.js\n./src/utils/api.js\n./src/hooks/useForm.js" },
    { type: "angela-output", text: "Found 3 JavaScript files modified in the last week. Would you like me to analyze these files or perform any operations on them?" }
  ],
  "create a feature branch for user authentication": [
    { type: "angela-output", text: "I'll help you create a feature branch for user authentication." },
    { type: "output", text: "Checking current Git status...\n" },
    { type: "output", text: "On branch main\nYour branch is up to date with 'origin/main'.\nnothing to commit, working tree clean" },
    { type: "angela-output", text: "Creating feature branch: feature/user-authentication...\nExecuting: git checkout -b feature/user-authentication" },
    { type: "output", text: "Switched to a new branch 'feature/user-authentication'" },
    { type: "angela-output", text: "Feature branch created successfully. Would you like me to set up a basic authentication structure for this feature?" }
  ],
  "deploy to production and notify the team": [
    { type: "angela-output", text: "I'll execute a deployment to production and notify the team when complete." },
    { type: "output", text: "Starting deployment process...\n" },
    { type: "output", text: "Step 1/4: Building production assets\nExecuting: npm run build" },
    { type: "output", text: "Build completed successfully." },
    { type: "output", text: "Step 2/4: Running test suite\nExecuting: npm test" },
    { type: "output", text: "All tests passed successfully." },
    { type: "output", text: "Step 3/4: Deploying to production server\nExecuting: deploy.sh --env=production" },
    { type: "output", text: "Deployment completed successfully.\nApplication deployed to https://example.com" },
    { type: "output", text: "Step 4/4: Notifying team via Slack\nExecuting: slack-notify \"Version 2.1.0 has been deployed to production by $(whoami)\"" },
    { type: "angela-output", text: "Deployment complete! Application is now live at https://example.com and the team has been notified." }
  ],
  "find and kill process using port 3000": [
    { type: "angela-output", text: "I'll identify and terminate the process using port 3000." },
    { type: "output", text: "Searching for process using port 3000...\nExecuting: lsof -i :3000" },
    { type: "output", text: "COMMAND  PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nnode    3542 username   21u  IPv6 149383      0t0  TCP *:3000 (LISTEN)" },
    { type: "angela-output", text: "Found process with PID 3542 (node) using port 3000. Preparing to terminate..." },
    { type: "angela-output", text: "Executing: kill -9 3542" },
    { type: "output", text: "Process terminated successfully." },
    { type: "angela-output", text: "Port 3000 is now available for use. Would you like to start a new service on this port?" }
  ]
};

/**
 * FeatureSection Component
 * 
 * Displays the key features of Angela CLI with interactive examples and a philosophical quote.
 */
const FeatureSection = ({ icons }) => {
  const [quote, setQuote] = useState(getRandomQuote());
  const [terminalHistory, setTerminalHistory] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const inputRef = useRef(null);
  const contentRef = useRef(null);
  
  // Change philosophical quote periodically
  useEffect(() => {
    const interval = setInterval(() => {
      setQuote(getRandomQuote());
    }, 15000);
    
    return () => clearInterval(interval);
  }, []);
  
  // Handle terminal input
  const handleInputChange = (e) => {
    setInputValue(e.target.value);
  };
  
  // Handle terminal command submission
  const handleInputSubmit = (e, command = null) => {
    e?.preventDefault();
    
    const cmd = command || inputValue;
    if (!cmd) return;
    
    // Add command to history
    setTerminalHistory(prev => [
      ...prev,
      { type: 'input', text: cmd }
    ]);
    
    setInputValue('');
    setIsTyping(true);
    
    // Simulate typing responses
    const responses = EXAMPLE_RESPONSES[cmd] || [
      { type: "angela-output", text: "I understand you want to: " + cmd },
      { type: "output", text: "This is a demonstration. For actual functionality, please install Angela CLI." }
    ];
    
    // Add responses with delays to simulate typing
    let delay = 500;
    responses.forEach(response => {
      setTimeout(() => {
        setTerminalHistory(prev => [...prev, response]);
        
        // Scroll to bottom of terminal
        if (contentRef.current) {
          contentRef.current.scrollTop = contentRef.current.scrollHeight;
        }
      }, delay);
      
      delay += Math.max(500, response.text.length * 10);
    });
    
    // End typing animation
    setTimeout(() => {
      setIsTyping(false);
      
      // Focus input after responses
      if (inputRef.current) {
        inputRef.current.focus();
      }
      
      // Scroll to bottom of terminal
      if (contentRef.current) {
        contentRef.current.scrollTop = contentRef.current.scrollHeight;
      }
    }, delay);
  };
  
  return (
    <FeatureSectionContainer id="features">
      <SectionTitle>Key Features</SectionTitle>
      
      <FeaturesGrid>
        {FEATURES.map((feature, index) => (
          <FeatureCard key={index}>
            <FeatureIconContainer className="feature-icon">
              {feature.icon}
            </FeatureIconContainer>
            <FeatureTitle>{feature.title}</FeatureTitle>
            <FeatureDescription>{feature.description}</FeatureDescription>
          </FeatureCard>
        ))}
      </FeaturesGrid>
      
      <PhilosophicalQuoteContainer>
        <QuoteText>"{quote.text}"</QuoteText>
        <QuoteAttribution>{quote.author}</QuoteAttribution>
      </PhilosophicalQuoteContainer>
      
      <InteractiveExample>
        <ExampleHeader>
          <div className="buttons">
            <div className="button red"></div>
            <div className="button yellow"></div>
            <div className="button green"></div>
          </div>
          <div className="title">angela-cli ~ interactive-demo</div>
        </ExampleHeader>
        
        <ExampleContent ref={contentRef}>
          {/* Welcome message */}
          <div className="angela-output">
            Welcome to the Angela CLI interactive demo. Type a command or select one of the examples below.
          </div>
          
          {/* Terminal history */}
          {terminalHistory.map((entry, index) => {
            if (entry.type === 'input') {
              return (
                <div key={index} className="input">
                  <span className="prompt">$</span>
                  <span>angela "{entry.text}"</span>
                </div>
              );
            } else {
              return (
                <div key={index} className={entry.type}>
                  {entry.text}
                </div>
              );
            }
          })}
          
          {/* Typing indicator */}
          {isTyping && <div className="output">Angela is thinking...</div>}
        </ExampleContent>
        
        <form onSubmit={handleInputSubmit}>
          <ExampleInput>
            <span className="prompt">$</span>
            <input
              ref={inputRef}
              type="text"
              value={inputValue}
              onChange={handleInputChange}
              placeholder="Try an example command or type your own..."
              disabled={isTyping}
            />
          </ExampleInput>
        </form>
        
        <ExampleButtons>
          {Object.keys(EXAMPLE_RESPONSES).map((command, index) => (
            <button
              key={index}
              onClick={(e) => handleInputSubmit(e, command)}
              disabled={isTyping}
            >
              {command}
            </button>
          ))}
        </ExampleButtons>
      </InteractiveExample>
    </FeatureSectionContainer>
  );
};

export default FeatureSection;
