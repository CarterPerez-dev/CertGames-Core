// src/components/pages/angela/AngelaPage.js
import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { FaGithub, FaTerminal, FaDownload, FaArrowRight, FaPlayCircle, FaStar, FaCode, FaLaptopCode, FaShield, FaTools, FaRocket, FaBrain, FaNetworkWired, FaUserPlus, FaRegLightbulb } from 'react-icons/fa';
import './AngelaCLI.css';

const AngelaPage = () => {
  // State for animations and interactions
  const [activeSection, setActiveSection] = useState('hero');
  const [typedText, setTypedText] = useState('');
  const [currentTextIndex, setCurrentTextIndex] = useState(0);
  const [animationPhase, setAnimationPhase] = useState(0);
  const [showCursor, setShowCursor] = useState(true);
  const [isTerminalActive, setIsTerminalActive] = useState(false);
  const [terminalOutput, setTerminalOutput] = useState([]);
  const [userCommand, setUserCommand] = useState('');
  const [installCopied, setInstallCopied] = useState(false);
  const [isDemoPlaying, setIsDemoPlaying] = useState(false);
  
  // Refs for scrolling
  const featuresRef = useRef(null);
  const installRef = useRef(null);
  const demoRef = useRef(null);
  const docsRef = useRef(null);
  const aboutRef = useRef(null);
  
  // Terminal demo text animation sequences
  const terminalTexts = [
    "angela \"find all JavaScript files modified in the last week\"",
    "angela \"create a feature branch for user authentication\"",
    "angela \"commit all changes with a descriptive message\"",
    "angela \"generate a React component for a login form\"",
    "angela workflows create deploy",
    "angela \"help me understand this error message\""
  ];
  
  // Text cycling for hero typing animation
  const heroTexts = [
    "World's First AGI Command Line Intelligence",
    "Ask your terminal anything in plain English",
    "Let AI help you with complex commands",
    "Code, deploy, and manage with natural language"
  ];
  
  // Fake terminal commands and responses for demo
  const demoCommands = [
    {
      command: "angela \"find large log files created this week\"",
      output: [
        "🧠 Analyzing request and gathering context...",
        "📁 Project type detected: Node.js",
        "🔍 I'll execute: find . -name \"*.log\" -size +1M -mtime -7 -type f",
        "📋 This will find log files larger than 1MB created in the last 7 days",
        "",
        "Results:",
        "./logs/server-2025-05-09.log (4.2MB)",
        "./logs/error-2025-05-10.log (2.8MB)",
        "./tmp/debug-2025-05-11.log (1.5MB)",
        "",
        "✅ Command executed successfully!"
      ]
    },
    {
      command: "angela \"create a feature branch for the payment integration module\"",
      output: [
        "🧠 Analyzing request and gathering context...",
        "📁 Project type detected: Git repository",
        "🔄 Checking current branch: main",
        "🔍 I'll execute: git checkout -b feature/payment-integration",
        "",
        "Created branch 'feature/payment-integration'",
        "Switched to branch 'feature/payment-integration'",
        "",
        "✅ Branch created successfully! You're now working on feature/payment-integration"
      ]
    },
    {
      command: "angela \"generate a Python function that validates email addresses\"",
      output: [
        "🧠 Analyzing request and gathering context...",
        "📝 Generating Python email validation function...",
        "",
        "```python",
        "import re",
        "",
        "def validate_email(email):",
        "    \"\"\"",
        "    Validates an email address with comprehensive checks.",
        "    Returns True if valid, False otherwise.",
        "    \"\"\"",
        "    # Regular expression pattern for email validation",
        "    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'",
        "    ",
        "    # Basic pattern check",
        "    if not re.match(pattern, email):",
        "        return False",
        "        ",
        "    # Additional checks",
        "    # Check for consecutive dots in local part",
        "    if '..' in email.split('@')[0]:",
        "        return False",
        "        ",
        "    # Check domain part",
        "    domain = email.split('@')[1]",
        "    if '..' in domain or domain.startswith('.') or domain.endswith('.'):",
        "        return False",
        "        ",
        "    return True",
        "```",
        "",
        "✅ Function generated! Would you like me to add tests or enhance this function further?"
      ]
    }
  ];
  
  // Features data
  const features = [
    {
      icon: <FaTerminal />,
      title: "Natural Language Commands",
      description: "Ask your terminal to perform tasks in plain English - no need to remember complex syntax."
    },
    {
      icon: <FaLaptopCode />,
      title: "Project Awareness",
      description: "Angela understands your project context, frameworks, and dependencies to provide relevant assistance."
    },
    {
      icon: <FaShield />,
      title: "Advanced Safety",
      description: "Risk assessment, command previews, and comprehensive rollback capabilities keep your system safe."
    },
    {
      icon: <FaTools />,
      title: "Developer Tool Integration",
      description: "Seamless integration with Git, Docker, package managers, and cloud CLIs."
    },
    {
      icon: <FaRocket />,
      title: "Multi-Step Operations",
      description: "Decompose complex goals into actionable steps with smart planning and execution."
    },
    {
      icon: <FaCode />,
      title: "Code Generation",
      description: "Generate functions, components, or entire projects with natural language descriptions."
    },
    {
      icon: <FaBrain />,
      title: "Semantic Code Understanding",
      description: "Angela can analyze and understand your codebase for context-aware assistance."
    },
    {
      icon: <FaNetworkWired />,
      title: "Workflow Automation",
      description: "Create, save, and execute complex workflows with a single command."
    }
  ];
  
  // Usage examples
  const usageExamples = [
    {
      category: "File Operations",
      commands: [
        "find all Python files modified in the last week",
        "create a new directory structure for a React app",
        "show me the content of config.json with syntax highlighting"
      ]
    },
    {
      category: "Git Operations",
      commands: [
        "create a new branch called feature/user-auth and switch to it",
        "commit all changes with a descriptive message",
        "show me what files I've changed since the last commit"
      ]
    },
    {
      category: "Code Generation",
      commands: [
        "create a Python function that validates email addresses",
        "generate a React component for a user settings form",
        "create a RESTful controller for user management"
      ]
    },
    {
      category: "Multi-Step Workflows",
      commands: [
        "create a feature branch, implement a user profile component, add tests, and commit",
        "update the version number, create a changelog, tag the release, and push",
        "find which commit introduced the bug, create a fix branch, and prepare a PR"
      ]
    }
  ];
  
  // FAQ data
  const faqs = [
    {
      question: "How is Angela different from regular CLIs or chatbots?",
      answer: "Angela is deeply integrated with your terminal environment and understands your project context. Unlike general AI assistants, Angela is specifically designed for command-line productivity with safety features, rollback capabilities, and developer tool integrations."
    },
    {
      question: "Does Angela require internet access?",
      answer: "For AI-powered features like natural language understanding and code generation, internet access is required to connect to the Gemini API. However, many core features like file operations, workflow execution, and rollback functionality work offline."
    },
    {
      question: "Is Angela secure to use?",
      answer: "Angela prioritizes safety with multiple layers: risk classification, command previews, permission checking, and comprehensive rollback capabilities. All configuration is stored locally, and only relevant snippets are sent to the API when needed."
    },
    {
      question: "What platforms does Angela support?",
      answer: "Angela is primarily designed for Unix-like systems (Linux, macOS). It can be used on Windows through WSL (Windows Subsystem for Linux). Native Windows support is on our roadmap."
    },
    {
      question: "What languages and frameworks does Angela understand?",
      answer: "Angela can detect and understand most popular languages and frameworks including Python, JavaScript/Node.js, React, Ruby, Java, Go, Rust, C#, PHP, and many more."
    }
  ];
  
  // Typing animation effect for hero section
  useEffect(() => {
    const currentText = heroTexts[currentTextIndex];
    let timeout;
    
    if (animationPhase === 0) {
      // Typing phase
      if (typedText.length < currentText.length) {
        timeout = setTimeout(() => {
          setTypedText(currentText.substring(0, typedText.length + 1));
        }, 50 + Math.random() * 50);
      } else {
        // Switch to pause phase
        setAnimationPhase(1);
        timeout = setTimeout(() => {
          setAnimationPhase(2);
        }, 2000);
      }
    } else if (animationPhase === 2) {
      // Deleting phase
      if (typedText.length > 0) {
        timeout = setTimeout(() => {
          setTypedText(typedText.substring(0, typedText.length - 1));
        }, 30);
      } else {
        // Switch to next text
        setAnimationPhase(0);
        setCurrentTextIndex((currentTextIndex + 1) % heroTexts.length);
      }
    }
    
    return () => clearTimeout(timeout);
  }, [typedText, currentTextIndex, animationPhase]);
  
  // Blinking cursor effect
  useEffect(() => {
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev);
    }, 530);
    
    return () => clearInterval(cursorInterval);
  }, []);
  
  // Terminal animation for auto demo
  useEffect(() => {
    if (isTerminalActive && terminalOutput.length === 0) {
      let currentCharIndex = 0;
      let commandIndex = 0;
      let currentCommand = '';
      
      const typeInterval = setInterval(() => {
        if (currentCharIndex < terminalTexts[commandIndex].length) {
          currentCommand = terminalTexts[commandIndex].substring(0, currentCharIndex + 1);
          setUserCommand(currentCommand);
          currentCharIndex++;
        } else {
          clearInterval(typeInterval);
          setTimeout(() => {
            setTerminalOutput(demoCommands[commandIndex % demoCommands.length].output);
            setTimeout(() => {
              commandIndex = (commandIndex + 1) % terminalTexts.length;
              currentCharIndex = 0;
              setUserCommand('');
              setTerminalOutput([]);
            }, 4000);
          }, 500);
        }
      }, 100);
      
      return () => clearInterval(typeInterval);
    }
  }, [isTerminalActive, terminalOutput.length]);
  
  // Scroll animation for sections
  useEffect(() => {
    const handleScroll = () => {
      const scrollPosition = window.scrollY + window.innerHeight / 2;
      
      const sections = [
        { ref: featuresRef, id: 'features' },
        { ref: installRef, id: 'install' },
        { ref: demoRef, id: 'demo' },
        { ref: docsRef, id: 'docs' },
        { ref: aboutRef, id: 'about' }
      ];
      
      for (const section of sections) {
        if (section.ref.current && 
            scrollPosition >= section.ref.current.offsetTop && 
            scrollPosition < section.ref.current.offsetTop + section.ref.current.offsetHeight) {
          setActiveSection(section.id);
          break;
        }
      }
      
      // Activate terminal when demo section is visible
      if (demoRef.current && 
          scrollPosition >= demoRef.current.offsetTop && 
          scrollPosition < demoRef.current.offsetTop + demoRef.current.offsetHeight) {
        if (!isTerminalActive) {
          setIsTerminalActive(true);
        }
      } else {
        if (isTerminalActive) {
          setIsTerminalActive(false);
          setUserCommand('');
          setTerminalOutput([]);
        }
      }
    };
    
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, [isTerminalActive]);
  
  const scrollToSection = (ref) => {
    ref.current.scrollIntoView({ behavior: 'smooth' });
  };
  
  const copyInstallCommand = () => {
    navigator.clipboard.writeText('curl -sSL https://raw.githubusercontent.com/CarterPerez-dev/angela-cli/main/scripts/install-quick.sh | bash');
    setInstallCopied(true);
    setTimeout(() => setInstallCopied(false), 2000);
  };
  
  const playDemo = () => {
    setIsDemoPlaying(true);
  };
  
  return (
    <div className="angela-container">
      {/* Animated grid background */}
      <div className="angela-grid-background">
        <div className="angela-grid-lines"></div>
        <div className="angela-stars">
          {Array.from({ length: 50 }).map((_, i) => (
            <div 
              key={i} 
              className="angela-star" 
              style={{
                top: `${Math.random() * 100}%`,
                left: `${Math.random() * 100}%`,
                animationDelay: `${Math.random() * 5}s`
              }}
            ></div>
          ))}
        </div>
      </div>
      
      {/* Navigation */}
      <nav className="angela-nav">
        <div className="angela-nav-logo" onClick={() => scrollToSection({ current: document.body })}>
          <FaTerminal className="angela-logo-icon" />
          <span>ANGELA-CLI</span>
        </div>
        <div className="angela-nav-links">
          <button onClick={() => scrollToSection(featuresRef)} className={activeSection === 'features' ? 'active' : ''}>Features</button>
          <button onClick={() => scrollToSection(installRef)} className={activeSection === 'install' ? 'active' : ''}>Install</button>
          <button onClick={() => scrollToSection(demoRef)} className={activeSection === 'demo' ? 'active' : ''}>Demo</button>
          <button onClick={() => scrollToSection(docsRef)} className={activeSection === 'docs' ? 'active' : ''}>Docs</button>
          <button onClick={() => scrollToSection(aboutRef)} className={activeSection === 'about' ? 'active' : ''}>About</button>
          <a href="https://github.com/CarterPerez-dev/angela-cli" target="_blank" rel="noopener noreferrer" className="angela-github-link">
            <FaGithub />
          </a>
        </div>
      </nav>
      
      {/* Hero Section */}
      <section className="angela-hero">
        <div className="angela-hero-content">
          <div className="angela-hero-title">
            <div className="angela-title-animation">
              <span className="angela-title-text">ANGELA</span>
              <span className="angela-title-gradient">CLI</span>
            </div>
          </div>
          <div className="angela-hero-subtitle">
            <span className="angela-typed-text">{typedText}</span>
            <span className={`angela-cursor ${showCursor ? 'visible' : 'hidden'}`}>_</span>
          </div>
          <div className="angela-hero-description">
            Your ambient-intelligence terminal companion that understands natural language and your development context
          </div>
          <div className="angela-hero-cta">
            <button className="angela-primary-button" onClick={() => scrollToSection(installRef)}>
              Get Started <FaArrowRight className="angela-btn-icon" />
            </button>
            <button className="angela-secondary-button" onClick={() => scrollToSection(demoRef)}>
              See Demo <FaPlayCircle className="angela-btn-icon" />
            </button>
          </div>
          <div className="angela-stats">
            <div className="angela-stat">
              <span className="angela-stat-value">8x</span>
              <span className="angela-stat-label">Faster CLI</span>
            </div>
            <div className="angela-stat">
              <span className="angela-stat-value">AGI</span>
              <span className="angela-stat-label">Powered</span>
            </div>
            <div className="angela-stat">
              <span className="angela-stat-value">100%</span>
              <span className="angela-stat-label">Open Source</span>
            </div>
          </div>
        </div>
        <div className="angela-hero-terminal">
          <div className="angela-terminal-header">
            <div className="angela-terminal-buttons">
              <span className="angela-terminal-button red"></span>
              <span className="angela-terminal-button yellow"></span>
              <span className="angela-terminal-button green"></span>
            </div>
            <div className="angela-terminal-title">~/projects/my-app</div>
          </div>
          <div className="angela-terminal-body">
            <div className="angela-terminal-line">
              <span className="angela-terminal-prompt">$</span>
              <span className="angela-terminal-text">angela "find all JavaScript files modified in the last week"</span>
            </div>
            <div className="angela-terminal-line angela-output">
              <span className="angela-terminal-text">Analyzing request and gathering context...</span>
            </div>
            <div className="angela-terminal-line angela-output">
              <span className="angela-terminal-text">I'll execute: find . -name "*.js" -mtime -7 -type f</span>
            </div>
            <div className="angela-terminal-line angela-output">
              <span className="angela-terminal-text">This will find all JavaScript files modified in the last 7 days</span>
            </div>
            <div className="angela-terminal-line angela-output">
              <span className="angela-terminal-text-result">./src/App.js</span>
            </div>
            <div className="angela-terminal-line angela-output">
              <span className="angela-terminal-text-result">./src/components/UserProfile.js</span>
            </div>
            <div className="angela-terminal-line angela-output">
              <span className="angela-terminal-text-result">./src/utils/auth.js</span>
            </div>
            <div className="angela-terminal-line">
              <span className="angela-terminal-prompt">$</span>
              <span className="angela-terminal-cursor"></span>
            </div>
          </div>
        </div>
      </section>
      
      {/* Features Section */}
      <section className="angela-features" ref={featuresRef}>
        <div className="angela-section-header">
          <h2 className="angela-section-title">
            <span className="angela-title-gradient">Features</span>
          </h2>
          <p className="angela-section-subtitle">Powerful capabilities that make your terminal smarter</p>
        </div>
        <div className="angela-features-grid">
          {features.map((feature, index) => (
            <div className="angela-feature-card" key={index}>
              <div className="angela-feature-icon">
                {feature.icon}
              </div>
              <h3 className="angela-feature-title">{feature.title}</h3>
              <p className="angela-feature-description">{feature.description}</p>
            </div>
          ))}
        </div>
      </section>
      
      {/* Install Section */}
      <section className="angela-install" ref={installRef}>
        <div className="angela-section-header">
          <h2 className="angela-section-title">
            <span className="angela-title-gradient">Installation</span>
          </h2>
          <p className="angela-section-subtitle">Get up and running in seconds</p>
        </div>
        <div className="angela-install-content">
          <div className="angela-install-terminal">
            <div className="angela-terminal-header">
              <div className="angela-terminal-buttons">
                <span className="angela-terminal-button red"></span>
                <span className="angela-terminal-button yellow"></span>
                <span className="angela-terminal-button green"></span>
              </div>
              <div className="angela-terminal-title">Quick Install</div>
            </div>
            <div className="angela-terminal-body">
              <div className="angela-terminal-line">
                <span className="angela-terminal-prompt">$</span>
                <span className="angela-terminal-text">curl -sSL https://raw.githubusercontent.com/CarterPerez-dev/angela-cli/main/scripts/install-quick.sh | bash</span>
                <button 
                  className="angela-copy-button" 
                  onClick={copyInstallCommand}
                  aria-label="Copy installation command"
                >
                  {installCopied ? "Copied!" : "Copy"}
                </button>
              </div>
            </div>
          </div>
          <div className="angela-install-steps">
            <div className="angela-install-step">
              <div className="angela-step-number">1</div>
              <div className="angela-step-content">
                <h3 className="angela-step-title">Run the installer</h3>
                <p className="angela-step-description">
                  The script checks for dependencies, installs the package, and sets up shell integration.
                </p>
              </div>
            </div>
            <div className="angela-install-step">
              <div className="angela-step-number">2</div>
              <div className="angela-step-content">
                <h3 className="angela-step-title">Configure your API key</h3>
                <p className="angela-step-description">
                  Run <code>angela init</code> to set up your Google Gemini API key and customize preferences.
                </p>
              </div>
            </div>
            <div className="angela-install-step">
              <div className="angela-step-number">3</div>
              <div className="angela-step-content">
                <h3 className="angela-step-title">Start using Angela</h3>
                <p className="angela-step-description">
                  Type <code>angela "your request in natural language"</code> and let Angela handle the rest!
                </p>
              </div>
            </div>
          </div>
          <div className="angela-install-buttons">
            <a href="https://github.com/CarterPerez-dev/angela-cli#-installation" target="_blank" rel="noopener noreferrer" className="angela-secondary-button">
              Advanced Installation Options <FaArrowRight className="angela-btn-icon" />
            </a>
          </div>
        </div>
      </section>
      
      {/* Demo Section */}
      <section className="angela-demo" ref={demoRef}>
        <div className="angela-section-header">
          <h2 className="angela-section-title">
            <span className="angela-title-gradient">Watch Angela in Action</span>
          </h2>
          <p className="angela-section-subtitle">See how Angela makes the command line intuitive and powerful</p>
        </div>
        <div className="angela-demo-content">
          <div className="angela-demo-terminal">
            <div className="angela-terminal-header">
              <div className="angela-terminal-buttons">
                <span className="angela-terminal-button red"></span>
                <span className="angela-terminal-button yellow"></span>
                <span className="angela-terminal-button green"></span>
              </div>
              <div className="angela-terminal-title">Demo</div>
            </div>
            <div className="angela-terminal-body">
              <div className="angela-terminal-line">
                <span className="angela-terminal-prompt">$</span>
                <span className="angela-terminal-text">{userCommand}</span>
                <span className="angela-terminal-cursor"></span>
              </div>
              {terminalOutput.map((line, index) => (
                <div className="angela-terminal-line angela-output" key={index}>
                  <span className="angela-terminal-text">{line}</span>
                </div>
              ))}
            </div>
            <div className="angela-terminal-overlay" onClick={() => setIsTerminalActive(true)}>
              <button className="angela-primary-button">
                <FaPlayCircle className="angela-btn-icon" /> Start Demo
              </button>
            </div>
          </div>
          <div className="angela-demo-examples">
            <h3 className="angela-examples-title">Try asking Angela to:</h3>
            <div className="angela-examples-grid">
              {usageExamples.map((category, cIndex) => (
                <div className="angela-example-category" key={cIndex}>
                  <h4 className="angela-category-title">{category.category}</h4>
                  <ul className="angela-example-list">
                    {category.commands.map((command, cmdIndex) => (
                      <li className="angela-example-item" key={cmdIndex}>
                        <span className="angela-example-prefix">angela "</span>
                        <span className="angela-example-command">{command}</span>
                        <span className="angela-example-suffix">"</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
      
      {/* Documentation Section */}
      <section className="angela-docs" ref={docsRef}>
        <div className="angela-section-header">
          <h2 className="angela-section-title">
            <span className="angela-title-gradient">Documentation</span>
          </h2>
          <p className="angela-section-subtitle">Everything you need to know about Angela CLI</p>
        </div>
        <div className="angela-docs-content">
          <div className="angela-docs-grid">
            <div className="angela-doc-card">
              <h3 className="angela-doc-title">Getting Started</h3>
              <ul className="angela-doc-links">
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-installation" target="_blank" rel="noopener noreferrer">Installation Guide</a></li>
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-initial-configuration" target="_blank" rel="noopener noreferrer">Configuration Options</a></li>
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-basic-usage" target="_blank" rel="noopener noreferrer">Basic Usage</a></li>
              </ul>
            </div>
            <div className="angela-doc-card">
              <h3 className="angela-doc-title">Core Features</h3>
              <ul className="angela-doc-links">
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-command-categories" target="_blank" rel="noopener noreferrer">Command Categories</a></li>
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-safety-features" target="_blank" rel="noopener noreferrer">Safety Features</a></li>
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-shell-integration" target="_blank" rel="noopener noreferrer">Shell Integration</a></li>
              </ul>
            </div>
            <div className="angela-doc-card">
              <h3 className="angela-doc-title">Advanced Topics</h3>
              <ul className="angela-doc-links">
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-workflows" target="_blank" rel="noopener noreferrer">Workflow Management</a></li>
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-code-generation" target="_blank" rel="noopener noreferrer">Code Generation</a></li>
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-toolchain-integration" target="_blank" rel="noopener noreferrer">Toolchain Integration</a></li>
              </ul>
            </div>
            <div className="angela-doc-card">
              <h3 className="angela-doc-title">Reference</h3>
              <ul className="angela-doc-links">
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-advanced-usage-examples" target="_blank" rel="noopener noreferrer">Usage Examples</a></li>
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-configuration-options" target="_blank" rel="noopener noreferrer">Configuration Reference</a></li>
                <li><a href="https://github.com/CarterPerez-dev/angela-cli#-frequently-asked-questions" target="_blank" rel="noopener noreferrer">FAQs</a></li>
              </ul>
            </div>
          </div>
          <div className="angela-doc-cta">
            <a href="https://github.com/CarterPerez-dev/angela-cli" target="_blank" rel="noopener noreferrer" className="angela-primary-button">
              Full Documentation <FaArrowRight className="angela-btn-icon" />
            </a>
          </div>
        </div>
      </section>
      
      {/* FAQ Section */}
      <section className="angela-faq">
        <div className="angela-section-header">
          <h2 className="angela-section-title">
            <span className="angela-title-gradient">Frequently Asked Questions</span>
          </h2>
        </div>
        <div className="angela-faq-grid">
          {faqs.map((faq, index) => (
            <div className="angela-faq-item" key={index}>
              <h3 className="angela-faq-question">{faq.question}</h3>
              <p className="angela-faq-answer">{faq.answer}</p>
            </div>
          ))}
        </div>
      </section>
      
      {/* About Section */}
      <section className="angela-about" ref={aboutRef}>
        <div className="angela-section-header">
          <h2 className="angela-section-title">
            <span className="angela-title-gradient">About Angela CLI</span>
          </h2>
        </div>
        <div className="angela-about-content">
          <div className="angela-about-text">
            <p>Angela CLI represents a paradigm shift in command-line interaction. It's an AI-powered command-line assistant deeply integrated into your terminal shell that blurs the boundary between traditional command-line tools and intelligent assistants.</p>
            <p>Unlike conventional CLI tools that require exact syntax or chatbots that operate in isolation, Angela understands natural language within your development context and can perform complex multi-step operations spanning multiple tools and systems.</p>
            <p>Angela doesn't just execute commands – it acts as an intelligent copilot for your terminal operations, enhancing productivity, reducing errors, and lowering the barrier to entry for complex tasks.</p>
            <div className="angela-about-buttons">
              <a href="https://github.com/CarterPerez-dev/angela-cli" target="_blank" rel="noopener noreferrer" className="angela-github-button">
                <FaGithub className="angela-btn-icon" /> Star on GitHub
              </a>
              <button className="angela-secondary-button" onClick={() => scrollToSection(installRef)}>
                <FaDownload className="angela-btn-icon" /> Install Now
              </button>
            </div>
          </div>
          <div className="angela-about-stats">
            <div className="angela-about-stat">
              <div className="angela-about-stat-icon">
                <FaStar />
              </div>
              <div className="angela-about-stat-value">4.9/5</div>
              <div className="angela-about-stat-label">User Rating</div>
            </div>
            <div className="angela-about-stat">
              <div className="angela-about-stat-icon">
                <FaUserPlus />
              </div>
              <div className="angela-about-stat-value">5k+</div>
              <div className="angela-about-stat-label">Active Users</div>
            </div>
            <div className="angela-about-stat">
              <div className="angela-about-stat-icon">
                <FaRegLightbulb />
              </div>
              <div className="angela-about-stat-value">1.2M+</div>
              <div className="angela-about-stat-label">Commands Generated</div>
            </div>
          </div>
        </div>
      </section>
      
      {/* Footer */}
      <footer className="angela-footer">
        <div className="angela-footer-content">
          <div className="angela-footer-logo">
            <FaTerminal className="angela-logo-icon" />
            <span>ANGELA-CLI</span>
          </div>
          <div className="angela-footer-links">
            <a href="https://github.com/CarterPerez-dev/angela-cli" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a href="https://github.com/CarterPerez-dev/angela-cli/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">License</a>
            <a href="https://github.com/CarterPerez-dev/angela-cli/issues" target="_blank" rel="noopener noreferrer">Report Issues</a>
            <a href="https://github.com/CarterPerez-dev/angela-cli/blob/main/CONTRIBUTING.md" target="_blank" rel="noopener noreferrer">Contribute</a>
          </div>
          <div className="angela-footer-attribution">
            Built with ❤️ by the Angela CLI Team
          </div>
        </div>
      </footer>
    </div>
  );
};

export default AngelaPage;
