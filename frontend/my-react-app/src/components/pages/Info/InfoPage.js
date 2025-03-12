// src/components/pages/Info/InfoPage.js
import React, { useEffect, useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import SEOHelmet from '../../SEOHelmet';
import StructuredData from '../../StructuredData';
import { 
  FaApple, 
  FaGoogle, 
  FaAppStore, 
  FaPlay, 
  FaArrowRight, 
  FaInfoCircle, 
  FaExternalLinkAlt 
} from 'react-icons/fa';
import './InfoPage.css';

const InfoPage = () => {
  // For tab switching functionality
  const [activeTab, setActiveTab] = useState('comptia');
  
  // For the typing animation effect in hero section
  const [displayText, setDisplayText] = useState('');
  const fullText = 'Level up your cybersecurity skills';
  
  // For counting animation
  const [questionCount, setQuestionCount] = useState(0);
  const [certCount, setCertCount] = useState(0);
  const [resourceCount, setResourceCount] = useState(0);
  
  // Refs for scroll sections
  const featuresRef = useRef(null);
  const toolsRef = useRef(null);
  const testsRef = useRef(null);
  const pricingRef = useRef(null);
  
  // Functions to handle card flipping and demo views
  const handleCardClick = (event, demoId = null) => {
    const card = event.currentTarget;
    card.classList.toggle('info-flipped');
    
    // Reset other flipped cards
    document.querySelectorAll('.info-flipped').forEach(flippedCard => {
      if (flippedCard !== card) {
        flippedCard.classList.remove('info-flipped');
      }
    });
    
    // If demoId is provided, store it for navigation
    if (demoId) {
      localStorage.setItem('lastViewedDemo', demoId);
    }
  };
  
  // Scroll to section function
  const scrollToSection = (ref) => {
    if (ref && ref.current) {
      ref.current.scrollIntoView({ behavior: 'smooth' });
    }
  };
  
  // For parallax effect on scroll
  useEffect(() => {
    const handleScroll = () => {
      const elements = document.querySelectorAll('.info-animate-on-scroll');
      
      elements.forEach(el => {
        const position = el.getBoundingClientRect();
        
        // If element is in viewport
        if(position.top < window.innerHeight && position.bottom >= 0) {
          el.classList.add('info-visible');
        }
      });
    };
    
    window.addEventListener('scroll', handleScroll);
    handleScroll(); // Check on initial load
    
    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);
  
  // Typing effect
  useEffect(() => {
    if (displayText.length < fullText.length) {
      const timer = setTimeout(() => {
        setDisplayText(fullText.slice(0, displayText.length + 1));
      }, 100);
      
      return () => clearTimeout(timer);
    }
  }, [displayText]);
  
  // Counting animation
  useEffect(() => {
    const questionsTarget = 13000;
    const certsTarget = 13;
    const resourcesTarget = 600;
    const duration = 2000; // ms
    const steps = 50;
    
    const questionsIncrement = questionsTarget / steps;
    const certsIncrement = certsTarget / steps;
    const resourcesIncrement = resourcesTarget / steps;
    const interval = duration / steps;
    
    let currentStep = 0;
    
    const timer = setInterval(() => {
      currentStep++;
      
      if (currentStep <= steps) {
        setQuestionCount(Math.floor(questionsIncrement * currentStep));
        setCertCount(Math.floor(certsIncrement * currentStep));
        setResourceCount(Math.floor(resourcesIncrement * currentStep));
      } else {
        setQuestionCount(questionsTarget);
        setCertCount(certsTarget);
        setResourceCount(resourcesTarget);
        clearInterval(timer);
      }
    }, interval);
    
    return () => clearInterval(timer);
  }, []);



// Website structured data
const websiteSchema = {
  "@context": "https://schema.org",
  "@type": "WebSite",
  "name": "CertGames",
  "url": "https://certgames.com",
  "potentialAction": {
    "@type": "SearchAction",
    "target": "https://certgames.com/search?q={search_term_string}",
    "query-input": "required name=search_term_string"
  }
};

// Course structured data
const courseSchema = {
  "@context": "https://schema.org",
  "@type": "Course",
  "name": "Cybersecurity Certification Training",
  "description": "Gamified cybersecurity training for CompTIA, ISC2, and AWS certifications with 13,000+ practice questions.",
  "provider": {
    "@type": "Organization",
    "name": "CertGames",
    "sameAs": "https://certgames.com"
  }
};

// FAQ structured data
const faqSchema = {
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "How up-to-date are the practice questions?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Our team of certified experts regularly updates all questions to match the latest exam objectives and industry changes. We ensure our content remains current with all certification requirements."
      }
    },
    {
      "@type": "Question",
      "name": "Can I access CertGames on my mobile device?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Absolutely! CertGames is fully responsive and works on all devices including desktop, tablet, and mobile phones. Your progress syncs across all platforms automatically."
      }
    },
    {
      "@type": "Question",
      "name": "How does the subscription work?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "For $9.99 per month, you gain unlimited access to all practice tests, tools, resources, and features. You can cancel your subscription at any time with no questions asked."
      }
    },
    {
      "@type": "Question",
      "name": "Is there a guarantee I'll pass my certification exam?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "While we can't guarantee passing (no one ethically can), our success rates are extremely high. Users who complete all practice tests for their target certification and maintain a score of 85% or higher have a passing rate of over 95% on their actual exams."
      }
    },
    {
      "@type": "Question",
      "name": "What if I need help with a specific concept?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Our 24/7 \"Ask Anything\" support feature allows you to ask any certification-related question and receive a thorough, personalized answer from our expert team, typically within 3 hours."
      }
    }
  ]
};

  return (
    <>
      <SEOHelmet 
        title="CertGames - Gamified Cybersecurity Training & Certification Prep"
        description="Level up your cybersecurity skills with CertGames. Practice for CompTIA, ISC2, and AWS certifications with 13,000+ questions in a fun, gamified learning environment."
        canonicalUrl="/"
      />
      <StructuredData data={websiteSchema} />
      <StructuredData data={courseSchema} />
      <StructuredData data={faqSchema} />
      <div className="info-container">
        {/* Navbar */}
        <InfoNavbar />
        
        {/* Hero Section */}
        <section className="info-hero-section">
          <div className="info-overlay"></div>
          <div className="info-hero-content">
            <div className="info-hero-text">
              <h1 className="info-hero-title">
                <span className="info-logo-text">Cert<span className="info-highlight">Games</span></span>
              </h1>
              <h2 className="info-hero-subtitle">{displayText}<span className="info-cursor"></span></h2>
              <p className="info-hero-description">
                The ultimate gamified cybersecurity training platform that makes learning fun, effective, and addictive.
              </p>
              <div className="info-hero-cta">
                <Link to="/register" className="info-button info-primary-button">
                  Start Your Journey <FaArrowRight className="info-icon" />
                </Link>
                <Link to="/login" className="info-button info-secondary-button">
                  Log In
                </Link>
              </div>
              <div className="info-quick-links">
                <button onClick={() => scrollToSection(featuresRef)} className="info-quick-link">
                  <span>Features</span>
                </button>
                <button onClick={() => scrollToSection(toolsRef)} className="info-quick-link">
                  <span>Learning Tools</span>
                </button>
                <button onClick={() => scrollToSection(testsRef)} className="info-quick-link">
                  <span>Certification Tests</span>
                </button>
                <button onClick={() => scrollToSection(pricingRef)} className="info-quick-link">
                  <span>Pricing</span>
                </button>
              </div>
            </div>

            <div className="info-hero-stats">
              <div className="info-stat-card">
                <div className="info-stat-value">{questionCount.toLocaleString()}</div>
                <div className="info-stat-label">Practice Questions</div>
              </div>
              <div className="info-stat-card">
                <div className="info-stat-value">{certCount}</div>
                <div className="info-stat-label">Certifications</div>
              </div>
              <div className="info-stat-card">
                <div className="info-stat-value">{resourceCount}+</div>
                <div className="info-stat-label">Learning Resources</div>
              </div>
            </div>
          </div>
          <div className="info-scroll-indicator">
            <div className="info-mouse"></div>
            <p>Scroll to explore</p>
          </div>
        </section>

        {/* Gamified Experience Section */}
        <section ref={featuresRef} className="info-feature-section info-gamified-section">
          <div className="info-section-header info-animate-on-scroll">
            <h2>
              <span className="info-section-icon">🎮</span>
              Gamified Learning Experience
            </h2>
            <p>Level up your skills while having fun</p>
          </div>
          <div className="info-feature-grid">
            <div 
              className="info-feature-card info-animate-on-scroll info-clickable-card"
              onClick={(e) => handleCardClick(e, 'xp-system')}
            >
              <div className="info-feature-icon">
                <i className="info-exp-icon">XP</i>
              </div>
              <h3>Earn XP & Level Up</h3>
              <p>Answer questions correctly to gain experience points and climb the ranks from rookie to elite hacker.</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch XP System Demo</span>
                  </Link>
                </div>
              </div>
            </div>
            <div 
              className="info-feature-card info-animate-on-scroll info-clickable-card" 
              onClick={(e) => handleCardClick(e, 'coins-system')}
            >
              <div className="info-feature-icon">
                <i className="info-coins-icon">💰</i>
              </div>
              <h3>Collect Coins</h3>
              <p>Earn virtual currency by completing tests and daily challenges to unlock exclusive avatars and boosts.</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch Coins System Demo</span>
                  </Link>
                </div>
              </div>
            </div>
            <div 
              className="info-feature-card info-animate-on-scroll info-clickable-card"
              onClick={(e) => handleCardClick(e, 'achievements')}
            >
              <div className="info-feature-icon">
                <i className="info-trophy-icon">🏆</i>
              </div>
              <h3>Unlock Achievements</h3>
              <p>Complete special tasks to earn badges and trophies that showcase your growing expertise.</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch Achievements Demo</span>
                  </Link>
                </div>
              </div>
            </div>
            <div 
              className="info-feature-card info-animate-on-scroll info-clickable-card"
              onClick={(e) => handleCardClick(e, 'leaderboards')}
            >
              <div className="info-feature-icon">
                <i className="info-leaderboard-icon">📊</i>
              </div>
              <h3>Compete on Leaderboards</h3>
              <p>See how you rank against other cybersecurity enthusiasts and strive to climb to the top.</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/public-leaderboard" className="info-demo-link">
                    <FaExternalLinkAlt className="info-demo-icon" />
                    <span>View Current Leaderboard</span>
                  </Link>
                </div>
              </div>
            </div>
            <div 
              className="info-feature-card info-animate-on-scroll info-clickable-card"
              onClick={(e) => handleCardClick(e, 'themes')}
            >
              <div className="info-feature-icon">
                <i className="info-theme-icon">🎨</i>
              </div>
              <h3>Customize Your Experience</h3>
              <p>Choose from multiple themes and personalize your learning environment to suit your style.</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch Theme Customization Demo</span>
                  </Link>
                </div>
              </div>
            </div>
            <div 
              className="info-feature-card info-animate-on-scroll info-clickable-card"
              onClick={(e) => handleCardClick(e, 'mobile')}
            >
              <div className="info-feature-icon">
                <i className="info-mobile-icon">📱</i>
              </div>
              <h3>Learn Anywhere</h3>
              <p>Access all features on desktop, mobile browsers, and our dedicated iOS app for learning on the go.</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch Mobile App Demo</span>
                  </Link>
                </div>
              </div>
            </div>
          </div>
          
          <div className="info-feature-links info-animate-on-scroll">
            <Link to="/demos" className="info-feature-link">
              <span>View All Feature Demos</span>
              <FaArrowRight className="info-link-icon" />
            </Link>
            <Link to="/public-leaderboard" className="info-feature-link">
              <span>Browse Leaderboard</span>
              <FaArrowRight className="info-link-icon" />
            </Link>
          </div>
          
          <div className="info-preview-placeholder info-animate-on-scroll">
            <div className="info-preview-overlay">
              <p>Leaderboard Preview</p>
            </div>
          </div>
        </section>

        {/* Certification Tests Section */}
        <section ref={testsRef} className="info-feature-section info-tests-section">
          <div className="info-section-header info-animate-on-scroll">
            <h2>
              <span className="info-section-icon">📝</span>
              Master 13 Certification Paths
            </h2>
            <p>13,000 practice questions across the most in-demand certifications</p>
          </div>
          <div className="info-test-features info-animate-on-scroll">
            <div className="info-test-features-list">
              <div className="info-test-feature">
                <span className="info-check-icon">✓</span>
                <span>Performance-Based Questions (PBQs)</span>
              </div>
              <div className="info-test-feature">
                <span className="info-check-icon">✓</span>
                <span>Realistic Exam Simulations</span>
              </div>
              <div className="info-test-feature">
                <span className="info-check-icon">✓</span>
                <span>Detailed Explanations</span>
              </div>
              <div className="info-test-feature">
                <span className="info-check-icon">✓</span>
                <span>Difficulty Progression System</span>
              </div>
              <div className="info-test-feature">
                <span className="info-check-icon">✓</span>
                <span>Customizable Test Lengths</span>
              </div>
              <div className="info-test-feature">
                <span className="info-check-icon">✓</span>
                <span>Memorable Exam Tips</span>
              </div>
              <div className="info-test-feature">
                <span className="info-check-icon">✓</span>
                <span>Progress Tracking & Analytics</span>
              </div>
              <div className="info-test-feature">
                <span className="info-check-icon">✓</span>
                <span>Exam Mode with Timed Sessions</span>
              </div>
            </div>
            <div className="info-test-selector">
              <div className="info-test-tabs">
                <button 
                  className={`info-test-tab ${activeTab === 'comptia' ? 'info-active' : ''}`} 
                  onClick={() => setActiveTab('comptia')}
                >
                  CompTIA
                </button>
                <button 
                  className={`info-test-tab ${activeTab === 'isc2' ? 'info-active' : ''}`} 
                  onClick={() => setActiveTab('isc2')}
                >
                  ISC2
                </button>
                <button 
                  className={`info-test-tab ${activeTab === 'aws' ? 'info-active' : ''}`} 
                  onClick={() => setActiveTab('aws')}
                >
                  AWS
                </button>
              </div>
              
              {/* CompTIA Tab Content */}
              <div className={`info-cert-list ${activeTab !== 'comptia' ? 'info-hidden' : ''}`}>
                <div className="info-cert-item">
                  <span className="info-cert-badge">A+</span>
                  <span className="info-cert-name">A+ Core 1 & Core 2</span>
                  <span className="info-cert-count">2,000 questions</span>
                </div>
                <div className="info-cert-item">
                  <span className="info-cert-badge">N+</span>
                  <span className="info-cert-name">Network+</span>
                  <span className="info-cert-count">1,000 questions</span>
                </div>
                <div className="info-cert-item">
                  <span className="info-cert-badge">S+</span>
                  <span className="info-cert-name">Security+</span>
                  <span className="info-cert-count">1,000 questions</span>
                </div>
                <div className="info-cert-item">
                  <span className="info-cert-badge">CySA+</span>
                  <span className="info-cert-name">CySA+</span>
                  <span className="info-cert-count">1,000 questions</span>
                </div>
                <div className="info-cert-item">
                  <span className="info-cert-badge">PenTest+</span>
                  <span className="info-cert-name">PenTest+</span>
                  <span className="info-cert-count">1,000 questions</span>
                </div>
                <div className="info-cert-dropdown">
                  <div className="info-show-more">
                    <span>+7 more certifications</span>
                  </div>
                  <div className="info-dropdown-content">
                    <div className="info-cert-item">
                      <span className="info-cert-badge">CASP+</span>
                      <span className="info-cert-name">CASP+</span>
                      <span className="info-cert-count">1,000 questions</span>
                    </div>
                    <div className="info-cert-item">
                      <span className="info-cert-badge">Linux+</span>
                      <span className="info-cert-name">Linux+</span>
                      <span className="info-cert-count">1,000 questions</span>
                    </div>
                    <div className="info-cert-item">
                      <span className="info-cert-badge">Data+</span>
                      <span className="info-cert-name">Data+</span>
                      <span className="info-cert-count">1,000 questions</span>
                    </div>
                    <div className="info-cert-item">
                      <span className="info-cert-badge">Server+</span>
                      <span className="info-cert-name">Server+</span>
                      <span className="info-cert-count">1,000 questions</span>
                    </div>
                    <div className="info-cert-item">
                      <span className="info-cert-badge">Cloud+</span>
                      <span className="info-cert-name">Cloud+</span>
                      <span className="info-cert-count">1,000 questions</span>
                    </div>
                  </div>
                </div>
              </div>
              
              {/* ISC2 Tab Content */}
              <div className={`info-cert-list ${activeTab !== 'isc2' ? 'info-hidden' : ''}`}>
                <div className="info-cert-item">
                  <span className="info-cert-badge">CISSP</span>
                  <span className="info-cert-name">CISSP</span>
                  <span className="info-cert-count">1,000 questions</span>
                </div>
              </div>
              
              {/* AWS Tab Content */}
              <div className={`info-cert-list ${activeTab !== 'aws' ? 'info-hidden' : ''}`}>
                <div className="info-cert-item">
                  <span className="info-cert-badge">CCP</span>
                  <span className="info-cert-name">Cloud Practitioner</span>
                  <span className="info-cert-count">1,000 questions</span>
                </div>
              </div>
            </div>
          </div>
          
          <div className="info-feature-links info-animate-on-scroll">
            <Link to="/exams" className="info-feature-link">
              <span>View All Certification Exams</span>
              <FaArrowRight className="info-link-icon" />
            </Link>
          </div>
        </section>

        {/* Interactive Tools Section */}
        <section ref={toolsRef} className="info-feature-section info-tools-section">
          <div className="info-section-header info-animate-on-scroll">
            <h2>
              <span className="info-section-icon">🛠️</span>
              Cutting-Edge Learning Tools
            </h2>
            <p>Unique tools to boost your cybersecurity understanding</p>
          </div>
          <div className="info-tools-grid">
            <div 
              className="info-tool-card info-animate-on-scroll info-clickable-card"
              onClick={(e) => handleCardClick(e, 'scenario-sphere')}
            >
              <h3>
                <span className="info-tool-icon">🔎</span>
                ScenarioSphere
              </h3>
              <p>Immerse yourself in realistic security scenarios with detailed storylines. Tackle simulated cyberattacks to build your incident response skills.</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch ScenarioSphere Demo</span>
                  </Link>
                </div>
              </div>
            </div>
            <div 
              className="info-tool-card info-animate-on-scroll info-clickable-card"
              onClick={(e) => handleCardClick(e, 'analogy-hub')}
            >
              <h3>
                <span className="info-tool-icon">🔄</span>
                Analogy Hub
              </h3>
              <p>Complex concepts made simple through custom analogies. Compare security concepts using memorable examples to reinforce your learning.</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch Analogy Hub Demo</span>
                  </Link>
                </div>
              </div>
            </div>
            <div 
              className="info-tool-card info-animate-on-scroll info-clickable-card"
              onClick={(e) => handleCardClick(e, 'grc-wizard')}
            >
              <h3>
                <span className="info-tool-icon">📋</span>
                GRC Wizard
              </h3>
              <p>Master governance, risk, and compliance topics with custom generated questions across multiple categories and difficulty levels.</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch GRC Wizard Demo</span>
                  </Link>
                </div>
              </div>
            </div>
            <div 
              className="info-tool-card info-animate-on-scroll info-clickable-card"
              onClick={(e) => handleCardClick(e, 'xploitcraft')}
            >
              <h3>
                <span className="info-tool-icon">⚔️</span>
                XploitCraft
              </h3>
              <p>Learn about exploitation techniques through educational code examples with detailed explanations for real world understanding.</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch XploitCraft Demo</span>
                  </Link>
                </div>
              </div>
            </div>
          </div>
          
          <div className="info-feature-links info-animate-on-scroll">
            <Link to="/demos" className="info-feature-link">
              <span>View All Tool Demos</span>
              <FaArrowRight className="info-link-icon" />
            </Link>
          </div>
        </section>

        {/* Resources Section */}
        <section className="info-feature-section info-resources-section">
          <div className="info-section-header info-animate-on-scroll">
            <h2>
              <span className="info-section-icon">📚</span>
              Comprehensive Resource Library
            </h2>
            <p>600+ curated resources to accelerate your learning</p>
          </div>
          <div className="info-resources-preview info-animate-on-scroll">
            <div className="info-resources-categories">
              <div className="info-resource-category">
                <span className="info-category-icon">🔧</span>
                <span>Security Tools</span>
              </div>
              <div className="info-resource-category">
                <span className="info-category-icon">🎓</span>
                <span>Courses</span>
              </div>
              <div className="info-resource-category">
                <span className="info-category-icon">📹</span>
                <span>YouTube Resources</span>
              </div>
              <div className="info-resource-category">
                <span className="info-category-icon">📜</span>
                <span>Certification Guides</span>
              </div>
              <div className="info-resource-category">
                <span className="info-category-icon">🛡️</span>
                <span>Security Frameworks</span>
              </div>
              <div className="info-resource-category">
                <span className="info-resource-more">+400 more</span>
              </div>
            </div>
          </div>
        </section>

        {/* Support Section */}
        <section className="info-feature-section info-support-section">
          <div className="info-section-header info-animate-on-scroll">
            <h2>
              <span className="info-section-icon">🤝</span>
              24/7 Expert Support
            </h2>
            <p>Get help whenever you need it</p>
          </div>
          <div className="info-support-content info-animate-on-scroll">
            <div 
              className="info-support-preview info-clickable-card"
              onClick={(e) => handleCardClick(e, 'support')}
            >
              <div className="info-support-chat">
                <div className="info-chat-header">
                  <h4>Support / Ask Anything</h4>
                </div>
                <div className="info-chat-message info-user-message">
                  <p>How do I know I am prepared for the Security+ exam?</p>
                  <span className="info-message-time">09:38 AM</span>
                </div>
                <div className="info-chat-message info-support-message">
                  <div className="info-support-avatar"></div>
                  <div className="info-message-content">
                    <p>Take a quick self check: grab the exam objectives PDF, skim each bullet point, and try to explain each one in your own words. If you can do that for most of them, go ahead and schedule the exam!</p>
                    <p>Would you like some tips on how to be confident during your exam?</p>
                  </div>
                  <span className="info-message-time">09:44 AM</span>
                </div>
                <div className="info-chat-input">
                  <input type="text" placeholder="Type your message here..." disabled />
                  <button className="info-send-button" disabled></button>
                </div>
              </div>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch Support System Demo</span>
                  </Link>
                </div>
              </div>
            </div>
            <div className="info-support-details">
              <h3>Your Personal Cybersecurity Tutor</h3>
              <ul className="info-support-features">
                <li>
                  <span className="info-check-icon">✓</span>
                  <span>Ask questions about any certification topic</span>
                </li>
                <li>
                  <span className="info-check-icon">✓</span>
                  <span>Get help with difficult concepts</span>
                </li>
                <li>
                  <span className="info-check-icon">✓</span>
                  <span>Receive customized study advice</span>
                </li>
                <li>
                  <span className="info-check-icon">✓</span>
                  <span>Average response time: 3 hours</span>
                </li>
                <li>
                  <span className="info-check-icon">✓</span>
                  <span>Technical assistance with platform features</span>
                </li>
              </ul>
              
              <div className="info-support-links">
                <Link to="/contact" className="info-support-link">
                  <span>Contact Support</span>
                  <FaArrowRight className="info-link-icon" />
                </Link>
              </div>
            </div>
          </div>
        </section>

        {/* Daily Rewards Section */}
        <section className="info-feature-section info-daily-section">
          <div className="info-section-header info-animate-on-scroll">
            <h2>
              <span className="info-section-icon">🎁</span>
              Daily Rewards & Challenges
            </h2>
            <p>Keep the momentum going with daily incentives</p>
          </div>
          <div className="info-daily-content info-animate-on-scroll">
            <div 
              className="info-daily-card info-clickable-card"
              onClick={(e) => handleCardClick(e, 'daily-bonus')}
            >
              <div className="info-daily-icon">🪙</div>
              <h3>Daily Bonus</h3>
              <p>Claim free coins every 24 hours to spend in the shop</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch Daily Bonus Demo</span>
                  </Link>
                </div>
              </div>
            </div>
            <div 
              className="info-daily-card info-clickable-card"
              onClick={(e) => handleCardClick(e, 'daily-pbq')}
            >
              <div className="info-daily-icon">🧩</div>
              <h3>Daily PBQ Challenge</h3>
              <p>Tackle a new performance-based question each day to earn bonus coins</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch Daily PBQ Demo</span>
                  </Link>
                </div>
              </div>
            </div>
            <div 
              className="info-daily-card info-clickable-card"
              onClick={(e) => handleCardClick(e, 'cyber-brief')}
            >
              <div className="info-daily-icon">📰</div>
              <h3>Cyber Brief</h3>
              <p>Stay informed with curated cybersecurity news and study tips</p>
              <div className="info-card-flip">
                <div className="info-demo-preview">
                  <Link to="/demos" className="info-demo-link">
                    <FaPlay className="info-demo-icon" />
                    <span>Watch Cyber Brief Demo</span>
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Pricing Section */}
        <section ref={pricingRef} className="info-pricing-section">
          <div className="info-section-header info-animate-on-scroll">
            <h2>
              <span className="info-section-icon">💎</span>
              Unlock Your Full Potential
            </h2>
            <p>Affordable access to premium cybersecurity training</p>
          </div>
          
          <div className="info-pricing-card info-animate-on-scroll">
            <h3 className="info-plan-name">Access</h3>
            <div className="info-price">
              <span className="info-currency">$</span>
              <span className="info-amount">9</span>
              <span className="info-decimal">.99</span>
              <span className="info-period">/month</span>
            </div>
            
            <ul className="info-pricing-features">
              <li>
                <span className="info-check-icon">✓</span>
                <span>13,000+ Practice Questions</span>
              </li>
              <li>
                <span className="info-check-icon">✓</span>
                <span>13 Certification Paths</span>
              </li>
              <li>
                <span className="info-check-icon">✓</span>
                <span>All Interactive Learning Tools</span>
              </li>
              <li>
                <span className="info-check-icon">✓</span>
                <span>Complete Resource Library</span>
              </li>
              <li>
                <span className="info-check-icon">✓</span>
                <span>24/7 Support / Ask Anything</span>
              </li>
              <li>
                <span className="info-check-icon">✓</span>
                <span>Gamified Learning Experience</span>
              </li>
              <li>
                <span className="info-check-icon">✓</span>
                <span>Daily Rewards & Challenges</span>
              </li>
            </ul>
            
            <Link to="/register" className="info-button info-cta-button">
              Get Started Now
            </Link>
            <p className="info-pricing-note">Cancel anytime. No long-term commitment.</p>
          </div>
        </section>

        {/* Testimonials Section */}
        <section className="info-testimonials-section">
          <div className="info-section-header info-animate-on-scroll">
            <h2>
              <span className="info-section-icon">💬</span>
              Testimonials
            </h2>
            <p>Join other IT enthusiasts who have leveled up their studying!</p>
          </div>
          
          <div className="info-testimonials-grid">
            <div className="info-testimonial-card info-animate-on-scroll">
              <div className="info-testimonial-content">
                <p>"I never thought I'd say this about a study site, but it's genuinely fun. The gamified aspect takes the monotomy out of studying, and having a that centralized resource hub is brilliant. My browser bookmarks are thanking me."</p>
              </div>
              <div className="info-testimonial-author">
                <div className="info-author-avatar" style={{ backgroundColor: '#4e54c8' }}></div>
                <div className="info-author-info">
                  <p className="info-author-name">Connor B.</p>
                  <p className="info-author-title">Security Analyst</p>
                </div>
              </div>
            </div>
            
            <div className="info-testimonial-card info-animate-on-scroll">
              <div className="info-testimonial-content">
                <p>"This site hits that sweet spot between education and entertainment. Studying for CompTIA certs feels rewarding instead of tedious. Big thumbs-up for the gamification, because I always tried to study like that myself, but now there is finally a dedicated webiste I can use."</p>
              </div>
              <div className="info-testimonial-author">
                <div className="info-author-avatar" style={{ backgroundColor: '#43cea2' }}></div>
                <div className="info-author-info">
                  <p className="info-author-name">Samantha K.</p>
                  <p className="info-author-title">Cybersecurity Manager</p>
                </div>
              </div>
            </div>
            
            <div className="info-testimonial-card info-animate-on-scroll">
              <div className="info-testimonial-content">
                <p>"I appreciate how this website doesn't feel like a lecture—more like playing a game that just happens to teach certifications. I also think the question page helped me alot when I needed to ask questions regarding my upcoming exam."</p>
              </div>
              <div className="info-testimonial-author">
                <div className="info-author-avatar" style={{ backgroundColor: '#ff9966' }}></div>
                <div className="info-author-info">
                  <p className="info-author-name">Leon T.</p>
                  <p className="info-author-title">IT Student</p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* FAQ Section */}
        <section className="info-faq-section">
          <div className="info-section-header info-animate-on-scroll">
            <h2>
              <span className="info-section-icon">❓</span>
              Frequently Asked Questions
            </h2>
            <p>Everything you need to know</p>
          </div>
          
          <div className="info-faq-content">
            <div className="info-faq-item info-animate-on-scroll">
              <h3 className="info-faq-question">How up-to-date are the practice questions?</h3>
              <p className="info-faq-answer">Our team of certified experts regularly updates all questions to match the latest exam objectives and industry changes. We ensure our content remains current with all certification requirements.</p>
            </div>
            
            <div className="info-faq-item info-animate-on-scroll">
              <h3 className="info-faq-question">Can I access CertGames on my mobile device?</h3>
              <p className="info-faq-answer">Absolutely! CertGames is fully responsive and works on all devices including desktop, tablet, and mobile phones. We also have a dedicated IOS app you can donwload in the App Store. Your progress syncs across all platforms automatically.</p>
            </div>
            
            <div className="info-faq-item info-animate-on-scroll">
              <h3 className="info-faq-question">How does the subscription work?</h3>
              <p className="info-faq-answer">For $9.99 per month, you gain unlimited access to all practice tests, tools, resources, and features. You can cancel your subscription at any time with no questions asked.</p>
            </div>
            
            <div className="info-faq-item info-animate-on-scroll">
              <h3 className="info-faq-question">Is there a guarantee I'll pass my certification exam?</h3>
              <p className="info-faq-answer">While we can't guarantee passing, our success rates are extremely high. Users who complete just half of our practice tests for their target certification and maintain a score of 75% or higher have a passing rate of over 95% on their actual exams.</p>
            </div>
            
            <div className="info-faq-item info-animate-on-scroll">
              <h3 className="info-faq-question">What if I need help with a specific concept?</h3>
              <p className="info-faq-answer">Our 24/7 "Ask Anything" support feature allows you to ask any certification-related question, test question, exam questions, study advice, and whatever you might need help with, you will receive a thorough, personalized answer from our expert team who have passed all certifications listed, typically within 3 hours.</p>
            </div>
            
            <div className="info-more-questions">
              <Link to="/contact" className="info-more-questions-link">
                <FaInfoCircle className="info-question-icon" />
                <span>Have more questions? Contact us</span>
              </Link>
            </div>
          </div>
        </section>

        {/* Final CTA Section */}
        <section className="info-final-cta">
          <div className="info-cta-content info-animate-on-scroll">
            <h2>Ready to Begin Your Cybersecurity Journey?</h2>
            <p>Join oter security professionals and IT enthusiasts who've transformed their careers/study prep with CertGames</p>
            <div className="info-cta-buttons">
              <Link to="/register" className="info-button info-primary-button">
                Create Your Account
              </Link>
              <Link to="/login" className="info-button info-secondary-button">
                Log In
              </Link>
            </div>
            <div className="info-oauth-options">
              <span>Quick sign-up with:</span>
              <div className="info-oauth-buttons">
                <button className="info-oauth-button info-google" onClick={() => window.location.href = "/api/oauth/login/google"}>
                  <FaGoogle className="info-oauth-icon" /> Google
                </button>
                <button className="info-oauth-button info-apple" onClick={() => window.location.href = "/api/oauth/login/apple"}>
                  <FaApple className="info-oauth-icon" /> Apple ID
                </button>
              </div>
            </div>
            <div className="info-app-download">
              <a href="#" className="info-app-link">
                <FaAppStore className="info-app-icon" />
                <span>Download on the App Store</span>
              </a>
            </div>
          </div>
          <div className="info-cta-graphic">
            <div className="info-glow"></div>
          </div>
        </section>

        {/* Footer */}
        <Footer />
      </div>
    </>
  );
};

export default InfoPage;
