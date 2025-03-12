// src/components/pages/Info/DemosPage.js
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FaPlay, FaChevronLeft, FaChevronRight } from 'react-icons/fa';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import './DemosPage.css';
import SEOHelmet from '../../SEOHelmet';


const DemosPage = () => {
  const [activeSection, setActiveSection] = useState('featured');
  const [activeDemo, setActiveDemo] = useState(null);

  // Demo data - this would be replaced with actual demo data
  const demoData = {
    gamification: [
      {
        id: 'xp-system',
        title: 'XP & Leveling System',
        description: 'See how completing tests and answering questions correctly earns you XP to level up your profile.',
        videoUrl: '/demos/xp-system.mp4', // Placeholder - will be replaced
        thumbnail: 'https://via.placeholder.com/600x338?text=XP+System+Demo'
      },
      {
        id: 'coins-system',
        title: 'Coins & Shop System',
        description: 'Watch how to earn coins and spend them in the shop to unlock unique avatars and boosts.',
        videoUrl: '/demos/coins-system.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Coins+System+Demo'
      },
      {
        id: 'achievements',
        title: 'Achievement System',
        description: 'Discover the various achievements you can unlock as you progress through your certification journey.',
        videoUrl: '/demos/achievements.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Achievements+Demo'
      },
      {
        id: 'leaderboards',
        title: 'Leaderboards',
        description: 'See how you stack up against other cybersecurity enthusiasts on our global leaderboards.',
        videoUrl: '/demos/leaderboards.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Leaderboards+Demo'
      }
    ],
    learning: [
      {
        id: 'scenario-sphere',
        title: 'ScenarioSphere',
        description: 'Experience realistic security scenarios with detailed storylines to build your incident response skills.',
        videoUrl: '/demos/scenario-sphere.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=ScenarioSphere+Demo'
      },
      {
        id: 'analogy-hub',
        title: 'Analogy Hub',
        description: 'See how complex security concepts are broken down using memorable analogies to enhance understanding.',
        videoUrl: '/demos/analogy-hub.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Analogy+Hub+Demo'
      },
      {
        id: 'grc-wizard',
        title: 'GRC Wizard',
        description: 'Watch how our GRC Wizard helps you master governance, risk, and compliance topics with custom-generated questions.',
        videoUrl: '/demos/grc-wizard.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=GRC+Wizard+Demo'
      },
      {
        id: 'xploitcraft',
        title: 'XploitCraft',
        description: 'Learn about exploitation techniques through educational code examples with detailed explanations.',
        videoUrl: '/demos/xploitcraft.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=XploitCraft+Demo'
      }
    ],
    daily: [
      {
        id: 'daily-bonus',
        title: 'Daily Bonus',
        description: 'See how to claim your daily free coins to spend in the shop.',
        videoUrl: '/demos/daily-bonus.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Daily+Bonus+Demo'
      },
      {
        id: 'pbq-challenge',
        title: 'Daily PBQ Challenge',
        description: 'Watch how the daily performance-based question challenges work and how to solve them.',
        videoUrl: '/demos/pbq-challenge.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=PBQ+Challenge+Demo'
      },
      {
        id: 'cyber-brief',
        title: 'Cyber Brief',
        description: 'Check out our daily cybersecurity news and study tips feature.',
        videoUrl: '/demos/cyber-brief.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Cyber+Brief+Demo'
      }
    ],
    tests: [
      {
        id: 'test-interface',
        title: 'Test Interface',
        description: 'See how our intuitive test interface makes studying for your certification exams a breeze.',
        videoUrl: '/demos/test-interface.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Test+Interface+Demo'
      },
      {
        id: 'exam-mode',
        title: 'Exam Mode',
        description: 'Experience our realistic exam simulation mode to prepare for the real thing.',
        videoUrl: '/demos/exam-mode.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Exam+Mode+Demo'
      },
      {
        id: 'review-answers',
        title: 'Review & Analytics',
        description: 'See how our detailed review and analytics help you identify and improve your weak areas.',
        videoUrl: '/demos/review-analytics.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Review+Analytics+Demo'
      }
    ],
    support: [
      {
        id: 'ask-anything',
        title: 'Ask Anything',
        description: 'Watch how our 24/7 support system works to help you with any questions or issues.',
        videoUrl: '/demos/ask-anything.mp4', // Placeholder
        thumbnail: 'https://via.placeholder.com/600x338?text=Ask+Anything+Demo'
      }
    ]
  };

  // Create a featured demos array with 1 demo from each category
  const featuredDemos = [
    demoData.gamification[0],
    demoData.learning[0],
    demoData.daily[0],
    demoData.tests[0],
    demoData.support[0]
  ];

  // Handle demo selection
  const handleDemoSelect = (demo) => {
    setActiveDemo(demo);
    // Scroll to video player
    document.getElementById('demo-player').scrollIntoView({ behavior: 'smooth' });
  };

  // Get current demos based on active section
  const getCurrentDemos = () => {
    switch(activeSection) {
      case 'featured':
        return featuredDemos;
      case 'gamification':
        return demoData.gamification;
      case 'learning':
        return demoData.learning;
      case 'daily':
        return demoData.daily;
      case 'tests':
        return demoData.tests;
      case 'support':
        return demoData.support;
      default:
        return featuredDemos;
    }
  };

  // Set default active demo when section changes
  useEffect(() => {
    const currentDemos = getCurrentDemos();
    if (currentDemos.length > 0) {
      setActiveDemo(currentDemos[0]);
    }
  }, [activeSection]);

  return (
    <>
      <SEOHelmet 
        title="Interactive Feature Demos | CertGames"
        description="See CertGames' interactive learning tools in action. Watch demos of our gamified cybersecurity training features, exam simulators and practice tests, and specialized learning tools."
        canonicalUrl="/demos"
      />
    <div className="demos-container">
      <InfoNavbar />
      
      <div className="demos-content">
        <div className="demos-header">
          <h1 className="demos-title">
            <span className="demos-icon">🎬</span>
            Feature Demos
          </h1>
          <p className="demos-subtitle">Watch our interactive demos to see CertGames in action</p>
        </div>

        {/* Demo Player Section */}
        <div id="demo-player" className="demo-player-section">
          {activeDemo && (
            <div className="demo-player-container">
              <div className="demo-video">
                {/* This would be replaced with an actual video player component */}
                <div className="demo-video-placeholder">
                  <img src={activeDemo.thumbnail} alt={activeDemo.title} />
                  <div className="play-overlay">
                    <FaPlay className="play-icon" />
                    <span>Demo Video Placeholder</span>
                  </div>
                </div>
              </div>
              <div className="demo-info">
                <h2>{activeDemo.title}</h2>
                <p>{activeDemo.description}</p>
                <div className="demo-cta">
                  <Link to="/register" className="demo-register-btn">
                    Try This Feature
                  </Link>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Demo Categories Navigation */}
        <div className="demo-categories">
          <button
            className={`category-button ${activeSection === 'featured' ? 'active' : ''}`}
            onClick={() => setActiveSection('featured')}
          >
            Featured
          </button>
          <button
            className={`category-button ${activeSection === 'gamification' ? 'active' : ''}`}
            onClick={() => setActiveSection('gamification')}
          >
            Gamification
          </button>
          <button
            className={`category-button ${activeSection === 'learning' ? 'active' : ''}`}
            onClick={() => setActiveSection('learning')}
          >
            Learning Tools
          </button>
          <button
            className={`category-button ${activeSection === 'daily' ? 'active' : ''}`}
            onClick={() => setActiveSection('daily')}
          >
            Daily Features
          </button>
          <button
            className={`category-button ${activeSection === 'tests' ? 'active' : ''}`}
            onClick={() => setActiveSection('tests')}
          >
            Test Experience
          </button>
          <button
            className={`category-button ${activeSection === 'support' ? 'active' : ''}`}
            onClick={() => setActiveSection('support')}
          >
            Support
          </button>
        </div>

        {/* Demo Thumbnails */}
        <div className="demo-thumbnails">
          <div className="thumbnails-header">
            <h3>{activeSection.charAt(0).toUpperCase() + activeSection.slice(1)} Demos</h3>
            <div className="thumbnails-navigation">
              <button className="nav-button">
                <FaChevronLeft />
              </button>
              <button className="nav-button">
                <FaChevronRight />
              </button>
            </div>
          </div>
          
          <div className="thumbnails-grid">
            {getCurrentDemos().map((demo) => (
              <div 
                key={demo.id} 
                className={`thumbnail-item ${activeDemo && activeDemo.id === demo.id ? 'active' : ''}`}
                onClick={() => handleDemoSelect(demo)}
              >
                <div className="thumbnail-image">
                  <img src={demo.thumbnail} alt={demo.title} />
                  <div className="thumbnail-overlay">
                    <FaPlay className="thumbnail-play" />
                  </div>
                </div>
                <h4 className="thumbnail-title">{demo.title}</h4>
              </div>
            ))}
          </div>
        </div>

        {/* Register CTA Section */}
        <div className="demos-cta-section">
          <div className="demos-cta-content">
            <h2>Ready to experience all these features?</h2>
            <p>Create your free account today and start your cybersecurity journey with CertGames!</p>
            <Link to="/register" className="cta-button">
              Create Your Account
            </Link>
          </div>
        </div>
      </div>

      <Footer />
    </div>
  );
};

export default DemosPage;
