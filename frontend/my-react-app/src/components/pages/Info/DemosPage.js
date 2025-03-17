// src/components/pages/Info/DemosPage.js
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FaPlay, FaChevronLeft, FaChevronRight } from 'react-icons/fa';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import SEOHelmet from '../../SEOHelmet';
import StructuredData from '../../StructuredData';
import './DemosPage.css';

// Video imports
import analogy from './videos/anal.mp4';
import bonus from './videos/bonus.mp4';
import grc from './videos/grcc.mp4';
import scenario from './videos/sc.mp4';
import recourse from './videos/rec.mp4';
import profile from './videos/prof.mp4';
import xploit from './videos/xploit.mp4';
import leader from './videos/leader.mp4';
import testinterface from './videos/testinterface.mp4';
import xp from './videos/xp.mp4';
import support from './videos/support.mp4';
import coin from './videos/coin.mp4';
import review from './videos/review.mp4';
import ach from './videos/achievements.mp4';
import shop from './videos/shop.mp4';

// Thumbnail imports
import colorsThumbnail from './images/colors.webp';
import testThumbnail from './images/test.webp';
import recThumbnail from './images/rec.webp';
import leaderThumbnail from './images/leader.webp';
import xploitThumbnail from './images/xploit.webp';
import grcThumbnail from './images/grc.webp';
import analogyThumbnail from './images/analogy.webp';
import scenThumbnail from './images/scen.webp';
import bonusThumbnail from './images/bonus.webp';
import pbqThumbnail from './images/pbqs.webp';
import reviewThumbnail from './images/review.webp';
import shopThumbnail from './images/shop.webp';
import supportThumbnail from './images/support.webp';
import xpThumbnail from './images/xboost.webp';
import achi from './images/achi.webp';

const DemosPage = () => {
  const [activeSection, setActiveSection] = useState('featured');
  const [activeDemo, setActiveDemo] = useState(null);

  // Breadcrumb schema for SEO
  const breadcrumbSchema = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    "itemListElement": [
      {
        "@type": "ListItem",
        "position": 1,
        "name": "Home",
        "item": "https://certgames.com/"
      },
      {
        "@type": "ListItem",
        "position": 2,
        "name": "Demo Features",
        "item": "https://certgames.com/demos"
      }
    ]
  };

  // Demo data with all videos and thumbnails
  const demoData = {
    gamification: [
      {
        id: 'xp-system',
        title: 'XP & Leveling System',
        description: 'See how completing tests and answering questions correctly earns you XP to level up your profile.',
        videoUrl: xp, 
        thumbnail: xpThumbnail
      },
      {
        id: 'coins-system',
        title: 'Coins & Shop System',
        description: 'Watch how to earn coins and spend them in the shop to unlock unique avatars and boosts.',
        videoUrl: shop,
        thumbnail: shopThumbnail
      },
      {
        id: 'achievements',
        title: 'Achievement System',
        description: 'Discover the various achievements you can unlock as you progress through your certification journey.',
        videoUrl: ach, 
        thumbnail: achi
      },
      {
        id: 'leaderboards',
        title: 'Leaderboards',
        description: 'See how you stack up against other cybersecurity enthusiasts on our global leaderboards.',
        videoUrl: leader,
        thumbnail: leaderThumbnail
      }
    ],
    learning: [
      {
        id: 'scenario-sphere',
        title: 'ScenarioSphere',
        description: 'Experience realistic security scenarios with detailed storylines to build your incident response skills.',
        videoUrl: scenario,
        thumbnail: scenThumbnail
      },
      {
        id: 'analogy-hub',
        title: 'Analogy Hub',
        description: 'See how complex security concepts are broken down using memorable analogies to enhance understanding.',
        videoUrl: analogy,
        thumbnail: analogyThumbnail
      },
      {
        id: 'grc-wizard',
        title: 'GRC Wizard',
        description: 'Watch how our GRC Wizard helps you master governance, risk, and compliance topics with custom-generated questions.',
        videoUrl: grc,
        thumbnail: grcThumbnail
      },
      {
        id: 'xploitcraft',
        title: 'XploitCraft',
        description: 'Learn about exploitation techniques through educational code examples with detailed explanations.',
        videoUrl: xploit,
        thumbnail: xploitThumbnail
      }
    ],
    daily: [
      {
        id: 'pbq-challenge',
        title: 'Daily PBQ Challenge',
        description: 'Watch how the daily performance-based question challenges work and how to solve them.',
        videoUrl: bonus, 
        thumbnail: bonusThumbnail
      }
    ],
    tests: [
      {
        id: 'test-interface',
        title: 'Test Interface',
        description: 'See how our intuitive test interface makes studying for your certification exams a breeze.',
        videoUrl: testinterface, 
        thumbnail: testThumbnail
      },
      {
        id: 'review-answers',
        title: 'Review & Analytics',
        description: 'See how our detailed review and analytics help you identify and improve your weak areas.',
        videoUrl: review,
        thumbnail: reviewThumbnail
      }
    ],
    support: [
      {
        id: 'ask-anything',
        title: 'Ask Anything',
        description: 'Watch how our 24/7 support system works to help you with any questions or issues.',
        videoUrl: support, 
        thumbnail: supportThumbnail
      }
    ],
    profile: [
      {
        id: 'profile-colors',
        title: 'Color Scheme Options',
        description: 'See how you can personalize your learning experience by switching between different color schemes.',
        videoUrl: profile,
        thumbnail: colorsThumbnail
      }
    ],
    resources: [
      {
        id: 'resource-hub',
        title: 'Resource Hub',
        description: 'Explore our comprehensive collection of study materials, guides, and references to boost your learning.',
        videoUrl: recourse,
        thumbnail: recThumbnail
      }
    ]
  };

  // Create a featured demos array with demos from each category
  const featuredDemos = [
    demoData.gamification[0],
    demoData.learning[0],
    demoData.daily[0],
    demoData.tests[0],
    demoData.support[0],
    demoData.profile[0],
    demoData.resources[0]
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
      case 'profile':
        return demoData.profile;
      case 'resources':
        return demoData.resources;
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
        description="See CertGames' interactive learning tools in action. Watch demos of our gamified cybersecurity training features, exam simulators, practice tests, study resources, and specialized learning tools."
        canonicalUrl="/demos"
      />
      <StructuredData data={breadcrumbSchema} />
    <div className="demos-container">
      <InfoNavbar />
      
      <main className="demos-content">
        <header className="demos-header">
          <h1 className="demos-title">
            <span className="demos-icon" aria-hidden="true">🎬</span>
            Feature Demos
          </h1>
          <p className="demos-subtitle">Watch our interactive demos to see CertGames in action</p>
        </header>

        {/* Demo Player Section */}
        <section id="demo-player" className="demo-player-section">
          {activeDemo && (
            <div className="demo-player-container">
              <div className="demo-video">
                {/* Updated video player component */}
                <div className="demo-video-placeholder">
                  {activeDemo.videoUrl ? (
                    <video 
                      src={activeDemo.videoUrl} 
                      poster={typeof activeDemo.thumbnail === 'string' ? activeDemo.thumbnail : undefined}
                      controls
                    />
                  ) : (
                    <>
                      <img src={activeDemo.thumbnail} alt={`Demonstration of ${activeDemo.title} feature`} />
                      <div className="play-overlay">
                        <FaPlay className="play-icon" aria-hidden="true" />
                        <span>Demo Video Placeholder</span>
                      </div>
                    </>
                  )}
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
        </section>

        {/* Demo Categories Navigation */}
        <nav className="demo-categories" aria-label="Demo categories">
          <button
            className={`category-button ${activeSection === 'featured' ? 'active' : ''}`}
            onClick={() => setActiveSection('featured')}
            aria-pressed={activeSection === 'featured'}
          >
            Featured
          </button>
          <button
            className={`category-button ${activeSection === 'gamification' ? 'active' : ''}`}
            onClick={() => setActiveSection('gamification')}
            aria-pressed={activeSection === 'gamification'}
          >
            Gamification
          </button>
          <button
            className={`category-button ${activeSection === 'learning' ? 'active' : ''}`}
            onClick={() => setActiveSection('learning')}
            aria-pressed={activeSection === 'learning'}
          >
            Learning Tools
          </button>
          <button
            className={`category-button ${activeSection === 'daily' ? 'active' : ''}`}
            onClick={() => setActiveSection('daily')}
            aria-pressed={activeSection === 'daily'}
          >
            Daily Features
          </button>
          <button
            className={`category-button ${activeSection === 'tests' ? 'active' : ''}`}
            onClick={() => setActiveSection('tests')}
            aria-pressed={activeSection === 'tests'}
          >
            Test Experience
          </button>
          <button
            className={`category-button ${activeSection === 'profile' ? 'active' : ''}`}
            onClick={() => setActiveSection('profile')}
            aria-pressed={activeSection === 'profile'}
          >
            Profile
          </button>
          <button
            className={`category-button ${activeSection === 'resources' ? 'active' : ''}`}
            onClick={() => setActiveSection('resources')}
            aria-pressed={activeSection === 'resources'}
          >
            Resources
          </button>
          <button
            className={`category-button ${activeSection === 'support' ? 'active' : ''}`}
            onClick={() => setActiveSection('support')}
            aria-pressed={activeSection === 'support'}
          >
            Support
          </button>
        </nav>

        {/* Demo Thumbnails */}
        <section className="demo-thumbnails">
          <div className="thumbnails-header">
            <h3>{activeSection.charAt(0).toUpperCase() + activeSection.slice(1)} Demos</h3>
            <div className="thumbnails-navigation" aria-label="Thumbnail navigation">
              <button className="nav-button" aria-label="Previous demos">
                <FaChevronLeft aria-hidden="true" />
              </button>
              <button className="nav-button" aria-label="Next demos">
                <FaChevronRight aria-hidden="true" />
              </button>
            </div>
          </div>
          
          <div className="thumbnails-grid" role="list">
            {getCurrentDemos().map((demo) => (
              <div 
                key={demo.id} 
                className={`thumbnail-item ${activeDemo && activeDemo.id === demo.id ? 'active' : ''}`}
                onClick={() => handleDemoSelect(demo)}
                role="listitem"
                tabIndex="0"
                aria-selected={activeDemo && activeDemo.id === demo.id}
              >
                {/* Updated thumbnail component */}
                <div className="thumbnail-image">
                  <img src={demo.thumbnail} alt={`Thumbnail for ${demo.title} demo`} />
                  <div className="thumbnail-overlay">
                    <FaPlay className="thumbnail-play" aria-hidden="true" />
                  </div>
                </div>
                <h4 className="thumbnail-title">{demo.title}</h4>
              </div>
            ))}
          </div>
        </section>

        {/* Register CTA Section */}
        <section className="demos-cta-section">
          <div className="demos-cta-content">
            <h2>Ready to experience all these features?</h2>
            <p>Create your free account today and start your cybersecurity journey with CertGames!</p>
            <Link to="/register" className="cta-button">
              Create Your Account
            </Link>
          </div>
        </section>
      </main>

      <Footer />
    </div>
    </>
  );
};

export default DemosPage;
