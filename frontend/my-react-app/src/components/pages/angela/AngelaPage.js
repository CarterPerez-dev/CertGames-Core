// frontend/my-react-app/src/components/pages/angela/AngelaPage.js
import React, { useState, useEffect, useRef } from 'react';
import { Global, css } from '@emotion/react';
import styled from '@emotion/styled';
import { FaBrain, FaCogs, FaSearch, FaShieldAlt, FaTerminal, FaCode, FaGlobe, FaLightbulb } from 'react-icons/fa';
import HeroSection from './components/HeroSection';
import FeatureSection from './components/FeatureSection';
import InstallSection from './components/InstallSection';
import DialogueSystem from './components/DialogueSystem';
import PhilosophicalFooter from './components/PhilosophicalFooter';
import ThoughtFlowAnimation from './animations/ThoughtFlowAnimations';
import { dialogueData } from './utils/dialogueData';
import { ANGELA_THEME as THEME } from './styles/PhilosophicalTheme';

// Matrix Rain Effect Component
const MatrixRain = () => {
  const canvasRef = useRef(null);
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });

  useEffect(() => {
    const updateDimensions = () => {
      if (canvasRef.current) {
        setDimensions({
          width: window.innerWidth,
          height: window.innerHeight
        });
      }
    };

    window.addEventListener('resize', updateDimensions);
    updateDimensions();

    return () => window.removeEventListener('resize', updateDimensions);
  }, []);

  useEffect(() => {
    if (!canvasRef.current || dimensions.width === 0) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    
    canvas.width = dimensions.width;
    canvas.height = dimensions.height;
    
    // Characters for the matrix rain
    const characters = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
    
    // Character array setup
    const fontSize = 14;
    const columns = Math.ceil(canvas.width / fontSize);
    
    // Array of drops - one per column
    const drops = Array(columns).fill(0);
    
    // Matrix rain drawing
    const draw = () => {
      // Black with alpha for fade effect
      ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      // Set font and color
      ctx.fillStyle = THEME.colors.terminalGreen;
      ctx.font = `${fontSize}px monospace`;
      
      // Draw characters
      for (let i = 0; i < drops.length; i++) {
        // Get random character
        const text = characters.charAt(Math.floor(Math.random() * characters.length));
        
        // Draw text at (i*fontSize, drops[i]*fontSize)
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);
        
        // If drop reaches bottom or random chance, reset to top
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        
        // Move drops down
        drops[i]++;
      }
    };
    
    // Animation loop
    const interval = setInterval(draw, 35);
    
    return () => clearInterval(interval);
  }, [dimensions]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: -1,
        opacity: 0.15
      }}
    />
  );
};

// Custom global styles for improved appearance
const angelaEnhancedStyles = css`
  /* Import required fonts */
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=IBM+Plex+Serif:wght@400;500;600&family=VT323&display=swap');
  
  /* Variables for consistent theming */
  :root {
    --angela-bg-primary: #0a0a0a;
    --angela-bg-secondary: #121215;
    --angela-bg-tertiary: #1a1a1a;
    --angela-text-primary: #e0e0e0;
    --angela-text-secondary: #aaaaaa;
    --angela-text-tertiary: #777777;
    --angela-accent-primary: #ff3333;
    --angela-accent-secondary: #ff5555;
    --angela-accent-tertiary: #990000;
    --angela-accent-glow: rgba(255, 50, 50, 0.6);
    --angela-border-primary: #333333;
    --angela-border-secondary: #222222;
    --angela-terminal-green: #33ff33;
    --angela-terminal-cyan: #33ffff;
    --angela-terminal-yellow: #ffff33;
    
    /* Spacing */
    --angela-space-xs: 0.25rem;
    --angela-space-sm: 0.5rem;
    --angela-space-md: 1rem;
    --angela-space-lg: 1.5rem;
    --angela-space-xl: 2rem;
    --angela-space-xxl: 3rem;
  }
  
  .angela-page {
    background-color: var(--angela-bg-primary);
    color: var(--angela-text-primary);
    font-family: 'IBM Plex Mono', 'Courier New', monospace;
    line-height: 1.6;
    overflow-x: hidden;
    position: relative;
    min-height: 100vh;
    
    * {
      box-sizing: border-box;
    }

    /* Center all main content sections */
    .angela-content {
      width: 100%;
      max-width: 1200px;
      margin: 0 auto;
      padding: var(--angela-space-xl);
    }
    
    /* Add textured background */
    .noise-texture {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3CfeColorMatrix type='matrix' values='1 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 0.1 0'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E");
      opacity: 0.07;
      pointer-events: none;
      z-index: -1;
    }
    
    /* Enhanced scanline effect */
    .scanlines {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: linear-gradient(
        to bottom,
        transparent 49.5%,
        rgba(32, 32, 32, 0.05) 49.5%,
        rgba(32, 32, 32, 0.05) 50.5%,
        transparent 50.5%
      );
      background-size: 100% 4px;
      pointer-events: none;
      z-index: 1;
      opacity: 0.25;
    }
    
    /* Typography improvements */
    h1, h2, h3, h4, h5, h6 {
      font-family: 'VT323', 'Press Start 2P', monospace;
      letter-spacing: 0.05em;
      line-height: 1.2;
    }
    
    .section-title {
      font-size: 3rem;
      color: var(--angela-text-primary);
      text-align: center;
      margin-bottom: 3rem;
      text-transform: uppercase;
      position: relative;
    }
    
    .section-title::after {
      content: "";
      position: absolute;
      bottom: -1rem;
      left: 50%;
      transform: translateX(-50%);
      width: 80px;
      height: 4px;
      background-color: var(--angela-accent-primary);
    }
    
    /* Improve feature cards */
    .feature-card {
      background-color: var(--angela-bg-secondary);
      border: 1px solid var(--angela-border-primary);
      border-radius: 6px;
      padding: 1.5rem;
      transition: all 0.3s ease;
      position: relative;
      height: 100%;
      display: flex;
      flex-direction: column;
    }
    
    .feature-card:hover {
      transform: translateY(-5px);
      border-color: var(--angela-accent-primary);
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
    }
    
    .feature-icon {
      font-size: 2.5rem;
      color: var(--angela-accent-primary);
      margin-bottom: 1rem;
      transition: all 0.3s ease;
    }
    
    .feature-card:hover .feature-icon {
      transform: scale(1.1);
      color: var(--angela-accent-secondary);
    }
    
    /* Improve code blocks */
    .code-block {
      position: relative;
      background-color: var(--angela-bg-secondary);
      border: 2px solid var(--angela-border-primary);
      padding: 1.5rem;
      margin: 2rem auto;
      overflow-x: auto;
      border-radius: 6px;
    }
    
    /* Responsive adjustments */
    @media (max-width: 768px) {
      .angela-content {
        padding: var(--angela-space-md);
      }
      
      .section-title {
        font-size: 2.25rem;
      }
    }
  }
`;

// Improved page container with proper alignment
const AngelaPageContainer = styled.div`
  min-height: 100vh;
  width: 100%;
  background-color: ${THEME.colors.bgPrimary};
  color: ${THEME.colors.textPrimary};
  position: relative;
  overflow-x: hidden;
  
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: radial-gradient(
      circle at center,
      ${THEME.colors.bgSecondary} 0%,
      ${THEME.colors.bgPrimary} 70%
    );
    z-index: -2;
    pointer-events: none;
  }
`;

// Section wrapper to ensure centered content
const SectionWrapper = styled.div`
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 2rem;
  
  @media (max-width: 768px) {
    padding: 0 1rem;
  }
`;

// Section separator with improved styling
const SectionSeparator = styled.div`
  width: 100%;
  max-width: 1200px;
  margin: 4rem auto;
  height: 8px;
  background-image: repeating-linear-gradient(
    to right,
    ${THEME.colors.borderPrimary},
    ${THEME.colors.borderPrimary} 8px,
    transparent 8px,
    transparent 16px
  );
  position: relative;
  
  &::before, &::after {
    content: "";
    position: absolute;
    width: 16px;
    height: 16px;
    background-color: ${THEME.colors.accentPrimary};
  }
  
  &::before {
    left: calc(50% - 50px);
    top: -4px;
  }
  
  &::after {
    right: calc(50% - 50px);
    top: -4px;
  }
`;

// Navigation button with improved styling
const NavigationButton = styled.button`
  position: fixed;
  bottom: 40px;
  right: 40px;
  background-color: ${THEME.colors.bgSecondary};
  color: ${THEME.colors.terminalGreen};
  border: 2px solid ${THEME.colors.borderPrimary};
  width: 60px;
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
  cursor: pointer;
  z-index: 100;
  transition: all 0.3s ${THEME.animations.curveEaseInOut};
  box-shadow: 0 0 10px rgba(51, 255, 51, 0.3);
  border-radius: 8px;
  
  &:hover {
    background-color: ${THEME.colors.bgTertiary};
    transform: translateY(-5px);
    box-shadow: 0 5px 15px rgba(51, 255, 51, 0.4);
  }
  
  &::after {
    content: "⬆";
    font-family: monospace;
  }
`;

/**
 * AngelaPage Component
 * 
 * The main container component for the Angela CLI landing page.
 * Enhanced with better alignment, responsive design, and visual effects.
 */
const AngelaPage = () => {
  const [scrollPosition, setScrollPosition] = useState(0);
  const [showScrollButton, setShowScrollButton] = useState(false);
  const [glitchActive, setGlitchActive] = useState(false);
  const dialogueRef = useRef(null);
  const heroRef = useRef(null);

  // Track scroll position for effects
  useEffect(() => {
    const handleScroll = () => {
      const position = window.scrollY;
      setScrollPosition(position);
      setShowScrollButton(position > 500);
      
      // Trigger glitch effect at certain scroll points
      if (
        (position > 1000 && position < 1050) ||
        (position > 2200 && position < 2250)
      ) {
        if (!glitchActive) {
          setGlitchActive(true);
          setTimeout(() => setGlitchActive(false), 500);
        }
      }
    };
    
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, [glitchActive]);

  // Handle scroll to top button
  const handleScrollToTop = () => {
    window.scrollTo({
      top: 0,
      behavior: "smooth"
    });
  };

  // Scroll to dialogue section
  const scrollToDialogue = () => {
    if (dialogueRef.current) {
      dialogueRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <AngelaPageContainer className="angela-page">
      {/* Enhanced global styles */}
      <Global styles={angelaEnhancedStyles} />
      
      {/* Background effects */}
      <div className="noise-texture"></div>
      <div className="scanlines"></div>
      <MatrixRain />
      
      {/* Main content */}
      <HeroSection ref={heroRef} onExploreClick={scrollToDialogue} />
      
      <SectionSeparator />
      
      <SectionWrapper>
        <div ref={dialogueRef}>
          <DialogueSystem 
            dialogueData={dialogueData}
            philosophical={true}
            enableLooping={true}
            initialDepth={1}
            rightProgression={true} // Enable rightward and downward progression
          />
        </div>
      </SectionWrapper>
      
      <SectionSeparator />
      
      <SectionWrapper>
        <FeatureSection iconLibrary={
          {
            brain: <FaBrain />,
            cogs: <FaCogs />,
            search: <FaSearch />,
            shield: <FaShieldAlt />,
            terminal: <FaTerminal />,
            code: <FaCode />,
            globe: <FaGlobe />,
            lightbulb: <FaLightbulb />
          }
        } />
      </SectionWrapper>
      
      <SectionSeparator />
      
      <SectionWrapper>
        <InstallSection />
      </SectionWrapper>
      
      <SectionSeparator />
      
      <PhilosophicalFooter />
      
      {/* Ambient animation effects */}
      <ThoughtFlowAnimation
        active={true}
        particleCount={20}
        bubbleCount={10}
        lineCount={15}
        baseColor={THEME.colors.textMuted}
        accentColor={`${THEME.colors.accentPrimary}33`}
        origin="center"
        zIndex={-1}
      />
      
      {/* Navigation */}
      {showScrollButton && (
        <NavigationButton 
          onClick={handleScrollToTop}
          aria-label="Scroll to Top"
        />
      )}
    </AngelaPageContainer>
  );
};

export default AngelaPage;
