// frontend/my-react-app/src/components/pages/angela/AngelaPage.js
import React, { useState, useEffect, useRef } from 'react';
import { Global, css } from '@emotion/react';
import styled from '@emotion/styled';
import { 
  FaBrain, 
  FaCogs, 
  FaSearch, 
  FaShieldAlt, 
  FaTerminal, 
  FaCode, 
  FaGlobe, 
  FaLightbulb,
  FaChevronUp,
  FaGithub,
  FaBook,
  FaDownload
} from 'react-icons/fa';

import HeroSection from './components/HeroSection';
import FeatureSection from './components/FeatureSection';
import InstallSection from './components/InstallSection';
import DialogueSystem from './components/DialogueSystem';
import PhilosophicalFooter from './components/PhilosophicalFooter';
import ThoughtFlowAnimation from './animations/ThoughtFlowAnimations';
import { dialogueData } from './utils/dialogueData';
import { ANGELA_THEME as THEME } from './styles/PhilosophicalTheme';

// Enhanced global styles with improved textures and typography
const angelaEnhancedStyles = css`
  /* Import required fonts */
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=IBM+Plex+Serif:wght@400;500;600&family=VT323&family=Press+Start+2P&display=swap');
  
  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

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
  }
  
  body {
    margin: 0;
    padding: 0;
    overflow-x: hidden;
  }
  
  .angela-page {
    background-color: var(--angela-bg-primary);
    color: var(--angela-text-primary);
    font-family: 'IBM Plex Mono', 'Courier New', monospace;
    line-height: 1.6;
    overflow-x: hidden;
    position: relative;
    min-height: 100vh;
    width: 100%;
    scroll-behavior: smooth;
    
    /* Ensure all main content sections are centered properly with consistent max-width */
    section, .section-inner {
      width: 100%;
      max-width: 1200px;
      margin: 0 auto;
      padding: 4rem 2rem;
    }
    
    @media (max-width: 768px) {
      section, .section-inner {
        padding: 3rem 1rem;
      }
    }
    
    /* Enhanced textured background */
    .noise-texture {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3CfeColorMatrix type='matrix' values='1 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 0.15 0'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E");
      opacity: 0.12;
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
      opacity: 0.3;
    }
    
    /* Improved typography defaults */
    h1, h2, h3, h4, h5, h6 {
      font-family: 'IBM Plex Mono', monospace;
      letter-spacing: 0.5px;
      line-height: 1.2;
      margin-top: 0;
    }
    
    p, li, a, button {
      font-family: 'IBM Plex Mono', monospace;
      letter-spacing: 0.3px;
    }
    
    a {
      color: var(--angela-accent-primary);
      text-decoration: none;
      transition: all 0.2s ease;
      
      &:hover {
        color: var(--angela-accent-secondary);
        text-decoration: underline;
      }
    }
  }
`;

// Improved page container with proper alignment and enhanced visuals
const AngelaPageContainer = styled.div`
  min-height: 100vh;
  width: 100%;
  background-color: ${THEME.colors.bgPrimary};
  color: ${THEME.colors.textPrimary};
  position: relative;
  overflow-x: hidden;
  display: flex;
  flex-direction: column;
  align-items: center;
  
  /* Enhanced radial gradient background */
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: radial-gradient(
      ellipse at center,
      ${THEME.colors.bgSecondary}40 0%,
      ${THEME.colors.bgPrimary}80 70%,
      ${THEME.colors.bgPrimary} 100%
    );
    z-index: -2;
    pointer-events: none;
  }
  
  /* Grid texture overlay */
  &::after {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-image: 
      linear-gradient(rgba(20, 20, 20, 0.05) 1px, transparent 1px),
      linear-gradient(90deg, rgba(20, 20, 20, 0.05) 1px, transparent 1px);
    background-size: 20px 20px;
    z-index: -1;
    pointer-events: none;
    opacity: 0.5;
  }
`;

// Fixed section wrapper to ensure centered content
const SectionWrapper = styled.div`
  width: 100%;
  display: flex;
  justify-content: center;
  position: relative;
  padding: 0 1rem;
  max-width: 1200px;
  margin: 0 auto;
  
  /* Horizontal line divider */
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(
      to right,
      transparent 0%,
      ${THEME.colors.borderPrimary} 50%,
      transparent 100%
    );
    opacity: 0.5;
  }
`;

// Enhanced section separator with improved styling
const SectionSeparator = styled.div`
  width: 100%;
  max-width: 1200px;
  margin: 2rem auto;
  height: 1px;
  background: linear-gradient(
    to right,
    transparent 0%,
    ${THEME.colors.borderPrimary} 20%,
    ${THEME.colors.accentPrimary}33 50%,
    ${THEME.colors.borderPrimary} 80%,
    transparent 100%
  );
  position: relative;
  
  &::before, &::after {
    content: "";
    position: absolute;
    top: 50%;
    transform: translateY(-50%);
    width: 8px;
    height: 8px;
    background-color: ${THEME.colors.accentPrimary};
    border-radius: 50%;
    box-shadow: 0 0 8px ${THEME.colors.accentGlow};
  }
  
  &::before {
    left: calc(50% - 40px);
  }
  
  &::after {
    right: calc(50% - 40px);
  }
`;

// Enhanced scroll button with improved styling
const ScrollButton = styled.button`
  position: fixed;
  bottom: 40px;
  right: 40px;
  background-color: ${THEME.colors.bgSecondary};
  color: ${THEME.colors.textPrimary};
  border: 2px solid ${THEME.colors.accentPrimary}66;
  width: 50px;
  height: 50px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  cursor: pointer;
  z-index: 100;
  transition: all 0.3s ${THEME.animations.curveEaseInOut};
  box-shadow: 0 0 15px rgba(0, 0, 0, 0.5), 0 0 30px ${THEME.colors.accentGlow}33;
  border-radius: 50%;
  opacity: ${props => props.visible ? 1 : 0};
  transform: translateY(${props => props.visible ? 0 : '20px'});
  pointer-events: ${props => props.visible ? 'all' : 'none'};
  
  &:hover {
    background-color: ${THEME.colors.accentPrimary};
    color: ${THEME.colors.textPrimary};
    transform: translateY(-5px);
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.7), 0 0 30px ${THEME.colors.accentGlow}66;
  }
  
  @media (max-width: 768px) {
    bottom: 20px;
    right: 20px;
    width: 40px;
    height: 40px;
    font-size: 16px;
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
  const featuresRef = useRef(null);
  const installRef = useRef(null);

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

  // Scroll to specific sections
  const scrollToSection = (ref) => {
    if (ref && ref.current) {
      ref.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <AngelaPageContainer className="angela-page">
      {/* Enhanced global styles */}
      <Global styles={angelaEnhancedStyles} />
      
      {/* Background effects */}
      <div className="noise-texture"></div>
      <div className="scanlines"></div>
      
      {/* Matrix Rain animation in the background */}
      <MatrixRain />
      
      {/* Hero Section */}
      <div style={{ width: '100%' }}>
        <HeroSection 
          ref={heroRef} 
          onExploreClick={() => scrollToSection(dialogueRef)} 
        />
      </div>
      
      <SectionSeparator />
      
      {/* Dialogue System - Properly centered */}
      <SectionWrapper>
        <div ref={dialogueRef} style={{ width: '100%', maxWidth: '1200px' }}>
          <DialogueSystem 
            dialogueData={dialogueData}
            philosophical={true}
            enableLooping={true}
            initialDepth={1}
            rightProgression={true} // Enable rightward and downward progression
            loopAfterDepth={20}
          />
        </div>
      </SectionWrapper>
      
      <SectionSeparator />
      
      {/* Features Section */}
      <SectionWrapper>
        <div ref={featuresRef} style={{ width: '100%', maxWidth: '1200px' }}>
          <FeatureSection 
            icons={{
              brain: <FaBrain />,
              cogs: <FaCogs />,
              search: <FaSearch />,
              shield: <FaShieldAlt />,
              terminal: <FaTerminal />,
              code: <FaCode />,
              globe: <FaGlobe />,
              lightbulb: <FaLightbulb />
            }} 
          />
        </div>
      </SectionWrapper>
      
      <SectionSeparator />
      
      {/* Installation Section */}
      <SectionWrapper>
        <div ref={installRef} style={{ width: '100%', maxWidth: '1200px' }}>
          <InstallSection />
        </div>
      </SectionWrapper>
      
      <SectionSeparator />
      
      {/* Footer */}
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
      
      {/* Scroll to top button */}
      <ScrollButton 
        onClick={handleScrollToTop}
        visible={showScrollButton}
        aria-label="Scroll to Top"
      >
        <FaChevronUp />
      </ScrollButton>
    </AngelaPageContainer>
  );
};

// Matrix Rain Effect Component - Enhanced with more characters and better performance
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
    
    // Expanded characters for the matrix rain
    const characters = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン¥∞§¶†‡≠±≈∫√∑∏πΣΔΩαβγδεζηθικλμνξοπρστυφχψω';
    
    // Character array setup
    const fontSize = 14;
    const columns = Math.ceil(canvas.width / fontSize);
    
    // Array of drops - one per column
    const drops = Array(columns).fill(0);
    const speeds = Array(columns).fill(0).map(() => Math.random() * 0.8 + 0.5);
    const charIndices = Array(columns).fill(0).map(() => Math.floor(Math.random() * characters.length));
    
    // Matrix rain drawing with optimizations
    const draw = () => {
      // Semi-transparent black for fade effect
      ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      for (let i = 0; i < drops.length; i++) {
        // Vary the character
        charIndices[i] = (charIndices[i] + 1) % characters.length;
        const text = characters.charAt(charIndices[i]);
        
        // Add gradient effect with more green at the head
        const headColor = drops[i] === 0 ? '#50ff50' : '#33ff33';
        const midColor = '#29cc29';
        const tailColor = '#164016';
        
        if (drops[i] > 1) {
          // Tail character
          ctx.fillStyle = tailColor;
          ctx.font = `${fontSize - 2}px monospace`;
          ctx.fillText(characters.charAt((charIndices[i] + 5) % characters.length), 
                      i * fontSize, (drops[i] - 1) * fontSize);
        }
        
        // Mid character
        if (drops[i] > 0) {
          ctx.fillStyle = midColor;
          ctx.font = `${fontSize - 1}px monospace`;
          ctx.fillText(characters.charAt((charIndices[i] + 2) % characters.length), 
                      i * fontSize, drops[i] * fontSize - fontSize);
        }
        
        // Head character (latest)
        ctx.fillStyle = headColor;
        ctx.font = `${fontSize}px monospace`;
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);
        
        // If drop reaches bottom or random chance, reset to top
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        
        // Move drops down at varying speeds
        drops[i] += speeds[i];
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

export default AngelaPage;
