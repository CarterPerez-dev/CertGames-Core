// frontend/my-react-app/src/components/pages/angela/AngelaPage.js
import React, { useState, useEffect, useRef } from 'react';
import { Global, css } from '@emotion/react';
import styled from '@emotion/styled';
import HeroSection from './components/HeroSection';
import FeatureSection from './components/FeatureSection';
import InstallSection from './components/InstallSection';
import DialogueSystem from './components/DialogueSystem';
import PhilosophicalFooter from './components/PhilosophicalFooter';
import ThoughtFlowAnimation from './animations/ThoughtFlowAnimations';
import { dialogueData } from './utils/dialogueData';
import { angelaGlobalStyles } from './styles/AngelaStyles';
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

// Main page container
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

// Scanline effect overlay
const ScanlineOverlay = styled.div`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  z-index: 1000;
  opacity: 0.15;
  background: linear-gradient(
    to bottom,
    transparent 0%,
    rgba(32, 32, 32, 0.15) 50%,
    transparent 100%
  );
  background-size: 100% 4px;
  animation: scanline-move 10s linear infinite;
  
  @keyframes scanline-move {
    from { background-position: 0 0; }
    to { background-position: 0 100vh; }
  }
`;

// Glitch effect for transitions
const GlitchOverlay = styled.div`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  z-index: 1001;
  opacity: ${props => props.active ? 0.5 : 0};
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3CfeColorMatrix type='matrix' values='1 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 0.5 0'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E");
  mix-blend-mode: overlay;
  transition: opacity 0.3s ease-in-out;
`;

// Section separator with pixel art styling
const SectionSeparator = styled.div`
  width: 100%;
  margin: 4rem 0;
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
    ${THEME.effects.pixelated}
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

// Navigation button with retro styling
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
  ${THEME.effects.pixelated}
  
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
 * Integrates all sections and provides global styling and effects.
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
      {/* Global styles */}
      <Global styles={angelaGlobalStyles} />
      
      {/* Background effects */}
      <MatrixRain />
      <ScanlineOverlay />
      <GlitchOverlay active={glitchActive} />
      
      {/* Main content */}
      <HeroSection ref={heroRef} onExploreClick={scrollToDialogue} />
      
      <SectionSeparator />
      
      <div ref={dialogueRef}>
        <DialogueSystem 
          dialogueData={dialogueData}
          philosophical={true}
          enableLooping={true}
          initialDepth={1}
        />
      </div>
      
      <SectionSeparator />
      
      <FeatureSection />
      
      <SectionSeparator />
      
      <InstallSection />
      
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
