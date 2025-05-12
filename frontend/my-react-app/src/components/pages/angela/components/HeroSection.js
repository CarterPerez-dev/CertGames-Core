// frontend/my-react-app/src/components/pages/angela/components/HeroSection.js
import React, { useState, useEffect, forwardRef } from 'react';
import styled from '@emotion/styled';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';
import { TypewriterText, GlitchEffect } from '../styles/AnimationStyles';
import ExpansionEffect from '../animations/ExpansionEffects';

// Container for the hero section
const HeroContainer = styled.section`
  min-height: 100vh;
  width: 100%;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  padding: 2rem;
  position: relative;
  overflow: hidden;
  
  @media (max-width: ${THEME.breakpoints.md}) {
    padding: 1rem;
  }
`;

// Logo container with animations
const LogoContainer = styled.div`
  margin-bottom: 2rem;
  position: relative;
  
  &::before {
    content: "";
    position: absolute;
    width: 140%;
    height: 140%;
    top: -20%;
    left: -20%;
    background: radial-gradient(
      circle at center,
      ${THEME.colors.accentPrimary}10 0%,
      transparent 70%
    );
    z-index: -1;
    opacity: 0.6;
  }
`;

// Angela logo with pixelated styling
const AngelaLogo = styled.div`
  font-family: ${THEME.typography.fontFamilySecondary};
  font-size: 5rem;
  font-weight: ${THEME.typography.weightBold};
  color: ${THEME.colors.textPrimary};
  text-shadow: 0 0 10px ${THEME.colors.accentGlow};
  letter-spacing: ${THEME.typography.spacingWide};
  position: relative;
  text-align: center;
  margin: 0 auto;
  
  .cli-text {
    font-size: 2.5rem;
    color: ${THEME.colors.accentPrimary};
    display: block;
    margin-top: -1rem;
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 3.5rem;
    
    .cli-text {
      font-size: 1.75rem;
    }
  }
`;

// Terminal-style text for the tagline
const Tagline = styled.div`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1.5rem;
  color: ${THEME.colors.textPrimary};
  margin: 2rem 0;
  text-align: center;
  max-width: 800px;
  padding: 0 1rem;
  position: relative;
  
  .highlight {
    color: ${THEME.colors.accentPrimary};
    font-weight: ${THEME.typography.weightMedium};
  }
  
  .terminal-text {
    font-family: ${THEME.typography.fontFamilyPrimary};
    display: inline-block;
    
    &::before {
      content: "> ";
      color: ${THEME.colors.terminalGreen};
    }
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 1.25rem;
  }
`;

// Terminal window for demonstration
const TerminalWindow = styled.div`
  width: 100%;
  max-width: 800px;
  background-color: ${THEME.colors.bgPrimary};
  border: 2px solid ${THEME.colors.borderPrimary};
  border-radius: 4px;
  overflow: hidden;
  margin: 2rem 0;
  box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3);
  
  @media (max-width: ${THEME.breakpoints.md}) {
    max-width: 90%;
  }
`;

// Terminal header with buttons
const TerminalHeader = styled.div`
  height: 36px;
  background-color: ${THEME.colors.bgSecondary};
  display: flex;
  align-items: center;
  padding: 0 12px;
  border-bottom: 1px solid ${THEME.colors.borderPrimary};
  
  .terminal-title {
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 14px;
    color: ${THEME.colors.textSecondary};
    flex-grow: 1;
    text-align: center;
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
const TerminalContent = styled.div`
  padding: 16px;
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 16px;
  line-height: 1.6;
  color: ${THEME.colors.textPrimary};
  max-height: 400px;
  overflow-y: auto;
  
  .prompt {
    color: ${THEME.colors.terminalGreen};
    margin-right: 8px;
  }
  
  .command {
    color: ${THEME.colors.textPrimary};
  }
  
  .output {
    color: ${THEME.colors.textSecondary};
    margin-top: 8px;
    margin-bottom: 16px;
  }
  
  .angela-output {
    color: ${THEME.colors.accentPrimary};
    margin-top: 8px;
    margin-bottom: 16px;
  }
  
  .cursor {
    display: inline-block;
    width: 10px;
    height: 18px;
    background-color: ${THEME.colors.textPrimary};
    margin-left: 4px;
    animation: blink 1s step-end infinite;
  }
  
  @keyframes blink {
    from, to { opacity: 1; }
    50% { opacity: 0; }
  }
`;

// Call-to-action buttons with pixel art styling
const CtaContainer = styled.div`
  display: flex;
  gap: 1.5rem;
  margin-top: 2rem;
  
  @media (max-width: ${THEME.breakpoints.sm}) {
    flex-direction: column;
    gap: 1rem;
  }
`;

// Pixelated button styles
const PixelButton = styled.button`
  border: none;
  background: transparent;
  cursor: pointer;
  position: relative;
  padding: 0;
  
  // Pixelated border
  &::before {
    content: "";
    position: absolute;
    top: -4px;
    left: -4px;
    right: -4px;
    bottom: -4px;
    background-color: ${props => props.primary ? THEME.colors.accentPrimary : THEME.colors.borderPrimary};
    z-index: -1;
    
    // Create pixelated corners
    clip-path: polygon(
      0% 4px, 4px 4px, 4px 0%, calc(100% - 4px) 0%, calc(100% - 4px) 4px, 100% 4px, 
      100% calc(100% - 4px), calc(100% - 4px) calc(100% - 4px), calc(100% - 4px) 100%, 
      4px 100%, 4px calc(100% - 4px), 0% calc(100% - 4px)
    );
  }
  
  .pixel-button-inner {
    padding: 12px 24px;
    font-family: ${THEME.typography.fontFamilySecondary};
    font-size: 18px;
    color: ${props => props.primary ? THEME.colors.textPrimary : THEME.colors.accentPrimary};
    background-color: ${props => props.primary ? THEME.colors.accentPrimary : THEME.colors.bgSecondary};
    display: inline-block;
    transition: all 0.2s ease;
    border: 2px solid ${props => props.primary ? THEME.colors.accentPrimary : THEME.colors.borderPrimary};
    text-transform: uppercase;
    letter-spacing: 1px;
    
    &:hover {
      transform: translateY(-2px);
      box-shadow: 0 3px 0 ${props => props.primary ? THEME.colors.accentSecondary : THEME.colors.borderSecondary};
    }
    
    &:active {
      transform: translateY(0);
      box-shadow: none;
    }
  }
`;

// Floating pixel art decoration elements
const PixelDecoration = styled.div`
  position: absolute;
  width: ${props => props.size || '20px'};
  height: ${props => props.size || '20px'};
  background-color: ${props => props.color || THEME.colors.accentPrimary};
  animation: float ${props => props.duration || '6s'} ease-in-out infinite;
  opacity: ${props => props.opacity || 0.6};
  box-shadow: 0 0 10px ${props => props.color || THEME.colors.accentPrimary};
  z-index: -1;
  ${THEME.effects.pixelated}
  
  @keyframes float {
    0% { transform: translateY(0) rotate(0deg); }
    50% { transform: translateY(-20px) rotate(10deg); }
    100% { transform: translateY(0) rotate(0deg); }
  }
  
  &.star::before, &.star::after {
    content: "";
    position: absolute;
    background-color: ${props => props.color || THEME.colors.accentPrimary};
    ${THEME.effects.pixelated}
  }
  
  &.star::before {
    width: 100%;
    height: 40%;
    top: 30%;
    left: 0;
  }
  
  &.star::after {
    width: 40%;
    height: 100%;
    top: 0;
    left: 30%;
  }
`;

/**
 * HeroSection Component
 * 
 * The main hero section for the Angela CLI landing page.
 * Features a logo, animated tagline, and terminal demonstration.
 */
const HeroSection = forwardRef(({ onExploreClick }, ref) => {
  const [typingStage, setTypingStage] = useState(0);
  const [showCursor, setShowCursor] = useState(true);
  
  // Demo terminal animation sequence
  useEffect(() => {
    const stages = [
      { delay: 1000, action: () => setTypingStage(1) },
      { delay: 2000, action: () => setTypingStage(2) },
      { delay: 3500, action: () => setTypingStage(3) },
      { delay: 5000, action: () => setTypingStage(4) },
      { delay: 7000, action: () => setTypingStage(5) },
      { delay: 8000, action: () => setShowCursor(false) },
      { delay: 9000, action: () => setTypingStage(6) },
      { delay: 12000, action: () => setTypingStage(7) },
      { delay: 14000, action: () => setTypingStage(0) },
    ];
    
    const timers = stages.map(stage => setTimeout(stage.action, stage.delay));
    
    return () => {
      timers.forEach(timer => clearTimeout(timer));
    };
  }, [typingStage]);
  
  return (
    <HeroContainer ref={ref}>
      {/* Decorative pixel elements */}
      <PixelDecoration 
        className="star"
        size="16px" 
        color={THEME.colors.accentPrimary} 
        style={{ top: '20%', left: '15%' }}
        duration="7s"
      />
      <PixelDecoration 
        size="12px" 
        color={THEME.colors.terminalGreen} 
        style={{ top: '25%', right: '20%' }}
        duration="9s"
      />
      <PixelDecoration 
        size="8px" 
        color={THEME.colors.textPrimary} 
        style={{ bottom: '30%', left: '10%' }}
        duration="5s"
        opacity={0.4}
      />
      <PixelDecoration 
        className="star"
        size="10px" 
        color={THEME.colors.terminalCyan} 
        style={{ bottom: '25%', right: '15%' }}
        duration="8s"
      />
      
      {/* Logo */}
      <LogoContainer>
        <AngelaLogo data-text="ANGELA">
          <GlitchEffect data-text="ANGELA">ANGELA</GlitchEffect>
          <span className="cli-text">CLI</span>
        </AngelaLogo>
      </LogoContainer>
      
      {/* Tagline */}
      <Tagline>
        <ExpansionEffect type="pulse" active={true} speed="normal">
          <div className="terminal-text">
            Worlds First <span className="highlight">AGI Command Line Intelligence</span>
          </div>
        </ExpansionEffect>
      </Tagline>
      
      {/* Terminal window demonstration */}
      <TerminalWindow>
        <TerminalHeader>
          <div className="buttons">
            <div className="button red"></div>
            <div className="button yellow"></div>
            <div className="button green"></div>
          </div>
          <div className="terminal-title">angela-cli ~ bash</div>
        </TerminalHeader>
        <TerminalContent>
          {/* Command 1 */}
          <div>
            <span className="prompt">$</span>
            <span className="command"> angela "create a React component for user authentication with OAuth support"</span>
          </div>
          
          {typingStage >= 1 && (
            <div className="angela-output">
              I'll help you create a React authentication component with OAuth support. Let me break this down:
            </div>
          )}
          
          {typingStage >= 2 && (
            <div className="output">
              ✓ Analyzing project structure<br />
              ✓ Detecting dependencies: react-router-dom, axios<br />
              ✓ Planning component architecture
            </div>
          )}
          
          {typingStage >= 3 && (
            <div className="angela-output">
              Creating AuthComponent.jsx with OAuth providers, access token management, and protected route wrapper...
            </div>
          )}
          
          {typingStage >= 4 && (
            <div className="output">
              ✓ Generated AuthComponent.jsx<br />
              ✓ Generated useAuth.js hook<br />
              ✓ Generated ProtectedRoute.jsx<br />
              ✓ Updated App.js with auth routes
            </div>
          )}
          
          {typingStage >= 5 && (
            <div className="angela-output">
              Authentication system successfully created with Google, GitHub, and email providers.
              Would you like me to explain how it works or make any modifications?
            </div>
          )}
          
          {/* Command 2 - only shown after full demo of first command */}
          {typingStage >= 6 && (
            <>
              <div>
                <span className="prompt">$</span>
                <span className="command"> angela "deploy this app to Vercel and set up CI/CD"</span>
              </div>
              
              <div className="angela-output">
                Planning deployment to Vercel with continuous integration pipeline...
              </div>
            </>
          )}
          
          {typingStage >= 7 && (
            <div className="output">
              ✓ Generated vercel.json configuration<br />
              ✓ Set up GitHub Actions workflow for CI/CD<br />
              ✓ Created deployment script with environment variable handling<br />
              ✓ Deployment successful: https://your-app.vercel.app
            </div>
          )}
          
          {showCursor && <span className="cursor"></span>}
        </TerminalContent>
      </TerminalWindow>
      
      {/* Call to action buttons */}
      <CtaContainer>
        <PixelButton primary onClick={onExploreClick}>
          <div className="pixel-button-inner">Explore</div>
        </PixelButton>
        <PixelButton onClick={() => window.open('https://github.com/CarterPerez-dev/angela-cli', '_blank')}>
          <div className="pixel-button-inner">GitHub</div>
        </PixelButton>
      </CtaContainer>
    </HeroContainer>
  );
});

export default HeroSection;
