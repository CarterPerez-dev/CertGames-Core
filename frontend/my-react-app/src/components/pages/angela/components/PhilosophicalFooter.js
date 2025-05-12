// frontend/my-react-app/src/components/pages/angela/components/PhilosophicalFooter.js
import React, { useState, useEffect } from 'react';
import styled from '@emotion/styled';
import { keyframes } from '@emotion/react';
import { 
  FaGithub, 
  FaBook, 
  FaExclamationCircle, 
  FaDiscord, 
  FaCode 
} from 'react-icons/fa';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';
import { getRandomQuoteForConcept } from '../utils/philosophicalQuotes';
import { detectPotentialLoop, generateParadoxInsight } from '../utils/paradoxGenerator';
import ParadoxTransition from '../animations/ParadoxTransitions';

// Pulse animation for subtle focus
const pulseAnimation = keyframes`
  0% {
    opacity: 0.8;
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0.2);
  }
  70% {
    opacity: 1;
    box-shadow: 0 0 0 10px rgba(255, 51, 51, 0);
  }
  100% {
    opacity: 0.8;
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0);
  }
`;

// Text reveal animation for quotes
const revealText = keyframes`
  0% {
    opacity: 0;
    transform: translateY(10px);
  }
  100% {
    opacity: 1;
    transform: translateY(0);
  }
`;

// Grid animation for background texture
const gridAnimation = keyframes`
  0% {
    background-position: 0px 0px;
    opacity: 0.05;
  }
  50% {
    opacity: 0.1;
  }
  100% {
    background-position: 20px 20px;
    opacity: 0.05;
  }
`;

// Main container for the philosophical footer
const FooterContainer = styled.footer`
  width: 100%;
  padding: 5rem 2rem 6rem;
  position: relative;
  overflow: hidden;
  display: flex;
  justify-content: center;
  background-color: ${THEME.colors.bgPrimary};
  
  /* Top border with gradient */
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(
      to right,
      transparent,
      ${THEME.colors.borderPrimary},
      transparent
    );
  }
  
  /* Animated grid background */
  &::after {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-image: 
      linear-gradient(rgba(51, 51, 51, 0.1) 1px, transparent 1px),
      linear-gradient(90deg, rgba(51, 51, 51, 0.1) 1px, transparent 1px);
    background-size: 20px 20px;
    z-index: -1;
    animation: ${gridAnimation} 20s linear infinite;
    opacity: 0.05;
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    padding: 3rem 1rem 5rem;
  }
`;

// Inner container to maintain max-width
const FooterInner = styled.div`
  max-width: 1200px;
  width: 100%;
`;

// Philosophical content container
const PhilosophicalContent = styled.div`
  max-width: 800px;
  margin: 0 auto;
  text-align: center;
  position: relative;
  
  /* Large quote mark */
  &::before {
    content: """;
    position: absolute;
    top: -4rem;
    left: 50%;
    transform: translateX(-50%);
    font-size: 8rem;
    color: ${THEME.colors.accentPrimary}20;
    font-family: ${THEME.typography.fontFamilyPhilosophical};
    z-index: -1;
    line-height: 1;
  }
`;

// Philosophical quote text with enhanced animation
const PhilosophicalText = styled.div`
  font-family: ${THEME.typography.fontFamilyPhilosophical};
  font-style: italic;
  font-size: 1.5rem;
  color: ${THEME.colors.textPrimary};
  margin-bottom: 1.5rem;
  line-height: 1.6;
  animation: ${revealText} 1s ${THEME.animations.curvePhilosophical} forwards;
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 1.25rem;
  }
`;

// Attribution for the quote
const Attribution = styled.div`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1rem;
  color: ${THEME.colors.textSecondary};
  margin-bottom: 3rem;
  
  &::before {
    content: "— ";
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 0.9rem;
  }
`;

// Links grid for bottom navigation
const LinkGrid = styled.div`
  display: flex;
  justify-content: center;
  flex-wrap: wrap;
  gap: 2rem;
  margin-top: 3rem;
  position: relative;
  
  /* Separator line above links */
  &::before {
    content: "";
    position: absolute;
    top: -1.5rem;
    left: 50%;
    transform: translateX(-50%);
    width: 50px;
    height: 1px;
    background-color: ${THEME.colors.borderPrimary};
  }
  
  @media (max-width: ${THEME.breakpoints.sm}) {
    gap: 1.5rem;
    flex-direction: column;
    align-items: center;
  }
`;

// Individual footer link with 8-bit styling
const FooterLink = styled.a`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 0.9rem;
  color: ${THEME.colors.textSecondary};
  text-decoration: none;
  position: relative;
  transition: all 0.2s ease;
  padding: 0.5rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  
  &:hover {
    color: ${THEME.colors.accentPrimary};
  }
  
  /* Animated underline effect */
  &::after {
    content: "";
    position: absolute;
    bottom: 0;
    left: 0;
    width: 0;
    height: 2px;
    background-color: ${THEME.colors.accentPrimary};
    transition: width 0.2s ease;
  }
  
  &:hover::after {
    width: 100%;
  }
  
  /* Icon styling */
  svg {
    font-size: 1.1rem;
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 0.8rem;
  }
`;

// Pixelated corner decoration
const PixelCorner = styled.div`
  position: absolute;
  width: 40px;
  height: 40px;
  z-index: 1;
  pointer-events: none;
  
  ${({ position }) => {
    if (position === 'top-left') {
      return `
        top: 40px;
        left: 40px;
        border-top: 4px solid ${THEME.colors.accentPrimary};
        border-left: 4px solid ${THEME.colors.accentPrimary};
      `;
    } else if (position === 'top-right') {
      return `
        top: 40px;
        right: 40px;
        border-top: 4px solid ${THEME.colors.accentPrimary};
        border-right: 4px solid ${THEME.colors.accentPrimary};
      `;
    } else if (position === 'bottom-left') {
      return `
        bottom: 40px;
        left: 40px;
        border-bottom: 4px solid ${THEME.colors.accentPrimary};
        border-left: 4px solid ${THEME.colors.accentPrimary};
      `;
    } else if (position === 'bottom-right') {
      return `
        bottom: 40px;
        right: 40px;
        border-bottom: 4px solid ${THEME.colors.accentPrimary};
        border-right: 4px solid ${THEME.colors.accentPrimary};
      `;
    }
  }}
  
  @media (max-width: ${THEME.breakpoints.md}) {
    width: 30px;
    height: 30px;
  }
  
  @media (max-width: ${THEME.breakpoints.sm}) {
    width: 20px;
    height: 20px;
  }
`;

// Copyright text with terminal styling
const CopyrightText = styled.div`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 0.8rem;
  color: ${THEME.colors.textTertiary};
  text-align: center;
  margin-top: 4rem;
  
  .terminal-text {
    font-family: ${THEME.typography.fontFamilyPrimary};
    display: inline-block;
    
    &::before {
      content: "> ";
      color: ${THEME.colors.terminalGreen};
    }
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 0.75rem;
  }
`;

// Recursive pattern decoration
const RecursivePattern = styled.div`
  position: absolute;
  bottom: 20px;
  left: 50%;
  transform: translateX(-50%);
  width: 80%;
  height: 2px;
  background: repeating-linear-gradient(
    to right,
    ${THEME.colors.borderPrimary} 0%,
    ${THEME.colors.borderPrimary} 10px,
    transparent 10px,
    transparent 20px
  );
  z-index: 1;
  opacity: 0.5;
`;

// Paradox insight display with animation
const ParadoxInsight = styled.div`
  font-family: ${THEME.typography.fontFamilyPhilosophical};
  font-style: italic;
  font-size: 1rem;
  color: ${THEME.colors.textSecondary};
  margin-top: 2rem;
  text-align: center;
  opacity: ${props => props.active ? 1 : 0};
  transform: translateY(${props => props.active ? 0 : '20px'});
  transition: all 0.5s ${THEME.animations.curvePhilosophical};
  max-width: 600px;
  margin-left: auto;
  margin-right: auto;
  animation: ${pulseAnimation} 6s infinite;
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 0.9rem;
  }
`;

/**
 * PhilosophicalFooter Component
 * 
 * The footer section for the Angela CLI landing page with philosophical quotes
 * and paradoxical insights that change over time.
 */
const PhilosophicalFooter = () => {
  // State for cycling philosophical content
  const [paradoxQuote, setParadoxQuote] = useState(getRandomQuoteForConcept(THEME.philosophicalConcepts.PARADOX));
  const [insight, setInsight] = useState(generateParadoxInsight());
  const [showInsight, setShowInsight] = useState(false);
  const [loopState, setLoopState] = useState(false);
  
  // Cycle through philosophical content
  useEffect(() => {
    const quoteTimer = setInterval(() => {
      // Change the paradox quote
      setParadoxQuote(getRandomQuoteForConcept(THEME.philosophicalConcepts.PARADOX));
    }, 10000);
    
    const insightTimer = setInterval(() => {
      // Show/hide the paradox insight
      setShowInsight(prev => !prev);
      
      // Generate a new insight when hiding
      if (showInsight) {
        setInsight(generateParadoxInsight());
      }
    }, 5000);
    
    const loopTimer = setInterval(() => {
      // Simulate potential loop detection
      setLoopState(detectPotentialLoop({ dummy: true }, new Set([1, 2, 3])));
    }, 15000);
    
    return () => {
      clearInterval(quoteTimer);
      clearInterval(insightTimer);
      clearInterval(loopTimer);
    };
  }, [showInsight]);
  
  return (
    <FooterContainer>
      <FooterInner>
        {/* Decorative pixel corners */}
        <PixelCorner position="top-left" />
        <PixelCorner position="top-right" />
        <PixelCorner position="bottom-left" />
        <PixelCorner position="bottom-right" />
        
        {/* Main philosophical content */}
        <PhilosophicalContent>
          <ParadoxTransition type={loopState ? 'paradox' : 'glitch'} isActive={true} intensity={0.3}>
            <PhilosophicalText>
              "{paradoxQuote.text}"
            </PhilosophicalText>
            <Attribution>{paradoxQuote.author}</Attribution>
          </ParadoxTransition>
          
          <ParadoxInsight active={showInsight}>
            {insight}
          </ParadoxInsight>
          
          {/* Links grid with React icons */}
          <LinkGrid>
            <FooterLink href="https://github.com/CarterPerez-dev/angela-cli" target="_blank" rel="noopener noreferrer">
              <FaGithub /> GitHub
            </FooterLink>
            <FooterLink href="https://github.com/CarterPerez-dev/angela-cli/issues" target="_blank" rel="noopener noreferrer">
              <FaExclamationCircle /> Report an Issue
            </FooterLink>
            <FooterLink href="https://github.com/CarterPerez-dev/angela-cli/wiki" target="_blank" rel="noopener noreferrer">
              <FaBook /> Documentation
            </FooterLink>
            <FooterLink href="https://discord.gg/angela-cli" target="_blank" rel="noopener noreferrer">
              <FaDiscord /> Community
            </FooterLink>
            <FooterLink href="https://docs.angela-cli.dev" target="_blank" rel="noopener noreferrer">
              <FaCode /> API Reference
            </FooterLink>
          </LinkGrid>
          
          {/* Copyright info */}
          <CopyrightText>
            <div className="terminal-text">
              © {new Date().getFullYear()} Angela CLI Team. All rights reserved. MIT License.
            </div>
          </CopyrightText>
        </PhilosophicalContent>
        
        {/* Decorative recursive pattern */}
        <RecursivePattern />
      </FooterInner>
    </FooterContainer>
  );
};

export default PhilosophicalFooter;
