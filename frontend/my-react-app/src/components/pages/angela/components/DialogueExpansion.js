// frontend/my-react-app/src/components/pages/angela/components/DialogueExpansion.js
import React, { useState, useEffect, useRef, useCallback } from 'react';
import styled from '@emotion/styled';
import { keyframes } from '@emotion/react';
import { css } from '@emotion/react';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

// Keyframe animations for various expansion effects
const expandAnimation = keyframes`
  from {
    max-height: 0;
    opacity: 0;
    transform: scale(0.97) translateY(-10px);
  }
  to {
    max-height: 2000px;
    opacity: 1;
    transform: scale(1) translateY(0);
  }
`;

const collapseAnimation = keyframes`
  from {
    max-height: 2000px;
    opacity: 1;
    transform: scale(1) translateY(0);
  }
  to {
    max-height: 0;
    opacity: 0;
    transform: scale(0.97) translateY(-10px);
  }
`;

const glitchAnimation = keyframes`
  0% {
    clip-path: inset(40% 0 61% 0);
    transform: translate(-2px, 2px);
  }
  20% {
    clip-path: inset(92% 0 1% 0);
    transform: translate(1px, -3px);
  }
  40% {
    clip-path: inset(43% 0 1% 0);
    transform: translate(-1px, 3px);
  }
  60% {
    clip-path: inset(25% 0 58% 0);
    transform: translate(3px, 1px);
  }
  80% {
    clip-path: inset(54% 0 7% 0);
    transform: translate(-3px, -2px);
  }
  100% {
    clip-path: inset(58% 0 43% 0);
    transform: translate(2px, 2px);
  }
`;

const pulseAnimation = keyframes`
  0% {
    transform: scale(0.97);
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0.2);
  }
  70% {
    transform: scale(1.01);
    box-shadow: 0 0 0 10px rgba(255, 51, 51, 0);
  }
  100% {
    transform: scale(1);
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0);
  }
`;

const voidAnimation = keyframes`
  0% {
    filter: brightness(0.7) contrast(1.2);
    box-shadow: inset 0 0 30px rgba(0, 0, 0, 0.8);
  }
  50% {
    filter: brightness(1.1) contrast(0.9);
    box-shadow: inset 0 0 20px rgba(0, 0, 0, 0.4);
  }
  100% {
    filter: brightness(0.7) contrast(1.2);
    box-shadow: inset 0 0 30px rgba(0, 0, 0, 0.8);
  }
`;

const paradoxAnimation = keyframes`
  0% {
    opacity: 1;
    filter: hue-rotate(0deg);
  }
  50% {
    opacity: 0.8;
    filter: hue-rotate(180deg);
  }
  100% {
    opacity: 1;
    filter: hue-rotate(360deg);
  }
`;

const particleFloat = keyframes`
  0% {
    transform: translateY(0) translateX(0) rotate(0deg);
    opacity: 0.1;
  }
  25% {
    opacity: 0.6;
  }
  75% {
    opacity: 0.3;
  }
  100% {
    transform: translateY(-30px) translateX(20px) rotate(20deg);
    opacity: 0;
  }
`;

// Enhanced styled components for expansion effects
const ExpansionContainer = styled.div`
  position: relative;
  overflow: hidden;
  max-height: ${props => props.isExpanded ? '2000px' : '0'};
  opacity: ${props => props.isExpanded ? '1' : '0'};
  transform-origin: top;
  will-change: max-height, opacity, transform; /* Performance optimization */
  
  /* Animation based on the expansion state */
  animation: ${props => props.isExpanded 
    ? css`${expandAnimation} ${props.duration || '0.5s'} ${props.curve || THEME.animations.curvePhilosophical} forwards`
    : css`${collapseAnimation} ${props.duration || '0.5s'} ${props.curve || THEME.animations.curvePhilosophical} forwards`
  };
  
  /* Avoid animating on first render */
  ${props => !props.hasAnimated && `
    animation: none !important;
  `}
  
  /* Special styling for looping nodes */
  ${props => props.isLoop && `
    &::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: linear-gradient(to bottom, 
        ${THEME.colors.bgPrimary}00 0%,
        ${THEME.colors.accentPrimary}10 50%,
        ${THEME.colors.bgPrimary}00 100%
      );
      z-index: -1;
      pointer-events: none;
      animation: ${paradoxAnimation} 8s infinite linear;
    }
  `}
  
  /* Progressive transformation based on depth */
  transform: ${props => props.depth > 0 ? 
    `translateX(${props.depth * 15}px) translateY(${props.depth * 8}px) rotate(${props.depth * 0.3}deg)` : 
    'none'
  };
  transition: transform 0.5s ${THEME.animations.curvePhilosophical};
`;

const ExpansionInner = styled.div`
  position: relative;
`;

const EffectOverlay = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  z-index: 1;
  opacity: ${props => props.intensity || 0.2};
  
  /* Apply different effects */
  ${props => props.effect === 'glitch' && `
    &::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-color: ${THEME.colors.accentPrimary}20;
      mix-blend-mode: difference;
      animation: ${glitchAnimation} 2s infinite linear;
    }
    
    &::after {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-color: ${THEME.colors.terminalGreen}20;
      mix-blend-mode: difference;
      animation: ${glitchAnimation} 2s infinite linear reverse;
      animation-delay: 0.2s;
    }
  `}
  
  ${props => props.effect === 'pulse' && `
    animation: ${pulseAnimation} 3s infinite ease-in-out;
  `}
  
  ${props => props.effect === 'void' && `
    animation: ${voidAnimation} 5s infinite ease-in-out;
    background: radial-gradient(
      circle at center,
      rgba(0, 0, 0, 0.7) 0%,
      rgba(0, 0, 0, 0) 70%
    );
  `}
  
  ${props => props.effect === 'paradox' && `
    animation: ${paradoxAnimation} 8s infinite linear;
    background: conic-gradient(
      from 0deg at 50% 50%,
      ${THEME.colors.bgPrimary} 0%,
      ${THEME.colors.accentPrimary}20 10%,
      ${THEME.colors.bgPrimary} 20%,
      ${THEME.colors.accentPrimary}20 30%,
      ${THEME.colors.bgPrimary} 40%,
      ${THEME.colors.accentPrimary}20 50%,
      ${THEME.colors.bgPrimary} 60%,
      ${THEME.colors.accentPrimary}20 70%,
      ${THEME.colors.bgPrimary} 80%,
      ${THEME.colors.accentPrimary}20 90%,
      ${THEME.colors.bgPrimary} 100%
    );
  `}
`;

const ThoughtParticle = styled.div`
  position: absolute;
  width: ${props => props.size || '8px'};
  height: ${props => props.size || '8px'};
  background-color: ${props => props.color || 'rgba(255, 255, 255, 0.1)'};
  border-radius: 50%;
  pointer-events: none;
  animation: ${particleFloat} ${props => props.duration || '5s'} ease-in-out;
  animation-delay: ${props => props.delay || '0s'};
  top: ${props => props.top || '50%'};
  left: ${props => props.left || '50%'};
  opacity: ${props => props.opacity || 0.3};
`;

/**
 * DialogueExpansion Component
 * 
 * Enhanced component that handles the expansion and collapse animations for dialogue content
 * with advanced transition effects and particle effects.
 * 
 * @param {boolean} isExpanded - Whether the content is expanded
 * @param {string} effect - The effect type to use (pulse, glitch, void, paradox)
 * @param {boolean} isLoop - Whether this expansion is part of a looping dialogue chain
 * @param {number} depth - The nesting depth of this expansion (for styling)
 * @param {boolean} showParticles - Whether to show thought particles 
 * @param {number} intensity - Intensity of the effect (0-1)
 * @param {string} duration - Animation duration
 * @param {function} onComplete - Callback for when animation completes
 * @param {React.ReactNode} children - The content to expand/collapse
 */
const DialogueExpansion = ({ 
  isExpanded = false,
  effect = 'pulse',
  isLoop = false,
  depth = 0,
  showParticles = true,
  intensity = 0.2,
  duration = '0.5s',
  onComplete = null,
  children
}) => {
  const [hasAnimated, setHasAnimated] = useState(false);
  const [particles, setParticles] = useState([]);
  const [isAnimating, setIsAnimating] = useState(false);
  const containerRef = useRef(null);
  
  // Generate particles on expansion
  useEffect(() => {
    if (isExpanded && showParticles) {
      // Generate random particles
      const newParticles = Array(10).fill().map((_, i) => ({
        id: `particle-${i}`,
        size: `${Math.random() * 6 + 4}px`,
        top: `${Math.random() * 100}%`,
        left: `${Math.random() * 100}%`,
        delay: `${Math.random() * 2}s`,
        duration: `${Math.random() * 3 + 3}s`,
        opacity: Math.random() * 0.3 + 0.1,
        color: Math.random() > 0.7 
          ? `${THEME.colors.accentPrimary}${Math.floor(Math.random() * 50 + 10)}`
          : `rgba(255, 255, 255, ${Math.random() * 0.15 + 0.05})`
      }));
      
      setParticles(newParticles);
    } else {
      setParticles([]);
    }
  }, [isExpanded, showParticles]);
  
  // Handle animation state
  useEffect(() => {
    if (isExpanded !== isAnimating) {
      setIsAnimating(isExpanded);
      
      // Mark as animated after first expansion
      if (isExpanded && !hasAnimated) {
        setHasAnimated(true);
      }
      
      // Call onComplete callback after animation
      if (onComplete) {
        const timer = setTimeout(() => {
          onComplete(isExpanded);
        }, parseFloat(duration) * 1000);
        
        return () => clearTimeout(timer);
      }
    }
  }, [isExpanded, isAnimating, hasAnimated, duration, onComplete]);
  
  // Determine which effect to use
  let effectType = effect;
  
  if (isLoop) {
    effectType = 'paradox'; // Override with paradox effect for loop nodes
  } else if (depth > 10) {
    effectType = 'void'; // Use void effect for deep nodes
  }
  
  // Determine animation duration based on depth
  const animationDuration = `${0.3 + Math.min(depth * 0.1, 0.7)}s`;
  
  // Determine animation curve based on effect
  const animationCurve = 
    effectType === 'glitch' ? THEME.animations.curveGlitch :
    effectType === 'paradox' ? THEME.animations.curvePhilosophical :
    THEME.animations.curveEaseInOut;
  
  return (
    <ExpansionContainer 
      ref={containerRef}
      isExpanded={isExpanded}
      hasAnimated={hasAnimated}
      isLoop={isLoop}
      depth={depth}
      duration={animationDuration}
      curve={animationCurve}
      className={`dialogue-expansion ${isExpanded ? 'expanded' : 'collapsed'} ${effectType}-effect depth-${depth} ${isLoop ? 'loop-node' : ''}`}
    >
      <ExpansionInner>
        {/* Thought particles */}
        {showParticles && isExpanded && particles.map(particle => (
          <ThoughtParticle
            key={particle.id}
            size={particle.size}
            top={particle.top}
            left={particle.left}
            delay={particle.delay}
            duration={particle.duration}
            opacity={particle.opacity}
            color={particle.color}
          />
        ))}
        
        {/* Effect overlay */}
        <EffectOverlay 
          effect={effectType}
          intensity={intensity}
          className={`effect-overlay ${effectType}-overlay`}
        />
        
        {/* Content */}
        <div className="expansion-content">
          {children}
        </div>
      </ExpansionInner>
    </ExpansionContainer>
  );
};

export default DialogueExpansion;
