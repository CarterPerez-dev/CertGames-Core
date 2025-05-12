// frontend/my-react-app/src/components/pages/angela/animations/ExpansionEffects.js
import React, { useState, useEffect, useRef } from 'react';
import styled from '@emotion/styled';
import { keyframes } from '@emotion/react';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

// Keyframe animations for various expansion effects
const pulseExpandAnimation = keyframes`
  0% {
    transform: scale(0.95);
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0.2);
    opacity: 0;
  }
  50% {
    transform: scale(1.02);
    box-shadow: 0 0 0 10px rgba(255, 51, 51, 0);
    opacity: 1;
  }
  100% {
    transform: scale(1);
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0);
    opacity: 1;
  }
`;

const glitchExpandAnimation = keyframes`
  0% {
    transform: translate(0) scale(0.98);
    clip-path: inset(50% 0 50% 0);
    filter: contrast(50%) brightness(50%);
  }
  10% {
    clip-path: inset(10% 0 70% 0);
    filter: contrast(100%) brightness(120%);
  }
  20% {
    transform: translate(-5px, 5px) scale(1.01);
    clip-path: inset(30% 0 40% 0);
  }
  30% {
    clip-path: inset(50% 0 30% 0);
    filter: contrast(80%) brightness(90%);
  }
  40% {
    transform: translate(5px, -5px) scale(0.99);
    clip-path: inset(10% 0 50% 0);
  }
  50% {
    clip-path: inset(40% 0 30% 0);
    filter: contrast(100%) brightness(100%);
  }
  60% {
    transform: translate(-3px, 2px) scale(1);
  }
  70% {
    clip-path: inset(0% 0 0% 0);
  }
  100% {
    transform: translate(0) scale(1);
    clip-path: inset(0% 0 0% 0);
    filter: contrast(100%) brightness(100%);
  }
`;

const lightStreakAnimation = keyframes`
  0% {
    transform: translateX(-100%) rotate(35deg);
    opacity: 0;
  }
  10% {
    opacity: 0.8;
  }
  60% {
    opacity: 0.8;
  }
  100% {
    transform: translateX(100%) rotate(35deg);
    opacity: 0;
  }
`;

const voidExpandAnimation = keyframes`
  0% {
    transform: scale(0.5);
    opacity: 0;
    box-shadow: inset 0 0 25px 5px rgba(0, 0, 0, 0.9);
  }
  60% {
    transform: scale(1.03);
    opacity: 1;
  }
  100% {
    transform: scale(1);
    opacity: 1;
    box-shadow: inset 0 0 0 0 rgba(0, 0, 0, 0);
  }
`;

const circularRevealAnimation = keyframes`
  0% {
    clip-path: circle(0% at 50% 50%);
    opacity: 0.2;
  }
  100% {
    clip-path: circle(75% at 50% 50%);
    opacity: 1;
  }
`;

// Styled components for the expansion effects
const ExpansionEffectContainer = styled.div`
  position: relative;
  overflow: hidden;
  width: 100%;
  opacity: ${props => props.active ? 1 : 0};
  max-height: ${props => props.active ? '2000px' : '0'};
  transition: 
    max-height ${props => props.speed === 'fast' ? '0.5s' : '0.8s'} ${THEME.animations.curvePhilosophical},
    opacity ${props => props.speed === 'fast' ? '0.3s' : '0.6s'} ${THEME.animations.curveEaseInOut};
`;

const PulseExpansion = styled.div`
  position: relative;
  animation: ${pulseExpandAnimation} ${props => props.duration || '0.8s'} ${THEME.animations.curvePhilosophical} forwards;
`;

const GlitchExpansion = styled.div`
  position: relative;
  animation: ${glitchExpandAnimation} ${props => props.duration || '0.6s'} linear forwards;
  
  &::before, &::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    opacity: 0.1;
    pointer-events: none;
  }
  
  &::before {
    background: repeating-linear-gradient(
      to bottom,
      transparent,
      transparent 1px,
      ${THEME.colors.accentPrimary}30 1px,
      ${THEME.colors.accentPrimary}30 2px
    );
    background-size: 100% 4px;
    z-index: 1;
    animation: ${glitchExpandAnimation} 0.8s linear forwards reverse;
    animation-delay: 0.1s;
  }
  
  &::after {
    background: linear-gradient(
      90deg,
      ${THEME.colors.accentPrimary}20,
      transparent 10%,
      transparent 90%,
      ${THEME.colors.accentPrimary}20
    );
    z-index: 2;
  }
`;

const VoidExpansion = styled.div`
  position: relative;
  animation: ${voidExpandAnimation} ${props => props.duration || '1s'} ${THEME.animations.curvePhilosophical} forwards;
  
  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(
      circle at center,
      ${THEME.colors.bgSecondary} 0%,
      ${THEME.colors.bgPrimary} 70%,
      ${THEME.colors.voidBlack} 100%
    );
    opacity: 0.2;
    pointer-events: none;
    z-index: -1;
  }
`;

const CircularReveal = styled.div`
  position: relative;
  animation: ${circularRevealAnimation} ${props => props.duration || '0.7s'} ${THEME.animations.curvePhilosophical} forwards;
`;

const LightStreak = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  width: 300%;
  height: 100%;
  background: linear-gradient(
    90deg,
    transparent,
    ${props => props.color || 'rgba(255, 255, 255, 0.2)'},
    transparent
  );
  transform: translateX(-100%) rotate(35deg);
  animation: ${lightStreakAnimation} ${props => props.duration || '0.8s'} ease-out forwards;
  animation-delay: ${props => props.delay || '0.2s'};
  pointer-events: none;
  z-index: 2;
`;

/**
 * ExpansionEffect Component
 * 
 * Creates various animations for expanding dialogue content with
 * different philosophical themes
 * 
 * @param {string} type - Effect type ('pulse', 'glitch', 'void', 'circular', 'enlightenment')
 * @param {boolean} active - Whether the effect is active
 * @param {string} speed - Animation speed ('fast', 'normal', 'slow')
 * @param {function} onAnimationComplete - Callback when animation completes
 * @param {React.ReactNode} children - Content to apply the effect to
 */
const ExpansionEffect = ({
  type = 'pulse',
  active = true,
  speed = 'normal',
  onAnimationComplete = null,
  children
}) => {
  const [hasAnimated, setHasAnimated] = useState(false);
  const contentRef = useRef(null);
  
  // Handle animation completion
  useEffect(() => {
    if (active && !hasAnimated) {
      const timer = setTimeout(() => {
        setHasAnimated(true);
        if (onAnimationComplete) {
          onAnimationComplete();
        }
      }, getDuration());
      
      return () => clearTimeout(timer);
    }
    
    // Reset when deactivated
    if (!active) {
      setHasAnimated(false);
    }
  }, [active, hasAnimated, onAnimationComplete]);
  
  // Determine animation duration based on speed
  const getDuration = () => {
    if (speed === 'fast') return 600;
    if (speed === 'slow') return 1200;
    return 800;
  };
  
  // Get appropriate duration string for CSS animation
  const getDurationString = () => {
    if (speed === 'fast') return '0.6s';
    if (speed === 'slow') return '1.2s';
    return '0.8s';
  };
  
  // Render the appropriate effect based on type
  const renderContent = () => {
    switch (type) {
      case 'glitch':
        return (
          <GlitchExpansion duration={getDurationString()} ref={contentRef}>
            {children}
          </GlitchExpansion>
        );
      
      case 'void':
        return (
          <VoidExpansion duration={getDurationString()} ref={contentRef}>
            {children}
          </VoidExpansion>
        );
      
      case 'circular':
        return (
          <CircularReveal duration={getDurationString()} ref={contentRef}>
            {children}
          </CircularReveal>
        );
      
      case 'enlightenment':
        return (
          <PulseExpansion duration={getDurationString()} ref={contentRef}>
            <LightStreak color="rgba(255, 255, 255, 0.3)" duration="1.2s" delay="0.1s" />
            <LightStreak color={`${THEME.colors.terminalGreen}30`} duration="1s" delay="0.3s" />
            {children}
          </PulseExpansion>
        );
        
      case 'paradox':
        return (
          <GlitchExpansion duration={getDurationString()} ref={contentRef}>
            <LightStreak color={`${THEME.colors.accentPrimary}40`} duration="0.9s" delay="0.1s" />
            {children}
          </GlitchExpansion>
        );
      
      case 'pulse':
      default:
        return (
          <PulseExpansion duration={getDurationString()} ref={contentRef}>
            {children}
          </PulseExpansion>
        );
    }
  };
  
  return (
    <ExpansionEffectContainer 
      active={active} 
      speed={speed}
      className={`expansion-effect type-${type} ${active ? 'active' : ''} ${hasAnimated ? 'completed' : ''}`}
    >
      {active && renderContent()}
    </ExpansionEffectContainer>
  );
};

/**
 * NodeExpansion Component
 * 
 * Specialized expansion effect for dialogue nodes with philosophical theming
 * 
 * @param {string} concept - Philosophical concept that determines the effect
 * @param {boolean} active - Whether the expansion is active
 * @param {boolean} isLoop - Whether this is a loop node
 * @param {string} speed - Animation speed
 * @param {function} onComplete - Callback when animation completes
 * @param {React.ReactNode} children - Content to expand
 */
export const NodeExpansion = ({
  concept = THEME.philosophicalConcepts.QUESTION,
  active = true,
  isLoop = false,
  speed = 'normal',
  onComplete = null,
  children
}) => {
  // Choose the appropriate effect based on the philosophical concept
  let effectType = 'pulse';
  
  if (isLoop) {
    effectType = 'paradox';
  } else if (concept === THEME.philosophicalConcepts.PARADOX) {
    effectType = 'glitch';
  } else if (concept === THEME.philosophicalConcepts.ENLIGHTENMENT) {
    effectType = 'enlightenment';
  } else if (concept === THEME.philosophicalConcepts.VOID) {
    effectType = 'void';
  } else if (concept === THEME.philosophicalConcepts.CONSCIOUSNESS) {
    effectType = 'circular';
  }
  
  return (
    <ExpansionEffect
      type={effectType}
      active={active}
      speed={speed}
      onAnimationComplete={onComplete}
    >
      {children}
    </ExpansionEffect>
  );
};

export default ExpansionEffect;
