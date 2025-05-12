// frontend/my-react-app/src/components/pages/angela/animations/ParadoxTransitions.js
import React, { useState, useEffect, useRef } from 'react';
import styled from '@emotion/styled';
import { keyframes } from '@emotion/react';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

// Keyframe animations for paradox effects
const paradoxSpin = keyframes`
  0% {
    transform: perspective(800px) rotateY(0deg);
    opacity: 1;
  }
  40% {
    transform: perspective(800px) rotateY(180deg);
    opacity: 0.5;
  }
  60% {
    transform: perspective(800px) rotateY(180deg);
    opacity: 0.5;
  }
  100% {
    transform: perspective(800px) rotateY(360deg);
    opacity: 1;
  }
`;

const infiniteRegress = keyframes`
  0% {
    transform: scale(1) translateZ(0);
    filter: brightness(100%);
  }
  50% {
    transform: scale(0.9) translateZ(-50px);
    filter: brightness(70%);
  }
  100% {
    transform: scale(1) translateZ(0);
    filter: brightness(100%);
  }
`;

const realityBend = keyframes`
  0% {
    transform: skew(0deg, 0deg) scale(1);
    filter: blur(0px);
  }
  25% {
    transform: skew(2deg, 1deg) scale(1.03);
    filter: blur(1px) hue-rotate(20deg);
  }
  75% {
    transform: skew(-2deg, -1deg) scale(0.97);
    filter: blur(2px) hue-rotate(-20deg);
  }
  100% {
    transform: skew(0deg, 0deg) scale(1);
    filter: blur(0px);
  }
`;

const matrixGlitch = keyframes`
  0% {
    transform: translate(0);
    opacity: 1;
  }
  1% {
    transform: translate(-5px, 5px);
    opacity: 0.8;
  }
  2% {
    transform: translate(5px, -5px);
    opacity: 1;
  }
  3% {
    transform: translate(-3px, 2px);
    opacity: 0.9;
  }
  4% {
    transform: translate(0);
    opacity: 1;
  }
  25% {
    transform: translate(0);
    opacity: 1;
  }
  26% {
    transform: translate(5px, 0);
    opacity: 0.7;
  }
  27% {
    transform: translate(0);
    opacity: 1;
  }
  45% {
    transform: translate(0);
    opacity: 1;
  }
  46% {
    transform: translate(-2px, 5px);
    opacity: 0.8;
  }
  47% {
    transform: translate(0);
    opacity: 1;
  }
  70% {
    transform: translate(0);
    opacity: 1;
  }
  71% {
    transform: translate(10px, -5px);
    opacity: 0.6;
  }
  72% {
    transform: translate(-8px, 3px);
    opacity: 0.9;
  }
  73% {
    transform: translate(0);
    opacity: 1;
  }
  100% {
    transform: translate(0);
    opacity: 1;
  }
`;

const voidPulse = keyframes`
  0% {
    box-shadow: inset 0 0 20px 5px rgba(0, 0, 0, 0.8);
    background-color: rgba(0, 0, 0, 0.2);
  }
  50% {
    box-shadow: inset 0 0 40px 10px rgba(0, 0, 0, 0.9);
    background-color: rgba(0, 0, 0, 0.4);
  }
  100% {
    box-shadow: inset 0 0 20px 5px rgba(0, 0, 0, 0.8);
    background-color: rgba(0, 0, 0, 0.2);
  }
`;

// Styled components for paradox effects
const ParadoxContainer = styled.div`
  position: relative;
  perspective: 1000px;
  transform-style: preserve-3d;
  perspective-origin: center;
  overflow: hidden;
  width: 100%;
  
  ${props => props.isActive && `
    &::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
      z-index: 1;
      opacity: 0.3;
      background: linear-gradient(
        to bottom,
        transparent 0%,
        ${THEME.colors.accentPrimary}20 30%,
        ${THEME.colors.bgPrimary} 100%
      );
    }
  `}
`;

const ParadoxInner = styled.div`
  position: relative;
`;

// Different transition effect containers
const SpinContainer = styled.div`
  position: relative;
  animation: ${paradoxSpin} ${props => props.duration || '3s'} ${props => props.curve || 'ease-in-out'} 
    ${props => props.delay || '0s'} ${props => props.iterations || '1'};
  transform-origin: center;
  backface-visibility: visible;
`;

const InfiniteContainer = styled.div`
  position: relative;
  animation: ${infiniteRegress} ${props => props.duration || '8s'} ${props => props.curve || 'ease-in-out'} infinite;
  transform-origin: center;
`;

const BendContainer = styled.div`
  position: relative;
  animation: ${realityBend} ${props => props.duration || '5s'} ${props => props.curve || 'ease-in-out'} infinite;
`;

const GlitchContainer = styled.div`
  position: relative;
  animation: ${matrixGlitch} ${props => props.duration || '10s'} step-end infinite;
  
  &::before, &::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    z-index: 1;
    opacity: 0;
  }
  
  &::before {
    background-color: ${THEME.colors.accentPrimary}30;
    mix-blend-mode: difference;
    animation: ${matrixGlitch} 7s step-end infinite reverse;
  }
  
  &::after {
    background-color: ${THEME.colors.terminalGreen}20;
    mix-blend-mode: hard-light;
    animation: ${matrixGlitch} 8s step-end infinite;
    animation-delay: 0.5s;
  }
`;

const VoidContainer = styled.div`
  position: relative;
  animation: ${voidPulse} ${props => props.duration || '10s'} ${props => props.curve || 'ease-in-out'} infinite;
`;

const ScanlineOverlay = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: linear-gradient(
    to bottom,
    transparent 49.5%,
    ${THEME.colors.borderPrimary}50 49.5%,
    ${THEME.colors.borderPrimary}50 50.5%,
    transparent 50.5%
  );
  background-size: 100% 6px;
  pointer-events: none;
  z-index: 5;
  opacity: ${props => props.opacity || 0.15};
  animation: scanline-move 10s linear infinite;
  
  @keyframes scanline-move {
    from { background-position: 0 0; }
    to { background-position: 0 100%; }
  }
`;

/**
 * ParadoxTransition Component
 * 
 * Creates various transition effects for the philosophical dialogue system,
 * especially for loop and paradoxical content.
 * 
 * @param {string} type - Transition type ('spin', 'infinite', 'bend', 'glitch', 'void')
 * @param {boolean} isActive - Whether the effect is active
 * @param {boolean} isLooping - Whether this is part of a loop sequence
 * @param {number} intensity - Effect intensity (0-1)
 * @param {number} zIndex - Z-index for positioning
 * @param {Object} options - Additional options for the effect
 * @param {function} onComplete - Callback when transition completes
 * @param {React.ReactNode} children - Content to apply the transition to
 */
const ParadoxTransition = ({
  type = 'spin',
  isActive = false,
  isLooping = false,
  intensity = 0.5,
  zIndex = 1,
  options = {},
  onComplete = null,
  children
}) => {
  const [isTransitioning, setIsTransitioning] = useState(false);
  const [hasCompleted, setHasCompleted] = useState(false);
  const containerRef = useRef(null);
  
  // Duration based on intensity
  const getDuration = () => {
    // Base duration in seconds
    const baseDuration = {
      spin: 3,
      infinite: 8,
      bend: 5,
      glitch: 10,
      void: 10
    }[type] || 5;
    
    // Adjust by intensity - lower intensity means faster
    return `${baseDuration * (0.5 + intensity * 0.5)}s`;
  };
  
  // Animation curve based on type
  const getCurve = () => {
    if (type === 'glitch') return 'step-end';
    if (type === 'spin') return THEME.animations.curvePhilosophical;
    if (type === 'void') return 'ease-in-out';
    return THEME.animations.curveEaseInOut;
  };
  
  // Handle transition state
  useEffect(() => {
    if (isActive && !isTransitioning && !hasCompleted) {
      setIsTransitioning(true);
      
      // For one-time transitions
      if (type === 'spin' && !isLooping) {
        const timer = setTimeout(() => {
          setIsTransitioning(false);
          setHasCompleted(true);
          if (onComplete) onComplete();
        }, parseFloat(getDuration()) * 1000);
        
        return () => clearTimeout(timer);
      }
    }
    
    // Reset when deactivated
    if (!isActive) {
      setIsTransitioning(false);
      setHasCompleted(false);
    }
  }, [isActive, isTransitioning, hasCompleted, isLooping, type, onComplete]);
  
  // Render the appropriate effect container based on type
  const renderEffectContainer = () => {
    // Options with defaults
    const duration = options.duration || getDuration();
    const curve = options.curve || getCurve();
    const delay = options.delay || '0s';
    const iterations = isLooping ? 'infinite' : options.iterations || '1';
    
    switch (type) {
      case 'spin':
        return (
          <SpinContainer
            duration={duration}
            curve={curve}
            delay={delay}
            iterations={iterations}
          >
            {children}
          </SpinContainer>
        );
      
      case 'infinite':
        return (
          <InfiniteContainer
            duration={duration}
            curve={curve}
          >
            {children}
          </InfiniteContainer>
        );
      
      case 'bend':
        return (
          <BendContainer
            duration={duration}
            curve={curve}
          >
            {children}
          </BendContainer>
        );
      
      case 'glitch':
        return (
          <GlitchContainer
            duration={duration}
          >
            {children}
          </GlitchContainer>
        );
      
      case 'void':
        return (
          <VoidContainer
            duration={duration}
            curve={curve}
          >
            {children}
          </VoidContainer>
        );
      
      default:
        return children;
    }
  };
  
  return (
    <ParadoxContainer
      ref={containerRef}
      isActive={isActive}
      style={{ zIndex }}
      className={`paradox-transition type-${type} ${isActive ? 'active' : ''} ${isTransitioning ? 'transitioning' : ''} ${hasCompleted ? 'completed' : ''} ${isLooping ? 'looping' : ''}`}
    >
      <ParadoxInner className="paradox-inner">
        {renderEffectContainer()}
      </ParadoxInner>
      
      {/* Scanline overlay for visual effect */}
      {(type === 'glitch' || intensity > 0.7) && (
        <ScanlineOverlay opacity={0.1 + intensity * 0.2} />
      )}
    </ParadoxContainer>
  );
};

/**
 * LoopTransition Component
 * 
 * Specialized transition for the infinite loop effect in the dialogue system
 * 
 * @param {boolean} isActive - Whether the loop is active
 * @param {number} loopIndex - Current position in the loop
 * @param {number} loopTotal - Total number of nodes in the loop
 * @param {function} onLoopComplete - Callback when loop completes
 * @param {React.ReactNode} children - Content to loop
 */
export const LoopTransition = ({
  isActive = false,
  loopIndex = 0,
  loopTotal = 30,
  onLoopComplete = null,
  children
}) => {
  // Calculate where we are in the loop cycle
  const loopProgress = loopIndex / loopTotal;
  
  // Different transition types at different points in the loop
  let transitionType = 'spin';
  
  if (loopIndex === 0) {
    // Beginning of loop
    transitionType = 'glitch';
  } else if (loopProgress > 0.9) {
    // Near the end of the loop
    transitionType = 'void';
  } else if (loopProgress > 0.7) {
    // Later part of the loop
    transitionType = 'bend';
  } else if (loopProgress > 0.5) {
    // Middle of the loop
    transitionType = 'infinite';
  } else if (loopProgress > 0.3) {
    // First third of the loop
    transitionType = 'glitch';
  }
  
  // Intensity increases as we progress through the loop
  const intensity = Math.min(0.3 + loopProgress * 0.7, 1);
  
  return (
    <ParadoxTransition
      type={transitionType}
      isActive={isActive}
      isLooping={true}
      intensity={intensity}
      onComplete={onLoopComplete}
    >
      {children}
    </ParadoxTransition>
  );
};

/**
 * ResetReality Component
 * 
 * Special effect used when resetting from a loop back to the beginning
 * 
 * @param {boolean} isActive - Whether the reset is active
 * @param {function} onComplete - Callback when reset completes
 * @param {React.ReactNode} children - Content to reset
 */
export const ResetReality = ({
  isActive = false,
  onComplete = null,
  children
}) => {
  return (
    <ParadoxTransition
      type="spin"
      isActive={isActive}
      intensity={1}
      options={{
        duration: '1.5s',
        curve: THEME.animations.curvePhilosophical
      }}
      onComplete={onComplete}
    >
      {children}
    </ParadoxTransition>
  );
};

export default ParadoxTransition;
