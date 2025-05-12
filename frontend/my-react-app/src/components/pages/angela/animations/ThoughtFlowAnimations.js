// frontend/my-react-app/src/components/pages/angela/animations/ThoughtFlowAnimations.js
import React, { useState, useEffect, useRef } from 'react';
import styled, { keyframes } from '@emotion/styled';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

// Keyframe animations for the thought particles
const thoughtFlowAnimation = keyframes`
  0% {
    transform: translate(0, 0) scale(1);
    opacity: 0;
  }
  10% {
    opacity: 0.7;
  }
  90% {
    opacity: 0.3;
  }
  100% {
    transform: translate(var(--move-x, -50px), var(--move-y, -50px)) scale(var(--end-scale, 0.5));
    opacity: 0;
  }
`;

const pulseAnimation = keyframes`
  0% {
    transform: scale(1);
    opacity: var(--max-opacity, 0.7);
  }
  50% {
    transform: scale(1.2);
    opacity: var(--min-opacity, 0.3);
  }
  100% {
    transform: scale(1);
    opacity: var(--max-opacity, 0.7);
  }
`;

const floatAnimation = keyframes`
  0% {
    transform: translateY(0px) rotate(0deg);
  }
  50% {
    transform: translateY(var(--float-distance, -10px)) rotate(var(--float-rotation, 5deg));
  }
  100% {
    transform: translateY(0px) rotate(0deg);
  }
`;

// Styled components for the thought flow system
const ThoughtFlowContainer = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  overflow: hidden;
  z-index: ${props => props.zIndex || 0};
`;

const ThoughtParticle = styled.div`
  position: absolute;
  width: var(--size, 8px);
  height: var(--size, 8px);
  border-radius: 50%;
  background-color: var(--color, rgba(255, 255, 255, 0.2));
  opacity: 0;
  animation: ${thoughtFlowAnimation} var(--duration, 5s) ease-out forwards;
  animation-delay: var(--delay, 0s);
`;

const ThoughtBubble = styled.div`
  position: absolute;
  width: var(--size, 20px);
  height: var(--size, 20px);
  border-radius: 50%;
  border: 1px solid var(--border-color, rgba(255, 255, 255, 0.2));
  background-color: var(--bg-color, rgba(20, 20, 20, 0.5));
  box-shadow: 0 0 10px var(--glow-color, rgba(255, 255, 255, 0.1));
  animation: ${pulseAnimation} var(--duration, 3s) ease-in-out infinite;
  animation-delay: var(--delay, 0s);
`;

const ThoughtLine = styled.div`
  position: absolute;
  height: 1px;
  width: var(--length, 50px);
  background: linear-gradient(
    to right,
    transparent,
    var(--color, rgba(255, 255, 255, 0.2)),
    transparent
  );
  transform-origin: left center;
  transform: rotate(var(--angle, 0deg));
  opacity: var(--opacity, 0.5);
  animation: ${floatAnimation} var(--duration, 6s) ease-in-out infinite;
  animation-delay: var(--delay, 0s);
`;

const ThoughtCluster = styled.div`
  position: absolute;
  top: var(--top, 50%);
  left: var(--left, 50%);
  width: var(--size, 40px);
  height: var(--size, 40px);
  transform-origin: center;
  animation: ${floatAnimation} var(--duration, 8s) ease-in-out infinite;
  animation-delay: var(--delay, 0s);
`;

/**
 * ThoughtFlowEffect Component
 * 
 * Creates animated thought particles, bubbles, and connection lines
 * that flow upward/outward to simulate thought processes
 * 
 * @param {boolean} active - Whether the effect is active
 * @param {number} particleCount - Number of particles to generate
 * @param {number} bubbleCount - Number of thought bubbles
 * @param {number} lineCount - Number of connection lines
 * @param {number} clusterCount - Number of particle clusters
 * @param {string} baseColor - Base color for the effects
 * @param {number} zIndex - Z-index for positioning
 * @param {string} origin - Origin point ('center', 'bottom', etc.)
 */
const ThoughtFlowEffect = ({
  active = true,
  particleCount = 15,
  bubbleCount = 5,
  lineCount = 10,
  clusterCount = 3,
  baseColor = 'rgba(255, 255, 255, 0.2)',
  accentColor = THEME.colors.accentPrimary + '33', // 33 = 20% opacity
  zIndex = 0,
  origin = 'center'
}) => {
  const [particles, setParticles] = useState([]);
  const [bubbles, setBubbles] = useState([]);
  const [lines, setLines] = useState([]);
  const [clusters, setClusters] = useState([]);
  const containerRef = useRef(null);
  
  // Generate all visual elements when component mounts or active state changes
  useEffect(() => {
    if (!active) {
      setParticles([]);
      setBubbles([]);
      setLines([]);
      setClusters([]);
      return;
    }
    
    // Generate thought particles
    const newParticles = Array.from({ length: particleCount }).map((_, i) => ({
      id: `particle-${i}`,
      size: `${Math.random() * 8 + 4}px`,
      color: Math.random() > 0.7 ? accentColor : baseColor,
      top: getOriginY(origin) + Math.random() * 50 - 25 + '%',
      left: getOriginX(origin) + Math.random() * 50 - 25 + '%',
      moveX: `${Math.random() * 100 - 50}px`,
      moveY: `${Math.random() * -100 - 30}px`,
      endScale: Math.random() * 0.5 + 0.2,
      duration: `${Math.random() * 3 + 3}s`,
      delay: `${Math.random() * 5}s`
    }));
    setParticles(newParticles);
    
    // Generate thought bubbles
    const newBubbles = Array.from({ length: bubbleCount }).map((_, i) => ({
      id: `bubble-${i}`,
      size: `${Math.random() * 20 + 10}px`,
      borderColor: Math.random() > 0.7 ? accentColor : baseColor,
      bgColor: THEME.colors.bgSecondary + '80', // 80 = 50% opacity
      glowColor: Math.random() > 0.7 ? THEME.colors.accentGlow : THEME.colors.enlightenmentGlow,
      top: getOriginY(origin) + Math.random() * 70 - 35 + '%',
      left: getOriginX(origin) + Math.random() * 70 - 35 + '%',
      maxOpacity: Math.random() * 0.4 + 0.3,
      minOpacity: Math.random() * 0.2 + 0.1,
      duration: `${Math.random() * 4 + 4}s`,
      delay: `${Math.random() * 5}s`
    }));
    setBubbles(newBubbles);
    
    // Generate connecting thought lines
    const newLines = Array.from({ length: lineCount }).map((_, i) => ({
      id: `line-${i}`,
      length: `${Math.random() * 60 + 20}px`,
      color: Math.random() > 0.8 ? accentColor : baseColor,
      angle: `${Math.random() * 360}deg`,
      top: getOriginY(origin) + Math.random() * 80 - 40 + '%',
      left: getOriginX(origin) + Math.random() * 80 - 40 + '%',
      opacity: Math.random() * 0.3 + 0.1,
      floatDistance: `${Math.random() * 15 + 5}px`,
      floatRotation: `${Math.random() * 20 - 10}deg`,
      duration: `${Math.random() * 4 + 4}s`,
      delay: `${Math.random() * 5}s`
    }));
    setLines(newLines);
    
    // Generate particle clusters
    const newClusters = Array.from({ length: clusterCount }).map((_, i) => ({
      id: `cluster-${i}`,
      size: `${Math.random() * 30 + 20}px`,
      top: getOriginY(origin) + Math.random() * 60 - 30 + '%',
      left: getOriginX(origin) + Math.random() * 60 - 30 + '%',
      floatDistance: `${Math.random() * 20 + 10}px`,
      floatRotation: `${Math.random() * 20 - 10}deg`,
      duration: `${Math.random() * 5 + 5}s`,
      delay: `${Math.random() * 4}s`
    }));
    setClusters(newClusters);
    
  }, [active, particleCount, bubbleCount, lineCount, clusterCount, baseColor, accentColor, origin]);
  
  // Helper functions to get origin coordinates
  const getOriginX = (origin) => {
    if (origin === 'center') return 50;
    if (origin === 'left') return 20;
    if (origin === 'right') return 80;
    if (origin.includes('left')) return 20;
    if (origin.includes('right')) return 80;
    return 50;
  };
  
  const getOriginY = (origin) => {
    if (origin === 'center') return 50;
    if (origin === 'top') return 20;
    if (origin === 'bottom') return 80;
    if (origin.includes('top')) return 20;
    if (origin.includes('bottom')) return 80;
    return 50;
  };
  
  // Render cluster with child particles
  const renderCluster = (cluster) => {
    // Generate 3-5 child particles within the cluster
    const childParticles = Array.from({ length: Math.floor(Math.random() * 3) + 3 }).map((_, i) => ({
      id: `${cluster.id}-child-${i}`,
      size: `${Math.random() * 6 + 2}px`,
      color: Math.random() > 0.7 ? accentColor : baseColor,
      top: `${Math.random() * 100}%`,
      left: `${Math.random() * 100}%`,
      moveX: `${Math.random() * 20 - 10}px`,
      moveY: `${Math.random() * 20 - 15}px`,
      endScale: Math.random() * 0.3 + 0.2,
      duration: `${Math.random() * 2 + 2}s`,
      delay: `${Math.random() * 1}s`
    }));
    
    return (
      <ThoughtCluster
        key={cluster.id}
        style={{
          '--top': cluster.top,
          '--left': cluster.left,
          '--size': cluster.size,
          '--float-distance': cluster.floatDistance,
          '--float-rotation': cluster.floatRotation,
          '--duration': cluster.duration,
          '--delay': cluster.delay
        }}
      >
        {childParticles.map(particle => (
          <ThoughtParticle
            key={particle.id}
            style={{
              '--size': particle.size,
              '--color': particle.color,
              '--move-x': particle.moveX,
              '--move-y': particle.moveY,
              '--end-scale': particle.endScale,
              '--duration': particle.duration,
              '--delay': particle.delay,
              top: particle.top,
              left: particle.left
            }}
          />
        ))}
      </ThoughtCluster>
    );
  };
  
  if (!active) return null;
  
  return (
    <ThoughtFlowContainer ref={containerRef} zIndex={zIndex} className="thought-flow-effect">
      {/* Individual thought particles */}
      {particles.map(particle => (
        <ThoughtParticle
          key={particle.id}
          style={{
            '--size': particle.size,
            '--color': particle.color,
            '--move-x': particle.moveX,
            '--move-y': particle.moveY,
            '--end-scale': particle.endScale,
            '--duration': particle.duration,
            '--delay': particle.delay,
            top: particle.top,
            left: particle.left
          }}
        />
      ))}
      
      {/* Thought bubbles */}
      {bubbles.map(bubble => (
        <ThoughtBubble
          key={bubble.id}
          style={{
            '--size': bubble.size,
            '--border-color': bubble.borderColor,
            '--bg-color': bubble.bgColor,
            '--glow-color': bubble.glowColor,
            '--max-opacity': bubble.maxOpacity,
            '--min-opacity': bubble.minOpacity,
            '--duration': bubble.duration,
            '--delay': bubble.delay,
            top: bubble.top,
            left: bubble.left
          }}
        />
      ))}
      
      {/* Connecting thought lines */}
      {lines.map(line => (
        <ThoughtLine
          key={line.id}
          style={{
            '--length': line.length,
            '--color': line.color,
            '--angle': line.angle,
            '--opacity': line.opacity,
            '--float-distance': line.floatDistance,
            '--float-rotation': line.floatRotation,
            '--duration': line.duration,
            '--delay': line.delay,
            top: line.top,
            left: line.left
          }}
        />
      ))}
      
      {/* Particle clusters */}
      {clusters.map(cluster => renderCluster(cluster))}
    </ThoughtFlowContainer>
  );
};

export default ThoughtFlowEffect;
