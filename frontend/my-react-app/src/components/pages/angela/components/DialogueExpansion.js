// frontend/my-react-app/src/components/pages/angela/components/DialogueExpansion.js
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { 
  ExpansionContainer, 
  ExpansionInner, 
  ExpansionBackground,
  ThoughtParticle,
  ThoughtLine,
  createThoughtParticles,
  createThoughtLines
} from '../styles/DialogueStyles';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

/**
 * DialogueExpansion Component
 * 
 * Handles the expansion and collapse animations for dialogue content
 * with advanced transition effects and thoughtflow particles
 * 
 * @param {boolean} isExpanded - Whether the content is expanded
 * @param {string} effect - The effect type to use (pulse, glitch, thoughtFlow, paradox)
 * @param {boolean} isLoop - Whether this expansion is part of a looping dialogue chain
 * @param {number} depth - The nesting depth of this expansion (for styling)
 * @param {boolean} showParticles - Whether to show thought particles
 * @param {boolean} showLines - Whether to show thought lines
 * @param {React.ReactNode} children - The content to expand/collapse
 */
const DialogueExpansion = ({ 
  isExpanded,
  effect = 'pulse',
  isLoop = false,
  depth = 0,
  showParticles = true,
  showLines = true,
  children
}) => {
  const [thoughtParticles, setThoughtParticles] = useState([]);
  const [thoughtLines, setThoughtLines] = useState([]);
  const [hasExpanded, setHasExpanded] = useState(false);
  const [isAnimating, setIsAnimating] = useState(false);
  const containerRef = useRef(null);
  
  // Generate thought particles and lines when expanded
  useEffect(() => {
    if (isExpanded) {
      if (!hasExpanded) {
        setHasExpanded(true);
      }
      
      if (showParticles) {
        // Generate more particles at deeper levels for visual effect
        const particleCount = Math.max(5, 10 - depth * 2);
        setThoughtParticles(createThoughtParticles(particleCount));
      }
      
      if (showLines) {
        const lineCount = Math.max(3, 6 - depth);
        setThoughtLines(createThoughtLines(lineCount));
      }
      
      // Set animation state for timing effects
      setIsAnimating(true);
      const animationTimer = setTimeout(() => {
        setIsAnimating(false);
      }, 800); // Match this with CSS transition duration
      
      return () => clearTimeout(animationTimer);
    }
  }, [isExpanded, depth, showParticles, showLines, hasExpanded]);
  
  // Handle special loop effect
  useEffect(() => {
    if (isLoop && isExpanded) {
      // Add a pulsating background effect for loop nodes
      const loopElement = containerRef.current;
      if (loopElement) {
        loopElement.classList.add('paradox-loop-active');
      }
      
      return () => {
        if (loopElement) {
          loopElement.classList.remove('paradox-loop-active');
        }
      };
    }
  }, [isLoop, isExpanded]);
  
  // Render thought particles for visual effects
  const renderThoughtParticles = useCallback(() => {
    if (!isExpanded || !showParticles) return null;
    
    return thoughtParticles.map(particle => (
      <ThoughtParticle
        key={particle.id}
        size={particle.size}
        delay={particle.delay}
        duration={particle.duration}
        moveX={particle.moveX}
        moveY={particle.moveY}
        scale={particle.scale}
        maxOpacity={particle.maxOpacity}
        style={{
          left: particle.left,
          top: particle.top
        }}
      />
    ));
  }, [isExpanded, showParticles, thoughtParticles]);
  
  // Render thought lines for visual effects
  const renderThoughtLines = useCallback(() => {
    if (!isExpanded || !showLines) return null;
    
    return thoughtLines.map(line => (
      <ThoughtLine
        key={line.id}
        width={line.width}
        delay={line.delay}
        duration={line.duration}
        angle={line.angle}
        maxOpacity={line.maxOpacity}
        style={{
          left: line.left,
          top: line.top
        }}
      />
    ));
  }, [isExpanded, showLines, thoughtLines]);
  
  // Determine effect class based on props
  let effectClass = '';
  if (isLoop) {
    effectClass = 'paradox-effect';
  } else if (effect === 'glitch') {
    effectClass = 'glitch-effect';
  } else if (effect === 'thoughtFlow') {
    effectClass = 'thought-flow-effect';
  } else if (effect === 'paradox') {
    effectClass = 'paradox-effect';
  } else {
    effectClass = 'pulse-effect';
  }
  
  return (
    <ExpansionContainer 
      ref={containerRef}
      isExpanded={isExpanded}
      className={`dialogue-expansion ${isExpanded ? 'expanded' : ''} ${effectClass} ${isAnimating ? 'animating' : ''} ${isLoop ? 'loop-node' : ''}`}
      data-depth={depth}
    >
      <ExpansionInner className="expansion-inner">
        {/* Background effect layer */}
        <ExpansionBackground className="expansion-background" />
        
        {/* Thought particles for visual effect */}
        {showParticles && (
          <div className="thought-flow-container">
            {renderThoughtParticles()}
            {renderThoughtLines()}
          </div>
        )}
        
        {/* Content to be expanded */}
        <div className="expansion-content">
          {children}
        </div>
      </ExpansionInner>
    </ExpansionContainer>
  );
};

export default DialogueExpansion;
