// frontend/my-react-app/src/components/pages/angela/components/DialogueSystem.js
import React, { useState, useEffect, useRef, useCallback } from 'react';
import styled from '@emotion/styled';
import { keyframes } from '@emotion/react';
import DialogueNode from './DialogueNode';
import DialogueExpansion from './DialogueExpansion';
import { useDialogueChain } from '../hooks/useDialogueChain';
import { useInfiniteLoop } from '../hooks/useInfiniteLoop';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';
import { generateParadoxInsight } from '../utils/paradoxGenerator';
import ThoughtFlowEffect from '../animations/ThoughtFlowAnimations';

// Pulse animation for active nodes
const pulseEffect = keyframes`
  0% {
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0.4);
  }
  70% {
    box-shadow: 0 0 0 10px rgba(255, 51, 51, 0);
  }
  100% {
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0);
  }
`;

const paradoxEffect = keyframes`
  0% {
    filter: hue-rotate(0deg) brightness(1);
  }
  25% {
    filter: hue-rotate(90deg) brightness(1.1);
  }
  75% {
    filter: hue-rotate(270deg) brightness(0.9);
  }
  100% {
    filter: hue-rotate(360deg) brightness(1);
  }
`;

const glitchEffect = keyframes`
  0% {
    transform: translate(0);
  }
  1.5% {
    transform: translate(-2px, 2px);
  }
  3% {
    transform: translate(2px, -2px);
  }
  4.5% {
    transform: translate(0);
  }
  6% {
    transform: translate(0);
  }
  100% {
    transform: translate(0);
  }
`;

// Enhanced DialogueContainer with proper centering and styling
const DialogueContainer = styled.div`
  max-width: 900px;
  margin: 0 auto; /* Center alignment */
  padding: 2.5rem;
  position: relative;
  border-radius: 12px;
  background: ${props => props.isLooping ? 
    `linear-gradient(to bottom, ${THEME.colors.bgPrimary}aa, ${THEME.colors.bgSecondary}aa)` :
    `linear-gradient(to bottom, ${THEME.colors.bgPrimary}, ${THEME.colors.bgSecondary}22)`
  };
  box-shadow: ${props => props.isLooping ? 
    `0 0 30px rgba(255, 51, 51, 0.2)` :
    '0 0 20px rgba(0, 0, 0, 0.3)'
  };
  border: 1px solid ${props => props.isLooping ? 
    THEME.colors.accentPrimary + '33' : 
    THEME.colors.borderPrimary + '33'
  };
  transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
  
  /* CRT effect overlay */
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(
      rgba(18, 16, 16, 0) 50%, 
      rgba(0, 0, 0, 0.1) 50%
    );
    background-size: 100% 4px;
    z-index: -1;
    opacity: 0.2;
    border-radius: 12px;
    pointer-events: none;
  }
  
  /* Cyber grid pattern */
  &::after {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-image: 
      linear-gradient(rgba(51, 51, 51, 0.05) 1px, transparent 1px),
      linear-gradient(90deg, rgba(51, 51, 51, 0.05) 1px, transparent 1px);
    background-size: 20px 20px;
    z-index: -1;
    opacity: 0.5;
    border-radius: 12px;
    pointer-events: none;
  }
  
  /* Enhanced active state for looping */
  &.transitioning {
    animation: ${paradoxEffect} 1s linear;
  }
  
  &.looping {
    border: 1px solid ${THEME.colors.accentPrimary}44;
  }
  
  /* Glitch effect when transitioning states */
  &.glitching {
    animation: ${glitchEffect} 1s step-end;
    &::before {
      animation: ${glitchEffect} 1s step-end reverse;
    }
  }
  
  @media (max-width: 768px) {
    padding: 1.5rem 1rem;
    margin: 0 1rem;
  }
`;

// Header for the dialogue system
const DialogueHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid ${THEME.colors.borderPrimary};
  
  .dialogue-title {
    font-family: ${THEME.typography.fontFamilySecondary};
    font-size: 1.2rem;
    color: ${THEME.colors.textPrimary};
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  
  .dialogue-depth {
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 0.9rem;
    color: ${THEME.colors.textSecondary};
    padding: 0.25rem 0.5rem;
    background-color: ${THEME.colors.bgSecondary};
    border-radius: 4px;
    border: 1px solid ${THEME.colors.borderPrimary};
  }
  
  .dialogue-looping {
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 0.9rem;
    color: ${THEME.colors.accentPrimary};
    animation: ${pulseEffect} 2s infinite;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    background-color: ${THEME.colors.bgSecondary};
    border: 1px solid ${THEME.colors.accentPrimary}44;
  }
`;

// Content container with improved scrolling behavior and progressive indent for the rightward shift
const DialogueContent = styled.div`
  position: relative;
  max-height: 70vh;
  overflow-y: auto;
  perspective: 1000px;
  
  /* Improved scrollbar styling */
  &::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }
  
  &::-webkit-scrollbar-track {
    background: ${THEME.colors.bgSecondary};
    border-radius: 3px;
  }
  
  &::-webkit-scrollbar-thumb {
    background: ${THEME.colors.borderPrimary};
    border-radius: 3px;
  }
  
  &::-webkit-scrollbar-thumb:hover {
    background: ${THEME.colors.accentPrimary};
  }
  
  /* Create progressive space for rightward progression effect */
  padding-right: ${props => Math.min(props.depth * 20, 200)}px;
  transition: padding-right 0.8s cubic-bezier(0.34, 1.56, 0.64, 1);
  
  /* Create a perspective effect for depth */
  transform-style: preserve-3d;
  transform: ${props => props.depth > 5 ? `perspective(1000px) rotateX(${Math.min(props.depth - 5, 10)}deg)` : 'none'};
  transition: transform 0.8s cubic-bezier(0.34, 1.56, 0.64, 1);
`;

// Scanline effect overlay
const DialogueScanlines = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  z-index: 2;
  opacity: ${props => props.isLooping ? 0.3 : 0.15};
  background: linear-gradient(
    to bottom,
    transparent 50%,
    rgba(32, 32, 32, 0.1) 50%
  );
  background-size: 100% 4px;
  border-radius: 12px;
`;

// Navigation controls
const DialogueNavigation = styled.div`
  display: flex;
  justify-content: space-between;
  margin-top: 2rem;
  padding-top: 1rem;
  border-top: 1px solid ${THEME.colors.borderPrimary};
  
  button {
    background-color: ${THEME.colors.bgSecondary};
    color: ${THEME.colors.textSecondary};
    border: 1px solid ${THEME.colors.borderPrimary};
    padding: 0.5rem 1rem;
    border-radius: 4px;
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 0.9rem;
    cursor: pointer;
    transition: all 0.2s ease-in-out;
    
    &:hover:not(:disabled) {
      background-color: ${THEME.colors.bgTertiary};
      color: ${THEME.colors.textPrimary};
      border-color: ${THEME.colors.accentPrimary};
    }
    
    &:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    
    /* Reset button styling */
    &.reset-button {
      background-color: ${THEME.colors.borderPrimary};
      color: ${THEME.colors.textPrimary};
      
      &:hover:not(:disabled) {
        background-color: ${THEME.colors.accentPrimary};
      }
    }
  }
`;

// Paradoxical insight that appears during looping
const ParadoxInsight = styled.div`
  font-family: ${THEME.typography.fontFamilyPhilosophical};
  font-style: italic;
  font-size: 0.9rem;
  color: ${THEME.colors.textPrimary};
  margin-top: 1.5rem;
  text-align: center;
  opacity: ${props => props.show ? 1 : 0};
  transform: translateY(${props => props.show ? 0 : '10px'});
  transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
  
  /* Text fade in/out effect */
  &::before {
    content: "";
    position: absolute;
    left: 20%;
    right: 20%;
    bottom: -10px;
    height: 1px;
    background: linear-gradient(
      to right,
      transparent 0%,
      ${THEME.colors.accentPrimary}33 50%,
      transparent 100%
    );
  }
`;

// Wrapper for the progressive rightward shift effect
const ProgressiveShiftWrapper = styled.div`
  width: 100%;
  position: relative;
  transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
  
  /* This is where the magic happens - the rightward and downward shifts */
  transform: ${props => {
    const xOffset = props.depth * props.xShiftFactor;
    const yOffset = props.depth * props.yShiftFactor;
    const rotateZ = props.depth * 0.5;
    return `translate(${xOffset}px, ${yOffset}px) rotateZ(${rotateZ}deg)`;
  }};
  
  /* Add perspective for 3D effect */
  transform-style: preserve-3d;
  
  /* Only apply perspective effects at deeper levels */
  ${props => props.depth > 5 && `
    transform: translate(${props.depth * props.xShiftFactor}px, ${props.depth * props.yShiftFactor}px) 
               rotateZ(${props.depth * 0.5}deg)
               rotateY(${Math.min((props.depth - 5) * 2, 20)}deg);
  `}
`;

/**
 * DialogueSystem Component
 * 
 * Enhanced dialogue system that manages the philosophical Socratic dialogue.
 * Implements rightward and downward progression for a schizophrenic dialogue effect,
 * with paradoxical loop transitions and improved visual styling.
 */
const DialogueSystem = ({
  dialogueData,
  philosophical = true,
  terminal = false,
  autoAdvance = false,
  enableLooping = true,
  rightProgression = true,
  loopAfterDepth = 20,
  initialDepth = 0,
  onDialogueChange = null
}) => {
  // Use custom hooks to manage dialogue chain and looping
  const { 
    dialogue,
    expandedNodes,
    activeNodePath,
    expandNode,
    collapseNode,
    toggleNode,
    getCurrentDepth,
    getNodeByPath,
    getTotalNodesCount,
    dialogueHistory,
    resetDialogue,
    navigateNext,
    navigatePrevious
  } = useDialogueChain(dialogueData, initialDepth);
  
  const {
    isLooping,
    loopIndex,
    loopCycles,
    startLoop,
    advanceLoop,
    getLoopTransition,
    shouldEnterNewLoopPhase,
    createLoopPath,
    resetLoopState
  } = useInfiniteLoop(loopAfterDepth);
  
  // Internal state for tracking
  const [isReady, setIsReady] = useState(false);
  const [autoAdvanceActive, setAutoAdvanceActive] = useState(autoAdvance);
  const [autoAdvanceDelay, setAutoAdvanceDelay] = useState(1500); // milliseconds
  const [currentEffect, setCurrentEffect] = useState('pulse');
  const [isTransitioning, setIsTransitioning] = useState(false);
  const [paradoxInsight, setParadoxInsight] = useState('');
  const [showInsight, setShowInsight] = useState(false);
  const [disableNext, setDisableNext] = useState(false);
  const [disablePrev, setDisablePrev] = useState(true);
  const [xShiftFactor, setXShiftFactor] = useState(15); // pixels per depth level
  const [yShiftFactor, setYShiftFactor] = useState(10); // pixels per depth level
  const [isGlitching, setIsGlitching] = useState(false);
  
  const containerRef = useRef(null);
  const contentRef = useRef(null);
  
  // Setup dialogue system
  useEffect(() => {
    if (dialogueData && dialogueData.length > 0) {
      setIsReady(true);
      
      // Generate initial insight
      setParadoxInsight(generateParadoxInsight());
      
      // Show insight periodically
      const insightTimer = setInterval(() => {
        if (isLooping) {
          setShowInsight(prev => !prev);
          if (!showInsight) {
            setParadoxInsight(generateParadoxInsight());
          }
        }
      }, 5000);
      
      return () => clearInterval(insightTimer);
    }
  }, [dialogueData, isLooping, showInsight]);
  
  // Handle auto-advance
  useEffect(() => {
    let timer;
    if (autoAdvanceActive && isReady) {
      timer = setTimeout(() => {
        const depth = getCurrentDepth();
        // Stop auto-advancing after a certain depth
        if (depth >= 3) {
          setAutoAdvanceActive(false);
          return;
        }
        
        navigateNext();
        
      }, autoAdvanceDelay);
    }
    
    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [autoAdvanceActive, isReady, navigateNext, getCurrentDepth, autoAdvanceDelay]);
  
  // Check if we should start the loop
  useEffect(() => {
    if (enableLooping && getCurrentDepth() >= loopAfterDepth && !isLooping) {
      startLoop();
      
      // Trigger a glitch effect when loop starts
      setIsGlitching(true);
      setTimeout(() => setIsGlitching(false), 1000);
    }
  }, [enableLooping, getCurrentDepth, loopAfterDepth, isLooping, startLoop]);
  
  // Update disable states for navigation buttons
  useEffect(() => {
    const depth = getCurrentDepth();
    setDisablePrev(depth <= 1);
    setDisableNext(false); // We can always go deeper in an infinite loop
  }, [expandedNodes, getCurrentDepth]);
  
  // Adjust shift factors based on depth and looping state
  useEffect(() => {
    const depth = getCurrentDepth();
    
    // Increase the shift as we go deeper
    if (depth > 10) {
      // Make the shifts more dramatic at deeper levels
      setXShiftFactor(20);
      setYShiftFactor(15);
    } else if (depth > 5) {
      // Moderate shifts
      setXShiftFactor(15);
      setYShiftFactor(10);
    } else {
      // Initial subtle shifts
      setXShiftFactor(10);
      setYShiftFactor(5);
    }
    
    // When looping, make it more extreme
    if (isLooping) {
      setXShiftFactor(prev => prev * 1.2);
      setYShiftFactor(prev => prev * 1.2);
    }
  }, [getCurrentDepth, isLooping, loopCycles]);
  
  // Auto-scroll to show the latest content
  useEffect(() => {
    if (contentRef.current && expandedNodes.length > 0) {
      contentRef.current.scrollTo({
        top: contentRef.current.scrollHeight,
        behavior: 'smooth'
      });
    }
  }, [expandedNodes]);
  
  // Callback for node expansion
  const handleNodeExpand = useCallback((node, isExpanded, path) => {
    if (isTransitioning) return;
    
    // Apply a transition effect based on node type
    const effect = node.type === THEME.philosophicalConcepts.PARADOX 
      ? 'paradox' 
      : node.type === THEME.philosophicalConcepts.ENLIGHTENMENT 
        ? 'thoughtFlow'
        : 'pulse';
    
    setCurrentEffect(effect);
    setIsTransitioning(true);
    
    // Trigger glitch effect
    setIsGlitching(true);
    setTimeout(() => setIsGlitching(false), 500);
    
    // Briefly show transition effect
    setTimeout(() => {
      setIsTransitioning(false);
    }, 800);
    
    // Handle the expansion/collapse
    if (isExpanded) {
      expandNode(node, path);
    } else {
      collapseNode(node, path);
    }
    
    // Notify parent if callback provided
    if (onDialogueChange) {
      onDialogueChange({
        expanded: isExpanded,
        node,
        path,
        depth: getCurrentDepth(),
        totalNodes: getTotalNodesCount(),
        isLooping
      });
    }
    
    // Auto-scroll to new content
    setTimeout(() => {
      if (contentRef.current) {
        contentRef.current.scrollTo({
          top: contentRef.current.scrollHeight,
          behavior: 'smooth'
        });
      }
    }, 300);
    
    // Check if we need to handle the infinite loop
    if (enableLooping && getCurrentDepth() >= loopAfterDepth) {
      if (!isLooping) {
        startLoop();
      } else {
        // When already looping, apply special loop transition
        const loopTransition = getLoopTransition();
        setCurrentEffect(loopTransition);
        advanceLoop();
      }
    }
  }, [
    isTransitioning, expandNode, collapseNode, getCurrentDepth, getTotalNodesCount,
    enableLooping, loopAfterDepth, isLooping, startLoop, getLoopTransition, 
    advanceLoop, onDialogueChange
  ]);
  
  // Generate the paradoxical loop path if looping
  const getDialogueNodes = useCallback(() => {
    if (!isReady || !dialogue) return null;
    
    if (isLooping) {
      // When looping, we construct a special path that creates the illusion
      // of infinite nested dialogue but actually loops back
      const loopPath = createLoopPath(dialogue, dialogueHistory);
      return renderDialogueNodes(loopPath, 0);
    }
    
    // Normal rendering when not looping
    return renderDialogueNodes(dialogue, 0);
  }, [isReady, dialogue, isLooping, createLoopPath, dialogueHistory]);
  
  // Recursive function to render dialogue nodes
  const renderDialogueNodes = useCallback((nodes, depth, parentPath = []) => {
    if (!nodes || nodes.length === 0) return null;
    
    return nodes.map((node, index) => {
      const currentPath = [...parentPath, index];
      const pathKey = currentPath.join('-');
      const isExpanded = expandedNodes.some(expandedPath => 
        expandedPath.join('-') === currentPath.join('-')
      );
      
      // Only show nested question if the node is expanded
      const showNestedQuestion = isExpanded && node.nextQuestion;
      
      // Determine if this is a looping node
      const isLoopNode = isLooping && node.isLoop;
      
      // Calculate position in the expanded nodes list for progressive shift
      const expandedIndex = expandedNodes.findIndex(path => path.join('-') === currentPath.join('-'));
      const nodeDepth = expandedIndex !== -1 ? expandedIndex + 1 : 0;
      
      return (
        <ProgressiveShiftWrapper
          key={pathKey}
          depth={nodeDepth}
          xShiftFactor={rightProgression ? xShiftFactor : 0}
          yShiftFactor={rightProgression ? yShiftFactor : 0}
          className={`dialogue-node-wrapper depth-${nodeDepth} ${isLoopNode ? 'looping-node' : ''}`}
        >
          <DialogueNode
            node={node}
            depth={depth}
            isActive={activeNodePath.join('-') === currentPath.join('-')}
            isLast={index === nodes.length - 1}
            onExpand={(expanded) => handleNodeExpand(node, expanded, currentPath)}
            expanded={isExpanded}
            showNestedQuestion={showNestedQuestion}
            path={currentPath}
            isLoopNode={isLoopNode}
            loopTransition={getLoopTransition()}
            philosophical={philosophical}
            terminal={terminal}
          >
            {/* Render nested question */}
            {showNestedQuestion && renderDialogueNodes([node.nextQuestion], depth + 1, [...currentPath, 'nextQuestion'])}
          </DialogueNode>
        </ProgressiveShiftWrapper>
      );
    });
  }, [
    expandedNodes, activeNodePath, handleNodeExpand, getLoopTransition,
    isLooping, philosophical, terminal, rightProgression, xShiftFactor, yShiftFactor
  ]);
  
  // Handle navigation buttons
  const handleNavigateNext = useCallback(() => {
    if (disableNext) return;
    
    // Trigger a glitch effect when navigating
    setIsGlitching(true);
    setTimeout(() => setIsGlitching(false), 500);
    
    navigateNext();
  }, [disableNext, navigateNext]);
  
  const handleNavigatePrevious = useCallback(() => {
    if (disablePrev) return;
    
    // Trigger a glitch effect when navigating
    setIsGlitching(true);
    setTimeout(() => setIsGlitching(false), 500);
    
    navigatePrevious();
  }, [disablePrev, navigatePrevious]);
  
  // Function to reset dialogue state and position
  const handleResetDialogue = useCallback(() => {
    // Trigger a strong glitch effect when resetting
    setIsGlitching(true);
    setTimeout(() => setIsGlitching(false), 800);
    
    // Reset dialogue state
    resetDialogue();
    
    // Reset loop state if looping
    if (isLooping) {
      resetLoopState();
    }
    
    // Scroll to top of dialogue
    if (contentRef.current) {
      contentRef.current.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
    }
  }, [resetDialogue, isLooping, resetLoopState]);
  
  if (!isReady) {
    return (
      <DialogueContainer ref={containerRef}>
        <div className="dialogue-loading">
          <p>Initializing philosophical dialogue system...</p>
        </div>
      </DialogueContainer>
    );
  }
  
  return (
    <DialogueContainer 
      ref={containerRef}
      className={`dialogue-system ${isLooping ? 'looping' : ''} ${isTransitioning ? 'transitioning' : ''} ${isGlitching ? 'glitching' : ''}`}
      isLooping={isLooping}
    >
      {/* Header content */}
      <DialogueHeader>
        <div className="dialogue-title">Philosophical Dialogue</div>
        <span className="dialogue-depth">
          Depth: {getCurrentDepth()}
        </span>
        {isLooping && (
          <span className="dialogue-looping">
            ∞ Paradox Detected ∞
          </span>
        )}
      </DialogueHeader>
      
      {/* Main dialogue content */}
      <DialogueContent 
        ref={contentRef}
        depth={getCurrentDepth()}
      >
        {getDialogueNodes()}
      </DialogueContent>
      
      {/* Paradoxical insight */}
      {isLooping && (
        <ParadoxInsight show={showInsight}>
          {paradoxInsight}
        </ParadoxInsight>
      )}
      
      {/* Navigation controls */}
      <DialogueNavigation>
        <button 
          onClick={handleNavigatePrevious}
          disabled={disablePrev}
          aria-label="Previous question"
        >
          ← Previous
        </button>
        
        {/* Add reset button when dialogue is deep enough */}
        {getCurrentDepth() > 3 && (
          <button
            onClick={handleResetDialogue}
            className="reset-button"
            aria-label="Reset dialogue"
            style={{ marginLeft: 'auto', marginRight: 'auto' }}
          >
            ↺ Reset
          </button>
        )}
        
        <button
          onClick={handleNavigateNext}
          disabled={disableNext}
          aria-label="Next question"
        >
          Next →
        </button>
      </DialogueNavigation>
      
      {/* Ambient thought flow animations when looping */}
      {isLooping && (
        <ThoughtFlowEffect 
          active={true}
          particleCount={10}
          bubbleCount={5}
          origin="center"
          zIndex={1}
          opacity={0.3}
        />
      )}
      
      {/* Scanline effect overlay */}
      <DialogueScanlines isLooping={isLooping} />
    </DialogueContainer>
  );
};

export default DialogueSystem;
