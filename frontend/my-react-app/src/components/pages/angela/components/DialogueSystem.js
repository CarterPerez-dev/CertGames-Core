// frontend/my-react-app/src/components/pages/angela/components/DialogueSystem.js
import React, { useState, useEffect, useRef, useCallback } from 'react';
import styled from '@emotion/styled';
import { keyframes } from '@emotion/react';
import DialogueNode from './DialogueNode';
import DialogueExpansion from './DialogueExpansion';
import { useDialogueChain } from '../hooks/useDialogueChain';
import { useInfiniteLoop } from '../hooks/useInfiniteLoop';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

// Enhanced animation for dialogue node
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

// Enhanced DialogueContainer with proper alignment and improved styling
const DialogueContainer = styled.div`
  max-width: 900px;
  margin: 0 auto; /* Center alignment */
  padding: 2rem;
  position: relative;
  border-radius: 8px;
  background: ${props => props.isLooping ? 
    `linear-gradient(to bottom, ${THEME.colors.bgPrimary}aa, ${THEME.colors.bgSecondary}aa)` :
    `linear-gradient(to bottom, ${THEME.colors.bgPrimary}, ${THEME.colors.bgSecondary}22)`
  };
  box-shadow: ${props => props.isLooping ? 
    `0 0 30px rgba(255, 51, 51, 0.2)` :
    'none'
  };
  transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
  
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
    border-radius: 8px;
    pointer-events: none;
  }
  
  /* Enhanced active state for looping */
  &.transitioning {
    animation: ${paradoxEffect} 1s linear;
  }
  
  &.looping {
    border: 1px solid ${THEME.colors.accentPrimary}44;
  }
  
  @media (max-width: 768px) {
    padding: 1.5rem 1rem;
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
  
  .dialogue-depth {
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 0.9rem;
    color: ${THEME.colors.textSecondary};
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

// Content container with improved scrolling behavior
const DialogueContent = styled.div`
  position: relative;
  max-height: 70vh;
  overflow-y: auto;
  padding-right: 8px;
  
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
  padding-right: ${props => props.depth * 15 + 20}px;
  transition: padding-right 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
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
  border-radius: 8px;
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
  }
`;

// Paradoxical insight that appears during looping
const ParadoxInsight = styled.div`
  font-family: ${THEME.typography.fontFamilyPhilosophical};
  font-style: italic;
  font-size: 0.9rem;
  color: ${THEME.colors.accentPrimary};
  margin-top: 1.5rem;
  text-align: center;
  opacity: ${props => props.show ? 1 : 0};
  transform: translateY(${props => props.show ? 0 : '10px'});
  transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
`;

/**
 * DialogueSystem Component
 * 
 * Enhanced dialogue system that manages the philosophical Socratic dialogue.
 * Implements rightward and downward progression for a schizophrenic dialogue effect,
 * with paradoxical loop transitions and improved visual styling.
 * 
 * @param {Object[]} dialogueData - Initial dialogue tree data
 * @param {boolean} philosophical - Whether to use philosophical styling
 * @param {boolean} terminal - Whether to use terminal-style formatting
 * @param {boolean} autoAdvance - Whether to auto-advance the dialogue initially
 * @param {boolean} enableLooping - Whether to enable the paradoxical loop effect
 * @param {boolean} rightProgression - Whether to enable rightward/downward progression
 * @param {number} loopAfterDepth - After what depth to start the loop
 * @param {number} initialDepth - Initial depth to display
 * @param {function} onDialogueChange - Callback for dialogue state changes
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
    generateLoopNodeType,
    generateParadoxInsight
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
  }, [dialogueData, isLooping, showInsight, generateParadoxInsight]);
  
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
    }
  }, [enableLooping, getCurrentDepth, loopAfterDepth, isLooping, startLoop]);
  
  // Update disable states for navigation buttons
  useEffect(() => {
    const depth = getCurrentDepth();
    setDisablePrev(depth <= 1);
    setDisableNext(false); // We can always go deeper in an infinite loop
  }, [expandedNodes, getCurrentDepth]);
  
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
      
      // Apply rightward progression styling
      let xOffset = 0;
      let yOffset = 0;
      
      if (rightProgression && isExpanded) {
        // Calculate how deep we are in the expanded nodes list
        const expandedIndex = expandedNodes.findIndex(path => path.join('-') === currentPath.join('-'));
        if (expandedIndex !== -1) {
          xOffset = (expandedIndex + 1) * 15; // Shift right by 15px per level
          yOffset = (expandedIndex + 1) * 10; // Shift down by 10px per level
        }
      }
      
      return (
        <div 
          key={pathKey}
          className={`dialogue-node-wrapper ${isLoopNode ? 'looping-node' : ''}`}
          style={{
            transform: `translate(${xOffset}px, ${yOffset}px)`,
            transition: 'all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1)',
            position: 'relative',
            zIndex: 100 - depth
          }}
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
        </div>
      );
    });
  }, [
    expandedNodes, activeNodePath, handleNodeExpand, getLoopTransition,
    isLooping, philosophical, terminal, rightProgression
  ]);
  
  // Handle navigation buttons
  const handleNavigateNext = useCallback(() => {
    if (disableNext) return;
    navigateNext();
  }, [disableNext, navigateNext]);
  
  const handleNavigatePrevious = useCallback(() => {
    if (disablePrev) return;
    navigatePrevious();
  }, [disablePrev, navigatePrevious]);
  
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
      className={`dialogue-system ${isLooping ? 'looping' : ''} ${isTransitioning ? 'transitioning' : ''}`}
      isLooping={isLooping}
    >
      {/* Header content */}
      <DialogueHeader>
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
        <button
          onClick={handleNavigateNext}
          disabled={disableNext}
          aria-label="Next question"
        >
          Next →
        </button>
      </DialogueNavigation>
      
      {/* Scanline effect overlay */}
      <DialogueScanlines isLooping={isLooping} />
    </DialogueContainer>
  );
};

export default DialogueSystem;
