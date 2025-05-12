// frontend/my-react-app/src/components/pages/angela/components/DialogueSystem.js
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { DialogueContainer } from '../styles/DialogueStyles';
import DialogueNode from './DialogueNode';
import DialogueExpansion from './DialogueExpansion';
import { useDialogueChain } from '../hooks/useDialogueChain';
import { useInfiniteLoop } from '../hooks/useInfiniteLoop';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

/**
 * DialogueSystem Component
 * 
 * The main controller for the philosophical Socratic dialogue system.
 * This component orchestrates the dialogue chain, expansions, transitions,
 * and the paradoxical loop effect.
 * 
 * @param {Object[]} dialogueData - The initial dialogue tree data
 * @param {boolean} philosophical - Whether to use philosophical styling
 * @param {boolean} terminal - Whether to use terminal-style formatting
 * @param {boolean} autoAdvance - Whether to auto-advance the dialogue initially
 * @param {boolean} enableLooping - Whether to enable the paradoxical loop effect
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
  loopAfterDepth = 30,
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
    resetDialogue
  } = useDialogueChain(dialogueData, initialDepth);
  
  const {
    isLooping,
    startLoop,
    endLoop,
    getLoopTransition,
    getLoopIndex,
    createLoopPath
  } = useInfiniteLoop(loopAfterDepth);
  
  // Internal state for tracking
  const [isReady, setIsReady] = useState(false);
  const [autoAdvanceActive, setAutoAdvanceActive] = useState(autoAdvance);
  const [autoAdvanceDelay, setAutoAdvanceDelay] = useState(1000); // milliseconds
  const [currentEffect, setCurrentEffect] = useState('pulse');
  const [isTransitioning, setIsTransitioning] = useState(false);
  const containerRef = useRef(null);
  
  // Setup dialogue system
  useEffect(() => {
    if (dialogueData && dialogueData.length > 0) {
      setIsReady(true);
    }
  }, [dialogueData]);
  
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
        
        // Automatically expand the next node
        const nextNodePath = [...activeNodePath.slice(0, -1), activeNodePath[activeNodePath.length - 1] + 1];
        const nextNode = getNodeByPath(nextNodePath);
        if (nextNode) {
          expandNode(nextNode, nextNodePath);
        } else {
          setAutoAdvanceActive(false);
        }
      }, autoAdvanceDelay);
    }
    
    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [autoAdvanceActive, isReady, activeNodePath, expandNode, getNodeByPath, getCurrentDepth, autoAdvanceDelay]);
  
  // Check if we should start the loop
  useEffect(() => {
    if (enableLooping && getCurrentDepth() >= loopAfterDepth && !isLooping) {
      startLoop();
    }
  }, [enableLooping, getCurrentDepth, loopAfterDepth, isLooping, startLoop]);
  
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
    
    // Check if we need to handle the infinite loop
    if (enableLooping && getCurrentDepth() >= loopAfterDepth) {
      if (!isLooping) {
        startLoop();
      } else {
        // When already looping, apply special loop transition
        const loopTransition = getLoopTransition();
        setCurrentEffect(loopTransition);
      }
    }
  }, [
    isTransitioning, expandNode, collapseNode, getCurrentDepth, getTotalNodesCount,
    enableLooping, loopAfterDepth, isLooping, startLoop, getLoopTransition, onDialogueChange
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
      const isLoopNode = isLooping && getLoopIndex() === depth;
      
      return (
        <DialogueNode
          key={`node-${pathKey}`}
          node={node}
          depth={depth}
          isActive={activeNodePath.join('-') === currentPath.join('-')}
          isLast={index === nodes.length - 1}
          onExpand={handleNodeExpand}
          onNestedExpand={handleNodeExpand}
          expanded={isExpanded}
          showNestedQuestion={showNestedQuestion}
          path={currentPath}
          isTransitioning={isTransitioning}
          transitionEffect={isLoopNode ? 'paradox' : currentEffect}
          autoExpand={autoAdvanceActive && depth === 0 && index === 0}
          expandDelay={autoAdvanceDelay}
          philosophical={philosophical}
          terminal={terminal}
        />
      );
    });
  }, [
    expandedNodes, handleNodeExpand, autoAdvanceActive, autoAdvanceDelay,
    isTransitioning, currentEffect, isLooping, getLoopIndex, philosophical, terminal
  ]);
  
  // Add event handlers for keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Only handle keys if the dialogue is ready
      if (!isReady) return;
      
      switch (e.key) {
        case 'ArrowDown':
          // Navigate to next node
          break;
        case 'ArrowUp':
          // Navigate to previous node
          break;
        case 'ArrowRight':
        case 'Enter':
          // Expand current node
          break;
        case 'ArrowLeft':
        case 'Escape':
          // Collapse current node
          break;
        default:
          break;
      }
    };
    
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isReady]);
  
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
      fullWidth={false}
      centered={true}
    >
      {/* Header content */}
      <div className="dialogue-header">
        <span className="dialogue-depth">
          Depth: {getCurrentDepth()}
        </span>
        {isLooping && (
          <span className="dialogue-looping">
            ∞ Paradox Detected ∞
          </span>
        )}
      </div>
      
      {/* Main dialogue content */}
      <div className="dialogue-content">
        {getDialogueNodes()}
      </div>
      
      {/* Scanline effect overlay */}
      <div className="dialogue-scanlines"></div>
    </DialogueContainer>
  );
};

export default DialogueSystem;
