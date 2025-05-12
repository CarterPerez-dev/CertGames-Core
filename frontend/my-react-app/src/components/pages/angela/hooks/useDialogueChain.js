// frontend/my-react-app/src/components/pages/angela/hooks/useDialogueChain.js
import { useState, useCallback, useEffect } from 'react';

/**
 * Custom hook to manage the dialogue chain and navigation
 * 
 * This hook handles the recursive dialogue structure and navigation between nodes,
 * while tracking the history of revealed information.
 */
export const useDialogueChain = (initialDialogue, initialDepth = 0) => {
  const [dialogue, setDialogue] = useState(initialDialogue || []);
  const [expandedNodes, setExpandedNodes] = useState([]);
  const [activeNodePath, setActiveNodePath] = useState([]);
  const [dialogueHistory, setDialogueHistory] = useState([]);
  
  // Initialize with the first node expanded
  useEffect(() => {
    if (dialogue && dialogue.length > 0 && expandedNodes.length === 0) {
      setExpandedNodes([[0]]);
      setActiveNodePath([0]);
    }
  }, [dialogue]);
  
  // Get the current depth of the dialogue (how many nested levels are expanded)
  const getCurrentDepth = useCallback(() => {
    return expandedNodes.length;
  }, [expandedNodes]);
  
  // Get the total number of nodes in the dialogue (both expanded and unexpanded)
  const getTotalNodesCount = useCallback(() => {
    const countNodes = (node) => {
      if (!node || !node.nextQuestion) return 1;
      return 1 + countNodes(node.nextQuestion);
    };
    
    return dialogue.reduce((total, node) => total + countNodes(node), 0);
  }, [dialogue]);
  
  // Get a node by its path
  const getNodeByPath = useCallback((path) => {
    if (!path || path.length === 0 || !dialogue || dialogue.length === 0) {
      return null;
    }
    
    let currentNode = dialogue[path[0]];
    
    // Navigate through the path to find the node
    for (let i = 1; i < path.length; i++) {
      const segment = path[i];
      if (segment === 'nextQuestion' && currentNode.nextQuestion) {
        currentNode = currentNode.nextQuestion;
      } else if (typeof segment === 'number' && currentNode[segment]) {
        currentNode = currentNode[segment];
      } else {
        return null; // Invalid path
      }
    }
    
    return currentNode;
  }, [dialogue]);
  
  // Expand a node, adding its path to expandedNodes
  const expandNode = useCallback((node, path) => {
    // Check if the node is already expanded
    const isAlreadyExpanded = expandedNodes.some(
      expandedPath => expandedPath.join('-') === path.join('-')
    );
    
    if (isAlreadyExpanded) return;
    
    // Add to expanded nodes
    setExpandedNodes(prev => [...prev, path]);
    
    // Set as active node
    setActiveNodePath(path);
    
    // Add to dialogue history
    setDialogueHistory(prev => {
      // Ensure we don't add duplicates
      if (prev.some(item => item.path.join('-') === path.join('-'))) {
        return prev;
      }
      return [...prev, { node, path, timestamp: Date.now() }];
    });
  }, [expandedNodes]);
  
  // Collapse a node, removing its path and all descendant paths from expandedNodes
  const collapseNode = useCallback((node, path) => {
    const pathStr = path.join('-');
    
    // Remove this node and all descendant nodes
    setExpandedNodes(prev => 
      prev.filter(expandedPath => {
        const expandedPathStr = expandedPath.join('-');
        return !expandedPathStr.startsWith(pathStr);
      })
    );
    
    // Set active node to the closest parent
    const parentPath = path.slice(0, -1);
    if (parentPath.length > 0) {
      setActiveNodePath(parentPath);
    } else {
      // If no parent, set to first node
      setActiveNodePath([0]);
    }
  }, []);
  
  // Toggle a node's expanded state
  const toggleNode = useCallback((node, path) => {
    const isExpanded = expandedNodes.some(
      expandedPath => expandedPath.join('-') === path.join('-')
    );
    
    if (isExpanded) {
      collapseNode(node, path);
    } else {
      expandNode(node, path);
    }
  }, [expandedNodes, expandNode, collapseNode]);
  
  // Reset the dialogue to initial state
  const resetDialogue = useCallback(() => {
    setExpandedNodes([[0]]);
    setActiveNodePath([0]);
    setDialogueHistory([]);
  }, []);
  
  // Navigate to the next node in the dialogue
  const navigateNext = useCallback(() => {
    if (!dialogue || dialogue.length === 0) return;
    
    // Get the current node by active path
    const currentNode = getNodeByPath(activeNodePath);
    
    if (!currentNode) return;
    
    // If current node has a next question, expand it
    if (currentNode.nextQuestion) {
      const nextPath = [...activeNodePath, 'nextQuestion'];
      expandNode(currentNode.nextQuestion, nextPath);
      return;
    }
    
    // Otherwise try to move to the next sibling
    const parentPath = activeNodePath.slice(0, -1);
    const lastSegment = activeNodePath[activeNodePath.length - 1];
    
    if (typeof lastSegment === 'number' && parentPath.length === 0) {
      // We're at a root level node, try to move to the next root node
      const nextIndex = lastSegment + 1;
      if (nextIndex < dialogue.length) {
        const nextPath = [nextIndex];
        expandNode(dialogue[nextIndex], nextPath);
      }
    }
    // For nested nodes, we'd need more complex navigation logic here
    // which would depend on the specific structure of our dialogue data
  }, [dialogue, activeNodePath, getNodeByPath, expandNode]);
  
  // Navigate to the previous node in the dialogue
  const navigatePrevious = useCallback(() => {
    if (expandedNodes.length <= 1) return; // Don't go beyond the first node
    
    // Remove the last expanded node
    setExpandedNodes(prev => prev.slice(0, -1));
    
    // Set active node to the new last expanded node
    setActiveNodePath(prev => {
      const newPath = expandedNodes[expandedNodes.length - 2];
      return newPath || prev;
    });
  }, [expandedNodes]);
  
  return {
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
  };
};

// frontend/my-react-app/src/components/pages/angela/hooks/useInfiniteLoop.js
import { useState, useCallback, useEffect, useRef } from 'react';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

/**
 * Custom hook to manage the infinite philosophical loop
 * 
 * Creates the illusory recursive experience of falling deeper into the loop
 * while actually creating a carefully crafted cycle of nodes
 */
export const useInfiniteLoop = (loopAfterDepth = 20) => {
  const [isLooping, setIsLooping] = useState(false);
  const [loopIndex, setLoopIndex] = useState(0);
  const [loopCycles, setLoopCycles] = useState(0);
  const [loopPattern, setLoopPattern] = useState([]);
  const [lastTransition, setLastTransition] = useState('none');
  
  const loopStartTimestamp = useRef(null);
  const loopTransitions = [
    'spiral', 'vortex', 'paradox', 'reflection', 'enlightenment', 'recursion'
  ];
  
  // Start the infinite loop
  const startLoop = useCallback(() => {
    setIsLooping(true);
    setLoopIndex(0);
    setLoopCycles(0);
    loopStartTimestamp.current = Date.now();
    
    // Generate a pseudorandom pattern for the loop
    const patternLength = Math.floor(Math.random() * 3) + 3; // 3-5 nodes in the loop
    setLoopPattern(Array.from({ length: patternLength }, () => Math.random()));
  }, []);
  
  // Advance to the next state in the loop
  const advanceLoop = useCallback(() => {
    setLoopIndex(prevIndex => {
      const nextIndex = (prevIndex + 1) % loopPattern.length;
      
      // If we completed a cycle
      if (nextIndex === 0) {
        setLoopCycles(prev => prev + 1);
      }
      
      return nextIndex;
    });
    
    // Choose a new transition effect
    const availableTransitions = loopTransitions.filter(t => t !== lastTransition);
    const newTransition = availableTransitions[Math.floor(Math.random() * availableTransitions.length)];
    setLastTransition(newTransition);
  }, [loopPattern.length, lastTransition]);
  
  // Check if we should enter a new phase of the loop
  const shouldEnterNewLoopPhase = useCallback(() => {
    if (!isLooping) return false;
    
    // Based on loop duration and cycles
    const loopDuration = Date.now() - (loopStartTimestamp.current || 0);
    return loopDuration > 60000 * (loopCycles + 1); // New phase every minute, scaled by cycles
  }, [isLooping, loopCycles]);
  
  // Get the current transition effect
  const getLoopTransition = useCallback(() => {
    return lastTransition;
  }, [lastTransition]);
  
  // Create a loop path through the dialogue
  const createLoopPath = useCallback((dialogue, history) => {
    if (!isLooping || !dialogue || dialogue.length === 0 || history.length < loopAfterDepth) {
      return dialogue;
    }
    
    // Create a hybrid path that gives the illusion of progress but actually loops
    const recentHistory = history.slice(-5);
    const olderHistory = history.slice(-15, -5);
    
    // Build a loop by mixing recent nodes with modified older nodes
    const loopItems = [];
    
    // Always include the most recent node
    loopItems.push(recentHistory[recentHistory.length - 1]);
    
    // Add a few more recent nodes
    for (let i = recentHistory.length - 2; i >= 0; i--) {
      if (Math.random() > 0.3) { // 70% chance to include each recent node
        loopItems.push(recentHistory[i]);
      }
    }
    
    // Add some older nodes but modified to create déjà vu effect
    for (let i = 0; i < olderHistory.length; i++) {
      if (Math.random() > 0.7) { // 30% chance to include each older node
        const originalNode = olderHistory[i].node;
        
        // Create a modified version with subtle changes
        const modifiedNode = {
          ...originalNode,
          isLoop: true, // Mark as a loop node for special styling
          type: originalNode.type === THEME.philosophicalConcepts.PARADOX 
            ? THEME.philosophicalConcepts.PARADOX 
            : Math.random() > 0.5 ? originalNode.type : THEME.philosophicalConcepts.PARADOX,
        };
        
        loopItems.push({
          node: modifiedNode,
          path: olderHistory[i].path,
          timestamp: Date.now()
        });
      }
    }
    
    // Mix the original dialogue with loop items
    const result = [...dialogue];
    
    // Insert loop nodes into the normal dialogue flow
    loopItems.forEach((item, index) => {
      // Find the right place to insert
      const insertIndex = Math.min(
        result.length - 1,
        Math.floor(Math.random() * result.length)
      );
      
      // Modify the nextQuestion links to create the loop
      if (index > 0) {
        const previousNode = result[insertIndex - 1 >= 0 ? insertIndex - 1 : result.length - 1];
        if (previousNode) {
          previousNode.nextQuestion = item.node;
        }
      }
      
      result.splice(insertIndex, 0, item.node);
    });
    
    return result;
  }, [isLooping, loopAfterDepth]);
  
  // Reset the loop state
  const resetLoopState = useCallback(() => {
    setIsLooping(false);
    setLoopIndex(0);
    setLoopCycles(0);
    setLoopPattern([]);
    setLastTransition('none');
    loopStartTimestamp.current = null;
  }, []);
  
  return {
    isLooping,
    loopIndex,
    loopCycles,
    startLoop,
    advanceLoop,
    getLoopTransition,
    shouldEnterNewLoopPhase,
    createLoopPath,
    resetLoopState
  };
};

// frontend/my-react-app/src/components/pages/angela/hooks/useParadoxEffects.js
import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * Custom hook to manage psychedelic visual effects for the philosophical paradox experience
 * 
 * Controls a variety of visual distortions that intensify as the user goes deeper
 * into philosophical paradoxes
 */
export const useParadoxEffects = (paradoxLevel = 0, containerRef) => {
  const [effectsEnabled, setEffectsEnabled] = useState(true);
  const [intensity, setIntensity] = useState(0);
  const [effectType, setEffectType] = useState('subtle');
  const requestRef = useRef(null);
  const timeRef = useRef(0);
  
  // Available effect types
  const effectTypes = [
    'subtle',      // Slight distortions and color shifts
    'ripple',      // Wave-like distortions emanating from center
    'fractal',     // Self-similar patterns that repeat at different scales
    'kaleidoscope', // Symmetrical pattern reflections
    'glitch',      // Digital corruption-style effects
    'vortex',      // Spinning distortion pulling toward center
    'dissolution', // Elements gradually break apart and reform
    'recursion'    // Nested repetition effects
  ];
  
  // Update intensity based on paradox level
  useEffect(() => {
    // Gradually increase intensity to create smooth transitions
    const targetIntensity = Math.min(1.0, paradoxLevel / 10);
    
    const updateIntensity = () => {
      setIntensity(prev => {
        if (Math.abs(prev - targetIntensity) < 0.01) {
          return targetIntensity;
        }
        return prev + (targetIntensity - prev) * 0.05;
      });
    };
    
    const interval = setInterval(updateIntensity, 100);
    return () => clearInterval(interval);
  }, [paradoxLevel]);
  
  // Change effect type periodically, more frequently at higher levels
  useEffect(() => {
    if (paradoxLevel <= 1) {
      setEffectType('subtle');
      return;
    }
    
    // Change effect type more frequently with higher paradox levels
    const changeInterval = Math.max(10000, 30000 - (paradoxLevel * 2000));
    
    const changeEffectType = () => {
      const availableEffects = effectTypes.filter(type => type !== effectType);
      const newEffect = availableEffects[Math.floor(Math.random() * availableEffects.length)];
      setEffectType(newEffect);
    };
    
    const interval = setInterval(changeEffectType, changeInterval);
    return () => clearInterval(interval);
  }, [paradoxLevel, effectType]);
  
  // Apply visual effects to the container
  const applyEffects = useCallback(() => {
    if (!containerRef.current || !effectsEnabled) return;
    
    // Update time reference
    timeRef.current += 0.01;
    const time = timeRef.current;
    
    // Get container dimensions
    const width = containerRef.current.clientWidth;
    const height = containerRef.current.clientHeight;
    
    // Apply different effects based on type and intensity
    let effectStyle = '';
    
    switch (effectType) {
      case 'ripple':
        // Wave-like ripples
        const rippleX = Math.sin(time * 0.5) * 50 * intensity;
        const rippleY = Math.cos(time * 0.7) * 50 * intensity;
        effectStyle = `
          filter: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg"><filter id="ripple"><feDisplacementMap in="SourceGraphic" in2="noise" scale="${20 * intensity}" xChannelSelector="R" yChannelSelector="G"/></filter></svg>#ripple');
          transform: translate(${rippleX}px, ${rippleY}px);
        `;
        break;
        
      case 'fractal':
        // Fractal-like self-similar distortions
        const fractalScale = 1 + (Math.sin(time) * 0.1 * intensity);
        const fractalRotate = Math.sin(time * 0.2) * 5 * intensity;
        effectStyle = `
          transform: scale(${fractalScale}) rotate(${fractalRotate}deg);
          filter: hue-rotate(${Math.sin(time * 0.1) * 30 * intensity}deg);
        `;
        break;
        
      case 'kaleidoscope':
        // Symmetrical reflections
        effectStyle = `
          filter: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg"><filter id="kaleidoscope"><feConvolveMatrix order="8,8" kernelMatrix="1 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 1" preserveAlpha="true"/></filter></svg>#kaleidoscope');
          transform-origin: center;
          transform: rotate(${time * 10 * intensity}deg);
        `;
        break;
        
      case 'glitch':
        // Digital glitch effect
        const glitchX = Math.random() > 0.7 ? Math.random() * 10 * intensity : 0;
        const glitchY = Math.random() > 0.7 ? Math.random() * 10 * intensity : 0;
        const hueRotate = Math.random() > 0.5 ? Math.random() * 360 * intensity : 0;
        effectStyle = `
          transform: translate(${glitchX}px, ${glitchY}px);
          filter: hue-rotate(${hueRotate}deg) brightness(${1 + Math.random() * 0.4 * intensity});
        `;
        break;
        
      case 'vortex':
        // Spinning vortex effect
        effectStyle = `
          transform-origin: center;
          transform: rotate(${time * 20 * intensity}deg) scale(${1 + Math.sin(time) * 0.1 * intensity});
          filter: blur(${Math.sin(time * 2) * 5 * intensity}px);
        `;
        break;
        
      case 'dissolution':
        // Elements breaking apart
        effectStyle = `
          opacity: ${0.7 + Math.sin(time * 3) * 0.3 * intensity};
          filter: contrast(${1 + Math.sin(time) * 0.5 * intensity}) brightness(${1 + Math.cos(time * 0.7) * 0.3 * intensity});
          transform: skew(${Math.sin(time) * 10 * intensity}deg, ${Math.cos(time * 0.5) * 5 * intensity}deg);
        `;
        break;
        
      case 'recursion':
        // Nested repetition
        effectStyle = `
          transform-origin: center;
          transform: scale(${1 + Math.sin(time * 0.5) * 0.2 * intensity}) rotate(${Math.sin(time * 0.3) * 10 * intensity}deg);
          filter: saturate(${1 + Math.sin(time) * 0.5 * intensity}) brightness(${1 + Math.cos(time * 0.7) * 0.2 * intensity});
        `;
        break;
        
      case 'subtle':
      default:
        // Subtle distortions - default fallback
        effectStyle = `
          filter: hue-rotate(${Math.sin(time * 0.2) * 20 * intensity}deg) brightness(${1 + Math.sin(time * 0.5) * 0.1 * intensity});
          transform: scale(${1 + Math.sin(time * 0.1) * 0.02 * intensity});
        `;
        break;
    }
    
    // Apply the style to the container
    containerRef.current.style.cssText += effectStyle;
    
    // Continue animation loop
    requestRef.current = requestAnimationFrame(applyEffects);
  }, [effectsEnabled, effectType, intensity, containerRef]);
  
  // Set up and clean up animation frame
  useEffect(() => {
    requestRef.current = requestAnimationFrame(applyEffects);
    return () => {
      if (requestRef.current) {
        cancelAnimationFrame(requestRef.current);
      }
    };
  }, [applyEffects]);
  
  // Toggle effects on/off
  const toggleEffects = useCallback(() => {
    setEffectsEnabled(prev => !prev);
  }, []);
  
  // Force a specific effect type
  const setEffect = useCallback((type) => {
    if (effectTypes.includes(type)) {
      setEffectType(type);
    }
  }, []);
  
  return {
    intensity,
    effectType,
    toggleEffects,
    setEffect,
    effectsEnabled
  };
};
