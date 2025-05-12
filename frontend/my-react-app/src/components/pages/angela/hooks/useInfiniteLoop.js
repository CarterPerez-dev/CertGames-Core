// frontend/my-react-app/src/components/pages/angela/hooks/useInfiniteLoop.js
import { useState, useCallback, useRef, useEffect } from 'react';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

/**
 * useInfiniteLoop Hook
 * 
 * Custom hook that manages the paradoxical infinite loop effect in the
 * dialogue system. It creates a seamless loop where the user feels like they're
 * continually going deeper, but actually loops back to previous content in a
 * way that's difficult to detect.
 * 
 * @param {number} loopAfterDepth - After what depth to start the loop
 * @param {number} loopLength - How many nodes to include in the loop
 * @param {function} onLoopStarted - Callback when loop starts
 * @param {function} onLoopCycle - Callback when a loop cycle completes
 * @returns {Object} - Functions and state for managing the infinite loop
 */
export const useInfiniteLoop = (
  loopAfterDepth = 30,
  loopLength = 10,
  onLoopStarted = null,
  onLoopCycle = null
) => {
  // Whether the loop is active
  const [isLooping, setIsLooping] = useState(false);
  
  // Where we are in the loop cycle (0 to loopLength-1)
  const [loopIndex, setLoopIndex] = useState(0);
  
  // How many times we've cycled through the loop
  const [loopCycles, setLoopCycles] = useState(0);
  
  // Cache of nodes used in the loop
  const loopCache = useRef(new Map());
  
  // Random transitions to use for loop effect
  const transitions = useRef([
    'glitch',
    'paradox',
    'void',
    'enlightenment',
    'infinite'
  ]);
  
  /**
   * Start the infinite loop effect
   */
  const startLoop = useCallback(() => {
    setIsLooping(true);
    setLoopIndex(0);
    setLoopCycles(0);
    
    // Notify if callback provided
    if (onLoopStarted) {
      onLoopStarted();
    }
  }, [onLoopStarted]);
  
  /**
   * End the infinite loop effect
   */
  const endLoop = useCallback(() => {
    setIsLooping(false);
    setLoopIndex(0);
    setLoopCycles(0);
    loopCache.current.clear();
  }, []);
  
  /**
   * Get the current loop index
   * 
   * @returns {number} - The current loop index
   */
  const getLoopIndex = useCallback(() => {
    return loopIndex;
  }, [loopIndex]);
  
  /**
   * Advance to the next point in the loop
   */
  const advanceLoop = useCallback(() => {
    setLoopIndex((prevIndex) => {
      const nextIndex = (prevIndex + 1) % loopLength;
      
      // If we've completed a cycle
      if (nextIndex === 0) {
        setLoopCycles((prevCycles) => prevCycles + 1);
        
        // Notify if callback provided
        if (onLoopCycle) {
          onLoopCycle(loopCycles + 1);
        }
      }
      
      return nextIndex;
    });
  }, [loopLength, loopCycles, onLoopCycle]);
  
  /**
   * Get a transition effect for the current loop point
   * 
   * @returns {string} - The transition effect name
   */
  const getLoopTransition = useCallback(() => {
    // Deterministic but seemingly random transitions
    const transitionIndex = (loopIndex * 7 + loopCycles * 3) % transitions.current.length;
    return transitions.current[transitionIndex];
  }, [loopIndex, loopCycles]);
  
  /**
   * Determine if we should enter a new loop phase
   * 
   * @param {number} depth - The current dialogue depth
   * @returns {boolean} - Whether we should enter a new loop phase
   */
  const shouldEnterNewLoopPhase = useCallback((depth) => {
    if (!isLooping) return false;
    
    // If we've completed at least one cycle and reached a good transition point
    return loopCycles > 0 && loopIndex === 0 && depth >= loopAfterDepth + loopLength;
  }, [isLooping, loopCycles, loopIndex, loopAfterDepth, loopLength]);
  
  /**
   * Create a path that gives the illusion of infinite depth but actually loops
   * 
   * @param {Object[]} dialogue - Main dialogue tree
   * @param {Object[]} history - Dialogue interaction history
   * @returns {Object[]} - A modified dialogue tree that creates a loop
   */
  const createLoopPath = useCallback((dialogue, history) => {
    if (!isLooping || !dialogue || !history) {
      return dialogue;
    }
    
    // If this is the first time creating the loop
    if (loopCache.current.size === 0) {
      // Collect nodes to use in the loop
      let startIndex = Math.max(0, history.length - loopLength);
      for (let i = startIndex; i < history.length; i++) {
        if (history[i] && history[i].node) {
          // Cache the node with a loop index
          const loopKey = `loop-${i - startIndex}`;
          loopCache.current.set(loopKey, {
            ...history[i].node,
            // Mark as a loop node for special styling
            isLoop: true,
            // Add a type for philosophical theming
            type: i % 2 === 0 ? THEME.philosophicalConcepts.PARADOX : THEME.philosophicalConcepts.RECURSION
          });
        }
      }
    }
    
    // Create a copy of the dialogue to modify
    let modifiedDialogue = [...dialogue];
    
    // Now modify the next question of the last node in the tree
    // to create the loop back to earlier content
    const findAndModifyLastNode = (nodes) => {
      if (!nodes || nodes.length === 0) return;
      
      // Focus on the active branch - this is usually the first node at each level
      const node = nodes[0];
      
      if (node.nextQuestion) {
        // Recursively go to the next level
        findAndModifyLastNode([node.nextQuestion]);
      } else {
        // We've reached the deepest node, create the loop
        const loopKey = `loop-${loopIndex}`;
        const loopNode = loopCache.current.get(loopKey);
        
        if (loopNode) {
          // Create a modified copy with the loop flags
          const modifiedNode = {
            ...node,
            nextQuestion: {
              ...loopNode,
              // Ensure these flags are set
              isLoop: true,
              type: THEME.philosophicalConcepts.PARADOX
            }
          };
          
          // Replace the node in the array
          nodes[0] = modifiedNode;
        }
      }
    };
    
    // Apply the modification
    findAndModifyLastNode(modifiedDialogue);
    
    return modifiedDialogue;
  }, [isLooping, loopIndex]);
  
  /**
   * Reset the loop to a specific state
   * 
   * @param {number} newIndex - New loop index
   * @param {number} newCycles - New loop cycles count
   */
  const resetLoopState = useCallback((newIndex = 0, newCycles = 0) => {
    setLoopIndex(newIndex);
    setLoopCycles(newCycles);
    loopCache.current.clear();
  }, []);
  
  /**
   * Check if we've seen this exact node before in the loop
   * 
   * @param {Object} node - The node to check
   * @returns {boolean} - Whether this exact node has been seen before
   */
  const isRepeatingNode = useCallback((node) => {
    if (!node || !isLooping) return false;
    
    // Check each cached node for a match
    for (const cachedNode of loopCache.current.values()) {
      if (cachedNode.question === node.question && 
          cachedNode.answer === node.answer) {
        return true;
      }
    }
    
    return false;
  }, [isLooping]);
  
  /**
   * Generate a seemingly random philosophical type for a loop node
   * 
   * @returns {string} - A philosophical concept from THEME.philosophicalConcepts
   */
  const generateLoopNodeType = useCallback(() => {
    // Concepts that work well in a loop
    const loopConcepts = [
      THEME.philosophicalConcepts.PARADOX,
      THEME.philosophicalConcepts.RECURSION,
      THEME.philosophicalConcepts.INFINITE_REGRESS,
      THEME.philosophicalConcepts.SELF_REFERENCE,
      THEME.philosophicalConcepts.FRACTAL
    ];
    
    // Deterministic but seemingly random selection
    const conceptIndex = (loopIndex * 5 + loopCycles * 2) % loopConcepts.length;
    return loopConcepts[conceptIndex];
  }, [loopIndex, loopCycles]);
  
  return {
    isLooping,
    loopIndex,
    loopCycles,
    startLoop,
    endLoop,
    advanceLoop,
    getLoopIndex,
    getLoopTransition,
    shouldEnterNewLoopPhase,
    createLoopPath,
    resetLoopState,
    isRepeatingNode,
    generateLoopNodeType
  };
};

export default useInfiniteLoop;
