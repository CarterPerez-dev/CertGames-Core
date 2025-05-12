// frontend/my-react-app/src/components/pages/angela/hooks/useDialogueChain.js
import { useState, useEffect, useCallback, useRef } from 'react';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

/**
 * useDialogueChain Hook
 * 
 * Custom hook that manages the state of the philosophical dialogue system.
 * It handles the dialogue tree structure, expansion state, active nodes,
 * and traversal through the dialogue chain.
 * 
 * @param {Object[]} initialDialogue - Initial dialogue data
 * @param {number} initialDepth - Initial depth to display
 * @returns {Object} - Functions and state for managing the dialogue
 */
export const useDialogueChain = (initialDialogue = [], initialDepth = 0) => {
  // Main dialogue tree
  const [dialogue, setDialogue] = useState(initialDialogue);
  
  // Tracks which nodes are expanded
  const [expandedNodes, setExpandedNodes] = useState([]);
  
  // Tracks the currently active node path
  const [activeNodePath, setActiveNodePath] = useState([0]);
  
  // History of dialogue interactions for loop detection
  const [dialogueHistory, setDialogueHistory] = useState([]);
  
  // Used for loop detection and management
  const visitedNodes = useRef(new Set());
  
  // Initialize dialogue on component mount or when initialDialogue changes
  useEffect(() => {
    if (initialDialogue && initialDialogue.length > 0) {
      setDialogue(initialDialogue);
      
      // Auto-expand to initial depth
      if (initialDepth > 0) {
        const initialExpanded = [];
        let currentPath = [0];
        
        for (let i = 0; i < initialDepth; i++) {
          initialExpanded.push([...currentPath]);
          if (i < initialDepth - 1) {
            // Get the node at the current path
            const node = getNodeByPath(currentPath);
            if (node && node.nextQuestion) {
              currentPath = [...currentPath.slice(0, -1), currentPath[currentPath.length - 1], 0];
            } else {
              break;
            }
          }
        }
        
        setExpandedNodes(initialExpanded);
      }
    }
  }, [initialDialogue, initialDepth]);
  
  /**
   * Gets a node by its path in the dialogue tree
   * 
   * @param {number[]} path - Path to the node
   * @returns {Object|null} - The node at the specified path or null if not found
   */
  const getNodeByPath = useCallback((path) => {
    if (!path || path.length === 0 || !dialogue || dialogue.length === 0) {
      return null;
    }
    
    try {
      let currentNode = dialogue[path[0]];
      
      // Navigate through nested questions
      for (let i = 1; i < path.length; i++) {
        const index = path[i];
        
        if (currentNode.nextQuestion) {
          // If this is asking for the next question
          if (i === path.length - 1) {
            currentNode = currentNode.nextQuestion;
          } 
          // If this is asking for a path within the next question
          else {
            currentNode = currentNode.nextQuestion;
          }
        } else {
          return null; // Path invalid, no next question
        }
      }
      
      return currentNode;
    } catch (error) {
      console.error('Error getting node by path:', error);
      return null;
    }
  }, [dialogue]);
  
  /**
   * Gets the current depth of expanded dialogue
   * 
   * @returns {number} - The current dialogue depth
   */
  const getCurrentDepth = useCallback(() => {
    return expandedNodes.length;
  }, [expandedNodes]);
  
  /**
   * Gets the total number of visible nodes
   * 
   * @returns {number} - The total number of visible nodes
   */
  const getTotalNodesCount = useCallback(() => {
    return expandedNodes.length + 1; // +1 for the root node
  }, [expandedNodes]);
  
  /**
   * Checks if a node is expanded
   * 
   * @param {number[]} path - Path to the node
   * @returns {boolean} - Whether the node is expanded
   */
  const isNodeExpanded = useCallback((path) => {
    if (!path || path.length === 0) return false;
    
    const pathStr = path.join('-');
    return expandedNodes.some(expandedPath => expandedPath.join('-') === pathStr);
  }, [expandedNodes]);
  
  /**
   * Expands a node in the dialogue tree
   * 
   * @param {Object} node - The node to expand
   * @param {number[]} path - Path to the node
   */
  const expandNode = useCallback((node, path) => {
    if (!node || !path || path.length === 0) return;
    
    // Add to expanded nodes if not already expanded
    if (!isNodeExpanded(path)) {
      // First, update the active node
      setActiveNodePath(path);
      
      // Record this node in history
      const pathStr = path.join('-');
      setDialogueHistory(prev => [...prev, { path: pathStr, node }]);
      visitedNodes.current.add(pathStr);
      
      // Then expand it
      setExpandedNodes(prev => [...prev, path]);
    }
  }, [isNodeExpanded]);
  
  /**
   * Collapses a node in the dialogue tree
   * 
   * @param {Object} node - The node to collapse
   * @param {number[]} path - Path to the node
   */
  const collapseNode = useCallback((node, path) => {
    if (!node || !path || path.length === 0) return;
    
    // Remove from expanded nodes
    setExpandedNodes(prev => 
      prev.filter(expandedPath => expandedPath.join('-') !== path.join('-'))
    );
    
    // Also collapse any child nodes
    setExpandedNodes(prev => 
      prev.filter(expandedPath => {
        // Keep only paths that don't start with the collapsed path
        const expandedPathStr = expandedPath.join('-');
        const pathStr = path.join('-');
        return !expandedPathStr.startsWith(pathStr + '-');
      })
    );
  }, []);
  
  /**
   * Toggles a node expansion state
   * 
   * @param {Object} node - The node to toggle
   * @param {number[]} path - Path to the node
   */
  const toggleNode = useCallback((node, path) => {
    if (isNodeExpanded(path)) {
      collapseNode(node, path);
    } else {
      expandNode(node, path);
    }
  }, [isNodeExpanded, collapseNode, expandNode]);
  
  /**
   * Get all children of a node
   * 
   * @param {Object} node - The parent node
   * @returns {Object[]} - Array of child nodes
   */
  const getNodeChildren = useCallback((node) => {
    if (!node) return [];
    
    const children = [];
    
    if (node.nextQuestion) {
      children.push(node.nextQuestion);
    }
    
    return children;
  }, []);
  
  /**
   * Reset the dialogue state
   */
  const resetDialogue = useCallback(() => {
    setExpandedNodes([]);
    setActiveNodePath([0]);
    setDialogueHistory([]);
    visitedNodes.current = new Set();
  }, []);
  
  /**
   * Checks if a node has been visited
   * 
   * @param {number[]} path - Path to check
   * @returns {boolean} - Whether the node has been visited
   */
  const hasVisitedNode = useCallback((path) => {
    const pathStr = path.join('-');
    return visitedNodes.current.has(pathStr);
  }, []);
  
  /**
   * Find the deepest expanded node path
   * 
   * @returns {number[]} - Path to the deepest expanded node
   */
  const findDeepestExpandedPath = useCallback(() => {
    if (expandedNodes.length === 0) return [0];
    
    // Sort by path length (descending)
    const sorted = [...expandedNodes].sort((a, b) => b.length - a.length);
    return sorted[0];
  }, [expandedNodes]);
  
  /**
   * Navigate to the next node in the dialogue
   * 
   * @returns {boolean} - Whether navigation was successful
   */
  const navigateNext = useCallback(() => {
    const deepestPath = findDeepestExpandedPath();
    const currentNode = getNodeByPath(deepestPath);
    
    if (currentNode && currentNode.nextQuestion) {
      const nextPath = [...deepestPath.slice(0, -1), deepestPath[deepestPath.length - 1], 0];
      const nextNode = getNodeByPath(nextPath);
      
      if (nextNode) {
        expandNode(nextNode, nextPath);
        return true;
      }
    }
    
    return false;
  }, [findDeepestExpandedPath, getNodeByPath, expandNode]);
  
  /**
   * Navigate to the previous node in the dialogue
   * 
   * @returns {boolean} - Whether navigation was successful
   */
  const navigatePrevious = useCallback(() => {
    if (expandedNodes.length <= 1) return false;
    
    const lastExpandedPath = expandedNodes[expandedNodes.length - 1];
    collapseNode(getNodeByPath(lastExpandedPath), lastExpandedPath);
    
    return true;
  }, [expandedNodes, collapseNode, getNodeByPath]);
  
  return {
    dialogue,
    expandedNodes,
    activeNodePath,
    dialogueHistory,
    expandNode,
    collapseNode,
    toggleNode,
    navigateNext,
    navigatePrevious,
    isNodeExpanded,
    getNodeByPath,
    getNodeChildren,
    getCurrentDepth,
    getTotalNodesCount,
    hasVisitedNode,
    findDeepestExpandedPath,
    resetDialogue
  };
};

export default useDialogueChain;
