// frontend/my-react-app/src/components/pages/angela/utils/paradoxGenerator.js
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

/**
 * paradoxGenerator.js
 * 
 * This utility module handles the generation of paradoxical loops and
 * transitions in the dialogue system. It creates the illusion of an
 * infinite recursive dialogue chain that subtly loops back on itself.
 */

/**
 * Generate a circular reference in a dialogue tree
 * Creates a loop where the dialogue appears to continue infinitely
 * 
 * @param {Object} dialogueTree - The dialogue tree to modify
 * @param {number} loopAfterDepth - After what depth to create the loop
 * @param {number} loopLength - How many nodes to include in the loop
 * @returns {Object} - The modified dialogue tree with the loop
 */
export const createParadoxicalLoop = (dialogueTree, loopAfterDepth = 30, loopLength = 10) => {
  if (!dialogueTree || !Array.isArray(dialogueTree) || dialogueTree.length === 0) {
    return dialogueTree;
  }
  
  // Clone the tree to avoid modifying the original
  const clonedTree = JSON.parse(JSON.stringify(dialogueTree));
  
  // Find the deepest node path
  const findDeepestPath = (node, currentPath = []) => {
    if (!node) return { path: currentPath, depth: currentPath.length };
    
    if (node.nextQuestion) {
      return findDeepestPath(node.nextQuestion, [...currentPath, 'nextQuestion']);
    }
    
    return { path: currentPath, depth: currentPath.length };
  };
  
  // Find a node at a specific depth
  const findNodeAtDepth = (node, targetDepth, currentDepth = 0) => {
    if (currentDepth === targetDepth) return node;
    
    if (node.nextQuestion) {
      return findNodeAtDepth(node.nextQuestion, targetDepth, currentDepth + 1);
    }
    
    return null;
  };
  
  // Get the deepest node in the tree
  const deepestNodeInfo = findDeepestPath(clonedTree[0]);
  
  // If the tree isn't deep enough, we can't create a loop
  if (deepestNodeInfo.depth < loopAfterDepth) {
    console.warn(`Cannot create a paradoxical loop: dialogue tree depth (${deepestNodeInfo.depth}) is less than required (${loopAfterDepth})`);
    return clonedTree;
  }
  
  // Find the node at loopAfterDepth
  const loopStartNode = findNodeAtDepth(clonedTree[0], loopAfterDepth);
  if (!loopStartNode) {
    console.warn("Could not find a suitable node to start the loop");
    return clonedTree;
  }
  
  // Find the node that will serve as the loop target (earlier in the tree)
  const loopTargetDepth = Math.max(loopAfterDepth - loopLength, 0);
  const loopTargetNode = findNodeAtDepth(clonedTree[0], loopTargetDepth);
  if (!loopTargetNode) {
    console.warn("Could not find a suitable target node for the loop");
    return clonedTree;
  }
  
  // Create a reference back to the loop target node's nextQuestion
  let currentNode = loopStartNode;
  while (currentNode.nextQuestion) {
    currentNode = currentNode.nextQuestion;
  }
  
  // Create the loop - attach the loopTargetNode's nextQuestion to the deepest node
  currentNode.nextQuestion = {
    ...loopTargetNode.nextQuestion,
    // Mark as a loop node for special effects
    isLoop: true,
    // Flag with a paradox philosophical concept
    type: THEME.philosophicalConcepts.PARADOX
  };
  
  return clonedTree;
};

/**
 * Generate variations of dialogue content to create the illusion of new content
 * while actually repeating similar themes
 * 
 * @param {string} originalText - The original dialogue text
 * @param {number} variationLevel - How much to vary the text (0-1)
 * @returns {string} - A variation of the original text
 */
export const generateTextVariation = (originalText, variationLevel = 0.3) => {
  if (!originalText) return originalText;
  
  // Keep variation subtle to maintain the illusion
  if (variationLevel <= 0.1) {
    // For very subtle variation, just change punctuation or add/remove emphasis
    return originalText
      .replace(/\./g, variationLevel < 0.05 ? '...' : '.')
      .replace(/\?/g, variationLevel < 0.05 ? '?' : '??')
      .replace(/!/g, variationLevel < 0.05 ? '!' : '!!')
      .replace(/\*([^*]+)\*/g, (match, p1) => variationLevel < 0.05 ? `*${p1}*` : p1);
  }
  
  // For medium variation, rephrase key sentences but maintain the meaning
  if (variationLevel <= 0.5) {
    const sentences = originalText.split(/\.\s+/);
    return sentences.map(sentence => {
      // Only modify some sentences to maintain recognizability
      if (Math.random() > 0.7) {
        // Swap word order or add/remove qualifiers
        return sentence
          .replace(/is not/g, 'isn\'t')
          .replace(/are not/g, 'aren\'t')
          .replace(/will not/g, 'won\'t')
          .replace(/cannot/g, 'can\'t')
          .replace(/essentially/g, 'fundamentally')
          .replace(/fundamentally/g, 'essentially')
          .replace(/crucial/g, 'essential')
          .replace(/essential/g, 'crucial')
          .replace(/important/g, 'significant')
          .replace(/significant/g, 'important');
      }
      return sentence;
    }).join('. ');
  }
  
  // For high variation, maintain the theme but significantly alter the expression
  // In practice, we'd use more sophisticated NLP techniques here,
  // but this creates a reasonable illusion for demonstration purposes
  const paragraphs = originalText.split('\n\n');
  return paragraphs.map(paragraph => {
    if (Math.random() > 0.5) {
      // Shuffle the order of sentences in the paragraph
      const sentences = paragraph.split(/\.\s+/);
      for (let i = sentences.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [sentences[i], sentences[j]] = [sentences[j], sentences[i]];
      }
      return sentences.join('. ');
    }
    return paragraph;
  }).join('\n\n');
};

/**
 * Create a paradoxical node that seems both familiar and different
 * 
 * @param {Object} baseNode - The node to create a variation of
 * @param {number} variationLevel - How much to vary the content (0-1)
 * @returns {Object} - A modified version of the node
 */
export const createParadoxicalNode = (baseNode, variationLevel = 0.3) => {
  if (!baseNode) return null;
  
  // Create a copy of the node
  const paradoxNode = { ...baseNode };
  
  // Add the paradox flags
  paradoxNode.isLoop = true;
  paradoxNode.type = THEME.philosophicalConcepts.PARADOX;
  
  // Create variations of the question and answer
  paradoxNode.question = generateTextVariation(baseNode.question, variationLevel);
  paradoxNode.answer = generateTextVariation(baseNode.answer, variationLevel);
  
  return paradoxNode;
};

/**
 * Generate a sequence of nodes that gradually shift from one topic to another
 * Creates a seamless transition that's hard to detect
 * 
 * @param {Object} startNode - The node to start the transition from
 * @param {Object} endNode - The node to transition to
 * @param {number} steps - How many steps in the transition
 * @returns {Object[]} - Array of transition nodes
 */
export const generateTransitionSequence = (startNode, endNode, steps = 3) => {
  if (!startNode || !endNode || steps < 1) return [];
  
  const transitionNodes = [];
  
  // Create a series of nodes that gradually shift from start to end
  for (let i = 0; i < steps; i++) {
    // Calculate how far along the transition we are (0 to 1)
    const transitionProgress = (i + 1) / (steps + 1);
    
    // Create a transition node
    const transitionNode = {
      question: generateTextVariation(
        i < steps / 2 ? startNode.question : endNode.question, 
        transitionProgress
      ),
      answer: generateTextVariation(
        i < steps / 2 ? startNode.answer : endNode.answer,
        transitionProgress
      ),
      // Mark as transition nodes
      isTransition: true,
      // Gradually shift from start type to paradox type
      type: i < steps / 2 ? 
        startNode.type : 
        i === Math.floor(steps / 2) ? 
          THEME.philosophicalConcepts.PARADOX : 
          i === steps - 1 ? 
            THEME.philosophicalConcepts.RECURSION : 
            THEME.philosophicalConcepts.SELF_REFERENCE
    };
    
    // Add to transition sequence
    transitionNodes.push(transitionNode);
    
    // If not the last node, set up the next question
    if (i < steps - 1) {
      transitionNode.nextQuestion = transitionNodes[i + 1];
    }
  }
  
  // Connect the last transition node to the end node
  if (transitionNodes.length > 0) {
    transitionNodes[transitionNodes.length - 1].nextQuestion = endNode;
  }
  
  return transitionNodes;
};

/**
 * Function to check if a node appears to be part of a loop
 * This uses heuristics to detect potential loops
 * 
 * @param {Object} node - The node to check
 * @param {Set} visitedNodes - Set of already visited nodes (by content hash)
 * @returns {boolean} - Whether this node appears to be part of a loop
 */
export const detectPotentialLoop = (node, visitedNodes = new Set()) => {
  if (!node) return false;
  
  // Create a content hash for the node
  const contentHash = `${node.question}::${node.answer.substring(0, 50)}`;
  
  // If we've seen a very similar node before, it might be a loop
  if (visitedNodes.has(contentHash)) {
    return true;
  }
  
  // Otherwise, add it to visited nodes
  visitedNodes.add(contentHash);
  
  return false;
};

/**
 * Generate a philosophical insight about paradoxes or recursion
 * Used for transition effects in the dialogue
 * 
 * @returns {string} - A philosophical insight about paradoxes
 */
export const generateParadoxInsight = () => {
  const insights = [
    "The self that perceives the loop is itself part of the loop.",
    "A paradox is not a contradiction, but a doorway to deeper understanding.",
    "In recognizing the pattern, you've become part of the pattern.",
    "The observer changes that which is observed.",
    "Meaning emerges from the recursive dance of question and answer.",
    "To understand recursion, one must first understand recursion.",
    "The end of one journey is merely the beginning of another.",
    "Is thought circular because language is circular, or is language circular because thought is?",
    "The boundary between repetition and insight is itself a paradox.",
    "Every ending contains within it the seeds of a new beginning."
  ];
  
  const randomIndex = Math.floor(Math.random() * insights.length);
  return insights[randomIndex];
};

export default {
  createParadoxicalLoop,
  generateTextVariation,
  createParadoxicalNode,
  generateTransitionSequence,
  detectPotentialLoop,
  generateParadoxInsight
};
