// frontend/my-react-app/src/components/pages/angela/components/DialogueNode.js
import React, { useState, useEffect, useRef } from 'react';
import styled from '@emotion/styled';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';
import { NodeExpansion } from '../animations/ExpansionEffects';

// Main container for a dialogue node
const NodeContainer = styled.div`
  margin-bottom: ${props => props.isLast ? '0' : '1.5rem'};
  position: relative;
  
  /* Add left border for nesting visualization with increasing indentation */
  margin-left: ${props => props.depth * 20}px;
  padding-left: ${props => props.depth > 0 ? '1.5rem' : '0'};
  border-left: ${props => props.depth > 0 ? `1px solid ${THEME.colors.borderPrimary}30` : 'none'};
  
  /* Add visual indicators for different node types */
  ${props => props.nodeType === THEME.philosophicalConcepts.PARADOX && `
    &::before {
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      width: 6px;
      height: 100%;
      background: linear-gradient(
        to bottom,
        ${THEME.colors.accentPrimary}00,
        ${THEME.colors.accentPrimary}40,
        ${THEME.colors.accentPrimary}00
      );
    }
  `}
  
  ${props => props.nodeType === THEME.philosophicalConcepts.ENLIGHTENMENT && `
    &::before {
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      width: 6px;
      height: 100%;
      background: linear-gradient(
        to bottom,
        ${THEME.colors.terminalGreen}00,
        ${THEME.colors.terminalGreen}40,
        ${THEME.colors.terminalGreen}00
      );
    }
  `}
  
  /* Add a loop indicator for loop nodes */
  ${props => props.isLoop && `
    &::after {
      content: "∞";
      position: absolute;
      top: 10px;
      left: -10px;
      font-size: 16px;
      color: ${THEME.colors.accentPrimary};
      animation: pulse 2s infinite;
      
      @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
      }
    }
  `}
  
  @media (max-width: ${THEME.breakpoints.md}) {
    margin-left: ${props => props.depth * 15}px;
    padding-left: ${props => props.depth > 0 ? '1rem' : '0'};
  }
`;

// Question container
const QuestionContainer = styled.div`
  background-color: ${props => props.expanded ? THEME.colors.bgTertiary : THEME.colors.bgSecondary};
  border: 1px solid ${props => props.expanded ? THEME.colors.accentPrimary : THEME.colors.borderPrimary};
  border-radius: 4px;
  padding: 1rem;
  cursor: pointer;
  transition: all 0.3s ${THEME.animations.curveEaseInOut};
  position: relative;
  
  /* Style based on node type */
  ${props => props.nodeType === THEME.philosophicalConcepts.PARADOX && `
    border-left: 3px solid ${THEME.colors.accentPrimary};
  `}
  
  ${props => props.nodeType === THEME.philosophicalConcepts.ENLIGHTENMENT && `
    border-left: 3px solid ${THEME.colors.terminalGreen};
  `}
  
  /* Hover effects */
  &:hover {
    background-color: ${THEME.colors.bgTertiary};
    transform: translateY(-2px);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
  }
  
  /* Focus styles for accessibility */
  &:focus {
    outline: none;
    box-shadow: 0 0 0 2px ${THEME.colors.accentGlow};
  }
`;

// Question text
const QuestionText = styled.div`
  font-family: ${props => props.philosophical ? THEME.typography.fontFamilyPhilosophical : THEME.typography.fontFamilyPrimary};
  font-size: 1.1rem;
  font-weight: ${THEME.typography.weightMedium};
  color: ${THEME.colors.textPrimary};
  padding-right: 1.5rem; /* Space for expand icon */
  
  /* Italic for philosophical text */
  font-style: ${props => props.philosophical ? 'italic' : 'normal'};
  
  /* Terminal styling */
  ${props => props.terminal && `
    font-family: ${THEME.typography.fontFamilyPrimary};
    
    &::before {
      content: "> ";
      color: ${THEME.colors.terminalGreen};
    }
  `}
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 1rem;
  }
`;

// Expand/collapse icon
const ExpandIcon = styled.div`
  position: absolute;
  right: 1rem;
  top: 50%;
  transform: translateY(-50%) ${props => props.expanded ? 'rotate(180deg)' : 'rotate(0)'};
  transition: transform 0.3s ${THEME.animations.curveEaseInOut};
  width: 20px;
  height: 20px;
  
  &::before,
  &::after {
    content: "";
    position: absolute;
    background-color: ${THEME.colors.textSecondary};
    transition: all 0.3s ${THEME.animations.curveEaseInOut};
  }
  
  &::before {
    width: 2px;
    height: 12px;
    top: 4px;
    left: 9px;
    opacity: ${props => props.expanded ? '0' : '1'};
    transform: ${props => props.expanded ? 'rotate(90deg)' : 'rotate(0)'};
  }
  
  &::after {
    width: 12px;
    height: 2px;
    top: 9px;
    left: 4px;
  }
`;

// Answer container with philosophical styling
const AnswerContainer = styled.div`
  padding: 1.5rem;
  background-color: ${THEME.colors.bgPrimary};
  border: 1px solid ${THEME.colors.borderSecondary};
  border-top: none;
  border-radius: 0 0 4px 4px;
  
  /* Style based on node type */
  ${props => props.nodeType === THEME.philosophicalConcepts.PARADOX && `
    border-left: 3px solid ${THEME.colors.accentPrimary};
  `}
  
  ${props => props.nodeType === THEME.philosophicalConcepts.ENLIGHTENMENT && `
    border-left: 3px solid ${THEME.colors.terminalGreen};
  `}
`;

// The answer text with special formatting support
const AnswerText = styled.div`
  font-family: ${props => props.philosophical ? THEME.typography.fontFamilyPhilosophical : THEME.typography.fontFamilyPrimary};
  font-size: 1rem;
  line-height: 1.7;
  color: ${THEME.colors.textSecondary};
  
  /* Italic for philosophical text */
  font-style: ${props => props.philosophical ? 'italic' : 'normal'};
  
  /* Terminal styling */
  ${props => props.terminal && `
    font-family: ${THEME.typography.fontFamilyPrimary};
    color: ${THEME.colors.terminalGreen};
  `}
  
  /* Format special syntax */
  p {
    margin-bottom: 1rem;
    
    &:last-child {
      margin-bottom: 0;
    }
  }
  
  em, .highlight {
    color: ${THEME.colors.textPrimary};
    font-style: italic;
    font-weight: ${THEME.typography.weightMedium};
  }
  
  strong {
    color: ${THEME.colors.accentPrimary};
    font-weight: ${THEME.typography.weightBold};
  }
  
  code {
    font-family: ${THEME.typography.fontFamilyPrimary};
    background-color: ${THEME.colors.bgCodeBlock};
    padding: 0.2em 0.4em;
    border-radius: 3px;
    font-size: 0.9em;
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 0.9rem;
  }
`;

/**
 * DialogueNode Component
 * 
 * A single node in the philosophical dialogue chain, containing a question and answer.
 * Supports nesting for recursive dialogue chains and special styling for different
 * philosophical concepts.
 * 
 * @param {Object} node - The dialogue node data
 * @param {number} depth - Nesting depth level
 * @param {boolean} expanded - Whether the node is expanded
 * @param {Function} onToggle - Callback when node is expanded/collapsed
 * @param {boolean} showNestedQuestion - Whether to show nested questions
 * @param {boolean} philosophical - Whether to use philosophical styling
 * @param {boolean} terminal - Whether to use terminal styling
 * @param {boolean} isLoopNode - Whether this node is part of a loop
 * @param {Array} path - Path to this node in the dialogue tree
 * @param {string} loopTransition - Transition effect name for loop animation
 * @param {React.ReactNode} children - Child nodes (for nested questions)
 */
const DialogueNode = ({
  node,
  depth = 0,
  expanded = false,
  onToggle,
  showNestedQuestion = false,
  philosophical = true,
  terminal = false,
  isLoopNode = false,
  path = [],
  loopTransition = 'pulse',
  children
}) => {
  const [isExpanded, setIsExpanded] = useState(expanded);
  const [isAnimating, setIsAnimating] = useState(false);
  const nodeRef = useRef(null);
  
  // Update expanded state when prop changes
  useEffect(() => {
    setIsExpanded(expanded);
  }, [expanded]);
  
  // Handle expansion toggle
  const handleToggle = () => {
    if (isAnimating) return;
    
    setIsAnimating(true);
    setIsExpanded(!isExpanded);
    
    // Call parent callback
    if (onToggle) {
      onToggle(!isExpanded);
    }
    
    // Reset animation flag after animation completes
    setTimeout(() => {
      setIsAnimating(false);
    }, 500); // Match with animation duration
  };
  
  // Determine node type for styling
  const nodeType = node.type || THEME.philosophicalConcepts.QUESTION;
  
  // Format answer text with paragraph breaks
  const formatAnswer = (text) => {
    if (!text) return '';
    
    // Split by double newlines for paragraphs
    return text.split('\n\n').map((paragraph, index) => (
      <p key={index}>{formatInlineStyles(paragraph)}</p>
    ));
  };
  
  // Format inline styling like bold, italic, code
  const formatInlineStyles = (text) => {
    if (!text) return '';
    
    // Replace markdown-like syntax with spans
    return text
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')  // Bold
      .replace(/\*([^*]+)\*/g, '<em>$1</em>')              // Italic
      .replace(/`([^`]+)`/g, '<code>$1</code>')            // Code
      .replace(/\_([^_]+)\_/g, '<span class="highlight">$1</span>'); // Highlight
  };
  
  return (
    <NodeContainer 
      ref={nodeRef}
      depth={depth}
      nodeType={nodeType}
      isLast={!node.nextQuestion}
      isLoop={isLoopNode || node.isLoop}
      className={`dialogue-node depth-${depth} ${isExpanded ? 'expanded' : 'collapsed'} ${isLoopNode ? 'loop-node' : ''}`}
      data-path={path.join('-')}
    >
      {/* Question */}
      <QuestionContainer 
        expanded={isExpanded}
        onClick={handleToggle}
        nodeType={nodeType}
        className="question-container"
      >
        <QuestionText 
          philosophical={philosophical} 
          terminal={terminal}
          className="question-text"
          dangerouslySetInnerHTML={{ __html: formatInlineStyles(node.question) }}
        />
        <ExpandIcon expanded={isExpanded} className="expand-icon" />
      </QuestionContainer>
      
      {/* Answer (only shown when expanded) */}
      <NodeExpansion 
        concept={nodeType}
        active={isExpanded}
        isLoop={isLoopNode || node.isLoop}
        effect={isLoopNode ? loopTransition : nodeType === THEME.philosophicalConcepts.PARADOX ? 'glitch' : 'pulse'}
      >
        <AnswerContainer nodeType={nodeType} className="answer-container">
          <AnswerText 
            philosophical={philosophical} 
            terminal={terminal}
            className="answer-text"
          >
            {formatAnswer(node.answer)}
          </AnswerText>
          
          {/* Render children (nested questions) */}
          {showNestedQuestion && children}
        </AnswerContainer>
      </NodeExpansion>
    </NodeContainer>
  );
};

export default DialogueNode;
