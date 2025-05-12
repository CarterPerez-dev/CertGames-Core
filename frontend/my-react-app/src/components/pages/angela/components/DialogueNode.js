// frontend/my-react-app/src/components/pages/angela/components/DialogueNode.js
import React, { useState, useEffect, useRef } from 'react';
import styled from '@emotion/styled';
import { keyframes } from '@emotion/react';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';
import { NodeExpansion } from '../animations/ExpansionEffects';

// Pulse animation for active nodes
const pulseAnimation = keyframes`
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

// Glitch animation for paradox nodes
const glitchAnimation = keyframes`
  0% {
    transform: translate(0);
  }
  20% {
    transform: translate(-2px, 2px);
  }
  40% {
    transform: translate(-2px, -2px);
  }
  60% {
    transform: translate(2px, 2px);
  }
  80% {
    transform: translate(2px, -2px);
  }
  100% {
    transform: translate(0);
  }
`;

// Improved main container for a dialogue node
const NodeContainer = styled.div`
  margin-bottom: ${props => props.isLast ? '0' : '1.5rem'};
  position: relative;
  
  /* Enhanced left border for nesting visualization with increasing indentation */
  margin-left: ${props => props.depth * 20}px;
  padding-left: ${props => props.depth > 0 ? '1.5rem' : '0'};
  border-left: ${props => props.depth > 0 ? `1px solid ${THEME.colors.borderPrimary}40` : 'none'};
  
  /* Improved transition effect */
  transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
  
  /* Enhanced visual indicators for different node types */
  ${props => props.nodeType === THEME.philosophicalConcepts.PARADOX && `
    &::before {
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      width: 4px;
      height: 100%;
      background: linear-gradient(
        to bottom,
        ${THEME.colors.accentPrimary}00,
        ${THEME.colors.accentPrimary}80,
        ${THEME.colors.accentPrimary}00
      );
      border-radius: 2px;
    }
  `}
  
  ${props => props.nodeType === THEME.philosophicalConcepts.ENLIGHTENMENT && `
    &::before {
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      width: 4px;
      height: 100%;
      background: linear-gradient(
        to bottom,
        ${THEME.colors.terminalGreen}00,
        ${THEME.colors.terminalGreen}80,
        ${THEME.colors.terminalGreen}00
      );
      border-radius: 2px;
    }
  `}
  
  /* Enhanced loop indicator for loop nodes */
  ${props => props.isLoop && `
    &::after {
      content: "∞";
      position: absolute;
      top: 10px;
      left: -10px;
      font-size: 16px;
      color: ${THEME.colors.accentPrimary};
      animation: ${pulseAnimation} 2s infinite;
      background-color: ${THEME.colors.bgPrimary};
      width: 20px;
      height: 20px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 8px rgba(0, 0, 0, 0.3);
      z-index: 2;
    }
  `}
  
  /* Enhanced active node indicator */
  ${props => props.isActive && `
    &::before {
      content: "";
      position: absolute;
      left: ${props.depth > 0 ? '0' : '-10px'};
      top: 20px;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background-color: ${THEME.colors.accentPrimary};
      box-shadow: 0 0 8px ${THEME.colors.accentGlow};
      z-index: 2;
    }
  `}
  
  @media (max-width: ${THEME.breakpoints.md}) {
    margin-left: ${props => props.depth * 15}px;
    padding-left: ${props => props.depth > 0 ? '1rem' : '0'};
  }
`;

// Enhanced question container with improved styling
const QuestionContainer = styled.div`
  background-color: ${props => props.expanded ? THEME.colors.bgTertiary : THEME.colors.bgSecondary};
  border: 1px solid ${props => props.expanded ? THEME.colors.accentPrimary : THEME.colors.borderPrimary};
  border-radius: 8px;
  padding: 1rem;
  cursor: pointer;
  transition: all 0.3s ${THEME.animations.curveEaseInOut};
  position: relative;
  overflow: hidden;
  
  /* Enhanced border styling based on node type */
  ${props => props.nodeType === THEME.philosophicalConcepts.PARADOX && `
    border-left: 3px solid ${THEME.colors.accentPrimary};
  `}
  
  ${props => props.nodeType === THEME.philosophicalConcepts.ENLIGHTENMENT && `
    border-left: 3px solid ${THEME.colors.terminalGreen};
  `}
  
  ${props => props.nodeType === THEME.philosophicalConcepts.RECURSION && `
    border-left: 3px solid ${THEME.colors.terminalCyan};
  `}
  
  /* Enhanced hover effects */
  &:hover {
    background-color: ${THEME.colors.bgTertiary};
    transform: translateY(-2px);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
  }
  
  /* Enhanced focus styles for accessibility */
  &:focus {
    outline: none;
    box-shadow: 0 0 0 2px ${THEME.colors.accentGlow};
  }
  
  /* Enhanced active/expanded state */
  ${props => props.expanded && `
    background-color: ${THEME.colors.bgTertiary};
    border-color: ${THEME.colors.accentPrimary};
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    border-bottom-left-radius: ${props.showNestedQuestion ? '0' : '8px'};
    border-bottom-right-radius: ${props.showNestedQuestion ? '0' : '8px'};
  `}
  
  /* Enhanced glitch effect on hover */
  &::after {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(
      to right,
      transparent 0%,
      rgba(255, 255, 255, 0.05) 50%,
      transparent 100%
    );
    opacity: 0;
    transition: opacity 0.3s, transform 0.5s;
    transform: translateX(-100%);
    pointer-events: none;
  }
  
  &:hover::after {
    opacity: 1;
    transform: translateX(100%);
    transition: transform 0.8s ease-in-out;
  }
  
  /* Enhanced styling for loop nodes */
  ${props => props.isLoop && `
    animation: ${glitchAnimation} 5s infinite linear alternate-reverse;
    animation-delay: ${Math.random() * 2}s;
    background-color: ${THEME.colors.bgSecondary};
    
    &::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 1px;
      background: linear-gradient(
        to right,
        transparent,
        ${THEME.colors.accentPrimary}80,
        transparent
      );
    }
  `}
`;

// Enhanced question text with improved typography
const QuestionText = styled.div`
  font-family: ${props => props.philosophical ? THEME.typography.fontFamilyPhilosophical : THEME.typography.fontFamilyPrimary};
  font-size: 1.1rem;
  font-weight: ${THEME.typography.weightMedium};
  color: ${THEME.colors.textPrimary};
  padding-right: 1.5rem; /* Space for expand icon */
  
  /* Enhanced italic for philosophical text */
  font-style: ${props => props.philosophical ? 'italic' : 'normal'};
  letter-spacing: ${props => props.philosophical ? THEME.typography.spacingWide : 'normal'};
  
  /* Enhanced terminal styling */
  ${props => props.terminal && `
    font-family: ${THEME.typography.fontFamilyPrimary};
    
    &::before {
      content: "> ";
      color: ${THEME.colors.terminalGreen};
    }
  `}
  
  /* Enhanced styling based on concept */
  ${props => props.concept === THEME.philosophicalConcepts.PARADOX && `
    color: ${THEME.colors.accentPrimary};
  `}
  
  ${props => props.concept === THEME.philosophicalConcepts.ENLIGHTENMENT && `
    color: ${THEME.colors.terminalGreen};
  `}
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 1rem;
  }
`;

// Enhanced expand/collapse icon
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

// Enhanced answer container with philosophical styling
const AnswerContainer = styled.div`
  padding: 1.5rem;
  background-color: ${THEME.colors.bgPrimary};
  border: 1px solid ${THEME.colors.borderSecondary};
  border-top: none;
  border-radius: 0 0 8px 8px;
  position: relative;
  overflow: hidden;
  
  /* Enhanced background pattern */
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-image: radial-gradient(
      ${THEME.colors.borderPrimary} 1px,
      transparent 1px
    );
    background-size: 20px 20px;
    opacity: 0.05;
    pointer-events: none;
    z-index: -1;
  }
  
  /* Enhanced styling based on node type */
  ${props => props.nodeType === THEME.philosophicalConcepts.PARADOX && `
    border-left: 3px solid ${THEME.colors.accentPrimary};
  `}
  
  ${props => props.nodeType === THEME.philosophicalConcepts.ENLIGHTENMENT && `
    border-left: 3px solid ${THEME.colors.terminalGreen};
  `}
  
  ${props => props.nodeType === THEME.philosophicalConcepts.RECURSION && `
    border-left: 3px solid ${THEME.colors.terminalCyan};
  `}
`;

// Enhanced answer text with special formatting support
const AnswerText = styled.div`
  font-family: ${props => props.philosophical ? THEME.typography.fontFamilyPhilosophical : THEME.typography.fontFamilyPrimary};
  font-size: 1rem;
  line-height: 1.7;
  color: ${THEME.colors.textSecondary};
  
  /* Enhanced italic for philosophical text */
  font-style: ${props => props.philosophical ? 'italic' : 'normal'};
  letter-spacing: ${props => props.philosophical ? THEME.typography.spacingWide : 'normal'};
  
  /* Enhanced terminal styling */
  ${props => props.terminal && `
    font-family: ${THEME.typography.fontFamilyPrimary};
    color: ${THEME.colors.terminalGreen};
    
    .prompt {
      color: ${THEME.colors.textPrimary};
      
      &::before {
        content: "$ ";
        color: ${THEME.colors.terminalGreen};
      }
    }
    
    .output {
      color: ${THEME.colors.textSecondary};
      margin-left: 1rem;
    }
  `}
  
  /* Enhanced text formatting */
  p {
    margin-bottom: 1rem;
    
    &:last-child {
      margin-bottom: 0;
    }
  }
  
  .highlight, em {
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
  
  /* Enhanced styling for special terms */
  .philosophical-term {
    font-style: italic;
    position: relative;
    
    &::after {
      content: "";
      position: absolute;
      left: 0;
      right: 0;
      bottom: -2px;
      height: 1px;
      background: linear-gradient(
        to right,
        transparent,
        ${THEME.colors.accentPrimary},
        transparent
      );
    }
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 0.9rem;
  }
`;

// Enhanced container for nested questions
const NestedQuestionContainer = styled.div`
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px dashed ${THEME.colors.borderPrimary};
  position: relative;
  
  /* Enhanced connection visual */
  &::before {
    content: "";
    position: absolute;
    top: -10px;
    left: 20px;
    width: 20px;
    height: 20px;
    border-right: 1px solid ${THEME.colors.borderPrimary};
    border-bottom: 1px solid ${THEME.colors.borderPrimary};
    transform: rotate(45deg);
  }
`;

/**
 * DialogueNode Component
 * 
 * Enhanced single node in the philosophical dialogue chain.
 * Supports nesting, progressive rightward/downward movement, and special styling
 * for different philosophical concepts.
 */
const DialogueNode = ({
  node,
  depth = 0,
  expanded = false,
  onExpand,
  showNestedQuestion = false,
  philosophical = true,
  terminal = false,
  isLoopNode = false,
  path = [],
  loopTransition = 'pulse',
  isActive = false,
  isLast = false,
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
    if (onExpand) {
      onExpand(!isExpanded);
    }
    
    // Reset animation flag after animation completes
    setTimeout(() => {
      setIsAnimating(false);
    }, 500); // Match with animation duration
  };
  
  // Determine node type for styling
  const nodeType = node.type || THEME.philosophicalConcepts.QUESTION;
  
  // Format answer text with paragraph breaks and markdown-like syntax
  const formatAnswer = (text) => {
    if (!text) return '';
    
    // Split by double newlines for paragraphs
    return text.split('\n\n').map((paragraph, index) => (
      <p key={index} dangerouslySetInnerHTML={{ __html: formatInlineStyles(paragraph) }} />
    ));
  };
  
  // Format inline styling like bold, italic, code
  const formatInlineStyles = (text) => {
    if (!text) return '';
    
    // Replace markdown-like syntax with spans and add CSS classes
    return text
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>') // Bold
      .replace(/\*([^*]+)\*/g, '<em class="highlight">$1</em>') // Italic/Highlight
      .replace(/`([^`]+)`/g, '<code>$1</code>') // Code
      .replace(/\_([^_]+)\_/g, '<span class="philosophical-term">$1</span>'); // Philosophical terms
  };
  
  return (
    <NodeContainer 
      ref={nodeRef}
      depth={depth}
      nodeType={nodeType}
      isLast={isLast}
      isLoop={isLoopNode}
      isActive={isActive}
      className={`dialogue-node depth-${depth} ${isExpanded ? 'expanded' : 'collapsed'} ${isLoopNode ? 'loop-node' : ''} ${isActive ? 'active' : ''}`}
      data-path={path.join('-')}
    >
      {/* Question */}
      <QuestionContainer 
        expanded={isExpanded}
        onClick={handleToggle}
        nodeType={nodeType}
        isLoop={isLoopNode}
        showNestedQuestion={showNestedQuestion}
        className="question-container"
      >
        <QuestionText 
          philosophical={philosophical} 
          terminal={terminal}
          concept={nodeType}
          className="question-text"
          dangerouslySetInnerHTML={{ __html: formatInlineStyles(node.question) }}
        />
        <ExpandIcon expanded={isExpanded} className="expand-icon" />
      </QuestionContainer>
      
      {/* Answer (only shown when expanded) */}
      <NodeExpansion 
        concept={nodeType}
        active={isExpanded}
        isLoop={isLoopNode}
        effect={isLoopNode ? loopTransition : nodeType === THEME.philosophicalConcepts.PARADOX ? 'glitch' : 'pulse'}
      >
        <AnswerContainer 
          nodeType={nodeType} 
          className="answer-container"
        >
          <AnswerText 
            philosophical={philosophical} 
            terminal={terminal}
            concept={nodeType}
            className="answer-text"
          >
            {formatAnswer(node.answer)}
          </AnswerText>
          
          {/* Render children (nested questions) */}
          {showNestedQuestion && (
            <NestedQuestionContainer className="nested-question-container">
              {children}
            </NestedQuestionContainer>
          )}
        </AnswerContainer>
      </NodeExpansion>
    </NodeContainer>
  );
};

export default DialogueNode;
