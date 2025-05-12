// frontend/my-react-app/src/components/pages/angela/styles/DialogueStyles.js
// Styling for the Socratic dialogue system components

import { css } from '@emotion/react';
import styled from '@emotion/styled';
import { ANGELA_THEME as THEME } from './PhilosophicalTheme';
import { 
  DialogueExpansionAnimation, 
  ThoughtFlowEffectAnimation, 
  ParadoxTransitionAnimation 
} from './AnimationStyles';

// ======================================================
// DIALOGUE CONTAINER STYLES
// ======================================================

export const DialogueContainer = styled.div`
  max-width: ${props => props.fullWidth ? '100%' : '800px'};
  margin: ${props => props.centered ? '0 auto' : '0'};
  padding: ${THEME.spacing.xl} ${THEME.spacing.md};
  position: relative;
  
  /* Apply all specialized animations */
  ${DialogueExpansionAnimation}
  ${ThoughtFlowEffectAnimation}
  ${ParadoxTransitionAnimation}
  
  /* Custom background that creates depth */
  background: linear-gradient(
    to bottom,
    ${THEME.colors.bgPrimary} 0%,
    ${THEME.colors.bgSecondary} 100%
  );
  border-radius: ${THEME.shapes.radiusMd};
  border: 1px solid ${THEME.colors.borderPrimary};
  box-shadow: ${THEME.shadows.md};
  
  /* CRT effect overlay */
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    pointer-events: none;
    background: linear-gradient(
      rgba(18, 16, 16, 0) 50%, 
      rgba(0, 0, 0, 0.1) 50%
    );
    background-size: 100% 4px;
    z-index: 2;
    opacity: 0.3;
    border-radius: ${THEME.shapes.radiusMd};
  }
  
  /* Ensure everything inside is positioned relative to this container */
  * {
    box-sizing: border-box;
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    padding: ${THEME.spacing.lg} ${THEME.spacing.sm};
  }
`;

// ======================================================
// DIALOGUE NODE STYLES
// ======================================================

export const DialogueNodeContainer = styled.div`
  margin-bottom: ${props => props.isLast ? '0' : THEME.spacing.lg};
  position: relative;
  transition: all ${THEME.animations.durationMedium} ${THEME.animations.curvePhilosophical};
  
  /* Add indent for nested dialogue */
  margin-left: ${props => props.depth > 0 ? `${props.depth * 20}px` : '0'};
  
  /* Connection line for nested dialogue */
  ${props => props.depth > 0 && css`
    &::before {
      content: "";
      position: absolute;
      left: -10px;
      top: 0;
      bottom: 0;
      width: 1px;
      background: linear-gradient(
        to bottom,
        ${THEME.colors.borderPrimary} 0%,
        ${THEME.colors.accentPrimary} 50%,
        ${THEME.colors.borderPrimary} 100%
      );
      opacity: 0.6;
    }
  `}
  
  /* Node active state */
  ${props => props.isActive && css`
    &::after {
      content: "";
      position: absolute;
      left: -14px;
      top: 20px;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background-color: ${THEME.colors.accentPrimary};
      box-shadow: 0 0 8px ${THEME.colors.accentGlow};
    }
  `}
  
  /* Apply different styling based on node type */
  ${props => props.nodeType === THEME.philosophicalConcepts.PARADOX && css`
    &::before {
      background: linear-gradient(
        to bottom,
        ${THEME.colors.borderPrimary} 0%,
        ${THEME.colors.errorRed} 50%,
        ${THEME.colors.borderPrimary} 100%
      );
    }
  `}
  
  ${props => props.nodeType === THEME.philosophicalConcepts.ENLIGHTENMENT && css`
    &::before {
      background: linear-gradient(
        to bottom,
        ${THEME.colors.borderPrimary} 0%,
        ${THEME.colors.terminalGreen} 50%,
        ${THEME.colors.borderPrimary} 100%
      );
    }
  `}
`;

export const QuestionContainer = styled.div`
  background-color: ${THEME.colors.bgSecondary};
  border-radius: ${THEME.shapes.dialogueBubbleRadius};
  border: 1px solid ${THEME.colors.borderPrimary};
  padding: ${THEME.spacing.md};
  cursor: pointer;
  transition: all ${THEME.animations.durationMedium} ${THEME.animations.curveEaseInOut};
  position: relative;
  overflow: hidden;
  
  /* Hover effects */
  &:hover {
    background-color: ${THEME.colors.bgTertiary};
    border-color: ${THEME.colors.accentPrimary};
    transform: translateY(-2px);
    box-shadow: ${THEME.shadows.md};
  }
  
  /* Focus styles for accessibility */
  &:focus {
    outline: none;
    box-shadow: 0 0 0 2px ${THEME.colors.accentGlow};
  }
  
  /* Active/expanded state */
  ${props => props.isExpanded && css`
    background-color: ${THEME.colors.bgTertiary};
    border-color: ${THEME.colors.accentPrimary};
    box-shadow: ${THEME.shadows.md};
  `}
  
  /* Subtle glitch effect on hover */
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
    transition: opacity ${THEME.animations.durationFast}, transform ${THEME.animations.durationFast};
    transform: translateX(-100%);
    pointer-events: none;
  }
  
  &:hover::after {
    opacity: 1;
    transform: translateX(100%);
    transition: transform 0.8s ease-in-out;
  }
  
  /* Special styling based on philosophical concept */
  ${props => props.nodeType === THEME.philosophicalConcepts.PARADOX && css`
    border-left: 3px solid ${THEME.colors.errorRed};
  `}
  
  ${props => props.nodeType === THEME.philosophicalConcepts.ENLIGHTENMENT && css`
    border-left: 3px solid ${THEME.colors.terminalGreen};
  `}
  
  ${props => props.nodeType === THEME.philosophicalConcepts.RECURSION && css`
    border-left: 3px solid ${THEME.colors.terminalCyan};
  `}
`;

export const QuestionText = styled.div`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: ${THEME.typography.size16};
  font-weight: ${THEME.typography.weightMedium};
  color: ${THEME.colors.textPrimary};
  letter-spacing: ${THEME.typography.spacingWide};
  
  /* Philosophical styling for the question */
  ${props => props.philosophical && css`
    font-family: ${THEME.typography.fontFamilyPhilosophical};
    font-style: italic;
  `}
  
  /* Terminal styling option */
  ${props => props.terminal && css`
    font-family: ${THEME.typography.fontFamilySecondary};
    &::before {
      content: "> ";
      color: ${THEME.colors.terminalGreen};
    }
  `}
  
  /* Concept-based color variations */
  ${props => props.concept === THEME.philosophicalConcepts.QUESTION && css`
    color: ${THEME.colors.textPrimary};
  `}
  
  ${props => props.concept === THEME.philosophicalConcepts.PARADOX && css`
    color: ${THEME.colors.accentPrimary};
  `}
  
  ${props => props.concept === THEME.philosophicalConcepts.VOID && css`
    color: ${THEME.colors.textSecondary};
  `}
`;

export const ExpandIcon = styled.div`
  position: absolute;
  right: ${THEME.spacing.md};
  top: 50%;
  transform: translateY(-50%) ${props => props.isExpanded ? 'rotate(180deg)' : 'rotate(0)'};
  transition: transform ${THEME.animations.durationMedium} ${THEME.animations.curveEaseInOut};
  width: 20px;
  height: 20px;
  color: ${THEME.colors.textSecondary};
  display: flex;
  align-items: center;
  justify-content: center;
  
  &::before,
  &::after {
    content: "";
    position: absolute;
    background-color: currentColor;
    transition: all ${THEME.animations.durationMedium} ${THEME.animations.curveEaseInOut};
  }
  
  &::before {
    width: 2px;
    height: 12px;
    top: 4px;
    left: 9px;
    opacity: ${props => props.isExpanded ? '0' : '1'};
    transform: ${props => props.isExpanded ? 'rotate(90deg)' : 'rotate(0)'};
  }
  
  &::after {
    width: 12px;
    height: 2px;
    top: 9px;
    left: 4px;
  }
`;

export const AnswerContainer = styled.div`
  padding: ${THEME.spacing.lg} ${THEME.spacing.md};
  background-color: ${THEME.colors.bgPrimary};
  border-radius: ${THEME.shapes.radiusSm};
  border: 1px solid ${THEME.colors.borderSecondary};
  margin-top: ${THEME.spacing.sm};
  position: relative;
  overflow: hidden;
  
  /* Subtle background pattern */
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
  }
  
  /* Special styling based on philosophical concept */
  ${props => props.concept === THEME.philosophicalConcepts.PARADOX && css`
    border-left: 3px solid ${THEME.colors.errorRed};
  `}
  
  ${props => props.concept === THEME.philosophicalConcepts.ENLIGHTENMENT && css`
    border-left: 3px solid ${THEME.colors.terminalGreen};
  `}
  
  ${props => props.concept === THEME.philosophicalConcepts.RECURSION && css`
    border-left: 3px solid ${THEME.colors.terminalCyan};
  `}
`;

export const AnswerText = styled.div`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: ${THEME.typography.size16};
  line-height: ${THEME.typography.lineHeightRelaxed};
  color: ${THEME.colors.textSecondary};
  
  /* Philosophical styling for the answer */
  ${props => props.philosophical && css`
    font-family: ${THEME.typography.fontFamilyPhilosophical};
    font-style: italic;
    letter-spacing: ${THEME.typography.spacingWide};
  `}
  
  /* Custom text color based on concept */
  ${props => props.concept === THEME.philosophicalConcepts.ANSWER && css`
    color: ${THEME.colors.textPrimary};
  `}
  
  /* Terminal styling */
  ${props => props.terminal && css`
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
      margin-left: ${THEME.spacing.md};
    }
  `}
  
  /* Text highlight styles */
  .highlight {
    color: ${THEME.colors.accentPrimary};
    font-weight: ${THEME.typography.weightMedium};
  }
  
  .code {
    font-family: ${THEME.typography.fontFamilyPrimary};
    background-color: ${THEME.colors.bgCodeBlock};
    padding: 0.2em 0.4em;
    border-radius: ${THEME.shapes.radiusSm};
    font-size: 0.9em;
  }
  
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
  
  p {
    margin-bottom: ${THEME.spacing.md};
    
    &:last-child {
      margin-bottom: 0;
    }
  }
`;

export const NestedQuestionContainer = styled.div`
  margin-top: ${THEME.spacing.lg};
  padding-top: ${THEME.spacing.md};
  border-top: 1px dashed ${THEME.colors.borderPrimary};
  position: relative;
  
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

// ======================================================
// DIALOGUE EXPANSION STYLES
// ======================================================

export const ExpansionContainer = styled.div`
  position: relative;
  overflow: hidden;
  max-height: ${props => props.isExpanded ? '2000px' : '0'};
  opacity: ${props => props.isExpanded ? '1' : '0'};
  transition: 
    max-height ${THEME.animations.durationSlow} ${THEME.animations.curvePhilosophical},
    opacity ${THEME.animations.durationMedium} ${THEME.animations.curveEaseInOut};
  transform-origin: top;
`;

export const ExpansionInner = styled.div`
  position: relative;
`;

export const ExpansionBackground = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: -1;
  background: linear-gradient(
    to bottom,
    ${THEME.colors.bgSecondary} 0%,
    ${THEME.colors.bgPrimary} 100%
  );
  opacity: 0.5;
`;

// ======================================================
// DIALOGUE TRANSITION EFFECTS
// ======================================================

export const TransitionEffect = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  z-index: 1;
  
  /* Basic pulse effect */
  ${props => props.effect === 'pulse' && css`
    background: radial-gradient(
      circle at center,
      ${THEME.colors.accentGlow} 0%,
      transparent 70%
    );
    opacity: 0;
    animation: pulsate 2s ease-in-out infinite;
    
    @keyframes pulsate {
      0% { opacity: 0; }
      50% { opacity: 0.3; }
      100% { opacity: 0; }
    }
  `}
  
  /* Glitch transition */
  ${props => props.effect === 'glitch' && css`
    background-image: linear-gradient(
      to bottom,
      transparent,
      rgba(255, 0, 0, 0.1) 10%,
      transparent 10.5%,
      transparent 20%,
      rgba(0, 255, 255, 0.1) 20.5%,
      transparent 21%
    );
    background-size: 100% 8px;
    background-repeat: repeat;
    opacity: 0;
    animation: glitch-reveal 1s ease-in-out;
    
    @keyframes glitch-reveal {
      0% { opacity: 0; }
      10% { opacity: 0.7; }
      15% { opacity: 0.1; }
      20% { opacity: 0.8; }
      30% { opacity: 0; }
      40% { opacity: 0.3; }
      50% { opacity: 0; }
    }
  `}
  
  /* Thought flow effect */
  ${props => props.effect === 'thoughtFlow' && css`
    background: radial-gradient(
      circle at 50% 50%,
      transparent 0%,
      ${THEME.colors.accentGlow} 10%,
      transparent 70%
    );
    animation: thought-flow 3s ease-in-out;
    
    @keyframes thought-flow {
      0% { opacity: 0; transform: scale(0); }
      30% { opacity: 0.3; transform: scale(1.2); }
      100% { opacity: 0; transform: scale(2); }
    }
  `}
  
  /* Paradox effect */
  ${props => props.effect === 'paradox' && css`
    background: conic-gradient(
      from 0deg at 50% 50%,
      ${THEME.colors.bgPrimary} 0%,
      ${THEME.colors.accentPrimary}20 10%,
      ${THEME.colors.bgPrimary} 20%,
      ${THEME.colors.accentPrimary}20 30%,
      ${THEME.colors.bgPrimary} 40%,
      ${THEME.colors.accentPrimary}20 50%,
      ${THEME.colors.bgPrimary} 60%,
      ${THEME.colors.accentPrimary}20 70%,
      ${THEME.colors.bgPrimary} 80%,
      ${THEME.colors.accentPrimary}20 90%,
      ${THEME.colors.bgPrimary} 100%
    );
    opacity: 0;
    animation: paradox-spin 3s ease-in-out;
    
    @keyframes paradox-spin {
      0% { opacity: 0; transform: rotate(0deg); }
      50% { opacity: 0.2; transform: rotate(180deg); }
      100% { opacity: 0; transform: rotate(360deg); }
    }
  `}
`;

// ======================================================
// THOUGHT PARTICLE EFFECTS
// ======================================================

export const ThoughtParticle = styled.div`
  position: absolute;
  width: ${props => props.size || '8px'};
  height: ${props => props.size || '8px'};
  background-color: ${props => props.color || 'rgba(255, 255, 255, 0.1)'};
  border-radius: 50%;
  pointer-events: none;
  animation: thought-particle ${props => props.duration || '5s'} ease-in-out infinite;
  animation-delay: ${props => props.delay || '0s'};
  
  @keyframes thought-particle {
    0% {
      transform: translate(0, 0) scale(1);
      opacity: 0;
    }
    10% {
      opacity: ${props => props.maxOpacity || 0.6};
    }
    90% {
      opacity: 0.1;
    }
    100% {
      transform: translate(
        ${props => props.moveX || '0px'},
        ${props => props.moveY || '-50px'}
      ) scale(${props => props.scale || 0.5});
      opacity: 0;
    }
  }
`;

export const ThoughtLine = styled.div`
  position: absolute;
  height: 1px;
  width: ${props => props.width || '50px'};
  background: linear-gradient(
    to right,
    transparent 0%,
    ${props => props.color || THEME.colors.textMuted} 50%,
    transparent 100%
  );
  transform-origin: left;
  transform: rotate(${props => props.angle || '0deg'});
  animation: thought-line ${props => props.duration || '4s'} ease-in-out infinite;
  animation-delay: ${props => props.delay || '0s'};
  
  @keyframes thought-line {
    0% {
      opacity: 0;
      transform: rotate(${props => props.angle || '0deg'}) scaleX(0);
    }
    20% {
      opacity: ${props => props.maxOpacity || 0.5};
      transform: rotate(${props => props.angle || '0deg'}) scaleX(1);
    }
    80% {
      opacity: ${props => props.maxOpacity || 0.5};
      transform: rotate(${props => props.angle || '0deg'}) scaleX(1);
    }
    100% {
      opacity: 0;
      transform: rotate(${props => props.angle || '0deg'}) scaleX(0);
    }
  }
`;

// ======================================================
// UTILITY EXPORTS
// ======================================================

export const createThoughtParticles = (count = 10) => {
  const particles = [];
  
  for (let i = 0; i < count; i++) {
    const size = Math.floor(Math.random() * 8) + 4 + 'px';
    const delay = Math.random() * 5 + 's';
    const duration = Math.random() * 4 + 3 + 's';
    const moveX = (Math.random() * 100 - 50) + 'px';
    const moveY = (Math.random() * -80 - 20) + 'px';
    const scale = Math.random() * 0.5 + 0.5;
    const maxOpacity = Math.random() * 0.5 + 0.1;
    
    particles.push({
      id: `particle-${i}`,
      size,
      delay,
      duration,
      moveX,
      moveY,
      scale,
      maxOpacity,
      left: Math.random() * 100 + '%',
      top: Math.random() * 100 + '%',
    });
  }
  
  return particles;
};

export const createThoughtLines = (count = 5) => {
  const lines = [];
  
  for (let i = 0; i < count; i++) {
    const width = Math.floor(Math.random() * 80) + 30 + 'px';
    const delay = Math.random() * 3 + 's';
    const duration = Math.random() * 3 + 3 + 's';
    const angle = Math.floor(Math.random() * 360) + 'deg';
    const maxOpacity = Math.random() * 0.3 + 0.1;
    
    lines.push({
      id: `line-${i}`,
      width,
      delay,
      duration,
      angle,
      maxOpacity,
      left: Math.random() * 100 + '%',
      top: Math.random() * 100 + '%',
    });
  }
  
  return lines;
};

export default {
  DialogueContainer,
  DialogueNodeContainer,
  QuestionContainer,
  QuestionText,
  ExpandIcon,
  AnswerContainer,
  AnswerText,
  NestedQuestionContainer,
  ExpansionContainer,
  ExpansionInner,
  ExpansionBackground,
  TransitionEffect,
  ThoughtParticle,
  ThoughtLine,
  createThoughtParticles,
  createThoughtLines,
};
