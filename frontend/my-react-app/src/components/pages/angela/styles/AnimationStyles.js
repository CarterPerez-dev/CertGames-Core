// frontend/my-react-app/src/components/pages/angela/styles/AnimationStyles.js
// Advanced animation system for the Angela CLI page

import { css, keyframes } from '@emotion/react';
import styled from '@emotion/styled';
import { ANGELA_THEME as THEME } from './PhilosophicalTheme';

// ======================================================
// KEYFRAME ANIMATIONS
// ======================================================

export const glitchAnimation = keyframes`
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

export const heavyGlitchAnimation = keyframes`
  0% {
    transform: translate(0);
    clip-path: inset(50% 0 30% 0);
  }
  10% {
    clip-path: inset(10% 0 60% 0);
  }
  20% {
    transform: translate(-5px, 5px);
    clip-path: inset(30% 0 20% 0);
  }
  30% {
    clip-path: inset(50% 0 40% 0);
  }
  40% {
    transform: translate(5px, -5px);
    clip-path: inset(70% 0 10% 0);
  }
  50% {
    clip-path: inset(20% 0 80% 0);
  }
  60% {
    transform: translate(5px, 5px);
    clip-path: inset(40% 0 30% 0);
  }
  70% {
    clip-path: inset(60% 0 30% 0);
  }
  80% {
    transform: translate(-5px, -5px);
    clip-path: inset(10% 0 50% 0);
  }
  90% {
    clip-path: inset(70% 0 40% 0);
  }
  100% {
    transform: translate(0);
    clip-path: inset(50% 0 30% 0);
  }
`;

export const pulseAnimation = keyframes`
  0% {
    opacity: 1;
    transform: scale(1);
  }
  50% {
    opacity: 0.8;
    transform: scale(1.05);
  }
  100% {
    opacity: 1;
    transform: scale(1);
  }
`;

export const floatAnimation = keyframes`
  0% {
    transform: translateY(0px);
  }
  50% {
    transform: translateY(-10px);
  }
  100% {
    transform: translateY(0px);
  }
`;

export const rotateAnimation = keyframes`
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
`;

export const fadeInAnimation = keyframes`
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
`;

export const fadeOutAnimation = keyframes`
  from {
    opacity: 1;
  }
  to {
    opacity: 0;
  }
`;

export const slideInUpAnimation = keyframes`
  from {
    transform: translateY(40px);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
`;

export const slideInDownAnimation = keyframes`
  from {
    transform: translateY(-40px);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
`;

export const slideInLeftAnimation = keyframes`
  from {
    transform: translateX(-40px);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
`;

export const slideInRightAnimation = keyframes`
  from {
    transform: translateX(40px);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
`;

export const typewriterAnimation = keyframes`
  from {
    width: 0;
  }
  to {
    width: 100%;
  }
`;

export const cursorBlinkAnimation = keyframes`
  from, to {
    border-color: transparent;
  }
  50% {
    border-color: ${THEME.colors.textPrimary};
  }
`;

export const flickerTextAnimation = keyframes`
  0% {
    opacity: 1;
  }
  5% {
    opacity: 0.7;
  }
  10% {
    opacity: 1;
  }
  15% {
    opacity: 0.5;
  }
  20% {
    opacity: 1;
  }
  55% {
    opacity: 1;
  }
  60% {
    opacity: 0.7;
  }
  65% {
    opacity: 1;
  }
  100% {
    opacity: 1;
  }
`;

export const expandAnimation = keyframes`
  from {
    max-height: 0;
    opacity: 0;
    transform: scale(0.95);
  }
  to {
    max-height: 2000px;
    opacity: 1;
    transform: scale(1);
  }
`;

export const collapseAnimation = keyframes`
  from {
    max-height: 2000px;
    opacity: 1;
    transform: scale(1);
  }
  to {
    max-height: 0;
    opacity: 0;
    transform: scale(0.95);
  }
`;

export const thoughtBubbleAnimation = keyframes`
  0% {
    transform: scale(0) translateY(20px);
    opacity: 0;
  }
  60% {
    transform: scale(1.1) translateY(-5px);
    opacity: 1;
  }
  100% {
    transform: scale(1) translateY(0);
    opacity: 1;
  }
`;

export const matrixRainAnimation = keyframes`
  0% {
    transform: translateY(-100%);
    opacity: 1;
  }
  80% {
    opacity: 0.9;
  }
  100% {
    transform: translateY(1000%);
    opacity: 0;
  }
`;

export const thoughtFlowAnimation = keyframes`
  0% {
    transform: translateY(0) rotate(0deg) scale(1);
    opacity: 0;
  }
  10% {
    opacity: 0.8;
  }
  90% {
    opacity: 0.6;
    transform: translateY(-50px) rotate(10deg) scale(1.2);
  }
  100% {
    transform: translateY(-70px) rotate(15deg) scale(1.4);
    opacity: 0;
  }
`;

export const existentialLoopAnimation = keyframes`
  0% {
    transform: scale(1) rotate(0deg);
  }
  25% {
    transform: scale(1.05) rotate(3deg);
  }
  50% {
    transform: scale(1) rotate(0deg);
  }
  75% {
    transform: scale(0.95) rotate(-3deg);
  }
  100% {
    transform: scale(1) rotate(0deg);
  }
`;

export const expansionPulseAnimation = keyframes`
  0% {
    transform: scale(1);
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0.7);
  }
  70% {
    transform: scale(1.05);
    box-shadow: 0 0 0 10px rgba(255, 51, 51, 0);
  }
  100% {
    transform: scale(1);
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0);
  }
`;

export const paradoxAnimation = keyframes`
  0% {
    transform: perspective(500px) rotateY(0deg);
  }
  50% {
    transform: perspective(500px) rotateY(180deg);
  }
  100% {
    transform: perspective(500px) rotateY(360deg);
  }
`;

export const voidInfiniteAnimation = keyframes`
  0% {
    transform: scale(1) translate(0, 0);
    opacity: 1;
  }
  50% {
    transform: scale(0.8) translate(10px, -10px);
    opacity: 0.7;
  }
  100% {
    transform: scale(1) translate(0, 0);
    opacity: 1;
  }
`;

export const textDistortAnimation = keyframes`
  0% {
    filter: blur(0px);
    transform: skew(0deg, 0deg);
  }
  20% {
    filter: blur(1px);
    transform: skew(2deg, 0deg);
  }
  40% {
    filter: blur(0px);
    transform: skew(-2deg, 1deg);
  }
  60% {
    filter: blur(0.5px);
    transform: skew(0deg, -1deg);
  }
  80% {
    filter: blur(2px);
    transform: skew(-1deg, 0deg);
  }
  100% {
    filter: blur(0px);
    transform: skew(0deg, 0deg);
  }
`;

export const scanlineAnimation = keyframes`
  0% {
    background-position: 0 0;
  }
  100% {
    background-position: 0 100%;
  }
`;

// ======================================================
// ANIMATION MIXINS
// ======================================================

export const fadeIn = (duration = THEME.animations.durationMedium, delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${fadeInAnimation} ${duration} ${curve} ${delay} forwards;
`;

export const fadeOut = (duration = THEME.animations.durationMedium, delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${fadeOutAnimation} ${duration} ${curve} ${delay} forwards;
`;

export const slideInUp = (duration = THEME.animations.durationMedium, delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${slideInUpAnimation} ${duration} ${curve} ${delay} forwards;
`;

export const slideInDown = (duration = THEME.animations.durationMedium, delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${slideInDownAnimation} ${duration} ${curve} ${delay} forwards;
`;

export const slideInLeft = (duration = THEME.animations.durationMedium, delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${slideInLeftAnimation} ${duration} ${curve} ${delay} forwards;
`;

export const slideInRight = (duration = THEME.animations.durationMedium, delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${slideInRightAnimation} ${duration} ${curve} ${delay} forwards;
`;

export const pulse = (duration = THEME.animations.durationSlow, delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${pulseAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const float = (duration = '3s', delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${floatAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const rotate = (duration = '20s', delay = '0ms', curve = 'linear') => css`
  animation: ${rotateAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const glitch = (duration = '1s', delay = '0ms', curve = 'steps(2, jump-none)') => css`
  animation: ${glitchAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const heavyGlitch = (duration = '2s', delay = '0ms', curve = 'linear') => css`
  animation: ${heavyGlitchAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const typewriter = (duration = '3s', characters = 40, delay = '0ms') => css`
  overflow: hidden;
  white-space: nowrap;
  display: inline-block;
  position: relative;
  animation: ${typewriterAnimation} ${duration} steps(${characters}, end) ${delay} forwards,
             ${cursorBlinkAnimation} 750ms step-end infinite;
  border-right: 3px solid transparent;
`;

export const flicker = (duration = '3s', delay = '0ms') => css`
  animation: ${flickerTextAnimation} ${duration} ease-in-out ${delay} infinite;
`;

export const expand = (duration = THEME.animations.durationSlow, delay = '0ms', curve = THEME.animations.curvePhilosophical) => css`
  animation: ${expandAnimation} ${duration} ${curve} ${delay} forwards;
  overflow: hidden;
`;

export const collapse = (duration = THEME.animations.durationSlow, delay = '0ms', curve = THEME.animations.curvePhilosophical) => css`
  animation: ${collapseAnimation} ${duration} ${curve} ${delay} forwards;
  overflow: hidden;
`;

export const thoughtBubble = (duration = THEME.animations.durationSlow, delay = '0ms', curve = THEME.animations.curvePhilosophical) => css`
  animation: ${thoughtBubbleAnimation} ${duration} ${curve} ${delay} forwards;
`;

export const thoughtFlow = (duration = '5s', delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${thoughtFlowAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const existentialLoop = (duration = '15s', delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${existentialLoopAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const expansionPulse = (duration = '2s', delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${expansionPulseAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const paradox = (duration = '15s', delay = '0ms', curve = 'linear') => css`
  animation: ${paradoxAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const voidInfinite = (duration = '8s', delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${voidInfiniteAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const textDistort = (duration = '5s', delay = '0ms', curve = THEME.animations.curveEaseInOut) => css`
  animation: ${textDistortAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const scanline = (duration = '10s', delay = '0ms', curve = 'linear') => css`
  background: linear-gradient(
    to bottom,
    transparent 0%,
    rgba(32, 32, 32, 0.15) 50%,
    transparent 100%
  );
  background-size: 100% 4px;
  animation: ${scanlineAnimation} ${duration} ${curve} ${delay} infinite;
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
`;

// ======================================================
// SPECIALIZED ANIMATION COMPONENTS
// ======================================================

export const GlitchEffect = styled.div`
  position: relative;
  display: inline-block;
  
  &::before,
  &::after {
    content: attr(data-text);
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
  }
  
  &::before {
    left: 2px;
    text-shadow: -1px 0 ${THEME.colors.accentPrimary};
    clip: rect(44px, 450px, 56px, 0);
    animation: ${glitchAnimation} 5s infinite linear alternate-reverse;
  }
  
  &::after {
    left: -2px;
    text-shadow: -1px 0 ${THEME.colors.terminalCyan};
    clip: rect(44px, 450px, 56px, 0);
    animation: ${glitchAnimation} 7s infinite linear alternate-reverse;
    animation-delay: 1s;
  }
`;

export const TypewriterText = styled.div`
  overflow: hidden;
  white-space: nowrap;
  display: inline-block;
  border-right: 0.15em solid ${THEME.colors.textPrimary};
  margin: 0;
  animation: 
    ${typewriterAnimation} ${props => props.duration || '3.5s'} steps(${props => props.steps || 40}, end),
    ${cursorBlinkAnimation} 0.75s step-end infinite;
`;

export const FlickeringText = styled.span`
  animation: ${flickerTextAnimation} ${props => props.duration || '3s'} ease-in-out infinite;
  display: inline-block;
`;

export const PulsingElement = styled.div`
  animation: ${pulseAnimation} ${props => props.duration || '2s'} ease-in-out infinite;
`;

export const FloatingElement = styled.div`
  animation: ${floatingAnimation} ${props => props.duration || '6s'} ease-in-out infinite;
  transform-origin: center;
`;

export const RotatingElement = styled.div`
  animation: ${rotateAnimation} ${props => props.duration || '20s'} linear infinite;
  transform-origin: center;
`;

export const FadeInElement = styled.div`
  opacity: 0;
  animation: ${fadeInAnimation} ${props => props.duration || THEME.animations.durationMedium} 
    ${props => props.curve || THEME.animations.curveEaseInOut} 
    ${props => props.delay || '0ms'} forwards;
`;

export const SlideInUpElement = styled.div`
  opacity: 0;
  transform: translateY(40px);
  animation: ${slideInUpAnimation} ${props => props.duration || THEME.animations.durationMedium} 
    ${props => props.curve || THEME.animations.curveEaseInOut} 
    ${props => props.delay || '0ms'} forwards;
`;

export const ExpandElement = styled.div`
  max-height: 0;
  overflow: hidden;
  opacity: 0;
  animation: ${expandAnimation} ${props => props.duration || THEME.animations.durationSlow}
    ${props => props.curve || THEME.animations.curvePhilosophical}
    ${props => props.delay || '0ms'} forwards;
`;

export const ParadoxElement = styled.div`
  animation: ${paradoxAnimation} ${props => props.duration || '15s'} linear infinite;
  transform-style: preserve-3d;
`;

export const ThoughtFlowParticle = styled.div`
  position: absolute;
  width: ${props => props.size || '10px'};
  height: ${props => props.size || '10px'};
  background-color: ${props => props.color || 'rgba(255, 255, 255, 0.2)'};
  border-radius: 50%;
  pointer-events: none;
  animation: ${thoughtFlowAnimation} ${props => props.duration || '5s'} 
    ${THEME.animations.curveEaseInOut} 
    ${props => props.delay || '0ms'} infinite;
`;

export const MatrixRainChar = styled.span`
  position: absolute;
  color: ${props => props.color || THEME.colors.terminalGreen};
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: ${props => props.size || THEME.typography.size16};
  line-height: 1;
  animation: ${matrixRainAnimation} ${props => props.duration || '8s'} 
    linear
    ${props => props.delay || '0ms'} infinite;
  opacity: ${props => props.opacity || 0.8};
  text-shadow: 0 0 5px ${props => props.color || THEME.colors.terminalGreen};
`;

export const ScanlineOverlay = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  ${scanline('10s', '0ms', 'linear')}
  opacity: ${props => props.opacity || 0.3};
  z-index: ${props => props.zIndex || THEME.zIndex.overlay};
`;

export const TextDistortContainer = styled.div`
  display: inline-block;
  ${textDistort()}
`;

// ======================================================
// SPECIALIZED ANIMATIONS FOR DIALOGUE COMPONENTS
// ======================================================

export const DialogueExpansionAnimation = css`
  .dialogue-expanding {
    ${expand()}
    transform-origin: top;
  }
  
  .dialogue-collapsing {
    ${collapse()}
    transform-origin: top;
  }
  
  .question-appearing {
    ${fadeIn(THEME.animations.durationMedium, '0ms', THEME.animations.curveEaseOut)}
  }
  
  .answer-appearing {
    ${slideInDown(THEME.animations.durationMedium, THEME.animations.delayMd, THEME.animations.curvePhilosophical)}
  }
  
  .dialogue-node-enter {
    opacity: 0;
    transform: translateY(20px);
  }
  
  .dialogue-node-enter-active {
    opacity: 1;
    transform: translateY(0);
    transition: opacity ${THEME.animations.durationMedium}, transform ${THEME.animations.durationMedium};
    transition-timing-function: ${THEME.animations.curvePhilosophical};
  }
  
  .dialogue-node-exit {
    opacity: 1;
  }
  
  .dialogue-node-exit-active {
    opacity: 0;
    transition: opacity ${THEME.animations.durationFast};
  }
`;

export const ThoughtFlowEffectAnimation = css`
  .thought-flow-container {
    position: absolute;
    width: 100%;
    height: 100%;
    pointer-events: none;
    z-index: ${THEME.zIndex.overlay};
  }
  
  .thought-bubble {
    ${thoughtBubble()}
    position: relative;
  }
  
  .thought-particle {
    ${thoughtFlow()}
    position: absolute;
    border-radius: 50%;
    background-color: rgba(255, 255, 255, 0.1);
  }
  
  .thought-line {
    position: absolute;
    height: 1px;
    background: linear-gradient(
      to right,
      transparent 0%,
      ${THEME.colors.textMuted} 50%,
      transparent 100%
    );
    transform-origin: left;
    ${thoughtFlow('7s', '0ms', THEME.animations.curveEaseInOut)}
  }
`;

export const ParadoxTransitionAnimation = css`
  .paradox-container {
    perspective: 1000px;
    position: relative;
  }
  
  .paradox-layer {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    ${paradox()}
    backface-visibility: hidden;
  }
  
  .paradox-fade {
    position: relative;
    opacity: 0;
    transform: scale(0.9);
    transition: 
      opacity ${THEME.animations.durationSlow} ${THEME.animations.curveEaseInOut},
      transform ${THEME.animations.durationSlow} ${THEME.animations.curveEaseInOut};
  }
  
  .paradox-fade.active {
    opacity: 1;
    transform: scale(1);
  }
  
  .paradox-loop-active {
    ${existentialLoop()}
  }
  
  .infinite-recursion {
    position: relative;
    ${voidInfinite()}
  }
  
  .paradox-glitch {
    position: relative;
    overflow: hidden;
    
    &::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 2px;
      background-color: ${THEME.colors.accentPrimary};
      animation: paradox-scan 2s linear infinite;
    }
    
    @keyframes paradox-scan {
      0% {
        left: -100%;
        opacity: 0;
      }
      10% {
        opacity: 1;
      }
      90% {
        opacity: 1;
      }
      100% {
        left: 100%;
        opacity: 0;
      }
    }
  }
`;

// ======================================================
// EXPORTS
// ======================================================

export default {
  // Keyframes
  glitchAnimation,
  heavyGlitchAnimation,
  pulseAnimation,
  floatAnimation,
  rotateAnimation,
  fadeInAnimation,
  fadeOutAnimation,
  slideInUpAnimation,
  slideInDownAnimation,
  slideInLeftAnimation,
  slideInRightAnimation,
  typewriterAnimation,
  cursorBlinkAnimation,
  flickerTextAnimation,
  expandAnimation,
  collapseAnimation,
  thoughtBubbleAnimation,
  matrixRainAnimation,
  thoughtFlowAnimation,
  existentialLoopAnimation,
  expansionPulseAnimation,
  paradoxAnimation,
  voidInfiniteAnimation,
  textDistortAnimation,
  scanlineAnimation,
  
  // Mixins
  fadeIn,
  fadeOut,
  slideInUp,
  slideInDown,
  slideInLeft,
  slideInRight,
  pulse,
  float,
  rotate,
  glitch,
  heavyGlitch,
  typewriter,
  flicker,
  expand,
  collapse,
  thoughtBubble,
  thoughtFlow,
  existentialLoop,
  expansionPulse,
  paradox,
  voidInfinite,
  textDistort,
  scanline,
  
  // Components
  GlitchEffect,
  TypewriterText,
  FlickeringText,
  PulsingElement,
  FloatingElement,
  RotatingElement,
  FadeInElement,
  SlideInUpElement,
  ExpandElement,
  ParadoxElement,
  ThoughtFlowParticle,
  MatrixRainChar,
  ScanlineOverlay,
  TextDistortContainer,
  
  // Specialized dialogue animations
  DialogueExpansionAnimation,
  ThoughtFlowEffectAnimation,
  ParadoxTransitionAnimation,
};
