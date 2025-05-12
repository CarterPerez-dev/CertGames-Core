// frontend/my-react-app/src/components/pages/angela/styles/AnimationStyles.js
// Enhanced animation system for the Angela CLI page

import { css, keyframes } from '@emotion/react';
import styled from '@emotion/styled';
import { ANGELA_THEME as THEME } from './PhilosophicalTheme';

// ======================================================
// ENHANCED KEYFRAME ANIMATIONS
// ======================================================

export const enhancedGlitchAnimation = keyframes`
  0% {
    transform: translate(0);
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  1.5% {
    transform: translate(-2px, 2px);
    text-shadow: 0 0 2px ${THEME.colors.accentPrimary}80;
  }
  3% {
    transform: translate(2px, -2px);
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  4.5% {
    transform: translate(0, 0);
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  10% {
    transform: translate(0);
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  12% {
    transform: translate(-5px, 0);
    text-shadow: -1px 0 ${THEME.colors.accentPrimary}80;
  }
  12.5% {
    transform: translate(5px, 0);
    text-shadow: 1px 0 ${THEME.colors.terminalGreen}80;
  }
  13% {
    transform: translate(0);
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  62% {
    transform: translate(0);
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  64% {
    transform: translate(0, 5px);
    text-shadow: 0 1px ${THEME.colors.accentPrimary}80;
  }
  64.5% {
    transform: translate(0, -5px);
    text-shadow: 0 -1px ${THEME.colors.accentPrimary}80;
  }
  65% {
    transform: translate(0);
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  100% {
    transform: translate(0);
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
`;

export const heavyGlitchAnimation = keyframes`
  0% {
    transform: translate(0);
    clip-path: inset(50% 0 30% 0);
    filter: hue-rotate(0deg);
  }
  10% {
    clip-path: inset(10% 0 60% 0);
    filter: hue-rotate(36deg);
  }
  20% {
    transform: translate(-5px, 5px);
    clip-path: inset(30% 0 20% 0);
    filter: hue-rotate(72deg);
  }
  30% {
    clip-path: inset(50% 0 40% 0);
    filter: hue-rotate(108deg);
  }
  40% {
    transform: translate(5px, -5px);
    clip-path: inset(70% 0 10% 0);
    filter: hue-rotate(144deg);
  }
  50% {
    clip-path: inset(20% 0 80% 0);
    filter: hue-rotate(180deg);
  }
  60% {
    transform: translate(5px, 5px);
    clip-path: inset(40% 0 30% 0);
    filter: hue-rotate(216deg);
  }
  70% {
    clip-path: inset(60% 0 30% 0);
    filter: hue-rotate(252deg);
  }
  80% {
    transform: translate(-5px, -5px);
    clip-path: inset(10% 0 50% 0);
    filter: hue-rotate(288deg);
  }
  90% {
    clip-path: inset(70% 0 40% 0);
    filter: hue-rotate(324deg);
  }
  100% {
    transform: translate(0);
    clip-path: inset(50% 0 30% 0);
    filter: hue-rotate(360deg);
  }
`;

export const enhancedPulseAnimation = keyframes`
  0% {
    transform: scale(1);
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0.4);
    filter: brightness(0.95);
  }
  20% {
    transform: scale(1.02);
    filter: brightness(1.05);
  }
  50% {
    transform: scale(1.05);
    box-shadow: 0 0 0 6px rgba(255, 51, 51, 0);
    filter: brightness(1.1);
  }
  80% {
    transform: scale(1.02);
    filter: brightness(1.05);
  }
  100% {
    transform: scale(1);
    box-shadow: 0 0 0 0 rgba(255, 51, 51, 0);
    filter: brightness(0.95);
  }
`;

export const enhancedFloatAnimation = keyframes`
  0% {
    transform: translateY(0) rotate(0deg);
    filter: brightness(1);
  }
  25% {
    transform: translateY(-8px) rotate(1deg);
    filter: brightness(1.05);
  }
  50% {
    transform: translateY(-12px) rotate(-1deg);
    filter: brightness(1.1);
  }
  75% {
    transform: translateY(-8px) rotate(1deg);
    filter: brightness(1.05);
  }
  100% {
    transform: translateY(0) rotate(0deg);
    filter: brightness(1);
  }
`;

export const enhancedRotateAnimation = keyframes`
  0% {
    transform: rotate(0deg) scale(1);
  }
  50% {
    transform: rotate(180deg) scale(1.05);
  }
  100% {
    transform: rotate(360deg) scale(1);
  }
`;

export const enhancedFadeInAnimation = keyframes`
  from {
    opacity: 0;
    transform: translateY(20px);
    filter: blur(10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
    filter: blur(0);
  }
`;

export const enhancedFadeOutAnimation = keyframes`
  from {
    opacity: 1;
    transform: translateY(0);
    filter: blur(0);
  }
  to {
    opacity: 0;
    transform: translateY(20px);
    filter: blur(10px);
  }
`;

export const enhancedTypewriterAnimation = keyframes`
  from {
    width: 0;
    border-right-color: ${THEME.colors.textPrimary};
  }
  to {
    width: 100%;
    border-right-color: ${THEME.colors.textPrimary};
  }
`;

export const enhancedCursorBlinkAnimation = keyframes`
  from, to {
    border-right-color: transparent;
  }
  50% {
    border-right-color: ${THEME.colors.textPrimary};
  }
`;

export const enhancedFlickerTextAnimation = keyframes`
  0% {
    opacity: 1;
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  5% {
    opacity: 0.7;
    text-shadow: 0 0 5px ${THEME.colors.accentPrimary}60;
  }
  10% {
    opacity: 1;
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  15% {
    opacity: 0.5;
    text-shadow: 0 0 10px ${THEME.colors.accentPrimary}80;
  }
  20% {
    opacity: 1;
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  55% {
    opacity: 1;
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  60% {
    opacity: 0.7;
    text-shadow: 0 0 5px ${THEME.colors.accentPrimary}60;
  }
  65% {
    opacity: 1;
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
  100% {
    opacity: 1;
    text-shadow: 0 0 0 ${THEME.colors.accentPrimary}00;
  }
`;

export const enhancedExpandAnimation = keyframes`
  from {
    max-height: 0;
    opacity: 0;
    transform: scale(0.95) translateY(-20px);
    filter: blur(5px);
  }
  to {
    max-height: 2000px;
    opacity: 1;
    transform: scale(1) translateY(0);
    filter: blur(0);
  }
`;

export const enhancedCollapseAnimation = keyframes`
  from {
    max-height: 2000px;
    opacity: 1;
    transform: scale(1) translateY(0);
    filter: blur(0);
  }
  to {
    max-height: 0;
    opacity: 0;
    transform: scale(0.95) translateY(-20px);
    filter: blur(5px);
  }
`;

export const enhancedThoughtBubbleAnimation = keyframes`
  0% {
    transform: scale(0) translateY(20px);
    opacity: 0;
    filter: blur(10px);
  }
  60% {
    transform: scale(1.1) translateY(-5px);
    opacity: 1;
    filter: blur(0);
  }
  80% {
    transform: scale(0.98) translateY(2px);
    opacity: 1;
  }
  100% {
    transform: scale(1) translateY(0);
    opacity: 1;
  }
`;

export const enhancedThoughtFlowAnimation = keyframes`
  0% {
    transform: translateY(0) rotate(0deg) scale(1);
    opacity: 0;
    filter: blur(5px);
  }
  10% {
    opacity: 0.8;
    filter: blur(2px);
  }
  80% {
    opacity: 0.6;
    filter: blur(3px);
  }
  100% {
    transform: translateY(-60px) rotate(15deg) scale(1.5);
    opacity: 0;
    filter: blur(8px);
  }
`;

export const enhancedExistentialLoopAnimation = keyframes`
  0% {
    transform: scale(1) rotate(0deg);
    filter: hue-rotate(0deg);
  }
  25% {
    transform: scale(1.05) rotate(3deg);
    filter: hue-rotate(90deg);
  }
  50% {
    transform: scale(1) rotate(0deg);
    filter: hue-rotate(180deg);
  }
  75% {
    transform: scale(0.95) rotate(-3deg);
    filter: hue-rotate(270deg);
  }
  100% {
    transform: scale(1) rotate(0deg);
    filter: hue-rotate(360deg);
  }
`;

export const enhancedParadoxAnimation = keyframes`
  0% {
    transform: perspective(500px) rotateY(0deg);
    filter: hue-rotate(0deg) brightness(1);
  }
  50% {
    transform: perspective(500px) rotateY(180deg);
    filter: hue-rotate(180deg) brightness(1.2);
  }
  100% {
    transform: perspective(500px) rotateY(360deg);
    filter: hue-rotate(360deg) brightness(1);
  }
`;

export const enhancedVoidInfiniteAnimation = keyframes`
  0% {
    transform: scale(1) translate(0, 0);
    filter: brightness(1) contrast(1);
    box-shadow: inset 0 0 20px rgba(0, 0, 0, 0.5);
  }
  50% {
    transform: scale(0.98) translate(5px, -5px);
    filter: brightness(0.8) contrast(1.2);
    box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8);
  }
  100% {
    transform: scale(1) translate(0, 0);
    filter: brightness(1) contrast(1);
    box-shadow: inset 0 0 20px rgba(0, 0, 0, 0.5);
  }
`;

export const enhancedTextDistortAnimation = keyframes`
  0% {
    filter: blur(0px);
    transform: skew(0deg, 0deg);
    text-shadow: 0 0 0 rgba(255, 51, 51, 0);
  }
  20% {
    filter: blur(1px);
    transform: skew(2deg, 0deg);
    text-shadow: 1px 0 1px rgba(255, 51, 51, 0.5);
  }
  40% {
    filter: blur(0px);
    transform: skew(-2deg, 1deg);
    text-shadow: -1px 1px 0 rgba(255, 51, 51, 0.3);
  }
  60% {
    filter: blur(0.5px);
    transform: skew(0deg, -1deg);
    text-shadow: 0 -1px 0 rgba(255, 51, 51, 0.2);
  }
  80% {
    filter: blur(2px);
    transform: skew(-1deg, 0deg);
    text-shadow: -1px 0 1px rgba(255, 51, 51, 0.4);
  }
  100% {
    filter: blur(0px);
    transform: skew(0deg, 0deg);
    text-shadow: 0 0 0 rgba(255, 51, 51, 0);
  }
`;

export const enhancedScanlineAnimation = keyframes`
  0% {
    background-position: 0 0;
  }
  100% {
    background-position: 0 100%;
  }
`;

// ======================================================
// ENHANCED ANIMATION MIXINS
// ======================================================

export const enhancedFadeIn = (duration = '0.5s', delay = '0ms', curve = 'cubic-bezier(0.34, 1.56, 0.64, 1)') => css`
  animation: ${enhancedFadeInAnimation} ${duration} ${curve} ${delay} forwards;
`;

export const enhancedFadeOut = (duration = '0.5s', delay = '0ms', curve = 'cubic-bezier(0.34, 1.56, 0.64, 1)') => css`
  animation: ${enhancedFadeOutAnimation} ${duration} ${curve} ${delay} forwards;
`;

export const enhancedPulse = (duration = '3s', delay = '0ms', curve = 'ease-in-out') => css`
  animation: ${enhancedPulseAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const enhancedFloat = (duration = '6s', delay = '0ms', curve = 'ease-in-out') => css`
  animation: ${enhancedFloatAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const enhancedRotate = (duration = '20s', delay = '0ms', curve = 'linear') => css`
  animation: ${enhancedRotateAnimation} ${duration} ${curve} ${delay} infinite;
  transform-origin: center;
`;

export const enhancedGlitch = (duration = '10s', delay = '0ms', curve = 'step-end') => css`
  animation: ${enhancedGlitchAnimation} ${duration} ${curve} ${delay} infinite;
  position: relative;
`;

export const enhancedHeavyGlitch = (duration = '5s', delay = '0ms', curve = 'linear') => css`
  animation: ${heavyGlitchAnimation} ${duration} ${curve} ${delay} infinite;
  position: relative;
`;

export const enhancedTypewriter = (duration = '3s', characters = 40, delay = '0ms') => css`
  overflow: hidden;
  white-space: nowrap;
  display: inline-block;
  position: relative;
  animation: 
    ${enhancedTypewriterAnimation} ${duration} steps(${characters}, end) ${delay} forwards,
    ${enhancedCursorBlinkAnimation} 0.75s step-end infinite;
  border-right: 3px solid transparent;
`;

export const enhancedFlicker = (duration = '5s', delay = '0ms', intensity = 1) => css`
  animation: ${enhancedFlickerTextAnimation} ${duration} ease-in-out ${delay} infinite;
  animation-duration: calc(${duration} * ${intensity});
`;

export const enhancedExpand = (duration = '0.7s', delay = '0ms', curve = 'cubic-bezier(0.34, 1.56, 0.64, 1)') => css`
  animation: ${enhancedExpandAnimation} ${duration} ${curve} ${delay} forwards;
  overflow: hidden;
`;

export const enhancedCollapse = (duration = '0.5s', delay = '0ms', curve = 'cubic-bezier(0.34, 1.56, 0.64, 1)') => css`
  animation: ${enhancedCollapseAnimation} ${duration} ${curve} ${delay} forwards;
  overflow: hidden;
`;

export const enhancedThoughtBubble = (duration = '0.8s', delay = '0ms', curve = 'cubic-bezier(0.34, 1.56, 0.64, 1)') => css`
  animation: ${enhancedThoughtBubbleAnimation} ${duration} ${curve} ${delay} forwards;
`;

export const enhancedThoughtFlow = (duration = '5s', delay = '0ms', curve = 'ease-in-out') => css`
  animation: ${enhancedThoughtFlowAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const enhancedExistentialLoop = (duration = '15s', delay = '0ms', curve = 'ease-in-out') => css`
  animation: ${enhancedExistentialLoopAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const enhancedParadox = (duration = '15s', delay = '0ms', curve = 'linear') => css`
  animation: ${enhancedParadoxAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const enhancedVoidInfinite = (duration = '10s', delay = '0ms', curve = 'ease-in-out') => css`
  animation: ${enhancedVoidInfiniteAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const enhancedTextDistort = (duration = '5s', delay = '0ms', curve = 'ease-in-out') => css`
  animation: ${enhancedTextDistortAnimation} ${duration} ${curve} ${delay} infinite;
`;

export const enhancedScanline = (duration = '10s', delay = '0ms', curve = 'linear') => css`
  background: linear-gradient(
    to bottom,
    transparent 49.5%,
    rgba(32, 32, 32, 0.1) 49.5%,
    rgba(32, 32, 32, 0.1) 50.5%,
    transparent 50.5%
  );
  background-size: 100% 4px;
  animation: ${enhancedScanlineAnimation} ${duration} ${curve} ${delay} infinite;
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 2;
`;

// ======================================================
// ENHANCED ANIMATION COMPONENTS
// ======================================================

export const EnhancedGlitchText = styled.span`
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
    opacity: 0.8;
  }
  
  &::before {
    left: 2px;
    text-shadow: -1px 0 ${THEME.colors.accentPrimary};
    clip: rect(44px, 450px, 56px, 0);
    animation: ${enhancedGlitchAnimation} 5s infinite linear alternate-reverse;
  }
  
  &::after {
    left: -2px;
    text-shadow: -1px 0 ${THEME.colors.terminalCyan};
    clip: rect(44px, 450px, 56px, 0);
    animation: ${enhancedGlitchAnimation} 7s infinite linear alternate-reverse;
    animation-delay: 1s;
  }
`;

export const EnhancedTypewriterText = styled.div`
  overflow: hidden;
  white-space: nowrap;
  display: inline-block;
  border-right: 0.15em solid ${THEME.colors.textPrimary};
  margin: 0;
  animation: 
    ${enhancedTypewriterAnimation} ${props => props.duration || '3.5s'} steps(${props => props.steps || 40}, end),
    ${enhancedCursorBlinkAnimation} 0.75s step-end infinite;
`;

export const EnhancedFlickeringText = styled.span`
  animation: ${enhancedFlickerTextAnimation} ${props => props.duration || '3s'} ease-in-out infinite;
  display: inline-block;
`;

export const EnhancedPulsingElement = styled.div`
  animation: ${enhancedPulseAnimation} ${props => props.duration || '3s'} ease-in-out infinite;
`;

export const EnhancedFloatingElement = styled.div`
  animation: ${enhancedFloatAnimation} ${props => props.duration || '6s'} ease-in-out infinite;
  transform-origin: center;
`;

export const EnhancedRotatingElement = styled.div`
  animation: ${enhancedRotateAnimation} ${props => props.duration || '20s'} linear infinite;
  transform-origin: center;
`;

export const EnhancedFadeInElement = styled.div`
  opacity: 0;
  animation: ${enhancedFadeInAnimation} ${props => props.duration || '0.5s'} 
    ${props => props.curve || 'cubic-bezier(0.34, 1.56, 0.64, 1)'} 
    ${props => props.delay || '0ms'} forwards;
`;

export const EnhancedExpandElement = styled.div`
  max-height: 0;
  overflow: hidden;
  opacity: 0;
  animation: ${enhancedExpandAnimation} ${props => props.duration || '0.7s'}
    ${props => props.curve || 'cubic-bezier(0.34, 1.56, 0.64, 1)'}
    ${props => props.delay || '0ms'} forwards;
`;

export const EnhancedParadoxElement = styled.div`
  animation: ${enhancedParadoxAnimation} ${props => props.duration || '15s'} linear infinite;
  transform-style: preserve-3d;
`;

export const EnhancedThoughtFlowParticle = styled.div`
  position: absolute;
  width: ${props => props.size || '10px'};
  height: ${props => props.size || '10px'};
  background-color: ${props => props.color || 'rgba(255, 255, 255, 0.2)'};
  border-radius: 50%;
  pointer-events: none;
  animation: ${enhancedThoughtFlowAnimation} ${props => props.duration || '5s'} 
    ease-in-out 
    ${props => props.delay || '0ms'} infinite;
`;

export const EnhancedScanlineOverlay = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  ${enhancedScanline('10s', '0ms', 'linear')}
  opacity: ${props => props.opacity || 0.3};
  z-index: ${props => props.zIndex || 1};
`;

export const EnhancedTextDistortContainer = styled.div`
  display: inline-block;
  ${enhancedTextDistort()}
`;

// ======================================================
// ENHANCED DIALOGUE-SPECIFIC ANIMATIONS
// ======================================================

export const EnhancedDialogueExpansionAnimation = css`
  .dialogue-expanding {
    ${enhancedExpand()}
    transform-origin: top;
  }
  
  .dialogue-collapsing {
    ${enhancedCollapse()}
    transform-origin: top;
  }
  
  .question-appearing {
    ${enhancedFadeIn('0.5s', '0ms', 'cubic-bezier(0.34, 1.56, 0.64, 1)')}
  }
  
  .answer-appearing {
    ${enhancedFadeIn('0.7s', '0.2s', 'cubic-bezier(0.34, 1.56, 0.64, 1)')}
  }
  
  .dialogue-node-enter {
    opacity: 0;
    transform: translateY(20px);
    filter: blur(5px);
  }
  
  .dialogue-node-enter-active {
    opacity: 1;
    transform: translateY(0);
    filter: blur(0);
    transition: opacity 0.5s, transform 0.5s, filter 0.5s;
    transition-timing-function: cubic-bezier(0.34, 1.56, 0.64, 1);
  }
  
  .dialogue-node-exit {
    opacity: 1;
    transform: translateY(0);
    filter: blur(0);
  }
  
  .dialogue-node-exit-active {
    opacity: 0;
    transform: translateY(-20px);
    filter: blur(5px);
    transition: opacity 0.3s, transform 0.3s, filter 0.3s;
  }
  
  .dialogue-transition-right {
    transition: transform 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
  }
`;

export const EnhancedThoughtFlowEffectAnimation = css`
  .thought-flow-container {
    position: absolute;
    width: 100%;
    height: 100%;
    pointer-events: none;
    z-index: 1;
    overflow: hidden;
  }
  
  .thought-bubble {
    ${enhancedThoughtBubble()}
    position: relative;
  }
  
  .thought-particle {
    ${enhancedThoughtFlow()}
    position: absolute;
    border-radius: 50%;
    background-color: rgba(255, 255, 255, 0.1);
    filter: blur(2px);
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
    ${enhancedThoughtFlow('7s', '0ms', 'ease-in-out')}
    filter: blur(1px);
  }
`;

export const EnhancedParadoxTransitionAnimation = css`
  .paradox-container {
    perspective: 1000px;
    position: relative;
    transform-style: preserve-3d;
  }
  
  .paradox-layer {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    ${enhancedParadox()}
    backface-visibility: hidden;
  }
  
  .paradox-fade {
    position: relative;
    opacity: 0;
    transform: scale(0.9);
    filter: blur(5px);
    transition: 
      opacity 0.7s cubic-bezier(0.34, 1.56, 0.64, 1),
      transform 0.7s cubic-bezier(0.34, 1.56, 0.64, 1),
      filter 0.7s cubic-bezier(0.34, 1.56, 0.64, 1);
  }
  
  .paradox-fade.active {
    opacity: 1;
    transform: scale(1);
    filter: blur(0);
  }
  
  .paradox-loop-active {
    ${enhancedExistentialLoop()}
  }
  
  .infinite-recursion {
    position: relative;
    ${enhancedVoidInfinite()}
  }
  
  .paradox-glitch {
    position: relative;
    overflow: hidden;
    ${enhancedHeavyGlitch()}
    
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

// Make sure to export both the original Glitch component and the Enhanced version
export const GlitchEffect = EnhancedGlitchText;
export const TypewriterText = EnhancedTypewriterText;

export default {
  // Enhanced keyframes
  enhancedGlitchAnimation,
  heavyGlitchAnimation,
  enhancedPulseAnimation,
  enhancedFloatAnimation,
  enhancedRotateAnimation,
  enhancedFadeInAnimation,
  enhancedFadeOutAnimation,
  enhancedTypewriterAnimation,
  enhancedCursorBlinkAnimation,
  enhancedFlickerTextAnimation,
  enhancedExpandAnimation,
  enhancedCollapseAnimation,
  enhancedThoughtBubbleAnimation,
  enhancedThoughtFlowAnimation,
  enhancedExistentialLoopAnimation,
  enhancedParadoxAnimation,
  enhancedVoidInfiniteAnimation,
  enhancedTextDistortAnimation,
  enhancedScanlineAnimation,
  
  // Enhanced mixins
  enhancedFadeIn,
  enhancedFadeOut,
  enhancedPulse,
  enhancedFloat,
  enhancedRotate,
  enhancedGlitch,
  enhancedHeavyGlitch,
  enhancedTypewriter,
  enhancedFlicker,
  enhancedExpand,
  enhancedCollapse,
  enhancedThoughtBubble,
  enhancedThoughtFlow,
  enhancedExistentialLoop,
  enhancedParadox,
  enhancedVoidInfinite,
  enhancedTextDistort,
  enhancedScanline,
  
  // Enhanced components
  EnhancedGlitchText,
  EnhancedTypewriterText,
  EnhancedFlickeringText,
  EnhancedPulsingElement,
  EnhancedFloatingElement,
  EnhancedRotatingElement,
  EnhancedFadeInElement,
  EnhancedExpandElement,
  EnhancedParadoxElement,
  EnhancedThoughtFlowParticle,
  EnhancedScanlineOverlay,
  EnhancedTextDistortContainer,
  
  // Enhanced dialogue-specific animations
  EnhancedDialogueExpansionAnimation,
  EnhancedThoughtFlowEffectAnimation,
  EnhancedParadoxTransitionAnimation,
  
  // Original named components for compatibility
  GlitchEffect: EnhancedGlitchText,
  TypewriterText: EnhancedTypewriterText,
  DialogueExpansionAnimation: EnhancedDialogueExpansionAnimation,
  ThoughtFlowEffectAnimation: EnhancedThoughtFlowEffectAnimation,
  ParadoxTransitionAnimation: EnhancedParadoxTransitionAnimation,
};
