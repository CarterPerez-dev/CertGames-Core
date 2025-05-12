// frontend/my-react-app/src/components/pages/angela/styles/AngelaStyles.js
// Main styling for the Angela CLI page components
import { css } from '@emotion/react';
import styled from '@emotion/styled';
import { ANGELA_THEME as THEME } from './PhilosophicalTheme';

// ======================================================
// GLOBAL STYLES
// ======================================================

export const angelaGlobalStyles = css`
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=IBM+Plex+Serif:wght@400;500;600&family=Press+Start+2P&family=VT323&display=swap');
  
  .angela-page {
    background-color: ${THEME.colors.bgPrimary};
    color: ${THEME.colors.textPrimary};
    font-family: ${THEME.typography.fontFamilyPrimary};
    line-height: ${THEME.typography.lineHeightNormal};
    overflow-x: hidden;
    position: relative;
    min-height: 100vh;
    
    * {
      box-sizing: border-box;
    }

    // Prevent inheritance from parent site
    h1, h2, h3, h4, h5, h6, p, span, div, button, a, input, textarea, ul, ol, li {
      font-family: ${THEME.typography.fontFamilyPrimary};
      margin: 0;
      padding: 0;
    }
    
    // Define scroll styles
    ::-webkit-scrollbar {
      width: 8px;
      height: 8px;
    }
    
    ::-webkit-scrollbar-track {
      background: ${THEME.colors.bgSecondary};
    }
    
    ::-webkit-scrollbar-thumb {
      background: ${THEME.colors.borderPrimary};
      border-radius: ${THEME.shapes.radiusSm};
    }
    
    ::-webkit-scrollbar-thumb:hover {
      background: ${THEME.colors.borderSecondary};
    }
    
    // Selection styles
    ::selection {
      background: ${THEME.colors.accentPrimary};
      color: ${THEME.colors.textPrimary};
      text-shadow: none;
    }
  }
  
  // Add keyframe animations used throughout the Angela page
  @keyframes ${THEME.animations.keyframeGlitch} {
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
  }
  
  @keyframes ${THEME.animations.keyframeTypewriter} {
    from { width: 0; }
    to { width: 100%; }
  }
  
  @keyframes ${THEME.animations.keyframePulse} {
    0% { opacity: 1; }
    50% { opacity: 0.6; }
    100% { opacity: 1; }
  }
  
  @keyframes ${THEME.animations.keyframeVHSTrack} {
    0% {
      transform: translateY(0);
    }
    100% {
      transform: translateY(100vh);
    }
  }
  
  @keyframes ${THEME.animations.keyframeMatrixRain} {
    0% {
      top: -10%;
      opacity: 1;
    }
    20% {
      opacity: 0.8;
    }
    50% {
      opacity: 0.6;
    }
    70% {
      opacity: 0.4;
    }
    100% {
      top: 100%;
      opacity: 0;
    }
  }
  
  @keyframes ${THEME.animations.keyframeThoughtFlow} {
    0% {
      transform: translateY(0) rotate(0deg);
      opacity: 0;
    }
    10% {
      opacity: 0.8;
    }
    90% {
      opacity: 0.6;
    }
    100% {
      transform: translateY(-50px) rotate(10deg);
      opacity: 0;
    }
  }
  
  @keyframes ${THEME.animations.keyframeExistentialLoop} {
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
  }
  
  @keyframes ${THEME.animations.keyframeFlickerText} {
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
  }
  
  @keyframes ${THEME.animations.keyframeExpansionPulse} {
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
  }
`;

// ======================================================
// LAYOUT COMPONENTS
// ======================================================

export const AngelaPageContainer = styled.div`
  width: 100%;
  min-height: 100vh;
  background-color: ${THEME.colors.bgPrimary};
  position: relative;
  overflow: hidden;
  
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    ${THEME.effects.scanlines}
    pointer-events: none;
    z-index: ${THEME.zIndex.background + 1};
    opacity: 0.3;
  }
  
  &::after {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    ${THEME.effects.vhsNoise}
    pointer-events: none;
    z-index: ${THEME.zIndex.background + 2};
  }
`;

export const AngelaContent = styled.main`
  max-width: 1200px;
  margin: 0 auto;
  padding: ${THEME.spacing.xl};
  position: relative;
  z-index: ${THEME.zIndex.base};
  
  @media (max-width: ${THEME.breakpoints.lg}) {
    padding: ${THEME.spacing.lg};
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    padding: ${THEME.spacing.md};
  }
`;

export const AngelaSection = styled.section`
  margin: ${THEME.spacing.xxl} 0;
  position: relative;
`;

export const AngelaAbyss = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: linear-gradient(
    to bottom,
    ${THEME.colors.bgPrimary} 0%,
    ${THEME.colors.voidBlack} 100%
  );
  z-index: ${THEME.zIndex.background};
`;

export const TerminalWindow = styled.div`
  ${THEME.effects.terminal}
  position: relative;
  margin: ${THEME.spacing.lg} 0;
  overflow: hidden;
  
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 28px;
    background: ${THEME.colors.bgSecondary};
    border-bottom: 1px solid ${THEME.colors.borderPrimary};
    display: flex;
    align-items: center;
    padding: 0 ${THEME.spacing.md};
  }
  
  &::after {
    content: "";
    position: absolute;
    top: 10px;
    left: ${THEME.spacing.md};
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: ${THEME.colors.accentPrimary};
    box-shadow: 20px 0 0 ${THEME.colors.terminalYellow}, 40px 0 0 ${THEME.colors.terminalGreen};
  }
`;

export const TerminalContent = styled.div`
  margin-top: 28px;
  padding: ${THEME.spacing.md};
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: ${THEME.typography.size14};
  line-height: 1.6;
  color: ${THEME.colors.textPrimary};
  
  pre {
    margin: 0;
    white-space: pre-wrap;
  }
`;

export const TerminalPrompt = styled.span`
  color: ${THEME.colors.terminalGreen};
  margin-right: ${THEME.spacing.xs};
  
  &::before {
    content: "${THEME.typography.terminalPrompt}";
  }
`;

// ======================================================
// TEXT COMPONENTS
// ======================================================

export const HeadingPrimary = styled.h1`
  font-family: ${THEME.typography.fontFamilySecondary};
  font-weight: ${THEME.typography.weightBold};
  font-size: ${THEME.typography.size48};
  line-height: ${THEME.typography.lineHeightTight};
  margin-bottom: ${THEME.spacing.lg};
  letter-spacing: ${THEME.typography.spacingWide};
  color: ${THEME.colors.textPrimary};
  text-transform: uppercase;
  
  ${props => props.glitch && `
    position: relative;
    
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
      animation: ${THEME.animations.keyframeGlitch} 5s infinite linear alternate-reverse;
    }
    
    &::after {
      left: -2px;
      text-shadow: -1px 0 ${THEME.colors.linkBlue};
      clip: rect(44px, 450px, 56px, 0);
      animation: ${THEME.animations.keyframeGlitch} 7s infinite linear alternate-reverse;
      animation-delay: 1s;
    }
  `}
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: ${THEME.typography.size36};
  }
`;

export const HeadingSecondary = styled.h2`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-weight: ${THEME.typography.weightMedium};
  font-size: ${THEME.typography.size28};
  line-height: ${THEME.typography.lineHeightSnug};
  margin-bottom: ${THEME.spacing.md};
  color: ${THEME.colors.textPrimary};
  
  ${props => props.philosophical && `
    font-family: ${THEME.typography.fontFamilyPhilosophical};
    font-style: italic;
    border-bottom: 1px solid ${THEME.colors.borderPrimary};
    padding-bottom: ${THEME.spacing.sm};
  `}
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: ${THEME.typography.size24};
  }
`;

export const HeadingTertiary = styled.h3`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-weight: ${THEME.typography.weightSemibold};
  font-size: ${THEME.typography.size20};
  line-height: ${THEME.typography.lineHeightSnug};
  margin-bottom: ${THEME.spacing.sm};
  color: ${props => props.accent ? THEME.colors.accentPrimary : THEME.colors.textPrimary};
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: ${THEME.typography.size18};
  }
`;

export const Paragraph = styled.p`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: ${THEME.typography.size16};
  line-height: ${THEME.typography.lineHeightRelaxed};
  margin-bottom: ${THEME.spacing.md};
  color: ${THEME.colors.textPrimary};
  
  ${props => props.secondary && `
    color: ${THEME.colors.textSecondary};
  `}
  
  ${props => props.philosophical && `
    font-family: ${THEME.typography.fontFamilyPhilosophical};
    font-style: italic;
    letter-spacing: ${THEME.typography.spacingWide};
  `}
  
  ${props => props.typing && `
    overflow: hidden;
    white-space: nowrap;
    animation: 
      ${THEME.animations.keyframeTypewriter} ${props.typingSpeed || THEME.animations.typingSpeedSlow} steps(${props.characters || 40}, end) forwards,
      cursor-blink 1s infinite;
      
    @keyframes cursor-blink {
      from, to { border-right-color: transparent }
      50% { border-right-color: ${THEME.colors.textPrimary}; }
    }
  `}
`;

export const SmallText = styled.span`
  font-size: ${THEME.typography.size14};
  color: ${THEME.colors.textTertiary};
  
  ${props => props.muted && `
    color: ${THEME.colors.textMuted};
    font-size: ${THEME.typography.size12};
  `}
`;

export const BlockQuote = styled.blockquote`
  font-family: ${THEME.typography.fontFamilyPhilosophical};
  font-style: italic;
  font-size: ${THEME.typography.size18};
  line-height: ${THEME.typography.lineHeightRelaxed};
  color: ${THEME.colors.textAccent};
  border-left: 4px solid ${THEME.colors.accentPrimary};
  padding: ${THEME.spacing.md} ${THEME.spacing.lg};
  margin: ${THEME.spacing.lg} 0;
  background: ${THEME.colors.bgSecondary};
  position: relative;
  
  &::before {
    content: """;
    position: absolute;
    top: -${THEME.spacing.md};
    left: ${THEME.spacing.sm};
    font-size: ${THEME.typography.size64};
    color: ${THEME.colors.textMuted};
    opacity: 0.3;
  }
  
  p {
    margin: 0;
  }
  
  cite {
    display: block;
    margin-top: ${THEME.spacing.sm};
    font-size: ${THEME.typography.size14};
    color: ${THEME.colors.textSecondary};
    font-style: normal;
    
    &::before {
      content: "— ";
    }
  }
`;

export const CodeText = styled.code`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 0.9em;
  background: ${THEME.colors.bgCodeBlock};
  color: ${THEME.colors.textPrimary};
  padding: 0.2em 0.4em;
  border-radius: ${THEME.shapes.radiusSm};
  border: 1px solid ${THEME.colors.borderPrimary};
`;

export const Link = styled.a`
  color: ${THEME.colors.accentPrimary};
  text-decoration: none;
  position: relative;
  transition: color ${THEME.animations.durationFast} ${THEME.animations.curveEaseInOut};
  
  &:hover {
    color: ${THEME.colors.accentSecondary};
    text-decoration: underline;
  }
  
  ${props => props.glitched && `
    &:hover {
      animation: ${THEME.animations.keyframeGlitch} 0.3s ease-in-out;
    }
  `}
  
  ${props => props.terminal && `
    &::before {
      content: ">";
      margin-right: 4px;
      color: ${THEME.colors.terminalGreen};
    }
  `}
`;

// ======================================================
// BUTTON COMPONENTS
// ======================================================

export const Button = styled.button`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: ${THEME.typography.size16};
  font-weight: ${THEME.typography.weightMedium};
  background: ${THEME.components.button.background};
  color: ${THEME.components.button.text};
  border: 1px solid ${THEME.components.button.border};
  border-radius: ${THEME.components.button.borderRadius};
  padding: ${THEME.components.button.padding};
  cursor: pointer;
  transition: ${THEME.components.button.transition};
  display: inline-flex;
  align-items: center;
  justify-content: center;
  
  &:hover {
    background: ${THEME.components.button.hoverBg};
  }
  
  &:active {
    background: ${THEME.components.button.activeBg};
  }
  
  &:disabled {
    background: ${THEME.components.button.disabledBg};
    color: ${THEME.components.button.disabledText};
    cursor: not-allowed;
  }
  
  ${props => props.primary && `
    background: ${THEME.colors.accentPrimary};
    color: ${THEME.colors.textPrimary};
    border-color: ${THEME.colors.accentPrimary};
    
    &:hover {
      background: ${THEME.colors.accentSecondary};
      border-color: ${THEME.colors.accentSecondary};
    }
    
    &:active {
      background: ${THEME.colors.accentTertiary};
      border-color: ${THEME.colors.accentTertiary};
    }
  `}
  
  ${props => props.outline && `
    background: transparent;
    color: ${THEME.colors.accentPrimary};
    border-color: ${THEME.colors.accentPrimary};
    
    &:hover {
      background: ${THEME.colors.accentPrimary};
      color: ${THEME.colors.textPrimary};
    }
  `}
  
  ${props => props.ghost && `
    background: transparent;
    border-color: transparent;
    
    &:hover {
      background: ${THEME.colors.bgSecondary};
    }
  `}
  
  ${props => props.terminal && `
    font-family: ${THEME.typography.fontFamilySecondary};
    background: ${THEME.colors.bgTerminal};
    border: 1px solid ${THEME.colors.borderPrimary};
    color: ${THEME.colors.terminalGreen};
    letter-spacing: ${THEME.typography.spacingTerminal};
    padding: ${THEME.spacing.sm} ${THEME.spacing.lg};
    
    &::before {
      content: ">";
      margin-right: ${THEME.spacing.sm};
    }
    
    &:hover {
      background: ${THEME.colors.bgSecondary};
      box-shadow: 0 0 8px ${THEME.colors.terminalGreen};
    }
  `}
  
  ${props => props.size === 'small' && `
    font-size: ${THEME.typography.size14};
    padding: ${THEME.spacing.xs} ${THEME.spacing.sm};
  `}
  
  ${props => props.size === 'large' && `
    font-size: ${THEME.typography.size18};
    padding: ${THEME.spacing.md} ${THEME.spacing.lg};
  `}
  
  ${props => props.icon && `
    svg {
      margin-right: ${THEME.spacing.xs};
    }
  `}
  
  ${props => props.iconOnly && `
    padding: ${THEME.spacing.sm};
    width: 40px;
    height: 40px;
    
    svg {
      margin-right: 0;
    }
  `}
  
  ${props => props.expanded && `
    width: 100%;
  `}
  
  ${props => props.philosophical && `
    font-family: ${THEME.typography.fontFamilyPhilosophical};
    letter-spacing: ${THEME.typography.spacingWide};
    border: 1px solid ${THEME.colors.borderPrimary};
    background: transparent;
    position: relative;
    overflow: hidden;
    
    &::before {
      content: "";
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(
        90deg,
        transparent,
        rgba(255, 255, 255, 0.1),
        transparent
      );
      transition: all 0.6s;
    }
    
    &:hover::before {
      left: 100%;
    }
  `}
`;

// ======================================================
// GRID COMPONENTS
// ======================================================

export const GridContainer = styled.div`
  display: grid;
  grid-template-columns: ${props => 
    props.columns 
      ? `repeat(${props.columns}, 1fr)` 
      : 'repeat(12, 1fr)'
  };
  gap: ${props => props.gap || THEME.spacing.gridGap};
  width: 100%;
  
  @media (max-width: ${THEME.breakpoints.lg}) {
    grid-template-columns: ${props => 
      props.tabletColumns 
        ? `repeat(${props.tabletColumns}, 1fr)` 
        : 'repeat(6, 1fr)'
    };
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    grid-template-columns: ${props => 
      props.mobileColumns 
        ? `repeat(${props.mobileColumns}, 1fr)` 
        : 'repeat(4, 1fr)'
    };
  }
`;

export const GridItem = styled.div`
  grid-column: ${props => props.span ? `span ${props.span}` : 'span 12'};
  
  @media (max-width: ${THEME.breakpoints.lg}) {
    grid-column: ${props => props.tabletSpan ? `span ${props.tabletSpan}` : props.span ? `span ${props.span}` : 'span 6'};
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    grid-column: ${props => props.mobileSpan ? `span ${props.mobileSpan}` : 'span 4'};
  }
`;

// ======================================================
// FLEX COMPONENTS
// ======================================================

export const FlexContainer = styled.div`
  display: flex;
  flex-direction: ${props => props.direction || 'row'};
  justify-content: ${props => props.justify || 'flex-start'};
  align-items: ${props => props.align || 'stretch'};
  flex-wrap: ${props => props.wrap || 'nowrap'};
  gap: ${props => props.gap || THEME.spacing.md};
  
  @media (max-width: ${THEME.breakpoints.md}) {
    flex-direction: ${props => props.mobileFlex || 'column'};
  }
`;

// ======================================================
// UTILITY COMPONENTS
// ======================================================

export const ScanlineOverlay = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  z-index: ${THEME.zIndex.overlay};
  opacity: 0.3;
  ${THEME.effects.scanlines}
`;

export const GlitchOverlay = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  z-index: ${THEME.zIndex.glitch};
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3CfeColorMatrix type='matrix' values='1 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 0.5 0'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E");
  opacity: 0.05;
  animation: ${THEME.animations.keyframeGlitch} 10s infinite;
`;

export const Divider = styled.hr`
  border: 0;
  height: 1px;
  background: ${THEME.colors.borderPrimary};
  margin: ${THEME.spacing.xl} 0;
`;

export const Spacer = styled.div`
  height: ${props => props.size || THEME.spacing.md};
`;

export const Badge = styled.span`
  display: inline-block;
  background: ${props => props.variant === 'primary' ? THEME.colors.accentPrimary : THEME.colors.bgSecondary};
  color: ${THEME.colors.textPrimary};
  font-size: ${THEME.typography.size12};
  font-weight: ${THEME.typography.weightMedium};
  padding: ${THEME.spacing.xs} ${THEME.spacing.sm};
  border-radius: ${THEME.shapes.radiusFull};
  margin-right: ${THEME.spacing.xs};
`;

export const Icon = styled.span`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: ${props => props.size || '24px'};
  height: ${props => props.size || '24px'};
  color: ${props => props.color || THEME.colors.textPrimary};
  
  svg {
    width: 100%;
    height: 100%;
  }
`;

export const TerminalBlinker = styled.span`
  display: inline-block;
  width: 8px;
  height: 16px;
  background-color: ${THEME.colors.textPrimary};
  animation: ${THEME.animations.keyframePulse} 1s infinite;
  margin-left: 2px;
`;

export const ScrollingText = styled.div`
  overflow: hidden;
  white-space: nowrap;
  position: relative;
  padding: ${THEME.spacing.sm} 0;
  
  .scrolling-text-content {
    display: inline-block;
    animation: scrolling-text 20s linear infinite;
    padding-right: ${THEME.spacing.lg};
  }
  
  @keyframes scrolling-text {
    0% { transform: translateX(100%); }
    100% { transform: translateX(-100%); }
  }
`;

export const MatrixRain = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  overflow: hidden;
  z-index: ${props => props.zIndex || THEME.zIndex.background};
  opacity: ${props => props.opacity || 0.1};
  
  .matrix-drop {
    position: absolute;
    color: ${THEME.colors.terminalGreen};
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: ${THEME.typography.size16};
    line-height: 1;
    animation: ${THEME.animations.keyframeMatrixRain} 8s linear infinite;
  }
`;

// ======================================================
// SPECIFIC COMPONENTS FOR ANGELA CLI PAGE
// ======================================================

export const AngelaLogo = styled.div`
  font-family: ${THEME.typography.fontFamilySecondary};
  font-size: ${THEME.typography.size48};
  font-weight: ${THEME.typography.weightBold};
  color: ${THEME.colors.textPrimary};
  margin-bottom: ${THEME.spacing.lg};
  letter-spacing: ${THEME.typography.spacingWide};
  position: relative;
  display: inline-block;
  
  .logo-text {
    position: relative;
    
    &::before {
      content: attr(data-text);
      position: absolute;
      left: -2px;
      text-shadow: 2px 0 ${THEME.colors.accentPrimary};
      clip: rect(44px, 450px, 56px, 0);
      animation: ${THEME.animations.keyframeGlitch} 5s infinite linear alternate-reverse;
    }
    
    &::after {
      content: attr(data-text);
      position: absolute;
      left: 2px;
      text-shadow: -2px 0 ${THEME.colors.terminalGreen};
      clip: rect(44px, 450px, 56px, 0);
      animation: ${THEME.animations.keyframeGlitch} 7s infinite linear alternate-reverse;
      animation-delay: 1s;
    }
  }
  
  .logo-icon {
    margin-right: ${THEME.spacing.sm};
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: ${THEME.typography.size32};
  }
`;

export const FeatureCard = styled.div`
  background: ${THEME.colors.bgSecondary};
  border: 1px solid ${THEME.colors.borderPrimary};
  border-radius: ${THEME.shapes.radiusMd};
  padding: ${THEME.spacing.lg};
  transition: all ${THEME.animations.durationMedium} ${THEME.animations.curveEaseInOut};
  
  &:hover {
    transform: translateY(-5px);
    box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3);
    border-color: ${THEME.colors.accentPrimary};
  }
  
  .feature-icon {
    font-size: ${THEME.typography.size32};
    color: ${THEME.colors.accentPrimary};
    margin-bottom: ${THEME.spacing.md};
  }
  
  h3 {
    font-size: ${THEME.typography.size20};
    margin-bottom: ${THEME.spacing.sm};
  }
  
  p {
    color: ${THEME.colors.textSecondary};
    margin-bottom: 0;
  }
`;

export const InstallBox = styled.div`
  background: ${THEME.colors.bgTerminal};
  border: 1px solid ${THEME.colors.borderPrimary};
  border-radius: ${THEME.shapes.radiusSm};
  padding: ${THEME.spacing.lg};
  margin: ${THEME.spacing.xl} 0;
  
  pre {
    margin: ${THEME.spacing.md} 0;
    padding: ${THEME.spacing.md};
    background: ${THEME.colors.bgCodeBlock};
    border-radius: ${THEME.shapes.radiusSm};
    overflow-x: auto;
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: ${THEME.typography.size14};
    color: ${THEME.colors.textPrimary};
  }
  
  .copy-button {
    position: absolute;
    top: ${THEME.spacing.sm};
    right: ${THEME.spacing.sm};
    background: ${THEME.colors.bgSecondary};
    border: 1px solid ${THEME.colors.borderPrimary};
    color: ${THEME.colors.textSecondary};
    border-radius: ${THEME.shapes.radiusSm};
    padding: ${THEME.spacing.xs} ${THEME.spacing.sm};
    font-size: ${THEME.typography.size12};
    cursor: pointer;
    transition: all ${THEME.animations.durationMedium};
    
    &:hover {
      background: ${THEME.colors.bgTertiary};
      color: ${THEME.colors.textPrimary};
    }
  }
`;

export const PhilosophicalQuote = styled.div`
  padding: ${THEME.spacing.lg};
  margin: ${THEME.spacing.xl} 0;
  position: relative;
  font-family: ${THEME.typography.fontFamilyPhilosophical};
  font-style: italic;
  font-size: ${THEME.typography.size18};
  color: ${THEME.colors.textPrimary};
  border-left: 4px solid ${THEME.colors.accentPrimary};
  background: ${THEME.colors.bgSecondary};
  
  &::before {
    content: """;
    position: absolute;
    top: -${THEME.spacing.lg};
    left: ${THEME.spacing.sm};
    font-size: ${THEME.typography.size72};
    color: ${THEME.colors.accentPrimary};
    opacity: 0.2;
  }
  
  cite {
    display: block;
    margin-top: ${THEME.spacing.md};
    font-style: normal;
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: ${THEME.typography.size14};
    color: ${THEME.colors.textSecondary};
    
    &::before {
      content: "— ";
    }
  }
`;

export const GlitchText = styled.span`
  position: relative;
  display: inline-block;
  
  &::before,
  &::after {
    content: attr(data-text);
    position: absolute;
    top: 0;
    width: 100%;
    height: 100%;
  }
  
  &::before {
    left: 2px;
    text-shadow: -1px 0 ${THEME.colors.accentPrimary};
    clip: rect(44px, 450px, 56px, 0);
    animation: ${THEME.animations.keyframeGlitch} 5s infinite linear alternate-reverse;
  }
  
  &::after {
    left: -2px;
    text-shadow: -1px 0 ${THEME.colors.terminalCyan};
    clip: rect(44px, 450px, 56px, 0);
    animation: ${THEME.animations.keyframeGlitch} 7s infinite linear alternate-reverse;
    animation-delay: 1s;
  }
`;

export const CTASection = styled.div`
  background: linear-gradient(
    to bottom,
    ${THEME.colors.bgSecondary} 0%,
    ${THEME.colors.bgPrimary} 100%
  );
  padding: ${THEME.spacing.xxl} 0;
  border-top: 1px solid ${THEME.colors.borderPrimary};
  border-bottom: 1px solid ${THEME.colors.borderPrimary};
  text-align: center;
  margin: ${THEME.spacing.xxxl} 0;
  
  h2 {
    font-size: ${THEME.typography.size36};
    margin-bottom: ${THEME.spacing.lg};
  }
  
  p {
    max-width: 600px;
    margin: 0 auto ${THEME.spacing.xl};
    font-size: ${THEME.typography.size18};
  }
  
  .cta-buttons {
    display: flex;
    gap: ${THEME.spacing.md};
    justify-content: center;
    
    @media (max-width: ${THEME.breakpoints.sm}) {
      flex-direction: column;
      align-items: center;
    }
  }
`;

export const VideoDemo = styled.div`
  position: relative;
  width: 100%;
  padding-bottom: 56.25%; // 16:9 aspect ratio
  background: ${THEME.colors.bgSecondary};
  border: 1px solid ${THEME.colors.borderPrimary};
  border-radius: ${THEME.shapes.radiusMd};
  overflow: hidden;
  margin: ${THEME.spacing.xl} 0;
  
  iframe {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: ${THEME.colors.bgSecondary};
  }
  
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 5px;
    background: linear-gradient(
      to right,
      ${THEME.colors.accentPrimary},
      ${THEME.colors.terminalGreen}
    );
    z-index: 1;
  }
`;

export default {
  AngelaPageContainer,
  AngelaContent,
  AngelaSection,
  HeadingPrimary,
  HeadingSecondary,
  HeadingTertiary,
  Paragraph,
  Button,
  Link,
  TerminalWindow,
  TerminalContent,
  TerminalPrompt,
  GridContainer,
  GridItem,
  FlexContainer,
  Divider,
  Spacer,
  Badge,
  Icon,
  ScanlineOverlay,
  GlitchOverlay,
  MatrixRain,
  AngelaLogo,
  FeatureCard,
  InstallBox,
  PhilosophicalQuote,
  GlitchText,
  CTASection,
  VideoDemo,
};
