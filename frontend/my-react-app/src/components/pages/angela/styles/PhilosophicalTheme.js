// frontend/my-react-app/src/components/pages/angela/styles/PhilosophicalTheme.js
// Core theme definition for the Angela CLI page
// This establishes the foundation of our philosophical, terminal-inspired design system

/**
 * Primary color palette for the Angela-CLI philosophical terminal theme
 * Uses a carefully selected range of dark tones with accent highlights
 */
export const ANGELA_COLORS = {
  // Core background shades
  bgPrimary: '#0a0a0a',       // Almost pure black for main background
  bgSecondary: '#121212',     // Slightly lighter black for secondary elements
  bgTertiary: '#1a1a1a',      // Dark gray for tertiary elements
  bgTerminal: '#101010',      // Terminal background
  
  // UI element backgrounds
  bgElevated: '#1a1a1a',      // Elevated surface background
  bgCodeBlock: '#121215',     // Code block background 
  bgHighlight: '#151515',     // Highlighted area background
  bgGlitch: '#131317',        // Glitch effect background
  
  // Borders and separators
  borderPrimary: '#333333',   // Primary border color
  borderSecondary: '#222222', // Secondary border color
  borderGlow: '#444444',      // Glowing border color
  borderHighlight: '#555555', // Highlighted border
  
  // Text colors
  textPrimary: '#e0e0e0',     // Primary text color (off-white)
  textSecondary: '#aaaaaa',   // Secondary text (light gray)
  textTertiary: '#777777',    // Tertiary text (medium gray)
  textAccent: '#cccccc',      // Accent text (brighter gray)
  textMuted: '#555555',       // Muted text (darker gray)
  
  // Accent colors
  accentPrimary: '#ff3333',   // Primary accent (red)
  accentSecondary: '#ff5555', // Secondary accent (lighter red)
  accentTertiary: '#990000',  // Tertiary accent (darker red)
  accentGlow: 'rgba(255, 50, 50, 0.6)', // Glowing accent
  
  // Terminal colors
  terminalGreen: '#33ff33',   // Terminal green text
  terminalCyan: '#33ffff',    // Terminal cyan
  terminalYellow: '#ffff33',  // Terminal yellow
  
  // Philosophical gradient points
  paradoxStart: '#131313',    // Start of paradox gradient
  paradoxEnd: '#1f1f1f',      // End of paradox gradient
  
  // Utility colors
  transparent: 'transparent',
  errorRed: '#ff3333',
  linkBlue: '#3399ff',
  successGreen: '#33cc33',
  
  // 8-bit pixel art specific colors
  pixelRed: '#ff0000',
  pixelWhite: '#ffffff',
  pixelGray: '#aaaaaa',
  pixelBlack: '#000000',
  
  // Glitch effect colors
  glitchRed: '#ff0000',
  glitchBlue: '#0000ff',
  glitchGreen: '#00ff00',
  
  // Philosophical theme special colors
  voidBlack: '#000000',       // The void/abyss
  consciousnessWhite: '#ffffff', // Consciousness
  existentialGray: '#666666', // Existential dread
  enlightenmentGlow: 'rgba(255, 255, 255, 0.1)', // Subtle enlightenment
};

/**
 * Typography system for the Angela CLI page
 * Uses monospace fonts with carefully tuned sizes and weights
 */
export const ANGELA_TYPOGRAPHY = {
  // Font families
  fontFamilyPrimary: "'IBM Plex Mono', 'Courier New', monospace",
  fontFamilySecondary: "'VT323', 'Press Start 2P', monospace", // More 8-bit style
  fontFamilyAccent: "'Press Start 2P', monospace", // Pure 8-bit for accents
  fontFamilyPhilosophical: "'IBM Plex Serif', 'Times New Roman', serif", // For philosophical quotes
  
  // Font weights
  weightLight: 300,
  weightRegular: 400,
  weightMedium: 500,
  weightSemibold: 600,
  weightBold: 700,
  
  // Font sizes
  size8: '0.5rem',      // 8px
  size10: '0.625rem',   // 10px
  size12: '0.75rem',    // 12px
  size14: '0.875rem',   // 14px
  size16: '1rem',       // 16px
  size18: '1.125rem',   // 18px
  size20: '1.25rem',    // 20px
  size24: '1.5rem',     // 24px
  size28: '1.75rem',    // 28px
  size32: '2rem',       // 32px
  size36: '2.25rem',    // 36px
  size42: '2.625rem',   // 42px
  size48: '3rem',       // 48px
  size56: '3.5rem',     // 56px
  size64: '4rem',       // 64px
  size72: '4.5rem',     // 72px
  
  // Line heights
  lineHeightTight: 1.1,
  lineHeightSnug: 1.2,
  lineHeightNormal: 1.5,
  lineHeightRelaxed: 1.75,
  lineHeightLoose: 2,
  
  // Letter spacing
  spacingTight: '-0.05em',
  spacingNormal: '0',
  spacingWide: '0.05em',
  spacingTerminal: '0.1em', // Terminal-like wide spacing
  spacingGlitch: '-0.02em', // Subtle glitch effect in text
  
  // Terminal specific
  terminalPrompt: '$ ',
  cursorBlink: '|',
};

/**
 * Spacing system for consistent layout
 */
export const ANGELA_SPACING = {
  none: '0',
  xs: '0.25rem',    // 4px
  sm: '0.5rem',     // 8px
  md: '1rem',       // 16px
  lg: '1.5rem',     // 24px
  xl: '2rem',       // 32px
  xxl: '3rem',      // 48px
  xxxl: '4rem',     // 64px
  
  // Grid specific
  gridGap: '1rem',
  gridGapLarge: '2rem',
  
  // Terminal specific
  terminalPadding: '1.5rem',
  lineSpacing: '1.5rem',
  paragraphSpacing: '2rem',
};

/**
 * Animation timings and curves
 */
export const ANGELA_ANIMATIONS = {
  // Durations
  durationFast: '150ms',
  durationMedium: '300ms',
  durationSlow: '500ms',
  durationVeryFast: '50ms',
  durationVerySlow: '800ms',
  durationGlitch: '100ms',
  
  // Typing speeds
  typingSpeedFast: '50ms',
  typingSpeedNormal: '80ms',
  typingSpeedSlow: '120ms',
  
  // Curves
  curveEaseOut: 'cubic-bezier(0.17, 0.67, 0.83, 0.67)',
  curveEaseIn: 'cubic-bezier(0.32, 0, 0.67, 0)',
  curveEaseInOut: 'cubic-bezier(0.65, 0, 0.35, 1)',
  curveGlitch: 'steps(2, jump-none)',
  curveTerminal: 'steps(8, end)',
  curvePhilosophical: 'cubic-bezier(0.34, 1.56, 0.64, 1)', // Philosophical contemplation
  
  // Delay increments
  delayXs: '50ms',
  delaySm: '100ms',
  delayMd: '200ms',
  delayLg: '300ms',
  delayXl: '500ms',
  
  // Keyframe names
  keyframeGlitch: 'angelaGlitch',
  keyframeTypewriter: 'angelaTypewriter',
  keyframePulse: 'angelaPulse',
  keyframeVHSTrack: 'angelaVHSTrack',
  keyframeMatrixRain: 'angelaMatrixRain',
  keyframeThoughtFlow: 'angelaThoughtFlow',
  keyframeExistentialLoop: 'angelaExistentialLoop',
  keyframeFlickerText: 'angelaFlickerText',
  keyframeExpansionPulse: 'angelaExpansionPulse',
};

/**
 * Z-index management system
 */
export const ANGELA_Z_INDEX = {
  background: -1,
  base: 0,
  elevated: 10,
  overlay: 100,
  modal: 1000,
  popover: 2000,
  tooltip: 3000,
  glitch: 50, // Glitch effects above content but below overlays
  existentialVoid: -99, // The void is below everything
  consciousness: 9999, // Consciousness is above all
};

/**
 * Border radiuses and other shape properties
 */
export const ANGELA_SHAPES = {
  radiusNone: '0',
  radiusSm: '2px',
  radiusMd: '4px',
  radiusLg: '8px',
  radiusXl: '16px',
  radiusFull: '9999px',
  
  // Terminal specific
  terminalRadius: '4px',
  pixelRadius: '2px', // For pixel-perfect corners
  
  // Border widths
  borderWidthThin: '1px',
  borderWidthMedium: '2px',
  borderWidthThick: '4px',
  borderWidthPixel: '1px', // For pixel-art style borders
  
  // Special shapes
  dialogueBubbleRadius: '4px',
  thoughtBubbleRadius: '12px 12px 12px 0',
};

/**
 * Shadow definitions for depth and elevation
 */
export const ANGELA_SHADOWS = {
  none: 'none',
  sm: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
  md: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
  lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
  xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
  
  // Terminal specific
  terminalGlow: '0 0 10px rgba(0, 0, 0, 0.3), 0 0 20px rgba(0, 0, 0, 0.2)',
  textGlow: '0 0 8px rgba(224, 224, 224, 0.3)',
  redGlow: '0 0 8px rgba(255, 50, 50, 0.6)',
  
  // Philosophical effects
  existentialGlow: '0 0 30px rgba(0, 0, 0, 0.8)',
  consciousnessGlow: '0 0 15px rgba(255, 255, 255, 0.15)',
  voidShadow: 'inset 0 0 50px rgba(0, 0, 0, 0.9)',
};

/**
 * Media query breakpoints
 */
export const ANGELA_BREAKPOINTS = {
  xs: '320px',
  sm: '640px',
  md: '768px',
  lg: '1024px',
  xl: '1280px',
  xxl: '1536px',
};

/**
 * Philosophical concepts used throughout the app
 * These are used for naming components, sections, and animations
 */
export const PHILOSOPHICAL_CONCEPTS = {
  // Core concepts
  CONSCIOUSNESS: 'consciousness',
  EXISTENCE: 'existence',
  VOID: 'void',
  PARADOX: 'paradox',
  DUALISM: 'dualism',
  ENLIGHTENMENT: 'enlightenment',
  DETERMINISM: 'determinism',
  FREE_WILL: 'freeWill',
  
  // Socratic themes
  QUESTION: 'question',
  ANSWER: 'answer',
  DIALOGUE: 'dialogue',
  INQUIRY: 'inquiry',
  MAIEUTICS: 'maieutics', // Socratic midwifery of ideas
  
  // Existential themes
  ANGST: 'angst',
  ABSURDITY: 'absurdity',
  FREEDOM: 'freedom',
  NOTHINGNESS: 'nothingness',
  AUTHENTICITY: 'authenticity',
  
  // Nihilistic themes
  MEANINGLESSNESS: 'meaninglessness',
  EMPTINESS: 'emptiness',
  TRANSVALUATION: 'transvaluation',
  
  // Phenomenological themes
  PERCEPTION: 'perception',
  INTENTION: 'intention',
  BEING_IN_WORLD: 'beingInWorld',
  NOESIS: 'noesis',
  NOEMA: 'noema',
  
  // Meta themes
  RECURSION: 'recursion',
  INFINITE_REGRESS: 'infiniteRegress',
  SELF_REFERENCE: 'selfReference',
  FRACTAL: 'fractal',
};

/**
 * Specific CSS effects for the terminal theme
 */
export const ANGELA_EFFECTS = {
  // Terminal effects
  scanlines: `
    background: linear-gradient(
      to bottom,
      transparent 0%,
      rgba(32, 32, 32, 0.15) 50%,
      transparent 100%
    );
    background-size: 100% 4px;
  `,
  vhsNoise: `
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3CfeColorMatrix type='matrix' values='1 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 0.5 0'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E");
    opacity: 0.05;
  `,
  pixelated: `
    image-rendering: pixelated;
    image-rendering: -moz-crisp-edges;
    image-rendering: crisp-edges;
  `,
  textShadow: `
    text-shadow: 0 0 2px rgba(224, 224, 224, 0.4);
  `,
  terminal: `
    font-family: 'IBM Plex Mono', 'Courier New', monospace;
    background-color: #101010;
    color: #e0e0e0;
    padding: 1.5rem;
    border-radius: 4px;
    border: 1px solid #333333;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.3), 0 0 20px rgba(0, 0, 0, 0.2);
  `,
  crt: `
    position: relative;
    overflow: hidden;
    &::before {
      content: " ";
      display: block;
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.1) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.03), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.03));
      background-size: 100% 2px, 3px 100%;
      pointer-events: none;
      z-index: 2;
    }
  `,
  glitchText: `
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
      text-shadow: -1px 0 #ff3333;
      clip: rect(44px, 450px, 56px, 0);
      animation: angela-glitch-anim 5s infinite linear alternate-reverse;
    }
    
    &::after {
      left: -2px;
      text-shadow: -1px 0 #3399ff;
      clip: rect(44px, 450px, 56px, 0);
      animation: angela-glitch-anim 5s infinite linear alternate-reverse;
      animation-delay: 1s;
    }
  `,
};

/**
 * Component-specific theme variables
 */
export const ANGELA_COMPONENTS = {
  // Terminal window styles
  terminal: {
    background: ANGELA_COLORS.bgTerminal,
    text: ANGELA_COLORS.textPrimary,
    border: ANGELA_COLORS.borderPrimary,
    borderRadius: ANGELA_SHAPES.terminalRadius,
    padding: ANGELA_SPACING.terminalPadding,
    fontFamily: ANGELA_TYPOGRAPHY.fontFamilyPrimary,
    shadow: ANGELA_SHADOWS.terminalGlow,
  },
  
  // Dialogue node styles
  dialogueNode: {
    background: ANGELA_COLORS.bgPrimary,
    questionBg: ANGELA_COLORS.bgSecondary,
    answerBg: ANGELA_COLORS.bgTertiary,
    border: ANGELA_COLORS.borderPrimary,
    questionText: ANGELA_COLORS.textPrimary,
    answerText: ANGELA_COLORS.textSecondary,
    padding: ANGELA_SPACING.md,
    margin: ANGELA_SPACING.md,
    borderRadius: ANGELA_SHAPES.dialogueBubbleRadius,
    animation: `${ANGELA_ANIMATIONS.curvePhilosophical} ${ANGELA_ANIMATIONS.durationSlow}`,
  },
  
  // Button styles
  button: {
    background: ANGELA_COLORS.bgSecondary,
    text: ANGELA_COLORS.textPrimary,
    border: ANGELA_COLORS.borderPrimary,
    borderRadius: ANGELA_SHAPES.radiusSm,
    padding: `${ANGELA_SPACING.sm} ${ANGELA_SPACING.md}`,
    hoverBg: ANGELA_COLORS.bgTertiary,
    activeBg: ANGELA_COLORS.accentPrimary,
    disabledBg: ANGELA_COLORS.bgTertiary,
    disabledText: ANGELA_COLORS.textTertiary,
    transition: `all ${ANGELA_ANIMATIONS.durationMedium} ${ANGELA_ANIMATIONS.curveEaseInOut}`,
  },
  
  // Code block styles
  codeBlock: {
    background: ANGELA_COLORS.bgCodeBlock,
    text: ANGELA_COLORS.textPrimary,
    border: ANGELA_COLORS.borderPrimary,
    borderRadius: ANGELA_SHAPES.radiusSm,
    padding: ANGELA_SPACING.md,
    fontFamily: ANGELA_TYPOGRAPHY.fontFamilyPrimary,
  },
  
  // Link styles
  link: {
    color: ANGELA_COLORS.accentPrimary,
    hover: ANGELA_COLORS.accentSecondary,
    visited: ANGELA_COLORS.accentTertiary,
    transition: `color ${ANGELA_ANIMATIONS.durationFast} ${ANGELA_ANIMATIONS.curveEaseInOut}`,
  },
  
  // Header styles
  header: {
    background: ANGELA_COLORS.bgPrimary,
    text: ANGELA_COLORS.textPrimary,
    height: '80px',
    borderBottom: `${ANGELA_SHAPES.borderWidthThin} solid ${ANGELA_COLORS.borderPrimary}`,
    zIndex: ANGELA_Z_INDEX.elevated,
  },
  
  // Footer styles
  footer: {
    background: ANGELA_COLORS.bgPrimary,
    text: ANGELA_COLORS.textTertiary,
    borderTop: `${ANGELA_SHAPES.borderWidthThin} solid ${ANGELA_COLORS.borderPrimary}`,
    padding: `${ANGELA_SPACING.xl} 0`,
  },
  
  // Philosophical section styles
  philosophicalSection: {
    background: ANGELA_COLORS.bgSecondary,
    text: ANGELA_COLORS.textPrimary,
    border: `${ANGELA_SHAPES.borderWidthThin} solid ${ANGELA_COLORS.borderSecondary}`,
    borderRadius: ANGELA_SHAPES.radiusMd,
    padding: ANGELA_SPACING.xl,
    margin: `${ANGELA_SPACING.xxl} 0`,
  },
};

/**
 * Theme export as a single object
 */
export const ANGELA_THEME = {
  colors: ANGELA_COLORS,
  typography: ANGELA_TYPOGRAPHY,
  spacing: ANGELA_SPACING,
  animations: ANGELA_ANIMATIONS,
  zIndex: ANGELA_Z_INDEX,
  shapes: ANGELA_SHAPES,
  shadows: ANGELA_SHADOWS,
  breakpoints: ANGELA_BREAKPOINTS,
  philosophicalConcepts: PHILOSOPHICAL_CONCEPTS,
  effects: ANGELA_EFFECTS,
  components: ANGELA_COMPONENTS,
};

export default ANGELA_THEME;
