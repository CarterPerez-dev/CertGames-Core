// frontend/my-react-app/src/components/pages/angela/components/DialogueNode.js
import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  DialogueNodeContainer,
  QuestionContainer,
  QuestionText,
  ExpandIcon,
  AnswerContainer,
  AnswerText,
  NestedQuestionContainer,
  TransitionEffect,
  ThoughtParticle,
  createThoughtParticles
} from '../styles/DialogueStyles';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

const DialogueNode = ({ 
  node, 
  depth = 0, 
  isActive = false, 
  isLast = false,
  onExpand,
  onNestedExpand,
  expanded = false,
  showNestedQuestion = false,
  parentNode = null,
  path = [],
  isTransitioning = false,
  transitionEffect = null,
  autoExpand = false,
  expandDelay = 0,
  philosophical = true,
  terminal = false
}) => {
  const [isExpanded, setIsExpanded] = useState(expanded);
  const [thoughtParticles, setThoughtParticles] = useState([]);
  const [hasPerformedTransition, setHasPerformedTransition] = useState(false);
  const nodeRef = useRef(null);
  const questionRef = useRef(null);
  const answerRef = useRef(null);
  
  // Determine the node type based on philosophical concepts
  const nodeType = node.type || THEME.philosophicalConcepts.QUESTION;
  
  // Generate thought particles for animation effects
  useEffect(() => {
    if (isExpanded) {
      setThoughtParticles(createThoughtParticles(5));
    }
  }, [isExpanded]);
  
  // Handle auto-expansion (used for the initial dialogue flow)
  useEffect(() => {
    let timeoutId;
    if (autoExpand && !isExpanded) {
      timeoutId = setTimeout(() => {
        handleExpand();
      }, expandDelay);
    }
    
    return () => {
      if (timeoutId) clearTimeout(timeoutId);
    };
  }, [autoExpand, expandDelay, isExpanded]);
  
  // Update expanded state when the prop changes
  useEffect(() => {
    setIsExpanded(expanded);
  }, [expanded]);
  
  // Handle node expansion
  const handleExpand = useCallback(() => {
    if (isTransitioning) return;
    
    const newExpandedState = !isExpanded;
    setIsExpanded(newExpandedState);
    
    if (onExpand) {
      onExpand(node, newExpandedState, path);
    }
    
    // Generate new thought particles when expanded
    if (newExpandedState) {
      setThoughtParticles(createThoughtParticles(5));
    }
  }, [isExpanded, isTransitioning, node, onExpand, path]);
  
  // Handle nested question expansion
  const handleNestedExpand = useCallback((nestedNode, isNestedExpanded, nestedPath) => {
    if (onNestedExpand) {
      onNestedExpand(nestedNode, isNestedExpanded, [...path, ...nestedPath]);
    }
  }, [onNestedExpand, path]);
  
  // Render the nested question if this node has one and it should be shown
  const renderNestedQuestion = () => {
    if (!node.nextQuestion || !showNestedQuestion) return null;
    
    return (
      <NestedQuestionContainer className="nested-question">
        <DialogueNode 
          node={node.nextQuestion}
          depth={depth + 1}
          onExpand={handleNestedExpand}
          onNestedExpand={onNestedExpand}
          path={[0]} // First index in the next level
          parentNode={node}
          philosophical={philosophical}
          terminal={terminal}
        />
      </NestedQuestionContainer>
    );
  };
  
  // Format the answer text with enhanced typography and styling
  const formatAnswerText = (text) => {
    if (!text) return '';
    
    // Process special formatting markers
    // - *text* for highlights
    // - `code` for code snippets
    // - _text_ for philosophical terms
    const formattedText = text
      .replace(/\*([^*]+)\*/g, '<span class="highlight">$1</span>')
      .replace(/`([^`]+)`/g, '<span class="code">$1</span>')
      .replace(/_([^_]+)_/g, '<span class="philosophical-term">$1</span>');
    
    // Split into paragraphs
    return formattedText.split('\n\n').map((paragraph, index) => (
      <p key={index} dangerouslySetInnerHTML={{ __html: paragraph }} />
    ));
  };
  
  // For terminal-styled text
  const formatTerminalText = (text) => {
    if (!text) return '';
    
    // Process terminal commands vs output
    const lines = text.split('\n');
    return lines.map((line, index) => {
      if (line.startsWith('$ ')) {
        return <p key={index} className="prompt">{line.substring(2)}</p>;
      } else {
        return <p key={index} className="output">{line}</p>;
      }
    });
  };
  
  // Render thought particles for animation effects
  const renderThoughtParticles = () => {
    if (!isExpanded) return null;
    
    return thoughtParticles.map(particle => (
      <ThoughtParticle
        key={particle.id}
        size={particle.size}
        delay={particle.delay}
        duration={particle.duration}
        moveX={particle.moveX}
        moveY={particle.moveY}
        scale={particle.scale}
        maxOpacity={particle.maxOpacity}
        style={{
          left: particle.left,
          top: particle.top
        }}
      />
    ));
  };
  
  // Determine if this is a paradoxical node (for special styling)
  const isParadoxical = node.type === THEME.philosophicalConcepts.PARADOX;
  
  // Determine if this is an enlightenment node (for special styling)
  const isEnlightenment = node.type === THEME.philosophicalConcepts.ENLIGHTENMENT;
  
  // Check if this node should apply the loop transition effect
  const isLoopNode = node.isLoop || false;
  
  return (
    <DialogueNodeContainer 
      ref={nodeRef}
      depth={depth}
      isActive={isActive}
      isLast={isLast}
      nodeType={nodeType}
      className={`dialogue-node ${isActive ? 'active' : ''} ${isExpanded ? 'expanded' : ''}`}
      data-node-path={path.join('-')}
    >
      <QuestionContainer 
        ref={questionRef}
        onClick={handleExpand}
        isExpanded={isExpanded}
        nodeType={nodeType}
        className={`question-container ${isExpanded ? 'expanded' : ''}`}
        isParadoxical={isParadoxical}
        isEnlightenment={isEnlightenment}
      >
        <QuestionText 
          philosophical={philosophical} 
          terminal={terminal}
          concept={nodeType}
          className="question-text"
        >
          {node.question}
        </QuestionText>
        <ExpandIcon isExpanded={isExpanded} className="expand-icon" />
      </QuestionContainer>
      
      {isExpanded && (
        <ExpansionEffect 
          isActive={isExpanded}
          isLoop={isLoopNode}
          effect={transitionEffect}
        >
          <AnswerContainer 
            ref={answerRef}
            concept={nodeType}
            className={`answer-container ${isParadoxical ? 'paradoxical' : ''} ${isEnlightenment ? 'enlightenment' : ''}`}
          >
            <AnswerText 
              philosophical={philosophical} 
              terminal={terminal}
              concept={THEME.philosophicalConcepts.ANSWER}
              className="answer-text"
            >
              {terminal 
                ? formatTerminalText(node.answer)
                : formatAnswerText(node.answer)
              }
            </AnswerText>
            
            {renderThoughtParticles()}
            
            {renderNestedQuestion()}
          </AnswerContainer>
        </ExpansionEffect>
      )}
    </DialogueNodeContainer>
  );
};

// Visual effect wrapper for the expansion animation
const ExpansionEffect = ({ children, isActive, isLoop, effect }) => {
  const [showEffect, setShowEffect] = useState(false);
  const [effectType, setEffectType] = useState(effect || 'pulse');
  
  useEffect(() => {
    if (isActive) {
      // Show the expansion effect briefly
      setShowEffect(true);
      const timer = setTimeout(() => {
        setShowEffect(false);
      }, 800);
      
      return () => clearTimeout(timer);
    }
  }, [isActive]);
  
  useEffect(() => {
    // Determine the effect type based on node properties
    if (isLoop) {
      setEffectType('paradox');
    } else if (effect) {
      setEffectType(effect);
    }
  }, [isLoop, effect]);
  
  return (
    <div className={`expansion-effect ${isActive ? 'active' : ''}`}>
      {showEffect && <TransitionEffect effect={effectType} className="transition-effect" />}
      <div className={`dialogue-expanding ${isActive ? 'active' : ''}`}>
        {children}
      </div>
    </div>
  );
};

export default DialogueNode;
