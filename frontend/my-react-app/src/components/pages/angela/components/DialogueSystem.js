import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { dialogueData } from '../utils/dialogueData';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';
import * as THREE from 'three';

// Custom hook for handling the 3D vortex animation
const useVortexAnimation = (containerRef, nodes, activeNodeIndex, transitionState) => {
  const sceneRef = useRef(null);
  const cameraRef = useRef(null);
  const rendererRef = useRef(null);
  const particlesRef = useRef(null);
  const textGroupsRef = useRef([]);
  const frameIdRef = useRef(null);
  const timeRef = useRef(0);
  
  // Initialize the Three.js scene
  useEffect(() => {
    if (!containerRef.current) return;
    
    // Clean up previous scene if it exists
    if (sceneRef.current) {
      if (frameIdRef.current) {
        cancelAnimationFrame(frameIdRef.current);
      }
      if (rendererRef.current && rendererRef.current.domElement) {
        containerRef.current.removeChild(rendererRef.current.domElement);
      }
    }
    
    // Set up the scene
    const scene = new THREE.Scene();
    scene.background = new THREE.Color('#000810');
    scene.fog = new THREE.FogExp2('#000810', 0.002);
    sceneRef.current = scene;
    
    // Set up the camera
    const camera = new THREE.PerspectiveCamera(
      75, 
      containerRef.current.clientWidth / containerRef.current.clientHeight, 
      0.1, 
      1000
    );
    camera.position.z = 30;
    cameraRef.current = camera;
    
    // Set up the renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(containerRef.current.clientWidth, containerRef.current.clientHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    containerRef.current.appendChild(renderer.domElement);
    rendererRef.current = renderer;
    
    // Add ambient and directional light
    const ambientLight = new THREE.AmbientLight(0x404040);
    scene.add(ambientLight);
    
    const directionalLight = new THREE.DirectionalLight(0xffffff, 1);
    directionalLight.position.set(0, 1, 1);
    scene.add(directionalLight);
    
    // Create particle system for the vortex effect
    const particleCount = 5000;
    const particles = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);
    const sizes = new Float32Array(particleCount);
    
    // Generate particles in a spiral pattern
    const spiralRadius = 25;
    const spiralTurns = 5;
    const totalAngle = spiralTurns * Math.PI * 2;
    
    for (let i = 0; i < particleCount; i++) {
      const i3 = i * 3;
      const progress = i / particleCount;
      
      // Spiral pattern calculation
      const angle = progress * totalAngle;
      const radius = spiralRadius * (1 - progress);
      
      positions[i3] = Math.cos(angle) * radius;
      positions[i3 + 1] = Math.sin(angle) * radius;
      positions[i3 + 2] = (progress * 200) - 100;
      
      // Random color from theme palette
      const colorKeys = Object.keys(THEME.colors);
      const randomColorKey = colorKeys[Math.floor(Math.random() * colorKeys.length)];
      const colorHex = THEME.colors[randomColorKey] || '#ffffff';
      const color = new THREE.Color(colorHex);
      
      colors[i3] = color.r;
      colors[i3 + 1] = color.g;
      colors[i3 + 2] = color.b;
      
      // Random size variation
      sizes[i] = Math.random() * 2 + 0.5;
    }
    
    particles.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    particles.setAttribute('color', new THREE.BufferAttribute(colors, 3));
    particles.setAttribute('size', new THREE.BufferAttribute(sizes, 1));
    
    const particleMaterial = new THREE.PointsMaterial({
      size: 1,
      vertexColors: true,
      transparent: true,
      opacity: 0.8,
      blending: THREE.AdditiveBlending,
      sizeAttenuation: true,
    });
    
    const particleSystem = new THREE.Points(particles, particleMaterial);
    scene.add(particleSystem);
    particlesRef.current = particleSystem;
    
    // Handle window resizing
    const handleResize = () => {
      if (!containerRef.current) return;
      
      camera.aspect = containerRef.current.clientWidth / containerRef.current.clientHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(containerRef.current.clientWidth, containerRef.current.clientHeight);
    };
    
    window.addEventListener('resize', handleResize);
    
    // Animation loop
    const animate = () => {
      frameIdRef.current = requestAnimationFrame(animate);
      
      // Increment time
      timeRef.current += 0.005;
      
      // Rotate and animate the particle system
      if (particlesRef.current) {
        particlesRef.current.rotation.z += 0.001;
        
        // Breathe effect
        const breatheScale = 1 + 0.05 * Math.sin(timeRef.current);
        particlesRef.current.scale.set(breatheScale, breatheScale, 1);
        
        // Update particle positions for flowing effect
        const positions = particlesRef.current.geometry.attributes.position.array;
        
        for (let i = 0; i < positions.length; i += 3) {
          // Flow along z-axis
          positions[i + 2] -= 0.2;
          
          // If particle goes too far, reset it at the beginning
          if (positions[i + 2] < -100) {
            const progress = Math.random();
            const angle = progress * totalAngle;
            const radius = spiralRadius * (1 - progress);
            
            positions[i] = Math.cos(angle) * radius;
            positions[i + 1] = Math.sin(angle) * radius;
            positions[i + 2] = 100;
          }
        }
        
        particlesRef.current.geometry.attributes.position.needsUpdate = true;
      }
      
      // Update text groups
      textGroupsRef.current.forEach((group, index) => {
        if (group) {
          // Calculate target position based on index
          const targetZ = index === activeNodeIndex ? 0 : index < activeNodeIndex ? 50 : -50;
          
          // Smoothly animate to target position
          group.position.z += (targetZ - group.position.z) * 0.05;
          
          // Rotate based on position
          group.rotation.y = Math.sin(timeRef.current * 0.5) * 0.1;
          group.rotation.x = Math.cos(timeRef.current * 0.3) * 0.05;
          
          // Scale based on position
          const distFromCenter = Math.abs(group.position.z);
          const scale = Math.max(0.1, 1 - distFromCenter / 100);
          group.scale.set(scale, scale, scale);
          
          // Opacity based on position
          if (group.children) {
            group.children.forEach(child => {
              if (child.material) {
                child.material.opacity = Math.max(0, 1 - distFromCenter / 50);
              }
            });
          }
        }
      });
      
      // Apply camera effects based on transition state
      if (transitionState === 'zooming-in') {
        cameraRef.current.position.z -= 0.5;
        cameraRef.current.rotation.z += 0.02;
      } else if (transitionState === 'zooming-out') {
        cameraRef.current.position.z += 0.5;
        cameraRef.current.rotation.z -= 0.02;
      } else if (transitionState === 'reorienting') {
        cameraRef.current.rotation.z *= 0.95; // Gradually return to neutral
      }
      
      // Render
      renderer.render(scene, camera);
    };
    
    animate();
    
    return () => {
      cancelAnimationFrame(frameIdRef.current);
      window.removeEventListener('resize', handleResize);
      if (containerRef.current && rendererRef.current) {
        containerRef.current.removeChild(rendererRef.current.domElement);
      }
    };
  }, [containerRef]);
  
  // Create or update text objects whenever nodes change
  useEffect(() => {
    if (!sceneRef.current || !nodes || nodes.length === 0) return;
    
    // Remove old text groups
    textGroupsRef.current.forEach(group => {
      if (group && sceneRef.current) {
        sceneRef.current.remove(group);
      }
    });
    
    textGroupsRef.current = [];
    
    // Create new text groups for each node
    nodes.forEach((node, index) => {
      const group = new THREE.Group();
      
      // Set initial position based on index relative to active node
      const z = index === activeNodeIndex ? 0 : index < activeNodeIndex ? 50 : -50;
      group.position.set(0, 0, z);
      
      // Add it to the scene and store reference
      sceneRef.current.add(group);
      textGroupsRef.current.push(group);
      
      // Create floating words from the question and answer
      // (This is simplified - a real implementation would use THREE.TextGeometry or sprites)
      const createTextMesh = (text, yOffset, size, color) => {
        // This is a placeholder for text rendering
        // In a real implementation, you would use TextGeometry or sprites
        const geometry = new THREE.PlaneGeometry(text.length * 0.4, 1);
        const material = new THREE.MeshBasicMaterial({
          color: new THREE.Color(color),
          transparent: true,
          opacity: 0.8,
          side: THREE.DoubleSide
        });
        const mesh = new THREE.Mesh(geometry, material);
        mesh.position.y = yOffset;
        group.add(mesh);
        
        // Add a "label" property for debugging
        mesh.userData = { text };
        
        return mesh;
      };
      
      // Create question text
      createTextMesh(node.question, 2, 0.5, THEME.colors.textPrimary);
      
      // Create answer text (truncated for performance)
      const answerPreview = node.answer.substring(0, 50) + '...';
      createTextMesh(answerPreview, -2, 0.4, THEME.colors.textSecondary);
      
      // Add philosophical type as a floating element
      if (node.type) {
        createTextMesh(node.type, 0, 0.3, THEME.colors.accentPrimary);
      }
    });
    
  }, [nodes, activeNodeIndex]);
  
  return { renderer: rendererRef.current };
};

// Component for the philosophical vortex experience
const PhilosophicalVortex = () => {
  const [loadedNodes, setLoadedNodes] = useState([]);
  const [activeNodeIndex, setActiveNodeIndex] = useState(0);
  const [transitionState, setTransitionState] = useState('idle'); // 'idle', 'zooming-in', 'zooming-out', 'reorienting'
  const [isReady, setIsReady] = useState(false);
  const [depth, setDepth] = useState(0);
  const [paradoxLevel, setParadoxLevel] = useState(0);
  const [revealedInsights, setRevealedInsights] = useState([]);
  const [audioEnabled, setAudioEnabled] = useState(false);
  
  // Audio sources
  const ambientSoundRef = useRef(null);
  const transitionSoundRef = useRef(null);
  const paradoxSoundRef = useRef(null);
  
  // DOM references
  const containerRef = useRef(null);
  const overlayRef = useRef(null);
  const textOverlayRef = useRef(null);
  
  // Cache flattened dialogue structure
  const flattenedDialogue = useMemo(() => {
    const flatten = (node, depth = 0, path = []) => {
      if (!node) return [];
      
      const current = {
        ...node,
        depth,
        path: [...path],
      };
      
      if (node.nextQuestion) {
        return [current, ...flatten(node.nextQuestion, depth + 1, [...path, 'nextQuestion'])];
      }
      
      return [current];
    };
    
    return dialogueData.flatMap((rootNode, rootIndex) => 
      flatten(rootNode, 0, [rootIndex])
    );
  }, []);
  
  // Initialize vortex animation
  const { renderer } = useVortexAnimation(containerRef, loadedNodes, activeNodeIndex, transitionState);
  
  // Process the dialogue data
  useEffect(() => {
    if (dialogueData && dialogueData.length > 0) {
      // Initially load just the first few nodes
      const initialNodes = flattenedDialogue.slice(0, 5);
      setLoadedNodes(initialNodes);
      setIsReady(true);
    }
  }, [flattenedDialogue]);
  
  // Handle audio setup
  useEffect(() => {
    if (audioEnabled) {
      // Set up ambient sound (would be implemented with Tone.js or HTML5 Audio)
      if (!ambientSoundRef.current) {
        // This is a placeholder for audio implementation
        ambientSoundRef.current = {
          play: () => console.log('Ambient sound playing'),
          pause: () => console.log('Ambient sound paused'),
          setVolume: (vol) => console.log(`Ambient volume: ${vol}`)
        };
        ambientSoundRef.current.play();
      }
      
      // Set up transition sound
      if (!transitionSoundRef.current) {
        // This is a placeholder for audio implementation
        transitionSoundRef.current = {
          play: () => console.log('Transition sound playing'),
          setVolume: (vol) => console.log(`Transition volume: ${vol}`)
        };
      }
      
      // Set up paradox sound
      if (!paradoxSoundRef.current) {
        // This is a placeholder for audio implementation
        paradoxSoundRef.current = {
          play: () => console.log('Paradox sound playing'),
          setVolume: (vol) => console.log(`Paradox volume: ${vol}`)
        };
      }
    }
    
    return () => {
      // Clean up audio
      if (ambientSoundRef.current) {
        ambientSoundRef.current.pause();
      }
    };
  }, [audioEnabled]);
  
  // Navigate to the next question
  const navigateNext = useCallback(() => {
    // Start transition animation
    setTransitionState('zooming-in');
    
    // Play transition sound if audio enabled
    if (audioEnabled && transitionSoundRef.current) {
      transitionSoundRef.current.play();
    }
    
    // Schedule state changes
    setTimeout(() => {
      // Move to next node in the flattened structure
      const nextIndex = activeNodeIndex + 1;
      
      // Check if we need to load more nodes
      if (nextIndex >= loadedNodes.length && nextIndex < flattenedDialogue.length) {
        const newNodes = [...loadedNodes, flattenedDialogue[nextIndex]];
        setLoadedNodes(newNodes);
      }
      
      setActiveNodeIndex(nextIndex);
      setDepth(flattenedDialogue[nextIndex]?.depth || 0);
      
      // Update paradox level based on depth
      if (flattenedDialogue[nextIndex]?.type === THEME.philosophicalConcepts.PARADOX) {
        setParadoxLevel(prevLevel => prevLevel + 1);
        
        // Play paradox sound if audio enabled
        if (audioEnabled && paradoxSoundRef.current) {
          paradoxSoundRef.current.play();
        }
        
        // Add a new philosophical insight
        const newInsight = generateParadoxInsight();
        setRevealedInsights(prev => [...prev, newInsight]);
      }
      
      // Continue transition
      setTransitionState('reorienting');
      
      // Eventually return to idle state
      setTimeout(() => {
        setTransitionState('idle');
      }, 800);
    }, 1000);
  }, [activeNodeIndex, loadedNodes, flattenedDialogue, audioEnabled]);
  
  // Navigate to the previous question
  const navigatePrevious = useCallback(() => {
    if (activeNodeIndex === 0) return;
    
    // Start transition animation
    setTransitionState('zooming-out');
    
    // Play transition sound if audio enabled
    if (audioEnabled && transitionSoundRef.current) {
      transitionSoundRef.current.play();
    }
    
    // Schedule state changes
    setTimeout(() => {
      const prevIndex = activeNodeIndex - 1;
      setActiveNodeIndex(prevIndex);
      setDepth(flattenedDialogue[prevIndex]?.depth || 0);
      
      // Update paradox level based on depth
      if (flattenedDialogue[prevIndex]?.type !== THEME.philosophicalConcepts.PARADOX) {
        setParadoxLevel(prevLevel => Math.max(0, prevLevel - 0.5));
      }
      
      // Continue transition
      setTransitionState('reorienting');
      
      // Eventually return to idle state
      setTimeout(() => {
        setTransitionState('idle');
      }, 800);
    }, 1000);
  }, [activeNodeIndex, flattenedDialogue, audioEnabled]);
  
  // Reset to beginning
  const resetJourney = useCallback(() => {
    setTransitionState('zooming-out');
    
    setTimeout(() => {
      setActiveNodeIndex(0);
      setDepth(0);
      setParadoxLevel(0);
      setRevealedInsights([]);
      setTransitionState('idle');
    }, 1200);
  }, []);
  
  // Handle keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        navigateNext();
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        navigatePrevious();
      } else if (e.key === 'Escape') {
        resetJourney();
      } else if (e.key === 'm') {
        setAudioEnabled(prev => !prev);
      }
    };
    
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [navigateNext, navigatePrevious, resetJourney]);
  
  // Generate philosophical insights
  const generateParadoxInsight = () => {
    const insights = [
      "The only constant is change itself.",
      "To know that you know nothing is the beginning of wisdom.",
      "The observer becomes the observed.",
      "We shape our tools, and thereafter our tools shape us.",
      "The map is not the territory, yet we can only navigate by maps.",
      "To understand recursion, you must first understand recursion.",
      "The medium is the message, and the message becomes the medium.",
      "You cannot step in the same river twice.",
      "The questions we ask limit the answers we can find.",
      "Consciousness is a paradox observing itself.",
      "When you stare into the abyss, the abyss stares back.",
      "The self is both the subject and object of its own inquiry.",
      "Language creates reality while being created by it.",
      "There are no facts, only interpretations of interpretations.",
      "Every definition contains its own contradiction.",
      "Absolute certainty is absolutely impossible."
    ];
    
    return insights[Math.floor(Math.random() * insights.length)];
  };
  
  // Get current question and answer text
  const currentNode = flattenedDialogue[activeNodeIndex];
  const question = currentNode?.question || "What is reality?";
  const answer = currentNode?.answer || "Reality is that which, when you stop believing in it, doesn't go away.";
  const type = currentNode?.type || THEME.philosophicalConcepts.QUESTION;
  
  // Calculate visual effects based on paradox level
  const blurAmount = Math.min(5, paradoxLevel * 0.5);
  const hueRotate = paradoxLevel * 15;
  const glitchIntensity = Math.min(10, paradoxLevel * 2);
  
  if (!isReady) {
    return <div>Initializing philosophical vortex...</div>;
  }
  
  return (
    <div className="philosophical-vortex-container">
      {/* 3D canvas container */}
      <div 
        ref={containerRef} 
        className="vortex-canvas"
        style={{
          width: '100%',
          height: '80vh',
          position: 'relative',
          overflow: 'hidden',
          backgroundColor: '#000810',
        }}
      />
      
      {/* Text overlay */}
      <div 
        ref={textOverlayRef}
        className="text-overlay"
        style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center',
          color: THEME.colors.textPrimary,
          zIndex: 10,
          pointerEvents: 'none',
          transition: 'all 0.8s cubic-bezier(0.34, 1.56, 0.64, 1)',
          filter: `blur(${blurAmount}px) hue-rotate(${hueRotate}deg)`,
        }}
      >
        <h2 
          className="question-text"
          style={{
            fontSize: '2rem',
            marginBottom: '1.5rem',
            fontFamily: THEME.typography.fontFamilyPhilosophical,
            color: getTypeColor(type),
            textShadow: '0 0 10px rgba(0, 0, 0, 0.8)',
          }}
        >
          {question}
        </h2>
        
        <div 
          className="answer-text"
          style={{
            fontSize: '1.2rem',
            lineHeight: 1.6,
            maxWidth: '600px',
            margin: '0 auto',
            fontFamily: THEME.typography.fontFamilyPrimary,
            color: THEME.colors.textSecondary,
            textShadow: '0 0 5px rgba(0, 0, 0, 0.8)',
          }}
        >
          {answer}
        </div>
      </div>
      
      {/* Paradox insights floating in space */}
      <div className="paradox-insights">
        {revealedInsights.map((insight, index) => (
          <div
            key={`insight-${index}`}
            className="floating-insight"
            style={{
              position: 'absolute',
              top: `${10 + Math.random() * 80}%`,
              left: `${10 + Math.random() * 80}%`,
              transform: `translate(-50%, -50%) rotate(${Math.random() * 20 - 10}deg)`,
              fontSize: '0.9rem',
              fontFamily: THEME.typography.fontFamilyPhilosophical,
              fontStyle: 'italic',
              color: THEME.colors.accentPrimary,
              opacity: 0.7,
              textShadow: '0 0 5px rgba(0, 0, 0, 0.8)',
              pointerEvents: 'none',
              maxWidth: '200px',
              textAlign: 'center',
              animation: 'float 15s infinite ease-in-out',
            }}
          >
            {insight}
          </div>
        ))}
      </div>
      
      {/* Navigation controls */}
      <div 
        className="navigation-controls"
        style={{
          position: 'absolute',
          bottom: '20px',
          left: '0',
          right: '0',
          display: 'flex',
          justifyContent: 'center',
          gap: '20px',
          zIndex: 20,
        }}
      >
        <button 
          onClick={navigatePrevious}
          disabled={activeNodeIndex === 0 || transitionState !== 'idle'}
          style={{
            backgroundColor: 'rgba(0, 0, 0, 0.6)',
            color: THEME.colors.textPrimary,
            border: `1px solid ${THEME.colors.borderPrimary}`,
            padding: '10px 20px',
            borderRadius: '4px',
            cursor: 'pointer',
            fontFamily: THEME.typography.fontFamilyPrimary,
            opacity: activeNodeIndex === 0 ? 0.5 : 1,
          }}
        >
          ← Previous
        </button>
        
        <button
          onClick={resetJourney}
          style={{
            backgroundColor: 'rgba(0, 0, 0, 0.6)',
            color: THEME.colors.accentPrimary,
            border: `1px solid ${THEME.colors.accentPrimary}`,
            padding: '10px 20px',
            borderRadius: '4px',
            cursor: 'pointer',
            fontFamily: THEME.typography.fontFamilyPrimary,
          }}
        >
          Reset Journey
        </button>
        
        <button
          onClick={navigateNext}
          disabled={transitionState !== 'idle'}
          style={{
            backgroundColor: 'rgba(0, 0, 0, 0.6)',
            color: THEME.colors.textPrimary,
            border: `1px solid ${THEME.colors.borderPrimary}`,
            padding: '10px 20px',
            borderRadius: '4px',
            cursor: 'pointer',
            fontFamily: THEME.typography.fontFamilyPrimary,
            opacity: transitionState !== 'idle' ? 0.5 : 1,
          }}
        >
          Next →
        </button>
      </div>
      
      {/* Audio toggle */}
      <button
        onClick={() => setAudioEnabled(prev => !prev)}
        style={{
          position: 'absolute',
          top: '20px',
          right: '20px',
          backgroundColor: 'transparent',
          color: THEME.colors.textSecondary,
          border: 'none',
          cursor: 'pointer',
          fontSize: '1.5rem',
          zIndex: 20,
        }}
      >
        {audioEnabled ? '🔊' : '🔇'}
      </button>
      
      {/* Information overlay */}
      <div
        className="info-overlay"
        style={{
          position: 'absolute',
          top: '20px',
          left: '20px',
          color: THEME.colors.textSecondary,
          fontFamily: THEME.typography.fontFamilyPrimary,
          fontSize: '0.8rem',
          zIndex: 20,
        }}
      >
        <div>Depth: {depth}</div>
        <div>Paradox Level: {paradoxLevel.toFixed(1)}</div>
        <div>Node: {activeNodeIndex + 1} / {flattenedDialogue.length}</div>
      </div>
      
      {/* Glitch overlay that intensifies with paradox level */}
      {paradoxLevel > 0 && (
        <div
          className="glitch-overlay"
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            pointerEvents: 'none',
            zIndex: 5,
            backgroundColor: 'transparent',
            opacity: Math.min(0.7, paradoxLevel * 0.1),
            mixBlendMode: 'difference',
          }}
        >
          <div 
            className="glitch-line"
            style={{
              position: 'absolute',
              height: '2px',
              width: '100%',
              top: `${Math.random() * 100}%`,
              backgroundColor: 'rgba(255, 255, 255, 0.5)',
              transform: `translateY(${Math.random() * 10 - 5}px)`,
            }}
          />
        </div>
      )}
      
      {/* Global CSS for animations */}
      <style jsx global>{`
        @keyframes float {
          0%, 100% {
            transform: translate(-50%, -50%) rotate(0deg) translateY(0);
          }
          25% {
            transform: translate(-50%, -50%) rotate(5deg) translateY(-20px);
          }
          75% {
            transform: translate(-50%, -50%) rotate(-5deg) translateY(20px);
          }
        }
        
        @keyframes glitch {
          0% {
            transform: translate(0);
          }
          20% {
            transform: translate(-${glitchIntensity}px, ${glitchIntensity}px);
          }
          40% {
            transform: translate(-${glitchIntensity}px, -${glitchIntensity}px);
          }
          60% {
            transform: translate(${glitchIntensity}px, ${glitchIntensity}px);
          }
          80% {
            transform: translate(${glitchIntensity}px, -${glitchIntensity}px);
          }
          100% {
            transform: translate(0);
          }
        }
        
        .question-text {
          animation: glitch ${1 / (paradoxLevel + 0.1)}s infinite;
        }
      `}</style>
    </div>
  );
};

// Helper function to get color based on philosophical concept type
const getTypeColor = (type) => {
  switch (type) {
    case THEME.philosophicalConcepts.QUESTION:
      return THEME.colors.textPrimary;
    case THEME.philosophicalConcepts.ANSWER:
      return THEME.colors.textSecondary;
    case THEME.philosophicalConcepts.PARADOX:
      return THEME.colors.accentPrimary;
    case THEME.philosophicalConcepts.CONSCIOUSNESS:
      return THEME.colors.accentSecondary;
    case THEME.philosophicalConcepts.ENLIGHTENMENT:
      return THEME.colors.accentTertiary;
    case THEME.philosophicalConcepts.PERCEPTION:
      return THEME.colors.highlightPrimary;
    case THEME.philosophicalConcepts.DUALISM:
      return THEME.colors.highlightSecondary;
    case THEME.philosophicalConcepts.DIALOGUE:
      return THEME.colors.highlightTertiary;
    default:
      return THEME.colors.textPrimary;
  }
};

export default PhilosophicalVortex;
