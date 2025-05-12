// frontend/my-react-app/src/components/pages/angela/animations/PhilosophicalParticles.js
import React, { useEffect, useRef, useState } from 'react';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

/**
 * Creates a particle system that reacts to philosophical concepts
 * and forms symbolic patterns representing different types of thought
 */
const PhilosophicalParticles = ({
  active = true,
  type = 'default', // default, question, answer, paradox, consciousness, enlightenment, perception, dualism, dialogue
  particleCount = 100,
  intensity = 1,
  size = '100%',
  height = '100%',
  backgroundColor = 'transparent',
  responsive = true,
  zIndex = 0,
  opacity = 0.7,
  onReady = null,
}) => {
  const containerRef = useRef(null);
  const canvasRef = useRef(null);
  const requestIdRef = useRef(null);
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
  const particlesRef = useRef([]);
  const timeRef = useRef(0);
  const [isInitialized, setIsInitialized] = useState(false);
  
  // Update dimensions on window resize
  useEffect(() => {
    if (!responsive || !containerRef.current) return;
    
    const updateDimensions = () => {
      if (containerRef.current) {
        const { offsetWidth, offsetHeight } = containerRef.current;
        setDimensions({
          width: offsetWidth,
          height: offsetHeight,
        });
        
        if (canvasRef.current) {
          canvasRef.current.width = offsetWidth;
          canvasRef.current.height = offsetHeight;
        }
      }
    };
    
    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    
    return () => {
      window.removeEventListener('resize', updateDimensions);
    };
  }, [responsive]);
  
  // Initialize particles based on philosophical type
  useEffect(() => {
    if (!active || !canvasRef.current || dimensions.width === 0 || dimensions.height === 0) return;
    
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    const { width, height } = dimensions;
    
    // Set canvas size
    canvas.width = width;
    canvas.height = height;
    
    // Create particles based on philosophical type
    const createParticles = () => {
      const particles = [];
      
      // Common properties for all particle types
      const baseProperties = {
        x: width / 2,
        y: height / 2,
        size: Math.random() * 4 + 1,
        opacity: Math.random() * 0.5 + 0.3,
      };
      
      // Get particle color based on philosophical type
      const getColorForType = () => {
        switch (type) {
          case 'question':
            return THEME.colors.textPrimary;
          case 'answer':
            return THEME.colors.textSecondary;
          case 'paradox':
            return THEME.colors.accentPrimary;
          case 'consciousness':
            return THEME.colors.accentSecondary;
          case 'enlightenment':
            return THEME.colors.accentTertiary;
          case 'perception':
            return THEME.colors.highlightPrimary;
          case 'dualism':
            return THEME.colors.highlightSecondary;
          case 'dialogue':
            return THEME.colors.highlightTertiary;
          default:
            return THEME.colors.textPrimary;
        }
      };
      
      // Behavior patterns based on philosophical type
      const setParticleBehavior = (particle) => {
        switch (type) {
          case 'question':
            // Questioning particles move outward in spirals
            const angle = Math.random() * Math.PI * 2;
            const distance = Math.random() * width * 0.4;
            particle.x = width / 2 + Math.cos(angle) * distance;
            particle.y = height / 2 + Math.sin(angle) * distance;
            particle.vx = Math.cos(angle) * (Math.random() * 0.5 + 0.5) * 0.7;
            particle.vy = Math.sin(angle) * (Math.random() * 0.5 + 0.5) * 0.7;
            particle.spin = (Math.random() - 0.5) * 0.1;
            particle.waveAmplitude = Math.random() * 5 + 2;
            particle.waveFrequency = Math.random() * 0.02 + 0.01;
            particle.wavePhase = Math.random() * Math.PI * 2;
            break;
            
          case 'answer':
            // Answer particles converge to form patterns
            particle.x = Math.random() * width;
            particle.y = Math.random() * height;
            particle.targetX = width / 2 + (Math.random() - 0.5) * width * 0.6;
            particle.targetY = height / 2 + (Math.random() - 0.5) * height * 0.6;
            particle.speed = Math.random() * 0.05 + 0.02;
            particle.wobbleFreq = Math.random() * 0.05 + 0.01;
            particle.wobbleAmp = Math.random() * 10 + 5;
            particle.phase = Math.random() * Math.PI * 2;
            break;
            
          case 'paradox':
            // Paradox particles move in contradictory patterns
            particle.x = width / 2 + (Math.random() - 0.5) * width * 0.8;
            particle.y = height / 2 + (Math.random() - 0.5) * height * 0.8;
            particle.vx = (Math.random() - 0.5) * 2;
            particle.vy = (Math.random() - 0.5) * 2;
            particle.reverseTime = Math.random() * 100 + 50;
            particle.reverseTick = 0;
            particle.pulseSpeed = Math.random() * 0.05 + 0.02;
            particle.pulseMagnitude = Math.random() * 0.5 + 0.5;
            break;
            
          case 'consciousness':
            // Consciousness particles form a neural network-like pattern
            particle.x = Math.random() * width;
            particle.y = Math.random() * height;
            particle.size = Math.random() * 3 + 1;
            particle.connections = [];
            particle.connectionCount = Math.floor(Math.random() * 3) + 1;
            particle.pulseSpeed = Math.random() * 0.05 + 0.01;
            particle.pulsePhase = Math.random() * Math.PI * 2;
            break;
            
          case 'enlightenment':
            // Enlightenment particles emanate from center in radiating waves
            const radius = Math.random() * (width > height ? height : width) * 0.4;
            const rad = Math.random() * Math.PI * 2;
            particle.x = width / 2 + Math.cos(rad) * radius;
            particle.y = height / 2 + Math.sin(rad) * radius;
            particle.angle = rad;
            particle.radius = radius;
            particle.speed = Math.random() * 0.5 + 0.5;
            particle.waveFreq = Math.random() * 0.1 + 0.05;
            particle.glowIntensity = Math.random() * 0.5 + 0.5;
            break;
            
          case 'perception':
            // Perception particles constantly shift and change perspective
            particle.x = Math.random() * width;
            particle.y = Math.random() * height;
            particle.z = Math.random() * 200 - 100;
            particle.perspective = 400;
            particle.vz = (Math.random() - 0.5) * 2;
            particle.rotationX = Math.random() * Math.PI * 2;
            particle.rotationY = Math.random() * Math.PI * 2;
            particle.rotationSpeedX = (Math.random() - 0.5) * 0.01;
            particle.rotationSpeedY = (Math.random() - 0.5) * 0.01;
            break;
            
          case 'dualism':
            // Dualism particles split into two opposing groups
            particle.group = Math.random() > 0.5 ? 1 : -1;
            particle.x = width / 2 + (Math.random() - 0.5) * width * 0.5;
            particle.y = height / 2 + (Math.random() - 0.5) * height * 0.5;
            particle.targetX = width / 2 + particle.group * (Math.random() * width * 0.3 + width * 0.1);
            particle.targetY = height / 2 + (Math.random() - 0.5) * height * 0.6;
            particle.speed = Math.random() * 0.03 + 0.01;
            particle.color = particle.group > 0 ? THEME.colors.highlightSecondary : THEME.colors.accentSecondary;
            break;
            
          case 'dialogue':
            // Dialogue particles form conversational flow patterns
            const startSide = Math.random() > 0.5;
            particle.x = startSide ? 0 : width;
            particle.y = Math.random() * height;
            particle.speed = Math.random() * 1 + 0.5;
            particle.amplitude = Math.random() * height * 0.2 + height * 0.05;
            particle.wavelength = Math.random() * width * 0.3 + width * 0.2;
            particle.phase = Math.random() * Math.PI * 2;
            break;
            
          default:
            // Default particles move in a gentle flow
            particle.x = Math.random() * width;
            particle.y = Math.random() * height;
            particle.vx = (Math.random() - 0.5) * 1;
            particle.vy = (Math.random() - 0.5) * 1;
            particle.friction = 0.95;
            break;
        }
        
        return particle;
      };
      
      // Create particles with type-specific behavior
      for (let i = 0; i < particleCount; i++) {
        const particle = {
          ...baseProperties,
          color: getColorForType(),
          id: i,
        };
        
        particles.push(setParticleBehavior(particle));
      }
      
      // For 'consciousness' type, create connections between particles
      if (type === 'consciousness') {
        // Create neural network-like connections
        particles.forEach(particle => {
          // Find nearest particles to connect to
          const others = [...particles].filter(p => p.id !== particle.id);
          others.sort((a, b) => {
            const distA = Math.sqrt(Math.pow(particle.x - a.x, 2) + Math.pow(particle.y - a.y, 2));
            const distB = Math.sqrt(Math.pow(particle.x - b.x, 2) + Math.pow(particle.y - b.y, 2));
            return distA - distB;
          });
          
          // Connect to nearest particles
          for (let i = 0; i < particle.connectionCount && i < others.length; i++) {
            particle.connections.push(others[i].id);
          }
        });
      }
      
      return particles;
    };
    
    particlesRef.current = createParticles();
    setIsInitialized(true);
    
    // Notify when ready
    if (onReady) {
      onReady();
    }
  }, [active, dimensions, type, particleCount, onReady]);
  
  // Animate particles
  useEffect(() => {
    if (!active || !isInitialized || !canvasRef.current) return;
    
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    const { width, height } = dimensions;
    
    // Animation loop
    const animate = () => {
      // Increment time
      timeRef.current += 0.01;
      const time = timeRef.current;
      
      // Clear canvas
      ctx.clearRect(0, 0, width, height);
      
      // Set background if not transparent
      if (backgroundColor !== 'transparent') {
        ctx.fillStyle = backgroundColor;
        ctx.fillRect(0, 0, width, height);
      }
      
      // Update and draw particles based on type
      switch (type) {
        case 'question':
          // Draw questioning particle spirals
          ctx.globalCompositeOperation = 'lighter';
          particlesRef.current.forEach(particle => {
            // Update position with outward spiral
            particle.x += particle.vx * intensity;
            particle.y += particle.vy * intensity;
            
            // Add wave motion
            const waveOffset = Math.sin(time * particle.waveFrequency + particle.wavePhase) * particle.waveAmplitude;
            const x = particle.x + Math.cos(particle.spin * time) * waveOffset;
            const y = particle.y + Math.sin(particle.spin * time) * waveOffset;
            
            // Reset if out of bounds
            if (x < -50 || x > width + 50 || y < -50 || y > height + 50) {
              const angle = Math.random() * Math.PI * 2;
              particle.x = width / 2;
              particle.y = height / 2;
              particle.vx = Math.cos(angle) * (Math.random() * 0.5 + 0.5) * 0.7;
              particle.vy = Math.sin(angle) * (Math.random() * 0.5 + 0.5) * 0.7;
            }
            
            // Draw particle
            ctx.beginPath();
            ctx.arc(x, y, particle.size, 0, Math.PI * 2);
            ctx.fillStyle = particle.color + Math.floor(particle.opacity * 255).toString(16).padStart(2, '0');
            ctx.fill();
            
            // Add glow
            ctx.shadowBlur = particle.size * 3;
            ctx.shadowColor = particle.color;
          });
          break;
          
        case 'answer':
          // Draw converging answer particles
          ctx.globalCompositeOperation = 'source-over';
          
          // First draw connections
          ctx.strokeStyle = THEME.colors.textSecondary + '33';
          ctx.lineWidth = 0.5;
          
          let lastX = null, lastY = null;
          
          particlesRef.current.forEach(particle => {
            // Move particle toward target with wobble
            const dx = particle.targetX - particle.x;
            const dy = particle.targetY - particle.y;
            const wobbleX = Math.sin(time * particle.wobbleFreq + particle.phase) * particle.wobbleAmp;
            const wobbleY = Math.cos(time * particle.wobbleFreq + particle.phase) * particle.wobbleAmp;
            
            particle.x += dx * particle.speed * intensity + wobbleX * 0.01;
            particle.y += dy * particle.speed * intensity + wobbleY * 0.01;
            
            // Draw connection line to previous particle
            if (lastX !== null && lastY !== null) {
              ctx.beginPath();
              ctx.moveTo(lastX, lastY);
              ctx.lineTo(particle.x, particle.y);
              ctx.stroke();
            }
            
            lastX = particle.x;
            lastY = particle.y;
          });
          
          // Then draw particles
          ctx.globalCompositeOperation = 'lighter';
          particlesRef.current.forEach(particle => {
            ctx.beginPath();
            ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
            ctx.fillStyle = particle.color + Math.floor(particle.opacity * 255).toString(16).padStart(2, '0');
            ctx.fill();
          });
          break;
          
        case 'paradox':
          // Draw paradoxical motion
          ctx.globalCompositeOperation = 'lighter';
          particlesRef.current.forEach(particle => {
            // Update position with occasional direction reversal
            particle.reverseTick++;
            if (particle.reverseTick >= particle.reverseTime) {
              particle.vx *= -1;
              particle.vy *= -1;
              particle.reverseTick = 0;
              particle.reverseTime = Math.random() * 100 + 50;
            }
            
            particle.x += particle.vx * intensity;
            particle.y += particle.vy * intensity;
            
            // Bounce off edges with randomized response
            if (particle.x < 0 || particle.x > width) {
              particle.vx *= -1;
              particle.vx += (Math.random() - 0.5) * 0.5;
            }
            if (particle.y < 0 || particle.y > height) {
              particle.vy *= -1;
              particle.vy += (Math.random() - 0.5) * 0.5;
            }
            
            // Apply pulsing effect
            const pulse = 1 + Math.sin(time * particle.pulseSpeed) * particle.pulseMagnitude;
            const currentSize = particle.size * pulse;
            
            // Draw particle with inverted color during pulse transitions
            const invert = Math.sin(time * particle.pulseSpeed) > 0;
            const currentColor = invert ? THEME.colors.bgPrimary : particle.color;
            
            ctx.beginPath();
            ctx.arc(particle.x, particle.y, currentSize, 0, Math.PI * 2);
            ctx.fillStyle = currentColor + Math.floor(particle.opacity * 255).toString(16).padStart(2, '0');
            ctx.fill();
            
            // Add contrast outline for inverted particles
            if (invert) {
              ctx.strokeStyle = particle.color + 'cc';
              ctx.lineWidth = 0.5;
              ctx.stroke();
            }
            
            // Add color trail
            ctx.globalAlpha = 0.3;
            ctx.beginPath();
            ctx.arc(
              particle.x - particle.vx * 3,
              particle.y - particle.vy * 3,
              currentSize * 0.7,
              0,
              Math.PI * 2
            );
            ctx.fillStyle = invert ? particle.color : THEME.colors.bgPrimary;
            ctx.fill();
            ctx.globalAlpha = 1;
          });
          break;
        
        case 'consciousness':
          // Draw neural network pattern
          ctx.globalCompositeOperation = 'lighter';
          
          // First draw connections
          particlesRef.current.forEach(particle => {
            // Draw pulse-animated connections
            particle.connections.forEach(targetId => {
              const target = particlesRef.current[targetId];
              if (target) {
                const dx = target.x - particle.x;
                const dy = target.y - particle.y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                // Only draw connections below a certain distance
                if (distance < width * 0.25) {
                  // Calculate connection opacity based on distance
                  const opacity = 0.15 * (1 - distance / (width * 0.25));
                  
                  // Create pulse effect along connection
                  const pulseTime = time * 0.5;
                  const pulseFactor = ((pulseTime + particle.pulsePhase) % 2) / 2;
                  const pulseX = particle.x + dx * pulseFactor;
                  const pulseY = particle.y + dy * pulseFactor;
                  
                  // Draw connection line
                  ctx.beginPath();
                  ctx.moveTo(particle.x, particle.y);
                  ctx.lineTo(target.x, target.y);
                  ctx.strokeStyle = particle.color + Math.floor(opacity * 255).toString(16).padStart(2, '0');
                  ctx.lineWidth = 0.5;
                  ctx.stroke();
                  
                  // Draw pulse point moving along the connection
                  if (distance > 30) {
                    ctx.beginPath();
                    ctx.arc(pulseX, pulseY, 1, 0, Math.PI * 2);
                    ctx.fillStyle = THEME.colors.accentPrimary + 'aa';
                    ctx.fill();
                  }
                }
              }
            });
          });
          
          // Then draw particles
          particlesRef.current.forEach(particle => {
            // Add subtle movement
            particle.x += (Math.random() - 0.5) * 0.2 * intensity;
            particle.y += (Math.random() - 0.5) * 0.2 * intensity;
            
            // Contain within bounds
            if (particle.x < 0) particle.x = 0;
            if (particle.x > width) particle.x = width;
            if (particle.y < 0) particle.y = 0;
            if (particle.y > height) particle.y = height;
            
            // Pulsing effect
            const pulseOpacity = (0.7 + Math.sin(time * particle.pulseSpeed + particle.pulsePhase) * 0.3) * particle.opacity;
            
            // Draw neuron
            ctx.beginPath();
            ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
            ctx.fillStyle = particle.color + Math.floor(pulseOpacity * 255).toString(16).padStart(2, '0');
            ctx.fill();
            
            // Add glow for active neurons
            if (pulseOpacity > 0.8) {
              ctx.shadowBlur = particle.size * 5;
              ctx.shadowColor = particle.color;
              ctx.beginPath();
              ctx.arc(particle.x, particle.y, particle.size * 1.5, 0, Math.PI * 2);
              ctx.fill();
              ctx.shadowBlur = 0;
            }
          });
          break;
          
        case 'enlightenment':
          // Draw radiating light waves
          ctx.globalCompositeOperation = 'lighter';
          
          // Draw central light source
          const gradient = ctx.createRadialGradient(
            width / 2, height / 2, 0,
            width / 2, height / 2, Math.min(width, height) * 0.25
          );
          gradient.addColorStop(0, THEME.colors.accentTertiary + 'aa');
          gradient.addColorStop(0.5, THEME.colors.accentTertiary + '44');
          gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
          
          ctx.fillStyle = gradient;
          ctx.fillRect(0, 0, width, height);
          
          // Draw particles
          particlesRef.current.forEach(particle => {
            // Update radius with outward motion
            particle.radius += particle.speed * intensity;
            
            // Reset particle when it goes too far
            if (particle.radius > Math.max(width, height)) {
              particle.radius = 0;
              particle.angle = Math.random() * Math.PI * 2;
              particle.speed = Math.random() * 0.5 + 0.5;
            }
            
            // Calculate position
            particle.x = width / 2 + Math.cos(particle.angle) * particle.radius;
            particle.y = height / 2 + Math.sin(particle.angle) * particle.radius;
            
            // Calculate wave effect
            const waveEffect = Math.sin(particle.radius * particle.waveFreq + time) * particle.glowIntensity;
            const currentOpacity = Math.max(0, Math.min(1, particle.opacity * (1 - particle.radius / Math.max(width, height)) * (1 + waveEffect)));
            
            // Skip rendering if too faint
            if (currentOpacity < 0.05) return;
            
            // Draw particle
            ctx.beginPath();
            ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
            ctx.fillStyle = particle.color + Math.floor(currentOpacity * 255).toString(16).padStart(2, '0');
            ctx.fill();
            
            // Add glow
            ctx.shadowBlur = particle.size * 3 * particle.glowIntensity * (1 + waveEffect);
            ctx.shadowColor = particle.color;
            ctx.fill();
            ctx.shadowBlur = 0;
          });
          break;
          
        case 'perception':
          // Draw 3D perspective-shifting particles
          ctx.globalCompositeOperation = 'lighter';
          
          // Sort by z-depth for pseudo-3D rendering
          const sortedParticles = [...particlesRef.current].sort((a, b) => a.z - b.z);
          
          sortedParticles.forEach(particle => {
            // Update 3D position
            particle.z += particle.vz * intensity;
            
            // Invert direction at bounds
            if (particle.z < -100 || particle.z > 100) {
              particle.vz *= -1;
            }
            
            // Update rotation
            particle.rotationX += particle.rotationSpeedX;
            particle.rotationY += particle.rotationSpeedY;
            
            // Project 3D position to 2D (basic perspective projection)
            const scale = particle.perspective / (particle.perspective + particle.z);
            const projX = width / 2 + (particle.x - width / 2) * scale;
            const projY = height / 2 + (particle.y - height / 2) * scale;
            
            // Calculate size with perspective
            const projSize = particle.size * scale;
            
            // Calculate opacity based on depth
            const depthOpacity = (particle.z + 100) / 200;
            const currentOpacity = particle.opacity * depthOpacity;
            
            // Draw projected particle
            ctx.beginPath();
            ctx.arc(projX, projY, projSize, 0, Math.PI * 2);
            ctx.fillStyle = particle.color + Math.floor(currentOpacity * 255).toString(16).padStart(2, '0');
            ctx.fill();
            
            // Add depth perception lines
            if (particle.z > 0) {
              ctx.beginPath();
              ctx.moveTo(projX, projY);
              ctx.lineTo(width / 2, height / 2);
              ctx.strokeStyle = particle.color + '22';
              ctx.lineWidth = 0.5 * scale;
              ctx.stroke();
            }
          });
          break;
          
        case 'dualism':
          // Draw particles split into opposing groups
          ctx.globalCompositeOperation = 'lighter';
          
          // First draw group connections
          particlesRef.current.forEach(particle => {
            // Find nearby particles in same group
            const neighbors = particlesRef.current.filter(p => 
              p.id !== particle.id && 
              p.group === particle.group &&
              Math.abs(p.x - particle.x) < width * 0.2 &&
              Math.abs(p.y - particle.y) < height * 0.2
            );
            
            // Draw connections to nearby group members
            neighbors.slice(0, 3).forEach(neighbor => {
              ctx.beginPath();
              ctx.moveTo(particle.x, particle.y);
              ctx.lineTo(neighbor.x, neighbor.y);
              ctx.strokeStyle = particle.color + '33';
              ctx.lineWidth = 0.5;
              ctx.stroke();
            });
            
            // Move toward target with some group cohesion
            const dx = particle.targetX - particle.x;
            const dy = particle.targetY - particle.y;
            particle.x += dx * particle.speed * intensity;
            particle.y += dy * particle.speed * intensity;
            
            // Apply boundary forces to keep groups on their sides
            if ((particle.group > 0 && particle.x < width / 2) ||
                (particle.group < 0 && particle.x > width / 2)) {
              particle.x += particle.group * intensity;
            }
          });
          
          // Draw dividing line
          const lineGradient = ctx.createLinearGradient(width / 2 - 10, 0, width / 2 + 10, 0);
          lineGradient.addColorStop(0, THEME.colors.accentSecondary + '55');
          lineGradient.addColorStop(0.5, THEME.colors.textPrimary + '88');
          lineGradient.addColorStop(1, THEME.colors.highlightSecondary + '55');
          
          ctx.beginPath();
          ctx.moveTo(width / 2, 0);
          ctx.lineTo(width / 2, height);
          ctx.strokeStyle = lineGradient;
          ctx.lineWidth = 1;
          ctx.stroke();
          
          // Then draw particles
          particlesRef.current.forEach(particle => {
            // Pulse effect synchronized with group
            const pulse = 1 + Math.sin(time * 2 + (particle.group > 0 ? 0 : Math.PI)) * 0.3;
            const currentSize = particle.size * pulse;
            
            ctx.beginPath();
            ctx.arc(particle.x, particle.y, currentSize, 0, Math.PI * 2);
            ctx.fillStyle = particle.color + Math.floor(particle.opacity * pulse * 255).toString(16).padStart(2, '0');
            ctx.fill();
            
            // Add glow during pulse peaks
            if (pulse > 1.2) {
              ctx.shadowBlur = particle.size * 3;
              ctx.shadowColor = particle.color;
              ctx.fill();
              ctx.shadowBlur = 0;
            }
          });
          break;
          
        case 'dialogue':
          // Draw conversational flow patterns
          ctx.globalCompositeOperation = 'lighter';
          
          particlesRef.current.forEach(particle => {
            // Update position with wave pattern
            particle.x += particle.speed * intensity;
            
            // Apply wave pattern to y position
            const waveY = Math.sin((particle.x / particle.wavelength) + particle.phase) * particle.amplitude;
            const y = particle.y + waveY;
            
            // Reset if out of bounds
            if (particle.x > width) {
              particle.x = 0;
              particle.y = Math.random() * height;
              particle.speed = Math.random() * 1 + 0.5;
              particle.amplitude = Math.random() * height * 0.2 + height * 0.05;
              particle.wavelength = Math.random() * width * 0.3 + width * 0.2;
            }
            
            // Draw particle
            ctx.beginPath();
            ctx.arc(particle.x, y, particle.size, 0, Math.PI * 2);
            ctx.fillStyle = particle.color + Math.floor(particle.opacity * 255).toString(16).padStart(2, '0');
            ctx.fill();
            
            // Draw particle trail
            ctx.beginPath();
            ctx.moveTo(particle.x, y);
            ctx.lineTo(Math.max(0, particle.x - particle.speed * 10), y - Math.sin((particle.x - particle.speed * 10) / particle.wavelength + particle.phase) * particle.amplitude);
            ctx.strokeStyle = particle.color + '77';
            ctx.lineWidth = particle.size * 0.7;
            ctx.stroke();
          });
          break;
          
        default:
          // Default particle animation
          ctx.globalCompositeOperation = 'source-over';
          
          particlesRef.current.forEach(particle => {
            // Update position
            particle.x += particle.vx * intensity;
            particle.y += particle.vy * intensity;
            
            // Apply friction
            particle.vx *= particle.friction;
            particle.vy *= particle.friction;
            
            // Bounce off edges
            if (particle.x < 0 || particle.x > width) {
              particle.vx *= -1;
            }
            if (particle.y < 0 || particle.y > height) {
              particle.vy *= -1;
            }
            
            // Add small random impulse occasionally
            if (Math.random() < 0.05) {
              particle.vx += (Math.random() - 0.5) * 0.5;
              particle.vy += (Math.random() - 0.5) * 0.5;
            }
            
            // Draw particle
            ctx.beginPath();
            ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
            ctx.fillStyle = particle.color + Math.floor(particle.opacity * 255).toString(16).padStart(2, '0');
            ctx.fill();
          });
          break;
      }
      
      // Continue animation loop
      requestIdRef.current = requestAnimationFrame(animate);
    };
    
    // Start animation
    requestIdRef.current = requestAnimationFrame(animate);
    
    // Cleanup
    return () => {
      if (requestIdRef.current) {
        cancelAnimationFrame(requestIdRef.current);
      }
    };
  }, [active, isInitialized, dimensions, type, backgroundColor, intensity]);
  
  if (!active) return null;
  
  return (
    <div
      ref={containerRef}
      style={{
        position: 'relative',
        width: size,
        height: height,
        overflow: 'hidden',
        zIndex,
        opacity,
      }}
    >
      <canvas
        ref={canvasRef}
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          pointerEvents: 'none',
        }}
      />
    </div>
  );
};

export default PhilosophicalParticles;
