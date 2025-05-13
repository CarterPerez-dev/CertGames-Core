// src/components/pages/angela/ParticleEffect.js
import React, { useRef, useMemo, useEffect, useState } from 'react';
import * as THREE from 'three';
import { Canvas, useFrame, extend } from '@react-three/fiber';
import { OrbitControls, useGLTF, Float } from '@react-three/drei';
import { EffectComposer, Bloom } from '@react-three/postprocessing';
import { BlendFunction } from 'postprocessing';
import { generateBustPoints, generateHeadPoints, morphPoints } from './ModelLoader';

// Component for the particle system
function ParticleSystem({ count = 4000, shape = 'cube', color = '#00ff96', mouseEffect = 1.5 }) {
  const mesh = useRef();
  const dummy = useMemo(() => new THREE.Object3D(), []);
  const particles = useMemo(() => {
    const temp = [];
    // Default positions (cube formation)
    let defaultPositions = [];
    
    // Generate positions for various shapes
    if (shape === 'cube') {
      const size = 2;
      for (let i = 0; i < count; i++) {
        const x = (Math.random() - 0.5) * size;
        const y = (Math.random() - 0.5) * size;
        const z = (Math.random() - 0.5) * size;
        defaultPositions.push({ position: [x, y, z], normal: [x, y, z] });
      }
    } else if (shape === 'sphere') {
      const radius = 1.2;
      for (let i = 0; i < count; i++) {
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos((Math.random() * 2) - 1);
        const x = radius * Math.sin(phi) * Math.cos(theta);
        const y = radius * Math.sin(phi) * Math.sin(theta);
        const z = radius * Math.cos(phi);
        defaultPositions.push({ 
          position: [x, y, z], 
          normal: [Math.sin(phi) * Math.cos(theta), Math.sin(phi) * Math.sin(theta), Math.cos(phi)]
        });
      }
    } else if (shape === 'torus') {
      const radius = 1.5;
      const tube = 0.4;
      for (let i = 0; i < count; i++) {
        const u = Math.random() * Math.PI * 2;
        const v = Math.random() * Math.PI * 2;
        const x = (radius + tube * Math.cos(v)) * Math.cos(u);
        const y = (radius + tube * Math.cos(v)) * Math.sin(u);
        const z = tube * Math.sin(v);
        defaultPositions.push({ 
          position: [x, y, z], 
          normal: [Math.cos(u) * Math.cos(v), Math.sin(u) * Math.cos(v), Math.sin(v)]
        });
      }
    } else if (shape === 'wave') {
      const size = 2.5;
      for (let i = 0; i < count; i++) {
        const x = (Math.random() - 0.5) * size;
        const z = (Math.random() - 0.5) * size;
        const y = Math.sin(x * 2) * Math.cos(z * 2) * 0.5;
        // Calculate wave normal
        const dx = 2 * Math.cos(x * 2) * Math.cos(z * 2);
        const dz = -2 * Math.sin(x * 2) * Math.sin(z * 2);
        const normal = new THREE.Vector3(-dx, 1, -dz).normalize();
        defaultPositions.push({ 
          position: [x, y, z], 
          normal: [normal.x, normal.y, normal.z]
        });
      }
    } else if (shape === 'head' || shape === 'bust') {
      // Generate a 3D head or bust
      defaultPositions = shape === 'head' 
        ? generateHeadPoints(count, 1.5)
        : generateBustPoints(count, 1.2);
    } else if (shape === 'morph') {
      // Generate particles that can morph between shapes
      const spherePoints = [];
      const headPoints = generateHeadPoints(count);
      
      // Create a sphere for morphing
      const radius = 1.2;
      for (let i = 0; i < count; i++) {
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos((Math.random() * 2) - 1);
        const x = radius * Math.sin(phi) * Math.cos(theta);
        const y = radius * Math.sin(phi) * Math.sin(theta);
        const z = radius * Math.cos(phi);
        spherePoints.push({ 
          position: [x, y, z], 
          normal: [Math.sin(phi) * Math.cos(theta), Math.sin(phi) * Math.sin(theta), Math.cos(phi)]
        });
      }
      
      // Start with a 50% morph between sphere and head
      defaultPositions = morphPoints(spherePoints, headPoints, 0.5);
    }
    
    // Add variation to each particle
    for (let i = 0; i < defaultPositions.length; i++) {
      const position = defaultPositions[i].position;
      const normal = defaultPositions[i].normal || [0, 0, 0];
      
      temp.push({
        position: position,
        basePosition: position,
        normal: normal,
        // Random offset for animation variation
        offset: Math.random() * Math.PI * 2,
        randomDelay: Math.random(),
        randomSize: Math.random() * 0.5 + 0.5,
        randomSpeed: Math.random() * 0.5 + 0.5
      });
    }
    return temp;
  }, [count, shape]);

  // Track mouse position
  const [mouse, setMouse] = useState({ x: 0, y: 0 });
  
  useEffect(() => {
    const handleMouseMove = (event) => {
      setMouse({
        x: (event.clientX / window.innerWidth) * 2 - 1,
        y: -(event.clientY / window.innerHeight) * 2 + 1
      });
    };
    
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  useFrame((state) => {
    const { clock } = state;
    const elapsedTime = clock.getElapsedTime();
    
    // Convert mouse position to 3D space with raycasting
    const mouseVector = new THREE.Vector3(mouse.x * 5, mouse.y * 5, 0);
    
    // Morphing progress for shape transitions (if shape is 'morph')
    const morphProgress = shape === 'morph' ? (Math.sin(elapsedTime * 0.2) + 1) / 2 : 0;
    
    particles.forEach((particle, i) => {
      // Extract particle properties
      const { basePosition, normal, offset, randomDelay, randomSize, randomSpeed } = particle;
      
      // Calculate distance to mouse
      const particlePos = new THREE.Vector3(basePosition[0], basePosition[1], basePosition[2]);
      const distanceToMouse = particlePos.distanceTo(mouseVector);
      
      // Dynamic movement based on mouse position and time
      let dynamicX = basePosition[0];
      let dynamicY = basePosition[1];
      let dynamicZ = basePosition[2];
      
      // Apply sine wave animation for ambient movement
      // Use normal vector for more natural motion along the surface
      const animationAmplitude = 0.1;
      dynamicX += Math.sin(elapsedTime * randomSpeed + offset) * animationAmplitude * randomDelay * normal[0];
      dynamicY += Math.cos(elapsedTime * randomSpeed + offset) * animationAmplitude * randomDelay * normal[1];
      dynamicZ += Math.sin(elapsedTime * randomSpeed + offset + Math.PI/2) * animationAmplitude * randomDelay * normal[2];
      
      // Mouse interaction effect - more sophisticated with normal direction
      if (distanceToMouse < 3) {
        // Calculate repulsion vector (pushes particles away from mouse)
        const repulsionStrength = (3 - distanceToMouse) * mouseEffect;
        const repulsionVector = particlePos.clone().sub(mouseVector).normalize();
        
        // Add normal influence for more natural flow
        const normalInfluence = 0.3;
        const normalVector = new THREE.Vector3(normal[0], normal[1], normal[2]).normalize();
        
        // Blend between repulsion and normal direction
        const blendedDirection = repulsionVector.clone()
          .multiplyScalar(1 - normalInfluence)
          .add(normalVector.multiplyScalar(normalInfluence));
        
        dynamicX += blendedDirection.x * repulsionStrength * randomDelay;
        dynamicY += blendedDirection.y * repulsionStrength * randomDelay;
        dynamicZ += blendedDirection.z * repulsionStrength * randomDelay;
      }
      
      // Apply gentle rotation to the entire shape
      if (shape === 'head' || shape === 'bust' || shape === 'morph') {
        const rotationY = elapsedTime * 0.1;
        const cos = Math.cos(rotationY);
        const sin = Math.sin(rotationY);
        const rotatedX = dynamicX * cos - dynamicZ * sin;
        const rotatedZ = dynamicX * sin + dynamicZ * cos;
        dynamicX = rotatedX;
        dynamicZ = rotatedZ;
      }
      
      // Update the instance
      dummy.position.set(dynamicX, dynamicY, dynamicZ);
      
      // Scale based on distance to mouse for extra visual effect
      const scaleFactor = distanceToMouse < 3 
        ? 1 + (3 - distanceToMouse) * 0.2 * randomSize 
        : randomSize;
      
      // For busts and heads, use smaller particles
      const particleSize = (shape === 'head' || shape === 'bust' || shape === 'morph') 
        ? scaleFactor * 0.7 
        : scaleFactor;
      
      dummy.scale.set(particleSize, particleSize, particleSize);
      
      // Apply rotation for more dynamic feel
      dummy.rotation.x = elapsedTime * randomSpeed * 0.5;
      dummy.rotation.y = elapsedTime * randomSpeed * 0.3;
      
      dummy.updateMatrix();
      mesh.current.setMatrixAt(i, dummy.matrix);
    });
    
    mesh.current.instanceMatrix.needsUpdate = true;
  });

  // Different particle geometries based on shape
  const particleGeometry = useMemo(() => {
    if (shape === 'head' || shape === 'bust' || shape === 'morph') {
      // Smaller, higher detail particles for organic shapes
      return new THREE.SphereGeometry(0.02, 12, 12);
    }
    // Default particles for geometric shapes
    return new THREE.SphereGeometry(0.03, 8, 8);
  }, [shape]);

  return (
    <instancedMesh ref={mesh} args={[null, null, particles.length]}>
      <primitive object={particleGeometry} attach="geometry" />
      <meshStandardMaterial 
        color={color} 
        emissive={color} 
        emissiveIntensity={0.5} 
        toneMapped={false} 
        roughness={0.2} 
        metalness={0.8} 
      />
    </instancedMesh>
  );
}

// Main component that sets up the Three.js scene
function ParticleScene({ shape = 'cube', particleColor = '#00ff96', count = 4000, mouseEffect = 1.5 }) {
  // Camera position depends on shape
  const cameraPosition = useMemo(() => {
    if (shape === 'head' || shape === 'bust' || shape === 'morph') {
      return [0, 0, 4]; // Closer for head/bust
    }
    return [0, 0, 5]; // Default position
  }, [shape]);
  
  return (
    <Canvas
      dpr={[1, 2]}
      camera={{ position: cameraPosition, fov: 50 }}
      gl={{ 
        antialias: false,
        alpha: true, 
        logarithmicDepthBuffer: true,
        toneMapping: THREE.NoToneMapping
      }}
      style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none' }}
    >
      <ambientLight intensity={0.5} />
      <spotLight position={[10, 10, 10]} angle={0.15} penumbra={1} intensity={1} castShadow />
      
      <Float
        speed={1} // Animation speed, defaults to 1
        rotationIntensity={0.1} // XYZ rotation intensity, defaults to 1
        floatIntensity={0.2} // Up/down float intensity, defaults to 1
        floatingRange={[-0.1, 0.1]} // Range of float motion, defaults to [-0.1, 0.1]
      >
        <ParticleSystem 
          count={count} 
          shape={shape} 
          color={particleColor} 
          mouseEffect={mouseEffect} 
        />
      </Float>
      
      <EffectComposer multisampling={0}>
        <Bloom 
          blendFunction={BlendFunction.ADD} 
          intensity={0.3} 
          luminanceThreshold={0.2} 
          luminanceSmoothing={0.9} 
          mipmapBlur 
        />
      </EffectComposer>
    </Canvas>
  );
}

// Exported component that wraps the 3D scene with necessary contexts
export default function ParticleEffect({ 
  shape = 'cube', 
  particleColor = '#00ff96', 
  particleCount = 4000,
  mouseEffect = 1.5
}) {
  return (
    <div className="angela-particle-container">
      <ParticleScene 
        shape={shape} 
        particleColor={particleColor} 
        count={particleCount} 
        mouseEffect={mouseEffect}
      />
    </div>
  );
}
