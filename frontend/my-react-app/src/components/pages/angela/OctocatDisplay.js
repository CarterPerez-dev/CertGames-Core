// src/components/pages/angela/OctocatDisplay.js
import React, { useState, useEffect } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import { BlendFunction } from 'postprocessing';
import { OrbitControls, Float } from '@react-three/drei';
import * as THREE from 'three';
import { generateOctocatPoints } from './ModelLoader';
import './OctocatDisplay.css';

// Component for the Octocat particle system
function OctocatParticleSystem({ count = 20000, color = '#7DBBE6', mouseEffect = 1.5 }) {
  const mesh = React.useRef();
  const dummy = React.useMemo(() => new THREE.Object3D(), []);
  const particles = React.useMemo(() => {
    const octocatPoints = generateOctocatPoints(count, 1.2);
    
    // Add variation to each particle
    return octocatPoints.map(point => ({
      position: point.position,
      basePosition: point.position,
      normal: point.normal || [0, 0, 0],
      offset: Math.random() * Math.PI * 2,
      randomDelay: Math.random(),
      randomSize: Math.random() * 0.4 + 0.1, // Smaller size variation
      randomSpeed: Math.random() * 0.5 + 0.5
    }));
  }, [count]);

  // Track mouse position
  const [mouse, setMouse] = useState({ x: 0, y: 0 });
  
  useEffect(() => {
    const handleMouseMove = (event) => {
      // Get the mouse position relative to the container
      const containerRect = event.currentTarget.getBoundingClientRect();
      setMouse({
        x: ((event.clientX - containerRect.left) / containerRect.width) * 2 - 1,
        y: -((event.clientY - containerRect.top) / containerRect.height) * 2 + 1
      });
    };
    
    const container = document.querySelector('.octocat-display-container');
    if (container) {
      container.addEventListener('mousemove', handleMouseMove);
      return () => container.removeEventListener('mousemove', handleMouseMove);
    }
  }, []);

  useFrame((state) => {
    const { clock } = state;
    const elapsedTime = clock.getElapsedTime();
    
    // Convert mouse position to 3D space
    const mouseVector = new THREE.Vector3(mouse.x * 5, mouse.y * 5, 0);
    
    particles.forEach((particle, i) => {
      const { basePosition, normal, offset, randomDelay, randomSize, randomSpeed } = particle;
      
      // Calculate distance to mouse
      const particlePos = new THREE.Vector3(basePosition[0], basePosition[1], basePosition[2]);
      const distanceToMouse = particlePos.distanceTo(mouseVector);
      
      // Dynamic movement
      let dynamicX = basePosition[0];
      let dynamicY = basePosition[1];
      let dynamicZ = basePosition[2];
      
      // Apply sine wave animation for ambient movement
      const animationAmplitude = 0.05; // Smaller amplitude for more subtle movement
      dynamicX += Math.sin(elapsedTime * randomSpeed + offset) * animationAmplitude * randomDelay * normal[0];
      dynamicY += Math.cos(elapsedTime * randomSpeed + offset) * animationAmplitude * randomDelay * normal[1];
      dynamicZ += Math.sin(elapsedTime * randomSpeed + offset + Math.PI/2) * animationAmplitude * randomDelay * normal[2];
      
      // Mouse interaction effect
      if (distanceToMouse < 2) {
        const repulsionStrength = (2 - distanceToMouse) * mouseEffect;
        const repulsionVector = particlePos.clone().sub(mouseVector).normalize();
        const normalInfluence = 0.3;
        const normalVector = new THREE.Vector3(normal[0], normal[1], normal[2]).normalize();
        
        const blendedDirection = repulsionVector.clone()
          .multiplyScalar(1 - normalInfluence)
          .add(normalVector.multiplyScalar(normalInfluence));
        
        dynamicX += blendedDirection.x * repulsionStrength * randomDelay;
        dynamicY += blendedDirection.y * repulsionStrength * randomDelay;
        dynamicZ += blendedDirection.z * repulsionStrength * randomDelay;
      }
      
      // Apply gentle rotation
      const rotationY = elapsedTime * 0.2; // Faster rotation
      const cos = Math.cos(rotationY);
      const sin = Math.sin(rotationY);
      const rotatedX = dynamicX * cos - dynamicZ * sin;
      const rotatedZ = dynamicX * sin + dynamicZ * cos;
      dynamicX = rotatedX;
      dynamicZ = rotatedZ;
      
      // Update the instance
      dummy.position.set(dynamicX, dynamicY, dynamicZ);
      
      // Scale based on distance to mouse
      const scaleFactor = distanceToMouse < 2 
        ? 1 + (2 - distanceToMouse) * 0.2 * randomSize 
        : randomSize;
      
      // Smaller particles for higher detail
      const particleSize = scaleFactor * 0.4;
      
      dummy.scale.set(particleSize, particleSize, particleSize);
      
      // Apply rotation for more dynamic feel
      dummy.rotation.x = elapsedTime * randomSpeed * 0.5;
      dummy.rotation.y = elapsedTime * randomSpeed * 0.3;
      
      dummy.updateMatrix();
      mesh.current.setMatrixAt(i, dummy.matrix);
    });
    
    mesh.current.instanceMatrix.needsUpdate = true;
  });

  // Smaller, higher detail particles
  const particleGeometry = React.useMemo(() => {
    return new THREE.SphereGeometry(0.015, 8, 8);
  }, []);

  return (
    <instancedMesh ref={mesh} args={[null, null, particles.length]}>
      <primitive object={particleGeometry} attach="geometry" />
      <meshStandardMaterial 
        color={color} 
        emissive={color} 
        emissiveIntensity={0.7} 
        toneMapped={false} 
        roughness={0.2} 
        metalness={0.8} 
      />
    </instancedMesh>
  );
}

function OctocatScene() {
  return (
    <Canvas
      dpr={[1, 2]}
      camera={{ position: [0, 0, 4], fov: 50 }}
      gl={{ 
        antialias: false,
        alpha: true, 
        logarithmicDepthBuffer: true,
        toneMapping: THREE.NoToneMapping
      }}
    >
      <ambientLight intensity={0.5} />
      <spotLight position={[10, 10, 10]} angle={0.15} penumbra={1} intensity={1} castShadow />
      
      <Float
        speed={1} 
        rotationIntensity={0.1} 
        floatIntensity={0.2} 
        floatingRange={[-0.1, 0.1]} 
      >
        <OctocatParticleSystem count={20000} color="#7DBBE6" mouseEffect={1.8} />
      </Float>
      
      <OrbitControls enablePan={false} enableZoom={true} maxDistance={10} minDistance={2} />
      
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

export default function OctocatDisplay() {
  return (
    <section className="octocat-section">
      <div className="octocat-section-header">
        <h2 className="octocat-section-title">
          <span className="octocat-title-gradient">GitHub Octocat</span>
        </h2>
        <p className="octocat-section-subtitle">Interactive 3D particle model</p>
      </div>
      <div className="octocat-display-container">
        <div className="octocat-display-case">
          <div className="octocat-display-frame">
            <div className="octocat-display-content">
              <OctocatScene />
            </div>
            <div className="octocat-display-base">
              <div className="octocat-display-controls">
                <div className="octocat-display-label">GitHub Octocat</div>
                <div className="octocat-display-detail">20,000 particles</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
