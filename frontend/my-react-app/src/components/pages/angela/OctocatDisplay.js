import React, { useState, useEffect } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { EffectComposer, Bloom } from '@react-three/postprocessing';
import { BlendFunction } from 'postprocessing';
import { OrbitControls, Float } from '@react-three/drei';
import * as THREE from 'three';
import './OctocatDisplay.css';

// Function to generate points in the shape of a 3D letter "A"
function generateLetterAPoints(count = 150000, scale = 1.3) {
  const points = [];
  
  // Define the parameters of the letter "A"
  const height = 2.0 * scale;
  const topWidth = 0.1 * scale; // Width at the peak of the A
  const bottomWidth = 1.4 * scale; // Width at the base of the A
  const thickness = 0.2 * scale; // Thickness of the strokes
  const crossbarHeight = height * 0.4; // Height of the crossbar from the original bottom (before centering)
  const crossbarWidth = 0.8 * scale; // Width of the crossbar
  const crossbarThickness = 0.15 * scale; // Thickness of the crossbar
  
  // Function to check if a point is within the left leg of the A
  // y_uncentered is used here, ranging from 0 to height
  function isInLeftLeg(x, y_uncentered, z) {
    const expectedX = -bottomWidth/2 + (bottomWidth/2 - topWidth/2) * (y_uncentered / height);
    const distanceFromLine = Math.abs(x - expectedX);
    return distanceFromLine < thickness/2 && Math.abs(z) < thickness/2;
  }
  
  // Function to check if a point is within the right leg of the A
  // y_uncentered is used here, ranging from 0 to height
  function isInRightLeg(x, y_uncentered, z) {
    const expectedX = bottomWidth/2 - (bottomWidth/2 - topWidth/2) * (y_uncentered / height);
    const distanceFromLine = Math.abs(x - expectedX);
    return distanceFromLine < thickness/2 && Math.abs(z) < thickness/2;
  }
  
  // Function to check if a point is within the crossbar of the A
  // y_uncentered is used here, ranging from 0 to height
  function isInCrossbar(x, y_uncentered, z) {
    if (Math.abs(y_uncentered - crossbarHeight) < crossbarThickness/2) {
      const maxX = crossbarWidth/2;
      return Math.abs(x) < maxX && Math.abs(z) < thickness/2;
    }
    return false;
  }
  
  let attempts = 0;
  const maxAttempts = count * 20; 
  
  while (points.length < count && attempts < maxAttempts) {
    attempts++;
    
    const x = (Math.random() * (bottomWidth + thickness)) - (bottomWidth + thickness)/2;
    const y_uncentered = Math.random() * height; // y generated in [0, height] range
    const z = (Math.random() - 0.5) * thickness * 2;
    
    if (isInLeftLeg(x, y_uncentered, z) || isInRightLeg(x, y_uncentered, z) || isInCrossbar(x, y_uncentered, z)) {
      let nx = 0, ny = 0, nz = 0;
      
      if (isInLeftLeg(x, y_uncentered, z)) {
        nx = -1; 
      } else if (isInRightLeg(x, y_uncentered, z)) {
        nx = 1;  
      } else { // Crossbar
        ny = 1;  
      }
      nz = Math.sign(z);
      
      // MODIFICATION: Center the y-coordinate by subtracting half the height
      const y_centered = y_uncentered - height / 2;
      
      points.push({
        position: [x, y_centered, z], // Use centered y
        normal: [nx, ny, nz]
      });
    }
  }
  
  // Add some depth variation
  // Note: basePoint.position[1] will already be centered because points in the 'points' array are centered.
  for (let i = 0; i < count * 0.3 && points.length < count; i++) {
    if (points.length === 0) break; // Safety check
    const basePoint = points[Math.floor(Math.random() * points.length)];
    const depthFactor = (Math.random() * 2 - 1) * thickness * 0.8;
    
    const newPoint = {
      position: [
        basePoint.position[0],
        basePoint.position[1], // This y is already centered
        basePoint.position[2] + depthFactor
      ],
      normal: [
        basePoint.normal[0],
        basePoint.normal[1],
        Math.sign(depthFactor)
      ]
    };
    points.push(newPoint);
  }
  
  // Add random variation (jitter)
  // Note: point.position[1] is already centered here.
  return points.map(point => {
    const jitter = 0.02 * scale * Math.random();
    return {
      position: [
        point.position[0] + jitter * (Math.random() - 0.5),
        point.position[1] + jitter * (Math.random() - 0.5),
        point.position[2] + jitter * (Math.random() - 0.5)
      ],
      normal: point.normal
    };
  });
}

// Component for the letter A particle system
function ClaymonicAParticleSystem({ count = 50000000, color = '#00e5ff', mouseEffect = 2.5 }) {
  const mesh = React.useRef();
  const dummy = React.useMemo(() => new THREE.Object3D(), []);
  const particles = React.useMemo(() => {
    // MODIFICATION: Increase scale from 1.0 to 2.0 (or another value for desired size)
    const letterAPoints = generateLetterAPoints(count, 2.0); // Larger scale
    
    return letterAPoints.map(point => ({
      position: point.position,
      basePosition: point.position, // basePosition will now be scaled and centered
      normal: point.normal || [0, 0, 0],
      offset: Math.random() * Math.PI * 2,
      randomDelay: Math.random(),
      randomSize: Math.random() * 0.3 + 0.005,
      randomSpeed: Math.random() * 0.3 + 0.2,
      randomColor: Math.random()
    }));
  }, [count]);

  // Track mouse position
  const [mouse, setMouse] = useState({ x: 0, y: 0 });
  
  useEffect(() => {
    const handleMouseMove = (event) => {
      const containerRect = event.currentTarget.getBoundingClientRect();
      setMouse({
        x: ((event.clientX - containerRect.left) / containerRect.width) * 2 - 1,
        y: -((event.clientY - containerRect.top) / containerRect.height) * 2 + 1
      });
    };
    
    const container = document.querySelector('.claytronic-display-container');
    if (container) {
      container.addEventListener('mousemove', handleMouseMove);
      return () => container.removeEventListener('mousemove', handleMouseMove);
    }
  }, []);

  useFrame((state) => {
    const { clock } = state;
    const elapsedTime = clock.getElapsedTime();
    
    const mouseVector = new THREE.Vector3(mouse.x * 4, mouse.y * 4, 0);
    
    particles.forEach((particle, i) => {
      const { basePosition, normal, offset, randomDelay, randomSize, randomSpeed } = particle;
      
      const particlePos = new THREE.Vector3(basePosition[0], basePosition[1], basePosition[2]);
      const distanceToMouse = particlePos.distanceTo(mouseVector);
      
      let dynamicX = basePosition[0];
      let dynamicY = basePosition[1];
      let dynamicZ = basePosition[2];
      
      const animationAmplitude = 0.04;
      dynamicX += Math.sin(elapsedTime * randomSpeed + offset) * animationAmplitude * randomDelay * normal[0];
      dynamicY += Math.cos(elapsedTime * randomSpeed + offset) * animationAmplitude * randomDelay * normal[1];
      dynamicZ += Math.sin(elapsedTime * randomSpeed + offset + Math.PI/2) * animationAmplitude * randomDelay * normal[2];
      
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
      
      const rotationY = elapsedTime * 0.3; 
      const cos = Math.cos(rotationY);
      const sin = Math.sin(rotationY);
      const rotatedX = dynamicX * cos - dynamicZ * sin;
      const rotatedZ = dynamicX * sin + dynamicZ * cos;
      dynamicX = rotatedX;
      dynamicZ = rotatedZ;
      
      dummy.position.set(dynamicX, dynamicY, dynamicZ);
      
      const scaleFactor = distanceToMouse < 2 
        ? 1 + (2 - distanceToMouse) * 0.2 * randomSize 
        : randomSize;
      
      const particleSize = scaleFactor * 0.28;
      dummy.scale.set(particleSize, particleSize, particleSize);
      
      dummy.rotation.x = elapsedTime * randomSpeed * 0.3;
      dummy.rotation.y = elapsedTime * randomSpeed * 0.2;
      
      dummy.updateMatrix();
      mesh.current.setMatrixAt(i, dummy.matrix);
    });
    
    mesh.current.instanceMatrix.needsUpdate = true;
  });

  const particleGeometry = React.useMemo(() => {
    return new THREE.SphereGeometry(0.012, 8, 8);
  }, []);

  return (
    <instancedMesh ref={mesh} args={[null, null, particles.length]}>
      <primitive object={particleGeometry} attach="geometry" />
      <meshStandardMaterial 
        color={color} 
        emissive={color} 
        emissiveIntensity={5} 
        toneMapped={false} 
        roughness={0.2} 
        metalness={0.8} 
      />
    </instancedMesh>
  );
}

function ClaymonicAScene() {
  return (
    <Canvas
      dpr={[1, 2]}
      camera={{ position: [0, 0, 5], fov: 50 }}
      gl={{ 
        antialias: true,
        alpha: true, 
        logarithmicDepthBuffer: true,
        toneMapping: THREE.ACESFilmicToneMapping
      }}
    >
      <color attach="background" args={['#0a0a1a']} />
      <ambientLight intensity={0.8} />
      <spotLight position={[10, 10, 10]} angle={0.15} penumbra={1} intensity={1.5} castShadow />
      <pointLight position={[-10, -10, -10]} intensity={0.8} />
      <pointLight position={[0, 0, 5]} intensity={1.2} color="#00e5ff" />
      
      <Float
        speed={1} 
        rotationIntensity={0.1} 
        floatIntensity={0.3} 
        floatingRange={[-0.1, 0.1]} 
      >
        <ClaymonicAParticleSystem count={75000} color="#00e5ff" mouseEffect={2.5} />
      </Float>
      
      <OrbitControls enablePan={false} enableZoom={true} maxDistance={10} minDistance={2} />
      
      <EffectComposer multisampling={4}>
        <Bloom 
          blendFunction={BlendFunction.ADD} 
          intensity={0.6} 
          luminanceThreshold={0.1} 
          luminanceSmoothing={0.9} 
          mipmapBlur 
        />
      </EffectComposer>
    </Canvas>
  );
}

export default function ClaymonicADisplay() {
  return (
    <section className="octocat-section">
      <div className="octocat-section-header">
        <h2 className="octocat-section-title">
          <span className="octocat-title-gradient">Angela-CLI</span>
        </h2>
        <p className="octocat-section-subtitle">Worlds First AGI</p>
      </div>
      <div className="claytronic-display-container octocat-display-container">
        <div className="octocat-display-case">
          <div className="octocat-display-frame">
            <div className="octocat-display-content">
              <ClaymonicAScene />
            </div>
            <div className="octocat-display-base">
              <div className="octocat-display-controls">
                <div className="octocat-display-label">Angela</div>
                <div className="octocat-display-detail">CLI</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
