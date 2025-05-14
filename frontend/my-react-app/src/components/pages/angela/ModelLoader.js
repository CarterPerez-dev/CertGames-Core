// src/components/pages/angela/ModelLoader.js
import React, { useMemo } from 'react';
import { useGLTF } from '@react-three/drei';
import * as THREE from 'three';

// Function to sample points on a 3D model surface
export function useModelPoints(modelPath, count = 5000) {
  const { scene } = useGLTF(modelPath);
  
  // Use a memo to avoid recomputing unless model or count changes
  const points = useMemo(() => {
    // Array to store all points
    const sampledPoints = [];
    
    // Process each mesh in the scene
    scene.traverse((object) => {
      if (object.isMesh) {
        const geometry = object.geometry;
        
        // Make sure we have position attribute
        if (!geometry.attributes.position) return;
        
        // Get position and normal data
        const positions = geometry.attributes.position.array;
        const normals = geometry.attributes.normal ? geometry.attributes.normal.array : null;
        
        // Get the mesh's world matrix to transform positions correctly
        const matrix = object.matrixWorld;
        
        // Vertices sampling (extract all vertices)
        for (let i = 0; i < positions.length; i += 3) {
          const x = positions[i];
          const y = positions[i + 1];
          const z = positions[i + 2];
          
          // Create a vector and apply world transform
          const vertex = new THREE.Vector3(x, y, z);
          vertex.applyMatrix4(matrix);
          
          // Add this point
          sampledPoints.push({
            position: [vertex.x, vertex.y, vertex.z],
            normal: normals ? [
              normals[i],
              normals[i + 1],
              normals[i + 2]
            ] : [0, 0, 0]
          });
        }
      }
    });
    
    // If we don't have enough points, duplicate some
    if (sampledPoints.length < count) {
      const multiplier = Math.ceil(count / sampledPoints.length);
      const originalLength = sampledPoints.length;
      
      for (let i = 0; i < originalLength && sampledPoints.length < count; i++) {
        for (let j = 0; j < multiplier && sampledPoints.length < count; j++) {
          // Add slight variations to make it look more natural
          const original = sampledPoints[i];
          const jitter = 0.01 * Math.random();
          
          sampledPoints.push({
            position: [
              original.position[0] + jitter * (Math.random() - 0.5),
              original.position[1] + jitter * (Math.random() - 0.5),
              original.position[2] + jitter * (Math.random() - 0.5)
            ],
            normal: original.normal
          });
        }
      }
    }
    
    // If we have too many points, randomly select subset
    if (sampledPoints.length > count) {
      // Shuffle array using Fisher-Yates algorithm
      for (let i = sampledPoints.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [sampledPoints[i], sampledPoints[j]] = [sampledPoints[j], sampledPoints[i]];
      }
      
      // Take only the first 'count' elements
      return sampledPoints.slice(0, count);
    }
    
    return sampledPoints;
  }, [scene, count]);
  
  return points;
}

// Function to generate points in the shape of a head/bust
export function generateHeadPoints(count = 5000, scale = 1) {
  // We'll create an algorithmic approximation of a head shape
  return Array.from({ length: count }, (_, i) => {
    // Parameters for parametric equations
    const u = Math.random() * Math.PI * 2;
    const v = Math.random() * Math.PI;
    
    // Base oval shape for the head
    let x, y, z;
    
    // Determine if this point should be part of the head or neck
    const isHead = Math.random() > 0.2;
    
    if (isHead) {
      // Head shape (elongated ellipsoid)
      const a = 0.8 * scale; // width
      const b = 1.0 * scale; // height
      const c = 0.9 * scale; // depth
      
      x = a * Math.sin(v) * Math.cos(u);
      y = b * Math.cos(v) + 0.2; // Shift upward
      z = c * Math.sin(v) * Math.sin(u);
      
      // Add features (like face indentations, etc.)
      if (Math.abs(z) < 0.5 && y < 0.2 && y > -0.3) {
        // Face area - add some indentation
        z *= 0.8;
      }
      
      // Add bump for nose
      if (Math.abs(x) < 0.2 && z > 0.3 && z < 0.7 && y < 0.2 && y > -0.2) {
        z += 0.1;
      }
    } else {
      // Neck/shoulder area
      const neckWidth = 0.3 * scale;
      const neckHeight = 0.5 * scale;
      
      x = neckWidth * Math.sin(v) * Math.cos(u);
      y = - + neckHeight * Math.random(); // Position below the head
      z = neckWidth * Math.sin(v) * Math.sin(u);
    }
    
    // Add slight randomness to make it look more natural
    const jitter = 0.05 * Math.random() * scale;
    
    return {
      position: [
        x + jitter * (Math.random() - 0.5),
        y + jitter * (Math.random() - 0.5),
        z + jitter * (Math.random() - 0.5)
      ],
      normal: [
        Math.sin(v) * Math.cos(u),
        Math.cos(v),
        Math.sin(v) * Math.sin(u)
      ]
    };
  });
}

// Generate torso points to create a bust
export function generateTorsoPoints(count = 2000, scale = 1) {
  return Array.from({ length: count }, (_, i) => {
    // Parameters
    const u = Math.random() * Math.PI * 2;
    const v = Math.random() * Math.PI;
    
    // Torso shape (modified cylinder/cone)
    const topWidth = 0.8 * scale;
    const bottomWidth = 1.0 * scale;
    const height = 1.2 * scale;
    
    // Linear interpolation from top to bottom width
    const t = (v / Math.PI); // 0 at top, 1 at bottom
    const width = topWidth * (1 - t) + bottomWidth * t;
    
    let x = width * Math.cos(u);
    let z = width * Math.sin(u);
    let y = -1.0 - t * height; // Position below the head/neck
    
    // Add slight randomness
    const jitter = 0.05 * Math.random() * scale;
    
    return {
      position: [
        x + jitter * (Math.random() - 0.5),
        y + jitter * (Math.random() - 0.5),
        z + jitter * (Math.random() - 0.5)
      ],
      normal: [
        Math.cos(u),
        0,
        Math.sin(u)
      ]
    };
  });
}

// Main function to generate bust points combining head and torso
export function generateBustPoints(count = 7000, scale = 1) {
  // Distribute points between head and torso
  const headCount = Math.floor(count * 0.7); // 70% for head and neck
  const torsoCount = count - headCount; // Remaining for torso
  
  const headPoints = generateHeadPoints(headCount, scale);
  const torsoPoints = generateTorsoPoints(torsoCount, scale);
  
  // Combine the points
  return [...headPoints, ...torsoPoints];
}

// Function to generate points that transition between two shapes
export function morphPoints(sourcePoints, targetPoints, progress) {
  // Ensure we have the same number of points
  const count = Math.min(sourcePoints.length, targetPoints.length);
  
  return Array.from({ length: count }, (_, i) => {
    const source = sourcePoints[i];
    const target = targetPoints[i];
    
    // Linear interpolation between source and target positions
    return {
      position: [
        source.position[0] * (1 - progress) + target.position[0] * progress,
        source.position[1] * (1 - progress) + target.position[1] * progress,
        source.position[2] * (1 - progress) + target.position[2] * progress
      ],
      normal: [
        source.normal[0] * (1 - progress) + target.normal[0] * progress,
        source.normal[1] * (1 - progress) + target.normal[1] * progress,
        source.normal[2] * (1 - progress) + target.normal[2] * progress
      ]
    };
  });
}

// Function to generate points in the shape of a GitHub Octocat
// Updated function to generate points in the shape of a GitHub Octocat
// Updated function to generate points in the shape of a GitHub Octocat
export function generateOctocatPoints(count = 30000, scale = 1) {
  // Create an array to hold all the points
  const points = [];
  
  // Generate the head (rounded square shape rather than perfectly spherical)
  const headCount = Math.floor(count * 0.45);
  const headRadius = 0.85 * scale;
  for (let i = 0; i < headCount; i++) {
    // More square-ish distribution for Octocat's head
    // Use a mix of sphere and cube distributions
    let x, y, z;
    
    
    if (Math.random() < 0.7) {
      // Mostly use a rounded square distribution
      x = (Math.random() * 2 - 1) * headRadius;
      y = (Math.random() * 2 - 1) * headRadius * 0.9 + 0.2 * scale; // Shift up a bit
      z = (Math.random() * 2 - 1) * headRadius * 0.85; // Slightly flatter in Z
      
      // Round the corners by rejecting points that are too far out
      const distance = Math.sqrt(x*x + y*y + z*z);
      if (distance > headRadius * 1.2) {
        i--; // Try again
        continue;
      }
      
      // Make it more square-ish by pulling points toward the edges
      x = Math.sign(x) * (Math.abs(x) ** 0.8) * headRadius;
      z = Math.sign(z) * (Math.abs(z) ** 0.8) * headRadius;
    } else {
      // Some pure spherical points for smoothness
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos((Math.random() * 2) - 1);
      x = headRadius * Math.sin(phi) * Math.cos(theta);
      y = headRadius * Math.sin(phi) * Math.sin(theta) * 0.9 + 0.2 * scale; // Shift up a bit
      z = headRadius * Math.cos(phi) * 0.85; // Slightly flatter in Z
    }
    
    // Only keep points that are not in the bottom-back section
    if (!(z < -headRadius * 0.3 && y < -headRadius * 0.3)) {
      // Calculate normal vector (pointing outward from center)
      const nx = x / Math.sqrt(x*x + y*y + z*z);
      const ny = y / Math.sqrt(x*x + y*y + z*z);
      const nz = z / Math.sqrt(x*x + y*y + z*z);
      
      points.push({
        position: [x, y, z],
        normal: [nx, ny, nz]
      });
    }
  }
  
  // Generate the ears (more prominent cat ears)
  const earCount = Math.floor(count * 0.1);
  const earSize = 0.3 * scale;
  const earHeight = 0.4 * scale;
  const earSpacing = 0.6 * scale;
  
  for (let i = 0; i < earCount; i++) {
    const side = i < earCount / 2 ? -1 : 1; // Left or right ear
    
    // Base position of ear
    const baseX = side * earSpacing;
    const baseY = headRadius * 0.8;
    const baseZ = 0; // Centered front to back
    
    // Generate a triangular ear shape
    let t = Math.random();
    let s = Math.random();
    
    // Create a triangular distribution
    if (s > t) {
      const temp = t;
      t = s;
      s = temp;
    }
    
    let x = baseX + (s - 0.5) * earSize;
    let y = baseY + t * earHeight;
    let z = baseZ + (s - 0.5) * earSize;
    
    // Calculate normal (simplified)
    const nx = 0;
    const ny = 1;
    const nz = 0;
    
    points.push({
      position: [x, y, z],
      normal: [nx, ny, nz]
    });
  }
  
  // Generate the body (more octopus-like with a smaller, rounded body)
  const bodyCount = Math.floor(count * 0.2);
  const bodyWidth = 0.6 * scale;
  const bodyHeight = 0.5 * scale;
  for (let i = 0; i < bodyCount; i++) {
    // Make the body oval-shaped
    const u = Math.random() * Math.PI * 2;
    const v = Math.random();
    const radius = bodyWidth * (1 - v * 0.2); // Slight taper
    
    let x = radius * Math.cos(u);
    let y = -bodyHeight * v - 0.4 * scale; // Position below the head
    let z = radius * Math.sin(u);
    
    // Calculate normal (pointing outward)
    const nx = Math.cos(u);
    const ny = -0.1; // Slight downward component
    const nz = Math.sin(u);
    
    points.push({
      position: [x, y, z],
      normal: [nx, ny, nz]
    });
  }
  
  // Generate the tentacles (more realistic octopus tentacles)
  const tentacleCount = Math.floor(count * 0.25);
  const numTentacles = 5; // Create 5 tentacles
  
  for (let t = 0; t < numTentacles; t++) {
    // Calculate angle for this tentacle (arranged in a semicircle at the bottom)
    const angle = (t / (numTentacles - 1)) * Math.PI + Math.PI / 2;
    
    // Base position where tentacle connects to body
    const baseX = Math.cos(angle) * bodyWidth * 0.8;
    const baseZ = Math.sin(angle) * bodyWidth * 0.8;
    const baseY = -0.7 * scale;
    
    const pointsPerTentacle = Math.floor(tentacleCount / numTentacles);
    
    // Create a curved tentacle
    for (let i = 0; i < pointsPerTentacle; i++) {
      const progress = i / pointsPerTentacle;
      const tentacleLength = 0.9 * scale + (Math.random() * 0.3 * scale);
      
      // Create a curved tentacle with sinusoidal motion
      const curveFactor = 0.25 * scale;
      const curve = Math.sin(progress * Math.PI * 2) * curveFactor;
      const curveDirection = (t % 2 === 0) ? 1 : -1; // Alternate curve direction
      
      // Apply curve in a direction perpendicular to the tentacle
      const perpendicularAngle = angle + Math.PI/2;
      
      const x = baseX + curve * Math.cos(perpendicularAngle) * curveDirection;
      const y = baseY - progress * tentacleLength;
      const z = baseZ + curve * Math.sin(perpendicularAngle) * curveDirection;
      
      // Thickness tapers toward the end
      const thickness = (1 - progress * 0.8) * 0.15 * scale;
      
      // Add some point variety in a small radius around the central curve
      const jitterRadius = thickness * Math.random();
      const jitterAngle = Math.random() * Math.PI * 2;
      
      const jitterX = jitterRadius * Math.cos(jitterAngle);
      const jitterZ = jitterRadius * Math.sin(jitterAngle);
      
      // Calculate normal (simplified)
      const tangentY = -tentacleLength;
      const tangentX = curve * Math.cos(perpendicularAngle) * curveDirection * Math.PI * 2 * Math.cos(progress * Math.PI * 2);
      const tangentZ = curve * Math.sin(perpendicularAngle) * curveDirection * Math.PI * 2 * Math.cos(progress * Math.PI * 2);
      
      // Normalize the tangent
      const tangentMagnitude = Math.sqrt(tangentX*tangentX + tangentY*tangentY + tangentZ*tangentZ);
      const tX = tangentX / tangentMagnitude;
      const tY = tangentY / tangentMagnitude;
      const tZ = tangentZ / tangentMagnitude;
      
      // Use tangent to calculate normal (simplified)
      const nx = -tX;
      const ny = -tY;
      const nz = -tZ;
      
      points.push({
        position: [x + jitterX, y, z + jitterZ],
        normal: [nx, ny, nz]
      });
    }
  }
  
  // Add eyes (two distinct circular eyes)
  const eyeCount = Math.floor(count * 0.05);
  const eyeSize = 0.18 * scale;
  const eyeSpacing = 0.35 * scale;
  const eyeForward = 0.75 * scale; // Position eyes toward front
  
  for (let i = 0; i < eyeCount; i++) {
    const side = i < eyeCount / 2 ? -1 : 1; // Left or right eye
    
    // Make eyes more circular and distinct
    const theta = Math.random() * Math.PI * 2;
    const radius = Math.sqrt(Math.random()) * eyeSize; // Sqrt for uniform disc distribution
    
    let eyeX = side * eyeSpacing + radius * Math.cos(theta) * 0.5; // Flatten circle to oval
    let eyeY = 0.2 * scale + radius * Math.sin(theta);
    let eyeZ = eyeForward; // Push to front
    
    points.push({
      position: [eyeX, eyeY, eyeZ],
      normal: [0, 0, 1] // Eyes face forward
    });
  }
  
  // Generate face feature points (small amount to suggest a mouth or smile)
  const faceCount = Math.floor(count * 0.03);
  for (let i = 0; i < faceCount; i++) {
    // Create a subtle curved line for the mouth
    const t = Math.random();
    const mouthWidth = 0.25 * scale;
    const mouthHeight = 0.05 * scale;
    
    let x = (t * 2 - 1) * mouthWidth;
    let y = -0.05 * scale + Math.sin(t * Math.PI) * mouthHeight;
    let z = eyeForward * 0.95; // Slightly behind the eyes
    
    points.push({
      position: [x, y, z],
      normal: [0, 0, 1]
    });
  }
  
  // Add randomness to all points for a more natural look
  return points.map(point => {
    const jitter = 0.015 * scale * Math.random();
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

export default {
  useModelPoints,
  generateHeadPoints,
  generateTorsoPoints,
  generateBustPoints,
  morphPoints,
  generateOctocatPoints
};
