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
export function generateOctocatPoints(count = 20000, scale = 1) {
  // Create an array to hold all the points
  const points = [];
  
  // Generate the head (spherical base)
  const headCount = Math.floor(count * 0.4);
  const headRadius = 0.8 * scale;
  for (let i = 0; i < headCount; i++) {
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos((Math.random() * 2) - 1);
    const x = headRadius * Math.sin(phi) * Math.cos(theta);
    const y = headRadius * Math.sin(phi) * Math.sin(theta) + 0.2 * scale; // Shift up a bit
    const z = headRadius * Math.cos(phi);
    
    // Only keep points that are not in the bottom section
    if (z > -headRadius * 0.5) {
      points.push({
        position: [x, y, z],
        normal: [Math.sin(phi) * Math.cos(theta), Math.sin(phi) * Math.sin(theta), Math.cos(phi)]
      });
    }
  }
  
  // Generate the body
  const bodyCount = Math.floor(count * 0.3);
  const bodyWidth = 0.65 * scale;
  const bodyHeight = 0.8 * scale;
  for (let i = 0; i < bodyCount; i++) {
    // Make the body more oval-shaped and tapered at the bottom
    const u = Math.random() * Math.PI * 2;
    const v = Math.random();
    const radius = bodyWidth * (1 - v * 0.3); // Taper at the bottom
    
    const x = radius * Math.cos(u);
    const y = -bodyHeight * v - 0.3 * scale; // Position below the head
    const z = radius * Math.sin(u);
    
    points.push({
      position: [x, y, z],
      normal: [Math.cos(u), 0, Math.sin(u)]
    });
  }
  
  // Generate the tentacles
  const tentacleCount = Math.floor(count * 0.3);
  const numTentacles = 5; // Create 5 tentacles
  
  for (let t = 0; t < numTentacles; t++) {
    const angle = (t / numTentacles) * Math.PI * 2;
    const baseX = Math.cos(angle) * bodyWidth * 0.9;
    const baseZ = Math.sin(angle) * bodyWidth * 0.9;
    const baseY = -0.6 * scale - Math.random() * 0.4 * scale;
    
    const pointsPerTentacle = Math.floor(tentacleCount / numTentacles);
    
    // Create a curved tentacle
    for (let i = 0; i < pointsPerTentacle; i++) {
      const progress = i / pointsPerTentacle;
      const tentacleLength = 0.8 * scale + (Math.random() * 0.4 * scale);
      
      // Create a curve with sine wave
      const curve = Math.sin(progress * Math.PI * 2) * 0.2 * scale;
      
      const x = baseX + curve * Math.cos(angle + Math.PI/2);
      const y = baseY - progress * tentacleLength;
      const z = baseZ + curve * Math.sin(angle + Math.PI/2);
      
      // Calculate normal approximation
      const tangent = new THREE.Vector3(
        Math.cos(angle + Math.PI/2) * 0.2 * Math.PI * 2 * Math.cos(progress * Math.PI * 2),
        -tentacleLength,
        Math.sin(angle + Math.PI/2) * 0.2 * Math.PI * 2 * Math.cos(progress * Math.PI * 2)
      ).normalize();
      
      const normal = new THREE.Vector3(x, 0, z).normalize();
      normal.cross(tangent).normalize();
      
      points.push({
        position: [x, y, z],
        normal: [normal.x, normal.y, normal.z]
      });
    }
  }
  
  // Add eyes
  const eyeCount = Math.floor(count * 0.05);
  const eyeSize = 0.15 * scale;
  const eyeSpacing = 0.3 * scale;
  
  for (let i = 0; i < eyeCount; i++) {
    const side = i < eyeCount / 2 ? -1 : 1; // Left or right eye
    
    const theta = Math.random() * Math.PI * 0.5 - Math.PI * 0.25; // Front-facing
    const phi = Math.random() * Math.PI * 0.5 + Math.PI * 0.25; // Upper half
    
    const eyeX = side * eyeSpacing + (Math.random() - 0.5) * eyeSize;
    const eyeY = 0.2 * scale + (Math.random() - 0.5) * eyeSize;
    const eyeZ = headRadius * 0.8 + (Math.random() - 0.5) * eyeSize; // Push to front
    
    points.push({
      position: [eyeX, eyeY, eyeZ],
      normal: [0, 0, 1] // Eyes face forward
    });
  }
  
  // Add jitter to all points for a more natural look
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

export default {
  useModelPoints,
  generateHeadPoints,
  generateTorsoPoints,
  generateBustPoints,
  morphPoints,
  generateOctocatPoints
};
