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

export default {
  useModelPoints,
  generateHeadPoints,
  generateTorsoPoints,
  generateBustPoints,
  morphPoints
};
