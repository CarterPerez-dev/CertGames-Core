// src/components/pages/games/IncidentResponder/GameInstructions.js
import React from 'react';
import { FaTimes, FaExclamationTriangle, FaClipboardCheck, FaStar, FaPercentage } from 'react-icons/fa';
import './GameInstructions.css';

const GameInstructions = ({ onClose }) => {
  return (
    <div className="ir_game_instructions_overlay">
      <div className="ir_game_instructions_container">
        <button className="ir_game_instructions_close" onClick={onClose}>
          <FaTimes />
        </button>
        
        <h2 className="ir_game_instructions_title">How to Play Incident Responder</h2>
        
        <div className="ir_game_instructions_section">
          <h3><FaClipboardCheck /> Game Overview</h3>
          <p>Test your cybersecurity incident response skills in realistic scenarios. You'll face various security incidents and must make decisions that affect the outcome.</p>
        </div>
        
        <div className="ir_game_instructions_section">
          <h3><FaExclamationTriangle /> Gameplay</h3>
          <ul className="ir_game_instructions_list">
            <li>Select a scenario based on type and difficulty</li>
            <li>Read the scenario background and your role</li>
            <li>Each scenario consists of 5 stages where you'll make critical decisions</li>
            <li>Choose the best response in each stage within the time limit (if applicable)</li>
            <li>After each decision, you'll see feedback on your choice</li>
            <li>Complete all stages to receive your final score and analysis</li>
          </ul>
        </div>
        
        <div className="ir_game_instructions_section">
          <h3><FaStar /> Scoring</h3>
          <ul className="ir_game_instructions_list">
            <li>Each decision is worth points based on its effectiveness</li>
            <li>Maximum points are awarded for optimal decisions</li>
            <li>Your final score is calculated as a percentage of maximum possible points</li>
            <li>Response rating (0-100) determines your responder rank</li>
            <li>Time bonuses may be awarded for quick responses</li>
            <li>XP and coins are awarded based on your performance</li>
          </ul>
        </div>
        
        <div className="ir_game_instructions_section">
          <h3><FaPercentage /> Score Calculation</h3>
          <p>Your score is calculated as:</p>
          <div className="ir_game_instructions_formula">
            Score % = (Points Earned / Maximum Possible Points) × 100
          </div>
          <p>Response ratings determine your rank:</p>
          <ul className="ir_game_instructions_list">
            <li>90-100: Expert Responder</li>
            <li>70-89: Skilled Responder</li>
            <li>50-69: Competent Responder</li>
            <li>0-49: Novice Responder</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default GameInstructions;
