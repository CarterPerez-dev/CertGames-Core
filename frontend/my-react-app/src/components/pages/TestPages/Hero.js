import React from 'react';
import './Hero.css';

// Hero section component
const Hero = ({ name, title }) => {
  return (
    <section id="hero" className="hero-section">
      <div className="container hero-content">
        <h1>Hello, I'm <span className="hero-name">{name}</span>.</h1>
        <p className="hero-subtitle">I am a passionate <span className="hero-title">{title}</span>.</p>
        <p className="hero-tagline">
          Dedicated to safeguarding digital assets and building secure systems.
          Exploring the frontiers of cybersecurity to make the digital world a safer place.
        </p>
        <a href="#projects" className="btn hero-btn">View My Work</a>
        <a href="#contact" className="btn btn-secondary hero-btn">Get In Touch</a>
      </div>
    </section>
  );
};

export default Hero;
