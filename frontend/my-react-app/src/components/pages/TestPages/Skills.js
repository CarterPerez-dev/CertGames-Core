import React from 'react';
import './Skills.css';

// Skills section component
const Skills = ({ skills }) => {
  if (!skills || (!skills.technical && !skills.soft)) {
    return null; // Don't render if no skills data
  }

  return (
    <section id="skills" className="skills-section">
      <div className="container">
        <h2 className="section-title">Skills</h2>
        <div className="skills-grid">
          {skills.technical && skills.technical.length > 0 && (
            <div className="skills-category">
              <h3>Technical Skills</h3>
              <ul className="skills-list">
                {skills.technical.map((skill, index) => (
                  <li key={index} className="skill-item">{skill}</li>
                ))}
              </ul>
            </div>
          )}
          {skills.soft && skills.soft.length > 0 && (
            <div className="skills-category">
              <h3>Soft Skills</h3>
              <ul className="skills-list">
                {skills.soft.map((skill, index) => (
                  <li key={index} className="skill-item">{skill}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </section>
  );
};

export default Skills;
