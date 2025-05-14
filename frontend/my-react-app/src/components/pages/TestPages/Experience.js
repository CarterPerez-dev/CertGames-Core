import React from 'react';
import './Experience.css';

// Experience section component
const Experience = ({ items }) => {
  if (!items || items.length === 0) {
    return null; // Don't render if no experience items
  }

  return (
    <section id="experience" className="experience-section">
      <div className="container">
        <h2 className="section-title">Experience</h2>
        <div className="experience-timeline">
          {items.map((exp, index) => (
            <div key={index} className="experience-item">
              <div className="experience-dot"></div>
              <div className="experience-content">
                <h3>{exp.role}</h3>
                <p className="experience-company">{exp.company}</p>
                <p className="experience-years">{exp.years}</p>
                {exp.responsibilities && (
                  <ul className="experience-responsibilities">
                    {exp.responsibilities.map((resp, i) => (
                      <li key={i}>{resp}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Experience;
