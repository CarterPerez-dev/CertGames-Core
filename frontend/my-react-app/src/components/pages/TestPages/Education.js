import React from 'react';
import './Education.css';

// Education section component
const Education = ({ items }) => {
  if (!items || items.length === 0) {
    return null; // Don't render if no education items
  }

  return (
    <section id="education" className="education-section">
      <div className="container">
        <h2 className="section-title">Education</h2>
        <div className="education-list">
          {items.map((edu, index) => (
            <div key={index} className="education-item">
              <h3>{edu.degree}</h3>
              <p className="education-institution">{edu.institution}</p>
              <p className="education-years">{edu.years}</p>
              {edu.description && <p className="education-description">{edu.description}</p>}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Education;
