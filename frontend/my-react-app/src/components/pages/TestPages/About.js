import React from 'react';
import './About.css';

// About section component
const About = () => {
  return (
    <section id="about" className="about-section">
      <div className="container">
        <h2 className="section-title">About Me</h2>
        <div className="about-content">
          <div className="about-text">
            <p>
              Hello! I'm Alex Doe, a dedicated and analytical Cybersecurity Professional with a Master's degree
              from the University of Maryland Global Campus. My passion lies in understanding and mitigating
              cyber threats to protect information and systems.
            </p>
            <p>
              I am driven by a continuous learning mindset, always eager to explore new technologies and
              methodologies in the ever-evolving field of cybersecurity. My academic background has provided
              me with a strong foundation in network security, cryptography, ethical hacking, and risk management.
            </p>
            <p>
              I am currently seeking opportunities where I can apply my skills to contribute to a security-conscious
              organization, help defend against cyber attacks, and grow as a cybersecurity expert.
              When I'm not delving into security topics, I enjoy [mention a hobby or two, e.g., coding personal projects, reading tech blogs, or hiking].
            </p>
          </div>
          {/* Optional: Add an image here */}
          {/* <div className="about-image">
            <img src="path/to/your/image.jpg" alt="Alex Doe" />
          </div> */}
        </div>
      </div>
    </section>
  );
};

export default About;
