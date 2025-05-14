import React from 'react';
import './Projects.css';

// Projects section component
const Projects = ({ items }) => {
  if (!items || items.length === 0) {
    return null; // Don't render if no project items
  }

  return (
    <section id="projects" className="projects-section">
      <div className="container">
        <h2 className="section-title">Projects</h2>
        <div className="projects-grid">
          {items.map((project, index) => (
            <div key={index} className="project-card">
              <h3>{project.title}</h3>
              <p className="project-description">{project.description}</p>
              {project.technologies && project.technologies.length > 0 && (
                <div className="project-technologies">
                  <strong>Technologies:</strong>
                  <ul>
                    {project.technologies.map((tech, i) => (
                      <li key={i}>{tech}</li>
                    ))}
                  </ul>
                </div>
              )}
              <div className="project-links">
                {project.link && project.link !== "#" && (
                  <a href={project.link} target="_blank" rel="noopener noreferrer" className="btn project-btn">
                    View Project
                  </a>
                )}
                {project.repo && project.repo !== "#" && (
                  <a href={project.repo} target="_blank" rel="noopener noreferrer" className="btn btn-secondary project-btn">
                    View Code
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Projects;
