// frontend/my-react-app/src/components/pages/Portfolio/PortfolioForm.js
import React, { useState } from 'react';
import './portfolio.css';

const PortfolioForm = ({ userId, onGenerationStart, onGenerationComplete, onError }) => {
  const [resumeText, setResumeText] = useState('');
  const [preferences, setPreferences] = useState({
    template_style: 'modern',
    color_scheme: 'professional',
    features: ['projects', 'skills', 'contact']
  });
  const [step, setStep] = useState(1);

  const handleTemplateStyleChange = (style) => {
    setPreferences(prev => ({
      ...prev,
      template_style: style
    }));
  };

  const handleColorSchemeChange = (scheme) => {
    setPreferences(prev => ({
      ...prev,
      color_scheme: scheme
    }));
  };

  const handleFeatureToggle = (feature) => {
    setPreferences(prev => {
      const features = [...prev.features];
      
      if (features.includes(feature)) {
        return {
          ...prev,
          features: features.filter(f => f !== feature)
        };
      } else {
        return {
          ...prev,
          features: [...features, feature]
        };
      }
    });
  };

  const handleGeneratePortfolio = async (e) => {
    e.preventDefault();
    
    if (!resumeText.trim()) {
      onError('Please provide your resume text');
      return;
    }
    
    try {
      onGenerationStart();
      
      const response = await fetch('/api/portfolio/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-Id': userId
        },
        body: JSON.stringify({
          resume_text: resumeText,
          preferences
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to generate portfolio');
      }
      
      const data = await response.json();
      onGenerationComplete(data);
      
    } catch (err) {
      console.error('Error generating portfolio:', err);
      onError(err.message || 'Failed to generate portfolio. Please try again.');
    }
  };

  const nextStep = () => {
    setStep(prev => prev + 1);
  };

  const prevStep = () => {
    setStep(prev => prev - 1);
  };

  return (
    <div className="portfolio-form-container">
      {step === 1 && (
        <div className="form-step">
          <h2>Step 1: Choose Your Template Style</h2>
          <div className="template-options">
            <div 
              className={`template-option ${preferences.template_style === 'modern' ? 'selected' : ''}`}
              onClick={() => handleTemplateStyleChange('modern')}
            >
              <div className="template-preview modern-preview"></div>
              <h3>Modern</h3>
              <p>Clean, minimalist design with ample white space</p>
            </div>
            
            <div 
              className={`template-option ${preferences.template_style === 'creative' ? 'selected' : ''}`}
              onClick={() => handleTemplateStyleChange('creative')}
            >
              <div className="template-preview creative-preview"></div>
              <h3>Creative</h3>
              <p>Bold, eye-catching design for creative professionals</p>
            </div>
            
            <div 
              className={`template-option ${preferences.template_style === 'corporate' ? 'selected' : ''}`}
              onClick={() => handleTemplateStyleChange('corporate')}
            >
              <div className="template-preview corporate-preview"></div>
              <h3>Corporate</h3>
              <p>Professional design suitable for corporate environments</p>
            </div>
            
            <div 
              className={`template-option ${preferences.template_style === 'tech' ? 'selected' : ''}`}
              onClick={() => handleTemplateStyleChange('tech')}
            >
              <div className="template-preview tech-preview"></div>
              <h3>Tech</h3>
              <p>Modern tech-inspired design with code aesthetics</p>
            </div>
          </div>
          
          <div className="form-navigation">
            <button className="next-button" onClick={nextStep}>Next: Choose Colors</button>
          </div>
        </div>
      )}
      
      {step === 2 && (
        <div className="form-step">
          <h2>Step 2: Select Color Scheme</h2>
          
          <div className="color-scheme-options">
            <div 
              className={`color-scheme-option ${preferences.color_scheme === 'professional' ? 'selected' : ''}`}
              onClick={() => handleColorSchemeChange('professional')}
            >
              <div className="color-preview professional-colors">
                <div className="color-swatch"></div>
                <div className="color-swatch"></div>
                <div className="color-swatch"></div>
              </div>
              <h3>Professional</h3>
              <p>Navy blue, light gray, and white</p>
            </div>
            
            <div 
              className={`color-scheme-option ${preferences.color_scheme === 'creative' ? 'selected' : ''}`}
              onClick={() => handleColorSchemeChange('creative')}
            >
              <div className="color-preview creative-colors">
                <div className="color-swatch"></div>
                <div className="color-swatch"></div>
                <div className="color-swatch"></div>
              </div>
              <h3>Creative</h3>
              <p>Purple, light pink, and white</p>
            </div>
            
            <div 
              className={`color-scheme-option ${preferences.color_scheme === 'tech' ? 'selected' : ''}`}
              onClick={() => handleColorSchemeChange('tech')}
            >
              <div className="color-preview tech-colors">
                <div className="color-swatch"></div>
                <div className="color-swatch"></div>
                <div className="color-swatch"></div>
              </div>
              <h3>Tech</h3>
              <p>Dark gray, neon green, and white</p>
            </div>
            
            <div 
              className={`color-scheme-option ${preferences.color_scheme === 'minimal' ? 'selected' : ''}`}
              onClick={() => handleColorSchemeChange('minimal')}
            >
              <div className="color-preview minimal-colors">
                <div className="color-swatch"></div>
                <div className="color-swatch"></div>
                <div className="color-swatch"></div>
              </div>
              <h3>Minimal</h3>
              <p>Black, white, and light gray</p>
            </div>
          </div>
          
          <div className="form-navigation">
            <button className="back-button" onClick={prevStep}>Back</button>
            <button className="next-button" onClick={nextStep}>Next: Select Features</button>
          </div>
        </div>
      )}
      
      {step === 3 && (
        <div className="form-step">
          <h2>Step 3: Choose Portfolio Features</h2>
          
          <div className="features-selection">
            <p>Select which sections to include in your portfolio:</p>
            
            <div className="feature-checkboxes">
              <label className="feature-checkbox">
                <input 
                  type="checkbox" 
                  checked={preferences.features.includes('projects')}
                  onChange={() => handleFeatureToggle('projects')}
                />
                <span>Projects</span>
              </label>
              
              <label className="feature-checkbox">
                <input 
                  type="checkbox" 
                  checked={preferences.features.includes('skills')}
                  onChange={() => handleFeatureToggle('skills')}
                />
                <span>Skills</span>
              </label>
              
              <label className="feature-checkbox">
                <input 
                  type="checkbox" 
                  checked={preferences.features.includes('experience')}
                  onChange={() => handleFeatureToggle('experience')}
                />
                <span>Experience</span>
              </label>
              
              <label className="feature-checkbox">
                <input 
                  type="checkbox" 
                  checked={preferences.features.includes('education')}
                  onChange={() => handleFeatureToggle('education')}
                />
                <span>Education</span>
              </label>
              
              <label className="feature-checkbox">
                <input 
                  type="checkbox" 
                  checked={preferences.features.includes('contact')}
                  onChange={() => handleFeatureToggle('contact')}
                />
                <span>Contact Form</span>
              </label>
              
              <label className="feature-checkbox">
                <input 
                  type="checkbox" 
                  checked={preferences.features.includes('testimonials')}
                  onChange={() => handleFeatureToggle('testimonials')}
                />
                <span>Testimonials</span>
              </label>
              
              <label className="feature-checkbox">
                <input 
                  type="checkbox" 
                  checked={preferences.features.includes('blog')}
                  onChange={() => handleFeatureToggle('blog')}
                />
                <span>Blog Section</span>
              </label>
              
              <label className="feature-checkbox">
                <input 
                  type="checkbox" 
                  checked={preferences.features.includes('darkmode')}
                  onChange={() => handleFeatureToggle('darkmode')}
                />
                <span>Dark Mode Toggle</span>
              </label>
            </div>
          </div>
          
          <div className="form-navigation">
            <button className="back-button" onClick={prevStep}>Back</button>
            <button className="next-button" onClick={nextStep}>Next: Add Your Resume</button>
          </div>
        </div>
      )}
      
      {step === 4 && (
        <div className="form-step">
          <h2>Step 4: Paste Your Resume</h2>
          
          <div className="resume-input-section">
            <p>Paste your resume content below. This information will be used to generate your portfolio:</p>
            
            <textarea
              className="resume-textarea"
              value={resumeText}
              onChange={(e) => setResumeText(e.target.value)}
              placeholder="Copy and paste your resume text here. Include your professional experience, education, skills, and any projects you'd like to showcase."
              rows={15}
            ></textarea>
            
            <div className="resume-tips">
              <h4>Tips for best results:</h4>
              <ul>
                <li>Include your full name and professional title</li>
                <li>List your technical skills and proficiency levels</li>
                <li>Describe your professional experience with bullet points</li>
                <li>Include education, certifications, and notable achievements</li>
                <li>Mention any significant projects with brief descriptions</li>
              </ul>
            </div>
          </div>
          
          <div className="form-navigation">
            <button className="back-button" onClick={prevStep}>Back</button>
            <button 
              className="generate-button"
              onClick={handleGeneratePortfolio}
              disabled={!resumeText.trim()}
            >
              Generate Portfolio
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default PortfolioForm;
