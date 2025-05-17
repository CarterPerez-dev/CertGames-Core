// Enhanced PortfolioForm Component
import React, { useState, useEffect } from 'react';
import { FaPalette, FaDesktop, FaCode, FaPencilAlt, FaLayerGroup, FaMagic, FaArrowRight, FaArrowLeft, FaRocket, FaCheck, FaTimes, FaInfoCircle } from 'react-icons/fa';
import './portfolio.css';

const PortfolioForm = ({ userId, onGenerationStart, onGenerationComplete, onError }) => {
  const [resumeText, setResumeText] = useState('');
  const [preferences, setPreferences] = useState({
    template_style: 'modern',
    color_scheme: 'professional',
    features: ['projects', 'skills', 'contact']
  });
  const [step, setStep] = useState(1);
  const [isValidatingResume, setIsValidatingResume] = useState(false);
  const [resumeAnalysis, setResumeAnalysis] = useState(null);
  const [touchedFields, setTouchedFields] = useState({
    template_style: false,
    color_scheme: false,
    features: false,
    resumeText: false
  });
  const [formSubmitting, setFormSubmitting] = useState(false);
  
  const totalSteps = 4;

  // Check if the current step is valid to proceed
  const isStepValid = () => {
    switch(step) {
      case 1:
        return preferences.template_style;
      case 2:
        return preferences.color_scheme;
      case 3:
        return preferences.features.length > 0;
      case 4:
        return resumeText.trim().length >= 100;
      default:
        return true;
    }
  };

  // Analyze resume when it changes
  useEffect(() => {
    if (resumeText.trim().length >= 100 && touchedFields.resumeText) {
      const analyzeResume = setTimeout(() => {
        setIsValidatingResume(true);
        
        // Simulate resume analysis (in a real app, this would call an API)
        setTimeout(() => {
          const keywordCount = resumeText.toLowerCase().split(/\s+/).filter(word => 
            ['experience', 'skills', 'project', 'education', 'developed', 'created', 'designed'].includes(word)
          ).length;
          
          const contentScore = Math.min(100, Math.floor((resumeText.length / 500) * 70) + (keywordCount * 3));
          
          setResumeAnalysis({
            score: contentScore,
            wordCount: resumeText.split(/\s+/).length,
            characterCount: resumeText.length,
            keyPhrases: keywordCount >= 3,
            recommendation: contentScore < 70 ? 'Add more details about your experience and skills' : 'Your resume looks good!'
          });
          
          setIsValidatingResume(false);
        }, 1000);
      }, 800);
      
      return () => clearTimeout(analyzeResume);
    }
  }, [resumeText, touchedFields.resumeText]);

  const handleTemplateStyleChange = (style) => {
    console.log(`Selected template style: ${style}`);
    setPreferences(prev => ({
      ...prev,
      template_style: style
    }));
    setTouchedFields(prev => ({
      ...prev,
      template_style: true
    }));
  };

  const handleColorSchemeChange = (scheme) => {
    console.log(`Selected color scheme: ${scheme}`);
    setPreferences(prev => ({
      ...prev,
      color_scheme: scheme
    }));
    setTouchedFields(prev => ({
      ...prev,
      color_scheme: true
    }));
  };

  const handleFeatureToggle = (feature) => {
    console.log(`Toggling feature: ${feature}`);
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
    setTouchedFields(prev => ({
      ...prev,
      features: true
    }));
  };


  
  const handleGeneratePortfolio = async (e) => {
      e.preventDefault();
      
      // Input validation (keep existing code)
      if (!resumeText.trim() || resumeText.trim().length < 100) {
        onError('Resume text is too short or empty');
        return;
      }
      
      try {
        setFormSubmitting(true);
        
        // Call this to initiate loading sequence in PortfolioPage
        if (onGenerationStart) {
          onGenerationStart(); 
        }
        
        // Make the initial generation request
        const response = await fetch('/api/portfolio/generate-stream', {
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
          throw new Error(errorData.error || 'Failed to start portfolio generation');
        }
        
        // Instead of polling, set a single timeout
        console.log("Portfolio generation started - waiting 4 minutes for completion");
        
        // Fixed 4-minute timeout before checking status once
        setTimeout(async () => {
          try {
            console.log("Checking portfolio status after timeout");
            const statusResponse = await fetch('/api/portfolio/status/generation', {
              headers: { 'X-User-Id': userId }
            });
            
            if (statusResponse.ok) {
              const statusData = await statusResponse.json();
              
              if (statusData.success && statusData.status === 'completed' && statusData.portfolio_id) {
                console.log("Portfolio generated successfully:", statusData.portfolio_id);
                
                try {
                  const portfolioResponse = await fetch(`/api/portfolio/${statusData.portfolio_id}`, {
                    headers: { 'X-User-Id': userId }
                  });
                  
                  if (portfolioResponse.ok) {
                    const portfolioData = await portfolioResponse.json();
                    
                    if (!portfolioData.portfolio || Object.keys(portfolioData.portfolio.components || {}).length === 0) {
                      throw new Error('Received empty portfolio data');
                    }
                    
                    onGenerationComplete(portfolioData.portfolio);
                    setFormSubmitting(false);
                  } else {
                    console.error("Error fetching portfolio:", await portfolioResponse.text());
                    throw new Error('Failed to fetch the generated portfolio');
                  }
                } catch (fetchError) {
                  console.error("Error fetching portfolio details:", fetchError);
                  onError(fetchError.message || 'Error retrieving portfolio');
                  setFormSubmitting(false);
                }
              } else if (statusData.status === 'failed') {
                  onError(statusData.error || "Portfolio generation failed on the server.");
                  setFormSubmitting(false);
              } else {
                  // Still pending after timeout - let user know
                  onError("Portfolio generation is taking longer than expected. Please check back in your portfolio list shortly.");
                  setFormSubmitting(false);
              }
            } else {
              onError('Failed to check generation status');
              setFormSubmitting(false);
            }
          } catch (timeoutError) {
            console.error('Error checking portfolio status after timeout:', timeoutError);
            onError(timeoutError.message || 'Error checking portfolio status');
            setFormSubmitting(false);
          }
        }, 3 * 60 * 1000); // 4 minutes in milliseconds
        
      } catch (err) {
        console.error('Error generating portfolio:', err);
        onError(err.message || 'Failed to generate portfolio. Please try again.');
        setFormSubmitting(false);
      }
  };
  
           

  const nextStep = () => {
    if (step < totalSteps && isStepValid()) {
      console.log(`Moving from step ${step} to step ${step + 1}`);
      setStep(prev => prev + 1);
      window.scrollTo(0, 0);
    }
  };

  const prevStep = () => {
    if (step > 1) {
      console.log(`Moving from step ${step} to step ${step - 1}`);
      setStep(prev => prev - 1);
      window.scrollTo(0, 0);
    }
  };


/**
 * Provides a more helpful generation status message based on elapsed time
 * @param {number} startTimeMs The start time in milliseconds
 * @returns {string} A contextual loading message
 */
  const getPortfolioGenerationMessage = (startTimeMs) => {
    if (!startTimeMs) return "Generating your portfolio...";
    
    const elapsedSeconds = Math.floor((Date.now() - startTimeMs) / 1000);
    
    if (elapsedSeconds < 30) {
      return "Analyzing your resume and planning portfolio structure...";
    } else if (elapsedSeconds < 60) {
      return "Creating component files and styling...";
    } else if (elapsedSeconds < 120) {
      return "Generation in progress - this may take a few minutes...";
    } else if (elapsedSeconds < 240) {
      return "Still working - almost there! Complex portfolios take longer to generate.";
    } else {
      return "Portfolio is being finalized - please wait while we complete the process...";
    }
  };



  const renderProgressBar = () => {
    return (
      <div className="portfolio-form-progress">
        <div className="step-connector"></div>
        <div 
          className="step-connector-progress" 
          style={{ width: `${((step - 1) / (totalSteps - 1)) * 100}%` }}
        ></div>
        
        {[...Array(totalSteps)].map((_, index) => {
          const stepNumber = index + 1;
          return (
            <div 
              key={stepNumber} 
              className={`progress-step ${stepNumber < step ? 'completed' : ''} ${stepNumber === step ? 'active' : ''}`}
              onClick={() => {
                if (stepNumber < step) {
                  setStep(stepNumber);
                }
              }}
            >
              <div className="step-number">
                {stepNumber < step ? <FaCheck className="step-check-icon" /> : stepNumber}
              </div>
              <div className="step-label">
                {stepNumber === 1 && 'Template Style'}
                {stepNumber === 2 && 'Colors'}
                {stepNumber === 3 && 'Features'}
                {stepNumber === 4 && 'Resume'}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className="portfolio-form-container">
      {renderProgressBar()}
      
      {step === 1 && (
        <div className="portfolio-form-step">
          <div className="portfolio-form-header">
            <FaDesktop className="form-header-icon" />
            <h2>Choose Your Template Style</h2>
            <p className="form-header-description">
              Select a template style that best represents your professional brand and the industry you're targeting
            </p>
          </div>
          
          <div className="portfolio-template-options">
            <div 
              className={`portfolio-template-option ${preferences.template_style === 'modern' ? 'selected' : ''}`}
              onClick={() => handleTemplateStyleChange('modern')}
            >
              <div className="template-preview modern-preview">
                <div className="template-hover-overlay">
                  <FaCheck className="template-selected-icon" />
                </div>
              </div>
              <div className="template-info">
                <h3>Modern</h3>
                <p>Sleek dark interface with vibrant blue accents, perfect for developers and tech professionals</p>
                <div className="template-features">
                  <span className="feature-tag">Sleek UI</span>
                  <span className="feature-tag">Developer-Focused</span>
                  <span className="feature-tag">Professional</span>
                </div>
              </div>
            </div>
            
            <div 
              className={`portfolio-template-option ${preferences.template_style === 'creative' ? 'selected' : ''}`}
              onClick={() => handleTemplateStyleChange('creative')}
            >
              <div className="template-preview creative-preview">
                <div className="template-hover-overlay">
                  <FaCheck className="template-selected-icon" />
                </div>
              </div>
              <div className="template-info">
                <h3>Creative</h3>
                <p>Bold design with vibrant red and orange gradients to showcase your creative talents and stand out</p>
                <div className="template-features">
                  <span className="feature-tag">Eye-Catching</span>
                  <span className="feature-tag">Vibrant</span>
                  <span className="feature-tag">Dynamic</span>
                </div>
              </div>
            </div>
            
            <div 
              className={`portfolio-template-option ${preferences.template_style === 'corporate' ? 'selected' : ''}`}
              onClick={() => handleTemplateStyleChange('corporate')}
            >
              <div className="template-preview corporate-preview">
                <div className="template-hover-overlay">
                  <FaCheck className="template-selected-icon" />
                </div>
              </div>
              <div className="template-info">
                <h3>Corporate</h3>
                <p>Clean professional layout with strategic use of white space and navy blue accents for business portfolios</p>
                <div className="template-features">
                  <span className="feature-tag">Business-Ready</span>
                  <span className="feature-tag">Structured</span>
                  <span className="feature-tag">Professional</span>
                </div>
              </div>
            </div>
            
            <div 
              className={`portfolio-template-option ${preferences.template_style === 'tech' ? 'selected' : ''}`}
              onClick={() => handleTemplateStyleChange('tech')}
            >
              <div className="template-preview tech-preview">
                <div className="template-hover-overlay">
                  <FaCheck className="template-selected-icon" />
                </div>
              </div>
              <div className="template-info">
                <h3>Tech</h3>
                <p>Dark-themed developer portfolio with code elements, terminal-inspired UI, and teal accent highlights</p>
                <div className="template-features">
                  <span className="feature-tag">Code-Inspired</span>
                  <span className="feature-tag">Terminal UI</span>
                  <span className="feature-tag">Dark Theme</span>
                </div>
              </div>
            </div>
          </div>
          
          <div className="portfolio-form-guidance">
            <FaInfoCircle className="guidance-icon" />
            <div className="guidance-content">
              <h4>How to choose the right template</h4>
              <p>Consider your industry and target audience when selecting a template style:</p>
              <ul>
                <li><strong>Modern</strong>: Great for most industries, especially tech and digital</li>
                <li><strong>Creative</strong>: Ideal for designers, artists, photographers, and marketers</li>
                <li><strong>Corporate</strong>: Perfect for finance, consulting, legal, and traditional businesses</li>
                <li><strong>Tech</strong>: Designed for developers, IT professionals, and tech enthusiasts</li>
              </ul>
            </div>
          </div>
          
          <div className="portfolio-form-navigation">
            <div className="navigation-placeholder"></div>
            <button 
              className="portfolio-next-button"
              onClick={nextStep}
              disabled={!isStepValid()}
            >
              <span>Next: Choose Colors</span>
              <FaArrowRight className="button-icon" />
            </button>
          </div>
        </div>
      )}
      
      {step === 2 && (
        <div className="portfolio-form-step">
          <div className="portfolio-form-header">
            <FaPalette className="form-header-icon" />
            <h2>Select Color Scheme</h2>
            <p className="form-header-description">
              Choose a color palette that complements your template style and personal brand
            </p>
          </div>
          
          <div className="portfolio-color-options">
            <div 
              className={`portfolio-color-option ${preferences.color_scheme === 'professional' ? 'selected' : ''}`}
              onClick={() => handleColorSchemeChange('professional')}
            >
              <div className="color-preview professional-colors">
                <div className="color-overlay">
                  <FaCheck className="color-selected-icon" />
                </div>
                <div className="color-swatch professional-1"></div>
                <div className="color-swatch professional-2"></div>
                <div className="color-swatch professional-3"></div>
              </div>
              <div className="color-info">
                <h3>Professional</h3>
                <p>Navy blue, light gray, and white - timeless and trustworthy</p>
                <div className="color-best-for">
                  <span>Best for: Business, Finance, Law, Healthcare</span>
                </div>
              </div>
            </div>
            
            <div 
              className={`portfolio-color-option ${preferences.color_scheme === 'creative' ? 'selected' : ''}`}
              onClick={() => handleColorSchemeChange('creative')}
            >
              <div className="color-preview creative-colors">
                <div className="color-overlay">
                  <FaCheck className="color-selected-icon" />
                </div>
                <div className="color-swatch creative-1"></div>
                <div className="color-swatch creative-2"></div>
                <div className="color-swatch creative-3"></div>
              </div>
              <div className="color-info">
                <h3>Creative</h3>
                <p>Purple, pink gradients, and white - expressive and distinctive</p>
                <div className="color-best-for">
                  <span>Best for: Design, Arts, Marketing, Entertainment</span>
                </div>
              </div>
            </div>
            
            <div 
              className={`portfolio-color-option ${preferences.color_scheme === 'tech' ? 'selected' : ''}`}
              onClick={() => handleColorSchemeChange('tech')}
            >
              <div className="color-preview tech-colors">
                <div className="color-overlay">
                  <FaCheck className="color-selected-icon" />
                </div>
                <div className="color-swatch tech-1"></div>
                <div className="color-swatch tech-2"></div>
                <div className="color-swatch tech-3"></div>
              </div>
              <div className="color-info">
                <h3>Tech</h3>
                <p>Dark gray, neon green accents, and white - modern and technical</p>
                <div className="color-best-for">
                  <span>Best for: Software Development, IT, Data Science</span>
                </div>
              </div>
            </div>
            
            <div 
              className={`portfolio-color-option ${preferences.color_scheme === 'minimal' ? 'selected' : ''}`}
              onClick={() => handleColorSchemeChange('minimal')}
            >
              <div className="color-preview minimal-colors">
                <div className="color-overlay">
                  <FaCheck className="color-selected-icon" />
                </div>
                <div className="color-swatch minimal-1"></div>
                <div className="color-swatch minimal-2"></div>
                <div className="color-swatch minimal-3"></div>
              </div>
              <div className="color-info">
                <h3>Minimal</h3>
                <p>Black, white, and subtle gray - clean, focused and versatile</p>
                <div className="color-best-for">
                  <span>Best for: Photography, Architecture, Any Industry</span>
                </div>
              </div>
            </div>
          </div>
          
          <div className="portfolio-form-navigation">
            <button 
              className="portfolio-back-button"
              onClick={prevStep}
            >
              <FaArrowLeft className="button-icon" />
              <span>Back</span>
            </button>
            
            <button 
              className="portfolio-next-button"
              onClick={nextStep}
              disabled={!isStepValid()}
            >
              <span>Next: Select Features</span>
              <FaArrowRight className="button-icon" />
            </button>
          </div>
        </div>
      )}
      
      {step === 3 && (
        <div className="portfolio-form-step">
          <div className="portfolio-form-header">
            <FaLayerGroup className="form-header-icon" />
            <h2>Choose Portfolio Features</h2>
            <p className="form-header-description">
              Select which sections and features to include in your professional portfolio
            </p>
          </div>
          
          <div className="portfolio-features-selection">
            <div className="features-grid">
              <div className="feature-category">
                <h3 className="feature-category-title">Core Sections</h3>
                
                <label className={`portfolio-feature-checkbox ${preferences.features.includes('projects') ? 'selected' : ''}`}>
                  <div className="checkbox-input">
                    <input 
                      type="checkbox" 
                      checked={preferences.features.includes('projects')}
                      onChange={() => handleFeatureToggle('projects')}
                    />
                    <div className="custom-checkbox">
                      <FaCheck className="check-icon" />
                    </div>
                  </div>
                  <div className="checkbox-content">
                    <div className="checkbox-header">
                      <span className="checkbox-label">Projects</span>
                      <span className="checkbox-tag">Recommended</span>
                    </div>
                    <p className="checkbox-description">Showcase your work with detailed project descriptions</p>
                  </div>
                </label>
                
                <label className={`portfolio-feature-checkbox ${preferences.features.includes('skills') ? 'selected' : ''}`}>
                  <div className="checkbox-input">
                    <input 
                      type="checkbox" 
                      checked={preferences.features.includes('skills')}
                      onChange={() => handleFeatureToggle('skills')}
                    />
                    <div className="custom-checkbox">
                      <FaCheck className="check-icon" />
                    </div>
                  </div>
                  <div className="checkbox-content">
                    <div className="checkbox-header">
                      <span className="checkbox-label">Skills</span>
                      <span className="checkbox-tag">Recommended</span>
                    </div>
                    <p className="checkbox-description">Display your technical and professional skills with ratings</p>
                  </div>
                </label>
                
                <label className={`portfolio-feature-checkbox ${preferences.features.includes('experience') ? 'selected' : ''}`}>
                  <div className="checkbox-input">
                    <input 
                      type="checkbox" 
                      checked={preferences.features.includes('experience')}
                      onChange={() => handleFeatureToggle('experience')}
                    />
                    <div className="custom-checkbox">
                      <FaCheck className="check-icon" />
                    </div>
                  </div>
                  <div className="checkbox-content">
                    <div className="checkbox-header">
                      <span className="checkbox-label">Experience</span>
                      <span className="checkbox-tag">Recommended</span>
                    </div>
                    <p className="checkbox-description">Detail your work history and professional experience</p>
                  </div>
                </label>
                
                <label className={`portfolio-feature-checkbox ${preferences.features.includes('education') ? 'selected' : ''}`}>
                  <div className="checkbox-input">
                    <input 
                      type="checkbox" 
                      checked={preferences.features.includes('education')}
                      onChange={() => handleFeatureToggle('education')}
                    />
                    <div className="custom-checkbox">
                      <FaCheck className="check-icon" />
                    </div>
                  </div>
                  <div className="checkbox-content">
                    <div className="checkbox-header">
                      <span className="checkbox-label">Education</span>
                    </div>
                    <p className="checkbox-description">Highlight your educational background and certifications</p>
                  </div>
                </label>
              </div>
              
              <div className="feature-category">
                <h3 className="feature-category-title">Additional Features</h3>
                
                <label className={`portfolio-feature-checkbox ${preferences.features.includes('contact') ? 'selected' : ''}`}>
                  <div className="checkbox-input">
                    <input 
                      type="checkbox" 
                      checked={preferences.features.includes('contact')}
                      onChange={() => handleFeatureToggle('contact')}
                    />
                    <div className="custom-checkbox">
                      <FaCheck className="check-icon" />
                    </div>
                  </div>
                  <div className="checkbox-content">
                    <div className="checkbox-header">
                      <span className="checkbox-label">Contact Form</span>
                      <span className="checkbox-tag">Recommended</span>
                    </div>
                    <p className="checkbox-description">Allow potential employers to contact you directly</p>
                  </div>
                </label>
                
                <label className={`portfolio-feature-checkbox ${preferences.features.includes('testimonials') ? 'selected' : ''}`}>
                  <div className="checkbox-input">
                    <input 
                      type="checkbox" 
                      checked={preferences.features.includes('testimonials')}
                      onChange={() => handleFeatureToggle('testimonials')}
                    />
                    <div className="custom-checkbox">
                      <FaCheck className="check-icon" />
                    </div>
                  </div>
                  <div className="checkbox-content">
                    <div className="checkbox-header">
                      <span className="checkbox-label">Testimonials</span>
                    </div>
                    <p className="checkbox-description">Display recommendations and testimonials from colleagues</p>
                  </div>
                </label>
                
                <label className={`portfolio-feature-checkbox ${preferences.features.includes('blog') ? 'selected' : ''}`}>
                  <div className="checkbox-input">
                    <input 
                      type="checkbox" 
                      checked={preferences.features.includes('blog')}
                      onChange={() => handleFeatureToggle('blog')}
                    />
                    <div className="custom-checkbox">
                      <FaCheck className="check-icon" />
                    </div>
                  </div>
                  <div className="checkbox-content">
                    <div className="checkbox-header">
                      <span className="checkbox-label">Blog Section</span>
                    </div>
                    <p className="checkbox-description">Add a blog to showcase your expertise and thoughts</p>
                  </div>
                </label>
                
                <label className={`portfolio-feature-checkbox ${preferences.features.includes('darkmode') ? 'selected' : ''}`}>
                  <div className="checkbox-input">
                    <input 
                      type="checkbox" 
                      checked={preferences.features.includes('darkmode')}
                      onChange={() => handleFeatureToggle('darkmode')}
                    />
                    <div className="custom-checkbox">
                      <FaCheck className="check-icon" />
                    </div>
                  </div>
                  <div className="checkbox-content">
                    <div className="checkbox-header">
                      <span className="checkbox-label">Dark Mode Toggle</span>
                      <span className="checkbox-tag">Popular</span>
                    </div>
                    <p className="checkbox-description">Add a light/dark mode switch for better accessibility</p>
                  </div>
                </label>
              </div>
            </div>
          </div>
          
          <div className="portfolio-form-navigation">
            <button 
              className="portfolio-back-button"
              onClick={prevStep}
            >
              <FaArrowLeft className="button-icon" />
              <span>Back</span>
            </button>
            
            <button 
              className="portfolio-next-button"
              onClick={nextStep}
              disabled={!isStepValid()}
            >
              <span>Next: Add Resume Content</span>
              <FaArrowRight className="button-icon" />
            </button>
          </div>
        </div>
      )}
      
      {step === 4 && (
        <div className="portfolio-form-step">
          <div className="portfolio-form-header">
            <FaPencilAlt className="form-header-icon" />
            <h2>Add Your Resume Content</h2>
            <p className="form-header-description">
              Provide your resume text to generate a personalized portfolio that showcases your experience and skills **THE MORE INFO YOU ADD, THE BETTER THE PORTFOLIO**
            </p>
          </div>
          
          <div className="portfolio-resume-section">
            <div className="resume-input-area">
              <div className="resume-textarea-container">
                <textarea
                  className={`portfolio-resume-textarea ${touchedFields.resumeText && resumeText.trim().length < 100 ? 'invalid' : ''}`}
                  value={resumeText}
                  onChange={(e) => {
                    setResumeText(e.target.value);
                    if (!touchedFields.resumeText) {
                      setTouchedFields(prev => ({
                        ...prev,
                        resumeText: true
                      }));
                    }
                  }}
                  placeholder="Copy and paste your resume text here. Include your professional experience, education, skills, and any projects you'd like to showcase."
                  rows={15}
                ></textarea>
                
                {touchedFields.resumeText && resumeText.trim().length < 100 && (
                  <div className="resume-validation-error">
                    <FaTimes className="error-icon" />
                    <span>Please provide more detailed content (at least 100 characters)</span>
                  </div>
                )}
                
                <div className="resume-char-counter">
                  {resumeText.length} characters
                  {resumeText.length > 0 && ` (${resumeText.split(/\s+/).length} words)`}
                </div>
              </div>
              
              {isValidatingResume && (
                <div className="resume-analyzing">
                  <div className="analyzing-spinner"></div>
                  <span>Analyzing content...</span>
                </div>
              )}
              
              {resumeAnalysis && !isValidatingResume && (
                <div className="resume-analysis-results">
                  <h3>Content Analysis</h3>
                  
                  <div className="content-score">
                    <div className="score-label">Content Quality Score</div>
                    <div className="score-bar-container">
                      <div 
                        className={`score-bar ${resumeAnalysis.score >= 70 ? 'good' : 'needs-improvement'}`}
                        style={{ width: `${resumeAnalysis.score}%` }}
                      ></div>
                    </div>
                    <div className="score-value">{resumeAnalysis.score}%</div>
                  </div>
                  
                  <div className="analysis-stats">
                    <div className="analysis-stat">
                      <div className="stat-label">Word Count</div>
                      <div className="stat-value">{resumeAnalysis.wordCount}</div>
                      <div className="stat-tag">{resumeAnalysis.wordCount >= 100 ? 'Good' : 'Too Short'}</div>
                    </div>
                    
                    <div className="analysis-stat">
                      <div className="stat-label">Key Phrases</div>
                      <div className="stat-value">{resumeAnalysis.keyPhrases ? 'Detected' : 'Limited'}</div>
                      <div className="stat-tag">{resumeAnalysis.keyPhrases ? 'Good' : 'Add More'}</div>
                    </div>
                  </div>
                  
                  <div className="analysis-recommendation">
                    <FaInfoCircle className="recommendation-icon" />
                    <p>{resumeAnalysis.recommendation}</p>
                  </div>
                </div>
              )}
            </div>
            
            <div className="resume-tips-container">
              <div className="resume-tips">
                <h4>Tips for Best Results</h4>
                <ul className="tips-list">
                  <li>Include your <strong>full name</strong> and professional title</li>
                  <li>List your <strong>technical skills</strong> and proficiency levels</li>
                  <li>Describe your <strong>professional experience</strong> with bullet points</li>
                  <li>Include <strong>education</strong>, certifications, and notable achievements</li>
                  <li>Mention any <strong>significant projects</strong> with brief descriptions</li>
                  <li>Highlight your <strong>accomplishments</strong> and <strong>metrics</strong> where possible</li>
                </ul>
              </div>
              
              <div className="example-snippet">
                <h4>Example Snippet</h4>
                <div className="example-content">
                  <p><strong>John Smith</strong> | Full Stack Developer</p>
                  <p><strong>Experience:</strong> 3 years as a Full Stack Developer at XYZ Tech, where I led the development of a customer portal that increased user engagement by 45%.</p>
                  <p><strong>Skills:</strong> JavaScript, React, Node.js, Python, SQL, AWS</p>
                  <p><strong>Education:</strong> BS Computer Science, State University (2018)</p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="portfolio-form-navigation">
            <button 
              className="portfolio-back-button"
              onClick={prevStep}
            >
              <FaArrowLeft className="button-icon" />
              <span>Back</span>
            </button>
            
            <button 
              className="portfolio-generate-button"
              onClick={handleGeneratePortfolio}
              disabled={!isStepValid() || formSubmitting}
            >
              {formSubmitting ? (
                <>
                  <div className="button-spinner"></div>
                  <span>Generating...</span>
                </>
              ) : (
                <>
                  <FaMagic className="button-icon" />
                  <span>Generate Portfolio</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default PortfolioForm;
