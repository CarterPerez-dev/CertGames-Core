// portfolio.js - Enhanced Portfolio Page
// Complete rewrite with modern animations, better UX, and improved flow

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import { 
  FaCode, FaDesktop, FaPalette, FaPuzzlePiece, FaRocket, 
  FaCog, FaSyncAlt, FaCheck, FaUserAlt, FaGlobe, FaEye, 
  FaLaptopCode, FaMobileAlt, FaServer, FaDatabase, FaNetworkWired,
  FaFileCode, FaSearchPlus, FaFolderOpen, FaExclamationCircle,
  FaCopy, FaRegClone, FaBriefcase, FaLightbulb, FaLink,
  FaInfoCircle, FaShare, FaTwitter, FaLinkedin, FaEnvelope,
  FaFilter, FaSort, FaClock, FaCheckCircle, FaFileDownload, 
  FaUndoAlt, FaCloudUploadAlt, FaExternalLinkAlt, FaSpinner
} from 'react-icons/fa';
import ReactMarkdown from 'react-markdown'; // For markdown content rendering
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'; // For code preview
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import './portfolio.css';

// Utility Functions
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Portfolio Service - Handles API Calls
const portfolioService = {
  async getPortfolios() {
    try {
      // Mock API call for demo
      await sleep(1000);
      return {
        success: true,
        data: [...Array(6)].map((_, i) => ({
          id: `portfolio-${i+1}`,
          title: `My Portfolio ${i+1}`,
          template: ['Modern', 'Creative', 'Corporate', 'Tech'][i % 4],
          colorScheme: ['Professional', 'Vibrant', 'Minimal', 'Tech'][i % 4],
          createdAt: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
          isDeployed: i % 3 === 0,
          deployedUrl: i % 3 === 0 ? `https://myportfolio${i+1}.example.com` : null,
          skills: ['React', 'JavaScript', 'CSS', i % 2 ? 'TypeScript' : 'Node.js'].slice(0, Math.floor(Math.random() * 3) + 2),
          features: {
            hasProjects: true,
            hasSkills: true,
            hasContact: i % 2 === 0,
            hasTestimonials: i % 3 === 0,
            hasTimeline: i % 2 === 1,
          }
        }))
      };
    } catch (error) {
      console.error("Error fetching portfolios:", error);
      return { success: false, error: "Failed to fetch portfolios" };
    }
  },
  
  async createPortfolio(portfolioData) {
    try {
      // Mock API call for demo
      await sleep(2000);
      return {
        success: true,
        data: {
          id: `portfolio-${Date.now()}`,
          ...portfolioData,
          createdAt: new Date().toISOString(),
          isDeployed: false
        }
      };
    } catch (error) {
      console.error("Error creating portfolio:", error);
      return { success: false, error: "Failed to create portfolio" };
    }
  },
  
  async deployPortfolio(portfolioId) {
    try {
      // Mock API call for demo
      await sleep(5000);
      return {
        success: true,
        data: {
          id: portfolioId,
          isDeployed: true,
          deployedUrl: `https://myportfolio${portfolioId.split('-')[1]}.example.com`
        }
      };
    } catch (error) {
      console.error("Error deploying portfolio:", error);
      return { success: false, error: "Failed to deploy portfolio" };
    }
  },
  
  async getPortfolioFiles(portfolioId) {
    try {
      // Mock API call for demo
      await sleep(1500);
      return {
        success: true,
        data: {
          files: {
            'index.html': `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>My Portfolio</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <header>
    <div class="container">
      <h1>John Doe</h1>
      <nav>
        <ul>
          <li><a href="#about">About</a></li>
          <li><a href="#projects">Projects</a></li>
          <li><a href="#skills">Skills</a></li>
          <li><a href="#contact">Contact</a></li>
        </ul>
      </nav>
    </div>
  </header>
  
  <main>
    <!-- Hero Section -->
    <section id="hero">
      <div class="container">
        <h2>Full Stack Developer</h2>
        <p>I create beautiful, functional websites and applications.</p>
        <a href="#contact" class="cta-button">Get in touch</a>
      </div>
    </section>
    
    <!-- About Section -->
    <section id="about">
      <div class="container">
        <h2>About Me</h2>
        <div class="about-content">
          <div class="about-text">
            <p>Hello! I'm John, a passionate full-stack developer with over 5 years of experience in building web applications. I specialize in JavaScript, React, and Node.js.</p>
            <p>I love creating intuitive and performant user experiences, and I'm always looking to learn new technologies and improve my skills.</p>
          </div>
          <div class="about-image">
            <img src="images/profile.jpg" alt="John Doe">
          </div>
        </div>
      </div>
    </section>
    
    <!-- More sections omitted for brevity -->
  </main>
  
  <footer>
    <div class="container">
      <p>&copy; 2025 John Doe. All rights reserved.</p>
      <div class="social-links">
        <a href="#" target="_blank">GitHub</a>
        <a href="#" target="_blank">LinkedIn</a>
        <a href="#" target="_blank">Twitter</a>
      </div>
    </div>
  </footer>
  
  <script src="script.js"></script>
</body>
</html>`,
            'styles.css': `/* Base Styles */
:root {
  --primary-color: #735bf2;
  --secondary-color: #ff4c8b;
  --text-color: #1a202c;
  --background-color: #f8fafc;
  --light-gray: #e2e8f0;
  --dark-gray: #4a5568;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  line-height: 1.6;
  color: var(--text-color);
  background-color: var(--background-color);
}

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 2rem;
}

/* Header Styles */
header {
  background-color: white;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  position: fixed;
  width: 100%;
  top: 0;
  z-index: 100;
}

header .container {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem 2rem;
}

header h1 {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--primary-color);
}

nav ul {
  display: flex;
  list-style: none;
}

nav ul li {
  margin-left: 2rem;
}

nav ul li a {
  text-decoration: none;
  color: var(--dark-gray);
  font-weight: 500;
  transition: color 0.3s ease;
}

nav ul li a:hover {
  color: var(--primary-color);
}

/* Hero Section */
#hero {
  height: 100vh;
  display: flex;
  align-items: center;
  background: linear-gradient(135deg, rgba(115, 91, 242, 0.1), rgba(255, 76, 139, 0.1));
  text-align: center;
}

#hero h2 {
  font-size: 3rem;
  margin-bottom: 1.5rem;
  color: var(--text-color);
}

#hero p {
  font-size: 1.5rem;
  margin-bottom: 2rem;
  color: var(--dark-gray);
  max-width: 600px;
  margin-left: auto;
  margin-right: auto;
}

.cta-button {
  display: inline-block;
  background: var(--primary-color);
  color: white;
  padding: 1rem 2rem;
  border-radius: 30px;
  text-decoration: none;
  font-weight: 600;
  transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.cta-button:hover {
  transform: translateY(-3px);
  box-shadow: 0 10px 20px rgba(115, 91, 242, 0.3);
}

/* Additional sections and responsive styles omitted for brevity */`,
            'script.js': `// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function(e) {
    e.preventDefault();
    
    const target = document.querySelector(this.getAttribute('href'));
    
    if (target) {
      window.scrollTo({
        top: target.offsetTop - 80, // Adjust for header height
        behavior: 'smooth'
      });
    }
  });
});

// Add active class to navigation links on scroll
window.addEventListener('scroll', () => {
  const sections = document.querySelectorAll('section');
  const navLinks = document.querySelectorAll('nav ul li a');
  
  let currentSection = '';
  
  sections.forEach(section => {
    const sectionTop = section.offsetTop;
    const sectionHeight = section.clientHeight;
    
    if (window.pageYOffset >= sectionTop - 100) {
      currentSection = section.getAttribute('id');
    }
  });
  
  navLinks.forEach(link => {
    link.classList.remove('active');
    if (link.getAttribute('href') === \`#\${currentSection}\`) {
      link.classList.add('active');
    }
  });
});

// More JavaScript functionality omitted for brevity`,
            'README.md': `# Portfolio Website

A modern, responsive portfolio website built with HTML, CSS, and JavaScript.

## Features

- Responsive design that works on all devices
- Smooth scrolling navigation
- Animated sections
- Project showcase with filtering
- Contact form with validation
- Skills visualization

## Customization

To customize this portfolio:

1. Update the personal information in index.html
2. Replace project images in the /images folder
3. Modify the color scheme in styles.css using CSS variables
4. Add your own projects to the projects section

## Deployment

This portfolio is ready to deploy on any static website hosting, such as:

- GitHub Pages
- Netlify
- Vercel
- Firebase Hosting

## License

MIT License`
          }
        }
      };
    } catch (error) {
      console.error("Error fetching portfolio files:", error);
      return { success: false, error: "Failed to fetch portfolio files" };
    }
  }
};

// ========================================================================
// Main Components
// ========================================================================

// PortfolioPage Component - Manages the overall page and state
const PortfolioPage = () => {
  const [activeTab, setActiveTab] = useState('portfolios');
  const [selectedPortfolio, setSelectedPortfolio] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(null);

  const user = useSelector(state => state.user);
  const navigate = useNavigate();
  
  const handleRefresh = async () => {
    setIsRefreshing(true);
    await sleep(1000); // Simulated refresh
    setIsRefreshing(false);
  };
  
  const renderContent = () => {
    switch (activeTab) {
      case 'create':
        return <PortfolioCreator onComplete={() => setActiveTab('portfolios')} />;
      case 'preview':
        return <PortfolioPreview portfolio={selectedPortfolio} onBack={() => setActiveTab('portfolios')} />;
      case 'deploy':
        return <PortfolioDeployment portfolio={selectedPortfolio} onBack={() => setActiveTab('portfolios')} onComplete={() => setActiveTab('portfolios')} />;
      case 'portfolios':
      default:
        return <PortfolioList onSelect={(portfolio) => {
          setSelectedPortfolio(portfolio);
          setActiveTab('preview');
        }} onCreateNew={() => setActiveTab('create')} />;
    }
  };
  
  return (
    <div className="portfolio-page-container">
      <div className="portfolio-page-header">
        <div className="portfolio-page-title-section">
          <h1 className="portfolio-page-title">Portfolio Builder</h1>
          <p className="portfolio-page-subtitle">Create and showcase your professional portfolio website in minutes</p>
        </div>
        <div className="portfolio-page-actions">
          <button 
            className={`portfolio-refresh-button ${isRefreshing ? 'refreshing' : ''}`} 
            onClick={handleRefresh}
            disabled={isRefreshing}
          >
            <FaSyncAlt className={`refresh-icon ${isRefreshing ? 'spin' : ''}`} />
            {isRefreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>
      
      <div className="portfolio-page-tabs">
        <button 
          className={`portfolio-tab-button ${activeTab === 'portfolios' ? 'active' : ''}`}
          onClick={() => setActiveTab('portfolios')}
        >
          <FaBriefcase className="tab-icon" />
          My Portfolios
        </button>
        <button 
          className={`portfolio-tab-button ${activeTab === 'create' ? 'active' : ''}`}
          onClick={() => setActiveTab('create')}
        >
          <FaCode className="tab-icon" />
          Create Portfolio
        </button>
      </div>
      
      {error && (
        <div className="portfolio-error-banner">
          <div>
            <FaExclamationCircle /> {error}
          </div>
        </div>
      )}
      
      <div className="portfolio-page-content">
        {renderContent()}
      </div>
    </div>
  );
};

// ========================================================================
// Portfolio Creator Component
// ========================================================================

// The Portfolio Creation Wizard
const PortfolioCreator = ({ onComplete }) => {
  const [currentStep, setCurrentStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [formData, setFormData] = useState({
    template: null,
    colorScheme: null,
    features: {
      hasAbout: true,
      hasProjects: true,
      hasSkills: true,
      hasContact: false,
      hasTestimonials: false,
      hasTimeline: false,
      hasServices: false,
      hasBlog: false
    },
    resumeText: '',
    title: '',
    customizations: {}
  });
  
  const totalSteps = 4;
  
  useEffect(() => {
    // Generate a random progress for loading simulation
    if (loading) {
      const interval = setInterval(() => {
        setProgress(prev => {
          const increment = Math.random() * 10;
          const newProgress = Math.min(prev + increment, 99);
          return newProgress;
        });
      }, 500);
      
      return () => clearInterval(interval);
    }
  }, [loading]);
  
  const handleNext = () => {
    if (currentStep < totalSteps) {
      setCurrentStep(prev => prev + 1);
    } else {
      handleSubmit();
    }
  };
  
  const handleBack = () => {
    if (currentStep > 1) {
      setCurrentStep(prev => prev - 1);
    }
  };
  
  const handleStepClick = (step) => {
    if (step < currentStep) {
      setCurrentStep(step);
    }
  };
  
  const handleSubmit = async () => {
    setLoading(true);
    
    try {
      // Simulate portfolio creation
      const result = await portfolioService.createPortfolio(formData);
      
      if (result.success) {
        toast.success("Portfolio created successfully!");
        onComplete();
      } else {
        toast.error("Failed to create portfolio: " + result.error);
      }
    } catch (error) {
      console.error("Error creating portfolio:", error);
      toast.error("An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };
  
  const renderStepContent = () => {
    if (loading) {
      return (
        <div className="portfolio-loading-container">
          <FaRocket size={50} />
          <h2>Creating your portfolio...</h2>
          <p>This will only take a moment</p>
          
          <div className="portfolio-loading-progress-container">
            <div 
              className="portfolio-loading-progress-bar" 
              style={{ width: `${progress}%` }}
            ></div>
          </div>
          <p className="portfolio-loading-progress-text">{Math.round(progress)}%</p>
        </div>
      );
    }
    
    switch (currentStep) {
      case 1:
        return (
          <TemplateSelection 
            selectedTemplate={formData.template} 
            onSelect={(template) => setFormData({ ...formData, template })}
          />
        );
      case 2:
        return (
          <ColorSchemeSelection 
            selectedColorScheme={formData.colorScheme} 
            onSelect={(colorScheme) => setFormData({ ...formData, colorScheme })}
          />
        );
      case 3:
        return (
          <FeaturesSelection 
            features={formData.features} 
            onChange={(features) => setFormData({ ...formData, features })}
          />
        );
      case 4:
        return (
          <ResumeInput 
            resumeText={formData.resumeText} 
            onChange={(resumeText) => setFormData({ ...formData, resumeText })}
          />
        );
      default:
        return null;
    }
  };
  
  const getStepCompletionStatus = (step) => {
    if (currentStep > step) {
      return 'completed';
    } else if (currentStep === step) {
      return 'active';
    } else {
      return '';
    }
  };
  
  const isNextDisabled = () => {
    switch (currentStep) {
      case 1:
        return !formData.template;
      case 2:
        return !formData.colorScheme;
      case 3:
        return Object.values(formData.features).every(feature => feature === false);
      case 4:
        return formData.resumeText.trim().length < 50;
      default:
        return false;
    }
  };
  
  return (
    <div className="portfolio-form-container">
      <div className="portfolio-form-progress">
        <div className="step-connector"></div>
        <div 
          className="step-connector-progress" 
          style={{ width: `${((currentStep - 1) / (totalSteps - 1)) * 100}%` }}
        ></div>
        
        {[...Array(totalSteps)].map((_, index) => (
          <div 
            className={`progress-step ${getStepCompletionStatus(index + 1)}`}
            key={index}
            onClick={() => handleStepClick(index + 1)}
          >
            <div className="step-number">
              {getStepCompletionStatus(index + 1) === 'completed' ? (
                <FaCheck className="step-check-icon" />
              ) : (
                index + 1
              )}
            </div>
            <div className="step-label">
              {['Template', 'Colors', 'Features', 'Content'][index]}
            </div>
          </div>
        ))}
      </div>
      
      <div className="portfolio-form-step">
        {renderStepContent()}
      </div>
      
      <div className="portfolio-form-navigation">
        {currentStep > 1 ? (
          <button className="portfolio-back-button" onClick={handleBack}>
            <FaUndoAlt className="button-icon" /> Back
          </button>
        ) : (
          <div className="navigation-placeholder"></div>
        )}
        
        <button 
          className={currentStep === totalSteps ? 'portfolio-generate-button' : 'portfolio-next-button'}
          onClick={handleNext}
          disabled={isNextDisabled()}
        >
          {currentStep === totalSteps ? (
            <>
              <FaRocket className="button-icon" /> Generate Portfolio
            </>
          ) : (
            <>
              Next <FaArrowRight className="button-icon" />
            </>
          )}
        </button>
      </div>
    </div>
  );
};

// Template Selection Step
const TemplateSelection = ({ selectedTemplate, onSelect }) => {
  const templates = [
    {
      id: 'modern',
      name: 'Modern',
      description: 'Sleek and contemporary design with clean lines and minimal aesthetics',
      previewUrl: '/images/templates/modern.jpg',
      features: ['Responsive', 'Minimalist', 'Light/Dark Mode']
    },
    {
      id: 'creative',
      name: 'Creative',
      description: 'Bold and artistic layout perfect for designers, photographers and artists',
      previewUrl: '/images/templates/creative.jpg',
      features: ['Interactive', 'Animations', 'Gallery View']
    },
    {
      id: 'corporate',
      name: 'Corporate',
      description: 'Professional look ideal for business profiles and corporate portfolios',
      previewUrl: '/images/templates/corporate.jpg',
      features: ['Business Focused', 'Print Friendly', 'Contact Form']
    },
    {
      id: 'tech',
      name: 'Tech',
      description: 'Developer-focused template with code snippets and technical features',
      previewUrl: '/images/templates/tech.jpg',
      features: ['Code Highlight', 'GitHub Integration', 'Technical Resume']
    }
  ];
  
  return (
    <>
      <div className="portfolio-form-header">
        <div className="form-header-icon">
          <FaDesktop />
        </div>
        <h2>Choose a Template</h2>
        <p className="form-header-description">
          Select a template that best represents your professional style
        </p>
      </div>
      
      <div className="portfolio-template-options">
        {templates.map(template => (
          <div 
            key={template.id}
            className={`portfolio-template-option ${selectedTemplate === template.id ? 'selected' : ''}`}
            onClick={() => onSelect(template.id)}
          >
            <div className="template-preview" style={{ backgroundColor: '#f0f0f0' }}>
              <div className={`${template.id}-preview`} style={{ height: '100%', backgroundColor: '#ddd' }}></div>
              
              {selectedTemplate === template.id && (
                <div className="template-hover-overlay">
                  <FaCheck className="template-selected-icon" />
                </div>
              )}
            </div>
            
            <div className="template-info">
              <h3>{template.name}</h3>
              <p>{template.description}</p>
              
              <div className="template-features">
                {template.features.map((feature, index) => (
                  <span key={index} className="feature-tag">{feature}</span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
      
      <div className="portfolio-form-guidance">
        <div className="guidance-icon">
          <FaLightbulb />
        </div>
        <div className="guidance-content">
          <h4>Tips for choosing the right template</h4>
          <p>
            Your template sets the tone for your entire portfolio. Consider these factors when making your choice:
          </p>
          <ul>
            <li><strong>Industry standards:</strong> Different industries have different design expectations</li>
            <li><strong>Content focus:</strong> Some templates emphasize visuals, others highlight text content</li>
            <li><strong>Your personality:</strong> Choose a design that reflects your professional style</li>
          </ul>
        </div>
      </div>
    </>
  );
};

// Color Scheme Selection Step
const ColorSchemeSelection = ({ selectedColorScheme, onSelect }) => {
  const colorSchemes = [
    {
      id: 'professional',
      name: 'Professional',
      description: 'Clean and corporate color scheme suitable for most industries',
      bestFor: 'Business, Finance, Law, Healthcare',
      colors: ['#2c3e50', '#3498db', '#ecf0f1', '#2980b9']
    },
    {
      id: 'creative',
      name: 'Vibrant',
      description: 'Bright and energetic colors that make a bold statement',
      bestFor: 'Design, Art, Marketing, Entertainment',
      colors: ['#8e44ad', '#e74c3c', '#f39c12', '#2ecc71']
    },
    {
      id: 'tech',
      name: 'Tech',
      description: 'Modern color scheme inspired by technology and startups',
      bestFor: 'Software, IT, Engineering, Startups',
      colors: ['#1a202c', '#4a5568', '#00a0ff', '#00d563']
    },
    {
      id: 'minimal',
      name: 'Minimal',
      description: 'Subdued and elegant with focus on typography and spacing',
      bestFor: 'Architecture, Photography, UX Design',
      colors: ['#333333', '#666666', '#999999', '#f5f5f5']
    }
  ];
  
  return (
    <>
      <div className="portfolio-form-header">
        <div className="form-header-icon">
          <FaPalette />
        </div>
        <h2>Select Color Scheme</h2>
        <p className="form-header-description">
          Choose a color palette that complements your personal brand
        </p>
      </div>
      
      <div className="portfolio-color-options">
        {colorSchemes.map(scheme => (
          <div 
            key={scheme.id}
            className={`portfolio-color-option ${selectedColorScheme === scheme.id ? 'selected' : ''}`}
            onClick={() => onSelect(scheme.id)}
          >
            <div className="color-preview">
              <div 
                className={`${scheme.id}-colors`} 
                style={{ 
                  display: 'flex', 
                  height: '100%' 
                }}
              >
                {scheme.colors.map((color, index) => (
                  <div 
                    key={index} 
                    className="color-swatch" 
                    style={{ backgroundColor: color }}
                  ></div>
                ))}
              </div>
              
              {selectedColorScheme === scheme.id && (
                <div className="color-overlay">
                  <FaCheck className="color-selected-icon" />
                </div>
              )}
            </div>
            
            <div className="color-info">
              <h3>{scheme.name}</h3>
              <p>{scheme.description}</p>
              
              <div className="color-best-for">
                <span>Best for: {scheme.bestFor}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
      
      <div className="portfolio-form-guidance">
        <div className="guidance-icon">
          <FaLightbulb />
        </div>
        <div className="guidance-content">
          <h4>Color psychology in professional portfolios</h4>
          <p>
            Colors evoke specific emotions and perceptions. Choose colors that align with your industry and personal brand:
          </p>
          <ul>
            <li><strong>Blue:</strong> Trustworthy, professional, secure (ideal for business, finance, tech)</li>
            <li><strong>Green:</strong> Growth, health, stability (good for healthcare, environmental fields)</li>
            <li><strong>Purple:</strong> Creative, imaginative, luxurious (suits design, arts, premium brands)</li>
            <li><strong>Black/Gray:</strong> Sophisticated, timeless, elegant (works for upscale services)</li>
          </ul>
        </div>
      </div>
    </>
  );
};

// Features Selection Step
const FeaturesSelection = ({ features, onChange }) => {
  const handleFeatureToggle = (feature) => {
    onChange({
      ...features,
      [feature]: !features[feature]
    });
  };
  
  const featureCategories = [
    {
      title: 'Core Sections',
      features: [
        {
          id: 'hasAbout',
          label: 'About Me',
          description: 'A section introducing yourself with your background and expertise',
          recommended: true
        },
        {
          id: 'hasProjects',
          label: 'Projects Showcase',
          description: 'Featured work samples with descriptions and outcomes',
          recommended: true
        },
        {
          id: 'hasSkills',
          label: 'Skills & Expertise',
          description: 'Visual representation of your technical and soft skills',
          recommended: true
        },
        {
          id: 'hasContact',
          label: 'Contact Form',
          description: 'Let visitors reach out to you directly through your portfolio',
          recommended: true
        }
      ]
    },
    {
      title: 'Additional Sections',
      features: [
        {
          id: 'hasTestimonials',
          label: 'Testimonials',
          description: 'Showcase feedback and recommendations from clients or colleagues',
          tag: 'Popular'
        },
        {
          id: 'hasTimeline',
          label: 'Experience Timeline',
          description: 'Visual representation of your career journey and milestones',
          tag: 'Popular'
        },
        {
          id: 'hasServices',
          label: 'Services',
          description: 'Highlight specific services you offer with descriptions and pricing',
          tag: 'Business'
        },
        {
          id: 'hasBlog',
          label: 'Blog Section',
          description: 'Share your insights and expertise through articles',
          tag: 'Advanced'
        }
      ]
    }
  ];
  
  return (
    <>
      <div className="portfolio-form-header">
        <div className="form-header-icon">
          <FaPuzzlePiece />
        </div>
        <h2>Select Features</h2>
        <p className="form-header-description">
          Choose which sections and features to include in your portfolio
        </p>
      </div>
      
      <div className="portfolio-features-selection">
        <div className="features-grid">
          {featureCategories.map((category, categoryIndex) => (
            <div key={categoryIndex} className="feature-category">
              <h3 className="feature-category-title">{category.title}</h3>
              
              {category.features.map(feature => (
                <div 
                  key={feature.id} 
                  className={`portfolio-feature-checkbox ${features[feature.id] ? 'selected' : ''}`}
                  onClick={() => handleFeatureToggle(feature.id)}
                >
                  <div className="checkbox-input">
                    <input 
                      type="checkbox" 
                      checked={features[feature.id]} 
                      onChange={() => {}} 
                    />
                    <div className="custom-checkbox">
                      <FaCheck className="check-icon" />
                    </div>
                  </div>
                  
                  <div className="checkbox-content">
                    <div className="checkbox-header">
                      <span className="checkbox-label">{feature.label}</span>
                      {feature.recommended && (
                        <span className="checkbox-tag">Recommended</span>
                      )}
                      {feature.tag && (
                        <span className="checkbox-tag">{feature.tag}</span>
                      )}
                    </div>
                    <p className="checkbox-description">
                      {feature.description}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
      
      <div className="portfolio-form-guidance">
        <div className="guidance-icon">
          <FaLightbulb />
        </div>
        <div className="guidance-content">
          <h4>Less is more</h4>
          <p>
            While it might be tempting to include every feature, a focused portfolio with fewer, well-developed sections often creates a stronger impression than one filled with thin content.
          </p>
          <p>
            <strong>Pro tip:</strong> Consider your audience and career goals when selecting features. A developer might prioritize projects and skills, while a consultant might focus on testimonials and services.
          </p>
        </div>
      </div>
    </>
  );
};

// Resume Input Step
const ResumeInput = ({ resumeText, onChange }) => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [validationError, setValidationError] = useState('');
  const minLength = 50;
  
  const handleTextChange = (e) => {
    const newText = e.target.value;
    onChange(newText);
    
    if (newText.trim().length < minLength) {
      setValidationError(`Please enter at least ${minLength} characters`);
    } else {
      setValidationError('');
    }
  };
  
  const analyzeResume = async () => {
    if (resumeText.trim().length < minLength) {
      return;
    }
    
    setIsAnalyzing(true);
    
    try {
      // Simulate API call for content analysis
      await sleep(1500);
      
      setAnalysis({
        contentScore: 75,
        keywordDensity: 3.2,
        readabilityScore: 68,
        sentimentScore: 'Positive',
        wordCount: resumeText.split(/\s+/).length,
        recommendation: 'Consider adding more specific details about your technical skills and project accomplishments for a stronger impact.'
      });
    } catch (error) {
      console.error("Error analyzing content:", error);
    } finally {
      setIsAnalyzing(false);
    }
  };
  
  useEffect(() => {
    const debounceTimer = setTimeout(() => {
      if (resumeText.trim().length >= minLength) {
        analyzeResume();
      }
    }, 1000);
    
    return () => clearTimeout(debounceTimer);
  }, [resumeText]);
  
  return (
    <>
      <div className="portfolio-form-header">
        <div className="form-header-icon">
          <FaUserAlt />
        </div>
        <h2>Add Your Content</h2>
        <p className="form-header-description">
          Paste your resume or professional summary to generate personalized content
        </p>
      </div>
      
      <div className="portfolio-resume-section">
        <div className="resume-input-area">
          <div className="resume-textarea-container">
            <textarea
              className={`portfolio-resume-textarea ${validationError ? 'invalid' : ''}`}
              value={resumeText}
              onChange={handleTextChange}
              placeholder="Paste your resume, CV, or professional summary here... We'll use this to generate content for your portfolio."
            ></textarea>
            
            <div className="resume-char-counter">
              {resumeText.length} / 1000
            </div>
          </div>
          
          {validationError && (
            <div className="resume-validation-error">
              <FaExclamationCircle className="error-icon" />
              {validationError}
            </div>
          )}
          
          {isAnalyzing && (
            <div className="resume-analyzing">
              <div className="analyzing-spinner"></div>
              Analyzing content...
            </div>
          )}
          
          {analysis && (
            <div className="resume-analysis-results">
              <h3>Content Analysis</h3>
              
              <div className="content-score">
                <div className="score-label">Overall Content Quality</div>
                <div className="score-bar-container">
                  <div 
                    className={`score-bar ${analysis.contentScore >= 70 ? 'good' : 'needs-improvement'}`}
                    style={{ width: `${analysis.contentScore}%` }}
                  ></div>
                </div>
                <div className="score-value">{analysis.contentScore}/100</div>
              </div>
              
              <div className="analysis-stats">
                <div className="analysis-stat">
                  <div className="stat-label">Word Count</div>
                  <div className="stat-value">{analysis.wordCount}</div>
                  <span className={`stat-tag ${analysis.wordCount > 200 ? 'good' : 'poor'}`}>
                    {analysis.wordCount > 200 ? 'Good' : 'Too Short'}
                  </span>
                </div>
                
                <div className="analysis-stat">
                  <div className="stat-label">Readability</div>
                  <div className="stat-value">{analysis.readabilityScore}</div>
                  <span className={`stat-tag ${analysis.readabilityScore > 60 ? 'good' : 'poor'}`}>
                    {analysis.readabilityScore > 60 ? 'Easy' : 'Complex'}
                  </span>
                </div>
                
                <div className="analysis-stat">
                  <div className="stat-label">Sentiment</div>
                  <div className="stat-value">{analysis.sentimentScore}</div>
                  <span className="stat-tag good">Professional</span>
                </div>
              </div>
              
              <div className="analysis-recommendation">
                <FaInfoCircle className="recommendation-icon" />
                <p>{analysis.recommendation}</p>
              </div>
            </div>
          )}
        </div>
        
        <div className="resume-tips-container">
          <div className="resume-tips">
            <h4>Tips for Effective Content</h4>
            <ul className="tips-list">
              <li><strong>Be concise</strong> — Focus on your most relevant experiences and skills</li>
              <li><strong>Use action verbs</strong> — "Developed," "Led," "Achieved" instead of passive language</li>
              <li><strong>Include metrics</strong> — Quantify achievements when possible (e.g., "Increased sales by 25%")</li>
              <li><strong>Highlight tech skills</strong> — Be specific about languages, tools, and frameworks you know</li>
              <li><strong>Show personality</strong> — Brief personal touches make your portfolio memorable</li>
            </ul>
          </div>
          
          <div className="example-snippet">
            <h4>Example Snippet</h4>
            <div className="example-content">
              <p>
                I'm a <strong>full-stack developer</strong> with 5+ years of experience specializing in JavaScript frameworks. I've led the development of 3 enterprise-level React applications, reducing load times by 40% and increasing user engagement by 25%.
              </p>
              <p>
                My expertise includes React, Node.js, TypeScript, and AWS cloud services. I'm passionate about creating intuitive user experiences through clean, efficient code.
              </p>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

// ========================================================================
// Portfolio List Component
// ========================================================================

// Portfolio List Component - Displays all portfolios
const PortfolioList = ({ onSelect, onCreateNew }) => {
  const [portfolios, setPortfolios] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeFilter, setActiveFilter] = useState('all');
  const [sortBy, setSortBy] = useState('newest');
  const [searchFocused, setSearchFocused] = useState(false);
  
  useEffect(() => {
    const fetchPortfolios = async () => {
      setLoading(true);
      
      try {
        const response = await portfolioService.getPortfolios();
        
        if (response.success) {
          setPortfolios(response.data);
        } else {
          toast.error("Failed to fetch portfolios");
        }
      } catch (error) {
        console.error("Error fetching portfolios:", error);
        toast.error("An unexpected error occurred");
      } finally {
        setLoading(false);
      }
    };
    
    fetchPortfolios();
  }, []);
  
  const filteredPortfolios = portfolios
    .filter(portfolio => {
      // Search filter
      if (searchTerm && !portfolio.title.toLowerCase().includes(searchTerm.toLowerCase())) {
        return false;
      }
      
      // Status filter
      if (activeFilter === 'deployed' && !portfolio.isDeployed) {
        return false;
      }
      
      if (activeFilter === 'draft' && portfolio.isDeployed) {
        return false;
      }
      
      return true;
    })
    .sort((a, b) => {
      // Sort by selected option
      if (sortBy === 'newest') {
        return new Date(b.createdAt) - new Date(a.createdAt);
      }
      
      if (sortBy === 'oldest') {
        return new Date(a.createdAt) - new Date(b.createdAt);
      }
      
      return 0;
    });
  
  if (loading) {
    return (
      <div className="portfolio-loading-container">
        <FaSpinner size={40} className="spin" />
        <h2>Loading your portfolios...</h2>
        <p>This will only take a moment</p>
      </div>
    );
  }
  
  if (portfolios.length === 0) {
    return (
      <div className="portfolio-empty-state">
        <FaBriefcase className="portfolio-empty-icon" />
        <h3>You haven't created any portfolios yet</h3>
        <p>
          Create your first professional portfolio website in just a few minutes.
          Choose from beautiful templates and customize to match your style.
        </p>
        <div className="portfolio-empty-actions">
          <button className="portfolio-create-first-button" onClick={onCreateNew}>
            <FaCode className="button-icon" /> Create Your First Portfolio
          </button>
        </div>
      </div>
    );
  }
  
  return (
    <div className="portfolio-list-container">
      <div className="portfolio-list-header">
        <h2>My Portfolios</h2>
        
        <div className="portfolio-list-actions">
          <div className={`portfolio-search-container ${searchFocused ? 'focused' : ''}`}>
            <FaSearchPlus className="search-icon" />
            <input 
              type="text" 
              className="portfolio-search-input" 
              placeholder="Search portfolios..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onFocus={() => setSearchFocused(true)}
              onBlur={() => setSearchFocused(false)}
            />
            {searchTerm && (
              <button 
                className="search-clear-button"
                onClick={() => setSearchTerm('')}
              >
                &times;
              </button>
            )}
          </div>
        </div>
      </div>
      
      <div className="portfolio-controls">
        <div className="portfolio-filter-controls">
          <span className="filter-label">
            <FaFilter className="filter-icon" /> Filter:
          </span>
          <div className="filter-options">
            <button 
              className={`filter-option ${activeFilter === 'all' ? 'active' : ''}`}
              onClick={() => setActiveFilter('all')}
            >
              All
            </button>
            <button 
              className={`filter-option ${activeFilter === 'deployed' ? 'active' : ''}`}
              onClick={() => setActiveFilter('deployed')}
            >
              Deployed
            </button>
            <button 
              className={`filter-option ${activeFilter === 'draft' ? 'active' : ''}`}
              onClick={() => setActiveFilter('draft')}
            >
              Draft
            </button>
          </div>
        </div>
        
        <div className="portfolio-sort-controls">
          <span className="sort-label">
            <FaSort className="sort-icon" /> Sort:
          </span>
          <div className="sort-options">
            <button 
              className={`sort-option ${sortBy === 'newest' ? 'active' : ''}`}
              onClick={() => setSortBy('newest')}
            >
              Newest First
            </button>
            <button 
              className={`sort-option ${sortBy === 'oldest' ? 'active' : ''}`}
              onClick={() => setSortBy('oldest')}
            >
              Oldest First
            </button>
          </div>
        </div>
      </div>
      
      <div className="portfolio-list-stats">
        <div className="portfolio-stat">
          <div className="portfolio-stat-value">{portfolios.length}</div>
          <div className="portfolio-stat-label">Total Portfolios</div>
        </div>
        <div className="portfolio-stat">
          <div className="portfolio-stat-value">
            {portfolios.filter(p => p.isDeployed).length}
          </div>
          <div className="portfolio-stat-label">Deployed Sites</div>
        </div>
        <div className="portfolio-stat">
          <div className="portfolio-stat-value">
            {portfolios.filter(p => !p.isDeployed).length}
          </div>
          <div className="portfolio-stat-label">Draft Portfolios</div>
        </div>
      </div>
      
      {filteredPortfolios.length > 0 ? (
        <div className="portfolio-grid">
          {filteredPortfolios.map(portfolio => (
            <div key={portfolio.id} className="portfolio-item-card">
              <div className="portfolio-card-header">
                <div className="portfolio-card-title-row">
                  <h3 className="portfolio-card-title">{portfolio.title || `Portfolio ${portfolio.id.split('-')[1]}`}</h3>
                  <div className={`portfolio-status-badge ${portfolio.isDeployed ? 'deployed' : 'generated'}`}>
                    <span className="status-icon">
                      {portfolio.isDeployed ? <FaGlobe /> : <FaCog />}
                    </span>
                    {portfolio.isDeployed ? 'Live' : 'Generated'}
                  </div>
                </div>
                <div className="portfolio-card-meta">
                  <div className="portfolio-creation-time">
                    <FaClock /> 
                    {new Date(portfolio.createdAt).toLocaleDateString('en-US', {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric'
                    })}
                  </div>
                </div>
              </div>
              
              <div className="portfolio-card-details">
                <div className="portfolio-detail-item">
                  <FaDesktop className="detail-icon" />
                  <span className="detail-label">Template:</span>
                  <span className="detail-value">{portfolio.template}</span>
                </div>
                
                <div className="portfolio-detail-item">
                  <FaPalette className="detail-icon" />
                  <span className="detail-label">Colors:</span>
                  <span className="detail-value">{portfolio.colorScheme}</span>
                </div>
                
                <div className="portfolio-detail-item">
                  <FaPuzzlePiece className="detail-icon" />
                  <span className="detail-label">Skills:</span>
                  <span className="detail-value">
                    {portfolio.skills.join(', ')}
                  </span>
                </div>
                
                {portfolio.isDeployed && (
                  <div className="portfolio-url-item">
                    <div className="portfolio-detail-item">
                      <FaLink className="detail-icon" />
                      <span className="detail-label">URL:</span>
                      <a 
                        href={portfolio.deployedUrl} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="portfolio-url-link"
                      >
                        {portfolio.deployedUrl.replace('https://', '')}
                      </a>
                    </div>
                  </div>
                )}
              </div>
              
              <div className="portfolio-card-actions">
                <button 
                  className="portfolio-select-button"
                  onClick={() => onSelect(portfolio)}
                >
                  <FaEye className="select-icon" /> View
                </button>
                {!portfolio.isDeployed && (
                  <button 
                    className="portfolio-view-button"
                    onClick={() => onSelect(portfolio)}
                  >
                    <FaRocket className="view-icon" /> Deploy
                  </button>
                )}
                {portfolio.isDeployed && (
                  <a 
                    href={portfolio.deployedUrl} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="portfolio-view-button"
                  >
                    <FaExternalLinkAlt className="view-icon" /> Visit Site
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="portfolio-no-results">
          <FaSearchPlus className="no-results-icon" />
          <p>No portfolios match your search</p>
          <button 
            className="clear-search-button"
            onClick={() => {
              setSearchTerm('');
              setActiveFilter('all');
            }}
          >
            <FaUndoAlt className="button-icon" /> Clear Filters
          </button>
        </div>
      )}
      
      <div className="portfolio-list-explanation">
        <h3>About Portfolio Builder</h3>
        <p>
          Portfolio Builder makes it easy to create, manage, and deploy professional portfolio websites without any coding knowledge. Choose from beautiful templates, customize colors and features, add your content, and deploy with a single click.
        </p>
        
        <ul className="portfolio-tips">
          <li>
            <strong>Create multiple portfolios</strong> for different purposes or job applications
          </li>
          <li>
            <strong>Deploy to a custom domain</strong> to establish your professional online presence
          </li>
          <li>
            <strong>Update your portfolio</strong> with new projects and skills as you grow
          </li>
        </ul>
      </div>
    </div>
  );
};

// ========================================================================
// Portfolio Preview Component
// ========================================================================

// Portfolio Preview Component - Shows code preview and live preview
const PortfolioPreview = ({ portfolio, onBack }) => {
  const [activeTab, setActiveTab] = useState('code');
  const [activeDevice, setActiveDevice] = useState('desktop');
  const [previewLoading, setPreviewLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileContent, setFileContent] = useState(null);
  const [files, setFiles] = useState({});
  const [expandedFolders, setExpandedFolders] = useState(['src', 'styles']);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    const fetchFiles = async () => {
      setLoading(true);
      
      try {
        const response = await portfolioService.getPortfolioFiles(portfolio.id);
        
        if (response.success) {
          setFiles(response.data.files);
          
          // Set the first file as selected by default
          const firstFileName = Object.keys(response.data.files)[0];
          setSelectedFile(firstFileName);
          setFileContent(response.data.files[firstFileName]);
        } else {
          toast.error("Failed to fetch portfolio files");
        }
      } catch (error) {
        console.error("Error fetching portfolio files:", error);
        toast.error("An unexpected error occurred");
      } finally {
        setLoading(false);
      }
    };
    
    if (portfolio) {
      fetchFiles();
    }
  }, [portfolio]);
  
  const handleToggleFolder = (folder) => {
    if (expandedFolders.includes(folder)) {
      setExpandedFolders(expandedFolders.filter(f => f !== folder));
    } else {
      setExpandedFolders([...expandedFolders, folder]);
    }
  };
  
  const handleFileSelect = (fileName) => {
    setSelectedFile(fileName);
    setFileContent(files[fileName]);
  };
  
  const getFileLanguage = (fileName) => {
    if (fileName.endsWith('.js')) return 'javascript';
    if (fileName.endsWith('.css')) return 'css';
    if (fileName.endsWith('.html')) return 'html';
    if (fileName.endsWith('.json')) return 'json';
    if (fileName.endsWith('.md')) return 'markdown';
    return 'text';
  };
  
  const getFileIcon = (fileName) => {
    if (fileName.endsWith('.js')) return <FaFileCode className="js-file-icon" />;
    if (fileName.endsWith('.css')) return <FaFileCode className="css-file-icon" />;
    if (fileName.endsWith('.html')) return <FaFileCode className="html-file-icon" />;
    if (fileName.endsWith('.json')) return <FaFileCode className="json-file-icon" />;
    if (fileName.endsWith('.md')) return <FaFileCode className="md-file-icon" />;
    return <FaFileCode />;
  };
  
  const handleRefreshPreview = () => {
    setPreviewLoading(true);
    
    setTimeout(() => {
      setPreviewLoading(false);
    }, 1500);
  };
  
  return (
    <div className="portfolio-preview-container">
      <div className="portfolio-preview-header">
        <h2>Portfolio Preview</h2>
        
        <div className="portfolio-preview-tabs">
          <button 
            className={`portfolio-preview-tab ${activeTab === 'code' ? 'active' : ''}`}
            onClick={() => setActiveTab('code')}
          >
            <FaCode /> Code
          </button>
          <button 
            className={`portfolio-preview-tab ${activeTab === 'live' ? 'active' : ''}`}
            onClick={() => setActiveTab('live')}
          >
            <FaDesktop /> Live Preview
          </button>
        </div>
      </div>
      
      {activeTab === 'code' ? (
        <div className="portfolio-code-preview">
          <div className="portfolio-file-explorer">
            <div className="portfolio-file-explorer-header">
              <h3>Files</h3>
              <div className="portfolio-file-search">
                <input 
                  type="text" 
                  className="portfolio-file-search-input" 
                  placeholder="Search files..." 
                />
              </div>
            </div>
            
            <div className="portfolio-file-tree">
              {loading ? (
                <div className="loading-files">Loading files...</div>
              ) : Object.keys(files).length > 0 ? (
                <div className="portfolio-file-tree-node root-node">
                  {Object.keys(files).map(fileName => (
                    <div key={fileName} className="portfolio-file-tree-node">
                      <div 
                        className={`portfolio-file-item ${selectedFile === fileName ? 'active' : ''}`}
                        onClick={() => handleFileSelect(fileName)}
                      >
                        {getFileIcon(fileName)}
                        <span className="file-name">{fileName}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="no-files-message">No files found</div>
              )}
            </div>
          </div>
          
          <div className="portfolio-code-editor-container">
            {selectedFile ? (
              <>
                <div className="portfolio-editor-header">
                  <div className="portfolio-active-file">
                    {getFileIcon(selectedFile)}
                    <span className="file-name">{selectedFile}</span>
                  </div>
                  
                  <div className="portfolio-editor-actions">
                    <button className="portfolio-editor-action-btn">
                      <FaRegClone /> Copy
                    </button>
                    <button className="portfolio-editor-action-btn">
                      <FaFileDownload /> Download
                    </button>
                  </div>
                </div>
                
                <div className="portfolio-code-editor-wrapper">
                  <SyntaxHighlighter 
                    language={getFileLanguage(selectedFile)} 
                    style={vscDarkPlus}
                    customStyle={{ margin: 0, padding: '20px', height: '100%', fontSize: '14px' }}
                    showLineNumbers={true}
                  >
                    {fileContent}
                  </SyntaxHighlighter>
                </div>
              </>
            ) : (
              <div className="portfolio-no-file-selected">
                <FaCode className="no-file-icon" />
                <h3>No file selected</h3>
                <p>Select a file from the explorer to view its content</p>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="portfolio-live-preview-container">
          <div className="portfolio-preview-toolbar">
            <div className="portfolio-preview-device-selector">
              <button 
                className={`portfolio-device-button ${activeDevice === 'desktop' ? 'active' : ''}`}
                onClick={() => setActiveDevice('desktop')}
              >
                <FaDesktop className="device-icon" /> Desktop
              </button>
              <button 
                className={`portfolio-device-button ${activeDevice === 'mobile' ? 'active' : ''}`}
                onClick={() => setActiveDevice('mobile')}
              >
                <FaMobileAlt className="device-icon" /> Mobile
              </button>
            </div>
            
            <button 
              className="portfolio-preview-refresh-btn"
              onClick={handleRefreshPreview}
              disabled={previewLoading}
            >
              {previewLoading ? (
                <>
                  <div className="button-spinner"></div> Refreshing...
                </>
              ) : (
                <>
                  <FaSyncAlt className="refresh-icon" /> Refresh
                </>
              )}
            </button>
          </div>
          
          <div className={`portfolio-preview-frame-container ${activeDevice === 'mobile' ? 'mobile-container' : ''}`}>
            {previewLoading ? (
              <div className="preview-loading">
                <div className="preview-loading-spinner"></div>
                <p>Loading preview...</p>
              </div>
            ) : (
              <iframe 
                src="about:blank" 
                title="Portfolio Preview"
                className="portfolio-preview-frame"
                style={{ 
                  width: activeDevice === 'mobile' ? '375px' : '100%',
                  height: '100%'
                }}
              />
            )}
          </div>
        </div>
      )}
      
      <div className="portfolio-form-navigation" style={{ marginTop: '30px' }}>
        <button className="portfolio-back-button" onClick={onBack}>
          <FaUndoAlt className="button-icon" /> Back to Portfolios
        </button>
        
        {!portfolio.isDeployed && (
          <button className="portfolio-generate-button">
            <FaRocket className="button-icon" /> Deploy Portfolio
          </button>
        )}
      </div>
    </div>
  );
};

// ========================================================================
// Portfolio Deployment Component
// ========================================================================

// Portfolio Deployment Component - Handles deployment process and success
const PortfolioDeployment = ({ portfolio, onBack, onComplete }) => {
  const [deploymentStatus, setDeploymentStatus] = useState('processing'); // 'processing', 'success', 'error'
  const [deploymentProgress, setDeploymentProgress] = useState(0);
  const [deployedUrl, setDeployedUrl] = useState('');
  const [activeStage, setActiveStage] = useState(1);
  const [completedStages, setCompletedStages] = useState([]);
  const [copied, setCopied] = useState(false);
  
  useEffect(() => {
    const simulateDeployment = async () => {
      // Stage 1: Preparing files
      setActiveStage(1);
      await sleep(2000);
      setCompletedStages(prev => [...prev, 1]);
      setDeploymentProgress(25);
      
      // Stage 2: Building optimized version
      setActiveStage(2);
      await sleep(3000);
      setCompletedStages(prev => [...prev, 2]);
      setDeploymentProgress(50);
      
      // Stage 3: Uploading to servers
      setActiveStage(3);
      await sleep(2500);
      setCompletedStages(prev => [...prev, 3]);
      setDeploymentProgress(75);
      
      // Stage 4: Configuring domain
      setActiveStage(4);
      await sleep(2000);
      setCompletedStages(prev => [...prev, 4]);
      setDeploymentProgress(100);
      
      // Complete deployment
      const result = await portfolioService.deployPortfolio(portfolio.id);
      
      if (result.success) {
        setDeployedUrl(result.data.deployedUrl);
        setDeploymentStatus('success');
      } else {
        setDeploymentStatus('error');
      }
    };
    
    simulateDeployment();
  }, [portfolio.id]);
  
  const deploymentStages = [
    {
      id: 1,
      title: 'Preparing Files',
      description: 'Optimizing your content and assets for deployment'
    },
    {
      id: 2,
      title: 'Building Portfolio',
      description: 'Generating optimized production version of your portfolio'
    },
    {
      id: 3,
      title: 'Uploading to Servers',
      description: 'Transferring files to our high-performance hosting platform'
    },
    {
      id: 4,
      title: 'Configuring Domain',
      description: 'Setting up domain and SSL certificates'
    }
  ];
  
  const handleCopyUrl = () => {
    navigator.clipboard.writeText(deployedUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  
  if (deploymentStatus === 'processing') {
    return (
      <div className="portfolio-deployment-container">
        <div className="portfolio-deployment-header">
          <div className="deployment-title-icon">
            <FaRocket />
          </div>
          <h2>Deploying Your Portfolio</h2>
          <p className="portfolio-deployment-subtitle">
            We're setting everything up for you
          </p>
        </div>
        
        <div className="portfolio-deployment-processing">
          <div className="deployment-processing-animation">
            <div className="processing-circle"></div>
          </div>
          
          <div className="deployment-processing-text">
            <h3>Deployment in Progress</h3>
            <p>
              We're deploying your portfolio to our high-performance hosting platform.
              This usually takes about 1-2 minutes to complete.
            </p>
          </div>
          
          <div className="deployment-stages">
            {deploymentStages.map(stage => (
              <div 
                key={stage.id} 
                className={`deployment-stage ${activeStage === stage.id ? 'active' : ''} ${completedStages.includes(stage.id) ? 'completed' : ''}`}
              >
                <div className="stage-indicator">
                  {completedStages.includes(stage.id) ? (
                    <FaCheck className="stage-check-icon" />
                  ) : (
                    stage.id
                  )}
                </div>
                <div className="stage-content">
                  <h4 className="stage-title">{stage.title}</h4>
                  <p className="stage-description">{stage.description}</p>
                </div>
              </div>
            ))}
          </div>
          
          <div className="deployment-time-estimate">
            <FaClock className="deployment-time-icon" />
            Estimated time remaining: {Math.max(0, 2 - Math.ceil(deploymentProgress / 50))} minutes
          </div>
          
          <button className="deployment-cancel-button">
            <FaUndoAlt /> Cancel Deployment
          </button>
        </div>
      </div>
    );
  }
  
  if (deploymentStatus === 'success') {
    return (
      <div className="portfolio-deployment-container">
        <div className="portfolio-deployment-header">
          <div className="deployment-title-icon">
            <FaRocket />
          </div>
          <h2>Deployment Successful</h2>
          <p className="portfolio-deployment-subtitle">
            Your portfolio is now live and ready to share
          </p>
        </div>
        
        <div className="portfolio-deployment-success">
          <div className="deployment-success-header">
            <FaCheckCircle className="deployment-success-icon" />
            <h3>Your Portfolio is Live!</h3>
          </div>
          
          <div className="deployment-success-content">
            <p>
              Congratulations! Your portfolio has been successfully deployed and is now accessible worldwide.
              Your site is optimized for speed and performance, with SSL encryption for security.
            </p>
            
            <div className="deployment-url-container">
              <div className="deployment-url-header">
                <FaLink className="url-icon" />
                <h4>Your Portfolio URL</h4>
              </div>
              
              <div className="deployment-url-display">
                <a 
                  href={deployedUrl} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="portfolio-url-link"
                >
                  {deployedUrl}
                </a>
                
                <button 
                  className={`copy-url-button ${copied ? 'copied' : ''}`}
                  onClick={handleCopyUrl}
                >
                  {copied ? (
                    <>
                      <FaCheck /> Copied!
                    </>
                  ) : (
                    <>
                      <FaCopy /> Copy URL
                    </>
                  )}
                </button>
              </div>
            </div>
            
            <div className="deployment-success-actions">
              <a 
                href={deployedUrl} 
                target="_blank" 
                rel="noopener noreferrer"
                className="portfolio-view-live-button"
              >
                <FaExternalLinkAlt /> View Live Site
              </a>
              
              <button className="portfolio-customization-button" onClick={onComplete}>
                <FaUndoAlt /> Back to Portfolios
              </button>
            </div>
          </div>
        </div>
        
        <div className="deployment-share-options">
          <div className="share-options-header">
            <h3>Share Your Portfolio</h3>
            <p>Let the world know about your new professional portfolio</p>
          </div>
          
          <div className="share-options-grid">
            <div className="share-option-card">
              <FaTwitter className="share-platform-icon" />
              <h4>Share on Twitter</h4>
              <p>
                Share your portfolio with your professional network on Twitter/X
              </p>
              <button className="share-platform-button">
                <FaTwitter /> Share on Twitter
              </button>
            </div>
            
            <div className="share-option-card">
              <FaLinkedin className="share-platform-icon" />
              <h4>Share on LinkedIn</h4>
              <p>
                Add your portfolio to your LinkedIn profile for better visibility
              </p>
              <button className="share-platform-button">
                <FaLinkedin /> Share on LinkedIn
              </button>
            </div>
            
            <div className="share-option-card">
              <FaEnvelope className="share-platform-icon" />
              <h4>Share via Email</h4>
              <p>
                Send your portfolio directly to recruiters or potential clients
              </p>
              <button className="share-platform-button">
                <FaEnvelope /> Compose Email
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }
  
  // Error state
  return (
    <div className="portfolio-deployment-container">
      <div className="portfolio-deployment-header">
        <div className="deployment-title-icon">
          <FaExclamationCircle />
        </div>
        <h2>Deployment Failed</h2>
        <p className="portfolio-deployment-subtitle">
          We encountered an issue while deploying your portfolio
        </p>
      </div>
      
      {/* Error content would go here */}
      
      <div className="portfolio-form-navigation">
        <button className="portfolio-back-button" onClick={onBack}>
          <FaUndoAlt className="button-icon" /> Back to Preview
        </button>
        
        <button className="portfolio-next-button">
          <FaSyncAlt className="button-icon" /> Try Again
        </button>
      </div>
    </div>
  );
};

export default PortfolioPage;
