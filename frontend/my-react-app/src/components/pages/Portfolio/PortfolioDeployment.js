// Enhanced PortfolioDeployment Component
import React, { useState, useEffect } from 'react';
import { FaFighterJet, FaGithub, FaLink, FaCheckCircle, FaInfoCircle, FaClipboard, FaCode, FaQuestion, FaChevronDown, FaExternalLinkAlt } from 'react-icons/fa';
import './portfolio.css';

const PortfolioDeployment = ({ portfolio, userId, onDeploymentStart, onDeploymentComplete, onError }) => {
  const [githubToken, setGithubToken] = useState('');
  const [vercelToken, setVercelToken] = useState('');
  const [showTokenFields, setShowTokenFields] = useState(false);
  const [deploymentInProgress, setDeploymentInProgress] = useState(false);
  const [deploymentStage, setDeploymentStage] = useState(0);
  const [copied, setCopied] = useState(false);
  const [expandedFaq, setExpandedFaq] = useState(null);
  const [hasInteractedWithForm, setHasInteractedWithForm] = useState(false);

  // Frequently Asked Questions
  const faqItems = [
    {
      question: "Will I be able to update my portfolio later?",
      answer: "Yes, any changes you make to your portfolio code will be automatically deployed to your live site. You can edit your portfolio at any time through the Code Editor tab."
    },
    {
      question: "Is the hosting really free?",
      answer: "Yes, Vercel provides free hosting for personal projects. You can even connect a custom domain if you wish. The free tier includes SSL certificates, global CDN, and continuous deployment."
    },
    {
      question: "Are my tokens stored securely?",
      answer: "Your tokens are used only for the deployment process and are not stored on our servers. For added security, we recommend creating tokens with minimal permissions and revoking them after your portfolio is deployed."
    },
    {
      question: "How do I set up a custom domain?",
      answer: "After deployment, you can set up a custom domain through the Vercel dashboard. Go to your project settings, navigate to the Domains section, and follow the instructions to add and configure your domain."
    },
    {
      question: "What happens if I make changes to my portfolio?",
      answer: "Any changes you make to your portfolio in the Code Editor will be automatically committed to your GitHub repository. Vercel will detect these changes and automatically redeploy your portfolio."
    }
  ];

  // Animation for deployment stages
  useEffect(() => {
    if (deploymentInProgress) {
      console.log("Deployment in progress, starting stage animation");
      const stageInterval = setInterval(() => {
        setDeploymentStage(prevStage => {
          if (prevStage >= 3) {
            clearInterval(stageInterval);
            return 3;
          }
          return prevStage + 1;
        });
      }, 4000);
      
      return () => clearInterval(stageInterval);
    }
  }, [deploymentInProgress]);

  // Validate form fields
  const validateForm = () => {
    if (!githubToken || !vercelToken) {
      return false;
    }
    
    if (githubToken.length < 10 || vercelToken.length < 10) {
      return false;
    }
    
    return true;
  };

  const handleInputChange = (e, field) => {
    setHasInteractedWithForm(true);
    
    if (field === 'github') {
      setGithubToken(e.target.value);
    } else if (field === 'vercel') {
      setVercelToken(e.target.value);
    }
  };

  const handleDeploy = async (e) => {
    e.preventDefault();
    
    // Validate inputs
    if (showTokenFields && (!githubToken || !vercelToken)) {
      onError('Please provide both GitHub and Vercel tokens');
      return;
    }
    
    try {
      console.log("Starting deployment process");
      onDeploymentStart();
      setDeploymentInProgress(true);
      setDeploymentStage(0);
      
      const response = await fetch('/api/portfolio/deploy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-Id': userId
        },
        body: JSON.stringify({
          portfolio_id: portfolio._id,
          github_token: githubToken,
          vercel_token: vercelToken
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Deployment failed');
      }
      
      const data = await response.json();
      console.log("Deployment successful:", data);
      
      setDeploymentInProgress(false);
      onDeploymentComplete(data);
      
    } catch (err) {
      console.error('Error deploying portfolio:', err);
      setDeploymentInProgress(false);
      onError(err.message || 'Deployment failed. Please try again.');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const toggleFaq = (index) => {
    if (expandedFaq === index) {
      setExpandedFaq(null);
    } else {
      setExpandedFaq(index);
    }
  };

  const isDeployed = portfolio?.deployment?.deployed;
  const deploymentUrl = portfolio?.deployment?.url;

  return (
      <div className="portfolio-deployment-header">
        <div className="deployment-header-content">
          <FaFighterJet className="deployment-title-icon" />
          <h2>Deploy Your Portfolio</h2>
          <p className="portfolio-deployment-subtitle">Make your portfolio accessible online with just a few clicks</p>
        </div>
        <div className="deployment-header-graphic">
          <div className="deployment-illustration">
            <div className="deployment-rocket">
              <FaFighterJet />
            </div>
            <div className="deployment-planet"></div>
            <div className="deployment-stars">
              <div className="star s1"></div>
              <div className="star s2"></div>
              <div className="star s3"></div>
            </div>
          </div>
        </div>

      
      {isDeployed ? (
        <div className="portfolio-deployment-success">
          <div className="deployment-success-header">
            <FaCheckCircle className="deployment-success-icon" />
            <h3>Your Portfolio is Live!</h3>
          </div>
          
          <div className="deployment-success-content">
            <p>Your portfolio has been successfully deployed and is now accessible online.</p>
            
            <div className="deployment-url-container">
              <div className="deployment-url-header">
                <FaLink className="url-icon" />
                <h4>Portfolio URL</h4>
              </div>
              
              <div className="deployment-url-display">
                <a 
                  href={deploymentUrl} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="portfolio-url-link"
                >
                  {deploymentUrl}
                </a>
                
                <button 
                  className="copy-url-button"
                  onClick={() => copyToClipboard(deploymentUrl)}
                  title="Copy URL to clipboard"
                >
                  <FaClipboard />
                  <span className="copy-text">{copied ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>
            
            <div className="deployment-actions">
              <a 
                href={deploymentUrl} 
                target="_blank" 
                rel="noopener noreferrer"
                className="view-portfolio-button"
              >
                <FaExternalLinkAlt className="view-icon" />
                <span>View Portfolio</span>
              </a>
              
              <button className="share-portfolio-button">
                <FaLink className="share-icon" />
                <span>Share Portfolio</span>
              </button>
            </div>
            
            <div className="deployment-note">
              <FaInfoCircle className="note-icon" />
              <p>
                Your portfolio is automatically updated when you make changes to your code. 
                If the link doesn't work immediately, please try again in a few minutes as 
                deployment may take some time to propagate.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="portfolio-deployment-options">
          {deploymentInProgress ? (
            <div className="portfolio-deployment-progress">
              <div className="deployment-progress-animation">
                <div className="deployment-rocket-container">
                  <div className="deployment-rocket">
                    <FaFighterJet />
                  </div>
                  <div className="deployment-trail"></div>
                </div>
              </div>
              
              <h3 className="deployment-progress-title">Deployment in Progress</h3>
              
              <div className="deployment-stages">
                <div className={`deployment-stage ${deploymentStage >= 0 ? 'active' : ''} ${deploymentStage > 0 ? 'completed' : ''}`}>
                  <div className="stage-indicator">
                    <div className="stage-number">1</div>
                    <div className="stage-line"></div>
                  </div>
                  <div className="stage-content">
                    <h4>Preparing Files</h4>
                    <p>Optimizing your portfolio code for deployment</p>
                  </div>
                </div>
                
                <div className={`deployment-stage ${deploymentStage >= 1 ? 'active' : ''} ${deploymentStage > 1 ? 'completed' : ''}`}>
                  <div className="stage-indicator">
                    <div className="stage-number">2</div>
                    <div className="stage-line"></div>
                  </div>
                  <div className="stage-content">
                    <h4>Creating Repository</h4>
                    <p>Setting up a GitHub repository with your portfolio</p>
                  </div>
                </div>
                
                <div className={`deployment-stage ${deploymentStage >= 2 ? 'active' : ''} ${deploymentStage > 2 ? 'completed' : ''}`}>
                  <div className="stage-indicator">
                    <div className="stage-number">3</div>
                    <div className="stage-line"></div>
                  </div>
                  <div className="stage-content">
                    <h4>Configuring Hosting</h4>
                    <p>Setting up deployment on Vercel</p>
                  </div>
                </div>
                
                <div className={`deployment-stage ${deploymentStage >= 3 ? 'active' : ''} ${deploymentStage > 3 ? 'completed' : ''}`}>
                  <div className="stage-indicator">
                    <div className="stage-number">4</div>
                  </div>
                  <div className="stage-content">
                    <h4>Going Live</h4>
                    <p>Making your portfolio accessible online</p>
                  </div>
                </div>
              </div>
              
              <p className="deployment-wait-message">This process may take a few minutes. Please do not close this window.</p>
            </div>
          ) : (
            <>
              <div className="portfolio-deployment-section">
                <div className="deployment-section-header">
                  <FaCode className="section-icon" />
                  <h3>Get Your Portfolio Online</h3>
                </div>
                
                <div className="deployment-section-content">
                  <p>
                    Deploy your portfolio to make it accessible on the web. Your portfolio will be 
                    hosted on Vercel, a leading platform for frontend applications, which provides 
                    free hosting with custom domains, SSL certificates, and global CDN.
                  </p>
                  
                  {!showTokenFields ? (
                    <div className="deployment-starter">
                      <div className="deployment-benefits">
                        <h4>Deployment Benefits:</h4>
                        <ul className="benefits-list">
                          <li>Free, reliable hosting with global CDN</li>
                          <li>Custom domain support with SSL included</li>
                          <li>Professional URL to share with employers</li>
                          <li>Automatic updates when you edit your portfolio</li>
                          <li>Analytics to track visitor engagement</li>
                        </ul>
                      </div>
                      
                      <button 
                        className="start-deployment-button"
                        onClick={() => setShowTokenFields(true)}
                      >
                        <FaGithub className="button-icon" />
                        <span>Start Deployment</span>
                      </button>
                    </div>
                  ) : (
<form className="portfolio-deployment-form" onSubmit={handleDeploy}>
                      <div className="form-section">
                        <div className="form-section-header">
                          <FaGithub className="form-section-icon" />
                          <h4 className="form-section-title">GitHub Configuration</h4>
                        </div>
                        
                        <p className="form-section-description">
                          Your portfolio code will be stored in a GitHub repository. This allows 
                          for version control and easy updates.
                        </p>
                        
                        <div className="deployment-visual-container">
                          <div className="deployment-visual">
                            <div className="deployment-github-icon">
                            </div>
                            <div className="deployment-visual-arrow"></div>
                            <div className="deployment-code-icon">
                            </div>
                          </div>
                        </div>
                        
                        <div className="form-group">
                          <label htmlFor="github-token">GitHub Access Token</label>
                          <div className="">
                            <FaGithub className="input-icon" />
                            <input 
                              type="password"
                              id="github-token"
                              value={githubToken}
                              onChange={(e) => handleInputChange(e, 'github')}
                              placeholder="Enter your GitHub access token"
                              className={hasInteractedWithForm && !githubToken ? 'input-error' : ''}
                            />
                          </div>
                          {hasInteractedWithForm && !githubToken && 
                            <div className="input-error-message">GitHub token is required</div>
                          }
                          <p className="token-help">
                            <a 
                              href="https://github.com/settings/tokens/new" 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="token-help-link"
                            >
                              Create a GitHub token
                            </a> with 'repo' and 'workflow' permissions.
                          </p>
                        </div>
                      </div>
                      
                      <div className="form-section">
                        <div className="form-section-header">
                          <FaFighterJet className="form-section-icon" />
                          <h4 className="form-section-title">Vercel Configuration</h4>
                        </div>
                        
                        <p className="form-section-description">
                          Vercel will build and host your portfolio, making it accessible online with a custom URL.
                        </p>
                        
                        <div className="deployment-visual-container">
                          <div className="deployment-visual">
                            <div className="deployment-code-icon">
                            </div>
                            <div className="deployment-visual-arrow"></div>
                            <div className="deployment-vercel-icon">
                            </div>
                            <div className="deployment-visual-arrow"></div>
                            <div className="deployment-globe-icon">
                            </div>
                          </div>
                        </div>
                        
                        <div className="form-group">
                          <label htmlFor="vercel-token">Vercel Access Token</label>
                          <div className="input-with-icon">
                            <span className="input-icon vercel-icon"></span>
                            <input 
                              type="password"
                              id="vercel-token"
                              value={vercelToken}
                              onChange={(e) => handleInputChange(e, 'vercel')}
                              placeholder="Enter your Vercel access token"
                              className={hasInteractedWithForm && !vercelToken ? 'input-error' : ''}
                            />
                          </div>
                          {hasInteractedWithForm && !vercelToken && 
                            <div className="input-error-message">Vercel token is required</div>
                          }
                          <p className="token-help">
                            <a 
                              href="https://vercel.com/account/tokens" 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="token-help-link"
                            >
                              Create a Vercel token
                            </a> from your account settings.
                          </p>
                        </div>
                      </div>
                      
                      <div className="form-actions">
                        <button 
                          type="button"
                          className="deployment-back-button"
                          onClick={() => setShowTokenFields(false)}
                        >
                          Back
                        </button>
                        
                        <button 
                          type="submit"
                          className="deploy-button"
                          disabled={!validateForm()}
                        >
                          <FaGithub className="button-icon" />
                          <span>Deploy Portfolio</span>
                        </button>
                      </div>
                    </form>
                  )}
                </div>
              </div>
              
              <div className="faq-container">
                <h3>
                  <FaQuestion className="faq-header-icon" />
                  Frequently Asked Questions
                </h3>
                
                <div className="faq-questions">
                  {faqItems.map((item, index) => (
                    <div key={index} className="faq-item">
                      <div 
                        className="faq-question"
                        onClick={() => toggleFaq(index)}
                      >
                        <span>{item.question}</span>
                        <FaChevronDown className={`faq-toggle ${expandedFaq === index ? 'expanded' : ''}`} />
                      </div>
                      {expandedFaq === index && (
                        <div className="faq-answer">
                          {item.answer}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default PortfolioDeployment;
