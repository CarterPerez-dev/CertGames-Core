// Enhanced PortfolioDeployment Component with GitHub OAuth
import React, { useState, useEffect } from 'react';
import { FaFighterJet, FaGithub, FaLink, FaCheckCircle, FaInfoCircle, FaClipboard, FaCode, FaQuestion, FaChevronDown, FaExternalLinkAlt, FaLock, FaUnlock } from 'react-icons/fa';
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
  const [isUsingOAuth, setIsUsingOAuth] = useState(false);
  const [githubTokenSource, setGithubTokenSource] = useState('manual'); // 'manual' or 'oauth'

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

  // Check for GitHub OAuth success on component mount
  useEffect(() => {
    const checkGitHubAuth = async () => {
      try {
        const response = await fetch('/api/oauth/github/token', {
          headers: {
            'X-User-Id': userId
          }
        });
        
        if (response.ok) {
          const data = await response.json();
          if (data.github_token) {
            setGithubToken(data.github_token);
            setGithubTokenSource('oauth');
            setIsUsingOAuth(true);
            console.log("Successfully retrieved GitHub token from OAuth");
          }
        }
      } catch (err) {
        console.error("Error checking GitHub OAuth token:", err);
      }
    };
    
    // Check URL parameters for OAuth callbacks
    const queryParams = new URLSearchParams(window.location.search);
    if (queryParams.get('github_auth') === 'success') {
      checkGitHubAuth();
      // Remove the query parameter to avoid rechecking on refresh
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, [userId]);

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
    // If using OAuth for GitHub token, we only need to validate Vercel token
    if (githubTokenSource === 'oauth') {
      return vercelToken && vercelToken.length >= 10;
    }
    
    // Otherwise validate both tokens
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
      setGithubTokenSource('manual');
    } else if (field === 'vercel') {
      setVercelToken(e.target.value);
    }
  };

  const handleGitHubOAuth = (e) => {
    e.preventDefault();
    // Redirect to the GitHub OAuth endpoint
    window.location.href = '/api/oauth/github';
  };

  const handleDeploy = async (e) => {
    e.preventDefault();
    
    // Validate inputs
    if (showTokenFields) {
      if (githubTokenSource === 'manual' && !githubToken) {
        onError('Please provide a GitHub token or use GitHub OAuth');
        return;
      }
      
      if (!vercelToken) {
        onError('Please provide a Vercel token');
        return;
      }
    }
    
    try {
      console.log("Starting deployment process");
      onDeploymentStart();
      setDeploymentInProgress(true);
      setDeploymentStage(0);
      
      // Add validation for token formats
      if (githubTokenSource === 'manual') {
        if (githubToken.length < 36 || !githubToken.match(/^gh[ps]_[A-Za-z0-9_]{36,}$/)) {
          throw new Error('Invalid GitHub token format. Please ensure you are using a valid Personal Access Token.');
        }
      }
      
      if (vercelToken.length < 24) {
        throw new Error('Invalid Vercel token format. Please ensure you are using a valid API token.');
      }
      
      // Show stage 1: Preparing files
      setDeploymentStage(1);
      
      // Prepare request payload based on token source
      const requestBody = {
        portfolio_id: portfolio._id,
        vercel_token: vercelToken
      };
      
      // If using manual GitHub token, add it to the request
      if (githubTokenSource === 'manual') {
        requestBody.github_token = githubToken;
      }
      
      // If using OAuth, we'll set use_oauth to true
      if (githubTokenSource === 'oauth') {
        requestBody.use_oauth = true;
      }
      
      // Make the deployment request
      const response = await fetch('/api/portfolio/deploy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-Id': userId
        },
        body: JSON.stringify(requestBody)
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Deployment failed');
      }
      
      const data = await response.json();
      
      if (!data.task_id) {
        throw new Error('No task ID returned from deployment request');
      }
      
      const taskId = data.task_id;
      console.log(`Deployment task started: ${taskId}`);
      
      // Show stage 2: Creating Repository
      setDeploymentStage(2);
      
      // Start polling for task status
      const pollDeploymentStatus = async () => {
        try {
          const statusResponse = await fetch(`/api/portfolio/deploy/status/${taskId}`, {
            headers: {
              'X-User-Id': userId
            }
          });
          
          if (!statusResponse.ok) {
            throw new Error('Failed to check deployment status');
          }
          
          const statusData = await statusResponse.json();
          console.log("Deployment status:", statusData);
          
          if (statusData.status === 'completed') {
            // Deployment completed successfully
            console.log("Deployment completed successfully");
            
            // Set to stage 4 (final stage)
            setDeploymentStage(4);
            
            // Wait a moment before showing the success screen
            setTimeout(() => {
              setDeploymentInProgress(false);
              if (statusData.result && statusData.result.deployment_url) {
                onDeploymentComplete({
                  deployment_url: statusData.result.deployment_url,
                  github_repo: statusData.result.github_repo
                });
              } else {
                throw new Error('No deployment URL in completed result');
              }
            }, 1000);
            
            return;
            
          } else if (statusData.status === 'failed') {
            // Deployment failed
            console.error("Deployment failed:", statusData.error);
            throw new Error(statusData.error || 'Deployment failed');
            
          } else {
            // Deployment still in progress
            // Update the stage based on time elapsed
            if (statusData.started_at) {
              const elapsedTime = Date.now() / 1000 - statusData.started_at;
              if (elapsedTime > 60 && deploymentStage < 3) {
                setDeploymentStage(3); // Show stage 3 after 1 minute
              }
            }
            
            // Continue polling
            setTimeout(pollDeploymentStatus, 5000);
          }
          
        } catch (error) {
          console.error('Error checking deployment status:', error);
          setDeploymentInProgress(false);
          onError(error.message || 'Failed to check deployment status');
        }
      };
      
      // Start polling
      pollDeploymentStatus();
      
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
    <div className="portfolio-deployment-container">
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
              
              <button className="share-portfolio-button" onClick={() => copyToClipboard(deploymentUrl)}>
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
                        <FaFighterJet className="button-icon" />
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
                        
                        {/* GitHub Authorization Options */}
                        <div className="github-auth-options">
                          <div className="auth-option-header">
                            <h5>Choose how to authorize GitHub:</h5>
                          </div>
                          
                          <div className="auth-options">
                            <button 
                              type="button"
                              className={`github-oauth-button ${githubTokenSource === 'oauth' ? 'active' : ''}`}
                              onClick={handleGitHubOAuth}
                            >
                              <FaGithub className="oauth-icon" />
                              <span>Connect with GitHub</span>
                            </button>
                            
                            <div className="auth-divider">
                              <span>OR</span>
                            </div>
                            
                            <div className="manual-token-option">
                              <div className="form-group">
                                <label htmlFor="github-token">GitHub Access Token {githubTokenSource === 'oauth' && '(Optional - using OAuth)'}</label>
                                <div className="input-with-icon">
                                  <FaGithub className="input-icon" />
                                  <input 
                                    type="password"
                                    id="github-token"
                                    value={githubToken}
                                    onChange={(e) => handleInputChange(e, 'github')}
                                    placeholder={githubTokenSource === 'oauth' ? 'Using GitHub OAuth connection' : 'Enter your GitHub access token'}
                                    className={hasInteractedWithForm && githubTokenSource === 'manual' && !githubToken ? 'input-error' : ''}
                                    disabled={githubTokenSource === 'oauth'}
                                  />
                                  {githubTokenSource === 'oauth' && (
                                    <div className="oauth-status">
                                      <FaUnlock className="auth-icon" />
                                      <span>Authorized</span>
                                    </div>
                                  )}
                                </div>
                                {hasInteractedWithForm && githubTokenSource === 'manual' && !githubToken && 
                                  <div className="input-error-message">GitHub token is required for manual authentication</div>
                                }
                                <p className="token-help">
                                  <a 
                                    href="https://github.com/settings/tokens/new" 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                    className="token-help-link"
                                  >
                                    Create a GitHub token
                                  </a> with these permissions:
                                  <ul className="token-permissions">
                                    <li><strong>repo</strong> - Full control of private repositories</li>
                                    <li><strong>workflow</strong> - Update GitHub Action workflows</li>
                                  </ul>
                                  <span className="token-tip">Important: Make sure to copy your token immediately after creation, as GitHub won't show it again!</span>
                                </p>
                              </div>
                            </div>
                          </div>
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
                        
                        <div className="form-group">
                          <label htmlFor="vercel-token">Vercel Access Token</label>
                          <div className="input-with-icon">
                            <FaLock className="input-icon" />
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
                            </a> from your account settings with these settings:
                            <ul className="token-permissions">
                              <li>Description: Portfolio Generator</li>
                              <li>Scope: Full Account</li>
                            </ul>
                          </p>
                        </div>
                      </div>

                      {/* Deployment Help Section */}
                      <div className="deployment-help-section">
                        <h3>How to Deploy Your Portfolio</h3>
                        <ol className="deployment-steps">
                          <li>
                            <strong>Step 1: Create a GitHub Token</strong>
                            <p>Visit <a href="https://github.com/settings/tokens/new" target="_blank" rel="noopener noreferrer">GitHub Token Settings</a> to create a new token with 'repo' and 'workflow' permissions.</p>
                          </li>
                          <li>
                            <strong>Step 2: Create a Vercel Token</strong>
                            <p>Visit <a href="https://vercel.com/account/tokens" target="_blank" rel="noopener noreferrer">Vercel Token Settings</a> to create a new token with full account permissions.</p>
                          </li>
                          <li>
                            <strong>Step 3: Enter Your Tokens</strong>
                            <p>Enter both tokens in the form above and click "Deploy Portfolio".</p>
                          </li>
                          <li>
                            <strong>Step 4: Wait for Deployment</strong>
                            <p>The deployment process takes approximately 2-5 minutes. Do not close this window during deployment.</p>
                          </li>
                        </ol>
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
                          <FaFighterJet className="button-icon" />
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

              {/* Troubleshooting section */}
              <div className="deployment-troubleshooting">
                <h3>Troubleshooting</h3>
                <div className="troubleshooting-item">
                  <h4>Invalid Token Error</h4>
                  <p>Make sure your tokens have the correct permissions and have not expired.</p>
                </div>
                <div className="troubleshooting-item">
                  <h4>Deployment Failed</h4>
                  <p>Check your portfolio code for errors. Common issues include invalid imports or syntax errors.</p>
                </div>
                <div className="troubleshooting-item">
                  <h4>GitHub Rate Limit Exceeded</h4>
                  <p>GitHub has rate limits for API calls. If you receive this error, wait an hour before trying again.</p>
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
