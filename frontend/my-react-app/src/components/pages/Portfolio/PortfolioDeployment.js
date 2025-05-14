// frontend/my-react-app/src/components/pages/Portfolio/PortfolioDeployment.js
import React, { useState } from 'react';
import './portfolio.css';

const PortfolioDeployment = ({ portfolio, userId, onDeploymentStart, onDeploymentComplete, onError }) => {
  const [githubToken, setGithubToken] = useState('');
  const [vercelToken, setVercelToken] = useState('');
  const [showTokenFields, setShowTokenFields] = useState(false);
  const [deploymentInProgress, setDeploymentInProgress] = useState(false);

  const handleDeploy = async (e) => {
    e.preventDefault();
    
    // Validate inputs
    if (showTokenFields && (!githubToken || !vercelToken)) {
      onError('Please provide both GitHub and Vercel tokens');
      return;
    }
    
    try {
      onDeploymentStart();
      setDeploymentInProgress(true);
      
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
      setDeploymentInProgress(false);
      onDeploymentComplete(data);
      
    } catch (err) {
      setDeploymentInProgress(false);
      onError(err.message || 'Deployment failed. Please try again.');
    }
  };

  const isDeployed = portfolio?.deployment?.deployed;
  const deploymentUrl = portfolio?.deployment?.url;

  return (
    <div className="deployment-container">
      <div className="deployment-header">
        <h2>Deploy Your Portfolio</h2>
        <p>Deploy your portfolio to Vercel for free hosting</p>
      </div>
      
      {isDeployed ? (
        <div className="deployment-success">
          <div className="success-icon">✅</div>
          <h3>Your Portfolio is Live!</h3>
          <p>Your portfolio has been successfully deployed and is now accessible online.</p>
          
          <div className="deployment-url">
            <p>Visit your portfolio at:</p>
            <a 
              href={deploymentUrl} 
              target="_blank" 
              rel="noopener noreferrer"
              className="portfolio-url"
            >
              {deploymentUrl}
            </a>
          </div>
          
          <div className="deployment-note">
            <p>
              <strong>Note:</strong> It may take a few minutes for your portfolio to become fully available. 
              If the link doesn't work immediately, please try again in a few minutes.
            </p>
          </div>
        </div>
      ) : (
        <div className="deployment-options">
          {deploymentInProgress ? (
            <div className="deployment-in-progress">
              <div className="loading-spinner"></div>
              <h3>Deployment in Progress</h3>
              <p>Your portfolio is being deployed. This may take a few minutes.</p>
              <p>Please do not close this window.</p>
            </div>
          ) : (
            <>
              <div className="deployment-instructions">
                <h3>Deployment Instructions</h3>
                <p>
                  To deploy your portfolio, we'll need to create a GitHub repository and connect it to Vercel.
                  This process is automated, but requires access tokens for GitHub and Vercel.
                </p>
                
                {!showTokenFields ? (
                  <button 
                    className="show-tokens-button"
                    onClick={() => setShowTokenFields(true)}
                  >
                    Continue to Deployment
                  </button>
                ) : (
                  <form className="deployment-form" onSubmit={handleDeploy}>
                    <div className="form-group">
                      <label htmlFor="github-token">GitHub Access Token</label>
                      <input 
                        type="password"
                        id="github-token"
                        value={githubToken}
                        onChange={(e) => setGithubToken(e.target.value)}
                        placeholder="Enter your GitHub access token"
                      />
                      <p className="token-help">
                        <a 
                          href="https://github.com/settings/tokens/new" 
                          target="_blank" 
                          rel="noopener noreferrer"
                        >
                          Create a GitHub token
                        </a> with 'repo' and 'workflow' permissions.
                      </p>
                    </div>
                    
                    <div className="form-group">
                      <label htmlFor="vercel-token">Vercel Access Token</label>
                      <input 
                        type="password"
                        id="vercel-token"
                        value={vercelToken}
                        onChange={(e) => setVercelToken(e.target.value)}
                        placeholder="Enter your Vercel access token"
                      />
                      <p className="token-help">
                        <a 
                          href="https://vercel.com/account/tokens" 
                          target="_blank" 
                          rel="noopener noreferrer"
                        >
                          Create a Vercel token
                        </a> from your account settings.
                      </p>
                    </div>
                    
                    <button 
                      type="submit"
                      className="deploy-button"
                      disabled={!githubToken || !vercelToken}
                    >
                      Deploy Portfolio
                    </button>
                  </form>
                )}
              </div>
              
              <div className="deployment-info">
                <h3>What happens during deployment?</h3>
                <ul>
                  <li>A new GitHub repository will be created with your portfolio code</li>
                  <li>The repository will be connected to Vercel for hosting</li>
                  <li>Your portfolio will be deployed and available online</li>
                  <li>You'll receive a URL to access your live portfolio</li>
                </ul>
                
                <div className="deployment-note">
                  <strong>Note:</strong> Your tokens are used only for deployment and are not stored on our servers.
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
