// Enhanced PortfolioPage Component
import React, { useState, useEffect } from 'react';
import { useSelector } from 'react-redux';
import './portfolio.css';
import PortfolioForm from './PortfolioForm';
import PortfolioPreview from './PortfolioPreview';
import PortfolioList from './PortfolioList';
import PortfolioDeployment from './PortfolioDeployment';
import LoadingSpinner from '../common/LoadingSpinner';
import ErrorMessage from '../common/ErrorMessage';
import { FaCode, FaRocket, FaList, FaPlus, FaStar, FaExclamationCircle, FaSync, FaGithub} from 'react-icons/fa';

const PortfolioPage = () => {
  const { userId } = useSelector((state) => state.user);
  const [activeTab, setActiveTab] = useState('create');
  const [portfolios, setPortfolios] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [currentPortfolio, setCurrentPortfolio] = useState(null);
  const [generationComplete, setGenerationComplete] = useState(false);
  const [loadingMessage, setLoadingMessage] = useState('Loading...');
  const [loadingProgress, setLoadingProgress] = useState(0);
  const [refreshing, setRefreshing] = useState(false);

  console.log("Rendering PortfolioPage component");

  // Fetch user's portfolios on initial load
  useEffect(() => {
    if (userId) {
      console.log("User ID detected, fetching portfolios");
      fetchPortfolios();
    }
  }, [userId]);

  const fetchPortfolios = async () => {
    try {
      setRefreshing(true);
      setLoading(true);
      setLoadingMessage('Fetching your portfolios...');
      
      console.log("Making API request to fetch portfolios");
      const response = await fetch('/api/portfolio/list', {
        headers: {
          'X-User-Id': userId
        }
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Failed to fetch portfolios: ${response.status} - ${errorText}`);
        throw new Error('Failed to fetch portfolios');
      }
      
      const data = await response.json();
      console.log(`Fetched ${data.portfolios?.length || 0} portfolios:`, data.portfolios);
      
      if (!data.portfolios || !Array.isArray(data.portfolios)) {
        console.error("Invalid portfolios data structure:", data);
        throw new Error('Invalid portfolio data received');
      }
      
      setPortfolios(data.portfolios || []);
      setLoading(false);
      setRefreshing(false);
    } catch (err) {
      console.error('Error fetching portfolios:', err);
      setError('Failed to load existing portfolios. Please try again later.');
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleRefresh = () => {
    console.log("Manual refresh triggered");
    fetchPortfolios();
  };

  const handlePortfolioGenerated = (portfolioData) => {
    console.log("Portfolio generation completed successfully", portfolioData);
    
    // Ensure we have a valid portfolio object
    if (!portfolioData || !portfolioData._id) {
      console.error("Invalid portfolio data received:", portfolioData);
      setError("Generated portfolio data is incomplete");
      setLoading(false);
      return;
    }
    
    setCurrentPortfolio(portfolioData);
    setGenerationComplete(true);
    setActiveTab('preview'); // Switch to preview tab
    
    // Add a small delay before fetching portfolios to ensure the backend has updated
    setTimeout(() => {
      fetchPortfolios();
    }, 1000);
    
    setLoading(false);
  };

  const handlePortfolioError = (errorMessage) => {
    console.error("Portfolio error:", errorMessage);
    setError(errorMessage);
    setLoading(false);
  };

  const handleDismissError = () => {
    console.log("Dismissing error message");
    setError(null);
  };

  const handleDeploymentComplete = (deploymentData) => {
    console.log("Portfolio deployment completed", deploymentData);
    // Update the current portfolio with deployment info
    setCurrentPortfolio(prev => ({
      ...prev,
      deployment: {
        deployed: true,
        url: deploymentData.deployment_url
      }
    }));
    
    fetchPortfolios(); // Refresh the list
    setActiveTab('deploy'); // Switch to deploy tab
  };

  const handleSelectPortfolio = async (portfolioId) => {
    try {
      console.log(`Selecting portfolio with ID: ${portfolioId}`);
      setLoading(true);
      setLoadingMessage('Loading portfolio...');
      
      // Simulate loading progress
      const progressInterval = setInterval(() => {
        setLoadingProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 300);
      
      const response = await fetch(`/api/portfolio/${portfolioId}`, {
        headers: {
          'X-User-Id': userId
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to fetch portfolio details');
      }
      
      const data = await response.json();
      console.log("Received portfolio details successfully");
      
      // Complete progress
      setLoadingProgress(100);
      clearInterval(progressInterval);
      
      setCurrentPortfolio(data.portfolio);
      setGenerationComplete(true);
      setLoading(false);
      setActiveTab('preview');
      
      // Reset progress for next time
      setTimeout(() => setLoadingProgress(0), 500);
      
    } catch (err) {
      console.error("Error selecting portfolio:", err);
      setError('Failed to load portfolio details');
      setLoading(false);
      setLoadingProgress(0);
    }
  };

  return (
    <div className="portfolio-page-container">
      <div className="portfolio-page-header">
        <div className="portfolio-page-title-section">
          <h1 className="portfolio-page-title">Portfolio Creator</h1>
          <p className="portfolio-page-subtitle">Build a professional portfolio to showcase your skills and experience</p>
        </div>
        
        <div className="portfolio-page-actions">
          <button 
            className={`portfolio-refresh-button ${refreshing ? 'refreshing' : ''}`}
            onClick={handleRefresh}
            disabled={loading || refreshing}
          >
            <FaSync className={`refresh-icon ${refreshing ? 'spin' : ''}`} />
            <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      <div className="portfolio-page-tabs">
        <button 
          className={`portfolio-tab-button ${activeTab === 'create' ? 'active' : ''}`}
          onClick={() => setActiveTab('create')}
        >
          <FaPlus className="tab-icon" />
          <span>Create</span>
        </button>
        
        <button 
          className={`portfolio-tab-button ${activeTab === 'list' ? 'active' : ''}`}
          onClick={() => setActiveTab('list')}
        >
          <FaList className="tab-icon" />
          <span>My Portfolios</span>
        </button>
        
        {generationComplete && (
          <>
            <button 
              className={`portfolio-tab-button ${activeTab === 'preview' ? 'active' : ''}`}
              onClick={() => setActiveTab('preview')}
            >
              <FaCode className="tab-icon" />
              <span>Preview & Edit</span>
            </button>
            
            <button 
              className={`portfolio-tab-button ${activeTab === 'deploy' ? 'active' : ''}`}
              onClick={() => setActiveTab('deploy')}
            >
              <FaGithub className="tab-icon" />
              <span>Deploy</span>
            </button>
          </>
        )}
      </div>

      {error && (
        <div className="portfolio-error-banner">
          <ErrorMessage message={error} onDismiss={handleDismissError} />
        </div>
      )}

      <div className="portfolio-page-content">
        {loading ? (
          <div className="portfolio-loading-container">
            <LoadingSpinner message={loadingMessage} />
            
            {loadingProgress > 0 && (
              <div className="portfolio-loading-progress-container">
                <div 
                  className="portfolio-loading-progress-bar" 
                  style={{ width: `${loadingProgress}%` }}
                ></div>
                <span className="portfolio-loading-progress-text">{loadingProgress}%</span>
              </div>
            )}
            
            {/* Add this new section for generation status */}
            {loadingMessage.includes('Generating') && (
              <div className="portfolio-generation-status">
                <div className="generation-steps">
                  <div className={`generation-step ${loadingProgress > 10 ? 'active' : ''}`}>
                    <div className="step-icon">📝</div>
                    <div className="step-text">Analyzing Resume</div>
                    {loadingProgress > 10 && <div className="step-check">✓</div>}
                  </div>
                  
                  <div className={`generation-step ${loadingProgress > 35 ? 'active' : ''}`}>
                    <div className="step-icon">💻</div>
                    <div className="step-text">Creating Components</div>
                    {loadingProgress > 35 && <div className="step-check">✓</div>}
                  </div>
                  
                  <div className={`generation-step ${loadingProgress > 70 ? 'active' : ''}`}>
                    <div className="step-icon">🎨</div>
                    <div className="step-text">Applying Styles</div>
                    {loadingProgress > 70 && <div className="step-check">✓</div>}
                  </div>
                  
                  <div className={`generation-step ${loadingProgress > 95 ? 'active' : ''}`}>
                    <div className="step-icon">🚀</div>
                    <div className="step-text">Finalizing Portfolio</div>
                    {loadingProgress > 95 && <div className="step-check">✓</div>}
                  </div>
                </div>
                
                <div className="generation-tip">
                  <div className="tip-icon">💡</div>
                  <div className="tip-text">
                    This process typically takes 3-5 minutes. Can you click off the page you ask? I dont know....I vibe coded this in 6 hours, so I really couldnt tell you ¯\_(ツ)_/¯
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : (
          <>
            {activeTab === 'create' && (
              <PortfolioForm 
                userId={userId}
                onGenerationStart={(message) => {
                  setLoading(true);
                  // Use the custom message if provided, otherwise use default
                  setLoadingMessage(message || 'Generating your portfolio...');
                  
                  // Clear any existing interval to prevent multiple intervals running
                  if (window.progressInterval) {
                    clearInterval(window.progressInterval);
                  }
                  
                  // Reset progress to ensure we start from 0
                  setLoadingProgress(0);
                  
                  // Improved progressive simulation - no back and forth
                  let progress = 0;
                  const progressInterval = setInterval(() => {
                    // Gradually slow down progress as we approach 95%
                    const increment = progress < 30 ? 3 : 
                                      progress < 60 ? 2 : 
                                      progress < 85 ? 1 : 0.5;
                    
                    progress += increment;
                    if (progress >= 95) {
                      clearInterval(progressInterval);
                      progress = 95; // Cap at 95% until complete
                    }
                    setLoadingProgress(progress);
                  }, 1000); // Longer interval for more stable appearance
                  
                  // Store interval ID to clear it when generation completes
                  window.progressInterval = progressInterval;
                }}
                onGenerationComplete={(data) => {
                  // Clear progress interval
                  if (window.progressInterval) {
                    clearInterval(window.progressInterval);
                  }
                  
                  // Complete progress animation
                  setLoadingProgress(100);
                  setTimeout(() => {
                    setLoadingProgress(0);
                    handlePortfolioGenerated(data);
                  }, 500);
                }}
                onError={handlePortfolioError}
              />
            )}

            {activeTab === 'list' && (
              <PortfolioList
                portfolios={portfolios}
                onSelectPortfolio={handleSelectPortfolio}
                onRefresh={handleRefresh}
              />
            )}

            {activeTab === 'preview' && currentPortfolio && (
              <PortfolioPreview
                portfolio={currentPortfolio}
                userId={userId}
                onFixError={(isFixing) => { /* You might want to set a state for this if 'isFixingError' is used in PortfolioPreview */
                    console.log("Fix error status from preview:", isFixing);
                 }}
              />
            )}
            
            {activeTab === 'deploy' && currentPortfolio && (
              <PortfolioDeployment
                portfolio={currentPortfolio}
                userId={userId}
                onDeploymentStart={() => {
                  setLoading(true);
                  setLoadingMessage('Deploying your portfolio...');
                  
                  // Simulate deployment progress
                  let progress = 0;
                  const progressInterval = setInterval(() => {
                    progress += 3;
                    if (progress >= 90) {
                      clearInterval(progressInterval);
                      progress = 90;
                    }
                    setLoadingProgress(progress);
                  }, 500);
                  
                  // Store interval ID
                  window.deployProgressInterval = progressInterval;
                }}
                onDeploymentComplete={(data) => {
                  // Clear progress interval
                  if (window.deployProgressInterval) {
                    clearInterval(window.deployProgressInterval);
                  }
                  
                  // Complete progress animation
                  setLoadingProgress(100);
                  setTimeout(() => {
                    setLoadingProgress(0);
                    handleDeploymentComplete(data);
                  }, 500);
                }}
                onError={handlePortfolioError}
              />
            )}
          </>
        )}
      </div>
    </div>
  );
};
export default PortfolioPage;
