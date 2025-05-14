// frontend/my-react-app/src/components/pages/Portfolio/PortfolioPage.js
import React, { useState, useEffect } from 'react';
import { useSelector } from 'react-redux';
import './portfolio.css';
import PortfolioForm from './PortfolioForm';
import PortfolioPreview from './PortfolioPreview';
import PortfolioList from './PortfolioList';
import PortfolioDeployment from './PortfolioDeployment';
import { FaCode, FaRocket, FaList, FaPlus, FaStar } from 'react-icons/fa';

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

  // Fetch user's portfolios on initial load
  useEffect(() => {
    if (userId) {
      fetchPortfolios();
    }
  }, [userId]);

  const fetchPortfolios = async () => {
    try {
      setLoading(true);
      setLoadingMessage('Fetching your portfolios...');
      
      const response = await fetch('/api/portfolio/list', {
        headers: {
          'X-User-Id': userId
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to fetch portfolios');
      }
      
      const data = await response.json();
      setPortfolios(data.portfolios || []);
      setLoading(false);
    } catch (err) {
      console.error('Error fetching portfolios:', err);
      setError('Failed to load existing portfolios. Please try again later.');
      setLoading(false);
    }
  };

  const handlePortfolioGenerated = (portfolioData) => {
    setCurrentPortfolio(portfolioData);
    setGenerationComplete(true);
    fetchPortfolios(); // Refresh the list
    setActiveTab('preview'); // Switch to preview tab
  };

  const handlePortfolioError = (errorMessage) => {
    setError(errorMessage);
    setLoading(false);
  };

  const handleDeploymentComplete = (deploymentData) => {
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
            className="portfolio-refresh-button"
            onClick={fetchPortfolios}
            disabled={loading}
          >
            <span className="refresh-icon">🔄</span>
            <span>Refresh</span>
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
              <FaRocket className="tab-icon" />
              <span>Deploy</span>
            </button>
          </>
        )}
      </div>

      {error && (
        <div className="portfolio-error-banner">
          <div className="portfolio-error-content">
            <span className="portfolio-error-icon">⚠️</span>
            <p className="portfolio-error-message">{error}</p>
          </div>
          <button className="portfolio-error-dismiss" onClick={() => setError(null)}>
            ×
          </button>
        </div>
      )}

      <div className="portfolio-page-content">
        {loading ? (
          <div className="portfolio-loading-container">
            <div className="portfolio-loading-content">
              <div className="portfolio-loading-animation">
                <div className="portfolio-loading-spinner">
                  <div className="spinner-inner"></div>
                </div>
                <div className="portfolio-loading-icon">
                  <FaStar className="loading-star" />
                </div>
              </div>
              <h3 className="portfolio-loading-message">{loadingMessage}</h3>
              
              {loadingProgress > 0 && (
                <div className="portfolio-loading-progress-container">
                  <div 
                    className="portfolio-loading-progress-bar" 
                    style={{ width: `${loadingProgress}%` }}
                  ></div>
                  <span className="portfolio-loading-progress-text">{loadingProgress}%</span>
                </div>
              )}
            </div>
          </div>
        ) : (
          <>
            {activeTab === 'create' && (
              <PortfolioForm 
                userId={userId}
                onGenerationStart={() => {
                  setLoading(true);
                  setLoadingMessage('Generating your portfolio...');
                  
                  // Simulate loading progress for generation
                  let progress = 0;
                  const progressInterval = setInterval(() => {
                    progress += 5;
                    if (progress >= 95) {
                      clearInterval(progressInterval);
                      progress = 95;
                    }
                    setLoadingProgress(progress);
                  }, 800);
                  
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
                onRefresh={fetchPortfolios}
              />
            )}
            
            {activeTab === 'preview' && currentPortfolio && (
              <PortfolioPreview 
                portfolio={currentPortfolio}
                onFixError={(isFixing) => {
                  setLoading(isFixing);
                  if (isFixing) {
                    setLoadingMessage('Fixing code errors...');
                    setLoadingProgress(50);
                  } else {
                    setLoadingProgress(100);
                    setTimeout(() => setLoadingProgress(0), 500);
                  }
                }}
                userId={userId}
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
