// frontend/my-react-app/src/components/pages/Portfolio/PortfolioPage.js
import React, { useState, useEffect } from 'react';
import { useSelector } from 'react-redux';
import './portfolio.css';
import PortfolioForm from './PortfolioForm';
import PortfolioPreview from './PortfolioPreview';
import PortfolioList from './PortfolioList';
import PortfolioDeployment from './PortfolioDeployment';
import LoadingSpinner from '../common/LoadingSpinner';
import ErrorMessage from '../common/ErrorMessage';

const PortfolioPage = () => {
  const { userId } = useSelector((state) => state.user);
  const [activeTab, setActiveTab] = useState('create');
  const [portfolios, setPortfolios] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [currentPortfolio, setCurrentPortfolio] = useState(null);
  const [generationComplete, setGenerationComplete] = useState(false);

  // Fetch user's portfolios on initial load
  useEffect(() => {
    if (userId) {
      fetchPortfolios();
    }
  }, [userId]);

  const fetchPortfolios = async () => {
    try {
      setLoading(true);
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
      const response = await fetch(`/api/portfolio/${portfolioId}`, {
        headers: {
          'X-User-Id': userId
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to fetch portfolio details');
      }
      
      const data = await response.json();
      setCurrentPortfolio(data.portfolio);
      setGenerationComplete(true);
      setLoading(false);
      setActiveTab('preview');
    } catch (err) {
      setError('Failed to load portfolio details');
      setLoading(false);
    }
  };

  return (
    <div className="portfolio-page-container">
      <div className="portfolio-header">
        <h1>Portfolio Creator</h1>
        <p className="portfolio-subtitle">Generate a professional portfolio website for your job search</p>
      </div>

      <div className="portfolio-tabs">
        <button 
          className={`tab-button ${activeTab === 'create' ? 'active' : ''}`}
          onClick={() => setActiveTab('create')}
        >
          Create Portfolio
        </button>
        <button 
          className={`tab-button ${activeTab === 'list' ? 'active' : ''}`}
          onClick={() => setActiveTab('list')}
        >
          My Portfolios
        </button>
        {generationComplete && (
          <>
            <button 
              className={`tab-button ${activeTab === 'preview' ? 'active' : ''}`}
              onClick={() => setActiveTab('preview')}
            >
              Preview
            </button>
            <button 
              className={`tab-button ${activeTab === 'deploy' ? 'active' : ''}`}
              onClick={() => setActiveTab('deploy')}
            >
              Deploy
            </button>
          </>
        )}
      </div>

      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}

      <div className="portfolio-content">
        {loading ? (
          <LoadingSpinner message="Processing your request..." />
        ) : (
          <>
            {activeTab === 'create' && (
              <PortfolioForm 
                userId={userId}
                onGenerationStart={() => setLoading(true)}
                onGenerationComplete={handlePortfolioGenerated}
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
                onFixError={setLoading}
                userId={userId}
              />
            )}
            
            {activeTab === 'deploy' && currentPortfolio && (
              <PortfolioDeployment
                portfolio={currentPortfolio}
                userId={userId}
                onDeploymentStart={() => setLoading(true)}
                onDeploymentComplete={handleDeploymentComplete}
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
