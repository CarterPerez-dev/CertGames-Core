// frontend/my-react-app/src/components/pages/Portfolio/PortfolioList.js
import React from 'react';
import './portfolio.css';

const PortfolioList = ({ portfolios, onSelectPortfolio, onRefresh }) => {
  const formatDate = (timestamp) => {
    if (!timestamp) return 'Unknown';
    const date = new Date(timestamp * 1000);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  };

  if (!portfolios || portfolios.length === 0) {
    return (
      <div className="no-portfolios">
        <h3>You haven't created any portfolios yet</h3>
        <p>Go to the 'Create Portfolio' tab to generate your first portfolio.</p>
        <button className="refresh-button" onClick={onRefresh}>Refresh</button>
      </div>
    );
  }

  return (
    <div className="portfolios-list-container">
      <div className="portfolios-header">
        <h2>My Portfolios</h2>
        <button className="refresh-button" onClick={onRefresh}>
          Refresh
        </button>
      </div>
      
      <div className="portfolios-grid">
        {portfolios.map(portfolio => (
          <div key={portfolio._id} className="portfolio-card">
            <div className="portfolio-card-header">
              <h3>Portfolio</h3>
              <span className={`status-badge ${portfolio.status}`}>
                {portfolio.status}
              </span>
            </div>
            
            <div className="portfolio-card-details">
              <div className="detail-item">
                <span className="detail-label">Created:</span>
                <span className="detail-value">{formatDate(portfolio.created_at)}</span>
              </div>
              
              <div className="detail-item">
                <span className="detail-label">Template:</span>
                <span className="detail-value">{portfolio.preferences?.template_style || 'Custom'}</span>
              </div>
              
              <div className="detail-item">
                <span className="detail-label">Color Scheme:</span>
                <span className="detail-value">{portfolio.preferences?.color_scheme || 'Default'}</span>
              </div>
              
              {portfolio.deployment?.deployed && (
                <div className="detail-item">
                  <span className="detail-label">Deployed:</span>
                  <a 
                    href={portfolio.deployment.url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="detail-link"
                  >
                    View Live
                  </a>
                </div>
              )}
            </div>
            
            <div className="portfolio-card-actions">
              <button 
                className="select-portfolio-button"
                onClick={() => onSelectPortfolio(portfolio._id)}
              >
                Select Portfolio
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default PortfolioList;
