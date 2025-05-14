// frontend/my-react-app/src/components/pages/Portfolio/PortfolioList.js
import React, { useState } from 'react';
import { FaRocket, FaEdit, FaTrash, FaCalendarAlt, FaPalette, FaSwatchbook, FaExternalLinkAlt, FaSearch } from 'react-icons/fa';
import './portfolio.css';

const PortfolioList = ({ portfolios, onSelectPortfolio, onRefresh }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filteredPortfolios, setFilteredPortfolios] = useState(portfolios);

  // Update filtered portfolios when search term or portfolios change
  React.useEffect(() => {
    if (searchTerm.trim() === '') {
      setFilteredPortfolios(portfolios);
    } else {
      const filtered = portfolios.filter(portfolio => {
        // Search through preferences
        const templateStyle = portfolio.preferences?.template_style?.toLowerCase() || '';
        const colorScheme = portfolio.preferences?.color_scheme?.toLowerCase() || '';
        
        // Get creation date for search
        const creationDate = formatDate(portfolio.created_at);
        
        // Combine searchable fields
        const searchableText = `${templateStyle} ${colorScheme} ${creationDate} ${portfolio.status}`.toLowerCase();
        
        return searchableText.includes(searchTerm.toLowerCase());
      });
      setFilteredPortfolios(filtered);
    }
  }, [searchTerm, portfolios]);

  const formatDate = (timestamp) => {
    if (!timestamp) return 'Unknown';
    const date = new Date(timestamp * 1000);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  };

  const getTemplateIcon = (templateStyle) => {
    switch(templateStyle?.toLowerCase()) {
      case 'modern':
        return '🌟';
      case 'creative':
        return '🎨';
      case 'corporate':
        return '💼';
      case 'tech':
        return '💻';
      default:
        return '📄';
    }
  };

  const getColorIcon = (colorScheme) => {
    switch(colorScheme?.toLowerCase()) {
      case 'professional':
        return '🔵';
      case 'creative':
        return '🟣';
      case 'tech':
        return '🟢';
      case 'minimal':
        return '⚪';
      default:
        return '🎨';
    }
  };

  if (!portfolios || portfolios.length === 0) {
    return (
      <div className="portfolio-empty-state">
        <div className="portfolio-empty-icon">📂</div>
        <h3>You haven't created any portfolios yet</h3>
        <p>Go to the 'Create Portfolio' tab to generate your first portfolio.</p>
        <button className="portfolio-refresh-button" onClick={onRefresh}>
          <span className="refresh-icon">🔄</span>
          <span>Refresh</span>
        </button>
      </div>
    );
  }

  return (
    <div className="portfolio-list-container">
      <div className="portfolio-list-header">
        <h2>My Portfolios</h2>
        <div className="portfolio-list-actions">
          <div className="portfolio-search-container">
            <FaSearch className="search-icon" />
            <input
              type="text"
              placeholder="Search portfolios..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="portfolio-search-input"
            />
          </div>
          <button 
            className="portfolio-refresh-button"
            onClick={onRefresh}
          >
            <span className="refresh-icon">🔄</span>
            <span>Refresh</span>
          </button>
        </div>
      </div>
      
      <div className="portfolio-list-stats">
        <div className="portfolio-stat">
          <div className="portfolio-stat-value">{portfolios.length}</div>
          <div className="portfolio-stat-label">Total Portfolios</div>
        </div>
        <div className="portfolio-stat">
          <div className="portfolio-stat-value">
            {portfolios.filter(p => p.deployment?.deployed).length}
          </div>
          <div className="portfolio-stat-label">Deployed</div>
        </div>
      </div>
      
      {filteredPortfolios.length === 0 ? (
        <div className="portfolio-no-results">
          <p>No portfolios match your search. Try different keywords or clear your search.</p>
        </div>
      ) : (
        <div className="portfolio-grid">
          {filteredPortfolios.map(portfolio => (
            <div key={portfolio._id} className="portfolio-item-card">
              <div className="portfolio-card-header">
                <h3 className="portfolio-card-title">Portfolio</h3>
                <span className={`portfolio-status-badge ${portfolio.status}`}>
                  {portfolio.status === 'deployed' ? (
                    <><FaRocket className="status-icon" /> Deployed</>
                  ) : (
                    <><FaEdit className="status-icon" /> Generated</>
                  )}
                </span>
              </div>
              
              <div className="portfolio-card-details">
                <div className="portfolio-detail-item">
                  <FaCalendarAlt className="detail-icon" />
                  <span className="detail-label">Created:</span>
                  <span className="detail-value">{formatDate(portfolio.created_at)}</span>
                </div>
                
                <div className="portfolio-detail-item">
                  <FaPalette className="detail-icon" />
                  <span className="detail-label">Template:</span>
                  <span className="detail-value">
                    {getTemplateIcon(portfolio.preferences?.template_style)} {portfolio.preferences?.template_style || 'Custom'}
                  </span>
                </div>
                
                <div className="portfolio-detail-item">
                  <FaSwatchbook className="detail-icon" />
                  <span className="detail-label">Colors:</span>
                  <span className="detail-value">
                    {getColorIcon(portfolio.preferences?.color_scheme)} {portfolio.preferences?.color_scheme || 'Default'}
                  </span>
                </div>
                
                {portfolio.deployment?.deployed && (
                  <div className="portfolio-detail-item portfolio-url-item">
                    <FaExternalLinkAlt className="detail-icon" />
                    <span className="detail-label">URL:</span>
                    <a 
                      href={portfolio.deployment.url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="portfolio-url-link"
                    >
                      {portfolio.deployment.url.replace(/^https?:\/\//, '')}
                    </a>
                  </div>
                )}
              </div>
              
              <div className="portfolio-card-actions">
                <button 
                  className="portfolio-select-button"
                  onClick={() => onSelectPortfolio(portfolio._id)}
                >
                  <span className="select-icon">📝</span>
                  <span>Edit Portfolio</span>
                </button>
                {portfolio.deployment?.deployed && (
                  <a 
                    href={portfolio.deployment.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="portfolio-view-button"
                  >
                    <span className="view-icon">👁️</span>
                    <span>View Live</span>
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      
      <div className="portfolio-list-explanation">
        <h3>Managing Your Portfolios</h3>
        <p>
          Each portfolio you create is saved and can be edited or deployed at any time.
          Select a portfolio to preview, make changes, or deploy it to the web.
        </p>
        <ul className="portfolio-tips">
          <li>Click <strong>Edit Portfolio</strong> to view and modify your portfolio code</li>
          <li>Use the <strong>Deploy</strong> tab to make your portfolio accessible online</li>
          <li>Your portfolios are stored securely and can be accessed anytime</li>
        </ul>
      </div>
    </div>
  );
};

export default PortfolioList;
