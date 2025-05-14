// Enhanced PortfolioList Component
import React, { useState, useEffect } from 'react';
import { FaRocket, FaEdit, FaCalendarAlt, FaPalette, FaSwatchbook, FaExternalLinkAlt, FaSearch, FaPlus, FaInfo, FaFilter, FaSort, FaSortAlphaDown, FaSortAmountUp, FaRegClock } from 'react-icons/fa';
import './portfolio.css';

const PortfolioList = ({ portfolios, onSelectPortfolio, onRefresh }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filteredPortfolios, setFilteredPortfolios] = useState(portfolios);
  const [sortBy, setSortBy] = useState('date');
  const [sortDirection, setSortDirection] = useState('desc');
  const [filterStatus, setFilterStatus] = useState('all');
  const [isSearchFocused, setIsSearchFocused] = useState(false);

  // Update filtered portfolios when search term, sort options, or portfolios change
  useEffect(() => {
    console.log(`Filtering portfolios with search: "${searchTerm}", filter: ${filterStatus}, sort: ${sortBy}-${sortDirection}`);
    let filtered = [...portfolios];
    
    // Filter by search term
    if (searchTerm.trim() !== '') {
      filtered = filtered.filter(portfolio => {
        // Search through preferences
        const templateStyle = portfolio.preferences?.template_style?.toLowerCase() || '';
        const colorScheme = portfolio.preferences?.color_scheme?.toLowerCase() || '';
        
        // Get creation date for search
        const creationDate = formatDate(portfolio.created_at);
        
        // Combine searchable fields
        const searchableText = `${templateStyle} ${colorScheme} ${creationDate} ${portfolio.status}`.toLowerCase();
        
        return searchableText.includes(searchTerm.toLowerCase());
      });
    }
    
    // Filter by status
    if (filterStatus !== 'all') {
      filtered = filtered.filter(portfolio => {
        if (filterStatus === 'deployed') {
          return portfolio.deployment?.deployed === true;
        } else if (filterStatus === 'generated') {
          return !portfolio.deployment?.deployed;
        }
        return true;
      });
    }
    
    // Sort the filtered results
    filtered.sort((a, b) => {
      let comparison = 0;
      
      if (sortBy === 'date') {
        // Sort by creation date
        comparison = (a.created_at || 0) - (b.created_at || 0);
      } else if (sortBy === 'template') {
        // Sort by template style
        const templateA = a.preferences?.template_style?.toLowerCase() || '';
        const templateB = b.preferences?.template_style?.toLowerCase() || '';
        comparison = templateA.localeCompare(templateB);
      } else if (sortBy === 'color') {
        // Sort by color scheme
        const colorA = a.preferences?.color_scheme?.toLowerCase() || '';
        const colorB = b.preferences?.color_scheme?.toLowerCase() || '';
        comparison = colorA.localeCompare(colorB);
      }
      
      // Apply sort direction
      return sortDirection === 'asc' ? comparison : -comparison;
    });
    
    setFilteredPortfolios(filtered);
  }, [searchTerm, sortBy, sortDirection, filterStatus, portfolios]);

  const formatDate = (timestamp) => {
    if (!timestamp) return 'Unknown';
    const date = new Date(timestamp * 1000);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  };

  const getRelativeTime = (timestamp) => {
    if (!timestamp) return 'Unknown time';
    
    const now = new Date();
    const then = new Date(timestamp * 1000);
    const diffInSeconds = Math.floor((now - then) / 1000);
    
    if (diffInSeconds < 60) {
      return 'Just now';
    } else if (diffInSeconds < 3600) {
      const minutes = Math.floor(diffInSeconds / 60);
      return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    } else if (diffInSeconds < 86400) {
      const hours = Math.floor(diffInSeconds / 3600);
      return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    } else if (diffInSeconds < 2592000) {
      const days = Math.floor(diffInSeconds / 86400);
      return `${days} day${days > 1 ? 's' : ''} ago`;
    } else if (diffInSeconds < 31536000) {
      const months = Math.floor(diffInSeconds / 2592000);
      return `${months} month${months > 1 ? 's' : ''} ago`;
    } else {
      const years = Math.floor(diffInSeconds / 31536000);
      return `${years} year${years > 1 ? 's' : ''} ago`;
    }
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

  const toggleSortDirection = () => {
    console.log(`Toggling sort direction from ${sortDirection} to ${sortDirection === 'asc' ? 'desc' : 'asc'}`);
    setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
  };

  const handleChangeSortBy = (newSortBy) => {
    console.log(`Changing sort from ${sortBy} to ${newSortBy}`);
    if (sortBy === newSortBy) {
      // If clicking on the same sort option, toggle direction
      toggleSortDirection();
    } else {
      // If clicking on a different sort option, set it and use desc direction
      setSortBy(newSortBy);
      setSortDirection('desc');
    }
  };

  const handleFilterChange = (newFilter) => {
    console.log(`Changing filter from ${filterStatus} to ${newFilter}`);
    setFilterStatus(newFilter);
  };

  if (!portfolios || portfolios.length === 0) {
    return (
      <div className="portfolio-empty-state">
        <div className="portfolio-empty-icon">📂</div>
        <h3>You haven't created any portfolios yet</h3>
        <p>Go to the 'Create Portfolio' tab to generate your first portfolio.</p>
        <div className="portfolio-empty-actions">
          <button className="portfolio-create-first-button">
            <FaPlus className="button-icon" />
            <span>Create Your First Portfolio</span>
          </button>
          <button className="portfolio-refresh-button" onClick={onRefresh}>
            <span className="refresh-icon">🔄</span>
            <span>Refresh</span>
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
          <div className={`portfolio-search-container ${isSearchFocused ? 'focused' : ''}`}>
            <FaSearch className="search-icon" />
            <input
              type="text"
              placeholder="Search portfolios..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onFocus={() => setIsSearchFocused(true)}
              onBlur={() => setIsSearchFocused(false)}
              className="portfolio-search-input"
            />
            {searchTerm && (
              <button 
                className="search-clear-button"
                onClick={() => setSearchTerm('')}
              >
                ×
              </button>
            )}
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
      
      <div className="portfolio-controls">
        <div className="portfolio-filter-controls">
          <div className="filter-label">
            <FaFilter className="filter-icon" />
            <span>Filter:</span>
          </div>
          <div className="filter-options">
            <button 
              className={`filter-option ${filterStatus === 'all' ? 'active' : ''}`}
              onClick={() => handleFilterChange('all')}
            >
              All
            </button>
            <button 
              className={`filter-option ${filterStatus === 'deployed' ? 'active' : ''}`}
              onClick={() => handleFilterChange('deployed')}
            >
              Deployed
            </button>
            <button 
              className={`filter-option ${filterStatus === 'generated' ? 'active' : ''}`}
              onClick={() => handleFilterChange('generated')}
            >
              Generated
            </button>
          </div>
        </div>
        
        <div className="portfolio-sort-controls">
          <div className="sort-label">
            <FaSort className="sort-icon" />
            <span>Sort by:</span>
          </div>
          <div className="sort-options">
            <button 
              className={`sort-option ${sortBy === 'date' ? 'active' : ''}`}
              onClick={() => handleChangeSortBy('date')}
            >
              <FaRegClock className="sort-option-icon" />
              <span>Date {sortBy === 'date' && (sortDirection === 'asc' ? '↑' : '↓')}</span>
            </button>
            <button 
              className={`sort-option ${sortBy === 'template' ? 'active' : ''}`}
              onClick={() => handleChangeSortBy('template')}
            >
              <FaSwatchbook className="sort-option-icon" />
              <span>Template {sortBy === 'template' && (sortDirection === 'asc' ? '↑' : '↓')}</span>
            </button>
            <button 
              className={`sort-option ${sortBy === 'color' ? 'active' : ''}`}
              onClick={() => handleChangeSortBy('color')}
            >
              <FaPalette className="sort-option-icon" />
              <span>Color {sortBy === 'color' && (sortDirection === 'asc' ? '↑' : '↓')}</span>
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
            {portfolios.filter(p => p.deployment?.deployed).length}
          </div>
          <div className="portfolio-stat-label">Deployed</div>
        </div>
        <div className="portfolio-stat">
          <div className="portfolio-stat-value">
            {portfolios.filter(p => !p.deployment?.deployed).length}
          </div>
          <div className="portfolio-stat-label">In Progress</div>
        </div>
      </div>
      
      {filteredPortfolios.length === 0 ? (
        <div className="portfolio-no-results">
          <FaInfo className="no-results-icon" />
          <p>No portfolios match your search criteria.</p>
          <button 
            className="clear-search-button"
            onClick={() => {
              setSearchTerm('');
              setFilterStatus('all');
            }}
          >
            Clear Search & Filters
          </button>
        </div>
      ) : (
        <div className="portfolio-grid">
          {filteredPortfolios.map(portfolio => (
            <div key={portfolio._id} className="portfolio-item-card">
              <div className="portfolio-card-header">
                <div className="portfolio-card-title-row">
                  <h3 className="portfolio-card-title">
                    {getTemplateIcon(portfolio.preferences?.template_style)} Portfolio
                  </h3>
                  <span className={`portfolio-status-badge ${portfolio.status}`}>
                    {portfolio.deployment?.deployed ? (
                      <><FaRocket className="status-icon" /> Deployed</>
                    ) : (
                      <><FaEdit className="status-icon" /> Generated</>
                    )}
                  </span>
                </div>
                <div className="portfolio-card-meta">
                  <span className="portfolio-creation-time">
                    Created {getRelativeTime(portfolio.created_at)}
                  </span>
                </div>
              </div>
              
              <div className="portfolio-card-details">
                <div className="portfolio-detail-item">
                  <FaCalendarAlt className="detail-icon" />
                  <span className="detail-label">Created:</span>
                  <span className="detail-value">{formatDate(portfolio.created_at)}</span>
                </div>
                
                <div className="portfolio-detail-item">
                  <FaSwatchbook className="detail-icon" />
                  <span className="detail-label">Template:</span>
                  <span className="detail-value">
                    {getTemplateIcon(portfolio.preferences?.template_style)} {portfolio.preferences?.template_style || 'Custom'}
                  </span>
                </div>
                
                <div className="portfolio-detail-item">
                  <FaPalette className="detail-icon" />
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
          <li>You can create multiple portfolios with different styles and content</li>
        </ul>
      </div>
    </div>
  );
};

export default PortfolioList;
