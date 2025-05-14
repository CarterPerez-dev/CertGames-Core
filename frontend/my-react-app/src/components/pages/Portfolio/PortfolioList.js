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
