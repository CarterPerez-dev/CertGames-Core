// Portfolio Deployment Component - Handles deployment process and success
const PortfolioDeployment = ({ portfolio, onBack, onComplete }) => {
  const [deploymentStatus, setDeploymentStatus] = useState('processing'); // 'processing', 'success', 'error'
  const [deploymentProgress, setDeploymentProgress] = useState(0);
  const [deployedUrl, setDeployedUrl] = useState('');
  const [activeStage, setActiveStage] = useState(1);
  const [completedStages, setCompletedStages] = useState([]);
  const [copied, setCopied] = useState(false);
  
  useEffect(() => {
    const simulateDeployment = async () => {
      // Stage 1: Preparing files
      setActiveStage(1);
      await sleep(2000);
      setCompletedStages(prev => [...prev, 1]);
      setDeploymentProgress(25);
      
      // Stage 2: Building optimized version
      setActiveStage(2);
      await sleep(3000);
      setCompletedStages(prev => [...prev, 2]);
      setDeploymentProgress(50);
      
      // Stage 3: Uploading to servers
      setActiveStage(3);
      await sleep(2500);
      setCompletedStages(prev => [...prev, 3]);
      setDeploymentProgress(75);
      
      // Stage 4: Configuring domain
      setActiveStage(4);
      await sleep(2000);
      setCompletedStages(prev => [...prev, 4]);
      setDeploymentProgress(100);
      
      // Complete deployment
      const result = await portfolioService.deployPortfolio(portfolio.id);
      
      if (result.success) {
        setDeployedUrl(result.data.deployedUrl);
        setDeploymentStatus('success');
      } else {
        setDeploymentStatus('error');
      }
    };
    
    simulateDeployment();
  }, [portfolio.id]);
  
  const deploymentStages = [
    {
      id: 1,
      title: 'Preparing Files',
      description: 'Optimizing your content and assets for deployment'
    },
    {
      id: 2,
      title: 'Building Portfolio',
      description: 'Generating optimized production version of your portfolio'
    },
    {
      id: 3,
      title: 'Uploading to Servers',
      description: 'Transferring files to our high-performance hosting platform'
    },
    {
      id: 4,
      title: 'Configuring Domain',
      description: 'Setting up domain and SSL certificates'
    }
  ];
  
  const handleCopyUrl = () => {
    navigator.clipboard.writeText(deployedUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  
  if (deploymentStatus === 'processing') {
    return (
      <div className="portfolio-deployment-container">
        <div className="portfolio-deployment-header">
          <div className="deployment-title-icon">
            <FaRocket />
          </div>
          <h2>Deploying Your Portfolio</h2>
          <p className="portfolio-deployment-subtitle">
            We're setting everything up for you
          </p>
        </div>
        
        <div className="portfolio-deployment-processing">
          <div className="deployment-processing-animation">
            <div className="processing-circle"></div>
          </div>
          
          <div className="deployment-processing-text">
            <h3>Deployment in Progress</h3>
            <p>
              We're deploying your portfolio to our high-performance hosting platform.
              This usually takes about 1-2 minutes to complete.
            </p>
          </div>
          
          <div className="deployment-stages">
            {deploymentStages.map(stage => (
              <div 
                key={stage.id} 
                className={`deployment-stage ${activeStage === stage.id ? 'active' : ''} ${completedStages.includes(stage.id) ? 'completed' : ''}`}
              >
                <div className="stage-indicator">
                  {completedStages.includes(stage.id) ? (
                    <FaCheck className="stage-check-icon" />
                  ) : (
                    stage.id
                  )}
                </div>
                <div className="stage-content">
                  <h4 className="stage-title">{stage.title}</h4>
                  <p className="stage-description">{stage.description}</p>
                </div>
              </div>
            ))}
          </div>
          
          <div className="deployment-time-estimate">
            <FaClock className="deployment-time-icon" />
            Estimated time remaining: {Math.max(0, 2 - Math.ceil(deploymentProgress / 50))} minutes
          </div>
          
          <button className="deployment-cancel-button">
            <FaUndoAlt /> Cancel Deployment
          </button>
        </div>
      </div>
    );
  }
  
  if (deploymentStatus === 'success') {
    return (
      <div className="portfolio-deployment-container">
        <div className="portfolio-deployment-header">
          <div className="deployment-title-icon">
            <FaRocket />
          </div>
          <h2>Deployment Successful</h2>
          <p className="portfolio-deployment-subtitle">
            Your portfolio is now live and ready to share
          </p>
        </div>
        
        <div className="portfolio-deployment-success">
          <div className="deployment-success-header">
            <FaCheckCircle className="deployment-success-icon" />
            <h3>Your Portfolio is Live!</h3>
          </div>
          
          <div className="deployment-success-content">
            <p>
              Congratulations! Your portfolio has been successfully deployed and is now accessible worldwide.
              Your site is optimized for speed and performance, with SSL encryption for security.
            </p>
            
            <div className="deployment-url-container">
              <div className="deployment-url-header">
                <FaLink className="url-icon" />
                <h4>Your Portfolio URL</h4>
              </div>
              
              <div className="deployment-url-display">
                <a 
                  href={deployedUrl} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="portfolio-url-link"
                >
                  {deployedUrl}
                </a>
                
                <button 
                  className={`copy-url-button ${copied ? 'copied' : ''}`}
                  onClick={handleCopyUrl}
                >
                  {copied ? (
                    <>
                      <FaCheck /> Copied!
                    </>
                  ) : (
                    <>
                      <FaCopy /> Copy URL
                    </>
                  )}
                </button>
              </div>
            </div>
            
            <div className="deployment-success-actions">
              <a 
                href={deployedUrl} 
                target="_blank" 
                rel="noopener noreferrer"
                className="portfolio-view-live-button"
              >
                <FaExternalLinkAlt /> View Live Site
              </a>
              
              <button className="portfolio-customization-button" onClick={onComplete}>
                <FaUndoAlt /> Back to Portfolios
              </button>
            </div>
          </div>
        </div>
        
        <div className="deployment-share-options">
          <div className="share-options-header">
            <h3>Share Your Portfolio</h3>
            <p>Let the world know about your new professional portfolio</p>
          </div>
          
          <div className="share-options-grid">
            <div className="share-option-card">
              <FaTwitter className="share-platform-icon" />
              <h4>Share on Twitter</h4>
              <p>
                Share your portfolio with your professional network on Twitter/X
              </p>
              <button className="share-platform-button">
                <FaTwitter /> Share on Twitter
              </button>
            </div>
            
            <div className="share-option-card">
              <FaLinkedin className="share-platform-icon" />
              <h4>Share on LinkedIn</h4>
              <p>
                Add your portfolio to your LinkedIn profile for better visibility
              </p>
              <button className="share-platform-button">
                <FaLinkedin /> Share on LinkedIn
              </button>
            </div>
            
            <div className="share-option-card">
              <FaEnvelope className="share-platform-icon" />
              <h4>Share via Email</h4>
              <p>
                Send your portfolio directly to recruiters or potential clients
              </p>
              <button className="share-platform-button">
                <FaEnvelope /> Compose Email
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }
  
  // Error state
  return (
    <div className="portfolio-deployment-container">
      <div className="portfolio-deployment-header">
        <div className="deployment-title-icon">
          <FaExclamationCircle />
        </div>
        <h2>Deployment Failed</h2>
        <p className="portfolio-deployment-subtitle">
          We encountered an issue while deploying your portfolio
        </p>
      </div>
      
      {/* Error content would go here */}
      
      <div className="portfolio-form-navigation">
        <button className="portfolio-back-button" onClick={onBack}>
          <FaUndoAlt className="button-icon" /> Back to Preview
        </button>
        
        <button className="portfolio-next-button">
          <FaSyncAlt className="button-icon" /> Try Again
        </button>
      </div>
    </div>
  );
};

export default PortfolioPage;
