// ========================================================================
// Portfolio Preview Component
// ========================================================================

// Portfolio Preview Component - Shows code preview and live preview
const PortfolioPreview = ({ portfolio, onBack }) => {
  const [activeTab, setActiveTab] = useState('code');
  const [activeDevice, setActiveDevice] = useState('desktop');
  const [previewLoading, setPreviewLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileContent, setFileContent] = useState(null);
  const [files, setFiles] = useState({});
  const [expandedFolders, setExpandedFolders] = useState(['src', 'styles']);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    const fetchFiles = async () => {
      setLoading(true);
      
      try {
        const response = await portfolioService.getPortfolioFiles(portfolio.id);
        
        if (response.success) {
          setFiles(response.data.files);
          
          // Set the first file as selected by default
          const firstFileName = Object.keys(response.data.files)[0];
          setSelectedFile(firstFileName);
          setFileContent(response.data.files[firstFileName]);
        } else {
          toast.error("Failed to fetch portfolio files");
        }
      } catch (error) {
        console.error("Error fetching portfolio files:", error);
        toast.error("An unexpected error occurred");
      } finally {
        setLoading(false);
      }
    };
    
    if (portfolio) {
      fetchFiles();
    }
  }, [portfolio]);
  
  const handleToggleFolder = (folder) => {
    if (expandedFolders.includes(folder)) {
      setExpandedFolders(expandedFolders.filter(f => f !== folder));
    } else {
      setExpandedFolders([...expandedFolders, folder]);
    }
  };
  
  const handleFileSelect = (fileName) => {
    setSelectedFile(fileName);
    setFileContent(files[fileName]);
  };
  
  const getFileLanguage = (fileName) => {
    if (fileName.endsWith('.js')) return 'javascript';
    if (fileName.endsWith('.css')) return 'css';
    if (fileName.endsWith('.html')) return 'html';
    if (fileName.endsWith('.json')) return 'json';
    if (fileName.endsWith('.md')) return 'markdown';
    return 'text';
  };
  
  const getFileIcon = (fileName) => {
    if (fileName.endsWith('.js')) return <FaFileCode className="js-file-icon" />;
    if (fileName.endsWith('.css')) return <FaFileCode className="css-file-icon" />;
    if (fileName.endsWith('.html')) return <FaFileCode className="html-file-icon" />;
    if (fileName.endsWith('.json')) return <FaFileCode className="json-file-icon" />;
    if (fileName.endsWith('.md')) return <FaFileCode className="md-file-icon" />;
    return <FaFileCode />;
  };
  
  const handleRefreshPreview = () => {
    setPreviewLoading(true);
    
    setTimeout(() => {
      setPreviewLoading(false);
    }, 1500);
  };
  
  return (
    <div className="portfolio-preview-container">
      <div className="portfolio-preview-header">
        <h2>Portfolio Preview</h2>
        
        <div className="portfolio-preview-tabs">
          <button 
            className={`portfolio-preview-tab ${activeTab === 'code' ? 'active' : ''}`}
            onClick={() => setActiveTab('code')}
          >
            <FaCode /> Code
          </button>
          <button 
            className={`portfolio-preview-tab ${activeTab === 'live' ? 'active' : ''}`}
            onClick={() => setActiveTab('live')}
          >
            <FaDesktop /> Live Preview
          </button>
        </div>
      </div>
      
      {activeTab === 'code' ? (
        <div className="portfolio-code-preview">
          <div className="portfolio-file-explorer">
            <div className="portfolio-file-explorer-header">
              <h3>Files</h3>
              <div className="portfolio-file-search">
                <input 
                  type="text" 
                  className="portfolio-file-search-input" 
                  placeholder="Search files..." 
                />
              </div>
            </div>
            
            <div className="portfolio-file-tree">
              {loading ? (
                <div className="loading-files">Loading files...</div>
              ) : Object.keys(files).length > 0 ? (
                <div className="portfolio-file-tree-node root-node">
                  {Object.keys(files).map(fileName => (
                    <div key={fileName} className="portfolio-file-tree-node">
                      <div 
                        className={`portfolio-file-item ${selectedFile === fileName ? 'active' : ''}`}
                        onClick={() => handleFileSelect(fileName)}
                      >
                        {getFileIcon(fileName)}
                        <span className="file-name">{fileName}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="no-files-message">No files found</div>
              )}
            </div>
          </div>
          
          <div className="portfolio-code-editor-container">
            {selectedFile ? (
              <>
                <div className="portfolio-editor-header">
                  <div className="portfolio-active-file">
                    {getFileIcon(selectedFile)}
                    <span className="file-name">{selectedFile}</span>
                  </div>
                  
                  <div className="portfolio-editor-actions">
                    <button className="portfolio-editor-action-btn">
                      <FaRegClone /> Copy
                    </button>
                    <button className="portfolio-editor-action-btn">
                      <FaFileDownload /> Download
                    </button>
                  </div>
                </div>
                
                <div className="portfolio-code-editor-wrapper">
                  <SyntaxHighlighter 
                    language={getFileLanguage(selectedFile)} 
                    style={vscDarkPlus}
                    customStyle={{ margin: 0, padding: '20px', height: '100%', fontSize: '14px' }}
                    showLineNumbers={true}
                  >
                    {fileContent}
                  </SyntaxHighlighter>
                </div>
              </>
            ) : (
              <div className="portfolio-no-file-selected">
                <FaCode className="no-file-icon" />
                <h3>No file selected</h3>
                <p>Select a file from the explorer to view its content</p>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="portfolio-live-preview-container">
          <div className="portfolio-preview-toolbar">
            <div className="portfolio-preview-device-selector">
              <button 
                className={`portfolio-device-button ${activeDevice === 'desktop' ? 'active' : ''}`}
                onClick={() => setActiveDevice('desktop')}
              >
                <FaDesktop className="device-icon" /> Desktop
              </button>
              <button 
                className={`portfolio-device-button ${activeDevice === 'mobile' ? 'active' : ''}`}
                onClick={() => setActiveDevice('mobile')}
              >
                <FaMobileAlt className="device-icon" /> Mobile
              </button>
            </div>
            
            <button 
              className="portfolio-preview-refresh-btn"
              onClick={handleRefreshPreview}
              disabled={previewLoading}
            >
              {previewLoading ? (
                <>
                  <div className="button-spinner"></div> Refreshing...
                </>
              ) : (
                <>
                  <FaSyncAlt className="refresh-icon" /> Refresh
                </>
              )}
            </button>
          </div>
          
          <div className={`portfolio-preview-frame-container ${activeDevice === 'mobile' ? 'mobile-container' : ''}`}>
            {previewLoading ? (
              <div className="preview-loading">
                <div className="preview-loading-spinner"></div>
                <p>Loading preview...</p>
              </div>
            ) : (
              <iframe 
                src="about:blank" 
                title="Portfolio Preview"
                className="portfolio-preview-frame"
                style={{ 
                  width: activeDevice === 'mobile' ? '375px' : '100%',
                  height: '100%'
                }}
              />
            )}
          </div>
        </div>
      )}
      
      <div className="portfolio-form-navigation" style={{ marginTop: '30px' }}>
        <button className="portfolio-back-button" onClick={onBack}>
          <FaUndoAlt className="button-icon" /> Back to Portfolios
        </button>
        
        {!portfolio.isDeployed && (
          <button className="portfolio-generate-button">
            <FaRocket className="button-icon" /> Deploy Portfolio
          </button>
        )}
      </div>
    </div>
  );
};
