// frontend/my-react-app/src/components/pages/Portfolio/PortfolioPreview.js
import React, { useState, useEffect } from 'react';
import CodeEditor from './CodeEditor';
import './portfolio.css';

const PortfolioPreview = ({ portfolio, userId, onFixError }) => {
  const [activeFile, setActiveFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [previewMode, setPreviewMode] = useState('code'); // 'code' or 'preview'
  const [errorMessage, setErrorMessage] = useState(null);

  useEffect(() => {
    // Set the first file as active by default
    if (portfolio && portfolio.components) {
      const files = Object.keys(portfolio.components);
      if (files.length > 0) {
        handleFileSelect(files[0]);
      }
    }
  }, [portfolio]);

  const handleFileSelect = (filePath) => {
    setActiveFile(filePath);
    
    if (portfolio.components[filePath]) {
      setFileContent(portfolio.components[filePath]);
    } else {
      setFileContent('');
    }
  };

  const handleFixError = async () => {
    if (!errorMessage || !activeFile) return;
    
    try {
      onFixError(true);
      
      const response = await fetch('/api/portfolio/fix-error', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-Id': userId
        },
        body: JSON.stringify({
          portfolio_id: portfolio._id,
          component_path: activeFile,
          error_message: errorMessage
        })
      });
      
      if (!response.ok) {
        throw new Error('Failed to fix error');
      }
      
      const data = await response.json();
      
      // Update the file content with the fixed code
      setFileContent(data.fixed_code);
      setErrorMessage(null);
      
      onFixError(false);
      
    } catch (err) {
      console.error('Error fixing code:', err);
      setErrorMessage('Failed to fix the error. Please try again.');
      onFixError(false);
    }
  };

  const getFileIcon = (filePath) => {
    if (filePath.endsWith('.js')) return '📄';
    if (filePath.endsWith('.css')) return '🎨';
    if (filePath.endsWith('.html')) return '🌐';
    if (filePath.endsWith('.json')) return '📦';
    return '📝';
  };

  const getFileLanguage = (filePath) => {
    if (filePath.endsWith('.js')) return 'javascript';
    if (filePath.endsWith('.css')) return 'css';
    if (filePath.endsWith('.html')) return 'html';
    if (filePath.endsWith('.json')) return 'json';
    return 'text';
  };

  const renderFileTree = () => {
    if (!portfolio || !portfolio.components) return null;
    
    // Group files by directory
    const filesByDir = {};
    Object.keys(portfolio.components).forEach(filePath => {
      const parts = filePath.split('/');
      const dir = parts.slice(0, -1).join('/');
      const fileName = parts[parts.length - 1];
      
      if (!filesByDir[dir]) filesByDir[dir] = [];
      filesByDir[dir].push({ path: filePath, name: fileName });
    });
    
    // Sort directories
    const sortedDirs = Object.keys(filesByDir).sort();
    
    return (
      <div className="file-tree">
        {sortedDirs.map(dir => (
          <div key={dir} className="file-directory">
            <div className="directory-name">📁 {dir || 'Root'}</div>
            <div className="directory-files">
              {filesByDir[dir].sort().map(file => (
                <div 
                  key={file.path}
                  className={`file-item ${activeFile === file.path ? 'active' : ''}`}
                  onClick={() => handleFileSelect(file.path)}
                >
                  {getFileIcon(file.name)} {file.name}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    );
  };

  const renderIframePreview = () => {
    // This is a simplified preview that would work for simple HTML content
    // In a real app, you'd want to setup a more sophisticated preview system
    if (!portfolio || !portfolio.components) return null;
    
    // For demo purposes, we'll just render the index.html if available
    const htmlContent = portfolio.components['public/index.html'] || '';
    
    return (
      <div className="iframe-preview">
        <iframe
          title="Portfolio Preview"
          srcDoc={htmlContent}
          sandbox="allow-scripts allow-same-origin"
          width="100%"
          height="100%"
        />
      </div>
    );
  };

  if (!portfolio) {
    return <div className="no-portfolio">No portfolio selected</div>;
  }

  return (
    <div className="portfolio-preview-container">
      <div className="preview-header">
        <h2>Portfolio Preview</h2>
        <div className="preview-tabs">
          <button 
            className={`preview-tab ${previewMode === 'code' ? 'active' : ''}`}
            onClick={() => setPreviewMode('code')}
          >
            Code Editor
          </button>
          <button 
            className={`preview-tab ${previewMode === 'preview' ? 'active' : ''}`}
            onClick={() => setPreviewMode('preview')}
          >
            Live Preview
          </button>
        </div>
      </div>
      
      {previewMode === 'code' ? (
        <div className="code-preview">
          <div className="file-explorer">
            <h3>Files</h3>
            {renderFileTree()}
          </div>
          
          <div className="code-editor-container">
            {activeFile ? (
              <>
                <div className="editor-header">
                  <span>{activeFile}</span>
                </div>
                <CodeEditor
                  value={fileContent}
                  language={getFileLanguage(activeFile)}
                  theme="vs-dark"
                  onChange={setFileContent}
                  onError={setErrorMessage}
                />
                {errorMessage && (
                  <div className="error-container">
                    <div className="error-message">{errorMessage}</div>
                    <button className="fix-error-button" onClick={handleFixError}>
                      Fix Error
                    </button>
                  </div>
                )}
              </>
            ) : (
              <div className="no-file-selected">Select a file to view and edit</div>
            )}
          </div>
        </div>
      ) : (
        renderIframePreview()
      )}
    </div>
  );
};

export default PortfolioPreview;
