// frontend/my-react-app/src/components/pages/Portfolio/PortfolioPreview.js
import React, { useState, useEffect, useCallback } from 'react';
import CodeEditor from './CodeEditor';
import './portfolio.css';

const PortfolioPreview = ({ portfolio, userId, onFixError }) => {
  const [activeFile, setActiveFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [previewMode, setPreviewMode] = useState('code'); // 'code' or 'preview'
  const [errorMessage, setErrorMessage] = useState(null);
  const [isFixingError, setIsFixingError] = useState(false);
  const [previewHtml, setPreviewHtml] = useState('');
  const [fileTree, setFileTree] = useState({});

  // Process portfolio data when it changes
  useEffect(() => {
    if (portfolio && portfolio.components) {
      // Organize files into a tree structure
      const tree = organizeFilesIntoTree(portfolio.components);
      setFileTree(tree);
      
      // Set the first file as active by default or maintain current selection
      const files = Object.keys(portfolio.components);
      if (files.length > 0) {
        if (!activeFile || !portfolio.components[activeFile]) {
          handleFileSelect(files[0]);
        } else {
          // Update content for currently selected file
          setFileContent(portfolio.components[activeFile]);
        }
      }
      
      // Generate preview HTML
      generatePreviewHtml(portfolio.components);
    }
  }, [portfolio, activeFile]);

  // Organize files into directory structure
  const organizeFilesIntoTree = (components) => {
    const tree = {};
    
    Object.keys(components).forEach(filePath => {
      const parts = filePath.split('/');
      let currentLevel = tree;
      
      // Build the tree structure
      for (let i = 0; i < parts.length - 1; i++) {
        const part = parts[i];
        if (!currentLevel[part]) {
          currentLevel[part] = { __isDir: true };
        }
        currentLevel = currentLevel[part];
      }
      
      // Add the file at the correct level
      const fileName = parts[parts.length - 1];
      currentLevel[fileName] = { __filePath: filePath };
    });
    
    return tree;
  };

  // Generate preview HTML from portfolio components
  const generatePreviewHtml = useCallback((components) => {
    // First check if we have the necessary files
    const htmlFile = components['public/index.html'] || '';
    
    if (!htmlFile) {
      setPreviewHtml('<div style="padding: 20px; color: #666;">No HTML template found</div>');
      return;
    }
    
    // Basic strategy: inject CSS and JS into the HTML template
    let processedHtml = htmlFile;
    
    // Inject CSS
    const cssContent = Object.entries(components)
      .filter(([key]) => key.endsWith('.css'))
      .map(([_, content]) => content)
      .join('\n');
    
    // Inject inline CSS
    const styleTag = `<style>${cssContent}</style>`;
    processedHtml = processedHtml.replace('</head>', `${styleTag}</head>`);
    
    // For JS, we'll add script tags but with a warning that full execution isn't supported
    processedHtml = processedHtml.replace(
      '</body>',
      `<div style="position: fixed; bottom: 0; left: 0; right: 0; background: #f8d7da; color: #721c24; padding: 10px; font-size: 12px; text-align: center;">
        ⚠️ This is a simplified preview. JavaScript functionality is limited. Check the console for any errors.
      </div></body>`
    );
    
    setPreviewHtml(processedHtml);
  }, []);

  const handleFileSelect = (filePath) => {
    setActiveFile(filePath);
    
    if (portfolio && portfolio.components && portfolio.components[filePath]) {
      setFileContent(portfolio.components[filePath]);
      
      // Clear any previous error when switching files
      setErrorMessage(null);
    } else {
      setFileContent('');
    }
  };

  const handleUpdateFileContent = (newContent) => {
    setFileContent(newContent);
    
    // Here we would typically update the portfolio object
    // This would require an API call to save the changes
    // For now, we'll just update the local state
  };

  const handleFixError = async () => {
    if (!errorMessage || !activeFile) return;
    
    try {
      setIsFixingError(true);
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
          error_message: errorMessage,
          component_code: fileContent
        })
      });
      
      if (!response.ok) {
        throw new Error('Failed to fix error');
      }
      
      const data = await response.json();
      
      // Update the file content with the fixed code
      setFileContent(data.fixed_code);
      setErrorMessage(null);
      
      // Update the portfolio object locally
      const updatedComponents = {
        ...portfolio.components,
        [activeFile]: data.fixed_code
      };
      
      // Regenerate preview HTML
      generatePreviewHtml(updatedComponents);
      
      setIsFixingError(false);
      onFixError(false);
      
    } catch (err) {
      console.error('Error fixing code:', err);
      setErrorMessage(`Failed to fix the error: ${err.message}. Please try again.`);
      setIsFixingError(false);
      onFixError(false);
    }
  };

  const getFileIcon = (filePath) => {
    if (filePath.endsWith('.js') || filePath.endsWith('.jsx')) return '📄';
    if (filePath.endsWith('.css')) return '🎨';
    if (filePath.endsWith('.html')) return '🌐';
    if (filePath.endsWith('.json')) return '📦';
    if (filePath.endsWith('.svg')) return '🖼️';
    if (filePath.endsWith('.md')) return '📝';
    return '📄';
  };

  const getFileLanguage = (filePath) => {
    if (filePath.endsWith('.js')) return 'javascript';
    if (filePath.endsWith('.jsx')) return 'javascript';
    if (filePath.endsWith('.css')) return 'css';
    if (filePath.endsWith('.html')) return 'html';
    if (filePath.endsWith('.json')) return 'json';
    if (filePath.endsWith('.svg')) return 'xml';
    if (filePath.endsWith('.md')) return 'markdown';
    return 'plaintext';
  };

  // Recursive function to render the file tree
  const renderFileTreeNode = (node, path = '', isRoot = true) => {
    if (!node) return null;
    
    // Sort entries: directories first, then files
    const entries = Object.entries(node).sort((a, b) => {
      // Skip the __isDir and __filePath special properties
      if (a[0] === '__isDir' || a[0] === '__filePath') return 1;
      if (b[0] === '__isDir' || b[0] === '__filePath') return -1;
      
      // Directories before files
      const aIsDir = a[1].__isDir;
      const bIsDir = b[1].__isDir;
      if (aIsDir && !bIsDir) return -1;
      if (!aIsDir && bIsDir) return 1;
      
      // Alphabetical order within same type
      return a[0].localeCompare(b[0]);
    });
    
    return (
      <div className={`portfolio-file-tree-node ${isRoot ? 'root-node' : ''}`}>
        {entries.map(([name, value]) => {
          // Skip special properties
          if (name === '__isDir' || name === '__filePath') return null;
          
          const fullPath = path ? `${path}/${name}` : name;
          
          if (value.__isDir) {
            // Directory node
            return (
              <div key={fullPath} className="portfolio-directory-node">
                <div className="portfolio-directory-name">
                  <span className="directory-icon">📁</span>
                  <span className="directory-label">{name}</span>
                </div>
                <div className="portfolio-directory-children">
                  {renderFileTreeNode(value, fullPath, false)}
                </div>
              </div>
            );
          } else if (value.__filePath) {
            // File node
            const filePath = value.__filePath;
            return (
              <div 
                key={filePath}
                className={`portfolio-file-item ${activeFile === filePath ? 'active' : ''}`}
                onClick={() => handleFileSelect(filePath)}
              >
                <span className="file-icon">{getFileIcon(filePath)}</span>
                <span className="file-name">{name}</span>
              </div>
            );
          }
          
          return null;
        })}
      </div>
    );
  };

  if (!portfolio) {
    return <div className="portfolio-no-portfolio">No portfolio selected</div>;
  }

  return (
    <div className="portfolio-preview-container">
      <div className="portfolio-preview-header">
        <h2>Portfolio Preview</h2>
        <div className="portfolio-preview-tabs">
          <button 
            className={`portfolio-preview-tab ${previewMode === 'code' ? 'active' : ''}`}
            onClick={() => setPreviewMode('code')}
          >
            <span className="tab-icon">💻</span>
            Code Editor
          </button>
          <button 
            className={`portfolio-preview-tab ${previewMode === 'preview' ? 'active' : ''}`}
            onClick={() => setPreviewMode('preview')}
          >
            <span className="tab-icon">👁️</span>
            Live Preview
          </button>
        </div>
      </div>
      
      {previewMode === 'code' ? (
        <div className="portfolio-code-preview">
          <div className="portfolio-file-explorer">
            <div className="portfolio-file-explorer-header">
              <h3>Files</h3>
              <div className="portfolio-file-search">
                <input 
                  type="text" 
                  placeholder="Search files..."
                  className="portfolio-file-search-input"
                />
              </div>
            </div>
            <div className="portfolio-file-tree">
              {renderFileTreeNode(fileTree)}
            </div>
          </div>
          
          <div className="portfolio-code-editor-container">
            {activeFile ? (
              <>
                <div className="portfolio-editor-header">
                  <div className="portfolio-active-file">
                    <span className="file-icon">{getFileIcon(activeFile)}</span>
                    <span className="file-path">{activeFile}</span>
                  </div>
                  <div className="portfolio-editor-actions">
                    <button className="portfolio-editor-action-btn">
                      <span>Format</span>
                    </button>
                  </div>
                </div>
                <CodeEditor
                  value={fileContent}
                  language={getFileLanguage(activeFile)}
                  theme="vs-dark"
                  onChange={handleUpdateFileContent}
                  onError={setErrorMessage}
                />
                {errorMessage && (
                  <div className="portfolio-error-container">
                    <div className="portfolio-error-message">
                      <span className="error-icon">⚠️</span>
                      <span className="error-text">{errorMessage}</span>
                    </div>
                    <button 
                      className="portfolio-fix-error-button"
                      onClick={handleFixError}
                      disabled={isFixingError}
                    >
                      {isFixingError ? (
                        <>
                          <span className="fix-spinner"></span>
                          <span>Fixing...</span>
                        </>
                      ) : (
                        <>
                          <span className="fix-icon">🔧</span>
                          <span>Auto-Fix Error</span>
                        </>
                      )}
                    </button>
                  </div>
                )}
              </>
            ) : (
              <div className="portfolio-no-file-selected">
                <div className="no-file-icon">📁</div>
                <h3>No file selected</h3>
                <p>Select a file from the explorer to view and edit</p>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="portfolio-live-preview-container">
          <div className="portfolio-preview-toolbar">
            <div className="portfolio-preview-device-selector">
              <button className="portfolio-device-button active">
                <span className="device-icon">💻</span>
                <span>Desktop</span>
              </button>
              <button className="portfolio-device-button">
                <span className="device-icon">📱</span>
                <span>Mobile</span>
              </button>
            </div>
            <button className="portfolio-preview-refresh-btn">
              <span className="refresh-icon">🔄</span>
              <span>Refresh</span>
            </button>
          </div>
          <div className="portfolio-preview-frame-container">
            <iframe
              className="portfolio-preview-frame"
              title="Portfolio Preview"
              srcDoc={previewHtml}
              sandbox="allow-scripts allow-same-origin"
              width="100%"
              height="100%"
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default PortfolioPreview;
