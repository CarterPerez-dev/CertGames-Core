// frontend/my-react-app/src/components/pages/Portfolio/PortfolioPreview.js
import React, { useState, useEffect, useRef } from 'react';
import CodeEditor from './CodeEditor';
import { FaCode, FaInfo, FaFile, FaFolder, FaExclamationTriangle, FaWrench, FaCopy, FaSync, FaCheck, FaQuestionCircle, FaInfoCircle, FaListAlt, FaLightbulb, FaGithub } from 'react-icons/fa';
import './portfolio.css';

const PortfolioPreview = ({ portfolio, userId, onFixError }) => {
  const [activeFile, setActiveFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [previewMode, setPreviewMode] = useState('code'); // 'code' or 'help'
  const [errorMessage, setErrorMessage] = useState(null);
  const [isFixingError, setIsFixingError] = useState(false);
  const [fileTree, setFileTree] = useState({});
  const [searchQuery, setSearchQuery] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Process portfolio data when it changes
  useEffect(() => {
    if (portfolio && portfolio.components) {
      console.log("Portfolio provided to editor:", {
        id: portfolio._id,
        componentCount: Object.keys(portfolio.components).length,
        componentKeys: Object.keys(portfolio.components)
      });
      
      // If no components, log warning and set error
      if (Object.keys(portfolio.components).length === 0) {
        console.error("Portfolio has no components");
        setErrorMessage("Portfolio data is incomplete. No components found.");
        return;
      }
      
      // Organize files into a tree structure
      const tree = organizeFilesIntoTree(portfolio.components);
      setFileTree(tree);
      
      // If we have a portfolio but no activeFile is set, set the first file as active
      if (!activeFile || !portfolio.components[activeFile]) {
        const files = Object.keys(portfolio.components);
        if (files.length > 0) {
          const defaultFile = files.find(f => f.endsWith('App.js')) || files[0];
          console.log(`Setting default active file: ${defaultFile}`);
          handleFileSelect(defaultFile);
        }
      }
    }
  }, [portfolio]);

  // Organize files into directory structure
  const organizeFilesIntoTree = (components) => {
    console.log("Organizing file tree structure");
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

  const handleFileSelect = (filePath) => {
    console.log(`Selecting file: ${filePath}`);
    setActiveFile(filePath);
    
    if (portfolio && portfolio.components && portfolio.components[filePath]) {
      setFileContent(portfolio.components[filePath]);
      
      // Clear any previous error when switching files
      setErrorMessage(null);
    } else {
      console.warn(`File not found in portfolio components: ${filePath}`);
      setFileContent('');
    }
  };

  const handleUpdateFileContent = (newContent) => {
    if (newContent === fileContent) return;
    
    console.log(`Updating content for file: ${activeFile}`);
    setFileContent(newContent);
    
    // Update the portfolio object locally
    if (portfolio && portfolio.components) {
      const updatedComponents = {
        ...portfolio.components,
        [activeFile]: newContent
      };
      
      // Add log for file update
      console.log(`Updated content for ${activeFile}`);
    }
  };

  const handleFixError = async () => {
    if (!errorMessage || !activeFile) {
      console.warn("Cannot fix error: No error message or active file");
      return;
    }
    
    try {
      console.log(`Attempting to fix error in ${activeFile}:`, errorMessage);
      setIsFixingError(true);
      if (onFixError) onFixError(true);
      
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
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to fix error');
      }
      
      const data = await response.json();
      console.log("Error fixed successfully");
      
      // Update the file content with the fixed code
      setFileContent(data.fixed_code);
      setErrorMessage(null);
      
      setIsFixingError(false);
      if (onFixError) onFixError(false);
      
    } catch (err) {
      console.error('Error fixing code:', err);
      setErrorMessage(`Failed to fix the error: ${err.message}. Please try again.`);
      setIsFixingError(false);
      if (onFixError) onFixError(false);
    }
  };


  
  const handleSaveFile = async (filePath, content) => {
    try {
      setIsSaving(true);
      
      const response = await fetch('/api/portfolio/update-file', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-Id': userId
        },
        body: JSON.stringify({
          portfolio_id: portfolio._id,
          file_path: filePath,
          content: content
        })
      });
      
      if (!response.ok) {
        throw new Error('Failed to save file');
      }
      
      // Show success message
      setSuccessMessage('File saved successfully');
      setTimeout(() => setSuccessMessage(null), 3000);
      
    } catch (err) {
      setErrorMessage('Error saving file: ' + err.message);
    } finally {
      setIsSaving(false);
    }
  };
  
  const handleCreateFile = async (filePath) => {
    try {
      if (!filePath) {
        setErrorMessage('File path is required');
        return;
      }
      
      const response = await fetch('/api/portfolio/create-file', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-Id': userId
        },
        body: JSON.stringify({
          portfolio_id: portfolio._id,
          file_path: filePath,
          content: '// New file created'
        })
      });
      
      if (!response.ok) {
        throw new Error('Failed to create file');
      }
      
      // Update the file tree and select the new file
      const data = await response.json();
      
      // Update the local file tree
      setFileTree(prevTree => {
        const newTree = {...prevTree};
        // Add the new file to the tree (simplified - would need more logic for nested paths)
        const fileName = filePath.split('/').pop();
        const dirPath = filePath.substring(0, filePath.lastIndexOf('/'));
        
        // Create directory structure if needed
        let currentLevel = newTree;
        dirPath.split('/').forEach(part => {
          if (!currentLevel[part]) {
            currentLevel[part] = { __isDir: true };
          }
          currentLevel = currentLevel[part];
        });
        
        // Add the file
        currentLevel[fileName] = { __filePath: filePath };
        
        return newTree;
      });
      
      // Select the new file
      handleFileSelect(filePath);
      
    } catch (err) {
      setErrorMessage('Error creating file: ' + err.message);
    }
  };

  const getFileIcon = (filePath) => {
    if (filePath.endsWith('.js') || filePath.endsWith('.jsx')) return <FaFile className="js-file-icon" />;
    if (filePath.endsWith('.css')) return <FaFile className="css-file-icon" />;
    if (filePath.endsWith('.html')) return <FaFile className="html-file-icon" />;
    if (filePath.endsWith('.json')) return <FaFile className="json-file-icon" />;
    if (filePath.endsWith('.svg')) return <FaFile className="svg-file-icon" />;
    if (filePath.endsWith('.md')) return <FaFile className="md-file-icon" />;
    return <FaFile />;
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

  // Filter files based on search query
  const filterFiles = (node, path = '', results = {}, parentMatched = false) => {
    if (!node) return results;
    
    if (searchQuery.trim() === '') return node;
    
    const searchLower = searchQuery.toLowerCase();
    let nodeMatched = parentMatched;
    
    // Copy non-file/dir properties
    const filteredNode = {};
    Object.entries(node).forEach(([key, value]) => {
      if (key === '__isDir' || key === '__filePath') {
        filteredNode[key] = value;
      }
    });
    
    // Process entries
    Object.entries(node).forEach(([name, value]) => {
      if (name === '__isDir' || name === '__filePath') return;
      
      const fullPath = path ? `${path}/${name}` : name;
      
      if (value.__isDir) {
        // It's a directory
        const matchesSearch = name.toLowerCase().includes(searchLower);
        const subResults = filterFiles(value, fullPath, {}, matchesSearch || parentMatched);
        
        // Check if there are any entries in the filtered subdirectory
        const hasMatchingChildren = Object.keys(subResults).some(key => 
          key !== '__isDir' && key !== '__filePath'
        );
        
        if (matchesSearch || hasMatchingChildren) {
          filteredNode[name] = subResults;
          nodeMatched = true;
        }
      } else if (value.__filePath) {
        // It's a file
        const filePath = value.__filePath;
        if (name.toLowerCase().includes(searchLower) || parentMatched) {
          filteredNode[name] = { __filePath: filePath };
          nodeMatched = true;
        }
      }
    });
    
    return nodeMatched ? filteredNode : {};
  };

  const filteredFileTree = searchQuery.trim() ? filterFiles(fileTree) : fileTree;

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
                  <FaFolder className="directory-icon" />
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
                {getFileIcon(filePath)}
                <span className="file-name">{name}</span>
              </div>
            );
          }
          
          return null;
        })}
      </div>
    );
  };

  // FAQ/Help content for the Help tab
    const renderHelpContent = () => {
      return (
        <div className="portfolio-help-content">
          <div className="help-section">
            <h3><FaInfoCircle /> About Your Portfolio</h3>
            <p>This is your generated portfolio project. You can view and edit all the code files in the Code Editor tab. Here are some answers to common questions:</p>
          </div>
          
          <div className="help-section">
            <h3><FaQuestionCircle /> Frequently Asked Questions</h3>
            
            <div className="help-question">
              <h4>What files make up my portfolio?</h4>
              <p>Your portfolio consists of:</p>
              <ul>
                <li><strong>public/index.html</strong> - The main HTML template</li>
                <li><strong>src/index.js</strong> - The entry point for React</li>
                <li><strong>src/App.js</strong> - The main React component</li>
                <li><strong>src/components/</strong> - Individual UI components</li>
                <li><strong>*.css files</strong> - Styling for your components</li>
              </ul>
            </div>
            
            <div className="help-question">
              <h4>How do I edit my portfolio?</h4>
              <p>Use the Code Editor tab to edit any file. Changes are saved automatically. If you encounter errors, the Auto-Fix feature can help resolve common issues.</p>
            </div>
            
            <div className="help-question">
              <h4>How do I view my portfolio?</h4>
              <p>To see your portfolio, you'll need to deploy it using the Deploy tab. After deployment, you'll receive a live URL to share with others.</p>
            </div>
            
            <div className="help-question">
              <h4>What if I want to change my portfolio content?</h4>
              <p>Edit the text directly in the components. For example, to change your personal information, find the component that displays it (often in a file like About.js or Home.js) and update the text.</p>
            </div>
            
            <div className="help-question">
              <h4>Can I add more pages or sections?</h4>
              <p>Yes! You can create new components in the src/components folder and import them in your App.js or other existing components.</p>
            </div>
          </div>
          
          <div className="help-section">
            <h3><FaLightbulb /> Tips for Editing</h3>
            <ul>
              <li>Use the search function to quickly find files</li>
              <li>Check App.js to understand the structure of your portfolio</li>
              <li>CSS files control the appearance - look there to change colors, spacing, etc.</li>
              <li>If you break something, don't worry! Use the Auto-Fix feature or revert your changes</li>
              <li>Remember to save your changes before deploying</li>
            </ul>
          </div>
          
          <div className="help-section">
            <h3><FaListAlt /> Common Tasks</h3>
            <div className="common-tasks">
              <div className="task-item">
                <h4>Changing Colors</h4>
                <p>Look for CSS variables (often in index.css) or color values like #ffffff or rgb(0,0,0) in CSS files.</p>
              </div>
              
              <div className="task-item">
                <h4>Updating Your Information</h4>
                <p>Search for placeholder text in component files (like "John Doe" or "Lorem ipsum") and replace with your info.</p>
              </div>
              
              <div className="task-item">
                <h4>Adding Projects</h4>
                <p>Find the projects component and add new project entries following the existing pattern.</p>
              </div>
              
              <div className="task-item">
                <h4>Fixing Layout Issues</h4>
                <p>Check the CSS files for the component with layout problems. Look for properties like margin, padding, display, and flex.</p>
              </div>
            </div>
          </div>
          
          {/* New Deployment Documentation Section */}
          <div className="help-section deployment-docs">
            <h3><FaGithub /> Deploying Your Portfolio</h3>
            
            <div className="deployment-help-section">
              <h3>How to Deploy Your Portfolio</h3>
              <ol className="deployment-steps">
                <li>
                  <strong>Step 1: Create a GitHub Token</strong>
                  <p>Visit <a href="https://github.com/settings/tokens/new" target="_blank" rel="noopener noreferrer">GitHub Token Settings</a> to create a new token with 'repo' and 'workflow' permissions.</p>
                </li>
                <li>
                  <strong>Step 2: Create a Vercel Token</strong>
                  <p>Visit <a href="https://vercel.com/account/tokens" target="_blank" rel="noopener noreferrer">Vercel Token Settings</a> to create a new token with full account permissions.</p>
                </li>
                <li>
                  <strong>Step 3: Enter Your Tokens</strong>
                  <p>Enter both tokens in the form on the Deploy tab and click "Deploy Portfolio".</p>
                </li>
                <li>
                  <strong>Step 4: Wait for Deployment</strong>
                  <p>The deployment process takes approximately 2-5 minutes. Do not close the window during deployment.</p>
                </li>
              </ol>
            </div>
            
            <div className="deployment-troubleshooting">
              <h3>Troubleshooting</h3>
              <div className="troubleshooting-item">
                <h4>Invalid Token Error</h4>
                <p>Make sure your tokens have the correct permissions and have not expired. When creating a GitHub token, ensure it has the 'repo' and 'workflow' permissions.</p>
              </div>
              <div className="troubleshooting-item">
                <h4>Deployment Failed</h4>
                <p>Check your portfolio code for errors. Common issues include invalid imports or syntax errors. Use the Code Editor to fix issues before deploying.</p>
              </div>
              <div className="troubleshooting-item">
                <h4>GitHub Rate Limit Exceeded</h4>
                <p>GitHub has rate limits for API calls. If you receive this error, wait an hour before trying again.</p>
              </div>
              <div className="troubleshooting-item">
                <h4>Deployment Stuck</h4>
                <p>If deployment appears stuck for more than 10 minutes, try refreshing the page and starting the deployment process again.</p>
              </div>
            </div>
          </div>
        </div>
      );
    };

  if (!portfolio) {
    return (
      <div className="portfolio-preview-container portfolio-no-portfolio">
        <div className="portfolio-empty-message">
          <FaInfo className="empty-icon" />
          <h3>No Portfolio Selected</h3>
          <p>Create or select a portfolio to edit</p>
        </div>
      </div>
    );
  }

  return (
    <div className="portfolio-preview-container">
      <div className="portfolio-preview-header">
        <h2>Portfolio Editor</h2>
        <div className="portfolio-preview-tabs">
          <button 
            className={`portfolio-preview-tab ${previewMode === 'code' ? 'active' : ''}`}
            onClick={() => setPreviewMode('code')}
          >
            <FaCode className="tab-icon" />
            Code Editor
          </button>
          <button 
            className={`portfolio-preview-tab ${previewMode === 'help' ? 'active' : ''}`}
            onClick={() => setPreviewMode('help')}
          >
            <FaQuestionCircle className="tab-icon" />
            Documentation & Help
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
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
            </div>
            <div className="portfolio-file-tree">
              {Object.keys(filteredFileTree).length > 0 ? 
                renderFileTreeNode(filteredFileTree) : 
                <div className="no-files-message">No files matching search</div>
              }
            </div>
          </div>
          
          <div className="portfolio-code-editor-container">
            {activeFile ? (
              <>
                <div className="portfolio-editor-header">
                  <div className="portfolio-active-file">
                    {getFileIcon(activeFile)}
                    <span className="file-path">{activeFile}</span>
                  </div>
                  <div className="portfolio-editor-actions">
                    <button 
                      className="portfolio-editor-action-btn"
                      onClick={() => {
                        navigator.clipboard.writeText(fileContent);
                        // Show a brief "Copied!" message
                        const tempBtn = document.getElementById('copy-button');
                        if (tempBtn) {
                          const originalText = tempBtn.innerHTML;
                          tempBtn.innerHTML = '<span class="copied-icon">✓</span> Copied!';
                          setTimeout(() => {
                            tempBtn.innerHTML = originalText;
                          }, 2000);
                        }
                      }}
                      id="copy-button"
                    >
                      <FaCopy className="action-icon" />
                      <span>Copy</span>
                    </button>
                  </div>      
                  <div className="portfolio-editor-actions">
                    <button 
                      className="portfolio-editor-action-btn"
                      onClick={() => {
                        // Save the current file
                        handleSaveFile(activeFile, fileContent);
                      }}
                    >
                      <FaSave className="action-icon" />
                      <span>Save</span>
                    </button>
                    
                    <button 
                      className="portfolio-editor-action-btn"
                      onClick={() => setShowNewFileModal(true)}
                    >
                      <FaPlus className="action-icon" />
                      <span>New File</span>
                    </button>
                  </div>
                  
                  {/* New File Modal */}
                  {showNewFileModal && (
                    <div className="portfolio-modal">
                      <div className="portfolio-modal-content">
                        <h3>Create New File</h3>
                        <input 
                          type="text" 
                          placeholder="File path (e.g., src/components/NewComponent.js)"
                          value={newFilePath}
                          onChange={(e) => setNewFilePath(e.target.value)}
                        />
                        <div className="portfolio-modal-buttons">
                          <button onClick={() => setShowNewFileModal(false)}>Cancel</button>
                          <button 
                            onClick={() => {
                              handleCreateFile(newFilePath);
                              setShowNewFileModal(false);
                            }}
                          >
                            Create
                          </button>
                        </div>
                      </div>
                    </div>
                  )}         
            
                <CodeEditor
                  value={fileContent}
                  language={getFileLanguage(activeFile)}
                  theme="vs-dark"
                  onChange={handleUpdateFileContent}
                  onError={(error) => {
                    setErrorMessage(error);
                  }}
                />
                
                {errorMessage && (
                  <div className="portfolio-error-container">
                    <div className="portfolio-error-message">
                      <FaExclamationTriangle className="error-icon" />
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
                          <FaWrench className="fix-icon" />
                          <span>Auto-Fix Error</span>
                        </>
                      )}
                    </button>
                  </div>
                )}
              </>
            ) : (
              <div className="portfolio-no-file-selected">
                <FaCode className="no-file-icon" />
                <h3>No file selected</h3>
                <p>Select a file from the explorer to view and edit</p>
              </div>
            )}
          </div>
        </div>
      ) : (
        renderHelpContent()
      )}
    </div>
  );
};

export default PortfolioPreview;
