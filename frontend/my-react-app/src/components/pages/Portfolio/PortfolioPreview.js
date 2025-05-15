// frontend/my-react-app/src/components/pages/Portfolio/PortfolioPreview.js
import React, { useState, useEffect, useCallback, useRef } from 'react';
import CodeEditor from './CodeEditor';
import { FaCode, FaBug, FaFile, FaFolder, FaInfo, FaExclamationTriangle, FaWrench, FaCopy, FaSync, FaTimes, FaPlay, FaCheck, FaLightbulb } from 'react-icons/fa';
import './portfolio.css';

const PortfolioPreview = ({ portfolio, userId, onFixError }) => {
  const [activeFile, setActiveFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [errorMessage, setErrorMessage] = useState(null);
  const [isFixingError, setIsFixingError] = useState(false);
  const [fileTree, setFileTree] = useState({});
  const [searchQuery, setSearchQuery] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [allErrors, setAllErrors] = useState({});
  const [consoleLogs, setConsoleLogs] = useState([]);
  const [isErrorPanelExpanded, setIsErrorPanelExpanded] = useState(true);
  const [globalErrorCount, setGlobalErrorCount] = useState(0);
  const [errorFixRecommendations, setErrorFixRecommendations] = useState({});
  const [fixingAllErrors, setFixingAllErrors] = useState(false);
  
  const consoleEndRef = useRef(null);

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
      
      // Reset errors when switching portfolios
      setAllErrors({});
      setErrorMessage(null);
      setConsoleLogs([]);
      setGlobalErrorCount(0);
      
      // If we have a portfolio but no activeFile is set, set the first file as active
      if (!activeFile || !portfolio.components[activeFile]) {
        const files = Object.keys(portfolio.components);
        if (files.length > 0) {
          const defaultFile = files.find(f => f.endsWith('App.js')) || files[0];
          console.log(`Setting default active file: ${defaultFile}`);
          handleFileSelect(defaultFile);
        }
      }
      
      // Perform initial validation of all JS files
      validateAllFiles(portfolio.components);
    }
  }, [portfolio]);

  // Auto-scroll console to bottom when new logs are added
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [consoleLogs]);

  // Update global error count whenever allErrors changes
  useEffect(() => {
    const count = Object.values(allErrors).filter(Boolean).length;
    setGlobalErrorCount(count);
    
    // Auto-expand error panel if there are errors
    if (count > 0 && !isErrorPanelExpanded) {
      setIsErrorPanelExpanded(true);
    }
  }, [allErrors]);

  // Validate all JavaScript files in the portfolio
  const validateAllFiles = (components) => {
    // Clear existing logs and add a new validation log
    setConsoleLogs([
      {
        type: 'info',
        message: '🔍 Starting validation of all files...',
        timestamp: new Date().toLocaleTimeString()
      }
    ]);
    
    const jsFiles = Object.keys(components).filter(path => 
      path.endsWith('.js') || path.endsWith('.jsx')
    );
    
    let newErrors = {};
    let fileCounter = 0;

    // Uses Babel standalone to validate JS syntax
    const validateFile = (filePath, content) => {
      try {
        // Simple syntax validation
        new Function(content);
        return null;
      } catch (err) {
        console.log(`Error in ${filePath}:`, err.message);
        return err.message;
      }
    };

    // Process files one by one
    jsFiles.forEach(filePath => {
      const content = components[filePath];
      fileCounter++;
      
      // Add log for validation
      setConsoleLogs(prev => [
        ...prev,
        {
          type: 'log',
          message: `Validating ${filePath} (${fileCounter}/${jsFiles.length})`,
          timestamp: new Date().toLocaleTimeString()
        }
      ]);
      
      // Check for syntax errors
      const error = validateFile(filePath, content);
      
      if (error) {
        newErrors[filePath] = error;
        
        // Add error to console
        setConsoleLogs(prev => [
          ...prev,
          {
            type: 'error',
            message: `❌ Error in ${filePath}: ${error}`,
            timestamp: new Date().toLocaleTimeString()
          }
        ]);
        
        // Generate fix recommendation
        generateFixRecommendation(filePath, error, content);
      }
    });
    
    // Final validation summary
    setConsoleLogs(prev => [
      ...prev,
      {
        type: 'info',
        message: `✅ Validation complete. ${Object.keys(newErrors).length} errors found across ${jsFiles.length} files.`,
        timestamp: new Date().toLocaleTimeString()
      }
    ]);
    
    setAllErrors(newErrors);
  };

  // Generate a fix recommendation for an error
  const generateFixRecommendation = (filePath, errorMessage, content) => {
    // Common error patterns and recommended fixes
    const commonErrors = [
      {
        pattern: /missing \) after argument list/i,
        suggestion: "Check your function calls for missing closing parentheses."
      },
      {
        pattern: /unexpected token/i,
        suggestion: "Check for syntax errors like missing brackets, commas, or semicolons."
      },
      {
        pattern: /is not defined/i,
        suggestion: "Make sure all variables are properly defined and imported."
      },
      {
        pattern: /expected an identifier/i,
        suggestion: "Check for proper syntax in variable declarations and function parameters."
      },
      {
        pattern: /cannot read property/i,
        suggestion: "Add null checks before accessing object properties."
      }
    ];
    
    // Find matching suggestion
    const matchedError = commonErrors.find(err => err.pattern.test(errorMessage));
    const suggestion = matchedError ? matchedError.suggestion : "Use auto-fix to attempt to resolve this error.";
    
    // Set recommendation
    setErrorFixRecommendations(prev => ({
      ...prev,
      [filePath]: suggestion
    }));
  };

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
      
      // If there's an error for this file, show it
      if (allErrors[filePath]) {
        setErrorMessage(allErrors[filePath]);
      } else {
        setErrorMessage(null);
      }
      
      // Add log for file selection
      setConsoleLogs(prev => [
        ...prev,
        {
          type: 'info',
          message: `📁 Opened file: ${filePath}`,
          timestamp: new Date().toLocaleTimeString()
        }
      ]);
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
      setConsoleLogs(prev => [
        ...prev,
        {
          type: 'log',
          message: `✏️ File updated: ${activeFile}`,
          timestamp: new Date().toLocaleTimeString()
        }
      ]);
    }
  };

  const handleValidateCode = () => {
    setIsRefreshing(true);
    
    // Add log for validation
    setConsoleLogs(prev => [
      ...prev,
      {
        type: 'info',
        message: `🔍 Manually validating all files...`,
        timestamp: new Date().toLocaleTimeString()
      }
    ]);
    
    setTimeout(() => {
      validateAllFiles(portfolio.components);
      setIsRefreshing(false);
    }, 500);
  };

  const handleFixError = async (specificFile = null) => {
    const fileToFix = specificFile || activeFile;
    
    if (!allErrors[fileToFix] || !fileToFix) {
      console.warn("Cannot fix error: No error for this file");
      return;
    }
    
    try {
      console.log(`Attempting to fix error in ${fileToFix}:`, allErrors[fileToFix]);
      
      if (specificFile) {
        // If fixing a specific file (not the active one), we need to get its content
        setFileContent(portfolio.components[fileToFix]);
      }
      
      setIsFixingError(true);
      if (onFixError) onFixError(true);
      
      // Add log for fix attempt
      setConsoleLogs(prev => [
        ...prev,
        {
          type: 'info',
          message: `🔧 Attempting to fix error in ${fileToFix}...`,
          timestamp: new Date().toLocaleTimeString()
        }
      ]);
      
      const response = await fetch('/api/portfolio/fix-error', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-Id': userId
        },
        body: JSON.stringify({
          portfolio_id: portfolio._id,
          component_path: fileToFix,
          error_message: allErrors[fileToFix],
          component_code: portfolio.components[fileToFix]
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to fix error');
      }
      
      const data = await response.json();
      console.log("Error fixed successfully");
      
      // Update the file content with the fixed code if it's the active file
      if (fileToFix === activeFile) {
        setFileContent(data.fixed_code);
      }
      
      // Update the portfolio object locally
      const updatedComponents = {
        ...portfolio.components,
        [fileToFix]: data.fixed_code
      };
      
      // Remove error for this file
      const updatedErrors = {...allErrors};
      delete updatedErrors[fileToFix];
      setAllErrors(updatedErrors);
      
      // Clear error message if this is the active file
      if (fileToFix === activeFile) {
        setErrorMessage(null);
      }
      
      // Add success log
      setConsoleLogs(prev => [
        ...prev,
        {
          type: 'success',
          message: `✅ Successfully fixed error in ${fileToFix}`,
          timestamp: new Date().toLocaleTimeString()
        }
      ]);
      
      setIsFixingError(false);
      if (onFixError) onFixError(false);
      
    } catch (err) {
      console.error('Error fixing code:', err);
      
      // Add error log
      setConsoleLogs(prev => [
        ...prev,
        {
          type: 'error',
          message: `❌ Failed to fix error in ${fileToFix}: ${err.message}`,
          timestamp: new Date().toLocaleTimeString()
        }
      ]);
      
      if (fileToFix === activeFile) {
        setErrorMessage(`Failed to fix the error: ${err.message}. Please try again.`);
      }
      
      setIsFixingError(false);
      if (onFixError) onFixError(false);
    }
  };
  
  const handleFixAllErrors = async () => {
    if (Object.keys(allErrors).length === 0) {
      // Add log for no errors
      setConsoleLogs(prev => [
        ...prev,
        {
          type: 'info',
          message: `✅ No errors to fix!`,
          timestamp: new Date().toLocaleTimeString()
        }
      ]);
      return;
    }
    
    setFixingAllErrors(true);
    
    // Add log for fix all attempt
    setConsoleLogs(prev => [
      ...prev,
      {
        type: 'info',
        message: `🔧 Attempting to fix all errors...`,
        timestamp: new Date().toLocaleTimeString()
      }
    ]);
    
    // Fix each error one by one
    const errorFiles = Object.keys(allErrors);
    let fixCount = 0;
    
    for (const filePath of errorFiles) {
      try {
        await handleFixError(filePath);
        fixCount++;
      } catch (err) {
        console.error(`Failed to fix error in ${filePath}:`, err);
      }
    }
    
    // Add final log
    setConsoleLogs(prev => [
      ...prev,
      {
        type: 'info',
        message: `✅ Fixed ${fixCount}/${errorFiles.length} errors`,
        timestamp: new Date().toLocaleTimeString()
      }
    ]);
    
    setFixingAllErrors(false);
  };

  const handleClearConsole = () => {
    setConsoleLogs([]);
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
            const hasError = allErrors[filePath] ? true : false;
            
            return (
              <div 
                key={filePath}
                className={`portfolio-file-item ${activeFile === filePath ? 'active' : ''} ${hasError ? 'has-error' : ''}`}
                onClick={() => handleFileSelect(filePath)}
              >
                {getFileIcon(filePath)}
                <span className="file-name">{name}</span>
                {hasError && <FaExclamationTriangle className="file-error-icon" />}
              </div>
            );
          }
          
          return null;
        })}
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
        <div className="portfolio-preview-actions">
          <button 
            className={`portfolio-validate-button ${isRefreshing ? 'refreshing' : ''}`}
            onClick={handleValidateCode}
            disabled={isRefreshing}
          >
            <FaSync className={`action-icon ${isRefreshing ? 'spin' : ''}`} />
            <span>Validate Code</span>
          </button>
          
          <button 
            className="portfolio-fix-all-button"
            onClick={handleFixAllErrors}
            disabled={Object.keys(allErrors).length === 0 || fixingAllErrors}
          >
            <FaWrench className="action-icon" />
            <span>
              {fixingAllErrors ? 'Fixing...' : `Fix All Errors (${Object.keys(allErrors).length})`}
            </span>
          </button>
        </div>
      </div>
      
      {/* Error Panel - Shows all errors in the project */}
      <div className={`portfolio-error-panel ${isErrorPanelExpanded ? 'expanded' : 'collapsed'}`}>
        <div className="error-panel-header" onClick={() => setIsErrorPanelExpanded(!isErrorPanelExpanded)}>
          <div className="error-panel-title">
            <FaBug className="error-icon" />
            <h3>Error Console {globalErrorCount > 0 && `(${globalErrorCount})`}</h3>
          </div>
          <button className="error-panel-toggle">
            {isErrorPanelExpanded ? '▼' : '▶'}
          </button>
        </div>
        
        <div className="error-panel-content">
          {globalErrorCount === 0 ? (
            <div className="no-errors-message">
              <FaCheck className="success-icon" />
              <p>No errors detected in the portfolio code.</p>
            </div>
          ) : (
            <div className="error-list">
              {Object.entries(allErrors).map(([filePath, errorMsg]) => (
                <div key={filePath} className="error-item">
                  <div className="error-item-header">
                    <div className="error-file-path" onClick={() => handleFileSelect(filePath)}>
                      {getFileIcon(filePath)} {filePath}
                    </div>
                    <button 
                      className="error-fix-button"
                      onClick={() => handleFixError(filePath)}
                      disabled={isFixingError}
                    >
                      <FaWrench className="fix-icon" />
                      <span>Fix</span>
                    </button>
                  </div>
                  <div className="error-message-content">
                    {errorMsg}
                  </div>
                  {errorFixRecommendations[filePath] && (
                    <div className="error-recommendation">
                      <FaLightbulb className="recommendation-icon" />
                      <span>{errorFixRecommendations[filePath]}</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      
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
                  {allErrors[activeFile] && (
                    <div className="file-error-badge">
                      <FaExclamationTriangle className="file-error-icon" />
                    </div>
                  )}
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
                  
                  {allErrors[activeFile] && (
                    <button 
                      className="portfolio-editor-action-btn error-fix-btn"
                      onClick={() => handleFixError()}
                      disabled={isFixingError}
                    >
                      <FaWrench className="action-icon" />
                      <span>{isFixingError ? 'Fixing...' : 'Fix Error'}</span>
                    </button>
                  )}
                </div>
              </div>
              
              <CodeEditor
                value={fileContent}
                language={getFileLanguage(activeFile)}
                theme="vs-dark"
                onChange={handleUpdateFileContent}
                onError={(error) => {
                  if (error) {
                    setErrorMessage(error);
                    
                    // Update allErrors
                    setAllErrors(prev => ({
                      ...prev,
                      [activeFile]: error
                    }));
                    
                    // Generate fix recommendation
                    generateFixRecommendation(activeFile, error, fileContent);
                    
                    // Add to console
                    setConsoleLogs(prev => [
                      ...prev,
                      {
                        type: 'error',
                        message: `❌ Error in ${activeFile}: ${error}`,
                        timestamp: new Date().toLocaleTimeString()
                      }
                    ]);
                  } else {
                    setErrorMessage(null);
                    
                    // Remove from allErrors if it was there
                    if (allErrors[activeFile]) {
                      const updatedErrors = {...allErrors};
                      delete updatedErrors[activeFile];
                      setAllErrors(updatedErrors);
                      
                      // Add fixed log
                      setConsoleLogs(prev => [
                        ...prev,
                        {
                          type: 'success',
                          message: `✅ Fixed error in ${activeFile}`,
                          timestamp: new Date().toLocaleTimeString()
                        }
                      ]);
                    }
                  }
                }}
              />
            </>
          ) : (
            <div className="portfolio-no-file-selected">
              <FaCode className="no-file-icon" />
              <h3>No file selected</h3>
              <p>Select a file from the explorer to view and edit</p>
            </div>
          )}
        </div>
        
        {/* Console Panel */}
        <div className="portfolio-console-panel">
          <div className="console-panel-header">
            <div className="console-panel-title">
              <FaCode className="console-icon" />
              <h3>Console Output</h3>
            </div>
            <button 
              className="console-clear-btn"
              onClick={handleClearConsole}
              disabled={consoleLogs.length === 0}
            >
              Clear
            </button>
          </div>
          
          <div className="console-panel-content">
            {consoleLogs.length === 0 ? (
              <div className="console-empty-message">
                <p>No console output yet. Validation results will appear here.</p>
              </div>
            ) : (
              <div className="console-logs">
                {consoleLogs.map((log, index) => (
                  <div key={index} className={`console-log ${log.type}`}>
                    <span className="log-timestamp">{log.timestamp}</span>
                    <span className={`log-type ${log.type}`}>{log.type.toUpperCase()}</span>
                    <span className="log-message">{log.message}</span>
                  </div>
                ))}
                <div ref={consoleEndRef} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default PortfolioPreview;
