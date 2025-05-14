// frontend/my-react-app/src/components/pages/Portfolio/PortfolioPreview.js
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { transform } from '@babel/standalone';
import CodeEditor from './CodeEditor';
import { FaCode, FaEye, FaDesktop, FaMobile, FaSync, FaCheck, FaTimes, FaFile, FaFolder, FaInfo, FaExclamationTriangle, FaWrench, FaBug, FaCopy, FaDownload, FaClipboard } from 'react-icons/fa';
import './portfolio.css';

const PortfolioPreview = ({ portfolio, userId, onFixError }) => {
  const [activeFile, setActiveFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [previewMode, setPreviewMode] = useState('code'); // 'code' or 'preview'
  const [errorMessage, setErrorMessage] = useState(null);
  const [isFixingError, setIsFixingError] = useState(false);
  const [previewHtml, setPreviewHtml] = useState('');
  const [fileTree, setFileTree] = useState({});
  const [previewDevice, setPreviewDevice] = useState('desktop');
  const [searchQuery, setSearchQuery] = useState('');
  const [isPreviewRefreshing, setIsPreviewRefreshing] = useState(false);
  const [previewError, setPreviewError] = useState(null);
  const [isPreviewGenerated, setIsPreviewGenerated] = useState(false);
  const iframeRef = useRef(null);

  // Process portfolio data when it changes
  useEffect(() => {
    if (portfolio && portfolio.components) {
      console.log("Portfolio provided to preview:", {
        id: portfolio._id,
        componentCount: Object.keys(portfolio.components).length,
        componentKeys: Object.keys(portfolio.components)
      });
      
      // If no components, log warning and set error
      if (Object.keys(portfolio.components).length === 0) {
        console.error("Portfolio has no components");
        setPreviewError("Portfolio data is incomplete. No components found.");
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
      
      // Generate preview HTML
      try {
        generatePreviewHtml(portfolio.components);
        setIsPreviewGenerated(true);
      } catch (err) {
        console.error("Failed to generate preview HTML:", err);
        setPreviewError("Failed to generate preview HTML. Please check the code for errors.");
        setIsPreviewGenerated(false);
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


  
  const generatePreviewHtml = useCallback((components) => {
    console.log("Generating enhanced preview HTML");
    
    // Debug what components we have
    const componentKeys = Object.keys(components);
    console.log("Available components:", componentKeys);
    
    // First check if we have the necessary files
    const htmlFile = components['public/index.html'] || '';
    
    if (!htmlFile) {
      console.error("No HTML template found in components");
      setPreviewHtml('<div style="padding: 20px; color: #666;">No HTML template found</div>');
      return;
    }
    
    // Basic strategy: inject CSS, Babel, and our React simulation into the HTML template
    let processedHtml = htmlFile;
    
    // 1. Add Babel standalone for JSX transpilation
    const babelScript = `
      <script src="https://cdnjs.cloudflare.com/ajax/libs/babel-standalone/7.22.10/babel.min.js"></script>
    `;
    processedHtml = processedHtml.replace('</head>', `${babelScript}</head>`);
    
    // 2. Inject CSS
    const cssContent = Object.entries(components)
      .filter(([key]) => key.endsWith('.css'))
      .map(([_, content]) => content)
      .join('\n');
    
    console.log(`Found ${cssContent.length} bytes of CSS content to inject`);
    
    // Inject inline CSS
    const styleTag = `<style>${cssContent}</style>`;
    processedHtml = processedHtml.replace('</head>', `${styleTag}</head>`);
    
    try {
      // 3. Enhanced React Simulation
      const enhancedReactSimulation = `
        <script>
          // Enhanced React Simulation
          window.React = {
            createElement: function(type, props, ...children) {
              // Handle function components
              if (typeof type === 'function') {
                try {
                  return type(props || {});
                } catch(e) {
                  console.error('Error rendering component:', e);
                  return document.createTextNode(\`Error: \${e.message}\`);
                }
              }
              
              // Handle string types (native DOM elements)
              if (typeof type === 'string') {
                const element = document.createElement(type);
                
                // Apply props/attributes
                if (props) {
                  Object.entries(props).forEach(([key, value]) => {
                    if (key === 'className') {
                      element.className = value;
                    } else if (key === 'style' && typeof value === 'object') {
                      Object.assign(element.style, value);
                    } else if (key === 'dangerouslySetInnerHTML' && value.__html) {
                      element.innerHTML = value.__html;
                    } else if (key.startsWith('on') && typeof value === 'function') {
                      // Handle event listeners
                      const eventName = key.slice(2).toLowerCase();
                      element.addEventListener(eventName, value);
                    } else if (!key.startsWith('__') && key !== 'children') {
                      // Regular attributes
                      element.setAttribute(key, value);
                    }
                  });
                }
                
                // Append children
                children.flat().forEach(child => {
                  if (child === null || child === undefined || child === false) return;
                  
                  if (typeof child === 'object' && child.nodeType) {
                    element.appendChild(child);
                  } else {
                    element.appendChild(document.createTextNode(String(child)));
                  }
                });
                
                return element;
              }
              
              // Handle fragments and special types
              if (type === React.Fragment) {
                const fragment = document.createDocumentFragment();
                children.flat().forEach(child => {
                  if (child !== null && child !== undefined && child !== false) {
                    fragment.appendChild(
                      typeof child === 'object' && child.nodeType 
                        ? child
                        : document.createTextNode(String(child))
                    );
                  }
                });
                return fragment;
              }
              
              // Fallback
              const div = document.createElement('div');
              div.textContent = \`Unknown type: \${type}\`;
              return div;
            },
            
            // Hook simulation
            createRef: () => ({ current: null }),
            useRef: (initialValue) => ({ current: initialValue }),
            useState: function(initialValue) {
              const value = typeof initialValue === 'function' ? initialValue() : initialValue;
              const setValue = function() { 
                console.log('setState called with', arguments); 
                // This is just a mock that doesn't actually update state
              };
              return [value, setValue];
            },
            useEffect: function(fn, deps) {
              try { 
                // Only run effects once in our simulation
                fn(); 
              } catch(e) { 
                console.error('useEffect error:', e); 
              }
            },
            useCallback: (fn) => fn,
            useMemo: (fn) => fn(),
            useContext: () => ({}),
            Fragment: Symbol('Fragment'),
            
            // Support for React.memo and other HOCs
            memo: (Component) => Component,
            forwardRef: (Component) => Component
          };
          
          // ReactDOM simulation
          window.ReactDOM = {
            render: function(element, container) {
              while (container.firstChild) {
                container.removeChild(container.firstChild);
              }
              container.appendChild(element);
            },
            createRoot: function(container) {
              return {
                render: function(element) {
                  while (container.firstChild) {
                    container.removeChild(container.firstChild);
                  }
                  container.appendChild(element);
                }
              };
            },
            createPortal: function(children, container) {
              container.innerHTML = '';
              if (typeof children === 'object' && children.nodeType) {
                container.appendChild(children);
              } else {
                container.textContent = String(children);
              }
              return children;
            }
          };
          
          // JSX Transformation functions (using Babel standalone)
          const transformJSX = (code) => {
            try {
              return Babel.transform(code, {
                presets: ['react'],
                filename: 'preview.jsx'
              }).code;
            } catch (error) {
              console.error('Error transforming JSX:', error);
              return \`/* JSX Transform Error: \${error.message} */\`;
            }
          };
          
          // Helper function to convert string to function
          const stringToFunction = (str) => {
            try {
              return new Function('React', 'ReactDOM', 'props', \`
                "use strict";
                const exports = {};
                const module = { exports };
                \${str}
                return typeof exports.default !== 'undefined' ? exports.default : module.exports;
              \`)(React, ReactDOM, {});
            } catch (e) {
              console.error('Error converting string to function:', e);
              return () => React.createElement('div', { style: { color: 'red' } }, 
                \`Component Error: \${e.message}\`
              );
            }
          };
        </script>
      `;
      
      processedHtml = processedHtml.replace('</head>', `${enhancedReactSimulation}</head>`);
      
      // 4. Extract and transform component code
      const componentMap = {};
      
      // Process component files
      Object.entries(components)
        .filter(([key]) => key.startsWith('src/components/') && key.endsWith('.js'))
        .forEach(([key, content]) => {
          // Extract component name from path
          const componentName = key.split('/').pop().replace('.js', '');
          componentMap[componentName] = content;
        });
      
      // Process App.js and index.js
      const appJs = components['src/App.js'] || '';
      const indexJs = components['src/index.js'] || '';
      
      // Create a script to initialize the application
      const appInitScript = `
        <script type="text/babel">
          document.addEventListener('DOMContentLoaded', function() {
            try {
              console.log("Initializing enhanced portfolio preview");
              
              // Define Components
              ${Object.entries(componentMap).map(([name, code]) => `
                // Component: ${name}
                const ${name} = (function() {
                  ${code.replace(/import\s+.*?from\s+['"].*?['"]/g, '// Import removed:')}
                  return ${name};
                })();
              `).join('\n')}
              
              // Define App
              const App = (function() {
                ${appJs.replace(/import\s+.*?from\s+['"].*?['"]/g, '// Import removed:')}
                return App;
              })();
              
              // Initialize React app
              const rootElement = document.getElementById('root');
              if (rootElement && typeof App === 'function') {
                try {
                  console.log("Rendering App component");
                  const appElement = React.createElement(App, {});
                  ReactDOM.createRoot(rootElement).render(appElement);
                  console.log("App rendered successfully");
                } catch (err) {
                  console.error("Error rendering App:", err);
                  rootElement.innerHTML = \`
                    <div style="color: #721c24; background: #f8d7da; padding: 20px; border-radius: 5px;">
                      <h3>Rendering Error</h3>
                      <p>\${err.message}</p>
                      <pre>\${err.stack}</pre>
                    </div>
                  \`;
                }
              } else {
                console.error("Root element or App component not found");
                document.body.innerHTML = \`
                  <div style="color: #721c24; background: #f8d7da; padding: 20px; border-radius: 5px;">
                    <h3>Preview Error</h3>
                    <p>Could not render the App component. Check if the App component is properly defined and exported.</p>
                  </div>
                \`;
              }
            } catch(err) {
              console.error("Preview initialization error:", err);
              document.body.innerHTML = \`
                <div style="color: #721c24; background: #f8d7da; padding: 20px; border-radius: 5px;">
                  <h3>Preview Error</h3>
                  <p>\${err.message}</p>
                  <pre>\${err.stack}</pre>
                </div>
              \`;
            }
          });
        </script>
      `;
      
      processedHtml = processedHtml.replace('</body>', `${appInitScript}</body>`);
      
    } catch(err) {
      console.error("Error processing JS for preview:", err);
      setPreviewError(`Error generating preview: ${err.message}`);
    }
    
    // Add preview message
    processedHtml = processedHtml.replace('</body>', `
      <div style="position: fixed; bottom: 0; left: 0; right: 0; background: #f8d7da; color: #721c24; padding: 10px; 
           font-size: 12px; text-align: center; font-family: Arial, sans-serif; z-index: 1000;">
        ⚠️ This is a simplified preview. Some interactive features may not work. Check the browser console for errors.
      </div></body>
    `);
    
    console.log("Enhanced preview HTML generated successfully, length:", processedHtml.length);
    setPreviewHtml(processedHtml);
    setPreviewError(null);
  }, []);

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
      
      // Regenerate preview HTML when code changes
      if (activeFile.endsWith('.js') || activeFile.endsWith('.css') || activeFile.endsWith('.html')) {
        setTimeout(() => {
          try {
            generatePreviewHtml(updatedComponents);
          } catch (err) {
            console.error("Error regenerating preview after file update:", err);
            setPreviewError(`Error updating preview: ${err.message}`);
          }
        }, 1000);
      }
    }
  };

  const handleRefreshPreview = () => {
    console.log("Manually refreshing preview");
    setIsPreviewRefreshing(true);
    
    // Regenerate the preview HTML
    if (portfolio && portfolio.components) {
      try {
        generatePreviewHtml(portfolio.components);
        
        // Refresh the iframe if it exists
        if (iframeRef.current) {
          try {
            const iframe = iframeRef.current;
            const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
            iframeDoc.open();
            iframeDoc.write(previewHtml);
            iframeDoc.close();
            console.log("Iframe content refreshed");
          } catch (err) {
            console.error("Error refreshing iframe:", err);
            setPreviewError(`Error refreshing preview: ${err.message}`);
          }
        }
      } catch (err) {
        console.error("Error during manual preview refresh:", err);
        setPreviewError(`Failed to refresh preview: ${err.message}`);
      }
    }
    
    setTimeout(() => {
      setIsPreviewRefreshing(false);
    }, 500);
  };

  const handleFixError = async () => {
    if (!errorMessage || !activeFile) {
      console.warn("Cannot fix error: No error message or active file");
      return;
    }
    
    try {
      console.log(`Attempting to fix error in ${activeFile}:`, errorMessage);
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
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to fix error');
      }
      
      const data = await response.json();
      console.log("Error fixed successfully");
      
      // Update the file content with the fixed code
      setFileContent(data.fixed_code);
      setErrorMessage(null);
      
      // Update the portfolio object locally
      const updatedComponents = {
        ...portfolio.components,
        [activeFile]: data.fixed_code
      };
      
      // Regenerate preview HTML
      try {
        generatePreviewHtml(updatedComponents);
      } catch (err) {
        console.error("Error regenerating preview after fixing error:", err);
        setPreviewError(`Error updating preview: ${err.message}`);
      }
      
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

  if (!portfolio) {
    return (
      <div className="portfolio-preview-container portfolio-no-portfolio">
        <div className="portfolio-empty-message">
          <FaInfo className="empty-icon" />
          <h3>No Portfolio Selected</h3>
          <p>Create or select a portfolio to preview and edit</p>
        </div>
      </div>
    );
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
            <FaCode className="tab-icon" />
            Code Editor
          </button>
          <button 
            className={`portfolio-preview-tab ${previewMode === 'preview' ? 'active' : ''}`}
            onClick={() => setPreviewMode('preview')}
          >
            <FaEye className="tab-icon" />
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
                          tempBtn.innerHTML = `<FaCheck className="copied-icon" /> Copied!`;
                          setTimeout(() => {
                            tempBtn.innerHTML = originalText;
                          }, 2000);
                        }
                      }}
                      id="copy-button"
                    >
                      <FaCopy className="action-icon" />
                      <span>Copy All</span>
                    </button>
                  </div>
                    <button 
                      className="portfolio-editor-action-btn"
                      onClick={handleRefreshPreview}
                    >
                      <FaSync className={isPreviewRefreshing ? 'refreshing' : ''} />
                      <span>Refresh Preview</span>
                    </button>
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
        <div className="portfolio-live-preview-container">
          <div className="portfolio-preview-toolbar">
            <div className="portfolio-preview-device-selector">
              <button 
                className={`portfolio-device-button ${previewDevice === 'desktop' ? 'active' : ''}`}
                onClick={() => setPreviewDevice('desktop')}
              >
                <FaDesktop className="device-icon" />
                <span>Desktop</span>
              </button>
              <button 
                className={`portfolio-device-button ${previewDevice === 'mobile' ? 'active' : ''}`}
                onClick={() => setPreviewDevice('mobile')}
              >
                <FaMobile className="device-icon" />
                <span>Mobile</span>
              </button>
            </div>
            <button 
              className="portfolio-preview-refresh-btn"
              onClick={handleRefreshPreview}
              disabled={isPreviewRefreshing}
            >
              <FaSync className={`refresh-icon ${isPreviewRefreshing ? 'refreshing' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
          
          {previewError && (
            <div className="portfolio-preview-error">
              <FaBug className="preview-error-icon" />
              <div className="preview-error-message">
                <h3>Preview Error</h3>
                <p>{previewError}</p>
                <div className="preview-error-help">
                  <p>Check that your code has the following:</p>
                  <ul>
                    <li>A valid App.js component with a default export</li>
                    <li>A proper index.html with a root element</li>
                    <li>Components that don't rely on browser APIs</li>
                  </ul>
                </div>
              </div>
            </div>
          )}
          
          <div 
            className={`portfolio-preview-frame-container ${previewDevice === 'mobile' ? 'mobile-container' : ''}`}
          >
            {isPreviewGenerated ? (
              <iframe
                ref={iframeRef}
                className="portfolio-preview-frame"
                title="Portfolio Preview"
                srcDoc={previewHtml}
                sandbox="allow-scripts allow-same-origin"
                width="100%"
                height="100%"
                onLoad={() => console.log("Preview iframe loaded")}
                onError={(e) => {
                  console.error("Preview iframe error:", e);
                  setPreviewError("Error loading preview. Check the code for errors.");
                }}
              />
            ) : (
              <div className="preview-loading">
                <div className="preview-loading-spinner"></div>
                <p>Generating preview...</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default PortfolioPreview;
