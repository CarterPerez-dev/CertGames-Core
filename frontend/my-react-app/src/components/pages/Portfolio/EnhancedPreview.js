// frontend/my-react-app/src/components/pages/Portfolio/EnhancedPreview.js
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { FaExclamationTriangle, FaSync, FaDesktop, FaMobile, FaTimes, FaTerminal, FaCode } from 'react-icons/fa';
import './portfolio.css';

const ErrorDisplay = ({ errors }) => {
  if (!errors || errors.length === 0) return null;
  
  return (
    <div className="portfolio-live-errors">
      <div className="live-errors-header">
        <FaExclamationTriangle className="error-icon" />
        <h3>Compilation/Runtime Errors</h3>
      </div>
      <div className="live-errors-list">
        {errors.map((error, index) => (
          <div key={index} className="live-error-item">
            <div className="error-message">{error.message}</div>
            {error.location && (
              <div className="error-location">
                <span className="error-file">{error.location.file || 'Unknown file'}</span>
                {error.location.line && (
                  <span className="error-line">Line {error.location.line}</span>
                )}
              </div>
            )}
            {error.stack && (
              <div className="error-stack">{error.stack}</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

const ConsoleOutput = ({ logs, onClear }) => {
  const consoleRef = useRef(null);
  
  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [logs]);
  
  if (!logs || logs.length === 0) {
    return (
      <div className="portfolio-console">
        <div className="console-header">
          <div className="console-title">
            <FaTerminal className="console-icon" />
            <span>Console</span>
          </div>
          <button className="console-clear-btn" onClick={onClear} disabled={true}>
            Clear
          </button>
        </div>
        <div className="console-content" ref={consoleRef}>
          <div className="console-empty">No console output yet</div>
        </div>
      </div>
    );
  }
  
  return (
    <div className="portfolio-console">
      <div className="console-header">
        <div className="console-title">
          <FaTerminal className="console-icon" />
          <span>Console</span>
          <span className="log-count">({logs.length})</span>
        </div>
        <button className="console-clear-btn" onClick={onClear}>
          Clear
        </button>
      </div>
      <div className="console-content" ref={consoleRef}>
        {logs.map((log, index) => (
          <div key={index} className={`console-log ${log.type}`}>
            <span className="log-time">{log.time}</span>
            <span className={`log-type ${log.type}`}>{log.type}</span>
            <span className="log-message">{log.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const EnhancedPreview = ({ portfolioComponents, onError }) => {
  const iframeRef = useRef(null);
  const [previewDevice, setPreviewDevice] = useState('desktop');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [errors, setErrors] = useState([]);
  const [consoleLogs, setConsoleLogs] = useState([]);
  const [previewHtml, setPreviewHtml] = useState('');
  const [showConsole, setShowConsole] = useState(false);
  const [isFirstLoad, setIsFirstLoad] = useState(true);
  
  // Generate HTML content for preview
  const generatePreviewHtml = useCallback((components) => {
    if (!components) return '';
    
    try {
      // Get basic HTML template
      const htmlTemplate = components['public/index.html'] || `
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Portfolio Preview</title>
          </head>
          <body>
            <div id="root"></div>
          </body>
        </html>
      `;
      
      // Extract all CSS content
      const cssContent = Object.entries(components)
        .filter(([key]) => key.endsWith('.css'))
        .map(([_, content]) => content)
        .join('\n');
      
      // Start building the enhanced preview
      let finalHtml = htmlTemplate;
      
      // Add Babel for JSX transpilation
      const babelScript = `
        <script src="https://unpkg.com/@babel/standalone@7.19.1/babel.min.js"></script>
      `;
      finalHtml = finalHtml.replace('</head>', `${babelScript}</head>`);
      
      // Add CSS
      const styleTag = `<style>${cssContent}</style>`;
      finalHtml = finalHtml.replace('</head>', `${styleTag}</head>`);
      
      // Add error reporting and console forwarding
      const errorHandlingScript = `
        <script>
          // Error forwarding to parent window
          window.onerror = function(message, source, lineno, colno, error) {
            const errorData = {
              type: 'runtime',
              message: message,
              location: {
                file: source.split('/').pop(),
                line: lineno,
                column: colno
              },
              stack: error && error.stack
            };
            
            // Send to parent
            window.parent.postMessage({
              type: 'preview-error',
              error: errorData
            }, '*');
            
            return true; // Prevent default error handling
          };
          
          // Catch unhandled promise rejections
          window.addEventListener('unhandledrejection', function(event) {
            const errorData = {
              type: 'promise',
              message: event.reason.message || 'Unhandled Promise rejection',
              stack: event.reason.stack
            };
            
            window.parent.postMessage({
              type: 'preview-error',
              error: errorData
            }, '*');
          });
          
          // Console message forwarding
          const originalConsoleLog = console.log;
          const originalConsoleError = console.error;
          const originalConsoleWarn = console.warn;
          const originalConsoleInfo = console.info;
          
          console.log = function() {
            const args = Array.from(arguments).map(arg => 
              typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
            ).join(' ');
            
            window.parent.postMessage({
              type: 'console-log',
              logType: 'log',
              message: args
            }, '*');
            
            originalConsoleLog.apply(console, arguments);
          };
          
          console.error = function() {
            const args = Array.from(arguments).map(arg => 
              typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
            ).join(' ');
            
            window.parent.postMessage({
              type: 'console-log',
              logType: 'error',
              message: args
            }, '*');
            
            originalConsoleError.apply(console, arguments);
          };
          
          console.warn = function() {
            const args = Array.from(arguments).map(arg => 
              typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
            ).join(' ');
            
            window.parent.postMessage({
              type: 'console-log',
              logType: 'warn',
              message: args
            }, '*');
            
            originalConsoleWarn.apply(console, arguments);
          };
          
          console.info = function() {
            const args = Array.from(arguments).map(arg => 
              typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
            ).join(' ');
            
            window.parent.postMessage({
              type: 'console-log',
              logType: 'info',
              message: args
            }, '*');
            
            originalConsoleInfo.apply(console, arguments);
          };
          
          // Notify parent when DOM is ready
          document.addEventListener('DOMContentLoaded', function() {
            window.parent.postMessage({
              type: 'preview-loaded'
            }, '*');
            
            console.info('Preview loaded successfully');
          });
        </script>
      `;
      finalHtml = finalHtml.replace('</head>', `${errorHandlingScript}</head>`);
      
      // Add React and ReactDOM
      const reactScript = `
        <script src="https://unpkg.com/react@18.2.0/umd/react.development.js"></script>
        <script src="https://unpkg.com/react-dom@18.2.0/umd/react-dom.development.js"></script>
      `;
      finalHtml = finalHtml.replace('</head>', `${reactScript}</head>`);
      
      // Extract component code
      // First, process component files
      const componentMap = {};
      
      Object.entries(components)
        .filter(([key]) => key.startsWith('src/components/') && key.endsWith('.js'))
        .forEach(([key, content]) => {
          const componentName = key.split('/').pop().replace('.js', '');
          componentMap[componentName] = content;
        });
      
      // Process App.js and index.js
      const appJs = components['src/App.js'] || '';
      const indexJs = components['src/index.js'] || '';
      
      // Create a script to initialize the application
      const appInitScript = `
        <script type="text/babel" data-type="module">
          try {
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
                throw err; // Re-throw for the error handler
              }
            } else {
              console.error("Root element or App component not found");
              document.body.innerHTML = \`
                <div style="color: #721c24; background: #f8d7da; padding: 20px; border-radius: 5px;">
                  <h3>Preview Error</h3>
                  <p>Could not render the App component. Check if the App component is properly defined and exported.</p>
                </div>
              \`;
              throw new Error("App component not found or not exported properly");
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
        </script>
      `;
      
      finalHtml = finalHtml.replace('</body>', `${appInitScript}</body>`);
      
      // Add preview message
      finalHtml = finalHtml.replace('</body>', `
        <div style="position: fixed; bottom: 0; left: 0; right: 0; background: #f8d7da; color: #721c24; padding: 10px; 
             font-size: 12px; text-align: center; font-family: Arial, sans-serif; z-index: 1000;">
          ⚠️ This is a live preview environment. Check the console for errors and logs.
        </div></body>
      `);
      
      console.log("Enhanced preview HTML generated, length:", finalHtml.length);
      return finalHtml;
      
    } catch (err) {
      console.error("Error generating preview HTML:", err);
      onError(err.message);
      return `
        <html>
          <body>
            <div style="color: #721c24; background: #f8d7da; padding: 20px; border-radius: 5px;">
              <h3>Error Generating Preview</h3>
              <p>${err.message}</p>
            </div>
          </body>
        </html>
      `;
    }
  }, [onError]);
  
  // Update HTML when components change
  useEffect(() => {
    if (portfolioComponents) {
      const html = generatePreviewHtml(portfolioComponents);
      setPreviewHtml(html);
      
      // Reset errors and logs when generating new preview
      if (!isFirstLoad) {
        setErrors([]);
        setConsoleLogs([]);
      }
    }
  }, [portfolioComponents, generatePreviewHtml, isFirstLoad]);
  
  // Handle messages from iframe
  useEffect(() => {
    const handleMessage = (event) => {
      if (!event.data || !event.data.type) return;
      
      switch (event.data.type) {
        case 'preview-error':
          setErrors(prevErrors => [...prevErrors, event.data.error]);
          // Also show significant errors to the parent component
          if (onError && event.data.error.message) {
            onError(event.data.error.message);
          }
          // Auto-show console when errors occur
          setShowConsole(true);
          break;
          
        case 'console-log':
          const now = new Date();
          const timeStr = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
          
          setConsoleLogs(prevLogs => [
            ...prevLogs, 
            {
              time: timeStr,
              type: event.data.logType,
              message: event.data.message
            }
          ]);
          break;
          
        case 'preview-loaded':
          setIsFirstLoad(false);
          break;
          
        default:
          break;
      }
    };
    
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [onError]);
  
  // Handle refresh
  const handleRefreshPreview = () => {
    setIsRefreshing(true);
    
    try {
      // Reset errors and logs
      setErrors([]);
      setConsoleLogs([]);
      
      // Regenerate HTML
      const html = generatePreviewHtml(portfolioComponents);
      setPreviewHtml(html);
      
      // Reload iframe
      if (iframeRef.current) {
        const iframe = iframeRef.current;
        const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
        iframeDoc.open();
        iframeDoc.write(html);
        iframeDoc.close();
      }
    } catch (err) {
      console.error("Error refreshing preview:", err);
      onError(`Error refreshing preview: ${err.message}`);
    }
    
    setTimeout(() => setIsRefreshing(false), 500);
  };
  
  // Clear console logs
  const handleClearConsole = () => {
    setConsoleLogs([]);
  };
  
  return (
    <div className="enhanced-preview-container">
      <div className="enhanced-preview-header">
        <div className="preview-device-controls">
          <button 
            className={`preview-device-button ${previewDevice === 'desktop' ? 'active' : ''}`}
            onClick={() => setPreviewDevice('desktop')}
          >
            <FaDesktop className="device-icon" />
            <span>Desktop</span>
          </button>
          <button 
            className={`preview-device-button ${previewDevice === 'mobile' ? 'active' : ''}`}
            onClick={() => setPreviewDevice('mobile')}
          >
            <FaMobile className="device-icon" />
            <span>Mobile</span>
          </button>
        </div>
        
        <div className="preview-actions">
          <button 
            className={`preview-console-toggle ${showConsole ? 'active' : ''}`}
            onClick={() => setShowConsole(!showConsole)}
          >
            <FaTerminal className="console-icon" />
            <span>{showConsole ? 'Hide Console' : 'Show Console'}</span>
            {consoleLogs.length > 0 && !showConsole && (
              <span className="console-badge">{consoleLogs.length}</span>
            )}
          </button>
          
          <button 
            className={`preview-refresh-button ${isRefreshing ? 'refreshing' : ''}`}
            onClick={handleRefreshPreview}
            disabled={isRefreshing}
          >
            <FaSync className={`refresh-icon ${isRefreshing ? 'spinning' : ''}`} />
            <span>{isRefreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>
        </div>
      </div>
      
      {errors.length > 0 && (
        <ErrorDisplay errors={errors} />
      )}
      
      <div className={`enhanced-preview-content ${showConsole ? 'with-console' : ''}`}>
        <div className={`preview-frame-container ${previewDevice === 'mobile' ? 'mobile' : ''}`}>
          <iframe
            ref={iframeRef}
            className="enhanced-preview-frame"
            title="Portfolio Live Preview"
            srcDoc={previewHtml}
            sandbox="allow-scripts allow-forms allow-same-origin"
            loading="eager"
            onLoad={() => setIsRefreshing(false)}
          />
        </div>
        
        {showConsole && (
          <ConsoleOutput logs={consoleLogs} onClear={handleClearConsole} />
        )}
      </div>
    </div>
  );
};

export default EnhancedPreview;
