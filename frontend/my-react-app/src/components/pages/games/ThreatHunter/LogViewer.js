// src/components/pages/games/ThreatHunter/LogViewer.js
import React, { useState, useEffect, useRef } from 'react';
import { FaFlag, FaRegFlag, FaExclamationTriangle, FaSearch, FaInfoCircle } from 'react-icons/fa';
import './ThreatHunter.css';

const LogViewer = ({ logs, selectedLog, flaggedLines = {}, onSelectLog, onFlagLine }) => {
  const [currentLogIndex, setCurrentLogIndex] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [currentSearchIndex, setCurrentSearchIndex] = useState(-1);
  const [highlightedLineIndex, setHighlightedLineIndex] = useState(-1);
  
  const logViewerRef = useRef(null);
  
  // Get the currently visible log
  const currentLog = logs ? logs[currentLogIndex] : null;
  
  // Auto scroll to highlighted search result
  useEffect(() => {
    if (currentSearchIndex >= 0 && searchResults.length > 0) {
      const lineIndex = searchResults[currentSearchIndex];
      setHighlightedLineIndex(lineIndex);
      
      // Find and scroll to the element
      const element = document.getElementById(`log-line-${lineIndex}`);
      if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  }, [currentSearchIndex, searchResults]);
  
  // Parse and handle log data
  const handleLogSwitch = (index) => {
    setCurrentLogIndex(index);
    if (onSelectLog) {
      onSelectLog(logs[index].id);
    }
    // Reset search when switching logs
    setSearchTerm('');
    setSearchResults([]);
    setCurrentSearchIndex(-1);
    setHighlightedLineIndex(-1);
  };
  
  // Search functionality
  const handleSearch = () => {
    if (!searchTerm.trim() || !currentLog) {
      setSearchResults([]);
      setCurrentSearchIndex(-1);
      return;
    }
    
    const results = [];
    currentLog.content.forEach((line, index) => {
      if (line.text.toLowerCase().includes(searchTerm.toLowerCase())) {
        results.push(index);
      }
    });
    
    setSearchResults(results);
    setCurrentSearchIndex(results.length > 0 ? 0 : -1);
  };
  
  const navigateSearch = (direction) => {
    if (searchResults.length === 0) return;
    
    let newIndex;
    if (direction === 'next') {
      newIndex = (currentSearchIndex + 1) % searchResults.length;
    } else {
      newIndex = (currentSearchIndex - 1 + searchResults.length) % searchResults.length;
    }
    
    setCurrentSearchIndex(newIndex);
  };
  
  const handleFlagLine = (lineIndex) => {
    if (onFlagLine && currentLog) {
      onFlagLine(currentLog.id, lineIndex);
    }
  };

  // Enhanced syntax highlighting function
  const applyLogSyntaxHighlighting = (text) => {
    if (!text) return '';
    
    // Create a temporary div element to hold the text for manipulation
    const tempElement = document.createElement('div');
    tempElement.textContent = text;
    let highlightedText = tempElement.textContent;
    
    // Define regex patterns for different elements
    const patterns = {
      // HTTP Methods
      httpMethod: /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\b/g,
      
      // HTTP Status Codes
      httpStatus: /\s(\d{3})\s/g,
      
      // IP Addresses with categorization
      ipAddress: /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g,
      
      // MAC Addresses
      macAddress: /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g,
      
      // Various Timestamp formats
      timestampISO: /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?/g,
      timestampUnix: /\b\d{10,13}\b/g,
      timestampCommonLog: /\[\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]/g,
      
      // Log levels
      logLevel: /\b(TRACE|DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|ERR|CRITICAL|CRIT|ALERT|EMERGENCY|EMERG|FATAL)\b/g,
      
      // URL paths and components
      urlPath: /\/([\w\-._~:/?#[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})+/g,
      urlAdmin: /\/admin(\/[\w\-._~:/?#[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*/g,
      urlApi: /\/api(\/[\w\-._~:/?#[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*/g,
      
      // URL Query Parameters
      urlQuery: /\?([^=]+=[^&]*(&[^=]+=[^&]*)*)(\s|$)/g,
      urlQueryParam: /([^=&]+)=([^&]*)/g,
      
      // File extensions
      fileExt: /\.(php|aspx|jsp|js|ts|html|htm|css|scss|less|json|xml|exe|dll|bat|sh|jpg|png|gif|svg|pdf|doc|xls|zip|tar|gz)\b/g,
      
      // User agents
      userAgent: /"([^"]*(Mozilla|AppleWebKit|Chrome|Safari|Firefox|Edge|MSIE|bot|crawl|spider)[^"]*)"/g,
      
      // Network ports
      networkPort: /:(\d{1,5})\b/g,
      
      // File paths
      filePath: /\b([A-Za-z]:)?((\\|\/)[^\s:*?"<>|]+)+\b/g,
      filePathSensitive: /\b([A-Za-z]:)?(\\|\/)(etc|passwd|shadow|hosts|config|wp-config\.php|\.env|\.git|\.ssh)\b/g,
      
      // Authentication-related
      authSuccess: /\b(logged in|authentication success|successfully authenticated|auth success)\b/gi,
      authFailure: /\b(authentication fail|failed login|auth fail|invalid password|incorrect password)\b/gi,
      
      // Data transfer sizes
      dataSize: /\b(\d+)(B|KB|MB|GB|TB|bytes|kB)\b/g,
      
      // Domain names
      domainName: /\b([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,})\b/gi,
      
      // SQL fragments
      sqlQuery: /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|UNION|DROP|CREATE|ALTER)\b/gi,
      sqlInjection: /('|")\s*(OR|AND)\s*['"]?\s*\d+\s*=\s*\d+\s*--/g,
      
      // Base64 content (simplified pattern)
      base64: /\b[A-Za-z0-9+/]{20,}={0,2}\b/g,
      
      // Email addresses
      email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      
      // Common attack patterns
      attackXSS: /<script>|<\/script>|javascript:|alert\(|on(load|click|mouseover|error)=/gi,
      attackSQLi: /'--|\bOR\s+1=1\b|\bAND\s+1=1\b|\/\*|\*\/|UNION\s+SELECT/gi,
      attackPathTraversal: /\.\.\//g,
      attackCmd: /\b(cmd|command|powershell|bash|sh|exec|system|passthru)\b/gi,
      
      // HTTP headers
      httpHeader: /\b(Content-Type|Authorization|X-[A-Za-z-]+|Cookie|User-Agent|Host|Referer)\b:/gi,
      
      // JSON/XML fragments
      jsonFragment: /(\{|\[).*?(\}|\])/g,
      
      // Commands and processes
      command: /\b(curl|wget|ping|nmap|ssh|telnet|ftp|nc|netcat)\b/gi,
      process: /\b(svchost|cmd|sh|bash|powershell|python|perl|ruby|java|node)\b/gi,
      processPID: /\bPID:\s*(\d+)\b/g,
      
      // Error messages
      errorMessage: /\b(error|exception|failed|failure|fatal)\b/gi,
      
      // System components
      component: /\[([\w\-.]+)\]/g,
      
      // Numbers
      number: /\b\d+\b/g,
      
      // Service names
      service: /\b(http|https|ftp|ssh|smtp|imap|pop3|ldap|dns)\b/gi,
    };
    
    // Replace each match with HTML span tags
    
    // HTTP Methods
    highlightedText = highlightedText.replace(patterns.httpMethod, (match) => {
      const lowerMatch = match.toLowerCase();
      return `<span class="http-method-${lowerMatch}">${match}</span>`;
    });
    
    // HTTP Status Codes
    highlightedText = highlightedText.replace(patterns.httpStatus, (match, statusCode) => {
      const statusClass = statusCode.startsWith('2') ? 'status-2xx' : 
                         statusCode.startsWith('3') ? 'status-3xx' : 
                         statusCode.startsWith('4') ? 'status-4xx' : 
                         statusCode.startsWith('5') ? 'status-5xx' : '';
      const specificClass = `status-${statusCode}`;
      return ` <span class="${statusClass} ${specificClass}">${statusCode}</span> `;
    });
    
    // IP Addresses
    highlightedText = highlightedText.replace(patterns.ipAddress, (match) => {
      let ipClass = 'ip-address';
      if (match.startsWith('127.') || match === '::1') {
        ipClass += ' ip-loopback';
      } else if (match.startsWith('192.168.') || match.startsWith('10.') || 
                 (match.startsWith('172.') && 
                  parseInt(match.split('.')[1]) >= 16 && 
                  parseInt(match.split('.')[1]) <= 31)) {
        ipClass += ' ip-internal';
      } else {
        ipClass += ' ip-external';
      }
      
      // Add suspicious flag for known suspicious IPs
      const suspiciousIPs = ['45.23.125.87', '185.176.43.89', '103.45.67.89', '185.123.100.45'];
      if (suspiciousIPs.includes(match)) {
        ipClass += ' ip-suspicious';
      }
      
      return `<span class="${ipClass}">${match}</span>`;
    });
    
    // MAC Addresses
    highlightedText = highlightedText.replace(patterns.macAddress, (match) => {
      return `<span class="mac-address">${match}</span>`;
    });
    
    // Timestamps
    highlightedText = highlightedText.replace(patterns.timestampISO, (match) => {
      return `<span class="timestamp timestamp-iso">${match}</span>`;
    });
    
    highlightedText = highlightedText.replace(patterns.timestampCommonLog, (match) => {
      return `<span class="timestamp timestamp-common-log">${match}</span>`;
    });
    
    highlightedText = highlightedText.replace(patterns.timestampUnix, (match) => {
      return `<span class="timestamp timestamp-unix">${match}</span>`;
    });
    
    // Log levels
    highlightedText = highlightedText.replace(patterns.logLevel, (match) => {
      const level = match.toLowerCase();
      let levelClass = '';
      
      if (level === 'trace') levelClass = 'log-level-trace';
      else if (level === 'debug') levelClass = 'log-level-debug';
      else if (level === 'info') levelClass = 'log-level-info';
      else if (level === 'notice') levelClass = 'log-level-notice';
      else if (level === 'warning' || level === 'warn') levelClass = 'log-level-warning';
      else if (level === 'error' || level === 'err') levelClass = 'log-level-error';
      else if (level === 'critical' || level === 'crit') levelClass = 'log-level-critical';
      else if (level === 'alert') levelClass = 'log-level-alert';
      else if (level === 'emergency' || level === 'emerg' || level === 'fatal') levelClass = 'log-level-emergency';
      
      return `<span class="${levelClass}">${match}</span>`;
    });
    
    // URL paths - special cases first
    highlightedText = highlightedText.replace(patterns.urlAdmin, (match) => {
      return `<span class="url-path url-admin">${match}</span>`;
    });
    
    highlightedText = highlightedText.replace(patterns.urlApi, (match) => {
      return `<span class="url-path url-api">${match}</span>`;
    });
    
    // URL queries
    highlightedText = highlightedText.replace(patterns.urlQuery, (match) => {
      // Check for suspicious query params like SQL injection or XSS
      let queryClass = "url-query-param";
      if (match.includes("'") || match.includes("script") || match.includes("alert") || 
          match.includes("../") || match.includes("../../../") || match.includes("OR 1=1")) {
        queryClass += " url-query-suspicious";
      }
      
      // Parse individual parameters
      let queryParams = match;
      queryParams = queryParams.replace(patterns.urlQueryParam, (paramMatch, name, value) => {
        return `<span class="url-query-param">${name}</span>=<span class="url-query-value">${value}</span>`;
      });
      
      return queryParams;
    });
    
    // Generic URL paths (lowest priority for URLs)
    highlightedText = highlightedText.replace(patterns.urlPath, (match) => {
      if (match.includes('admin') || match.includes('api') || match.includes('?')) {
        return match; // Already processed by more specific patterns
      }
      return `<span class="url-path">${match}</span>`;
    });
    
    // File Extensions
    highlightedText = highlightedText.replace(patterns.fileExt, (match) => {
      const ext = match.substring(1).toLowerCase(); // Remove the dot
      return `<span class="file-ext-${ext}">${match}</span>`;
    });
    
    // User Agents
    highlightedText = highlightedText.replace(patterns.userAgent, (match) => {
      let agentClass = 'user-agent';
      
      if (match.includes('Chrome')) {
        agentClass += ' user-agent-chrome';
      } else if (match.includes('Firefox')) {
        agentClass += ' user-agent-firefox';
      } else if (match.includes('Safari') && !match.includes('Chrome')) {
        agentClass += ' user-agent-safari';
      } else if (match.includes('Edge')) {
        agentClass += ' user-agent-edge';
      } else if (match.includes('MSIE') || match.includes('Trident')) {
        agentClass += ' user-agent-ie';
      }
      
      if (match.includes('bot') || match.includes('crawl') || match.includes('spider')) {
        agentClass += ' user-agent-bot';
      }
      
      if (match.includes('Android') || match.includes('iPhone') || match.includes('Mobile')) {
        agentClass += ' user-agent-mobile';
      }
      
      // Check for suspicious user agents
      if (match.includes('sqlmap') || match.includes('nikto') || match.includes('nmap') || 
          match.includes('burp') || match.includes('hydra')) {
        agentClass += ' user-agent-suspicious';
      }
      
      return `<span class="${agentClass}">${match}</span>`;
    });
    
    // Network Ports
    highlightedText = highlightedText.replace(patterns.networkPort, (match, port) => {
      const portNum = parseInt(port);
      let portClass = '';
      
      if (port === '80') portClass = 'port-http';
      else if (port === '443') portClass = 'port-https';
      else if (port === '22') portClass = 'port-ssh';
      else if (port === '21' || port === '20') portClass = 'port-ftp';
      else if (port === '25' || port === '587') portClass = 'port-smtp';
      else if (port === '3306') portClass = 'port-mysql';
      else if (port === '3389') portClass = 'port-rdp';
      else if (port === '53') portClass = 'port-dns';
      else if (portNum >= 1024 && portNum <= 49151) portClass = 'port-high';
      else if (portNum >= 49152) portClass = 'port-ephemeral';
      else portClass = 'port-uncommon';
      
      return `:${port.replace(port, `<span class="${portClass}">${port}</span>`)}`;
    });
    
    // File Paths - sensitive paths first
    highlightedText = highlightedText.replace(patterns.filePathSensitive, (match) => {
      return `<span class="file-path file-path-sensitive">${match}</span>`;
    });
    
    // Generic file paths
    highlightedText = highlightedText.replace(patterns.filePath, (match) => {
      let pathClass = 'file-path';
      
      if (match.includes('\\')) {
        pathClass += ' file-path-windows';
      } else {
        pathClass += ' file-path-linux';
      }
      
      if (match.includes('/etc/') || match.includes('/bin/') || 
          match.includes('/usr/') || match.includes('C:\\Windows\\')) {
        pathClass += ' file-path-system';
      }
      
      if (match.includes('/config/') || match.includes('/conf/') || 
          match.includes('Config') || match.includes('config')) {
        pathClass += ' file-path-config';
      }
      
      if (match.includes('/tmp/') || match.includes('Temp') || match.includes('temp')) {
        pathClass += ' file-path-temporary';
      }
      
      return `<span class="${pathClass}">${match}</span>`;
    });
    
    // Authentication events
    highlightedText = highlightedText.replace(patterns.authSuccess, (match) => {
      return `<span class="auth-success">${match}</span>`;
    });
    
    highlightedText = highlightedText.replace(patterns.authFailure, (match) => {
      return `<span class="auth-failure">${match}</span>`;
    });
    
    // Data sizes
    highlightedText = highlightedText.replace(patterns.dataSize, (match, size, unit) => {
      const sizeNum = parseInt(size);
      let sizeClass = 'data-size-small';
      
      if ((unit === 'MB' && sizeNum > 10) || 
          (unit === 'GB') || 
          (unit === 'TB')) {
        sizeClass = 'data-size-very-large';
      } else if ((unit === 'MB' && sizeNum > 1) || 
                 (unit === 'KB' && sizeNum > 1000)) {
        sizeClass = 'data-size-large';
      } else if ((unit === 'KB' && sizeNum > 100) || 
                 (unit === 'MB' && sizeNum <= 1)) {
        sizeClass = 'data-size-medium';
      }
      
      return `<span class="${sizeClass}">${match}</span>`;
    });
    
    // Domain names
    highlightedText = highlightedText.replace(patterns.domainName, (match) => {
      let domainClass = 'domain-common';
      
      if (match.includes('localhost') || match.includes('.local') || 
          match.includes('.internal') || match.includes('.intranet')) {
        domainClass = 'domain-local';
      } else if (match.includes('.example') || match.includes('.test') || 
                 match.includes('.invalid') || match.includes('.localhost')) {
        domainClass = 'domain-internal';
      } else if (match.includes('.ru') || match.includes('.cn') || 
                 match.includes('-cdn') || match.includes('.xyz') ||
                 match.includes('malicious') || match.includes('evil')) {
        domainClass = 'domain-suspicious';
      } else if (!/\.com|\.org|\.net|\.edu|\.gov/.test(match)) {
        domainClass = 'domain-uncommon';
      }
      
      return `<span class="${domainClass}">${match}</span>`;
    });
    
    // SQL injection patterns first
    highlightedText = highlightedText.replace(patterns.sqlInjection, (match) => {
      return `<span class="sql-injection">${match}</span>`;
    });
    
    // SQL fragments
    highlightedText = highlightedText.replace(patterns.sqlQuery, (match) => {
      const command = match.toLowerCase();
      let sqlClass = 'sql-query';
      
      if (command === 'select') sqlClass = 'sql-select';
      else if (command === 'insert') sqlClass = 'sql-insert';
      else if (command === 'update') sqlClass = 'sql-update';
      else if (command === 'delete') sqlClass = 'sql-delete';
      else if (command === 'drop') sqlClass = 'sql-drop';
      
      return `<span class="${sqlClass}">${match}</span>`;
    });
    
    // Base64 content
    highlightedText = highlightedText.replace(patterns.base64, (match) => {
      return `<span class="base64-content">${match}</span>`;
    });
    
    // Email addresses
    highlightedText = highlightedText.replace(patterns.email, (match) => {
      return `<span class="email-address">${match}</span>`;
    });
    
    // Attack patterns
    highlightedText = highlightedText.replace(patterns.attackXSS, (match) => {
      return `<span class="attack-xss">${match}</span>`;
    });
    
    highlightedText = highlightedText.replace(patterns.attackSQLi, (match) => {
      return `<span class="attack-sqli">${match}</span>`;
    });
    
    highlightedText = highlightedText.replace(patterns.attackPathTraversal, (match) => {
      return `<span class="attack-path-traversal">${match}</span>`;
    });
    
    highlightedText = highlightedText.replace(patterns.attackCmd, (match) => {
      return `<span class="attack-cmd-injection">${match}</span>`;
    });
    
    // HTTP headers
    highlightedText = highlightedText.replace(patterns.httpHeader, (match) => {
      let headerClass = 'header-content';
      
      if (match.startsWith('X-') || match.includes('Content-Security')) {
        headerClass = 'header-security';
      } else if (match.includes('Authorization') || match.includes('Cookie')) {
        headerClass = 'header-auth';
      } else if (match.includes('Cache')) {
        headerClass = 'header-cache';
      } else if (match.startsWith('X-')) {
        headerClass = 'header-custom';
      }
      
      return `<span class="${headerClass}">${match}</span>`;
    });
    
    // Commands
    highlightedText = highlightedText.replace(patterns.command, (match) => {
      return `<span class="command">${match}</span>`;
    });
    
    // Processes
    highlightedText = highlightedText.replace(patterns.process, (match) => {
      let processClass = 'process-regular';
      
      const systemProcesses = ['svchost', 'explorer', 'winlogon', 'services', 'csrss'];
      const suspiciousProcesses = ['mimikatz', 'netcat', 'meterpreter', 'Empire'];
      
      if (systemProcesses.some(p => match.toLowerCase().includes(p))) {
        processClass = 'process-system';
      } else if (suspiciousProcesses.some(p => match.toLowerCase().includes(p)) ||
                match.includes('svchost32')) {
        processClass = 'process-suspicious';
      }
      
      return `<span class="${processClass}">${match}</span>`;
    });
    
    // Process PIDs
    highlightedText = highlightedText.replace(patterns.processPID, (match, pid) => {
      return `PID: <span class="process-pid">${pid}</span>`;
    });
    
    // Error messages
    highlightedText = highlightedText.replace(patterns.errorMessage, (match) => {
      return `<span class="error-message">${match}</span>`;
    });
    
    // System components
    highlightedText = highlightedText.replace(patterns.component, (match, component) => {
      let componentClass = 'component';
      
      if (component.includes('db') || component.includes('sql') || component.includes('mongo')) {
        componentClass += ' component-db';
      } else if (component.includes('web') || component.includes('http')) {
        componentClass += ' component-web';
      } else if (component.includes('auth') || component.includes('login')) {
        componentClass += ' component-auth';
      } else if (component.includes('file') || component.includes('disk')) {
        componentClass += ' component-file';
      } else if (component.includes('net') || component.includes('socket')) {
        componentClass += ' component-network';
      } else if (component.includes('sec') || component.includes('firewall')) {
        componentClass += ' component-security';
      }
      
      return `[<span class="${componentClass}">${component}</span>]`;
    });
    
    // Service names
    highlightedText = highlightedText.replace(patterns.service, (match) => {
      let serviceClass = 'service-web';
      
      if (match === 'http' || match === 'https') {
        serviceClass = 'service-web';
      } else if (match === 'smtp' || match === 'imap' || match === 'pop3') {
        serviceClass = 'service-mail';
      } else if (match === 'ftp') {
        serviceClass = 'service-file';
      } else if (match === 'ssh') {
        serviceClass = 'service-secure';
      } else if (match === 'ldap') {
        serviceClass = 'service-auth';
      } else if (match === 'dns') {
        serviceClass = 'service-name';
      }
      
      return `<span class="${serviceClass}">${match}</span>`;
    });
    
    // Mark suspicious content
    // This can be based on a list of known suspicious patterns in your logs
    const suspiciousPatterns = [
      /admin' OR 1=1--/g,
      /\.\.\/\.\.\/\.\.\//g,
      /shell\.php/g,
      /backdoor/g,
      /malicious/g,
      /unexpected outbound connection/gi,
      /large file transfer/gi,
      /spawned.*?cmd\.exe/gi,
      /powershell\.exe executed encoded command/gi,
      /unusual location/gi,
      /encoded command/gi,
      /multiple files encrypted/gi,
      /ransom/gi,
      /path traversal attempt/gi,
      /potentially malicious file/gi,
      /success for user 'admin'/gi,
      /SQL injection/gi,
      /shell\.php disguised/gi
    ];
    
    for (const pattern of suspiciousPatterns) {
      highlightedText = highlightedText.replace(pattern, (match) => {
        return `<span class="suspicious-high">${match}</span>`;
      });
    }
    
    return highlightedText;
  };
  
  // If no logs are available, show a message
  if (!logs || logs.length === 0) {
    return (
      <div className="log-viewer-empty">
        <FaExclamationTriangle className="empty-icon" />
        <p>No log files available for analysis.</p>
      </div>
    );
  }
  
  // If the current log has no content
  if (currentLog && (!currentLog.content || currentLog.content.length === 0)) {
    // Log for debugging
    console.log("Current log has no content:", currentLog);
  }
  
  return (
    <div className="log-viewer">
      <div className="log-header">
        <div className="log-tabs">
          {logs.map((log, index) => (
            <button
              key={log.id}
              className={`log-tab ${index === currentLogIndex ? 'active' : ''}`}
              onClick={() => handleLogSwitch(index)}
            >
              {log.name}
            </button>
          ))}
        </div>
        
        <div className="log-search">
          <div className="search-input-container">
            <input
              type="text"
              placeholder="Search logs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
            />
            <button className="search-button" onClick={handleSearch}>
              <FaSearch />
            </button>
          </div>
          
          {searchResults.length > 0 && (
            <div className="search-navigation">
              <span className="results-count">
                {currentSearchIndex + 1}/{searchResults.length}
              </span>
              <button 
                className="nav-button prev"
                onClick={() => navigateSearch('prev')}
              >
                ↑
              </button>
              <button 
                className="nav-button next"
                onClick={() => navigateSearch('next')}
              >
                ↓
              </button>
            </div>
          )}
        </div>
      </div>
      
      <div className="log-content" ref={logViewerRef}>
        {currentLog && (
          <div className="log-info">
            <div className="log-info-header">
              <span className="log-name">{currentLog.name}</span>
              <span className="log-type">{currentLog.type}</span>
            </div>
            <div className="log-meta">
              <span className="log-timestamp">Timestamp: {currentLog.timestamp}</span>
              <span className="log-source">Source: {currentLog.source}</span>
            </div>
          </div>
        )}
        
        <div className="log-lines">
          {currentLog && currentLog.content && Array.isArray(currentLog.content) && currentLog.content.map((line, index) => {
            const isHighlighted = index === highlightedLineIndex;
            const isFlagged = currentLog && flaggedLines[currentLog.id] && 
                              flaggedLines[currentLog.id].includes(index);
            const hasSearchMatch = searchTerm && line.text && line.text.toLowerCase().includes(searchTerm.toLowerCase());
            
            // Apply syntax highlighting to the line text
            const highlightedLineText = applyLogSyntaxHighlighting(line.text);
            
            return (
              <div 
                key={index}
                id={`log-line-${index}`}
                className={`log-line ${isHighlighted ? 'highlighted' : ''} ${isFlagged ? 'flagged' : ''} ${hasSearchMatch ? 'search-match' : ''}`}
              >
                <div className="line-number">{index + 1}</div>
                <div className="line-text">
                  <div dangerouslySetInnerHTML={{ __html: highlightedLineText }} />
                </div>
                <div className="line-actions">
                  <button 
                    className={`flag-button ${isFlagged ? 'active' : ''}`}
                    onClick={() => handleFlagLine(index)}
                    title={isFlagged ? "Unflag this line" : "Flag as suspicious"}
                  >
                    {isFlagged ? <FaFlag /> : <FaRegFlag />}
                  </button>
                </div>
              </div>
            );
          })}
          
          {/* Display message if content array is empty or not defined */}
          {currentLog && (!currentLog.content || !Array.isArray(currentLog.content) || currentLog.content.length === 0) && (
            <div className="log-empty-message">
              <p>This log file appears to be empty or contains no readable content.</p>
            </div>
          )}
        </div>
      </div>
      
      <div className="log-viewer-footer">
        <div className="log-statistics">
          <span>Total Lines: {currentLog && currentLog.content ? currentLog.content.length : 0}</span>
          <span>Flagged: {currentLog && flaggedLines[currentLog.id] ? flaggedLines[currentLog.id].length : 0}</span>
        </div>
        <div className="help-text">
          <FaInfoCircle />
          <span>Click <FaRegFlag /> to flag suspicious log entries</span>
        </div>
      </div>
    </div>
  );
};

export default LogViewer;
