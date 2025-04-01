import React, { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import './PerformanceDashboard.css';
import reportWebVitals from './reportWebVitals';
import { Chart, registerables } from 'chart.js';
Chart.register(...registerables);

const PerformanceDashboard = () => {
  // State for various metrics
  const [webVitals, setWebVitals] = useState({
    CLS: null,
    FID: null,
    FCP: null,
    LCP: null,
    TTFB: null
  });
  
  const [systemInfo, setSystemInfo] = useState({
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    cookiesEnabled: navigator.cookieEnabled,
    language: navigator.language,
    screenWidth: window.screen.width,
    screenHeight: window.screen.height,
    windowWidth: window.innerWidth,
    windowHeight: window.innerHeight,
    pixelRatio: window.devicePixelRatio,
    onlineStatus: navigator.onLine
  });
  
  const [memoryUsage, setMemoryUsage] = useState(null);
  const [frameRate, setFrameRate] = useState(0);
  const [networkInfo, setNetworkInfo] = useState({
    downlink: null,
    effectiveType: null,
    rtt: null
  });
  const [resourceTimings, setResourceTimings] = useState([]);
  const [pageLoadTime, setPageLoadTime] = useState(null);
  const [isEasterEggVisible, setIsEasterEggVisible] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [darkMode, setDarkMode] = useState(false);
  const [cpuInfo, setCpuInfo] = useState({ usage: 0 });
  const [simulatedLoad, setSimulatedLoad] = useState(0);
  const [isReferrerScanner, setIsReferrerScanner] = useState(false);
  
  // Refs for charts
  const vitalsChartRef = useRef(null);
  const memoryChartRef = useRef(null);
  const framerateChartRef = useRef(null);
  const vitalsChartInstance = useRef(null);
  const memoryChartInstance = useRef(null);
  const framerateChartInstance = useRef(null);
  
  // Historical data for charts
  const [memoryHistory, setMemoryHistory] = useState([]);
  const [framerateHistory, setFramerateHistory] = useState([]);
  
  const location = useLocation();
  
  // Easter egg detection on mount
  useEffect(() => {
    // Check if came from suspicious referrer or potential directory scanner
    const referrer = document.referrer;
    const possibleScanners = ['dirbuster', 'dirb', 'gobuster', 'wfuzz', 'burp', 'nikto', 'nessus', 'acunetix', 'nmap'];
    
    // If there's no referrer or the referrer has a suspicious term
    if (!referrer || possibleScanners.some(scanner => referrer.toLowerCase().includes(scanner))) {
      setTimeout(() => {
        setIsReferrerScanner(true);
        setIsEasterEggVisible(true);
      }, 2000);
    }
    
    // If URL has specific parameters that could be from scanning
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('scan') || urlParams.has('test') || urlParams.has('debug')) {
      setTimeout(() => {
        setIsEasterEggVisible(true);
      }, 2000);
    }
  }, []);

  // Initialize theme from local storage
  useEffect(() => {
    const savedTheme = localStorage.getItem('performanceDashboardTheme');
    if (savedTheme === 'dark') {
      setDarkMode(true);
      document.body.classList.add('dark-mode');
    }
  }, []);

  // Toggle dark mode
  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
    if (!darkMode) {
      document.body.classList.add('dark-mode');
      localStorage.setItem('performanceDashboardTheme', 'dark');
    } else {
      document.body.classList.remove('dark-mode');
      localStorage.setItem('performanceDashboardTheme', 'light');
    }
    
    // Redraw charts with new theme
    if (vitalsChartInstance.current) {
      vitalsChartInstance.current.destroy();
      initVitalsChart();
    }
    if (memoryChartInstance.current) {
      memoryChartInstance.current.destroy();
      initMemoryChart();
    }
    if (framerateChartInstance.current) {
      framerateChartInstance.current.destroy();
      initFramerateChart();
    }
  };

  // Web Vitals collection
  useEffect(() => {
    function handlePerfMetric(metric) {
      setWebVitals(prevMetrics => ({
        ...prevMetrics,
        [metric.name]: metric.value
      }));
    }
    
    reportWebVitals(handlePerfMetric);
  }, []);
  
  // Memory and CPU usage monitoring
  useEffect(() => {
    const memoryInterval = setInterval(() => {
      // Check if performance.memory is available (Chrome only)
      if (window.performance && window.performance.memory) {
        const memory = {
          jsHeapSizeLimit: window.performance.memory.jsHeapSizeLimit,
          totalJSHeapSize: window.performance.memory.totalJSHeapSize,
          usedJSHeapSize: window.performance.memory.usedJSHeapSize
        };
        setMemoryUsage(memory);
        
        // Update memory history for chart (keep last 60 points)
        setMemoryHistory(prevHistory => {
          const newHistory = [...prevHistory, 
            {time: new Date().toLocaleTimeString(), 
             value: (memory.usedJSHeapSize / memory.jsHeapSizeLimit) * 100}];
          if (newHistory.length > 60) return newHistory.slice(1);
          return newHistory;
        });
      }
      
      // Simulate CPU usage since we can't directly measure it in browser
      setCpuInfo(prev => {
        const randomVariation = Math.random() * 5 - 2.5; // -2.5 to 2.5
        let newValue = prev.usage + randomVariation + (simulatedLoad * 10);
        newValue = Math.min(Math.max(newValue, 0), 100); // Keep between 0-100
        return { usage: newValue };
      });
    }, 1000);
    
    return () => clearInterval(memoryInterval);
  }, [simulatedLoad]);
  
  // Frame rate monitoring
  useEffect(() => {
    let frames = 0;
    let lastTime = performance.now();
    let animFrameId;
    
    const countFrames = () => {
      frames++;
      const currentTime = performance.now();
      
      if (currentTime - lastTime >= 1000) {
        setFrameRate(frames);
        
        // Update framerate history (keep last 60 points)
        setFramerateHistory(prevHistory => {
          const newHistory = [...prevHistory, 
            {time: new Date().toLocaleTimeString(), value: frames}];
          if (newHistory.length > 60) return newHistory.slice(1);
          return newHistory;
        });
        
        frames = 0;
        lastTime = currentTime;
      }
      
      animFrameId = requestAnimationFrame(countFrames);
    };
    
    animFrameId = requestAnimationFrame(countFrames);
    return () => cancelAnimationFrame(animFrameId);
  }, []);
  
  // Network info collection
  useEffect(() => {
    // Get network information if available
    if ('connection' in navigator) {
      const conn = navigator.connection;
      
      setNetworkInfo({
        downlink: conn.downlink,
        effectiveType: conn.effectiveType,
        rtt: conn.rtt
      });
      
      // Listen for changes
      const updateNetworkInfo = () => {
        setNetworkInfo({
          downlink: conn.downlink,
          effectiveType: conn.effectiveType,
          rtt: conn.rtt
        });
      };
      
      conn.addEventListener('change', updateNetworkInfo);
      return () => conn.removeEventListener('change', updateNetworkInfo);
    }
  }, []);
  
  // Resource timing collection
  useEffect(() => {
    const collectResourceTimings = () => {
      const resources = performance.getEntriesByType('resource');
      const resourceData = resources.slice(-10).map(resource => ({
        name: resource.name.split('/').pop(),
        duration: resource.duration,
        size: resource.transferSize
      }));
      
      setResourceTimings(resourceData);
    };
    
    collectResourceTimings();
    const interval = setInterval(collectResourceTimings, 5000);
    
    return () => clearInterval(interval);
  }, []);
  
  // Page load time
  useEffect(() => {
    if (window.performance && window.performance.timing) {
      const timing = window.performance.timing;
      const loadTime = timing.loadEventEnd - timing.navigationStart;
      setPageLoadTime(loadTime);
    }
  }, []);
  
  // Charts initialization
  useEffect(() => {
    initVitalsChart();
    initMemoryChart();
    initFramerateChart();
    
    return () => {
      if (vitalsChartInstance.current) vitalsChartInstance.current.destroy();
      if (memoryChartInstance.current) memoryChartInstance.current.destroy();
      if (framerateChartInstance.current) framerateChartInstance.current.destroy();
    };
  }, [webVitals, memoryHistory, framerateHistory, darkMode]);
  
  // Charts initialization functions
  const initVitalsChart = () => {
    if (!vitalsChartRef.current) return;
    
    const ctx = vitalsChartRef.current.getContext('2d');
    
    // If chart already exists, destroy it
    if (vitalsChartInstance.current) {
      vitalsChartInstance.current.destroy();
    }
    
    const textColor = darkMode ? '#eaeaea' : '#333333';
    const gridColor = darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
    
    vitalsChartInstance.current = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['CLS', 'FID (ms)', 'FCP (ms)', 'LCP (ms)', 'TTFB (ms)'],
        datasets: [{
          label: 'Web Vitals',
          data: [
            webVitals.CLS || 0,
            webVitals.FID || 0,
            webVitals.FCP || 0,
            webVitals.LCP || 0,
            webVitals.TTFB || 0
          ],
          backgroundColor: [
            'rgba(75, 192, 192, 0.6)',  // CLS
            'rgba(255, 99, 132, 0.6)',  // FID
            'rgba(54, 162, 235, 0.6)',  // FCP
            'rgba(255, 206, 86, 0.6)',  // LCP
            'rgba(153, 102, 255, 0.6)'  // TTFB
          ],
          borderColor: [
            'rgba(75, 192, 192, 1)',
            'rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)',
            'rgba(255, 206, 86, 1)',
            'rgba(153, 102, 255, 1)'
          ],
          borderWidth: 1
        }]
      },
      options: {
        plugins: {
          legend: {
            labels: {
              color: textColor
            }
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              color: textColor
            },
            grid: {
              color: gridColor
            }
          },
          x: {
            ticks: {
              color: textColor
            },
            grid: {
              color: gridColor
            }
          }
        }
      }
    });
  };
  
  const initMemoryChart = () => {
    if (!memoryChartRef.current || memoryHistory.length === 0) return;
    
    const ctx = memoryChartRef.current.getContext('2d');
    
    // If chart already exists, destroy it
    if (memoryChartInstance.current) {
      memoryChartInstance.current.destroy();
    }
    
    const textColor = darkMode ? '#eaeaea' : '#333333';
    const gridColor = darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
    
    memoryChartInstance.current = new Chart(ctx, {
      type: 'line',
      data: {
        labels: memoryHistory.map(point => point.time),
        datasets: [{
          label: 'Memory Usage %',
          data: memoryHistory.map(point => point.value),
          fill: true,
          backgroundColor: 'rgba(75, 192, 192, 0.2)',
          borderColor: 'rgba(75, 192, 192, 1)',
          tension: 0.1
        }]
      },
      options: {
        plugins: {
          legend: {
            labels: {
              color: textColor
            }
          }
        },
        scales: {
          y: {
            min: 0,
            max: 100,
            ticks: {
              color: textColor
            },
            grid: {
              color: gridColor
            }
          },
          x: {
            ticks: {
              color: textColor,
              maxRotation: 0,
              autoSkip: true,
              maxTicksLimit: 10
            },
            grid: {
              color: gridColor
            }
          }
        }
      }
    });
  };
  
  const initFramerateChart = () => {
    if (!framerateChartRef.current || framerateHistory.length === 0) return;
    
    const ctx = framerateChartRef.current.getContext('2d');
    
    // If chart already exists, destroy it
    if (framerateChartInstance.current) {
      framerateChartInstance.current.destroy();
    }
    
    const textColor = darkMode ? '#eaeaea' : '#333333';
    const gridColor = darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
    
    framerateChartInstance.current = new Chart(ctx, {
      type: 'line',
      data: {
        labels: framerateHistory.map(point => point.time),
        datasets: [{
          label: 'FPS',
          data: framerateHistory.map(point => point.value),
          fill: false,
          borderColor: 'rgba(54, 162, 235, 1)',
          tension: 0.1
        }]
      },
      options: {
        plugins: {
          legend: {
            labels: {
              color: textColor
            }
          }
        },
        scales: {
          y: {
            min: 0,
            max: 70,
            ticks: {
              color: textColor
            },
            grid: {
              color: gridColor
            }
          },
          x: {
            ticks: {
              color: textColor,
              maxRotation: 0,
              autoSkip: true,
              maxTicksLimit: 10
            },
            grid: {
              color: gridColor
            }
          }
        }
      }
    });
  };
  
  // Function to generate load for testing
  const generateLoad = (level) => {
    setSimulatedLoad(level);
    
    if (level > 0) {
      // Create a computational load
      const startTime = performance.now();
      while (performance.now() - startTime < 200 * level) {
        // Purposely inefficient code to generate load
        const arr = [];
        for (let i = 0; i < 10000 * level; i++) {
          arr.push(Math.random());
        }
        arr.sort();
      }
    }
  };
  
  // Function to handle tab switching
  const switchTab = (tab) => {
    setActiveTab(tab);
    
    // Redraw charts when switching to them
    if (tab === 'visualizations') {
      setTimeout(() => {
        initVitalsChart();
        initMemoryChart();
        initFramerateChart();
      }, 100);
    }
  };
  
  const getPerformanceScore = () => {
    let score = 0;
    let factors = 0;
    
    // FCP score - lower is better (< 2000ms is good)
    if (webVitals.FCP) {
      const fcpScore = webVitals.FCP < 1000 ? 100 : 
                       webVitals.FCP < 2000 ? 80 : 
                       webVitals.FCP < 3000 ? 60 : 
                       webVitals.FCP < 4000 ? 40 : 20;
      score += fcpScore;
      factors++;
    }
    
    // LCP score - lower is better (< 2500ms is good)
    if (webVitals.LCP) {
      const lcpScore = webVitals.LCP < 1500 ? 100 : 
                       webVitals.LCP < 2500 ? 80 : 
                       webVitals.LCP < 4000 ? 60 : 
                       webVitals.LCP < 6000 ? 40 : 20;
      score += lcpScore;
      factors++;
    }
    
    // FID score - lower is better (< 100ms is good)
    if (webVitals.FID) {
      const fidScore = webVitals.FID < 50 ? 100 : 
                       webVitals.FID < 100 ? 80 : 
                       webVitals.FID < 200 ? 60 : 
                       webVitals.FID < 300 ? 40 : 20;
      score += fidScore;
      factors++;
    }
    
    // CLS score - lower is better (< 0.1 is good)
    if (webVitals.CLS) {
      const clsScore = webVitals.CLS < 0.05 ? 100 : 
                       webVitals.CLS < 0.1 ? 80 : 
                       webVitals.CLS < 0.15 ? 60 : 
                       webVitals.CLS < 0.2 ? 40 : 20;
      score += clsScore;
      factors++;
    }
    
    // Framerate score - higher is better (> 50 is good)
    if (frameRate) {
      const framerateScore = frameRate > 58 ? 100 :
                            frameRate > 50 ? 80 :
                            frameRate > 40 ? 60 :
                            frameRate > 30 ? 40 : 20;
      score += framerateScore;
      factors++;
    }
    
    return factors > 0 ? Math.round(score / factors) : 0;
  };
  
  const getScoreClass = (score) => {
    if (score >= 90) return 'excellent';
    if (score >= 70) return 'good';
    if (score >= 50) return 'average';
    if (score >= 30) return 'poor';
    return 'bad';
  };
  
  const formatBytes = (bytes) => {
    if (!bytes) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };
  
  const score = getPerformanceScore();
  const scoreClass = getScoreClass(score);
  
  return (
    <div className={`performance-dashboard ${darkMode ? 'dark-mode' : ''}`}>
      {isEasterEggVisible && (
        <div className="easter-egg-container">
          <div className="easter-egg-message">
            <h3>🕵️‍♂️ Your are not that guy buddy</h3>
            <p>{isReferrerScanner ? 
              "Wow, you actually figured out how to use a dirbuster? Look at you, you smug little genius, practically a 1337 hax0r already! At this rate, you might crack a MySpace password by 2040, script kiddie!" : 
              "FYI, your IP and all your pathetic data is mine! So congrats, you’re fucked!"}
            </p>
            <p>Feel free to look around, its literally just performance metrics lol <span className="easter-egg-blink">@retardfinder</span></p>
            <button onClick={() => setIsEasterEggVisible(false)}>🎁</button>
          </div>
        </div>
      )}
      
      <div className="dashboard-header">
        <h1>Performance Dashboard <span className="version">v1.0.2</span></h1>
        <div className="dashboard-controls">
          <button className="theme-toggle" onClick={toggleDarkMode}>
            {darkMode ? '☀️ Light Mode' : '🌙 Dark Mode'}
          </button>
        </div>
      </div>
      
      <div className="dashboard-tabs">
        <button 
          className={activeTab === 'overview' ? 'active' : ''} 
          onClick={() => switchTab('overview')}
        >
          Overview
        </button>
        <button 
          className={activeTab === 'visualizations' ? 'active' : ''} 
          onClick={() => switchTab('visualizations')}
        >
          Visualizations
        </button>
        <button 
          className={activeTab === 'resources' ? 'active' : ''} 
          onClick={() => switchTab('resources')}
        >
          Resources
        </button>
        <button 
          className={activeTab === 'system' ? 'active' : ''} 
          onClick={() => switchTab('system')}
        >
          System Info
        </button>
        <button 
          className={activeTab === 'test' ? 'active' : ''} 
          onClick={() => switchTab('test')}
        >
          Test Tools
        </button>
      </div>
      
      <div className="dashboard-content">
        {activeTab === 'overview' && (
          <div className="overview-panel">
            <div className="performance-score">
              <div className={`score-circle ${scoreClass}`}>
                <div className="score-value">{score}</div>
              </div>
              <div className="score-label">Performance Score</div>
            </div>
            
            <div className="metrics-overview">
              <div className="metrics-group">
                <h3>Web Vitals</h3>
                <div className="metric-item">
                  <span className="metric-label">First Contentful Paint (FCP)</span>
                  <span className="metric-value">{webVitals.FCP ? `${webVitals.FCP.toFixed(1)} ms` : 'Loading...'}</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Largest Contentful Paint (LCP)</span>
                  <span className="metric-value">{webVitals.LCP ? `${webVitals.LCP.toFixed(1)} ms` : 'Loading...'}</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">First Input Delay (FID)</span>
                  <span className="metric-value">{webVitals.FID ? `${webVitals.FID.toFixed(1)} ms` : 'Loading...'}</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Cumulative Layout Shift (CLS)</span>
                  <span className="metric-value">{webVitals.CLS ? webVitals.CLS.toFixed(3) : 'Loading...'}</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Time to First Byte (TTFB)</span>
                  <span className="metric-value">{webVitals.TTFB ? `${webVitals.TTFB.toFixed(1)} ms` : 'Loading...'}</span>
                </div>
              </div>
              
              <div className="metrics-group">
                <h3>Runtime Performance</h3>
                <div className="metric-item">
                  <span className="metric-label">FPS</span>
                  <span className="metric-value">{frameRate}</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">CPU Usage (est.)</span>
                  <span className="metric-value">{cpuInfo.usage.toFixed(1)}%</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Memory Usage</span>
                  <span className="metric-value">
                    {memoryUsage ? 
                      `${formatBytes(memoryUsage.usedJSHeapSize)} / ${formatBytes(memoryUsage.jsHeapSizeLimit)}` : 
                      'Not available'}
                  </span>
                </div>
              </div>
              
              <div className="metrics-group">
                <h3>Network</h3>
                <div className="metric-item">
                  <span className="metric-label">Page Load Time</span>
                  <span className="metric-value">{pageLoadTime ? `${(pageLoadTime / 1000).toFixed(2)}s` : 'N/A'}</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Connection Type</span>
                  <span className="metric-value">{networkInfo.effectiveType || 'Unknown'}</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Downlink</span>
                  <span className="metric-value">{networkInfo.downlink ? `${networkInfo.downlink} Mbps` : 'Unknown'}</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Round Trip Time</span>
                  <span className="metric-value">{networkInfo.rtt ? `${networkInfo.rtt} ms` : 'Unknown'}</span>
                </div>
              </div>
            </div>
          </div>
        )}
        
        {activeTab === 'visualizations' && (
          <div className="visualizations-panel">
            <div className="chart-container">
              <h3>Web Vitals</h3>
              <canvas ref={vitalsChartRef}></canvas>
            </div>
            
            <div className="chart-container">
              <h3>Memory Usage Over Time</h3>
              {memoryUsage ? (
                <canvas ref={memoryChartRef}></canvas>
              ) : (
                <div className="chart-unavailable">Memory usage data not available in this browser</div>
              )}
            </div>
            
            <div className="chart-container">
              <h3>Framerate Over Time</h3>
              <canvas ref={framerateChartRef}></canvas>
            </div>
          </div>
        )}
        
        {activeTab === 'resources' && (
          <div className="resources-panel">
            <h3>Resource Timing</h3>
            
            <table className="resources-table">
              <thead>
                <tr>
                  <th>Resource</th>
                  <th>Size</th>
                  <th>Load Time</th>
                </tr>
              </thead>
              <tbody>
                {resourceTimings.length > 0 ? (
                  resourceTimings.map((resource, index) => (
                    <tr key={index}>
                      <td className="resource-name">{resource.name}</td>
                      <td>{resource.size > 0 ? formatBytes(resource.size) : 'Cached'}</td>
                      <td>{resource.duration.toFixed(1)} ms</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="3" className="no-data">No resource timing data available</td>
                  </tr>
                )}
              </tbody>
            </table>
            
            <div className="resource-summary">
              <div className="summary-item">
                <span className="summary-label">Total Resources</span>
                <span className="summary-value">{resourceTimings.length}</span>
              </div>
              <div className="summary-item">
                <span className="summary-label">Average Load Time</span>
                <span className="summary-value">
                  {resourceTimings.length > 0 
                    ? `${(resourceTimings.reduce((acc, res) => acc + res.duration, 0) / resourceTimings.length).toFixed(1)} ms` 
                    : 'N/A'}
                </span>
              </div>
              <div className="summary-item">
                <span className="summary-label">Total Transfer Size</span>
                <span className="summary-value">
                  {resourceTimings.length > 0 
                    ? formatBytes(resourceTimings.reduce((acc, res) => acc + (res.size || 0), 0)) 
                    : 'N/A'}
                </span>
              </div>
            </div>
          </div>
        )}
        
        {activeTab === 'system' && (
          <div className="system-panel">
            <h3>System Information</h3>
            
            <div className="system-info-grid">
              <div className="system-info-card">
                <h4>Browser</h4>
                <div className="info-item">
                  <span className="info-label">User Agent</span>
                  <span className="info-value">{systemInfo.userAgent}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Language</span>
                  <span className="info-value">{systemInfo.language}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Cookies Enabled</span>
                  <span className="info-value">{systemInfo.cookiesEnabled ? 'Yes' : 'No'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Online Status</span>
                  <span className="info-value">{systemInfo.onlineStatus ? 'Online' : 'Offline'}</span>
                </div>
              </div>
              
              <div className="system-info-card">
                <h4>Display</h4>
                <div className="info-item">
                  <span className="info-label">Screen Resolution</span>
                  <span className="info-value">{`${systemInfo.screenWidth} × ${systemInfo.screenHeight}`}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Window Size</span>
                  <span className="info-value">{`${systemInfo.windowWidth} × ${systemInfo.windowHeight}`}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Pixel Ratio</span>
                  <span className="info-value">{systemInfo.pixelRatio}</span>
                </div>
              </div>
              
              <div className="system-info-card">
                <h4>Hardware</h4>
                <div className="info-item">
                  <span className="info-label">Platform</span>
                  <span className="info-value">{systemInfo.platform}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Memory</span>
                  <span className="info-value">
                    {memoryUsage 
                      ? `${formatBytes(memoryUsage.usedJSHeapSize)} / ${formatBytes(memoryUsage.jsHeapSizeLimit)}` 
                      : 'Not available'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">CPU Cores (logical)</span>
                  <span className="info-value">
                    {navigator.hardwareConcurrency || 'Not available'}
                  </span>
                </div>
              </div>
              
              <div className="system-info-card">
                <h4>Application</h4>
                <div className="info-item">
                  <span className="info-label">Page URL</span>
                  <span className="info-value">{window.location.href}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Path</span>
                  <span className="info-value">{location.pathname}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Referrer</span>
                  <span className="info-value">{document.referrer || 'None'}</span>
                </div>
              </div>
            </div>
          </div>
        )}
        
        {activeTab === 'test' && (
          <div className="test-panel">
            <h3>Performance Test Tools</h3>
            
            <div className="test-tools">
              <div className="test-tool-card">
                <h4>CPU Load Generator</h4>
                <p>Simulate different levels of CPU usage to test performance under load.</p>
                <div className="load-buttons">
                  <button 
                    className={simulatedLoad === 0 ? 'active' : ''} 
                    onClick={() => generateLoad(0)}
                  >
                    None
                  </button>
                  <button 
                    className={simulatedLoad === 1 ? 'active' : ''} 
                    onClick={() => generateLoad(1)}
                  >
                    Low
                  </button>
                  <button 
                    className={simulatedLoad === 2 ? 'active' : ''} 
                    onClick={() => generateLoad(2)}
                  >
                    Medium
                  </button>
                  <button 
                    className={simulatedLoad === 3 ? 'active' : ''} 
                    onClick={() => generateLoad(3)}
                  >
                    High
                  </button>
                </div>
                <div className="load-indicator">
                  <div className="load-bar">
                    <div 
                      className="load-fill" 
                      style={{ width: `${cpuInfo.usage}%` }}
                    ></div>
                  </div>
                  <div className="load-value">{cpuInfo.usage.toFixed(1)}%</div>
                </div>
              </div>
              
              <div className="test-tool-card">
                <h4>Memory Usage</h4>
                <p>Current memory consumption of the application.</p>
                {memoryUsage ? (
                  <div className="memory-stats">
                    <div className="memory-item">
                      <span className="memory-label">Used</span>
                      <span className="memory-value">{formatBytes(memoryUsage.usedJSHeapSize)}</span>
                    </div>
                    <div className="memory-item">
                      <span className="memory-label">Total Allocated</span>
                      <span className="memory-value">{formatBytes(memoryUsage.totalJSHeapSize)}</span>
                    </div>
                    <div className="memory-item">
                      <span className="memory-label">Limit</span>
                      <span className="memory-value">{formatBytes(memoryUsage.jsHeapSizeLimit)}</span>
                    </div>
                    <div className="memory-progress">
                      <div className="memory-bar">
                        <div 
                          className="memory-fill" 
                          style={{ 
                            width: `${(memoryUsage.usedJSHeapSize / memoryUsage.jsHeapSizeLimit) * 100}%` 
                          }}
                        ></div>
                      </div>
                      <div className="memory-percent">
                        {((memoryUsage.usedJSHeapSize / memoryUsage.jsHeapSizeLimit) * 100).toFixed(1)}%
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="memory-unavailable">
                    Memory usage data not available in this browser
                  </div>
                )}
              </div>
              
              <div className="test-tool-card">
                <h4>Session Information</h4>
                <div className="session-info">
                  <div className="session-item">
                    <span className="session-label">Session Duration</span>
                    <span className="session-value" id="session-duration">Calculating...</span>
                  </div>
                  <div className="session-item">
                    <span className="session-label">Page URL</span>
                    <span className="session-value">{window.location.href}</span>
                  </div>
                  <div className="session-item">
                    <span className="session-label">User Agent</span>
                    <span className="session-value">{navigator.userAgent}</span>
                  </div>
                </div>
                <script dangerouslySetInnerHTML={{
                  __html: `
                    // Calculate session duration
                    const startTime = new Date();
                    setInterval(() => {
                      const now = new Date();
                      const diff = now - startTime;
                      const hours = Math.floor(diff / (1000 * 60 * 60));
                      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                      const seconds = Math.floor((diff % (1000 * 60)) / 1000);
                      
                      const formatted = 
                        (hours > 0 ? hours + 'h ' : '') + 
                        (minutes > 0 || hours > 0 ? minutes + 'm ' : '') + 
                        seconds + 's';
                      
                      document.getElementById('session-duration').textContent = formatted;
                    }, 1000);
                  `
                }} />
              </div>
            </div>
          </div>
        )}
      </div>
      
      <div className="dashboard-footer">
        <div className="footer-info">
          <span>Performance Dashboard v1.0.2</span>
          <span>• Last updated: March 31, 2025</span>
        </div>
        <div className="footer-actions">
          <button onClick={() => window.location.reload()}>Refresh Data</button>
        </div>
      </div>
    </div>
  );
};

export default PerformanceDashboard;
