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
  const [customMarkName, setCustomMarkName] = useState('');
  const [customMarkList, setCustomMarkList] = useState([]);
  
  // NEW: Server metrics from backend
  const [serverMetrics, setServerMetrics] = useState({
    avgRequestTime: 0,
    avgDbQueryTime: 0,
    dataTransferRate: 0,
    throughput: 0,
    errorRate: 0,
    timestamp: new Date().toISOString()
  });
  
  // NEW: Navigation timing metrics
  const [navigationTiming, setNavigationTiming] = useState({
    dns: 0,
    tls: 0,
    connection: 0,
    ttfb: 0,
    domInteractive: 0,
    domComplete: 0,
    loadEvent: 0
  });
  
  // NEW: Performance budgets monitoring
  const [perfBudgets, setPerfBudgets] = useState({
    jsSize: { budget: 300, actual: 0, unit: 'KB' },
    cssSize: { budget: 100, actual: 0, unit: 'KB' },
    fontSize: { budget: 100, actual: 0, unit: 'KB' },
    imageSize: { budget: 500, actual: 0, unit: 'KB' },
    totalSize: { budget: 1000, actual: 0, unit: 'KB' },
    maxRequests: { budget: 30, actual: 0, unit: '' },
  });
  
  // NEW: Network requests monitoring
  const [networkRequests, setNetworkRequests] = useState([]);
  
  // NEW: Web vitals trends
  const [vitalsTrend, setVitalsTrend] = useState({
    FCP: [],
    LCP: [],
    FID: [],
    CLS: []
  });
  
  // NEW: Performance diagnosis issues
  const [performanceIssues, setPerformanceIssues] = useState([]);
  
  // Refs for charts
  const vitalsChartRef = useRef(null);
  const memoryChartRef = useRef(null);
  const framerateChartRef = useRef(null);
  const vitalsChartInstance = useRef(null);
  const memoryChartInstance = useRef(null);
  const framerateChartInstance = useRef(null);
  
  // NEW: Refs for additional charts
  const vitalsTrendChartRef = useRef(null);
  const vitalsTrendChartInstance = useRef(null);
  const navigationTimingChartRef = useRef(null);
  const navigationTimingChartInstance = useRef(null);
  const perfBudgetChartRef = useRef(null);
  const perfBudgetChartInstance = useRef(null);
  
  // Historical data for charts
  const [memoryHistory, setMemoryHistory] = useState([]);
  const [framerateHistory, setFramerateHistory] = useState([]);
  const [serverMetricsHistory, setServerMetricsHistory] = useState([]);
  
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

  // NEW: Mark performance for the dashboard load
  useEffect(() => {
    markPerformance('dashboard-loaded');
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
    initAllCharts();
  };
  
  // NEW: Custom performance marking utility
  const markPerformance = (markName, startMark = null) => {
    if (!window.performance || !window.performance.mark) return;
    
    // If start mark provided, create a measure
    if (startMark) {
      window.performance.mark(markName);
      window.performance.measure(
        `${startMark} to ${markName}`,
        startMark,
        markName
      );
      return;
    }
    
    // Otherwise just create a mark
    window.performance.mark(markName);
  };

  // NEW: Fetch server metrics from backend
  useEffect(() => {
    const fetchServerMetrics = async () => {
      try {
        const response = await fetch('/api/cracked/performance');
        if (response.ok) {
          const data = await response.json();
          setServerMetrics({
            avgRequestTime: data.avg_request_time || 0,
            avgDbQueryTime: data.avg_db_query_time_ms || 0,
            dataTransferRate: data.data_transfer_rate || 0,
            throughput: data.throughput || 0,
            errorRate: data.error_rate || 0,
            timestamp: data.timestamp || new Date().toISOString()
          });
          
          setServerMetricsHistory(prev => {
            const newHistory = [...prev, {
              time: new Date().toLocaleTimeString(),
              requestTime: data.avg_request_time || 0,
              dbTime: data.avg_db_query_time_ms || 0
            }];
            if (newHistory.length > 20) return newHistory.slice(-20);
            return newHistory;
          });
        }
      } catch (error) {
        console.error('Failed to fetch server metrics:', error);
      }
    };

    fetchServerMetrics();
    const intervalId = setInterval(fetchServerMetrics, 60000); // Refresh every minute
    
    return () => clearInterval(intervalId);
  }, []);

  // Web Vitals collection with trend tracking
  useEffect(() => {
    function handlePerfMetric(metric) {
      // Update current values
      setWebVitals(prevMetrics => ({
        ...prevMetrics,
        [metric.name]: metric.value
      }));
      
      // Add to trend data (limit to last 10 data points)
      if (['FCP', 'LCP', 'FID', 'CLS'].includes(metric.name)) {
        setVitalsTrend(prev => {
          const newTrend = {...prev};
          if (metric.name in newTrend) {
            newTrend[metric.name] = [...prev[metric.name], {
              timestamp: new Date().toLocaleTimeString(),
              value: metric.value
            }].slice(-10);
          }
          return newTrend;
        });
      }
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
        size: resource.transferSize,
        type: resource.initiatorType
      }));
      
      setResourceTimings(resourceData);
    };
    
    collectResourceTimings();
    const interval = setInterval(collectResourceTimings, 5000);
    
    return () => clearInterval(interval);
  }, []);
  
  // NEW: Network requests monitoring
  useEffect(() => {
    // Use PerformanceObserver to monitor resource loads
    if (window.PerformanceObserver) {
      const observer = new PerformanceObserver((list) => {
        const entries = list.getEntries().filter(entry => 
          entry.initiatorType === 'fetch' || 
          entry.initiatorType === 'xmlhttprequest'
        );
        
        if (entries.length > 0) {
          setNetworkRequests(prev => {
            const newRequests = [...prev, ...entries.map(entry => ({
              url: entry.name.split('?')[0], // Remove query params
              duration: entry.duration,
              size: entry.transferSize,
              timestamp: new Date().toLocaleTimeString()
            }))];
            
            // Keep only the last 20 requests
            return newRequests.slice(-20);
          });
        }
      });
      
      observer.observe({ entryTypes: ['resource'] });
      return () => observer.disconnect();
    }
  }, []);
  
  // NEW: Navigation timing metrics
  useEffect(() => {
    if (performance && performance.timing) {
      const timing = performance.timing;
      
      // Get detailed timing
      setNavigationTiming({
        dns: timing.domainLookupEnd - timing.domainLookupStart,
        tls: timing.secureConnectionStart > 0 ? timing.connectEnd - timing.secureConnectionStart : 0,
        connection: timing.connectEnd - timing.connectStart,
        ttfb: timing.responseStart - timing.requestStart,
        domInteractive: timing.domInteractive - timing.responseEnd,
        domComplete: timing.domComplete - timing.domInteractive,
        loadEvent: timing.loadEventEnd - timing.loadEventStart
      });
    }
  }, []);
  
  // Page load time
  useEffect(() => {
    if (window.performance && window.performance.timing) {
      const timing = window.performance.timing;
      const loadTime = timing.loadEventEnd - timing.navigationStart;
      setPageLoadTime(loadTime);
    }
  }, []);
  
  // NEW: Performance Budget calculation
  useEffect(() => {
    if (window.performance) {
      const resources = performance.getEntriesByType('resource');
      
      const sizes = {
        js: 0,
        css: 0,
        font: 0,
        image: 0,
        total: 0,
        requests: resources.length
      };
      
      resources.forEach(resource => {
        const size = resource.transferSize;
        sizes.total += size;
        
        if (resource.name.endsWith('.js')) sizes.js += size;
        else if (resource.name.endsWith('.css')) sizes.css += size;
        else if (resource.name.match(/\.(woff2?|ttf|otf|eot)/)) sizes.font += size;
        else if (resource.name.match(/\.(jpe?g|png|gif|svg|webp)/)) sizes.image += size;
      });
      
      setPerfBudgets({
        jsSize: { ...perfBudgets.jsSize, actual: Math.round(sizes.js / 1024) },
        cssSize: { ...perfBudgets.cssSize, actual: Math.round(sizes.css / 1024) },
        fontSize: { ...perfBudgets.fontSize, actual: Math.round(sizes.font / 1024) },
        imageSize: { ...perfBudgets.imageSize, actual: Math.round(sizes.image / 1024) },
        totalSize: { ...perfBudgets.totalSize, actual: Math.round(sizes.total / 1024) },
        maxRequests: { ...perfBudgets.maxRequests, actual: sizes.requests },
      });
    }
  }, []);
  
  // NEW: Automated performance diagnosis
  useEffect(() => {
    const runDiagnosis = () => {
      const issues = [];
      
      // Check Core Web Vitals
      if (webVitals.LCP > 2500) {
        issues.push({
          severity: 'high',
          area: 'Loading',
          issue: `Slow Largest Contentful Paint (${webVitals.LCP ? webVitals.LCP.toFixed(0) : "N/A"}ms)`,
          impact: 'Users perceive slow page loads, hurting engagement',
          solutions: [
            'Optimize and preload the LCP image/text',
            'Eliminate render-blocking resources',
            'Implement critical CSS',
            'Optimize server response times'
          ]
        });
      }
      
      if (webVitals.FID > 100) {
        issues.push({
          severity: 'high',
          area: 'Interactivity',
          issue: `Poor First Input Delay (${webVitals.FID ? webVitals.FID.toFixed(0) : "N/A"}ms)`,
          impact: 'Users experience lag when interacting with the page',
          solutions: [
            'Break up long JavaScript tasks',
            'Optimize event handlers',
            'Use web workers for heavy processing',
            'Reduce JavaScript execution time'
          ]
        });
      }
      
      if (webVitals.CLS > 0.1) {
        issues.push({
          severity: 'high',
          area: 'Visual Stability',
          issue: `High Cumulative Layout Shift (${webVitals.CLS ? webVitals.CLS.toFixed(3) : "N/A"})`,
          impact: 'Page elements move unexpectedly, frustrating users',
          solutions: [
            'Set explicit width/height for media elements',
            'Avoid inserting content above existing elements',
            'Use transform animations instead of properties that trigger layout changes',
            'Reserve space for dynamic content'
          ]
        });
      }
      
      // Check performance budget
      Object.entries(perfBudgets).forEach(([key, budget]) => {
        if (budget.actual > budget.budget) {
          const resourceType = key.replace('Size', '').replace('max', '');
          issues.push({
            severity: 'medium',
            area: 'Resource Size',
            issue: `${resourceType.toUpperCase()} exceeds budget (${budget.actual}${budget.unit} / ${budget.budget}${budget.unit})`,
            impact: 'Increased load time and bandwidth consumption',
            solutions: [
              `Optimize ${resourceType} resources`,
              'Implement code splitting',
              'Remove unused code',
              'Consider lazy loading techniques'
            ]
          });
        }
      });
      
      // Check server response time
      if (serverMetrics.avgRequestTime > 0.5) {
        issues.push({
          severity: 'medium',
          area: 'Server Performance',
          issue: `Slow server response time (${serverMetrics.avgRequestTime.toFixed(2)}s)`,
          impact: 'All user interactions are delayed by slow backend responses',
          solutions: [
            'Optimize database queries',
            'Implement caching',
            'Review server-side code efficiency',
            'Consider CDN or edge functions for static content'
          ]
        });
      }
      
      if (frameRate < 30) {
        issues.push({
          severity: 'medium',
          area: 'Animation Performance',
          issue: `Low framerate (${frameRate} FPS)`,
          impact: 'Animations and scrolling appear janky and unresponsive',
          solutions: [
            'Reduce JavaScript execution on the main thread',
            'Optimize CSS animations to use GPU acceleration',
            'Reduce DOM complexity',
            'Avoid forced reflows'
          ]
        });
      }
      
      setPerformanceIssues(issues);
    };
    
    // Run diagnosis when key metrics are updated
    if (webVitals.LCP || webVitals.FID || webVitals.CLS) {
      runDiagnosis();
    }
  }, [webVitals, perfBudgets, serverMetrics, frameRate]);
  
  // Initialize all charts
  const initAllCharts = () => {
    initVitalsChart();
    initMemoryChart();
    initFramerateChart();
    
    if (vitalsTrendChartRef.current) {
      initVitalsTrendChart();
    }
    
    if (navigationTimingChartRef.current) {
      initNavigationTimingChart();
    }
    
    if (perfBudgetChartRef.current) {
      initPerfBudgetChart();
    }
  };
  
  // Charts initialization on mount and data updates
  useEffect(() => {
    initAllCharts();
    
    return () => {
      // Cleanup chart instances
      if (vitalsChartInstance.current) vitalsChartInstance.current.destroy();
      if (memoryChartInstance.current) memoryChartInstance.current.destroy();
      if (framerateChartInstance.current) framerateChartInstance.current.destroy();
      if (vitalsTrendChartInstance.current) vitalsTrendChartInstance.current.destroy();
      if (navigationTimingChartInstance.current) navigationTimingChartInstance.current.destroy();
      if (perfBudgetChartInstance.current) perfBudgetChartInstance.current.destroy();
    };
  }, [webVitals, memoryHistory, framerateHistory, vitalsTrend, navigationTiming, perfBudgets, darkMode]);
  
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
  
  // NEW: Initialize Web Vitals trend chart
  const initVitalsTrendChart = () => {
    if (!vitalsTrendChartRef.current) return;
    
    // Check if at least one metric has data
    const hasData = Object.values(vitalsTrend).some(arr => arr.length > 0);
    if (!hasData) return;
    
    const ctx = vitalsTrendChartRef.current.getContext('2d');
    
    // If chart already exists, destroy it
    if (vitalsTrendChartInstance.current) {
      vitalsTrendChartInstance.current.destroy();
    }
    
    const textColor = darkMode ? '#eaeaea' : '#333333';
    const gridColor = darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
    
    // Create datasets for each metric that has data
    const datasets = [];
    
    if (vitalsTrend.FCP.length > 0) {
      datasets.push({
        label: 'FCP (ms)',
        data: vitalsTrend.FCP.map(point => point.value),
        borderColor: 'rgba(54, 162, 235, 1)',
        fill: false,
        tension: 0.1
      });
    }
    
    if (vitalsTrend.LCP.length > 0) {
      datasets.push({
        label: 'LCP (ms)',
        data: vitalsTrend.LCP.map(point => point.value),
        borderColor: 'rgba(255, 206, 86, 1)',
        fill: false,
        tension: 0.1
      });
    }
    
    if (vitalsTrend.FID.length > 0) {
      datasets.push({
        label: 'FID (ms)',
        data: vitalsTrend.FID.map(point => point.value),
        borderColor: 'rgba(255, 99, 132, 1)',
        fill: false,
        tension: 0.1
      });
    }
    
    if (vitalsTrend.CLS.length > 0) {
      datasets.push({
        label: 'CLS',
        data: vitalsTrend.CLS.map(point => point.value),
        borderColor: 'rgba(75, 192, 192, 1)',
        fill: false,
        tension: 0.1,
        yAxisID: 'y1'
      });
    }
    
    // Use timestamps from the first metric that has data
    const labels = Object.values(vitalsTrend).find(arr => arr.length > 0).map(point => point.timestamp);
    
    vitalsTrendChartInstance.current = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: datasets
      },
      options: {
        plugins: {
          legend: {
            labels: {
              color: textColor
            }
          },
          title: {
            display: true,
            text: 'Web Vitals Over Time',
            color: textColor
          }
        },
        scales: {
          y: {
            type: 'linear',
            display: true,
            position: 'left',
            title: {
              display: true,
              text: 'Time (ms)',
              color: textColor
            },
            ticks: {
              color: textColor
            },
            grid: {
              color: gridColor
            }
          },
          y1: {
            type: 'linear',
            display: true,
            position: 'right',
            title: {
              display: true,
              text: 'CLS Value',
              color: textColor
            },
            ticks: {
              color: textColor
            },
            grid: {
              drawOnChartArea: false
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
  
  // NEW: Initialize Navigation Timing chart
  const initNavigationTimingChart = () => {
    if (!navigationTimingChartRef.current) return;
    
    const ctx = navigationTimingChartRef.current.getContext('2d');
    
    // If chart already exists, destroy it
    if (navigationTimingChartInstance.current) {
      navigationTimingChartInstance.current.destroy();
    }
    
    const textColor = darkMode ? '#eaeaea' : '#333333';
    const gridColor = darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
    
    navigationTimingChartInstance.current = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['DNS', 'TLS', 'Connection', 'TTFB', 'DOM Interactive', 'DOM Complete', 'Load Event'],
        datasets: [{
          label: 'Time (ms)',
          data: [
            navigationTiming.dns,
            navigationTiming.tls,
            navigationTiming.connection,
            navigationTiming.ttfb,
            navigationTiming.domInteractive,
            navigationTiming.domComplete,
            navigationTiming.loadEvent
          ],
          backgroundColor: [
            'rgba(54, 162, 235, 0.6)',
            'rgba(75, 192, 192, 0.6)',
            'rgba(153, 102, 255, 0.6)',
            'rgba(255, 99, 132, 0.6)',
            'rgba(255, 159, 64, 0.6)',
            'rgba(255, 206, 86, 0.6)',
            'rgba(54, 162, 235, 0.6)'
          ],
          borderColor: [
            'rgba(54, 162, 235, 1)',
            'rgba(75, 192, 192, 1)',
            'rgba(153, 102, 255, 1)',
            'rgba(255, 99, 132, 1)',
            'rgba(255, 159, 64, 1)',
            'rgba(255, 206, 86, 1)',
            'rgba(54, 162, 235, 1)'
          ],
          borderWidth: 1
        }]
      },
      options: {
        indexAxis: 'y',
        plugins: {
          legend: {
            display: false
          },
          title: {
            display: true,
            text: 'Page Load Breakdown',
            color: textColor
          }
        },
        scales: {
          x: {
            ticks: {
              color: textColor
            },
            grid: {
              color: gridColor
            }
          },
          y: {
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
  
  // NEW: Initialize Performance Budget chart
  const initPerfBudgetChart = () => {
    if (!perfBudgetChartRef.current) return;
    
    const ctx = perfBudgetChartRef.current.getContext('2d');
    
    // If chart already exists, destroy it
    if (perfBudgetChartInstance.current) {
      perfBudgetChartInstance.current.destroy();
    }
    
    const textColor = darkMode ? '#eaeaea' : '#333333';
    const gridColor = darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
    
    // Prepare budget data
    const labels = Object.keys(perfBudgets).map(key => {
      // Convert camelCase to readable text
      return key
        .replace(/([A-Z])/g, ' $1') // Add space before capital letters
        .replace(/^./, str => str.toUpperCase()) // Capitalize first letter
        .replace('Size', '') // Remove 'Size' suffix
        .replace('Max', 'Max '); // Add space after 'Max'
    });
    
    const actualValues = Object.values(perfBudgets).map(budget => budget.actual);
    const budgetValues = Object.values(perfBudgets).map(budget => budget.budget);
    
    perfBudgetChartInstance.current = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Actual',
            data: actualValues,
            backgroundColor: actualValues.map((val, i) => 
              val > budgetValues[i] ? 'rgba(255, 99, 132, 0.6)' : 'rgba(54, 162, 235, 0.6)'
            ),
            borderColor: actualValues.map((val, i) => 
              val > budgetValues[i] ? 'rgba(255, 99, 132, 1)' : 'rgba(54, 162, 235, 1)'
            ),
            borderWidth: 1
          },
          {
            label: 'Budget',
            data: budgetValues,
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            borderColor: 'rgba(75, 192, 192, 1)',
            borderWidth: 1,
            borderDash: [5, 5]
          }
        ]
      },
      options: {
        plugins: {
          legend: {
            labels: {
              color: textColor
            }
          },
          title: {
            display: true,
            text: 'Performance Budget',
            color: textColor
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
        initAllCharts();
      }, 100);
    }
  };
  
  // Get performance score based on various metrics
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
    
    // Server Response Time - lower is better
    if (serverMetrics && serverMetrics.avgRequestTime) {
      const serverScore = serverMetrics.avgRequestTime < 0.05 ? 100 :
                         serverMetrics.avgRequestTime < 0.1 ? 80 :
                         serverMetrics.avgRequestTime < 0.3 ? 60 :
                         serverMetrics.avgRequestTime < 0.5 ? 40 : 20;
      score += serverScore;
      factors++;
    }
    
    return factors > 0 ? Math.round(score / factors) : 0;
  };
  
  // Get color class based on performance score
  const getScoreClass = (score) => {
    if (score >= 90) return 'excellent';
    if (score >= 70) return 'good';
    if (score >= 50) return 'average';
    if (score >= 30) return 'poor';
    return 'bad';
  };
  
  // Format bytes to human-readable size
  const formatBytes = (bytes) => {
    if (!bytes) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };
  
  // NEW: Get web vitals scores with benchmark comparisons
  const getWebVitalsScores = () => {
    const scores = {
      FCP: { 
        score: webVitals.FCP < 1800 ? 'good' : webVitals.FCP < 3000 ? 'needs-improvement' : 'poor',
        value: webVitals.FCP,
        benchmark: 1800,
        recommendation: webVitals.FCP >= 1800 ? 'Consider optimizing critical CSS and reducing server response time' : ''
      },
      LCP: { 
        score: webVitals.LCP < 2500 ? 'good' : webVitals.LCP < 4000 ? 'needs-improvement' : 'poor',
        value: webVitals.LCP,
        benchmark: 2500,
        recommendation: webVitals.LCP >= 2500 ? 'Optimize largest image/text block and implement resource prioritization' : ''
      },
      FID: { 
        score: webVitals.FID < 100 ? 'good' : webVitals.FID < 300 ? 'needs-improvement' : 'poor',
        value: webVitals.FID,
        benchmark: 100,
        recommendation: webVitals.FID >= 100 ? 'Break up long tasks and optimize JavaScript execution' : ''
      },
      CLS: { 
        score: webVitals.CLS < 0.1 ? 'good' : webVitals.CLS < 0.25 ? 'needs-improvement' : 'poor',
        value: webVitals.CLS,
        benchmark: 0.1,
        recommendation: webVitals.CLS >= 0.1 ? 'Add size attributes to images/videos and avoid inserting content above existing content' : ''
      }
    };
    
    return scores;
  };
  
  // NEW: Generate exportable performance report
  const generatePerformanceReport = () => {
    const report = {
      date: new Date().toISOString(),
      webVitals: {
        FCP: webVitals.FCP,
        LCP: webVitals.LCP,
        FID: webVitals.FID,
        CLS: webVitals.CLS,
        TTFB: webVitals.TTFB
      },
      resources: resourceTimings,
      memory: memoryUsage,
      framerate: frameRate,
      networkInfo: networkInfo,
      systemInfo: systemInfo,
      navigationTiming: navigationTiming,
      performanceScore: getPerformanceScore(),
      performanceIssues: performanceIssues,
      serverMetrics: serverMetrics,
      perfBudgets: perfBudgets
    };
    
    // Create downloadable JSON
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", `performance-report-${new Date().toISOString().slice(0,10)}.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };
  
  // NEW: Component for metric comparisons with benchmarks
  const MetricComparison = ({ metric, value, benchmark, unit }) => {
    if (value === null || value === undefined) {
      return (
        <div className="metric-comparison">
          <div className="comparison-header">
            <span>{metric}</span>
            <span className="comparison-indicator neutral">Not available</span>
          </div>
        </div>
      );
    }
    
    const percentDiff = ((value - benchmark) / benchmark) * 100;
    const isGood = metric === 'CLS' || metric === 'FID' || metric === 'LCP' || metric === 'FCP' 
      ? value < benchmark 
      : value > benchmark;
      
    return (
      <div className="metric-comparison">
        <div className="comparison-header">
          <span>{metric}</span>
          <span className={`comparison-indicator ${isGood ? 'good' : 'poor'}`}>
            {Math.abs(percentDiff).toFixed(1)}% {isGood ? 'better' : 'worse'}
          </span>
        </div>
        <div className="comparison-bars">
          <div className="your-value">
            <div className="bar-label">Your site: {value.toFixed(1)}{unit}</div>
            <div className="bar-container">
              <div className="bar" style={{ width: '100%' }}></div>
            </div>
          </div>
          <div className="benchmark-value">
            <div className="bar-label">Benchmark: {benchmark.toFixed(1)}{unit}</div>
            <div className="bar-container">
              <div className="bar benchmark" style={{ width: `${(benchmark/value)*100}%` }}></div>
            </div>
          </div>
        </div>
      </div>
    );
  };
  
  // NEW: Component for the network waterfall chart
  const NetworkWaterfallChart = () => {
    const [resources, setResources] = useState([]);
    const [startTime, setStartTime] = useState(0);
    const [endTime, setEndTime] = useState(1);
    
    useEffect(() => {
      if (performance && typeof performance.getEntriesByType === 'function') {
        const entries = performance.getEntriesByType('resource');
        
        if (entries.length > 0) {
          // Find the earliest and latest timestamps
          let minTime = entries[0].startTime;
          let maxTime = entries[0].startTime + entries[0].duration;
          
          entries.forEach(entry => {
            minTime = Math.min(minTime, entry.startTime);
            maxTime = Math.max(maxTime, entry.startTime + entry.duration);
          });
          
          setStartTime(minTime);
          setEndTime(maxTime);
          
          // Sort by start time
          const sortedEntries = [...entries].sort((a, b) => a.startTime - b.startTime);
          
          // Take the last 25 entries to avoid overcrowding
          setResources(sortedEntries.slice(-25));
        }
      }
    }, []);
    
    // Colors for different resource types
    const getResourceColor = (type) => {
      const types = {
        'script': '#FF9800',
        'css': '#2196F3',
        'fetch': '#4CAF50',
        'xmlhttprequest': '#4CAF50',
        'img': '#9C27B0',
        'font': '#F44336',
        'other': '#607D8B'
      };
      
      return types[type] || types.other;
    };
    
    // Calculate the width percentage based on time
    const getBarStyles = (resource) => {
      const totalTime = endTime - startTime;
      const startPercent = ((resource.startTime - startTime) / totalTime) * 100;
      const widthPercent = (resource.duration / totalTime) * 100;
      
      return {
        left: `${startPercent}%`,
        width: `${widthPercent}%`,
        backgroundColor: getResourceColor(resource.initiatorType)
      };
    };
    
    // Format file name from URL
    const getFileName = (url) => {
      try {
        return new URL(url).pathname.split('/').pop() || url;
      } catch {
        return url.split('/').pop() || url;
      }
    };
    
    return (
      <div className="network-waterfall-chart">
        <h3>Network Waterfall Chart</h3>
        
        <div className="timeline-container">
          <div className="timeline-header">
            <div className="timeline-labels">
              <span>Resource</span>
              <span>Type</span>
              <span>Size</span>
              <span>Time</span>
            </div>
          </div>
          
          <div className="timeline-body">
            {resources.map((resource, index) => (
              <div className="timeline-item" key={index}>
                <div className="timeline-info">
                  <span className="timeline-resource-name" title={resource.name}>
                    {getFileName(resource.name)}
                  </span>
                  <span className="timeline-resource-type">{resource.initiatorType}</span>
                  <span className="timeline-resource-size">
                    {resource.transferSize ? formatBytes(resource.transferSize) : 'cached'}
                  </span>
                  <span className="timeline-resource-duration">
                    {resource.duration.toFixed(0)}ms
                  </span>
                </div>
                <div className="timeline-bar-container">
                  <div
                    className="timeline-bar"
                    style={getBarStyles(resource)}
                    title={`${resource.name} - ${resource.duration.toFixed(0)}ms`}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
        
        <div className="timeline-legend">
          <div className="legend-item">
            <span className="legend-color" style={{backgroundColor: getResourceColor('script')}}></span>
            <span>JavaScript</span>
          </div>
          <div className="legend-item">
            <span className="legend-color" style={{backgroundColor: getResourceColor('css')}}></span>
            <span>CSS</span>
          </div>
          <div className="legend-item">
            <span className="legend-color" style={{backgroundColor: getResourceColor('img')}}></span>
            <span>Images</span>
          </div>
          <div className="legend-item">
            <span className="legend-color" style={{backgroundColor: getResourceColor('xmlhttprequest')}}></span>
            <span>XHR/Fetch</span>
          </div>
          <div className="legend-item">
            <span className="legend-color" style={{backgroundColor: getResourceColor('font')}}></span>
            <span>Fonts</span>
          </div>
        </div>
      </div>
    );
  };
  
  const score = getPerformanceScore();
  const scoreClass = getScoreClass(score);
  const webVitalsScores = getWebVitalsScores();
  
  return (
    <div className={`performance-dashboard ${darkMode ? 'dark-mode' : ''}`}>
      {isEasterEggVisible && (
        <div className="easter-egg-container">
          <div className="easter-egg-message">
            <h3>🕵️‍♂️ Your are not that guy buddy</h3>
            <p>{isReferrerScanner ? 
              "Wow, you actually figured out how to use a dirbuster? Look at you, you smug little genius, practically a 1337 hax0r already! At this rate, you might crack a MySpace password by 2040, script kiddie!" : 
              "FYI, your IP and all your pathetic data is mine! So congrats, you're fucked!"}
            </p>
            <p>Feel free to look around, its literally just performance metrics lol <span className="easter-egg-blink">@retardfinder</span></p>
            <button onClick={() => setIsEasterEggVisible(false)}>🎁</button>
          </div>
        </div>
      )}
      
      <div className="dashboard-header">
        <h1>Performance Dashboard <span className="version">v1.1.0</span></h1>
        <div className="dashboard-controls">
          <button className="export-btn" onClick={generatePerformanceReport}>
            Export Report
          </button>
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
          className={activeTab === 'diagnosis' ? 'active' : ''} 
          onClick={() => switchTab('diagnosis')}
        >
          Diagnosis
        </button>
        <button 
          className={activeTab === 'backends' ? 'active' : ''} 
          onClick={() => switchTab('backends')}
        >
          Backend Metrics
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
              
              {/* NEW: Show timestamp of last backend metrics */}
              <div className="last-updated">
                Last updated: {new Date(serverMetrics.timestamp).toLocaleTimeString()}
              </div>
            </div>
            
            <div className="metrics-overview">
              <div className="metrics-group">
                <h3>Web Vitals</h3>
                <div className="metric-item">
                  <span className="metric-label">First Contentful Paint (FCP)</span>
                  <span className={`metric-value ${webVitalsScores.FCP?.score || ''}`}>
                    {webVitals.FCP ? `${webVitals.FCP.toFixed(1)} ms` : 'Loading...'}
                  </span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Largest Contentful Paint (LCP)</span>
                  <span className={`metric-value ${webVitalsScores.LCP?.score || ''}`}>
                    {webVitals.LCP ? `${webVitals.LCP.toFixed(1)} ms` : 'Loading...'}
                  </span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">First Input Delay (FID)</span>
                  <span className={`metric-value ${webVitalsScores.FID?.score || ''}`}>
                    {webVitals.FID ? `${webVitals.FID.toFixed(1)} ms` : 'Loading...'}
                  </span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Cumulative Layout Shift (CLS)</span>
                  <span className={`metric-value ${webVitalsScores.CLS?.score || ''}`}>
                    {webVitals.CLS ? webVitals.CLS.toFixed(3) : 'Loading...'}
                  </span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Time to First Byte (TTFB)</span>
                  <span className="metric-value">
                    {webVitals.TTFB ? `${webVitals.TTFB.toFixed(1)} ms` : 'Loading...'}
                  </span>
                </div>
              </div>
              
              <div className="metrics-group">
                <h3>Runtime Performance</h3>
                <div className="metric-item">
                  <span className="metric-label">FPS</span>
                  <span className={`metric-value ${frameRate > 50 ? 'good' : frameRate > 30 ? 'needs-improvement' : 'poor'}`}>
                    {frameRate}
                  </span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">CPU Usage (est.)</span>
                  <span className={`metric-value ${cpuInfo.usage < 50 ? 'good' : cpuInfo.usage < 80 ? 'needs-improvement' : 'poor'}`}>
                    {cpuInfo.usage.toFixed(1)}%
                  </span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Memory Usage</span>
                  <span className="metric-value">
                    {memoryUsage ? 
                      `${formatBytes(memoryUsage.usedJSHeapSize)} / ${formatBytes(memoryUsage.jsHeapSizeLimit)}` : 
                      'Not available'}
                  </span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">DOM Size</span>
                  <span className="metric-value">
                    {document.querySelectorAll('*').length} elements
                  </span>
                </div>
              </div>
              
              <div className="metrics-group">
                <h3>Network</h3>
                <div className="metric-item">
                  <span className="metric-label">Page Load Time</span>
                  <span className={`metric-value ${pageLoadTime < 1000 ? 'good' : pageLoadTime < 3000 ? 'needs-improvement' : 'poor'}`}>
                    {pageLoadTime ? `${(pageLoadTime / 1000).toFixed(2)}s` : 'N/A'}
                  </span>
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
              
              {/* NEW: Backend Metrics Summary */}
              <div className="metrics-group">
                <h3>Backend Performance</h3>
                <div className="metric-item">
                  <span className="metric-label">Avg Request Time</span>
                  <span className={`metric-value ${serverMetrics.avgRequestTime < 0.1 ? 'good' : serverMetrics.avgRequestTime < 0.3 ? 'needs-improvement' : 'poor'}`}>
                    {(serverMetrics.avgRequestTime * 1000).toFixed(1)} ms
                  </span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Avg DB Query Time</span>
                  <span className={`metric-value ${serverMetrics.avgDbQueryTime < 50 ? 'good' : serverMetrics.avgDbQueryTime < 150 ? 'needs-improvement' : 'poor'}`}>
                    {serverMetrics.avgDbQueryTime.toFixed(1)} ms
                  </span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Request Throughput</span>
                  <span className="metric-value">
                    {serverMetrics.throughput.toFixed(1)} req/min
                  </span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Error Rate</span>
                  <span className={`metric-value ${serverMetrics.errorRate < 0.01 ? 'good' : serverMetrics.errorRate < 0.05 ? 'needs-improvement' : 'poor'}`}>
                    {(serverMetrics.errorRate * 100).toFixed(2)}%
                  </span>
                </div>
              </div>
            </div>
            
            {/* NEW: Performance Budget Overview */}
            <div className="perf-budget-overview">
              <h3>Performance Budget</h3>
              <div className="budget-grid">
                {Object.entries(perfBudgets).map(([key, budget]) => (
                  <div className="budget-item" key={key}>
                    <div className="budget-header">
                      <span className="budget-name">
                        {key.replace(/([A-Z])/g, ' $1')
                           .replace(/^./, str => str.toUpperCase())
                           .replace('Size', '')
                           .replace('Max', 'Max ')}
                      </span>
                      <span className={`budget-status ${budget.actual <= budget.budget ? 'good' : 'poor'}`}>
                        {budget.actual <= budget.budget ? 'Under Budget' : 'Over Budget'}
                      </span>
                    </div>
                    <div className="budget-bar-container">
                      <div 
                        className="budget-bar" 
                        style={{ width: `${Math.min(100, (budget.actual / budget.budget) * 100)}%` }}
                      ></div>
                      <div className="budget-marker" style={{ left: '100%' }}></div>
                    </div>
                    <div className="budget-values">
                      <span>{budget.actual}{budget.unit}</span>
                      <span>{budget.budget}{budget.unit}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            
            {/* NEW: Top Performance Issues */}
            {performanceIssues.length > 0 && (
              <div className="performance-issues-summary">
                <h3>Top Performance Issues</h3>
                <div className="issue-list">
                  {performanceIssues.slice(0, 3).map((issue, index) => (
                    <div className={`issue-item ${issue.severity}`} key={index}>
                      <div className="issue-header">
                        <span className="issue-area">{issue.area}</span>
                        <span className={`issue-severity ${issue.severity}`}>
                          {issue.severity.charAt(0).toUpperCase() + issue.severity.slice(1)}
                        </span>
                      </div>
                      <div className="issue-content">
                        <div className="issue-description">{issue.issue}</div>
                        <div className="issue-impact">{issue.impact}</div>
                      </div>
                    </div>
                  ))}
                </div>
                {performanceIssues.length > 3 && (
                  <button 
                    className="view-all-issues" 
                    onClick={() => switchTab('diagnosis')}
                  >
                    View All Issues ({performanceIssues.length})
                  </button>
                )}
              </div>
            )}
          </div>
        )}
        
        {activeTab === 'visualizations' && (
          <div className="visualizations-panel">
            <div className="chart-container">
              <h3>Web Vitals</h3>
              <canvas ref={vitalsChartRef}></canvas>
            </div>
            
            {/* NEW: Web Vitals Trend Chart */}
            <div className="chart-container">
              <h3>Web Vitals Over Time</h3>
              <canvas ref={vitalsTrendChartRef}></canvas>
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
            
            {/* NEW: Navigation Timing Chart */}
            <div className="chart-container">
              <h3>Page Load Breakdown</h3>
              <canvas ref={navigationTimingChartRef}></canvas>
            </div>
            
            {/* NEW: Performance Budget Chart */}
            <div className="chart-container">
              <h3>Performance Budget</h3>
              <canvas ref={perfBudgetChartRef}></canvas>
            </div>
            
            {/* NEW: Network Waterfall Chart */}
            <NetworkWaterfallChart />
          </div>
        )}
        
        {activeTab === 'resources' && (
          <div className="resources-panel">
            <h3>Resource Timing</h3>
            
            <table className="resources-table">
              <thead>
                <tr>
                  <th>Resource</th>
                  <th>Type</th>
                  <th>Size</th>
                  <th>Load Time</th>
                </tr>
              </thead>
              <tbody>
                {resourceTimings.length > 0 ? (
                  resourceTimings.map((resource, index) => (
                    <tr key={index}>
                      <td className="resource-name">{resource.name}</td>
                      <td>{resource.type || 'unknown'}</td>
                      <td>{resource.size > 0 ? formatBytes(resource.size) : 'Cached'}</td>
                      <td>{resource.duration.toFixed(1)} ms</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="4" className="no-data">No resource timing data available</td>
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
            
            {/* NEW: Network Requests Monitoring */}
            <div className="network-requests">
              <h3>Recent Network Requests</h3>
              <table className="resources-table">
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Size</th>
                    <th>Duration</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {networkRequests.length > 0 ? (
                    networkRequests.map((req, index) => (
                      <tr key={index}>
                        <td className="resource-name">{req.url}</td>
                        <td>{req.size > 0 ? formatBytes(req.size) : 'Cached'}</td>
                        <td>{req.duration.toFixed(1)} ms</td>
                        <td>{req.timestamp}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="4" className="no-data">No network requests detected yet</td>
                    </tr>
                  )}
                </tbody>
              </table>
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
                <div className="info-item">
                  <span className="info-label">Color Scheme</span>
                  <span className="info-value">
                    {window.matchMedia('(prefers-color-scheme: dark)').matches ? 'Dark' : 'Light'}
                  </span>
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
                <div className="info-item">
                  <span className="info-label">Device Memory</span>
                  <span className="info-value">
                    {navigator.deviceMemory ? `${navigator.deviceMemory} GB` : 'Not available'}
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
                <div className="info-item">
                  <span className="info-label">Page Visibility</span>
                  <span className="info-value">{document.visibilityState}</span>
                </div>
              </div>
              
              <div className="system-info-card">
                <h4>Navigation Timing</h4>
                <div className="info-item">
                  <span className="info-label">DNS Lookup</span>
                  <span className="info-value">{navigationTiming.dns} ms</span>
                </div>
                <div className="info-item">
                  <span className="info-label">TCP Connection</span>
                  <span className="info-value">{navigationTiming.connection} ms</span>
                </div>
                <div className="info-item">
                  <span className="info-label">TLS Negotiation</span>
                  <span className="info-value">{navigationTiming.tls} ms</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Server Response (TTFB)</span>
                  <span className="info-value">{navigationTiming.ttfb} ms</span>
                </div>
                <div className="info-item">
                  <span className="info-label">DOM Processing</span>
                  <span className="info-value">{navigationTiming.domInteractive} ms</span>
                </div>
                <div className="info-item">
                  <span className="info-label">DOM Content Loaded</span>
                  <span className="info-value">{navigationTiming.domComplete} ms</span>
                </div>
              </div>
              
              <div className="system-info-card">
                <h4>Feature Detection</h4>
                <div className="info-item">
                  <span className="info-label">Service Worker</span>
                  <span className="info-value">{('serviceWorker' in navigator) ? 'Supported' : 'Not supported'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">WebGL</span>
                  <span className="info-value">
                    {(() => {
                      try {
                        const canvas = document.createElement('canvas');
                        return !!(window.WebGLRenderingContext && 
                          (canvas.getContext('webgl') || canvas.getContext('experimental-webgl'))) 
                          ? 'Supported' : 'Not supported';
                      } catch (e) {
                        return 'Not supported';
                      }
                    })()}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">WebP Images</span>
                  <span className="info-value">
                    {(() => {
                      const elem = document.createElement('canvas');
                      if (elem.getContext && elem.getContext('2d')) {
                        return elem.toDataURL('image/webp').indexOf('data:image/webp') === 0 
                          ? 'Supported' : 'Not supported';
                      }
                      return 'Not supported';
                    })()}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">Intersection Observer</span>
                  <span className="info-value">
                    {('IntersectionObserver' in window) ? 'Supported' : 'Not supported'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
        
        {/* NEW: Diagnosis Tab */}
        {activeTab === 'diagnosis' && (
          <div className="diagnosis-panel">
            <h3>Performance Diagnosis</h3>
            
            {/* Web Vitals Benchmarks */}
            <div className="benchmarks-panel">
              <h4>Core Web Vitals Benchmarks</h4>
              
              <div className="benchmark-metrics">
                <MetricComparison 
                  metric="First Contentful Paint" 
                  value={webVitals.FCP} 
                  benchmark={1800} 
                  unit="ms" 
                />
                <MetricComparison 
                  metric="Largest Contentful Paint" 
                  value={webVitals.LCP} 
                  benchmark={2500} 
                  unit="ms" 
                />
                <MetricComparison 
                  metric="First Input Delay" 
                  value={webVitals.FID} 
                  benchmark={100} 
                  unit="ms" 
                />
                <MetricComparison 
                  metric="Cumulative Layout Shift" 
                  value={webVitals.CLS} 
                  benchmark={0.1} 
                  unit="" 
                />
              </div>
            </div>
            
            {/* Performance Issues */}
            <div className="performance-issues">
              <h4>Detected Issues</h4>
              
              {performanceIssues.length > 0 ? (
                <div className="issues-list">
                  {performanceIssues.map((issue, index) => (
                    <div className={`issue-card ${issue.severity}`} key={index}>
                      <div className="issue-header">
                        <span className="issue-title">{issue.issue}</span>
                        <span className={`issue-severity ${issue.severity}`}>
                          {issue.severity}
                        </span>
                      </div>
                      <div className="issue-details">
                        <div className="issue-area">
                          <span className="issue-label">Area:</span> {issue.area}
                        </div>
                        <div className="issue-impact">
                          <span className="issue-label">Impact:</span> {issue.impact}
                        </div>
                        <div className="issue-solutions">
                          <span className="issue-label">Solutions:</span>
                          <ul>
                            {issue.solutions.map((solution, i) => (
                              <li key={i}>{solution}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="no-issues">
                  <p>No performance issues detected! Your application is running optimally.</p>
                </div>
              )}
            </div>
            
            {/* Recommendations */}
            <div className="recommendations">
              <h4>Web Vitals Recommendations</h4>
              
              <div className="recommendations-list">
                {Object.entries(webVitalsScores).map(([key, metric]) => (
                  metric.recommendation && (
                    <div className={`recommendation-item ${metric.score}`} key={key}>
                      <span className="recommendation-metric">{key}:</span>
                      <span className="recommendation-text">{metric.recommendation}</span>
                    </div>
                  )
                ))}
                
                {/* Default recommendations if we don't have any metric-specific ones */}
                {Object.values(webVitalsScores).every(metric => !metric.recommendation) && (
                  <div className="no-recommendations">
                    <p>All metrics are within recommended thresholds. Keep up the good work!</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
        
        {/* NEW: Backend Metrics Tab */}
        {activeTab === 'backends' && (
          <div className="backend-panel">
            <h3>Backend Performance Metrics</h3>
            
            {/* Backend Metrics Overview */}
            <div className="backend-metrics-overview">
              <div className="backend-metric-card">
                <div className="backend-metric-value">
                  {(serverMetrics.avgRequestTime * 1000).toFixed(1)} 
                  <span className="backend-metric-unit">ms</span>
                </div>
                <div className="backend-metric-label">Average Request Time</div>
                <div className={`backend-metric-indicator ${
                  serverMetrics.avgRequestTime < 0.1 ? 'good' : 
                  serverMetrics.avgRequestTime < 0.3 ? 'average' : 'poor'
                }`}></div>
              </div>
              
              <div className="backend-metric-card">
                <div className="backend-metric-value">
                  {serverMetrics.avgDbQueryTime.toFixed(1)} 
                  <span className="backend-metric-unit">ms</span>
                </div>
                <div className="backend-metric-label">Average DB Query Time</div>
                <div className={`backend-metric-indicator ${
                  serverMetrics.avgDbQueryTime < 50 ? 'good' : 
                  serverMetrics.avgDbQueryTime < 150 ? 'average' : 'poor'
                }`}></div>
              </div>
              
              <div className="backend-metric-card">
                <div className="backend-metric-value">
                  {serverMetrics.throughput.toFixed(1)} 
                  <span className="backend-metric-unit">req/min</span>
                </div>
                <div className="backend-metric-label">Throughput</div>
                <div className="backend-metric-indicator neutral"></div>
              </div>
              
              <div className="backend-metric-card">
                <div className="backend-metric-value">
                  {(serverMetrics.errorRate * 100).toFixed(2)} 
                  <span className="backend-metric-unit">%</span>
                </div>
                <div className="backend-metric-label">Error Rate</div>
                <div className={`backend-metric-indicator ${
                  serverMetrics.errorRate < 0.01 ? 'good' : 
                  serverMetrics.errorRate < 0.05 ? 'average' : 'poor'
                }`}></div>
              </div>
              
              <div className="backend-metric-card">
                <div className="backend-metric-value">
                  {serverMetrics.dataTransferRate.toFixed(2)} 
                  <span className="backend-metric-unit">MB/s</span>
                </div>
                <div className="backend-metric-label">Data Transfer Rate</div>
                <div className="backend-metric-indicator neutral"></div>
              </div>
            </div>
            
            {/* Server Response Time History */}
            {serverMetricsHistory.length > 0 && (
              <div className="chart-container">
                <h4>Server Response Time History</h4>
                <canvas ref={ref => {
                  if (ref && serverMetricsHistory.length > 0) {
                    const ctx = ref.getContext('2d');
                    new Chart(ctx, {
                      type: 'line',
                      data: {
                        labels: serverMetricsHistory.map(point => point.time),
                        datasets: [
                          {
                            label: 'Request Time (ms)',
                            data: serverMetricsHistory.map(point => point.requestTime * 1000),
                            borderColor: 'rgba(54, 162, 235, 1)',
                            fill: false,
                            tension: 0.1,
                            yAxisID: 'y'
                          },
                          {
                            label: 'DB Time (ms)',
                            data: serverMetricsHistory.map(point => point.dbTime),
                            borderColor: 'rgba(255, 99, 132, 1)',
                            fill: false,
                            tension: 0.1,
                            yAxisID: 'y'
                          }
                        ]
                      },
                      options: {
                        plugins: {
                          legend: {
                            labels: {
                              color: darkMode ? '#eaeaea' : '#333333'
                            }
                          }
                        },
                        scales: {
                          y: {
                            type: 'linear',
                            display: true,
                            position: 'left',
                            title: {
                              display: true,
                              text: 'Time (ms)',
                              color: darkMode ? '#eaeaea' : '#333333'
                            },
                            ticks: {
                              color: darkMode ? '#eaeaea' : '#333333'
                            },
                            grid: {
                              color: darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'
                            }
                          },
                          x: {
                            ticks: {
                              color: darkMode ? '#eaeaea' : '#333333',
                              maxRotation: 0,
                              autoSkip: true,
                              maxTicksLimit: 10
                            },
                            grid: {
                              color: darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'
                            }
                          }
                        }
                      }
                    });
                  }
                }}></canvas>
              </div>
            )}
            
            {/* Health Checks Section */}
            <div className="health-checks">
              <h4>API Health Status</h4>
              <div className="health-endpoints">
                <div className="health-endpoint-item">
                  <span className="health-endpoint-name">/health</span>
                  <span className="health-endpoint-status">
                    <span className="status-indicator good"></span> Operational
                  </span>
                  <span className="health-endpoint-response-time">67ms</span>
                </div>
                <div className="health-endpoint-item">
                  <span className="health-endpoint-name">/test/achievements</span>
                  <span className="health-endpoint-status">
                    <span className="status-indicator good"></span> Operational
                  </span>
                  <span className="health-endpoint-response-time">124ms</span>
                </div>
                <div className="health-endpoint-item">
                  <span className="health-endpoint-name">/test/leaderboard</span>
                  <span className="health-endpoint-status">
                    <span className="status-indicator good"></span> Operational
                  </span>
                  <span className="health-endpoint-response-time">209ms</span>
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
              
              {/* NEW: Performance marks */}
              <div className="test-tool-card">
                <h4>Custom Performance Marks</h4>
                <p>Add custom performance markers to track specific events on this page.</p>
                <div className="performance-marks-form">
                  <input 
                    type="text" 
                    className="mark-input" 
                    placeholder="Enter mark name" 
                    value={customMarkName || ''}
                    onChange={(e) => setCustomMarkName(e.target.value)}
                  />
                  <button 
                    className="mark-button"
                    onClick={() => {
                      if (customMarkName) {
                        markPerformance(customMarkName);
                        setCustomMarkList(prevList => [...prevList, {
                          name: customMarkName,
                          time: new Date().toLocaleTimeString()
                        }]);
                        setCustomMarkName('');
                      }
                    }}
                  >
                    Add Mark
                  </button>
                </div>
                
                {customMarkList && customMarkList.length > 0 ? (
                  <div className="performance-marks-list">
                    <h5>Added Marks</h5>
                    <table className="marks-table">
                      <thead>
                        <tr>
                          <th>Mark Name</th>
                          <th>Time</th>
                        </tr>
                      </thead>
                      <tbody>
                        {customMarkList.map((mark, index) => (
                          <tr key={index}>
                            <td>{mark.name}</td>
                            <td>{mark.time}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="no-marks">No custom marks added yet</div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
      
      <div className="dashboard-footer">
        <div className="footer-info">
          <span>Performance Dashboard v1.1.0</span>
          <span>• Last updated: March 31, 2025</span>
        </div>
        <div className="footer-actions">
          <button onClick={() => window.location.reload()}>Refresh Data</button>
          <button onClick={generatePerformanceReport}>Export Report</button>
        </div>
      </div>
    </div>
  );
};

export default PerformanceDashboard;
