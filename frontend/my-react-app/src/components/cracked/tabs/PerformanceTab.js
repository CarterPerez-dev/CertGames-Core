// src/components/cracked/tabs/PerformanceTab.js
import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  FaChartLine, FaSync, FaSpinner, FaExclamationTriangle, FaDatabase,
  FaBolt, FaGlobe, FaExclamation, FaServer, FaInfoCircle, FaQuestionCircle, FaHome
} from "react-icons/fa";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, 
  Tooltip, Legend, ResponsiveContainer, BarChart, Bar,
  LineChart, Line, PieChart, Pie, Cell, ScatterChart, Scatter
} from "recharts";
import { adminFetch } from '../csrfHelper';

const PerformanceTab = () => {
  const [performanceData, setPerformanceData] = useState(null);
  const [webVitals, setWebVitals] = useState(null);
  const [errorLogs, setErrorLogs] = useState([]);
  const [perfLoading, setPerfLoading] = useState(false);
  const [perfError, setPerfError] = useState(null);
  const [activeSection, setActiveSection] = useState("overview");
  // Add a ref to track scroll position
  const scrollPositionRef = useRef(0);

  // Colors for chart elements
  const COLORS = {
    primary: "#6543cc",
    secondary: "#ff4c8b",
    success: "#2ecc71",
    warning: "#f39c12",
    danger: "#e74c3c",
    info: "#3498db",
    purple: "#9b59b6",
    teal: "#1abc9c",
    orange: "#e67e22",
    darkBlue: "#34495e",
    lightBlue: "#3498db",
    lightGreen: "#2ecc71"
  };

  // Industry benchmark data for comparison
  const BENCHMARKS = {
    webVitals: {
      lcp: 2500, // ms - good LCP is under 2.5s
      fcp: 1800, // ms - good FCP is under 1.8s
      cls: 0.1,  // unitless - good CLS is under 0.1
      ttfb: 800, // ms - good TTFB is under 800ms
      inp: 200   // ms - good INP is under 200ms
    },
    database: {
      queryTime: 50,   // ms - good query time under 50ms
      requestTime: 300, // ms - good request time under 300ms
      throughput: 30    // req/min - depends on application
    }
  };

  // Functions to save and restore scroll position
  const saveScrollPosition = () => {
    scrollPositionRef.current = window.scrollY;
  };

  const restoreScrollPosition = () => {
    window.scrollTo(0, scrollPositionRef.current);
  };

  // Fetch performance data
  const fetchPerformance = useCallback(async () => {
    saveScrollPosition(); // Save scroll position before loading
    setPerfLoading(true);
    setPerfError(null);
    try {
      // Fetch main performance metrics - using adminFetch
      const res = await adminFetch("/api/cracked/performance");
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch performance metrics");
      }
      setPerformanceData(data);

      // Fetch web vitals data - using adminFetch
      const vitalsRes = await adminFetch("/api/cracked/web-vitals");
      const vitalsData = await vitalsRes.json();
      if (vitalsRes.ok) {
        setWebVitals(vitalsData);
      }

      // Fetch recent errors - using adminFetch
      const errorRes = await adminFetch("/api/cracked/recent-errors");
      const errorData = await errorRes.json();
      if (errorRes.ok) {
        setErrorLogs(errorData.errors || []);
      }
    } catch (err) {
      setPerfError(err.message);
    } finally {
      setPerfLoading(false);
      setTimeout(restoreScrollPosition, 0); // Restore scroll position after data is loaded
    }
  }, []);

  // Auto-refresh performance data every 30 seconds for real-time monitoring
  useEffect(() => {
    fetchPerformance();
    const interval = setInterval(fetchPerformance, 30000); // 30s refresh
    return () => clearInterval(interval);
  }, [fetchPerformance]);

  // Calculate health scores
  const calculateHealthScore = (data) => {
    if (!data) return { score: 0, status: "unknown" };
    
    // Calculate score based on multiple factors
    let score = 0;
    let total = 0;
    
    // Database metrics
    if (data.avg_request_time <= 0.3) {
      score += 25;
    } else if (data.avg_request_time <= 0.6) {
      score += 15;
    } else if (data.avg_request_time <= 1) {
      score += 10;
    }
    total += 25;
    
    if (data.avg_db_query_time_ms <= 50) {
      score += 25;
    } else if (data.avg_db_query_time_ms <= 100) {
      score += 15;
    } else if (data.avg_db_query_time_ms <= 150) {
      score += 10;
    }
    total += 25;
    
    if (data.error_rate <= 0.01) {
      score += 25;
    } else if (data.error_rate <= 0.03) {
      score += 15;
    } else if (data.error_rate <= 0.05) {
      score += 10;
    }
    total += 25;
    
    if (data.throughput >= 20) {
      score += 25;
    } else if (data.throughput >= 10) {
      score += 15;
    } else if (data.throughput >= 5) {
      score += 10;
    }
    total += 25;
    
    const finalScore = Math.round((score / total) * 100);
    
    let status = "critical";
    if (finalScore >= 90) {
      status = "excellent";
    } else if (finalScore >= 75) {
      status = "good";
    } else if (finalScore >= 50) {
      status = "fair";
    } else if (finalScore >= 25) {
      status = "poor";
    }
    
    return { score: finalScore, status };
  };

  // Format bytes for display
  const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };

  // Component for score indicators
  const ScoreIndicator = ({ value, benchmark, unit, colorScale = "lower-better", label }) => {
    const getColor = () => {
      if (colorScale === "lower-better") {
        if (value <= benchmark * 0.8) return COLORS.success;
        if (value <= benchmark) return COLORS.warning;
        return COLORS.danger;
      } else { // higher-better
        if (value >= benchmark * 1.2) return COLORS.success;
        if (value >= benchmark) return COLORS.warning;
        return COLORS.danger;
      }
    };
    
    return (
      <div className="admin-score-indicator">
        <div className="admin-score-value" style={{ color: getColor() }}>
          {value}{unit}
        </div>
        <div className="admin-score-benchmark">
          Target: {benchmark}{unit}
        </div>
        <div className="admin-score-label">{label}</div>
      </div>
    );
  };

  // Metric description tooltip
  const MetricDescription = ({ title, description }) => {
    const [showTooltip, setShowTooltip] = useState(false);
    
    return (
      <div className="admin-metric-description">
        <span className="admin-metric-title">{title}</span>
        <div className="admin-tooltip-container">
          <FaQuestionCircle 
            className="admin-info-icon" 
            onMouseEnter={() => setShowTooltip(true)}
            onMouseLeave={() => setShowTooltip(false)}
          />
          {showTooltip && (
            <div className="admin-metric-tooltip">
              {description}
            </div>
          )}
        </div>
      </div>
    );
  };

  // Render overview section
  const renderOverview = () => {
    if (!performanceData) return null;
    
    const healthScore = calculateHealthScore(performanceData);
    
    return (
      <div className="admin-performance-section">
        <h3 className="admin-section-title">System Overview</h3>
        
        <div className="admin-health-score-card">
          <div className="admin-health-score-value">
            <div className={`admin-health-indicator admin-health-${healthScore.status}`}>
              {healthScore.score}%
            </div>
            <div className="admin-health-label">Health Score</div>
          </div>
          <div className="admin-health-details">
            <div className="admin-health-status">
              Status: <span className={`admin-status-${healthScore.status}`}>{healthScore.status}</span>
            </div>
            <div className="admin-health-description">
              {healthScore.status === "excellent" && "All systems are performing optimally."}
              {healthScore.status === "good" && "Systems are performing well with minor issues."}
              {healthScore.status === "fair" && "Performance is acceptable but could be improved."}
              {healthScore.status === "poor" && "Several performance issues require attention."}
              {healthScore.status === "critical" && "Critical performance issues detected."}
            </div>
          </div>
        </div>
        
        <div className="admin-overview-metrics">
          <div className="admin-metric-card">
            <div className="admin-metric-icon database-icon">
              <FaDatabase />
            </div>
            <div className="admin-metric-content">
              <MetricDescription 
                title="Database" 
                description="Average time spent on database operations per request. Lower is better."
              />
              <div className="admin-metric-value">{performanceData.avg_db_query_time_ms}ms</div>
            </div>
          </div>
          
          <div className="admin-metric-card">
            <div className="admin-metric-icon response-icon">
              <FaBolt />
            </div>
            <div className="admin-metric-content">
              <MetricDescription 
                title="Response Time" 
                description="Average time to process and respond to requests. Lower is better."
              />
              <div className="admin-metric-value">{(performanceData.avg_request_time * 1000).toFixed(0)}ms</div>
            </div>
          </div>
          
          <div className="admin-metric-card">
            <div className="admin-metric-icon throughput-icon">
              <FaGlobe />
            </div>
            <div className="admin-metric-content">
              <MetricDescription 
                title="Throughput" 
                description="Number of requests handled per minute. Higher is better."
              />
              <div className="admin-metric-value">{performanceData.throughput} req/min</div>
            </div>
          </div>
          
          <div className="admin-metric-card">
            <div className="admin-metric-icon error-icon">
              <FaExclamation />
            </div>
            <div className="admin-metric-content">
              <MetricDescription 
                title="Error Rate" 
                description="Percentage of requests that result in errors. Lower is better."
              />
              <div className="admin-metric-value">{(performanceData.error_rate * 100).toFixed(2)}%</div>
            </div>
          </div>
        </div>
        
        {performanceData.history && performanceData.history.length > 0 && (
          <div className="admin-chart-container">
            <h4>Response Time Trend (Last Hour)</h4>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={performanceData.history}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis 
                  dataKey="timestamp" 
                  tick={{fill: 'var(--admin-text-secondary)'}}
                  tickFormatter={(value) => {
                    const date = new Date(value);
                    return date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                  }}
                />
                <YAxis tick={{fill: 'var(--admin-text-secondary)'}} />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'var(--admin-bg-card)',
                    border: '1px solid var(--admin-border)',
                    borderRadius: '8px'
                  }}
                  labelStyle={{color: 'var(--admin-text)'}}
                  itemStyle={{color: 'var(--admin-text)'}}
                  formatter={(value) => [`${value} ms`, 'Response Time']}
                  labelFormatter={(value) => {
                    const date = new Date(value);
                    return date.toLocaleTimeString();
                  }}
                />
                <Legend />
                <Line 
                  type="monotone" 
                  dataKey="requestTime" 
                  name="Request Time (ms)" 
                  stroke={COLORS.primary} 
                  strokeWidth={2}
                  dot={false}
                  activeDot={{r: 6, stroke: COLORS.primary, strokeWidth: 2, fill: 'var(--admin-bg-card)'}}
                />
                <Line 
                  type="monotone" 
                  dataKey="dbTime" 
                  name="DB Time (ms)" 
                  stroke={COLORS.secondary} 
                  strokeWidth={2}
                  dot={false}
                  activeDot={{r: 6, stroke: COLORS.secondary, strokeWidth: 2, fill: 'var(--admin-bg-card)'}}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    );
  };

  // Render database performance section
  const renderDatabasePerformance = () => {
    if (!performanceData) return null;
    
    // Use history data for charts if available
    const historyData = performanceData.history || [];
    
    return (
      <div className="admin-performance-section">
        <h3 className="admin-section-title">Database Performance</h3>
        
        <div className="admin-database-metrics">
          <div className="admin-metric-card">
            <div className="admin-metric-icon query-icon">
              <FaDatabase />
            </div>
            <div className="admin-metric-content">
              <MetricDescription 
                title="Query Time" 
                description="Average time spent on database operations per request. Lower is better."
              />
              <div className="admin-metric-value">
                {performanceData.avg_db_query_time_ms}
                <span className="admin-metric-unit">ms</span>
              </div>
              <div className="admin-metric-benchmark">
                Benchmark: &lt;50ms
              </div>
            </div>
          </div>
          
          <div className="admin-metric-card">
            <div className="admin-metric-icon transfer-icon">
              <FaServer />
            </div>
            <div className="admin-metric-content">
              <MetricDescription 
                title="Data Transfer" 
                description="Average amount of data transferred per request. Lower is generally better."
              />
              <div className="admin-metric-value">
                {performanceData.data_transfer_rate}
                <span className="admin-metric-unit">MB/s</span>
              </div>
            </div>
          </div>
          
          <div className="admin-metric-card">
            <div className="admin-metric-icon cache-icon">
              <FaBolt />
            </div>
            <div className="admin-metric-content">
              <MetricDescription 
                title="Cache Hit Rate" 
                description="Percentage of requests served from cache. Higher is better."
              />
              <div className="admin-metric-value">
                {performanceData.cache_hit_rate ? `${(performanceData.cache_hit_rate * 100).toFixed(1)}%` : 'N/A'}
              </div>
            </div>
          </div>
          
          <div className="admin-metric-card">
            <div className="admin-metric-icon connection-icon">
              <FaGlobe />
            </div>
            <div className="admin-metric-content">
              <MetricDescription 
                title="Active Connections" 
                description="Number of currently active database connections."
              />
              <div className="admin-metric-value">
                {performanceData.active_connections || 'N/A'}
              </div>
            </div>
          </div>
        </div>
        
        <div className="admin-charts-row">
          <div className="admin-chart-container">
            <h4>Query Time Trend</h4>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={historyData}>
                <defs>
                  <linearGradient id="colorDbTime" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={COLORS.primary} stopOpacity={0.8} />
                    <stop offset="95%" stopColor={COLORS.primary} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis 
                  dataKey="timestamp" 
                  tick={{fill: 'var(--admin-text-secondary)'}}
                  tickFormatter={(value) => {
                    const date = new Date(value);
                    return date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                  }}
                />
                <YAxis tick={{fill: 'var(--admin-text-secondary)'}} />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'var(--admin-bg-card)',
                    border: '1px solid var(--admin-border)',
                    borderRadius: '8px'
                  }}
                  labelStyle={{color: 'var(--admin-text)'}}
                  itemStyle={{color: 'var(--admin-text)'}}
                  formatter={(value) => [`${value} ms`, 'DB Query Time']}
                  labelFormatter={(value) => {
                    const date = new Date(value);
                    return date.toLocaleTimeString();
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="dbTime"
                  stroke={COLORS.primary}
                  fillOpacity={1}
                  fill="url(#colorDbTime)"
                  name="DB Query Time (ms)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          
          <div className="admin-chart-container">
            <h4>Request Time vs Data Size</h4>
            <ResponsiveContainer width="100%" height={300}>
              <ScatterChart>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis 
                  type="number" 
                  dataKey="responseBytes" 
                  name="Response Size" 
                  unit=" B"
                  tick={{fill: 'var(--admin-text-secondary)'}}
                />
                <YAxis 
                  type="number" 
                  dataKey="requestTime" 
                  name="Request Time" 
                  unit=" ms"
                  tick={{fill: 'var(--admin-text-secondary)'}}
                />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'var(--admin-bg-card)',
                    border: '1px solid var(--admin-border)',
                    borderRadius: '8px'
                  }}
                  labelStyle={{color: 'var(--admin-text)'}}
                  itemStyle={{color: 'var(--admin-text)'}}
                  formatter={(value, name) => {
                    if (name === 'Response Size') return [formatBytes(value), name];
                    return [`${value} ms`, name];
                  }}
                />
                <Legend />
                <Scatter 
                  name="Requests" 
                  data={performanceData.requests || []} 
                  fill={COLORS.info}
                />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        <div className="admin-charts-row">
          <div className="admin-chart-container">
            <h4>Throughput Trend</h4>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={historyData}>
                <defs>
                  <linearGradient id="colorThroughput" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={COLORS.success} stopOpacity={0.8} />
                    <stop offset="95%" stopColor={COLORS.success} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis 
                  dataKey="timestamp" 
                  tick={{fill: 'var(--admin-text-secondary)'}}
                  tickFormatter={(value) => {
                    const date = new Date(value);
                    return date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                  }}
                />
                <YAxis tick={{fill: 'var(--admin-text-secondary)'}} />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'var(--admin-bg-card)',
                    border: '1px solid var(--admin-border)',
                    borderRadius: '8px'
                  }}
                  labelStyle={{color: 'var(--admin-text)'}}
                  itemStyle={{color: 'var(--admin-text)'}}
                  formatter={(value) => [`${value} req/min`, 'Throughput']}
                  labelFormatter={(value) => {
                    const date = new Date(value);
                    return date.toLocaleTimeString();
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="throughput"
                  stroke={COLORS.success}
                  fillOpacity={1}
                  fill="url(#colorThroughput)"
                  name="Throughput (req/min)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          
          <div className="admin-chart-container">
            <h4>Routes by Request Count</h4>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={performanceData.routeStats || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis 
                  dataKey="route" 
                  tick={{fill: 'var(--admin-text-secondary)'}}
                />
                <YAxis tick={{fill: 'var(--admin-text-secondary)'}} />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'var(--admin-bg-card)',
                    border: '1px solid var(--admin-border)',
                    borderRadius: '8px'
                  }}
                  labelStyle={{color: 'var(--admin-text)'}}
                  itemStyle={{color: 'var(--admin-text)'}}
                />
                <Legend />
                <Bar dataKey="count" fill={COLORS.secondary} name="Request Count" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    );
  };

  // Render web vitals section
  const renderWebVitals = () => {
    if (!webVitals) return null;
    
    const vitalsData = [
      { name: 'LCP', value: webVitals.lcp.value, target: BENCHMARKS.webVitals.lcp, unit: 'ms', description: 'Largest Contentful Paint: Time until the largest content element is rendered' },
      { name: 'FCP', value: webVitals.fcp.value, target: BENCHMARKS.webVitals.fcp, unit: 'ms', description: 'First Contentful Paint: Time until first content is rendered' },
      { name: 'CLS', value: webVitals.cls.value, target: BENCHMARKS.webVitals.cls, unit: '', description: 'Cumulative Layout Shift: Measures visual stability' },
      { name: 'TTFB', value: webVitals.ttfb.value, target: BENCHMARKS.webVitals.ttfb, unit: 'ms', description: 'Time to First Byte: Time until first byte is received' },
      { name: 'INP', value: webVitals.inp.value, target: BENCHMARKS.webVitals.inp, unit: 'ms', description: 'Interaction to Next Paint: Responsiveness to user interactions' },
    ];
    
    // Prepare data for the chart
    const chartData = vitalsData.map(vital => {
      // Normalize values to percentages for the chart
      let percentage;
      
      if (vital.name === 'CLS') {
        // For CLS, lower is better, 0.1 is the target (100%)
        percentage = Math.min(100, (vital.target / Math.max(0.001, vital.value)) * 100);
      } else {
        // For time metrics, lower is better
        percentage = Math.min(100, (vital.target / Math.max(1, vital.value)) * 100);
      }
      
      return {
        name: vital.name,
        value: vital.value,
        percentage,
        target: vital.target,
        unit: vital.unit
      };
    });
    
    // Colors for the gauge chart
    const GAUGE_COLORS = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71'];
    
    return (
      <div className="admin-performance-section">
        <h3 className="admin-section-title">Web Vitals</h3>
        
        <div className="admin-web-vitals-description">
          <p>
            Web Vitals are a set of metrics that measure real-world user experience for loading performance, 
            interactivity, and visual stability. Improving these metrics enhances user experience.
          </p>
        </div>
        
        <div className="admin-web-vitals-metrics">
          {vitalsData.map(vital => (
            <div className="admin-web-vital-card" key={vital.name}>
              <div className="admin-web-vital-header">
                <h4>{vital.name}</h4>
                <div className="admin-web-vital-tooltip">
                  <FaInfoCircle className="admin-info-icon" />
                  <div className="admin-tooltip-content">
                    {vital.description}
                  </div>
                </div>
              </div>
              <div className={`admin-web-vital-value ${getVitalClass(vital.name, vital.value)}`}>
                {vital.value}{vital.unit}
              </div>
              <div className="admin-web-vital-target">
                Target: {vital.target}{vital.unit}
              </div>
              <div className="admin-web-vital-meter">
                <div 
                  className={`admin-web-vital-progress ${getVitalClass(vital.name, vital.value)}`}
                  style={{ 
                    width: `${getVitalPercentage(vital.name, vital.value, vital.target)}%` 
                  }}
                ></div>
              </div>
            </div>
          ))}
        </div>
        
        <div className="admin-charts-row">
          <div className="admin-chart-container">
            <h4>Web Vitals Performance</h4>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={chartData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="rgba(255,255,255,0.1)" />
                <XAxis 
                  type="number" 
                  domain={[0, 100]} 
                  tick={{fill: 'var(--admin-text-secondary)'}} 
                  tickFormatter={(value) => `${value}%`}
                />
                <YAxis 
                  dataKey="name" 
                  type="category" 
                  tick={{fill: 'var(--admin-text-secondary)'}} 
                />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'var(--admin-bg-card)',
                    border: '1px solid var(--admin-border)',
                    borderRadius: '8px'
                  }}
                  labelStyle={{color: 'var(--admin-text)'}}
                  itemStyle={{color: 'var(--admin-text)'}}
                  formatter={(value, name, props) => {
                    if (name === 'Performance') {
                      return [`${value.toFixed(0)}%`, name];
                    }
                    return [value, name];
                  }}
                  labelFormatter={(value) => `${value} Performance`}
                />
                <Legend />
                <Bar 
                  dataKey="percentage" 
                  name="Performance" 
                  radius={[0, 10, 10, 0]}
                  label={{ 
                    position: 'right', 
                    fill: 'var(--admin-text)', 
                    fontSize: 12,
                    formatter: (value) => `${Math.round(value)}%` 
                  }}
                >
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={getColorForPercentage(entry.percentage)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          
          <div className="admin-chart-container">
            <h4>Web Vitals History</h4>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={webVitals.history || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis 
                  dataKey="timestamp" 
                  tick={{fill: 'var(--admin-text-secondary)'}}
                  tickFormatter={(value) => {
                    const date = new Date(value);
                    return date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                  }}
                />
                <YAxis tick={{fill: 'var(--admin-text-secondary)'}} />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'var(--admin-bg-card)',
                    border: '1px solid var(--admin-border)',
                    borderRadius: '8px'
                  }}
                  labelStyle={{color: 'var(--admin-text)'}}
                  itemStyle={{color: 'var(--admin-text)'}}
                  formatter={(value, name) => {
                    if (name === 'CLS') return [value, name];
                    return [`${value} ms`, name];
                  }}
                  labelFormatter={(value) => {
                    const date = new Date(value);
                    return date.toLocaleTimeString();
                  }}
                />
                <Legend />
                <Line 
                  type="monotone" 
                  dataKey="lcp" 
                  name="LCP" 
                  stroke={COLORS.primary} 
                  dot={false}
                />
                <Line 
                  type="monotone" 
                  dataKey="fcp" 
                  name="FCP" 
                  stroke={COLORS.secondary} 
                  dot={false}
                />
                <Line 
                  type="monotone" 
                  dataKey="ttfb" 
                  name="TTFB" 
                  stroke={COLORS.info} 
                  dot={false}
                />
                <Line 
                  type="monotone" 
                  dataKey="inp" 
                  name="INP" 
                  stroke={COLORS.warning} 
                  dot={false}
                />
                <Line 
                  type="monotone" 
                  dataKey="cls" 
                  name="CLS" 
                  stroke={COLORS.success} 
                  dot={false}
                  // Scale CLS to be visible on the same chart
                  yAxisId="cls"
                />
                <YAxis 
                  yAxisId="cls" 
                  orientation="right" 
                  domain={[0, 0.5]}
                  tick={{fill: 'var(--admin-text-secondary)'}}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    );
  };

  // Helper function to get color based on percentage
  const getColorForPercentage = (percentage) => {
    if (percentage >= 90) return COLORS.success;
    if (percentage >= 75) return COLORS.lightGreen;
    if (percentage >= 50) return COLORS.warning;
    if (percentage >= 25) return COLORS.orange;
    return COLORS.danger;
  };

  // Helper function to get the CSS class for a web vital based on its value
  const getVitalClass = (name, value) => {
    switch (name) {
      case 'LCP':
        return value <= 2500 ? 'good' : value <= 4000 ? 'needs-improvement' : 'poor';
      case 'FCP':
        return value <= 1800 ? 'good' : value <= 3000 ? 'needs-improvement' : 'poor';
      case 'CLS':
        return value <= 0.1 ? 'good' : value <= 0.25 ? 'needs-improvement' : 'poor';
      case 'TTFB':
        return value <= 800 ? 'good' : value <= 1800 ? 'needs-improvement' : 'poor';
      case 'INP':
        return value <= 200 ? 'good' : value <= 500 ? 'needs-improvement' : 'poor';
      default:
        return '';
    }
  };

  // Helper function to get percentage for vital meter
  const getVitalPercentage = (name, value, target) => {
    // For all vitals, lower is better
    if (name === 'CLS') {
      // CLS is a special case with a smaller range
      const maxCLS = 0.5; // Max CLS for 0% on the meter
      return Math.max(0, 100 - ((value / maxCLS) * 100));
    }
    
    // For time-based metrics
    const maxValue = target * 2; // 2x the target is 0% on the meter
    return Math.max(0, 100 - ((value / maxValue) * 100));
  };

  // Render errors section
  const renderErrors = () => {
    return (
      <div className="admin-performance-section">
        <h3 className="admin-section-title">Error Monitoring</h3>
        
        <div className="admin-error-stats">
          <div className="admin-metric-card">
            <div className="admin-metric-icon error-rate-icon">
              <FaExclamationTriangle />
            </div>
            <div className="admin-metric-content">
              <MetricDescription 
                title="Error Rate" 
                description="Percentage of requests that result in errors. Lower is better."
              />
              <div className="admin-metric-value">
                {performanceData ? (performanceData.error_rate * 100).toFixed(2) : 0}%
              </div>
            </div>
          </div>
          
          <div className="admin-metric-card">
            <div className="admin-metric-icon error-count-icon">
              <FaExclamation />
            </div>
            <div className="admin-metric-content">
              <MetricDescription 
                title="Error Count (Last Hour)" 
                description="Total number of errors in the last hour."
              />
              <div className="admin-metric-value">
                {errorLogs ? errorLogs.length : 0}
              </div>
            </div>
          </div>
        </div>
        
        <div className="admin-error-history">
          <h4>Recent Errors</h4>
          {errorLogs && errorLogs.length > 0 ? (
            <div className="admin-error-table-container">
              <table className="admin-error-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Path</th>
                    <th>Method</th>
                    <th>Status</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {errorLogs.map((error, index) => (
                    <tr key={index}>
                      <td>{formatTime(error.timestamp)}</td>
                      <td>{error.path}</td>
                      <td>{error.method}</td>
                      <td>{error.status}</td>
                      <td>{error.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="admin-no-errors">
              <p>No errors recorded in the last hour. Great job!</p>
            </div>
          )}
        </div>
        
        {performanceData && performanceData.history && performanceData.history.length > 0 && (
          <div className="admin-chart-container">
            <h4>Error Rate History</h4>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={performanceData.history}>
                <defs>
                  <linearGradient id="colorErrorRate" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={COLORS.danger} stopOpacity={0.8} />
                    <stop offset="95%" stopColor={COLORS.danger} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis 
                  dataKey="timestamp" 
                  tick={{fill: 'var(--admin-text-secondary)'}}
                  tickFormatter={(value) => {
                    const date = new Date(value);
                    return date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                  }}
                />
                <YAxis 
                  tick={{fill: 'var(--admin-text-secondary)'}}
                  tickFormatter={(value) => `${(value * 100).toFixed(0)}%`}
                />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'var(--admin-bg-card)',
                    border: '1px solid var(--admin-border)',
                    borderRadius: '8px'
                  }}
                  labelStyle={{color: 'var(--admin-text)'}}
                  itemStyle={{color: 'var(--admin-text)'}}
                  formatter={(value) => [`${(value * 100).toFixed(2)}%`, 'Error Rate']}
                  labelFormatter={(value) => {
                    const date = new Date(value);
                    return date.toLocaleTimeString();
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="errorRate"
                  stroke={COLORS.danger}
                  fillOpacity={1}
                  fill="url(#colorErrorRate)"
                  name="Error Rate"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    );
  };

  // Render benchmarks section
  const renderBenchmarks = () => {
    if (!performanceData || !webVitals) return null;
    
    // Create comparison data
    const comparisonData = [
      {
        metric: 'Request Time',
        yours: (performanceData.avg_request_time * 1000).toFixed(0),
        industry: '300',
        unit: 'ms',
        description: 'Time to process a request'
      },
      {
        metric: 'Database Time',
        yours: performanceData.avg_db_query_time_ms,
        industry: '50',
        unit: 'ms',
        description: 'Time spent on database operations'
      },
      {
        metric: 'LCP',
        yours: webVitals.lcp.value,
        industry: BENCHMARKS.webVitals.lcp,
        unit: 'ms',
        description: 'Largest Contentful Paint'
      },
      {
        metric: 'FCP',
        yours: webVitals.fcp.value,
        industry: BENCHMARKS.webVitals.fcp,
        unit: 'ms',
        description: 'First Contentful Paint'
      },
      {
        metric: 'CLS',
        yours: webVitals.cls.value,
        industry: BENCHMARKS.webVitals.cls,
        unit: '',
        description: 'Cumulative Layout Shift'
      },
      {
        metric: 'TTFB',
        yours: webVitals.ttfb.value,
        industry: BENCHMARKS.webVitals.ttfb,
        unit: 'ms',
        description: 'Time to First Byte'
      },
      {
        metric: 'INP',
        yours: webVitals.inp.value,
        industry: BENCHMARKS.webVitals.inp,
        unit: 'ms',
        description: 'Interaction to Next Paint'
      }
    ];
    
    return (
      <div className="admin-performance-section">
        <h3 className="admin-section-title">Performance Benchmarks</h3>
        
        <div className="admin-benchmarks-description">
          <p>
            Compare your application's performance metrics with industry standards and best practices.
            For most metrics, lower values are better (except for throughput and cache hit rates).
          </p>
        </div>
        
        <div className="admin-benchmarks-table-container">
          <table className="admin-benchmarks-table">
            <thead>
              <tr>
                <th>Metric</th>
                <th>Your Value</th>
                <th>Industry Target</th>
                <th>Status</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {comparisonData.map((item, index) => (
                <tr key={index}>
                  <td>{item.metric}</td>
                  <td>{item.yours}{item.unit}</td>
                  <td>{item.industry}{item.unit}</td>
                  <td>
                    <div className={`admin-benchmark-status ${getBenchmarkStatus(item.metric, parseFloat(item.yours), parseFloat(item.industry))}`}>
                      {getBenchmarkStatus(item.metric, parseFloat(item.yours), parseFloat(item.industry))}
                    </div>
                  </td>
                  <td>{item.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        <div className="admin-benchmark-chart-container">
          <h4>Your Performance vs. Industry Standards</h4>
          <ResponsiveContainer width="100%" height={400}>
            <BarChart
              data={comparisonData}
              layout="vertical"
              margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
              <XAxis type="number" tick={{fill: 'var(--admin-text-secondary)'}} />
              <YAxis 
                dataKey="metric" 
                type="category" 
                tick={{fill: 'var(--admin-text-secondary)'}} 
              />
              <Tooltip 
                contentStyle={{
                  backgroundColor: 'var(--admin-bg-card)',
                  border: '1px solid var(--admin-border)',
                  borderRadius: '8px'
                }}
                labelStyle={{color: 'var(--admin-text)'}}
                itemStyle={{color: 'var(--admin-text)'}}
              />
              <Legend />
              <Bar dataKey="yours" fill={COLORS.secondary} name="Your Value" />
              <Bar dataKey="industry" fill={COLORS.primary} name="Industry Target" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    );
  };

  // Helper to determine benchmark status
  const getBenchmarkStatus = (metric, yours, industry) => {
    if (metric === 'Throughput') {
      // For throughput, higher is better
      if (yours >= industry * 1.2) return 'excellent';
      if (yours >= industry) return 'good';
      if (yours >= industry * 0.8) return 'fair';
      return 'poor';
    }
    
    // For everything else, lower is better
    if (yours <= industry * 0.8) return 'excellent';
    if (yours <= industry) return 'good';
    if (yours <= industry * 1.5) return 'fair';
    return 'poor';
  };

  // Helper to format timestamp
  const formatTime = (timestamp) => {
    if (!timestamp) return "";
    
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString([], {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch (e) {
      return timestamp;
    }
  };

  return (
    <div className="admin-tab-content performance-tab">
      <div className="admin-content-header">
        <h2><FaChartLine /> Performance Monitoring</h2>
        <button className="admin-refresh-btn" onClick={fetchPerformance}>
          <FaSync /> Refresh Metrics
        </button>
      </div>

      {perfLoading && (
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading performance data...</p>
        </div>
      )}

      {perfError && (
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {perfError}
        </div>
      )}

      {!perfLoading && !perfError && (
        <>
          <div className="admin-performance-navigation">
            <button 
              className={activeSection === "overview" ? "active" : ""}
              onClick={() => setActiveSection("overview")}
            >
              <FaHome /> Overview
            </button>
            <button 
              className={activeSection === "database" ? "active" : ""}
              onClick={() => setActiveSection("database")}
            >
              <FaDatabase /> Database
            </button>
            <button 
              className={activeSection === "webVitals" ? "active" : ""}
              onClick={() => setActiveSection("webVitals")}
            >
              <FaGlobe /> Web Vitals
            </button>
            <button 
              className={activeSection === "errors" ? "active" : ""}
              onClick={() => setActiveSection("errors")}
            >
              <FaExclamation /> Errors
            </button>
            <button 
              className={activeSection === "benchmarks" ? "active" : ""}
              onClick={() => setActiveSection("benchmarks")}
            >
              <FaChartLine /> Benchmarks
            </button>
          </div>

          {activeSection === "overview" && renderOverview()}
          {activeSection === "database" && renderDatabasePerformance()}
          {activeSection === "webVitals" && renderWebVitals()}
          {activeSection === "errors" && renderErrors()}
          {activeSection === "benchmarks" && renderBenchmarks()}
        </>
      )}
    </div>
  );
};

export default PerformanceTab;
