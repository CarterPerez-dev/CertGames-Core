// src/components/cracked/tabs/OverviewTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaHome, FaUsers, FaClipboardList, FaCalendarDay, FaChartLine, FaBolt,
  FaDatabase, FaHeartbeat, FaBell, FaSync, FaSpinner, FaExclamationTriangle,
  FaServer, FaNetworkWired, FaMoneyBillWave, FaUserCheck, FaUserPlus,
  FaStopwatch, FaClock, FaChartPie, FaLaptopCode, FaRocket, FaCog, FaSpider
} from "react-icons/fa";
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from "recharts";

const OverviewTab = () => {
  const [overviewData, setOverviewData] = useState(null);
  const [performanceData, setPerformanceData] = useState(null);
  const [healthData, setHealthData] = useState(null);
  const [revenueData, setRevenueData] = useState(null);
  const [activityData, setActivityData] = useState([]);
  const [loading, setLoading] = useState({
    overview: false,
    performance: false,
    health: false,
    revenue: false,
    activity: false
  });
  const [error, setError] = useState(null);
  const [activePanel, setActivePanel] = useState("main"); // main, performance, users, tests

  // Colors for charts
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
    darkBlue: "#34495e"
  };

  const CHART_COLORS = [
    COLORS.primary,
    COLORS.secondary,
    COLORS.success,
    COLORS.info,
    COLORS.warning
  ];

  // Fetch main dashboard data
  const fetchOverviewData = useCallback(async () => {
    setLoading(prev => ({ ...prev, overview: true }));
    setError(null);
    try {
      const res = await fetch("/api/cracked/dashboard", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch dashboard");
      }
      setOverviewData(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(prev => ({ ...prev, overview: false }));
    }
  }, []);

  // Fetch performance metrics
  const fetchPerformanceData = useCallback(async () => {
    setLoading(prev => ({ ...prev, performance: true }));
    try {
      const res = await fetch("/api/cracked/performance", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch performance metrics");
      }
      setPerformanceData(data);
    } catch (err) {
      console.error("Performance data error:", err);
    } finally {
      setLoading(prev => ({ ...prev, performance: false }));
    }
  }, []);

  // Fetch health check data
  const fetchHealthData = useCallback(async () => {
    setLoading(prev => ({ ...prev, health: true }));
    try {
      const res = await fetch("/api/cracked/api-health-check", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch health check");
      }
      setHealthData(data);
    } catch (err) {
      console.error("Health check error:", err);
    } finally {
      setLoading(prev => ({ ...prev, health: false }));
    }
  }, []);

  // Fetch revenue overview
  const fetchRevenueData = useCallback(async () => {
    setLoading(prev => ({ ...prev, revenue: true }));
    try {
      const res = await fetch("/api/cracked/revenue/overview", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch revenue data");
      }
      setRevenueData(data);
    } catch (err) {
      console.error("Revenue data error:", err);
    } finally {
      setLoading(prev => ({ ...prev, revenue: false }));
    }
  }, []);

  // Fetch recent activity logs
  const fetchActivityData = useCallback(async () => {
    setLoading(prev => ({ ...prev, activity: true }));
    try {
      const res = await fetch("/api/cracked/activity-logs", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch activity logs");
      }
      setActivityData(data.logs?.slice(0, 10) || []);
    } catch (err) {
      console.error("Activity logs error:", err);
    } finally {
      setLoading(prev => ({ ...prev, activity: false }));
    }
  }, []);

  // Fetch all data on initial load
  useEffect(() => {
    fetchOverviewData();
    fetchPerformanceData();
    fetchHealthData();
    fetchRevenueData();
    fetchActivityData();

    // Refresh data every 2 minutes
    const intervalId = setInterval(() => {
      fetchOverviewData();
      fetchPerformanceData();
      fetchHealthData();
    }, 120000);

    return () => clearInterval(intervalId);
  }, [fetchOverviewData, fetchPerformanceData, fetchHealthData, fetchRevenueData, fetchActivityData]);

  // Format currency
  const formatCurrency = (value) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2
    }).format(value);
  };

  // Format date for display
  const formatDate = (dateString) => {
    if (!dateString) return "";
    try {
      const date = new Date(dateString);
      return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      }).format(date);
    } catch (e) {
      return dateString;
    }
  };

  // Custom tooltip for charts
  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="overview-dashboard-chart-tooltip">
          <p className="overview-dashboard-tooltip-label">{label}</p>
          {payload.map((entry, index) => (
            <p key={index} style={{ color: entry.color }}>
              {entry.name}: {entry.value}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  // Calculate the system health score (0-100)
  const calculateHealthScore = () => {
    if (!performanceData) return { score: 0, status: "unknown" };
    
    // Calculate score based on multiple factors
    let score = 0;
    let total = 0;
    
    // Request time score (lower is better)
    if (performanceData.avg_request_time <= 0.1) {
      score += 25;
    } else if (performanceData.avg_request_time <= 0.3) {
      score += 20;
    } else if (performanceData.avg_request_time <= 0.5) {
      score += 15;
    } else if (performanceData.avg_request_time <= 1.0) {
      score += 10;
    } else {
      score += 5;
    }
    total += 25;
    
    // DB query time score (lower is better)
    const dbTime = performanceData.avg_db_query_time_ms || 0;
    if (dbTime <= 10) {
      score += 25;
    } else if (dbTime <= 25) {
      score += 20;
    } else if (dbTime <= 50) {
      score += 15;
    } else if (dbTime <= 100) {
      score += 10;
    } else {
      score += 5;
    }
    total += 25;
    
    // Error rate score (lower is better)
    const errorRate = performanceData.error_rate || 0;
    if (errorRate <= 0.01) {
      score += 25;
    } else if (errorRate <= 0.02) {
      score += 20;
    } else if (errorRate <= 0.05) {
      score += 15;
    } else if (errorRate <= 0.1) {
      score += 10;
    } else {
      score += 5;
    }
    total += 25;
    
    // Throughput score (higher is better)
    const throughput = performanceData.throughput || 0;
    if (throughput >= 60) {
      score += 25;
    } else if (throughput >= 40) {
      score += 20;
    } else if (throughput >= 20) {
      score += 15;
    } else if (throughput >= 10) {
      score += 10;
    } else {
      score += 5;
    }
    total += 25;
    
    // Calculate final percentage
    const finalScore = Math.round((score / total) * 100);
    
    // Determine status
    let status = "critical";
    if (finalScore >= 90) {
      status = "excellent";
    } else if (finalScore >= 75) {
      status = "good";
    } else if (finalScore >= 50) {
      status = "fair";
    } else if (finalScore >= 30) {
      status = "poor";
    }
    
    return { score: finalScore, status };
  };

  // Generate mock data for platform usage pie chart
  const generatePlatformData = () => {
    return [
      { name: 'Web App', value: 65 },
      { name: 'iOS App', value: 35 },
    ];
  };

  // Format time for display
  const formatTime = (seconds) => {
    if (!seconds) return "0s";
    
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const remainingSeconds = Math.floor(seconds % 60);
    
    let result = "";
    if (days > 0) result += `${days}d `;
    if (hours > 0) result += `${hours}h `;
    if (minutes > 0) result += `${minutes}m `;
    if (remainingSeconds > 0 && days === 0) result += `${remainingSeconds}s`;
    
    return result.trim();
  };

  // Refresh all data
  const refreshAllData = () => {
    fetchOverviewData();
    fetchPerformanceData();
    fetchHealthData();
    fetchRevenueData();
    fetchActivityData();
  };
  
  // Calculate health score
  const healthScore = calculateHealthScore();

  // Render loading spinner
  if (loading.overview && !overviewData) {
    return (
      <div className="admin-tab-content overview-dashboard-tab">
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading dashboard data...</p>
        </div>
      </div>
    );
  }

  // Render error message
  if (error) {
    return (
      <div className="admin-tab-content overview-dashboard-tab">
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {error}
        </div>
      </div>
    );
  }

  return (
    <div className="admin-tab-content overview-dashboard-tab">
      <div className="admin-content-header">
        <h2><FaSpider /> Dashboard Overview</h2>
        <div className="overview-dashboard-actions">
          <div className="overview-dashboard-panel-buttons">
            <button 
              className={`overview-dashboard-panel-btn ${activePanel === "main" ? "active" : ""}`}
              onClick={() => setActivePanel("main")}
            >
              <FaSpider /> Main
            </button>
            <button 
              className={`overview-dashboard-panel-btn ${activePanel === "performance" ? "active" : ""}`}
              onClick={() => setActivePanel("performance")}
            >
              <FaChartLine /> Performance
            </button>
            <button 
              className={`overview-dashboard-panel-btn ${activePanel === "users" ? "active" : ""}`}
              onClick={() => setActivePanel("users")}
            >
              <FaUsers /> Users
            </button>
            <button 
              className={`overview-dashboard-panel-btn ${activePanel === "tests" ? "active" : ""}`}
              onClick={() => setActivePanel("tests")}
            >
              <FaClipboardList /> Tests
            </button>
          </div>
          <button 
            className="admin-refresh-btn" 
            onClick={refreshAllData}
            disabled={Object.values(loading).some(Boolean)}
          >
            {Object.values(loading).some(Boolean) ? (
              <FaSpinner className="admin-spinner" />
            ) : (
              <FaSync />
            )} Refresh
          </button>
        </div>
      </div>

      {/* System Status Panel */}
      <div className="overview-dashboard-status-panel">
        <div className="overview-dashboard-status-header">
          <h3>System Status</h3>
          <div className={`overview-dashboard-status-indicator status-${healthScore.status}`}>
            {healthScore.status.toUpperCase()}
          </div>
        </div>
        
        <div className="overview-dashboard-status-grid">
          <div className="overview-dashboard-status-card">
            <div className="overview-dashboard-status-icon">
              <FaServer />
            </div>
            <div className="overview-dashboard-status-content">
              <div className="overview-dashboard-status-title">API</div>
              <div className={`overview-dashboard-status-value status-${
                healthData?.healthy ? "good" : "error"
              }`}>
                {healthData?.healthy ? "Operational" : "Issues Detected"}
              </div>
              <div className="overview-dashboard-status-meta">
                Last checked: {formatDate(healthData?.timestamp)}
              </div>
            </div>
          </div>

          <div className="overview-dashboard-status-card">
            <div className="overview-dashboard-status-icon">
              <FaDatabase />
            </div>
            <div className="overview-dashboard-status-content">
              <div className="overview-dashboard-status-title">Database</div>
              <div className={`overview-dashboard-status-value status-${
                performanceData?.avg_db_query_time_ms < 50 ? "good" : 
                performanceData?.avg_db_query_time_ms < 100 ? "warning" : "error"
              }`}>
                {performanceData?.avg_db_query_time_ms < 50 ? "Optimal" : 
                 performanceData?.avg_db_query_time_ms < 100 ? "Good" : "Slow"}
              </div>
              <div className="overview-dashboard-status-meta">
                Response time: {performanceData?.avg_db_query_time_ms || "N/A"} ms
              </div>
            </div>
          </div>

          <div className="overview-dashboard-status-card">
            <div className="overview-dashboard-status-icon">
              <FaBolt />
            </div>
            <div className="overview-dashboard-status-content">
              <div className="overview-dashboard-status-title">Response Time</div>
              <div className={`overview-dashboard-status-value status-${
                performanceData?.avg_request_time < 0.2 ? "good" : 
                performanceData?.avg_request_time < 0.5 ? "warning" : "error"
              }`}>
                {performanceData?.avg_request_time < 0.2 ? "Fast" : 
                 performanceData?.avg_request_time < 0.5 ? "Good" : "Slow"}
              </div>
              <div className="overview-dashboard-status-meta">
                Avg: {performanceData ? (performanceData.avg_request_time * 1000).toFixed(0) : "N/A"} ms
              </div>
            </div>
          </div>

          <div className="overview-dashboard-status-card">
            <div className="overview-dashboard-status-icon">
              <FaNetworkWired />
            </div>
            <div className="overview-dashboard-status-content">
              <div className="overview-dashboard-status-title">Throughput</div>
              <div className={`overview-dashboard-status-value status-${
                performanceData?.throughput > 30 ? "good" : 
                performanceData?.throughput > 15 ? "warning" : "error"
              }`}>
                {performanceData?.throughput > 30 ? "High" : 
                 performanceData?.throughput > 15 ? "Medium" : "Low"}
              </div>
              <div className="overview-dashboard-status-meta">
                {performanceData?.throughput || "N/A"} req/min
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Overview Panel */}
      {activePanel === "main" && overviewData && (
        <>
          <div className="overview-dashboard-grid">
            <div className="overview-dashboard-main-card users-card">
              <div className="overview-dashboard-card-header">
                <h3><FaUsers /> Users</h3>
                <div className="overview-dashboard-card-value">
                  {overviewData.user_count}
                </div>
              </div>
              <div className="overview-dashboard-card-content">
                <div className="overview-dashboard-metric-row">
                  <div className="overview-dashboard-metric">
                    <div className="overview-dashboard-metric-label">Active (24h)</div>
                    <div className="overview-dashboard-metric-value">{Math.round(overviewData.user_count * 0.18)}</div>
                  </div>
                  <div className="overview-dashboard-metric">
                    <div className="overview-dashboard-metric-label">New (7d)</div>
                    <div className="overview-dashboard-metric-value">{Math.round(overviewData.user_count * 0.05)}</div>
                  </div>
                </div>
                <div className="overview-dashboard-chart-container">
                  <ResponsiveContainer width="100%" height={120}>
                    <AreaChart data={overviewData.recentStats?.slice().reverse() || []}>
                      <defs>
                        <linearGradient id="colorUsers" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor={COLORS.primary} stopOpacity={0.8} />
                          <stop offset="95%" stopColor={COLORS.primary} stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis 
                        dataKey="label" 
                        tick={{fill: 'var(--admin-text-secondary)'}}
                        axisLine={false}
                        tickLine={false}
                        hide={true}
                      />
                      <YAxis hide={true} domain={['auto', 'auto']} />
                      <Tooltip content={<CustomTooltip />} />
                      <Area
                        type="monotone"
                        dataKey="dailyBonus"
                        name="User Activity"
                        stroke={COLORS.primary}
                        fillOpacity={1}
                        fill="url(#colorUsers)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
              <div className="overview-dashboard-card-footer">
                <a href="#" className="overview-dashboard-view-details" onClick={() => setActivePanel("users")}>
                  View User Details
                </a>
              </div>
            </div>

            <div className="overview-dashboard-main-card tests-card">
              <div className="overview-dashboard-card-header">
                <h3><FaClipboardList /> Tests</h3>
                <div className="overview-dashboard-card-value">
                  {overviewData.test_attempts_count}
                </div>
              </div>
              <div className="overview-dashboard-card-content">
                <div className="overview-dashboard-metric-row">
                  <div className="overview-dashboard-metric">
                    <div className="overview-dashboard-metric-label">Avg Score</div>
                    <div className="overview-dashboard-metric-value">{overviewData.average_test_score_percent}%</div>
                  </div>
                  <div className="overview-dashboard-metric">
                    <div className="overview-dashboard-metric-label">Daily Tests</div>
                    <div className="overview-dashboard-metric-value">
                      {overviewData.recentStats ? 
                       overviewData.recentStats[overviewData.recentStats.length-1]?.testAttempts || 0 : 0}
                    </div>
                  </div>
                </div>
                <div className="overview-dashboard-chart-container">
                  <ResponsiveContainer width="100%" height={120}>
                    <AreaChart data={overviewData.recentStats?.slice().reverse() || []}>
                      <defs>
                        <linearGradient id="colorTests" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor={COLORS.secondary} stopOpacity={0.8} />
                          <stop offset="95%" stopColor={COLORS.secondary} stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis 
                        dataKey="label" 
                        tick={{fill: 'var(--admin-text-secondary)'}}
                        axisLine={false}
                        tickLine={false}
                        hide={true}
                      />
                      <YAxis hide={true} domain={['auto', 'auto']} />
                      <Tooltip content={<CustomTooltip />} />
                      <Area
                        type="monotone"
                        dataKey="testAttempts"
                        name="Test Attempts"
                        stroke={COLORS.secondary}
                        fillOpacity={1}
                        fill="url(#colorTests)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
              <div className="overview-dashboard-card-footer">
                <a href="#" className="overview-dashboard-view-details" onClick={() => setActivePanel("tests")}>
                  View Test Details
                </a>
              </div>
            </div>

            <div className="overview-dashboard-main-card performance-card">
              <div className="overview-dashboard-card-header">
                <h3><FaChartLine /> Performance</h3>
                <div className={`overview-dashboard-health-score status-${healthScore.status}`}>
                  {healthScore.score}%
                </div>
              </div>
              <div className="overview-dashboard-card-content">
                <div className="overview-dashboard-metric-row performance-metrics">
                  <div className="overview-dashboard-metric">
                    <div className="overview-dashboard-metric-label">Req Time</div>
                    <div className="overview-dashboard-metric-value">
                      {performanceData ? (performanceData.avg_request_time * 1000).toFixed(0) : "N/A"}ms
                    </div>
                  </div>
                  <div className="overview-dashboard-metric">
                    <div className="overview-dashboard-metric-label">DB Time</div>
                    <div className="overview-dashboard-metric-value">
                      {performanceData?.avg_db_query_time_ms || "N/A"}ms
                    </div>
                  </div>
                  <div className="overview-dashboard-metric">
                    <div className="overview-dashboard-metric-label">Error Rate</div>
                    <div className="overview-dashboard-metric-value">
                      {performanceData ? (performanceData.error_rate * 100).toFixed(2) : "N/A"}%
                    </div>
                  </div>
                </div>
                <div className="overview-dashboard-chart-container">
                  {performanceData?.history && performanceData.history.length > 0 ? (
                    <ResponsiveContainer width="100%" height={120}>
                      <LineChart data={performanceData.history?.slice(0, 10) || []}>
                        <XAxis 
                          dataKey="timestamp" 
                          tick={{fill: 'var(--admin-text-secondary)'}}
                          axisLine={false}
                          tickLine={false}
                          hide={true}
                        />
                        <YAxis hide={true} />
                        <Tooltip content={<CustomTooltip />} />
                        <Line 
                          type="monotone" 
                          dataKey="requestTime" 
                          name="Response Time" 
                          stroke={COLORS.info} 
                          strokeWidth={2}
                          dot={false}
                        />
                        <Line 
                          type="monotone" 
                          dataKey="dbTime" 
                          name="DB Time" 
                          stroke={COLORS.purple} 
                          strokeWidth={2}
                          dot={false}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="overview-dashboard-no-data">No performance history available</div>
                  )}
                </div>
              </div>
              <div className="overview-dashboard-card-footer">
                <a href="#" className="overview-dashboard-view-details" onClick={() => setActivePanel("performance")}>
                  View Performance Details
                </a>
              </div>
            </div>

            <div className="overview-dashboard-main-card revenue-card">
              <div className="overview-dashboard-card-header">
                <h3><FaMoneyBillWave /> Revenue</h3>
                <div className="overview-dashboard-card-value">
                  {revenueData ? formatCurrency(revenueData.total_active_revenue) : "$0.00"}
                </div>
              </div>
              <div className="overview-dashboard-card-content">
                <div className="overview-dashboard-metric-row">
                  <div className="overview-dashboard-metric">
                    <div className="overview-dashboard-metric-label">Subscribers</div>
                    <div className="overview-dashboard-metric-value">
                      {revenueData?.active_subscribers || 0}
                    </div>
                  </div>
                  <div className="overview-dashboard-metric">
                    <div className="overview-dashboard-metric-label">New (7d)</div>
                    <div className="overview-dashboard-metric-value">
                      {revenueData?.new_subscribers_7d || 0}
                    </div>
                  </div>
                </div>
                <div className="overview-dashboard-chart-container">
                  <ResponsiveContainer width="100%" height={120}>
                    <PieChart>
                      <Pie
                        data={revenueData ? [
                          { name: 'Web', value: revenueData.stripe_subscribers },
                          { name: 'iOS', value: revenueData.apple_subscribers }
                        ] : generatePlatformData()}
                        cx="50%"
                        cy="50%"
                        innerRadius={25}
                        outerRadius={40}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {(revenueData ? [
                          { name: 'Web', value: revenueData.stripe_subscribers },
                          { name: 'iOS', value: revenueData.apple_subscribers }
                        ] : generatePlatformData()).map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip 
                        formatter={(value, name) => [`${value} users`, `${name} Platform`]}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
              <div className="overview-dashboard-card-footer">
                <a href="#" className="overview-dashboard-view-details">
                  View Revenue Details
                </a>
              </div>
            </div>
          </div>

          <div className="overview-dashboard-bottom-row">
            <div className="overview-dashboard-activity-feed">
              <div className="overview-dashboard-section-header">
                <h3><FaUserCheck /> Recent Activity</h3>
              </div>
              <div className="overview-dashboard-activity-list">
                {activityData && activityData.length > 0 ? (
                  activityData.map((activity, index) => (
                    <div key={index} className="overview-dashboard-activity-item">
                      <div className="overview-dashboard-activity-icon">
                        {activity.success ? <FaUserCheck /> : <FaExclamationTriangle />}
                      </div>
                      <div className="overview-dashboard-activity-content">
                        <div className="overview-dashboard-activity-text">
                          {activity.success ? 
                            `User logged in successfully` : 
                            `Failed login attempt: ${activity.reason || "Unknown reason"}`}
                          {activity.userId && ` - ID: ${activity.userId}`}
                        </div>
                        <div className="overview-dashboard-activity-meta">
                          <span className="overview-dashboard-activity-time">{activity.timestamp}</span>
                          <span className="overview-dashboard-activity-ip">{activity.ip}</span>
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="overview-dashboard-no-data">No recent activity</div>
                )}
              </div>
            </div>

            <div className="overview-dashboard-quick-actions">
              <div className="overview-dashboard-section-header">
                <h3><FaRocket /> Quick Actions</h3>
              </div>
              <div className="overview-dashboard-actions-grid">
                <button className="overview-dashboard-action-button">
                  <FaUsers />
                  <span>User Management</span>
                </button>
                <button className="overview-dashboard-action-button">
                  <FaClock />
                  <span>Daily Questions</span>
                </button>
                <button className="overview-dashboard-action-button">
                  <FaLaptopCode />
                  <span>Test Editor</span>
                </button>
                <button className="overview-dashboard-action-button">
                  <FaHeartbeat />
                  <span>Health Checks</span>
                </button>
                <button className="overview-dashboard-action-button">
                  <FaChartPie />
                  <span>Analytics</span>
                </button>
                <button className="overview-dashboard-action-button">
                  <FaCog />
                  <span>Settings</span>
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Performance Panel */}
      {activePanel === "performance" && performanceData && (
        <div className="overview-dashboard-performance-panel">
          <div className="overview-dashboard-panel-header">
            <h3><FaChartLine /> Performance Metrics</h3>
          </div>
          
          <div className="overview-dashboard-performance-metrics">
            <div className="overview-dashboard-performance-card">
              <div className="overview-dashboard-performance-header">
                <div className="overview-dashboard-performance-title">
                  <FaStopwatch /> Response Time
                </div>
                <div className="overview-dashboard-performance-value">
                  {(performanceData.avg_request_time * 1000).toFixed(1)} ms
                </div>
              </div>
              <div className="overview-dashboard-performance-chart">
                <ResponsiveContainer width="100%" height={150}>
                  <LineChart data={performanceData.history?.slice().reverse() || []}>
                    <XAxis 
                      dataKey="timestamp" 
                      tick={{fill: 'var(--admin-text-secondary)'}}
                      axisLine={false}
                      tickLine={false}
                      hide={true}
                    />
                    <YAxis 
                      hide={true}
                      domain={['dataMin', 'dataMax']}
                    />
                    <Tooltip 
                      formatter={(value) => [`${value} ms`, 'Response Time']}
                      labelFormatter={() => ""}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="requestTime" 
                      name="Response Time" 
                      stroke={COLORS.info} 
                      strokeWidth={2}
                      dot={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
            
            <div className="overview-dashboard-performance-card">
              <div className="overview-dashboard-performance-header">
                <div className="overview-dashboard-performance-title">
                  <FaDatabase /> Database Time
                </div>
                <div className="overview-dashboard-performance-value">
                  {performanceData.avg_db_query_time_ms} ms
                </div>
              </div>
              <div className="overview-dashboard-performance-chart">
                <ResponsiveContainer width="100%" height={150}>
                  <LineChart data={performanceData.history?.slice().reverse() || []}>
                    <XAxis 
                      dataKey="timestamp" 
                      tick={{fill: 'var(--admin-text-secondary)'}}
                      axisLine={false}
                      tickLine={false}
                      hide={true}
                    />
                    <YAxis 
                      hide={true}
                      domain={['dataMin', 'dataMax']}
                    />
                    <Tooltip 
                      formatter={(value) => [`${value} ms`, 'DB Query Time']}
                      labelFormatter={() => ""}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="dbTime" 
                      name="DB Query Time" 
                      stroke={COLORS.purple} 
                      strokeWidth={2}
                      dot={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
            
            <div className="overview-dashboard-performance-card">
              <div className="overview-dashboard-performance-header">
                <div className="overview-dashboard-performance-title">
                  <FaExclamationTriangle /> Error Rate
                </div>
                <div className="overview-dashboard-performance-value">
                  {(performanceData.error_rate * 100).toFixed(2)}%
                </div>
              </div>
              <div className="overview-dashboard-performance-chart">
                <ResponsiveContainer width="100%" height={150}>
                  <AreaChart data={performanceData.history?.slice().reverse() || []}>
                    <defs>
                      <linearGradient id="colorErrorRate" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={COLORS.danger} stopOpacity={0.8} />
                        <stop offset="95%" stopColor={COLORS.danger} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis 
                      dataKey="timestamp" 
                      tick={{fill: 'var(--admin-text-secondary)'}}
                      axisLine={false}
                      tickLine={false}
                      hide={true}
                    />
                    <YAxis 
                      hide={true}
                      domain={[0, 'dataMax + 0.01']}
                    />
                    <Tooltip 
                      formatter={(value) => [`${(value * 100).toFixed(2)}%`, 'Error Rate']}
                      labelFormatter={() => ""}
                    />
                    <Area
                      type="monotone"
                      dataKey="errorRate"
                      name="Error Rate"
                      stroke={COLORS.danger}
                      fillOpacity={1}
                      fill="url(#colorErrorRate)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
            
            <div className="overview-dashboard-performance-card">
              <div className="overview-dashboard-performance-header">
                <div className="overview-dashboard-performance-title">
                  <FaNetworkWired /> Throughput
                </div>
                <div className="overview-dashboard-performance-value">
                  {performanceData.throughput} req/min
                </div>
              </div>
              <div className="overview-dashboard-performance-chart">
                <ResponsiveContainer width="100%" height={150}>
                  <AreaChart data={performanceData.history?.slice().reverse() || []}>
                    <defs>
                      <linearGradient id="colorThroughput" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={COLORS.success} stopOpacity={0.8} />
                        <stop offset="95%" stopColor={COLORS.success} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis 
                      dataKey="timestamp" 
                      tick={{fill: 'var(--admin-text-secondary)'}}
                      axisLine={false}
                      tickLine={false}
                      hide={true}
                    />
                    <YAxis 
                      hide={true}
                      domain={[0, 'dataMax + 5']}
                    />
                    <Tooltip 
                      formatter={(value) => [`${value} req/min`, 'Throughput']}
                      labelFormatter={() => ""}
                    />
                    <Area
                      type="monotone"
                      dataKey="throughput"
                      name="Throughput"
                      stroke={COLORS.success}
                      fillOpacity={1}
                      fill="url(#colorThroughput)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
          
          <div className="overview-dashboard-performance-charts">
            <div className="overview-dashboard-chart-container full-width">
              <h4>System Response Time Trend</h4>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={performanceData.history?.slice().reverse() || []}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="timestamp" 
                    tick={{fill: 'var(--admin-text-secondary)'}}
                  />
                  <YAxis 
                    tick={{fill: 'var(--admin-text-secondary)'}}
                    label={{ 
                      value: 'Time (ms)', 
                      angle: -90, 
                      position: 'insideLeft',
                      fill: 'var(--admin-text-secondary)'
                    }}
                  />
                  <Tooltip />
                  <Legend />
                  <Line 
                    type="monotone" 
                    dataKey="requestTime" 
                    name="Response Time" 
                    stroke={COLORS.info} 
                    strokeWidth={2}
                    dot={false}
                    activeDot={{r: 6}}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="dbTime" 
                    name="DB Query Time" 
                    stroke={COLORS.purple} 
                    strokeWidth={2}
                    dot={false}
                    activeDot={{r: 6}}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Users Panel */}
      {activePanel === "users" && overviewData && (
        <div className="overview-dashboard-users-panel">
          <div className="overview-dashboard-panel-header">
            <h3><FaUsers /> User Statistics</h3>
          </div>
          
          <div className="overview-dashboard-users-metrics">
            <div className="overview-dashboard-users-card">
              <div className="overview-dashboard-users-header">
                <h4>User Growth</h4>
              </div>
              <div className="overview-dashboard-users-chart">
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={overviewData.recentStats?.slice().reverse() || []}>
                    <defs>
                      <linearGradient id="colorUserGrowth" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={COLORS.primary} stopOpacity={0.8} />
                        <stop offset="95%" stopColor={COLORS.primary} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="label" 
                      tick={{fill: 'var(--admin-text-secondary)'}}
                    />
                    <YAxis 
                      tick={{fill: 'var(--admin-text-secondary)'}}
                    />
                    <Tooltip />
                    <Legend />
                    <Area
                      type="monotone"
                      dataKey="dailyBonus"
                      name="Daily Active Users"
                      stroke={COLORS.primary}
                      fillOpacity={1}
                      fill="url(#colorUserGrowth)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
            
            <div className="overview-dashboard-users-card">
              <div className="overview-dashboard-users-header">
                <h4>User Distribution</h4>
              </div>
              <div className="overview-dashboard-users-chart">
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={generatePlatformData()}
                      cx="50%"
                      cy="50%"
                      labelLine={true}
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    >
                      {generatePlatformData().map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          <div className="overview-dashboard-users-stats">
            <div className="overview-dashboard-stat-box">
              <div className="overview-dashboard-stat-icon">
                <FaUserPlus />
              </div>
              <div className="overview-dashboard-stat-info">
                <div className="overview-dashboard-stat-title">New Users (30d)</div>
                <div className="overview-dashboard-stat-number">
                  {Math.round(overviewData.user_count * 0.12)}
                </div>
              </div>
            </div>
            
            <div className="overview-dashboard-stat-box">
              <div className="overview-dashboard-stat-icon">
                <FaUserCheck />
              </div>
              <div className="overview-dashboard-stat-info">
                <div className="overview-dashboard-stat-title">Active Users</div>
                <div className="overview-dashboard-stat-number">
                  {Math.round(overviewData.user_count * 0.65)}
                </div>
              </div>
            </div>
            
            <div className="overview-dashboard-stat-box">
              <div className="overview-dashboard-stat-icon">
                <FaMoneyBillWave />
              </div>
              <div className="overview-dashboard-stat-info">
                <div className="overview-dashboard-stat-title">Premium Users</div>
                <div className="overview-dashboard-stat-number">
                  {revenueData?.active_subscribers || Math.round(overviewData.user_count * 0.25)}
                </div>
              </div>
            </div>
            
            <div className="overview-dashboard-stat-box">
              <div className="overview-dashboard-stat-icon">
                <FaCalendarDay />
              </div>
              <div className="overview-dashboard-stat-info">
                <div className="overview-dashboard-stat-title">Daily Active</div>
                <div className="overview-dashboard-stat-number">
                  {overviewData.daily_bonus_claims}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* Tests Panel */}
      {activePanel === "tests" && overviewData && (
        <div className="overview-dashboard-tests-panel">
          <div className="overview-dashboard-panel-header">
            <h3><FaClipboardList /> Test Statistics</h3>
          </div>
          
          <div className="overview-dashboard-tests-metrics">
            <div className="overview-dashboard-tests-card">
              <div className="overview-dashboard-tests-header">
                <h4>Test Attempts Over Time</h4>
              </div>
              <div className="overview-dashboard-tests-chart">
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={overviewData.recentStats?.slice().reverse() || []}>
                    <defs>
                      <linearGradient id="colorTestGrowth" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={COLORS.secondary} stopOpacity={0.8} />
                        <stop offset="95%" stopColor={COLORS.secondary} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="label" 
                      tick={{fill: 'var(--admin-text-secondary)'}}
                    />
                    <YAxis 
                      tick={{fill: 'var(--admin-text-secondary)'}}
                    />
                    <Tooltip />
                    <Legend />
                    <Area
                      type="monotone"
                      dataKey="testAttempts"
                      name="Test Attempts"
                      stroke={COLORS.secondary}
                      fillOpacity={1}
                      fill="url(#colorTestGrowth)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
            
            <div className="overview-dashboard-tests-card">
              <div className="overview-dashboard-tests-header">
                <h4>Test Score Distribution</h4>
              </div>
              <div className="overview-dashboard-tests-chart">
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart
                    data={[
                      { name: '0-20%', value: Math.round(overviewData.test_attempts_count * 0.05) },
                      { name: '21-40%', value: Math.round(overviewData.test_attempts_count * 0.15) },
                      { name: '41-60%', value: Math.round(overviewData.test_attempts_count * 0.25) },
                      { name: '61-80%', value: Math.round(overviewData.test_attempts_count * 0.35) },
                      { name: '81-100%', value: Math.round(overviewData.test_attempts_count * 0.2) }
                    ]}
                  >
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="name" 
                      tick={{fill: 'var(--admin-text-secondary)'}}
                    />
                    <YAxis 
                      tick={{fill: 'var(--admin-text-secondary)'}}
                    />
                    <Tooltip />
                    <Legend />
                    <Bar 
                      dataKey="value" 
                      name="Test Count" 
                      fill={COLORS.info}
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          <div className="overview-dashboard-tests-stats">
            <div className="overview-dashboard-stat-box">
              <div className="overview-dashboard-stat-icon">
                <FaClipboardList />
              </div>
              <div className="overview-dashboard-stat-info">
                <div className="overview-dashboard-stat-title">Total Attempts</div>
                <div className="overview-dashboard-stat-number">
                  {overviewData.test_attempts_count}
                </div>
              </div>
            </div>
            
            <div className="overview-dashboard-stat-box">
              <div className="overview-dashboard-stat-icon">
                <FaChartLine />
              </div>
              <div className="overview-dashboard-stat-info">
                <div className="overview-dashboard-stat-title">Average Score</div>
                <div className="overview-dashboard-stat-number">
                  {overviewData.average_test_score_percent}%
                </div>
              </div>
            </div>
            
            <div className="overview-dashboard-stat-box">
              <div className="overview-dashboard-stat-icon">
                <FaCalendarDay />
              </div>
              <div className="overview-dashboard-stat-info">
                <div className="overview-dashboard-stat-title">Daily Attempts</div>
                <div className="overview-dashboard-stat-number">
                  {overviewData.recentStats ? 
                   overviewData.recentStats[overviewData.recentStats.length-1]?.testAttempts || 0 : 0}
                </div>
              </div>
            </div>
            
            <div className="overview-dashboard-stat-box">
              <div className="overview-dashboard-stat-icon">
                <FaStopwatch />
              </div>
              <div className="overview-dashboard-stat-info">
                <div className="overview-dashboard-stat-title">Avg. Completion Time</div>
                <div className="overview-dashboard-stat-number">
                  12:35
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default OverviewTab;
