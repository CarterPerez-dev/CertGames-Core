// src/components/cracked/tabs/OverviewTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaHome, FaUsers, FaClipboardList, FaCalendarDay, FaChartLine,
  FaDatabase, FaHeartbeat, FaBell, FaSync, FaSpinner, FaExclamationTriangle
} from "react-icons/fa";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from "recharts";

const OverviewTab = () => {
  const [overviewData, setOverviewData] = useState(null);
  const [overviewLoading, setOverviewLoading] = useState(false);
  const [overviewError, setOverviewError] = useState(null);

  const fetchOverview = useCallback(async () => {
    setOverviewLoading(true);
    setOverviewError(null);
    try {
      const res = await fetch("/api/cracked/dashboard", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch dashboard");
      }
      setOverviewData(data);
    } catch (err) {
      setOverviewError(err.message);
    } finally {
      setOverviewLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchOverview();
  }, [fetchOverview]);

  return (
    <div className="admin-tab-content overview-tab">
      <div className="admin-content-header">
        <h2><FaHome /> Dashboard Overview</h2>
        <button className="admin-refresh-btn" onClick={fetchOverview}>
          <FaSync /> Refresh Data
        </button>
      </div>

      {overviewLoading && (
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading dashboard data...</p>
        </div>
      )}

      {overviewError && (
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {overviewError}
        </div>
      )}

      {overviewData && !overviewLoading && (
        <>
          <div className="admin-stats-grid">
            <div className="admin-stat-card">
              <div className="admin-stat-icon users-icon">
                <FaUsers />
              </div>
              <div className="admin-stat-content">
                <h3>User Count</h3>
                <div className="admin-stat-value">{overviewData.user_count}</div>
              </div>
            </div>

            <div className="admin-stat-card">
              <div className="admin-stat-icon tests-icon">
                <FaClipboardList />
              </div>
              <div className="admin-stat-content">
                <h3>Test Attempts</h3>
                <div className="admin-stat-value">{overviewData.test_attempts_count}</div>
              </div>
            </div>

            <div className="admin-stat-card">
              <div className="admin-stat-icon bonus-icon">
                <FaCalendarDay />
              </div>
              <div className="admin-stat-content">
                <h3>Daily Bonus Claims</h3>
                <div className="admin-stat-value">{overviewData.daily_bonus_claims}</div>
              </div>
            </div>

            <div className="admin-stat-card">
              <div className="admin-stat-icon score-icon">
                <FaChartLine />
              </div>
              <div className="admin-stat-content">
                <h3>Avg Test Score</h3>
                <div className="admin-stat-value">{overviewData.average_test_score_percent}%</div>
              </div>
            </div>
          </div>

          <div className="admin-charts-section">
            <div className="admin-chart-container">
              <h3>Recent Stats (Last 7 Days)</h3>
              {overviewData.recentStats && overviewData.recentStats.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={overviewData.recentStats}>
                    <defs>
                      <linearGradient id="colorDailyBonus" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#2ecc71" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="#2ecc71" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="colorTestAttempts" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#6543cc" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="#6543cc" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="label" />
                    <YAxis />
                    <CartesianGrid strokeDasharray="3 3" />
                    <Tooltip />
                    <Legend />
                    <Area
                      type="monotone"
                      dataKey="dailyBonus"
                      stroke="#2ecc71"
                      fill="url(#colorDailyBonus)"
                      name="Daily Bonus Claims"
                    />
                    <Area
                      type="monotone"
                      dataKey="testAttempts"
                      stroke="#6543cc"
                      fill="url(#colorTestAttempts)"
                      name="Test Attempts"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="admin-no-data">No chart data available</div>
              )}
            </div>

            <div className="admin-cards-row">
              <div className="admin-metrics-card">
                <h3>Performance Snapshot</h3>
                {overviewData.performance_metrics && (
                  <div className="admin-metrics-list">
                    <div className="admin-metric-item">
                      <span className="admin-metric-label">Request Time:</span>
                      <span className="admin-metric-value">
                        {overviewData.performance_metrics.avg_request_time.toFixed(3)}s
                      </span>
                    </div>
                    <div className="admin-metric-item">
                      <span className="admin-metric-label">DB Query Time:</span>
                      <span className="admin-metric-value">
                        {overviewData.performance_metrics.avg_db_query_time_ms}ms
                      </span>
                    </div>
                    <div className="admin-metric-item">
                      <span className="admin-metric-label">Data Transfer:</span>
                      <span className="admin-metric-value">
                        {overviewData.performance_metrics.data_transfer_rate}
                      </span>
                    </div>
                    <div className="admin-metric-item">
                      <span className="admin-metric-label">Throughput:</span>
                      <span className="admin-metric-value">
                        {overviewData.performance_metrics.throughput} req/min
                      </span>
                    </div>
                    <div className="admin-metric-item">
                      <span className="admin-metric-label">Error Rate:</span>
                      <span className="admin-metric-value">
                        {(overviewData.performance_metrics.error_rate * 100).toFixed(2)}%
                      </span>
                    </div>
                  </div>
                )}
              </div>

              <div className="admin-metrics-card">
                <h3>System Status</h3>
                <div className="admin-status-indicators">
                  <div className="admin-status-item">
                    <div className="admin-status-icon green">
                      <FaDatabase />
                    </div>
                    <div className="admin-status-content">
                      <span className="admin-status-name">Database</span>
                      <span className="admin-status-value">Online</span>
                    </div>
                  </div>
                  <div className="admin-status-item">
                    <div className="admin-status-icon green">
                      <FaHeartbeat />
                    </div>
                    <div className="admin-status-content">
                      <span className="admin-status-name">API</span>
                      <span className="admin-status-value">Healthy</span>
                    </div>
                  </div>
                  <div className="admin-status-item">
                    <div className="admin-status-icon green">
                      <FaBell />
                    </div>
                    <div className="admin-status-content">
                      <span className="admin-status-name">Notifications</span>
                      <span className="admin-status-value">Active</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default OverviewTab;
