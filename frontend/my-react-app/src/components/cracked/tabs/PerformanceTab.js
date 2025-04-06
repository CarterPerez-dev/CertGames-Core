// src/components/cracked/tabs/PerformanceTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaChartLine, FaSync, FaSpinner, FaExclamationTriangle
} from "react-icons/fa";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, 
  Tooltip, Legend, ResponsiveContainer
} from "recharts";

const PerformanceTab = () => {
  const [performanceData, setPerformanceData] = useState(null);
  const [perfLoading, setPerfLoading] = useState(false);
  const [perfError, setPerfError] = useState(null);

  const fetchPerformance = useCallback(async () => {
    setPerfLoading(true);
    setPerfError(null);
    try {
      const res = await fetch("/api/cracked/performance", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch performance metrics");
      }
      setPerformanceData(data);
    } catch (err) {
      setPerfError(err.message);
    } finally {
      setPerfLoading(false);
    }
  }, []);

  // Auto-refresh performance data every 15 seconds to have "real-time" feeling.
  useEffect(() => {
    fetchPerformance();
    const interval = setInterval(fetchPerformance, 15000); // 15s refresh
    return () => clearInterval(interval);
  }, [fetchPerformance]);

  return (
    <div className="admin-tab-content performance-tab">
      <div className="admin-content-header">
        <h2><FaChartLine /> Performance Metrics</h2>
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

      {performanceData && !perfLoading && (
        <>
          <div className="admin-stats-grid">
            <div className="admin-stat-card">
              <div className="admin-stat-icon req-time-icon">
                <FaChartLine />
              </div>
              <div className="admin-stat-content">
                <h3>Request Time</h3>
                <div className="admin-stat-value">{performanceData.avg_request_time.toFixed(3)}s</div>
              </div>
            </div>

            <div className="admin-stat-card">
              <div className="admin-stat-icon db-time-icon">
                <FaChartLine />
              </div>
              <div className="admin-stat-content">
                <h3>DB Query Time</h3>
                <div className="admin-stat-value">{performanceData.avg_db_query_time_ms}ms</div>
              </div>
            </div>

            <div className="admin-stat-card">
              <div className="admin-stat-icon transfer-icon">
                <FaChartLine />
              </div>
              <div className="admin-stat-content">
                <h3>Data Transfer</h3>
                <div className="admin-stat-value">{performanceData.data_transfer_rate}</div>
              </div>
            </div>

            <div className="admin-stat-card">
              <div className="admin-stat-icon throughput-icon">
                <FaChartLine />
              </div>
              <div className="admin-stat-content">
                <h3>Throughput</h3>
                <div className="admin-stat-value">{performanceData.throughput} req/min</div>
              </div>
            </div>
          </div>

          <div className="admin-charts-grid">
            {/* Chart 1: Request Time */}
            <div className="admin-chart-container">
              <h3>Avg Request Time (Seconds) - Last Hour</h3>
              {Array.isArray(performanceData.history) && performanceData.history.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={performanceData.history}>
                    <defs>
                      <linearGradient id="colorRequestTime" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#6543cc" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="#6543cc" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="timestamp" />
                    <YAxis />
                    <CartesianGrid strokeDasharray="3 3" />
                    <Tooltip />
                    <Area
                      type="monotone"
                      dataKey="requestTime"
                      stroke="#6543cc"
                      fill="url(#colorRequestTime)"
                      name="Request Time (s)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="admin-no-data">No chart data available</div>
              )}
            </div>

            {/* Chart 2: DB Time */}
            <div className="admin-chart-container">
              <h3>Avg DB Time (ms) - Last Hour</h3>
              {Array.isArray(performanceData.history) && performanceData.history.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={performanceData.history}>
                    <defs>
                      <linearGradient id="colorDbTime" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ff4c8b" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="#ff4c8b" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="timestamp" />
                    <YAxis />
                    <CartesianGrid strokeDasharray="3 3" />
                    <Tooltip />
                    <Area
                      type="monotone"
                      dataKey="dbTime"
                      stroke="#ff4c8b"
                      fill="url(#colorDbTime)"
                      name="DB Time (ms)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="admin-no-data">No chart data available</div>
              )}
            </div>

            {/* Chart 3: Throughput */}
            <div className="admin-chart-container">
              <h3>Throughput (Requests/Min) - Last Hour</h3>
              {Array.isArray(performanceData.history) && performanceData.history.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={performanceData.history}>
                    <defs>
                      <linearGradient id="colorThroughput" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#2ecc71" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="#2ecc71" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="timestamp" />
                    <YAxis />
                    <CartesianGrid strokeDasharray="3 3" />
                    <Tooltip />
                    <Area
                      type="monotone"
                      dataKey="throughput"
                      stroke="#2ecc71"
                      fill="url(#colorThroughput)"
                      name="Throughput (req/min)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="admin-no-data">No chart data available</div>
              )}
            </div>

            {/* Chart 4: Error Rate */}
            <div className="admin-chart-container">
              <h3>Error Rate - Last Hour</h3>
              {Array.isArray(performanceData.history) && performanceData.history.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={performanceData.history}>
                    <defs>
                      <linearGradient id="colorErrorRate" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#e74c3c" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="#e74c3c" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="timestamp" />
                    <YAxis />
                    <CartesianGrid strokeDasharray="3 3" />
                    <Tooltip />
                    <Area
                      type="monotone"
                      dataKey="errorRate"
                      stroke="#e74c3c"
                      fill="url(#colorErrorRate)"
                      name="Error Rate"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="admin-no-data">No chart data available</div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default PerformanceTab;
