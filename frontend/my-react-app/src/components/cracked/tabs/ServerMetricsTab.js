// src/components/cracked/tabs/ServerMetricsTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaServer, FaSync, FaSpinner, FaExclamationTriangle, FaMemory,
  FaMicrochip, FaHdd, FaNetworkWired, FaClock, FaTachometerAlt
} from "react-icons/fa";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, 
  Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell
} from "recharts";
import { adminFetch } from '../csrfHelper';

const ServerMetricsTab = () => {
  const [metrics, setMetrics] = useState(null);
  const [metricsHistory, setMetricsHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Define colors for charts
  const COLORS = {
    cpu: "#8884d8",
    memory: "#82ca9d",
    disk: "#ffc658",
    network: "#ff8042",
    cpu_free: "#d0d1e6",
    memory_free: "#a1d99b",
    disk_free: "#fdae6b"
  };

  // For the pie charts
  const PIE_COLORS = ["#8884d8", "#AAAAAA"];

  // Function to fetch server metrics
  const fetchMetrics = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/cracked/server-metrics", {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch server metrics");
      }
      
      // Add timestamp for history charts
      const timestamp = new Date();
      data.timestampFormatted = timestamp.toLocaleTimeString();
      
      setMetrics(data);
      
      // Update history - keep last 20 data points
      setMetricsHistory(prevHistory => {
        const newHistory = [...prevHistory, {
          timestamp: timestamp.getTime(),
          timestampFormatted: timestamp.toLocaleTimeString(),
          cpu: data.cpu.percent,
          memory: data.memory.percent,
          disk: data.disk.percent,
          network_in: data.network.bytes_recv,
          network_out: data.network.bytes_sent
        }];
        
        // Only keep the last 20 entries
        return newHistory.slice(-20);
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial fetch and setup auto-refresh
  useEffect(() => {
    fetchMetrics();
    
    let intervalId;
    if (autoRefresh) {
      intervalId = setInterval(fetchMetrics, 5000); // Refresh every 5 seconds
    }
    
    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [fetchMetrics, autoRefresh]);

  // Format bytes to a human-readable format
  const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };

  return (
    <div className="admin-tab-content server-metrics-tab">
      <div className="admin-content-header">
        <h2><FaServer /> Server Metrics</h2>
        <div className="admin-refresh-controls">
          <button 
            className="admin-refresh-btn" 
            onClick={fetchMetrics}
            disabled={loading}
          >
            {loading ? <FaSpinner className="admin-spinner" /> : <FaSync />} Refresh Metrics
          </button>
          <label className="admin-auto-refresh-toggle">
            <input 
              type="checkbox"
              checked={autoRefresh}
              onChange={() => setAutoRefresh(!autoRefresh)}
            />
            Auto-refresh
          </label>
        </div>
      </div>

      {error && (
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {error}
        </div>
      )}

      {metrics && (
        <>
          <div className="admin-server-overview">
            <div className="admin-system-info-card">
              <h3><FaServer /> System Information</h3>
              <div className="admin-server-details">
                <div className="admin-server-detail">
                  <span className="admin-detail-label">Hostname:</span>
                  <span className="admin-detail-value">{metrics.system.hostname}</span>
                </div>
                <div className="admin-server-detail">
                  <span className="admin-detail-label">Uptime:</span>
                  <span className="admin-detail-value">
                    {metrics.system.uptime_days} days, {metrics.system.uptime_hours} hours, {metrics.system.uptime_minutes} minutes
                  </span>
                </div>
                <div className="admin-server-detail">
                  <span className="admin-detail-label">CPU Cores:</span>
                  <span className="admin-detail-value">{metrics.cpu.count}</span>
                </div>
                <div className="admin-server-detail">
                  <span className="admin-detail-label">Memory:</span>
                  <span className="admin-detail-value">{metrics.memory.total_gb} GB</span>
                </div>
                <div className="admin-server-detail">
                  <span className="admin-detail-label">Disk Space:</span>
                  <span className="admin-detail-value">{metrics.disk.total_gb} GB</span>
                </div>
              </div>
            </div>
          </div>

          <div className="admin-metrics-grid">
            {/* CPU Metrics */}
            <div className="admin-metric-card">
              <div className="admin-metric-header">
                <h3><FaMicrochip /> CPU Usage</h3>
                <div className="admin-metric-value">{metrics.cpu.percent}%</div>
              </div>
              <div className="admin-metric-chart">
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Used', value: metrics.cpu.percent },
                        { name: 'Free', value: 100 - metrics.cpu.percent }
                      ]}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {[0, 1].map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value) => `${value}%`} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="admin-metric-details">
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Context Switches:</span>
                  <span className="admin-detail-value">{metrics.cpu.ctx_switches.toLocaleString()}</span>
                </div>
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Interrupts:</span>
                  <span className="admin-detail-value">{metrics.cpu.interrupts.toLocaleString()}</span>
                </div>
              </div>
            </div>

            {/* Memory Metrics */}
            <div className="admin-metric-card">
              <div className="admin-metric-header">
                <h3><FaMemory /> Memory Usage</h3>
                <div className="admin-metric-value">{metrics.memory.percent}%</div>
              </div>
              <div className="admin-metric-chart">
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Used', value: metrics.memory.percent },
                        { name: 'Free', value: 100 - metrics.memory.percent }
                      ]}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {[0, 1].map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value) => `${value}%`} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="admin-metric-details">
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Total:</span>
                  <span className="admin-detail-value">{metrics.memory.total_gb} GB</span>
                </div>
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Used:</span>
                  <span className="admin-detail-value">{metrics.memory.used_gb} GB</span>
                </div>
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Available:</span>
                  <span className="admin-detail-value">{metrics.memory.available_gb} GB</span>
                </div>
              </div>
            </div>

            {/* Disk Metrics */}
            <div className="admin-metric-card">
              <div className="admin-metric-header">
                <h3><FaHdd /> Disk Usage</h3>
                <div className="admin-metric-value">{metrics.disk.percent}%</div>
              </div>
              <div className="admin-metric-chart">
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Used', value: metrics.disk.percent },
                        { name: 'Free', value: 100 - metrics.disk.percent }
                      ]}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {[0, 1].map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value) => `${value}%`} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="admin-metric-details">
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Total:</span>
                  <span className="admin-detail-value">{metrics.disk.total_gb} GB</span>
                </div>
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Used:</span>
                  <span className="admin-detail-value">{metrics.disk.used_gb} GB</span>
                </div>
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Free:</span>
                  <span className="admin-detail-value">{metrics.disk.free_gb} GB</span>
                </div>
              </div>
            </div>

            {/* Network Metrics */}
            <div className="admin-metric-card">
              <div className="admin-metric-header">
                <h3><FaNetworkWired /> Network Traffic</h3>
              </div>
              <div className="admin-metric-details">
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Sent:</span>
                  <span className="admin-detail-value">{formatBytes(metrics.network.bytes_sent)}</span>
                </div>
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Received:</span>
                  <span className="admin-detail-value">{formatBytes(metrics.network.bytes_recv)}</span>
                </div>
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Packets Sent:</span>
                  <span className="admin-detail-value">{metrics.network.packets_sent.toLocaleString()}</span>
                </div>
                <div className="admin-detail-item">
                  <span className="admin-detail-label">Packets Received:</span>
                  <span className="admin-detail-value">{metrics.network.packets_recv.toLocaleString()}</span>
                </div>
              </div>
            </div>
          </div>

          {/* History Charts */}
          <div className="admin-charts-section">
            <h3><FaTachometerAlt /> Performance History</h3>
            <div className="admin-resource-chart">
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={metricsHistory}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                  <XAxis 
                    dataKey="timestampFormatted" 
                    tick={{fill: 'var(--admin-text-secondary)'}}
                  />
                  <YAxis 
                    tick={{fill: 'var(--admin-text-secondary)'}}
                    domain={[0, 100]}
                    tickFormatter={(value) => `${value}%`}
                  />
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'var(--admin-bg-card)',
                      border: '1px solid var(--admin-border)',
                      borderRadius: '8px'
                    }}
                    labelStyle={{color: 'var(--admin-text)'}}
                    itemStyle={{color: 'var(--admin-text)'}}
                    formatter={(value) => [`${value}%`, '']}
                  />
                  <Legend />
                  <Area 
                    type="monotone" 
                    dataKey="cpu" 
                    name="CPU" 
                    stroke={COLORS.cpu} 
                    fill={COLORS.cpu} 
                    fillOpacity={0.3}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="memory" 
                    name="Memory" 
                    stroke={COLORS.memory} 
                    fill={COLORS.memory} 
                    fillOpacity={0.3}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="disk" 
                    name="Disk" 
                    stroke={COLORS.disk} 
                    fill={COLORS.disk} 
                    fillOpacity={0.3}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Top Processes */}
          <div className="admin-processes-section">
            <h3><FaClock /> Top Processes</h3>
            <div className="admin-data-table-container">
              <table className="admin-data-table">
                <thead>
                  <tr>
                    <th>PID</th>
                    <th>Name</th>
                    <th>User</th>
                    <th>CPU %</th>
                    <th>Memory %</th>
                  </tr>
                </thead>
                <tbody>
                  {metrics.top_processes.map((process) => (
                    <tr key={process.pid}>
                      <td>{process.pid}</td>
                      <td>{process.name}</td>
                      <td>{process.username}</td>
                      <td>{process.cpu_percent?.toFixed(1) || 0}</td>
                      <td>{process.memory_percent?.toFixed(1) || 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {loading && !metrics && (
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading server metrics...</p>
        </div>
      )}
    </div>
  );
};

export default ServerMetricsTab;
