// src/components/cracked/tabs/RevenueTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaChartLine, FaMoneyBillWave, FaApple, FaStripe, FaUser,
  FaUserPlus, FaUserMinus, FaCalendarAlt, FaSync,
  FaSpinner, FaExclamationTriangle, FaDollarSign
} from "react-icons/fa";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, 
  Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell
} from "recharts";
import { adminFetch } from '../csrfHelper';

const RevenueTab = () => {
  const [revenueOverview, setRevenueOverview] = useState(null);
  const [signupMetrics, setSignupMetrics] = useState([]);
  const [cancellationMetrics, setCancellationMetrics] = useState(null);
  const [recentSignups, setRecentSignups] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Pie chart colors
  const PLATFORM_COLORS = ["#6543cc", "#4285F4"];

  const fetchRevenueData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch revenue overview
      const overviewRes = await fetch("/api/cracked/revenue/overview", { credentials: "include" });
      if (!overviewRes.ok) {
        const errData = await overviewRes.json();
        throw new Error(errData.error || "Failed to fetch revenue overview");
      }
      const overviewData = await overviewRes.json();
      setRevenueOverview(overviewData);

      // Fetch signup metrics
      const signupsRes = await fetch("/api/cracked/revenue/signups", { credentials: "include" });
      if (!signupsRes.ok) {
        const errData = await signupsRes.json();
        throw new Error(errData.error || "Failed to fetch signup metrics");
      }
      const signupsData = await signupsRes.json();
      setSignupMetrics(signupsData);

      // Fetch cancellation metrics
      const cancellationRes = await fetch("/api/cracked/revenue/cancellation", { credentials: "include" });
      if (!cancellationRes.ok) {
        const errData = await cancellationRes.json();
        throw new Error(errData.error || "Failed to fetch cancellation metrics");
      }
      const cancellationData = await cancellationRes.json();
      setCancellationMetrics(cancellationData);

      // Fetch recent signups
      const recentRes = await fetch("/api/cracked/revenue/recent-signups", { credentials: "include" });
      if (!recentRes.ok) {
        const errData = await recentRes.json();
        throw new Error(errData.error || "Failed to fetch recent signups");
      }
      const recentData = await recentRes.json();
      setRecentSignups(recentData);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRevenueData();
    
    // Refresh recent signups every 60 seconds
    const intervalId = setInterval(() => {
      fetch("/api/cracked/revenue/recent-signups", { credentials: "include" })
        .then(res => {
          if (res.ok) return res.json();
          return null;
        })
        .then(data => {
          if (data) setRecentSignups(data);
        })
        .catch(err => console.error("Error refreshing recent signups:", err));
    }, 60000);
    
    return () => clearInterval(intervalId);
  }, [fetchRevenueData]);

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
        <div className="admin-chart-tooltip">
          <p className="admin-chart-tooltip-label">{label}</p>
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

  // Prepare data for platform distribution pie chart
  const preparePlatformData = () => {
    if (!revenueOverview) return [];
    
    return [
      { name: "Stripe (Web)", value: revenueOverview.stripe_subscribers },
      { name: "Apple (iOS)", value: revenueOverview.apple_subscribers }
    ];
  };

  return (
    <div className="admin-tab-content revenue-tab">
      <div className="admin-content-header">
        <h2><FaMoneyBillWave /> Revenue Dashboard</h2>
        <button className="admin-refresh-btn" onClick={fetchRevenueData}>
          <FaSync /> Refresh Data
        </button>
      </div>

      {loading && !revenueOverview && (
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading revenue data...</p>
        </div>
      )}

      {error && (
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {error}
        </div>
      )}

      {revenueOverview && (
        <>
          {/* Revenue Overview Stats */}
          <div className="admin-stats-grid">
            <div className="admin-stat-card">
              <div className="admin-stat-icon revenue-icon">
                <FaDollarSign />
              </div>
              <div className="admin-stat-content">
                <h3>Monthly Recurring Revenue</h3>
                <div className="admin-stat-value">
                  {formatCurrency(revenueOverview.total_active_revenue)}
                </div>
                <div className="admin-stat-subtext">
                  {revenueOverview.active_subscribers} active subscribers
                </div>
              </div>
            </div>

            <div className="admin-stat-card">
              <div className="admin-stat-icon new-revenue-icon">
                <FaCalendarAlt />
              </div>
              <div className="admin-stat-content">
                <h3>Last 7 Days</h3>
                <div className="admin-stat-value">
                  {formatCurrency(revenueOverview.new_revenue_7d)}
                </div>
                <div className="admin-stat-subtext">
                  {revenueOverview.new_subscribers_7d} new subscribers
                </div>
              </div>
            </div>

            <div className="admin-stat-card">
              <div className="admin-stat-icon all-time-icon">
                <FaChartLine />
              </div>
              <div className="admin-stat-content">
                <h3>All-Time Revenue</h3>
                <div className="admin-stat-value">
                  {formatCurrency(revenueOverview.all_time_revenue)}
                </div>
                <div className="admin-stat-subtext">
                  {revenueOverview.all_time_subscribers} total subscribers
                </div>
              </div>
            </div>

            <div className="admin-stat-card">
              <div className="admin-stat-icon retention-icon">
                <FaUserMinus />
              </div>
              <div className="admin-stat-content">
                <h3>Avg. Subscription Lifetime</h3>
                <div className="admin-stat-value">
                  {cancellationMetrics ? 
                    `${cancellationMetrics.average_duration_days} days` : 
                    'Loading...'}
                </div>
                <div className="admin-stat-subtext">
                  {cancellationMetrics ? 
                    `${cancellationMetrics.cancellation_rate}% cancel rate` : 
                    ''}
                </div>
              </div>
            </div>
          </div>

          {/* Charts Section */}
          <div className="admin-revenue-charts">
            <div className="admin-chart-container">
              <h3>Signups by Platform (Last 7 Days)</h3>
              <div className="admin-chart-wrapper">
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={signupMetrics}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <Tooltip content={<CustomTooltip />} />
                    <Legend />
                    <Bar dataKey="stripe" name="Stripe (Web)" stackId="a" fill="#6543cc" />
                    <Bar dataKey="apple" name="Apple (iOS)" stackId="a" fill="#4285F4" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="admin-chart-container">
              <h3>Platform Distribution</h3>
              <div className="admin-chart-wrapper admin-platform-chart">
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={preparePlatformData()}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    >
                      {preparePlatformData().map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={PLATFORM_COLORS[index % PLATFORM_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value) => [value, "Subscribers"]} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="admin-platform-stats">
                  <div className="admin-platform-stat">
                    <FaStripe className="admin-platform-icon stripe-icon" />
                    <div className="admin-platform-info">
                      <div className="admin-platform-name">Stripe (Web)</div>
                      <div className="admin-platform-value">
                        {formatCurrency(revenueOverview.stripe_revenue)}
                      </div>
                    </div>
                  </div>
                  <div className="admin-platform-stat">
                    <FaApple className="admin-platform-icon apple-icon" />
                    <div className="admin-platform-info">
                      <div className="admin-platform-name">Apple (iOS)</div>
                      <div className="admin-platform-value">
                        {formatCurrency(revenueOverview.apple_revenue)}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Signups & Cancellations Section */}
            <div className="admin-revenue-feed">
              <div className="admin-card">
                <h3><FaUserPlus /> Recent Signups</h3>
                <div className="admin-feed-container">
                  {recentSignups.length > 0 ? (
                    <div className="admin-feed-list">
                      {recentSignups.map((signup, index) => (
                        <div key={index} className="admin-feed-item">
                          <div className="admin-feed-icon">
                            {signup.platform === 'stripe' ? (
                              <FaStripe className="admin-feed-platform-icon stripe-icon" />
                            ) : (
                              <FaApple className="admin-feed-platform-icon apple-icon" />
                            )}
                          </div>
                          <div className="admin-feed-content">
                            <div className="admin-feed-title">
                              {signup.username}
                              <span className="admin-feed-email">{signup.email}</span>
                            </div>
                            <div className="admin-feed-time">
                              {formatDate(signup.signupDate)}
                            </div>
                          </div>
                          <div className="admin-feed-status">
                            <span className={`admin-feed-status-badge status-${signup.status}`}>
                              {signup.status}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="admin-no-data">
                      No recent signups to display
                    </div>
                  )}
                </div>
              </div>

              <div className="admin-card">
                <h3><FaUserMinus /> Recent Cancellations</h3>
                <div className="admin-feed-container">
                  {cancellationMetrics && cancellationMetrics.recent_cancellations && 
                   cancellationMetrics.recent_cancellations.length > 0 ? (
                    <div className="admin-feed-list">
                      {cancellationMetrics.recent_cancellations.map((cancel, index) => (
                        <div key={index} className="admin-feed-item">
                          <div className="admin-feed-icon">
                            {cancel.platform === 'stripe' ? (
                              <FaStripe className="admin-feed-platform-icon stripe-icon" />
                            ) : (
                              <FaApple className="admin-feed-platform-icon apple-icon" />
                            )}
                          </div>
                          <div className="admin-feed-content">
                            <div className="admin-feed-title">
                              {cancel.username}
                            </div>
                            <div className="admin-feed-time">
                              {formatDate(cancel.timestamp)}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="admin-no-data">
                      No recent cancellations to display
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default RevenueTab;
