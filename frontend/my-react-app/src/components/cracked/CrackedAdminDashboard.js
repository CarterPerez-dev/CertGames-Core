/**************************************************************************************
 * CrackedAdminDashboard.jsx
 * 
 * Full updated code for the Admin Dashboard component with improved Support tab UI.
 * This file references "CrackedAdminDashboard.css" for styling.
 **************************************************************************************/
import React, { useState, useEffect, useCallback } from "react";
import { io } from "socket.io-client";
import "./CrackedAdminDashboard.css";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Legend
} from "recharts";

// We keep this as a top-level variable
let adminSocket = null;

function CrackedAdminDashboard() {
  const [activeTab, setActiveTab] = useState("overview");

  /*****************************************
   * OVERVIEW
   *****************************************/
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
    if (activeTab === "overview") {
      fetchOverview();
    }
  }, [activeTab, fetchOverview]);

  /*****************************************
   * PERFORMANCE
   *****************************************/
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

  /*****************************************
   * USERS
   *****************************************/
  const [users, setUsers] = useState([]);
  const [userTotal, setUserTotal] = useState(0);
  const [userSearch, setUserSearch] = useState("");
  const [userPage, setUserPage] = useState(1);
  const [userLimit] = useState(10);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState(null);

  const [editUserId, setEditUserId] = useState(null);
  const [editUserData, setEditUserData] = useState({});

  const fetchUsers = useCallback(async () => {
    setUsersLoading(true);
    setUsersError(null);
    try {
      const params = new URLSearchParams({
        search: userSearch,
        page: userPage.toString(),
        limit: userLimit.toString()
      });
      const res = await fetch(`/api/cracked/users?${params.toString()}`, {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch users");
      }
      setUsers(data.users || []);
      setUserTotal(data.total || 0);
    } catch (err) {
      setUsersError(err.message);
    } finally {
      setUsersLoading(false);
    }
  }, [userSearch, userPage, userLimit]);

  useEffect(() => {
    if (activeTab === "users") {
      fetchUsers();
    }
  }, [activeTab, fetchUsers]);

  const handleUpdateUserField = (field, value) => {
    setEditUserData((prev) => ({ ...prev, [field]: value }));
  };

  const handleUserEdit = (u) => {
    setEditUserId(u._id);
    setEditUserData({
      username: u.username || "",
      coins: u.coins || 0,
      xp: u.xp || 0,
      level: u.level || 1,
      subscriptionActive: !!u.subscriptionActive,
      suspended: !!u.suspended
    });
  };

  const handleUserUpdateSubmit = async () => {
    if (!editUserId) return;
    try {
      const res = await fetch(`/api/cracked/users/${editUserId}`, {
        method: "PUT",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(editUserData)
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to update user");
        return;
      }
      alert("User updated!");
      fetchUsers();
    } catch (err) {
      console.error("User update error:", err);
    } finally {
      setEditUserId(null);
    }
  };

  const handleUserDelete = async (userId) => {
    if (!window.confirm("Are you sure you want to DELETE this user?")) return;
    try {
      const res = await fetch(`/api/cracked/users/${userId}`, {
        method: "DELETE",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to delete user");
        return;
      }
      alert("User deleted successfully.");
      fetchUsers();
    } catch (err) {
      console.error("User delete error:", err);
    }
  };

  // EXTRA: Reset user password
  const handleResetPassword = async (userId) => {
    if (!window.confirm("Reset this user's password to a random token?")) return;
    try {
      const res = await fetch(`/api/cracked/users/${userId}/reset-password`, {
        method: "POST",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to reset password");
        return;
      }
      alert(`Password reset success. New password: ${data.newPassword}`);
    } catch (err) {
      console.error(err);
      alert("Failed to reset password.");
    }
  };

  /*****************************************
   * TEST MANAGEMENT
   *****************************************/
  const [tests, setTests] = useState([]);
  const [testCategory, setTestCategory] = useState("");
  const [testsLoading, setTestsLoading] = useState(false);
  const [testsError, setTestsError] = useState(null);

  const [newTestData, setNewTestData] = useState({
    category: "",
    testId: "",
    testName: "",
    questions: []
  });

  const fetchTests = useCallback(async () => {
    setTestsLoading(true);
    setTestsError(null);
    try {
      const params = new URLSearchParams();
      if (testCategory) {
        params.set("category", testCategory);
      }
      const res = await fetch(`/api/cracked/tests?${params.toString()}`, {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch tests");
      }
      setTests(data);
    } catch (err) {
      setTestsError(err.message);
    } finally {
      setTestsLoading(false);
    }
  }, [testCategory]);

  useEffect(() => {
    if (activeTab === "tests") {
      fetchTests();
    }
  }, [activeTab, fetchTests]);

  const handleCreateTest = async () => {
    try {
      const body = {
        category: newTestData.category,
        testId: Number(newTestData.testId),
        testName: newTestData.testName,
        questions: []
      };
      const res = await fetch("/api/cracked/tests", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to create test");
        return;
      }
      alert("Test created!");
      fetchTests();
      setNewTestData({ category: "", testId: "", testName: "", questions: [] });
    } catch (err) {
      console.error("Create test error:", err);
    }
  };

  const handleDeleteTest = async (testObj) => {
    if (!window.confirm(`Delete test: ${testObj.testName}?`)) return;
    try {
      const res = await fetch(`/api/cracked/tests/${testObj._id}`, {
        method: "DELETE",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to delete test");
        return;
      }
      alert("Test deleted successfully.");
      fetchTests();
    } catch (err) {
      console.error("Delete test error:", err);
    }
  };

  /*****************************************
   * DAILY PBQs
   *****************************************/
  const [dailyList, setDailyList] = useState([]);
  const [dailyLoading, setDailyLoading] = useState(false);
  const [dailyError, setDailyError] = useState(null);

  const [newDaily, setNewDaily] = useState({
    prompt: "",
    dayIndex: "",
    correctIndex: "",
    explanation: ""
  });

  const fetchDailyPBQs = useCallback(async () => {
    setDailyLoading(true);
    setDailyError(null);
    try {
      const res = await fetch("/api/cracked/daily", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch daily PBQs");
      }
      setDailyList(data);
    } catch (err) {
      setDailyError(err.message);
    } finally {
      setDailyLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "daily") {
      fetchDailyPBQs();
    }
  }, [activeTab, fetchDailyPBQs]);

  const handleCreateDaily = async () => {
    try {
      const body = {
        prompt: newDaily.prompt,
        dayIndex: Number(newDaily.dayIndex) || 0,
        correctIndex: Number(newDaily.correctIndex) || 0,
        explanation: newDaily.explanation
      };
      const res = await fetch("/api/cracked/daily", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to create daily PBQ");
        return;
      }
      alert("Daily PBQ created!");
      fetchDailyPBQs();
      setNewDaily({ prompt: "", dayIndex: "", correctIndex: "", explanation: "" });
    } catch (err) {
      console.error("Create daily PBQ error:", err);
    }
  };

  const handleDeleteDaily = async (pbq) => {
    if (!window.confirm(`Delete daily PBQ: ${pbq.prompt}?`)) return;
    try {
      const res = await fetch(`/api/cracked/daily/${pbq._id}`, {
        method: "DELETE",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to delete daily PBQ");
        return;
      }
      alert("Daily PBQ deleted successfully.");
      fetchDailyPBQs();
    } catch (err) {
      console.error("Delete daily PBQ error:", err);
    }
  };

  /*****************************************
   * SUPPORT
   *****************************************/
  const [threads, setThreads] = useState([]);
  const [threadsLoading, setThreadsLoading] = useState(false);
  const [threadsError, setThreadsError] = useState(null);
  const [threadStatusFilter, setThreadStatusFilter] = useState("");
  const [currentThread, setCurrentThread] = useState(null);
  const [adminReply, setAdminReply] = useState("");

  // We store all threads (including messages) so we can do real‐time merges
  const [allThreadMap, setAllThreadMap] = useState({});
  // Show "user is typing" in real time
  const [userIsTyping, setUserIsTyping] = useState(false);

  // Admin create thread for user
  const [adminTargetUserId, setAdminTargetUserId] = useState("");
  const [adminInitialMsg, setAdminInitialMsg] = useState("");

  const fetchThreads = useCallback(async () => {
    setThreadsLoading(true);
    setThreadsError(null);
    try {
      const params = new URLSearchParams();
      if (threadStatusFilter) {
        params.set("status", threadStatusFilter);
      }
      const res = await fetch(`/api/cracked/supportThreads?${params.toString()}`, {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch support threads");
      }
      setThreads(data);
      setCurrentThread(null);

      // Join all threads so we get real‐time updates
      if (adminSocket && data.length > 0) {
        data.forEach((th) => {
          adminSocket.emit("join_thread", { threadId: th._id });
        });
      }
    } catch (err) {
      setThreadsError(err.message);
    } finally {
      setThreadsLoading(false);
    }
  }, [threadStatusFilter]);

  // Initialize adminSocket once
  useEffect(() => {
    if (!adminSocket) {
      const socket = io(window.location.origin, {
        path: "/api/socket.io",
        transports: ["websocket"]
      });
      adminSocket = socket;

      socket.on("connect", () => {
        console.log("Admin socket connected:", socket.id);
      });

      socket.on("disconnect", () => {
        console.log("Admin socket disconnected");
      });

      // Listen for new messages across ANY thread
      socket.on("new_message", (payload) => {
        const { threadId, message } = payload;
        setAllThreadMap((prev) => {
          const oldThread = prev[threadId] || { messages: [] };
          const oldMsgs = oldThread.messages;
          return {
            ...prev,
            [threadId]: {
              ...oldThread,
              messages: [...oldMsgs, message]
            }
          };
        });
        // If the currentThread is the same, append
        setCurrentThread((prev) => {
          if (prev && prev._id === threadId) {
            return {
              ...prev,
              messages: [...prev.messages, message]
            };
          }
          return prev;
        });
      });

      // user_typing / user_stop_typing
      socket.on("user_typing", (data) => {
        if (data.threadId && currentThread && currentThread._id === data.threadId) {
          setUserIsTyping(true);
        }
      });
      socket.on("user_stop_typing", (data) => {
        if (data.threadId && currentThread && currentThread._id === data.threadId) {
          setUserIsTyping(false);
        }
      });

      // Admin sees newly created threads
      socket.on("new_thread", (threadData) => {
        setThreads((prev) => [threadData, ...prev]);
        socket.emit("join_thread", { threadId: threadData._id });
      });
    }
  }, [currentThread]);

  useEffect(() => {
    if (activeTab === "support") {
      fetchThreads();
    }
  }, [activeTab, fetchThreads]);

  const handleViewThread = async (threadId) => {
    try {
      const res = await fetch(`/api/cracked/supportThreads/${threadId}`, {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to get thread");
        return;
      }
      setCurrentThread(data);
      setAdminReply("");
      setUserIsTyping(false);

      // Merge into allThreadMap
      setAllThreadMap((prev) => ({
        ...prev,
        [threadId]: data
      }));
    } catch (err) {
      console.error("View thread error:", err);
    }
  };

  const handleReplyToThread = async () => {
    if (!currentThread || !currentThread._id) return;
    try {
      const res = await fetch(`/api/cracked/supportThreads/${currentThread._id}/reply`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: adminReply })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to reply");
        return;
      }
      alert("Reply sent!");
      // Refresh the single thread from DB
      handleViewThread(currentThread._id);

      // Tell the user in real time
      if (adminSocket) {
        adminSocket.emit("admin_stop_typing", {
          threadId: currentThread._id
        });
        adminSocket.emit("admin_new_message", {
          threadId: currentThread._id,
          message: {
            sender: "admin",
            content: adminReply,
            timestamp: new Date().toISOString()
          }
        });
      }
      setAdminReply("");
    } catch (err) {
      console.error("Reply thread error:", err);
    }
  };

  const handleAdminReplyTyping = (threadId) => {
    if (adminSocket && threadId) {
      adminSocket.emit("admin_typing", { threadId });
    }
  };

  const handleCloseThread = async (threadId) => {
    const resolution = window.prompt("Enter a resolution note:", "Issue resolved.");
    if (resolution === null) return;
    try {
      const res = await fetch(`/api/cracked/supportThreads/${threadId}/close`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ resolution })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to close thread");
        return;
      }
      alert("Thread closed!");
      fetchThreads();
    } catch (err) {
      console.error("Close thread error:", err);
    }
  };

  const handleClearClosedThreads = async () => {
    if (!window.confirm("Are you sure you want to permanently delete all closed threads?")) return;
    try {
      const res = await fetch("/api/cracked/supportThreads/clear-closed", {
        method: "DELETE",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to clear closed threads");
        return;
      }
      alert(data.message || "Closed threads cleared");
      fetchThreads();
    } catch (err) {
      alert("Error clearing closed threads");
    }
  };

  const handleAdminCreateThread = async () => {
    if (!adminTargetUserId) {
      alert("Please enter a valid userId");
      return;
    }
    try {
      const body = {
        userId: adminTargetUserId,
        initialMessage: adminInitialMsg
      };
      const res = await fetch("/api/cracked/supportThreads/createFromAdmin", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to create thread from admin");
        return;
      }
      alert("Created new thread successfully!");
      setAdminTargetUserId("");
      setAdminInitialMsg("");
      fetchThreads();
    } catch (err) {
      console.error(err);
      alert("Error creating admin thread");
    }
  };

  /*****************************************
   * ACTIVITY LOGS
   *****************************************/
  const [activityLogs, setActivityLogs] = useState([]);
  const fetchActivityLogs = useCallback(async () => {
    try {
      const res = await fetch("/api/cracked/activity-logs", { credentials: "include" });
      const data = await res.json();
      if (data.logs) {
        setActivityLogs(data.logs);
      }
    } catch (err) {
      console.error(err);
    }
  }, []);

  /*****************************************
   * DB LOGS
   *****************************************/
  const [dbLogs, setDbLogs] = useState([]);
  const fetchDbLogs = useCallback(async () => {
    try {
      const res = await fetch("/api/cracked/db-logs", { credentials: "include" });
      const data = await res.json();
      setDbLogs(data);
    } catch (err) {
      console.error(err);
    }
  }, []);

  /*****************************************
   * DB SHELL
   *****************************************/
  const [dbShellCollection, setDbShellCollection] = useState("");
  const [dbShellFilter, setDbShellFilter] = useState("{}");
  const [dbShellLimit, setDbShellLimit] = useState(5);
  const [dbShellResults, setDbShellResults] = useState([]);

  const handleDbShellRead = async () => {
    try {
      const parsedFilter = JSON.parse(dbShellFilter);
      const body = {
        collection: dbShellCollection,
        filter: parsedFilter,
        limit: dbShellLimit
      };
      const res = await fetch("/api/cracked/db-shell/read", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (Array.isArray(data)) {
        setDbShellResults(data);
      } else {
        alert(data.error || "Error reading DB");
      }
    } catch (err) {
      alert("JSON filter is invalid or error occurred.");
      console.error(err);
    }
  };

  /*****************************************
   * HEALTH CHECKS
   *****************************************/
  const [healthChecks, setHealthChecks] = useState([]);
  const fetchHealthChecks = useCallback(async () => {
    try {
      const res = await fetch("/api/cracked/health-checks", { credentials: "include" });
      const data = await res.json();
      if (Array.isArray(data)) {
        setHealthChecks(data);
      } else if (data.results) {
        setHealthChecks(data.results);
      }
    } catch (err) {
      console.error(err);
    }
  }, []);

  /*****************************************
   * TAB SWITCH
   *****************************************/
  const switchTab = (tabName) => {
    setActiveTab(tabName);
    if (tabName === "activity") {
      fetchActivityLogs();
    } else if (tabName === "dbLogs") {
      fetchDbLogs();
    } else if (tabName === "dbShell") {
      setDbShellResults([]);
    } else if (tabName === "healthChecks") {
      fetchHealthChecks();
    }
  };

  /*****************************************
   * RENDER: OVERVIEW
   *****************************************/
  const renderOverviewTab = () => {
    if (overviewLoading) {
      return <div className="tab-content">Loading overview...</div>;
    }
    if (overviewError) {
      return <div className="tab-content error-msg">Error: {overviewError}</div>;
    }
    if (!overviewData) {
      return <div className="tab-content">No overview data yet.</div>;
    }

    const hasChartArray =
      Array.isArray(overviewData.recentStats) && overviewData.recentStats.length > 0;

    return (
      <div className="tab-content overview-tab">
        <h2>Overview Stats</h2>
        <ul>
          <li>User Count: {overviewData.user_count}</li>
          <li>Test Attempts: {overviewData.test_attempts_count}</li>
          <li>Daily Bonus Claims Today: {overviewData.daily_bonus_claims}</li>
          <li>Avg Test Score (%): {overviewData.average_test_score_percent}</li>
          <li>Timestamp (EST): {overviewData.timestamp_est}</li>
        </ul>
        <button onClick={fetchOverview}>Refresh Overview</button>

        <div className="chart-section">
          <h3>Recent Stats</h3>
          {hasChartArray ? (
            <div className="chart-container">
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={overviewData.recentStats}>
                  <defs>
                    <linearGradient id="colorDailyBonus" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#2ecc71" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="#2ecc71" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorTestAttempts" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3498db" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="#3498db" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="label" />
                  <YAxis />
                  <CartesianGrid strokeDasharray="3 3" />
                  <Tooltip />
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
                    stroke="#3498db"
                    fill="url(#colorTestAttempts)"
                    name="Test Attempts"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p>No chart data available.</p>
          )}
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: PERFORMANCE
   *****************************************/
  const renderPerformanceTab = () => {
    return (
      <div className="tab-content perf-tab">
        <h2>Performance Metrics</h2>
        <button onClick={fetchPerformance} style={{ marginBottom: "10px" }}>
          Refresh Perf Data
        </button>
        {perfLoading && <p>Loading performance data...</p>}
        {perfError && <p className="error-msg">Error: {perfError}</p>}
        {performanceData && (
          <>
            <div className="perf-details">
              <p>Avg Request Time: {performanceData.avg_request_time}s</p>
              {"avg_db_query_time_ms" in performanceData ? (
                <p>Avg DB Query Time: {performanceData.avg_db_query_time_ms} ms</p>
              ) : (
                <p>Avg DB Query Time: {performanceData.avg_db_query_time}s</p>
              )}
              <p>Data Transfer Rate: {performanceData.data_transfer_rate}</p>
              <p>Throughput: {performanceData.throughput} req/min</p>
              <p>Error Rate: {performanceData.error_rate}</p>
              <p>Timestamp (EST): {performanceData.timestamp}</p>
            </div>

            <div className="chart-section">
              <h3>Performance History</h3>
              {Array.isArray(performanceData.history) && performanceData.history.length > 0 ? (
                <div className="chart-container">
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={performanceData.history}>
                      <defs>
                        <linearGradient id="colorRequestTime" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#e67e22" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#e67e22" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="colorDbTime" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#9b59b6" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#9b59b6" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <CartesianGrid strokeDasharray="3 3" />
                      <Tooltip />
                      <Area
                        type="monotone"
                        dataKey="requestTime"
                        stroke="#e67e22"
                        fill="url(#colorRequestTime)"
                        name="Request Time (s)"
                      />
                      <Area
                        type="monotone"
                        dataKey="dbTime"
                        stroke="#9b59b6"
                        fill="url(#colorDbTime)"
                        name="DB Time (ms)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p>No chart data available.</p>
              )}
            </div>
          </>
        )}
      </div>
    );
  };

  /*****************************************
   * RENDER: USERS
   *****************************************/
  const renderUsersTab = () => {
    return (
      <div className="tab-content users-tab">
        <h2>User Management</h2>
        <div className="users-search-row">
          <input
            type="text"
            value={userSearch}
            placeholder="Search by username or email"
            onChange={(e) => setUserSearch(e.target.value)}
          />
          <button
            onClick={() => {
              setUserPage(1);
              fetchUsers();
            }}
          >
            Search
          </button>
        </div>
        <div style={{ marginTop: "10px" }}>
          <p>
            Page: {userPage} / {Math.ceil(userTotal / userLimit)} (Total: {userTotal})
          </p>
          <button
            disabled={userPage <= 1}
            onClick={() => setUserPage((prev) => Math.max(1, prev - 1))}
          >
            Prev
          </button>
          <button
            disabled={userPage >= Math.ceil(userTotal / userLimit)}
            onClick={() => setUserPage((prev) => prev + 1)}
          >
            Next
          </button>
        </div>
        {usersLoading && <div>Loading users...</div>}
        {usersError && <div className="error-msg">Error: {usersError}</div>}

        <table className="users-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Email</th>
              <th>Coins</th>
              <th>XP</th>
              <th>Level</th>
              <th>Suspended</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => {
              const isEditing = editUserId === u._id;
              return (
                <tr key={u._id}>
                  <td>{u._id}</td>
                  <td>
                    {isEditing ? (
                      <input
                        type="text"
                        value={editUserData.username}
                        onChange={(e) => handleUpdateUserField("username", e.target.value)}
                      />
                    ) : (
                      u.username
                    )}
                  </td>
                  <td>{u.email}</td>
                  <td>
                    {isEditing ? (
                      <input
                        type="number"
                        value={editUserData.coins}
                        onChange={(e) => handleUpdateUserField("coins", e.target.value)}
                      />
                    ) : (
                      u.coins
                    )}
                  </td>
                  <td>
                    {isEditing ? (
                      <input
                        type="number"
                        value={editUserData.xp}
                        onChange={(e) => handleUpdateUserField("xp", e.target.value)}
                      />
                    ) : (
                      u.xp
                    )}
                  </td>
                  <td>
                    {isEditing ? (
                      <input
                        type="number"
                        value={editUserData.level}
                        onChange={(e) => handleUpdateUserField("level", e.target.value)}
                      />
                    ) : (
                      u.level
                    )}
                  </td>
                  <td>
                    {isEditing ? (
                      <input
                        type="checkbox"
                        checked={!!editUserData.suspended}
                        onChange={(e) => handleUpdateUserField("suspended", e.target.checked)}
                      />
                    ) : (
                      u.suspended ? "Yes" : "No"
                    )}
                  </td>
                  <td>
                    {isEditing ? (
                      <>
                        <button onClick={handleUserUpdateSubmit}>Save</button>
                        <button onClick={() => setEditUserId(null)}>Cancel</button>
                      </>
                    ) : (
                      <>
                        <button onClick={() => handleUserEdit(u)}>Edit</button>
                        <button onClick={() => handleResetPassword(u._id)}>Reset PW</button>
                        <button onClick={() => handleUserDelete(u._id)}>Delete</button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
  };

  /*****************************************
   * RENDER: TESTS
   *****************************************/
  const renderTestsTab = () => {
    return (
      <div className="tab-content tests-tab">
        <h2>Test Management</h2>
        <div className="test-filter-row">
          <label>Category Filter:</label>
          <input
            type="text"
            placeholder="e.g. aplus"
            value={testCategory}
            onChange={(e) => setTestCategory(e.target.value)}
          />
          <button onClick={fetchTests}>Fetch Tests</button>
        </div>
        {testsLoading && <p>Loading tests...</p>}
        {testsError && <p className="error-msg">Error: {testsError}</p>}

        <div className="create-test-form">
          <h4>Create a new Test</h4>
          <input
            type="text"
            placeholder="Category"
            value={newTestData.category}
            onChange={(e) => setNewTestData((prev) => ({ ...prev, category: e.target.value }))}
          />
          <input
            type="text"
            placeholder="Test ID (number)"
            value={newTestData.testId}
            onChange={(e) => setNewTestData((prev) => ({ ...prev, testId: e.target.value }))}
          />
          <input
            type="text"
            placeholder="Test Name"
            value={newTestData.testName}
            onChange={(e) => setNewTestData((prev) => ({ ...prev, testName: e.target.value }))}
          />
          <button onClick={handleCreateTest}>Create Test</button>
        </div>

        <table className="tests-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Category</th>
              <th>TestId #</th>
              <th>Test Name</th>
              <th>Question Count</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {tests.map((t) => (
              <tr key={t._id}>
                <td>{t._id}</td>
                <td>{t.category}</td>
                <td>{t.testId}</td>
                <td>{t.testName || "(Unnamed)"} </td>
                <td>{t.questions ? t.questions.length : 0}</td>
                <td>
                  <button onClick={() => handleDeleteTest(t)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  /*****************************************
   * RENDER: DAILY
   *****************************************/
  const renderDailyTab = () => {
    return (
      <div className="tab-content daily-tab">
        <h2>Daily PBQ Management</h2>
        {dailyLoading && <p>Loading daily PBQs...</p>}
        {dailyError && <p className="error-msg">Error: {dailyError}</p>}

        <div className="create-daily-form">
          <h4>Create a new Daily PBQ</h4>
          <input
            type="text"
            placeholder="Prompt"
            value={newDaily.prompt}
            onChange={(e) => setNewDaily((prev) => ({ ...prev, prompt: e.target.value }))}
          />
          <input
            type="text"
            placeholder="Day Index"
            value={newDaily.dayIndex}
            onChange={(e) => setNewDaily((prev) => ({ ...prev, dayIndex: e.target.value }))}
          />
          <input
            type="text"
            placeholder="Correct Index"
            value={newDaily.correctIndex}
            onChange={(e) => setNewDaily((prev) => ({ ...prev, correctIndex: e.target.value }))}
          />
          <textarea
            placeholder="Explanation"
            value={newDaily.explanation}
            onChange={(e) => setNewDaily((prev) => ({ ...prev, explanation: e.target.value }))}
          />
          <button onClick={handleCreateDaily}>Create Daily PBQ</button>
        </div>

        <table className="daily-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Prompt</th>
              <th>DayIndex</th>
              <th>CorrectIndex</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {dailyList.map((d) => (
              <tr key={d._id}>
                <td>{d._id}</td>
                <td>{d.prompt}</td>
                <td>{d.dayIndex}</td>
                <td>{d.correctIndex}</td>
                <td>
                  <button onClick={() => handleDeleteDaily(d)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  /*****************************************
   * RENDER: SUPPORT
   *****************************************/
  const renderSupportTab = () => {
    return (
      <div className="tab-content support-tab">
        <h2>Support Threads</h2>
        <div className="thread-filter-row">
          <label>Status Filter:</label>
          <input
            type="text"
            placeholder="open / closed? etc."
            value={threadStatusFilter}
            onChange={(e) => setThreadStatusFilter(e.target.value)}
          />
          <button onClick={fetchThreads}>Fetch Threads</button>
        </div>
        {threadsLoading && <p>Loading threads...</p>}
        {threadsError && <p className="error-msg">Error: {threadsError}</p>}

        <div className="support-threads-container">
          <div className="threads-list">
            <ul>
              {threads.map((th) => (
                <li key={th._id}>
                  <strong>{th._id}</strong> - {th.status} - &nbsp;
                  <button onClick={() => handleViewThread(th._id)}>View</button>
                  &nbsp;
                  {th.status !== "closed" && (
                    <button onClick={() => handleCloseThread(th._id)}>Close</button>
                  )}
                </li>
              ))}
            </ul>
            <button style={{ marginTop: "10px" }} onClick={handleClearClosedThreads}>
              Clear All Closed Threads
            </button>
          </div>

          <div className="thread-details">
            {currentThread ? (
              <div className="current-thread-details">
                <h4>Thread: {currentThread._id}</h4>
                <p>Status: {currentThread.status}</p>
                <div className="messages-list-container">
                  <ul className="messages-list">
                    {currentThread.messages.map((m, idx) => (
                      <li key={idx}>
                        <strong>{m.sender}:</strong> {m.content} ({m.timestamp || ""})
                      </li>
                    ))}
                  </ul>
                </div>
                {/* Show if the user is typing */}
                {userIsTyping && (
                  <div className="typing-indicator-user">
                    <em>User is typing...</em>
                  </div>
                )}
                {currentThread.status !== "closed" && (
                  <div className="reply-container">
                    <textarea
                      rows={5} // <---  made bigger
                      placeholder="Type an admin reply..."
                      value={adminReply}
                      onChange={(e) => {
                        setAdminReply(e.target.value);
                        handleAdminReplyTyping(currentThread._id);
                      }}
                    />
                    <button onClick={handleReplyToThread}>Send Reply</button>
                  </div>
                )}
              </div>
            ) : (
              <p>Select a thread to view details.</p>
            )}
          </div>
        </div>

        <div style={{ marginTop: "20px" }}>
          <h3>Create Thread on behalf of a user</h3>
          <div
            className="create-thread-row"
            style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}
          >
            <input
              style={{ flex: "0 0 300px" }}
              placeholder="Target UserId"
              value={adminTargetUserId}
              onChange={(e) => setAdminTargetUserId(e.target.value)}
            />
            <input
              style={{ flex: "1" }}
              placeholder="Initial admin message..."
              value={adminInitialMsg}
              onChange={(e) => setAdminInitialMsg(e.target.value)}
            />
            <button onClick={handleAdminCreateThread}>Create</button>
          </div>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: ACTIVITY LOGS
   *****************************************/
  const renderActivityLogsTab = () => {
    return (
      <div className="tab-content activity-tab">
        <h2>Activity & Audit Logs</h2>
        <button onClick={fetchActivityLogs} style={{ marginBottom: "10px" }}>
          Refresh Logs
        </button>
        <table className="activity-table">
          <thead>
            <tr>
              <th>Timestamp (EST)</th>
              <th>IP</th>
              <th>UserId</th>
              <th>Success</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {activityLogs.map((log) => (
              <tr key={log._id}>
                <td>{log.timestamp}</td>
                <td>{log.ip}</td>
                <td>{log.userId || ""}</td>
                <td>{log.success ? "Yes" : "No"}</td>
                <td>{log.reason || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  /*****************************************
   * RENDER: DB LOGS
   *****************************************/
  const renderDbLogsTab = () => {
    return (
      <div className="tab-content db-logs-tab">
        <h2>DB Query Logs</h2>
        <button onClick={fetchDbLogs} style={{ marginBottom: "10px" }}>
          Refresh
        </button>
        <table className="db-logs-table">
          <thead>
            <tr>
              <th>Timestamp (EST)</th>
              <th>Route</th>
              <th>Method</th>
              <th>Duration (ms)</th>
              <th>DB Time (ms)</th>
              <th>Status</th>
              <th>Bytes</th>
            </tr>
          </thead>
          <tbody>
            {dbLogs.map((log) => (
              <tr key={log._id}>
                <td>{log.timestamp}</td>
                <td>{log.route}</td>
                <td>{log.method}</td>
                <td>{log.duration_ms}</td>
                <td>{log.db_time_ms}</td>
                <td>{log.http_status}</td>
                <td>{log.response_bytes}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  /*****************************************
   * RENDER: DB SHELL
   *****************************************/
  const renderDbShellTab = () => {
    return (
      <div className="tab-content db-shell-tab">
        <h2>Read-Only DB Shell</h2>
        <div className="db-shell-form">
          <label>Collection:</label>
          <input
            type="text"
            value={dbShellCollection}
            onChange={(e) => setDbShellCollection(e.target.value)}
          />
          <label>Filter (JSON):</label>
          <input
            type="text"
            value={dbShellFilter}
            onChange={(e) => setDbShellFilter(e.target.value)}
          />
          <label>Limit:</label>
          <input
            type="number"
            value={dbShellLimit}
            onChange={(e) => setDbShellLimit(e.target.valueAsNumber)}
          />
          <button onClick={handleDbShellRead}>Execute Read</button>
        </div>
        <pre className="db-shell-results">
          {JSON.stringify(dbShellResults, null, 2)}
        </pre>
      </div>
    );
  };

  /*****************************************
   * RENDER: HEALTH CHECKS
   *****************************************/
  const renderHealthChecksTab = () => {
    return (
      <div className="tab-content health-checks-tab">
        <h2>API Health Checks</h2>
        <button onClick={fetchHealthChecks} style={{ marginBottom: "10px" }}>
          Refresh Checks
        </button>
        <table className="health-checks-table">
          <thead>
            <tr>
              <th>checkedAt (EST)</th>
              <th>Endpoint</th>
              <th>Status</th>
              <th>OK</th>
              <th>Error</th>
            </tr>
          </thead>
          <tbody>
            {Array.isArray(healthChecks) &&
              healthChecks.map((hc, idx) => {
                if (hc.results) {
                  // multi results
                  return hc.results.map((r, j) => (
                    <tr key={`${hc._id}_${j}`}>
                      <td>{hc.checkedAt}</td>
                      <td>{r.endpoint}</td>
                      <td>{r.status}</td>
                      <td>{r.ok ? "Yes" : "No"}</td>
                      <td>{r.error || ""}</td>
                    </tr>
                  ));
                } else {
                  return (
                    <tr key={idx}>
                      <td>{hc.checkedAt}</td>
                      <td>{hc.endpoint}</td>
                      <td>{hc.status}</td>
                      <td>{hc.ok ? "Yes" : "No"}</td>
                      <td>{hc.error || ""}</td>
                    </tr>
                  );
                }
              })}
          </tbody>
        </table>
      </div>
    );
  };

  /*****************************************
   * MAIN RETURN
   *****************************************/
  return (
    <div className="cracked-admin-dashboard">
      <div className="cracked-admin-dashboard-container">
        <h1 className="admin-dashboard-title">Admin Dashboard</h1>

        {/* Tabs */}
        <div className="admin-tabs">
          <button
            className={activeTab === "overview" ? "active" : ""}
            onClick={() => switchTab("overview")}
          >
            Overview
          </button>
          <button
            className={activeTab === "users" ? "active" : ""}
            onClick={() => switchTab("users")}
          >
            Users
          </button>
          <button
            className={activeTab === "tests" ? "active" : ""}
            onClick={() => switchTab("tests")}
          >
            Tests
          </button>
          <button
            className={activeTab === "daily" ? "active" : ""}
            onClick={() => switchTab("daily")}
          >
            Daily PBQs
          </button>
          <button
            className={activeTab === "support" ? "active" : ""}
            onClick={() => switchTab("support")}
          >
            Support
          </button>
          <button
            className={activeTab === "performance" ? "active" : ""}
            onClick={() => switchTab("performance")}
          >
            Performance
          </button>
          <button
            className={activeTab === "activity" ? "active" : ""}
            onClick={() => switchTab("activity")}
          >
            Activity
          </button>
          <button
            className={activeTab === "dbLogs" ? "active" : ""}
            onClick={() => switchTab("dbLogs")}
          >
            DB Logs
          </button>
          <button
            className={activeTab === "dbShell" ? "active" : ""}
            onClick={() => switchTab("dbShell")}
          >
            DB Shell
          </button>
          <button
            className={activeTab === "healthChecks" ? "active" : ""}
            onClick={() => switchTab("healthChecks")}
          >
            Health Checks
          </button>
        </div>

        {/* Tabs' Content */}
        {activeTab === "overview" && renderOverviewTab()}
        {activeTab === "users" && renderUsersTab()}
        {activeTab === "tests" && renderTestsTab()}
        {activeTab === "daily" && renderDailyTab()}
        {activeTab === "support" && renderSupportTab()}
        {activeTab === "performance" && renderPerformanceTab()}
        {activeTab === "activity" && renderActivityLogsTab()}
        {activeTab === "dbLogs" && renderDbLogsTab()}
        {activeTab === "dbShell" && renderDbShellTab()}
        {activeTab === "healthChecks" && renderHealthChecksTab()}
      </div>
    </div>
  );
}

export default CrackedAdminDashboard;
