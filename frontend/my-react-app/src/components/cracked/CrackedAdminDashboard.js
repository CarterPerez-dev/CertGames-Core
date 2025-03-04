import React, { useState, useEffect, useCallback, useRef } from "react";
import { io } from "socket.io-client";
import "./CrackedAdminDashboard.css";
import {
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from "recharts";

// Icons
import {
  FaHome,
  FaUsers,
  FaClipboardList,
  FaCalendarDay,
  FaHeadset,
  FaChartLine,
  FaHistory,
  FaDatabase,
  FaTerminal,
  FaHeartbeat,
  FaEnvelope,
  FaChevronRight,
  FaChevronDown,
  FaBell,
  FaSync,
  FaSearch,
  FaUserEdit,
  FaTrash,
  FaKey,
  FaPlus,
  FaTimes,
  FaSave,
  FaCheck,
  FaCommentDots,
  FaInfoCircle,
  FaExclamationTriangle,
  FaSpinner,
  FaSignOutAlt,
  FaPaperPlane,
  FaCheckCircle,
  FaBars,
} from "react-icons/fa";

// We keep this as a top-level variable
let adminSocket = null;

function CrackedAdminDashboard() {
  const [activeTab, setActiveTab] = useState("overview");
  const [isNavCollapsed, setIsNavCollapsed] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const chatEndRef = useRef(null);

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

  // Auto-refresh performance data every 15 seconds to have "real-time" feeling.
  useEffect(() => {
    if (activeTab === "performance") {
      fetchPerformance();
      const interval = setInterval(fetchPerformance, 15000); // 15s refresh
      return () => clearInterval(interval);
    }
  }, [activeTab, fetchPerformance]);

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
        credentials: "include",
        headers: { "Content-Type": "application/json" }
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

      // Join all threads so we get real-time updates
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

      // Admin sees newly created threads in real-time
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

      // Scroll to bottom of chat after a short delay to ensure render
      setTimeout(() => {
        if (chatEndRef.current) {
          chatEndRef.current.scrollIntoView({ behavior: "smooth" });
        }
      }, 100);
    } catch (err) {
      console.error("View thread error:", err);
    }
  };

  const handleReplyToThread = async () => {
    if (!currentThread || !currentThread._id || adminReply.trim() === "") return;
    try {
      const replyMessage = {
        sender: "admin",
        content: adminReply,
        timestamp: new Date().toISOString()
      };

      if (adminSocket) {
        adminSocket.emit("admin_stop_typing", {
          threadId: currentThread._id
        });
      }

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

      // Update the local thread data directly
      setCurrentThread((prevThread) => {
        if (!prevThread) return null;
        return {
          ...prevThread,
          messages: [...prevThread.messages, replyMessage]
        };
      });

      // Update allThreadMap as well
      setAllThreadMap((prev) => {
        const oldThread = prev[currentThread._id] || { messages: [] };
        return {
          ...prev,
          [currentThread._id]: {
            ...oldThread,
            messages: [...oldThread.messages, replyMessage]
          }
        };
      });

      setAdminReply("");
      
      // Scroll to bottom of chat
      setTimeout(() => {
        if (chatEndRef.current) {
          chatEndRef.current.scrollIntoView({ behavior: "smooth" });
        }
      }, 100);
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
  const [activityLoading, setActivityLoading] = useState(false);
  const [activityError, setActivityError] = useState(null);
  
  const fetchActivityLogs = useCallback(async () => {
    setActivityLoading(true);
    setActivityError(null);
    try {
      const res = await fetch("/api/cracked/activity-logs", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch activity logs");
      }
      if (data.logs) {
        setActivityLogs(data.logs);
      }
    } catch (err) {
      setActivityError(err.message);
    } finally {
      setActivityLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "activity") {
      fetchActivityLogs();
    }
  }, [activeTab, fetchActivityLogs]);

  /*****************************************
   * DB LOGS
   *****************************************/
  const [dbLogs, setDbLogs] = useState([]);
  const [dbLogsLoading, setDbLogsLoading] = useState(false);
  const [dbLogsError, setDbLogsError] = useState(null);
  
  const fetchDbLogs = useCallback(async () => {
    setDbLogsLoading(true);
    setDbLogsError(null);
    try {
      const res = await fetch("/api/cracked/db-logs", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch DB logs");
      }
      setDbLogs(data);
    } catch (err) {
      setDbLogsError(err.message);
    } finally {
      setDbLogsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "dbLogs") {
      fetchDbLogs();
    }
  }, [activeTab, fetchDbLogs]);

  /*****************************************
   * DB SHELL
   *****************************************/
  const [dbShellCollection, setDbShellCollection] = useState("");
  const [dbShellFilter, setDbShellFilter] = useState("{}");
  const [dbShellLimit, setDbShellLimit] = useState(5);
  const [dbShellResults, setDbShellResults] = useState([]);
  const [dbShellLoading, setDbShellLoading] = useState(false);
  const [dbShellError, setDbShellError] = useState(null);

  const handleDbShellRead = async () => {
    setDbShellLoading(true);
    setDbShellError(null);
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
      if (!res.ok) {
        throw new Error(data.error || "Failed to read database");
      }
      if (Array.isArray(data)) {
        setDbShellResults(data);
      } else {
        setDbShellError(data.error || "Error reading DB");
      }
    } catch (err) {
      setDbShellError(err.message || "JSON filter is invalid or error occurred");
    } finally {
      setDbShellLoading(false);
    }
  };

  /*****************************************
   * HEALTH CHECKS
   *****************************************/
  const [healthChecks, setHealthChecks] = useState([]);
  const [healthLoading, setHealthLoading] = useState(false);
  const [healthError, setHealthError] = useState(null);
  
  const fetchHealthChecks = useCallback(async () => {
    setHealthLoading(true);
    setHealthError(null);
    try {
      const res = await fetch("/api/cracked/health-checks", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch health checks");
      }
      if (Array.isArray(data)) {
        setHealthChecks(data);
      } else if (data.results) {
        setHealthChecks(data.results);
      }
    } catch (err) {
      setHealthError(err.message);
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "healthChecks") {
      fetchHealthChecks();
    }
  }, [activeTab, fetchHealthChecks]);

  /*****************************************
   * NEWSLETTER
   *****************************************/
  const [subscribers, setSubscribers] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [newsletterLoading, setNewsletterLoading] = useState(false);
  const [newsletterError, setNewsletterError] = useState(null);
  const [activeNewsletterTab, setActiveNewsletterTab] = useState("subscribers");
  
  // New campaign form
  const [newCampaign, setNewCampaign] = useState({
    title: "",
    contentHtml: ""
  });
  
  // Current campaign being viewed/edited
  const [currentCampaign, setCurrentCampaign] = useState(null);

  const fetchSubscribers = async () => {
    setNewsletterLoading(true);
    setNewsletterError(null);
    try {
      // This is a placeholder - you'll need to implement this API endpoint
      const res = await fetch("/api/cracked/newsletter/subscribers", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch subscribers");
      }
      setSubscribers(data.subscribers || []);
    } catch (err) {
      setNewsletterError(err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  const fetchCampaigns = async () => {
    setNewsletterLoading(true);
    setNewsletterError(null);
    try {
      // This is a placeholder - you'll need to implement this API endpoint
      const res = await fetch("/api/cracked/newsletter/campaigns", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch campaigns");
      }
      setCampaigns(data.campaigns || []);
    } catch (err) {
      setNewsletterError(err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === "newsletter") {
      if (activeNewsletterTab === "subscribers") {
        fetchSubscribers();
      } else if (activeNewsletterTab === "campaigns") {
        fetchCampaigns();
      }
    }
  }, [activeTab, activeNewsletterTab]);

  const handleCreateCampaign = async () => {
    if (!newCampaign.title || !newCampaign.contentHtml) {
      alert("Please provide both title and content");
      return;
    }
    
    setNewsletterLoading(true);
    try {
      const res = await fetch("/api/cracked/newsletter/create", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newCampaign)
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to create campaign");
      }
      alert("Newsletter campaign created successfully!");
      setNewCampaign({ title: "", contentHtml: "" });
      fetchCampaigns();
    } catch (err) {
      setNewsletterError(err.message);
      alert("Error creating campaign: " + err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  const handleViewCampaign = async (campaignId) => {
    setNewsletterLoading(true);
    try {
      const res = await fetch(`/api/cracked/newsletter/${campaignId}`, { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch campaign");
      }
      setCurrentCampaign(data);
    } catch (err) {
      setNewsletterError(err.message);
      alert("Error viewing campaign: " + err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  const handleSendCampaign = async (campaignId) => {
    if (!window.confirm("Are you sure you want to send this newsletter to all subscribers?")) {
      return;
    }
    
    setNewsletterLoading(true);
    try {
      const res = await fetch(`/api/cracked/newsletter/send/${campaignId}`, {
        method: "POST",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to send campaign");
      }
      alert(`Newsletter sent to ${data.recipientsCount} recipients!`);
      fetchCampaigns();
    } catch (err) {
      setNewsletterError(err.message);
      alert("Error sending campaign: " + err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  /*****************************************
   * TAB SWITCH
   *****************************************/
  const switchTab = (tabName) => {
    setActiveTab(tabName);
    setMobileNavOpen(false);
  };

  /*****************************************
   * LOGOUT 
   *****************************************/
  const handleLogout = async () => {
    try {
      await fetch("/api/cracked/logout", {
        method: "POST",
        credentials: "include"
      });
      window.location.href = "/cracked/login";
    } catch (err) {
      console.error("Logout error:", err);
    }
  };

  /*****************************************
   * HELPER FUNCTIONS
   *****************************************/
  // Format time in a user-friendly way
  const formatTime = (timestamp) => {
    if (!timestamp) return "";
    
    try {
      const date = new Date(timestamp);
      return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      }).format(date);
    } catch (e) {
      return timestamp;
    }
  };

  // For rendering message content
  const renderMessageContent = (content) => {
    // Add URLs as clickable links
    return content.replace(
      /(https?:\/\/[^\s]+)/g, 
      '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>'
    );
  };

  /*****************************************
   * RENDER: OVERVIEW
   *****************************************/
  const renderOverviewTab = () => {
    const COLORS = ['#6543cc', '#ff4c8b', '#2ecc71', '#3498db', '#e67e22'];

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

  /*****************************************
   * RENDER: PERFORMANCE
   *****************************************/
  const renderPerformanceTab = () => {
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
                  <FaDatabase />
                </div>
                <div className="admin-stat-content">
                  <h3>DB Query Time</h3>
                  <div className="admin-stat-value">{performanceData.avg_db_query_time_ms}ms</div>
                </div>
              </div>

              <div className="admin-stat-card">
                <div className="admin-stat-icon transfer-icon">
                  <FaDatabase />
                </div>
                <div className="admin-stat-content">
                  <h3>Data Transfer</h3>
                  <div className="admin-stat-value">{performanceData.data_transfer_rate}</div>
                </div>
              </div>

              <div className="admin-stat-card">
                <div className="admin-stat-icon throughput-icon">
                  <FaDatabase />
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

  /*****************************************
   * RENDER: USERS
   *****************************************/
  const renderUsersTab = () => {
    return (
      <div className="admin-tab-content users-tab">
        <div className="admin-content-header">
          <h2><FaUsers /> User Management</h2>
          <div className="admin-search-row">
            <div className="admin-search-box">
              <FaSearch />
              <input
                type="text"
                placeholder="Search by username or email"
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
              />
            </div>
            <button className="admin-search-btn" onClick={() => { setUserPage(1); fetchUsers(); }}>
              Search
            </button>
          </div>
        </div>

        <div className="admin-pagination">
          <span>Page: {userPage} / {Math.ceil(userTotal / userLimit)} (Total: {userTotal})</span>
          <div className="admin-pagination-controls">
            <button 
              disabled={userPage <= 1} 
              onClick={() => setUserPage((prev) => Math.max(1, prev - 1))}
              className="admin-pagination-btn"
            >
              Previous
            </button>
            <button 
              disabled={userPage >= Math.ceil(userTotal / userLimit)} 
              onClick={() => setUserPage((prev) => prev + 1)}
              className="admin-pagination-btn"
            >
              Next
            </button>
          </div>
        </div>

        {usersLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading users...</p>
          </div>
        )}

        {usersError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {usersError}
          </div>
        )}

        <div className="admin-data-table-container">
          <table className="admin-data-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Coins</th>
                <th>XP</th>
                <th>Level</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isEditing = editUserId === u._id;
                return (
                  <tr key={u._id} className={isEditing ? "editing-row" : ""}>
                    <td>
                      {isEditing ? (
                        <input
                          type="text"
                          value={editUserData.username}
                          onChange={(e) => handleUpdateUserField("username", e.target.value)}
                          className="admin-edit-input"
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
                          className="admin-edit-input"
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
                          className="admin-edit-input"
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
                          className="admin-edit-input"
                        />
                      ) : (
                        u.level
                      )}
                    </td>
                    <td>
                      {isEditing ? (
                        <div className="admin-checkbox-wrap">
                          <label>
                            Suspended:
                            <input
                              type="checkbox"
                              checked={!!editUserData.suspended}
                              onChange={(e) => handleUpdateUserField("suspended", e.target.checked)}
                            />
                          </label>
                        </div>
                      ) : (
                        <span className={u.suspended ? "status-suspended" : "status-active"}>
                          {u.suspended ? "Suspended" : "Active"}
                        </span>
                      )}
                    </td>
                    <td>
                      {isEditing ? (
                        <div className="admin-action-buttons">
                          <button 
                            onClick={handleUserUpdateSubmit}
                            className="admin-btn save-btn"
                            title="Save changes"
                          >
                            <FaSave />
                          </button>
                          <button 
                            onClick={() => setEditUserId(null)}
                            className="admin-btn cancel-btn"
                            title="Cancel"
                          >
                            <FaTimes />
                          </button>
                        </div>
                      ) : (
                        <div className="admin-action-buttons">
                          <button 
                            onClick={() => handleUserEdit(u)}
                            className="admin-btn edit-btn"
                            title="Edit user"
                          >
                            <FaUserEdit />
                          </button>
                          <button 
                            onClick={() => handleResetPassword(u._id)}
                            className="admin-btn reset-btn"
                            title="Reset password"
                          >
                            <FaKey />
                          </button>
                          <button 
                            onClick={() => handleUserDelete(u._id)}
                            className="admin-btn delete-btn"
                            title="Delete user"
                          >
                            <FaTrash />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: TESTS
   *****************************************/
  const renderTestsTab = () => {
    return (
      <div className="admin-tab-content tests-tab">
        <div className="admin-content-header">
          <h2><FaClipboardList /> Test Management</h2>
          <div className="admin-filter-row">
            <input
              type="text"
              placeholder="Filter by category (e.g. aplus)"
              value={testCategory}
              onChange={(e) => setTestCategory(e.target.value)}
              className="admin-filter-input"
            />
            <button className="admin-filter-btn" onClick={fetchTests}>
              <FaSearch /> Filter
            </button>
          </div>
        </div>

        <div className="admin-card">
          <h3><FaPlus /> Create New Test</h3>
          <div className="admin-form-grid">
            <div className="admin-form-group">
              <label>Category:</label>
              <input
                type="text"
                value={newTestData.category}
                onChange={(e) => setNewTestData((prev) => ({ ...prev, category: e.target.value }))}
                placeholder="e.g. aplus"
              />
            </div>
            <div className="admin-form-group">
              <label>Test ID:</label>
              <input
                type="text"
                value={newTestData.testId}
                onChange={(e) => setNewTestData((prev) => ({ ...prev, testId: e.target.value }))}
                placeholder="Numeric test ID"
              />
            </div>
            <div className="admin-form-group">
              <label>Test Name:</label>
              <input
                type="text"
                value={newTestData.testName}
                onChange={(e) => setNewTestData((prev) => ({ ...prev, testName: e.target.value }))}
                placeholder="Test name"
              />
            </div>
          </div>
          <div className="admin-form-actions">
            <button className="admin-submit-btn" onClick={handleCreateTest}>
              Create Test
            </button>
          </div>
        </div>

        {testsLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading tests...</p>
          </div>
        )}

        {testsError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {testsError}
          </div>
        )}

        <div className="admin-data-table-container">
          <table className="admin-data-table">
            <thead>
              <tr>
                <th>Category</th>
                <th>Test ID</th>
                <th>Test Name</th>
                <th>Questions</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tests.map((t) => (
                <tr key={t._id}>
                  <td>{t.category}</td>
                  <td>{t.testId}</td>
                  <td>{t.testName || "(Unnamed)"}</td>
                  <td>{t.questions ? t.questions.length : 0}</td>
                  <td>
                    <div className="admin-action-buttons">
                      <button 
                        onClick={() => handleDeleteTest(t)}
                        className="admin-btn delete-btn"
                        title="Delete test"
                      >
                        <FaTrash />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: DAILY
   *****************************************/
  const renderDailyTab = () => {
    return (
      <div className="admin-tab-content daily-tab">
        <div className="admin-content-header">
          <h2><FaCalendarDay /> Daily PBQ Management</h2>
          <button className="admin-refresh-btn" onClick={fetchDailyPBQs}>
            <FaSync /> Refresh
          </button>
        </div>

        <div className="admin-card">
          <h3><FaPlus /> Create New Daily PBQ</h3>
          <div className="admin-form-grid">
            <div className="admin-form-group">
              <label>Prompt:</label>
              <input
                type="text"
                value={newDaily.prompt}
                onChange={(e) => setNewDaily((prev) => ({ ...prev, prompt: e.target.value }))}
                placeholder="Question prompt"
              />
            </div>
            <div className="admin-form-group">
              <label>Day Index:</label>
              <input
                type="text"
                value={newDaily.dayIndex}
                onChange={(e) => setNewDaily((prev) => ({ ...prev, dayIndex: e.target.value }))}
                placeholder="Numeric day index"
              />
            </div>
            <div className="admin-form-group">
              <label>Correct Index:</label>
              <input
                type="text"
                value={newDaily.correctIndex}
                onChange={(e) => setNewDaily((prev) => ({ ...prev, correctIndex: e.target.value }))}
                placeholder="Correct answer index"
              />
            </div>
          </div>
          <div className="admin-form-group full-width">
            <label>Explanation:</label>
            <textarea
              value={newDaily.explanation}
              onChange={(e) => setNewDaily((prev) => ({ ...prev, explanation: e.target.value }))}
              placeholder="Explanation for the correct answer"
              rows={4}
            ></textarea>
          </div>
          <div className="admin-form-actions">
            <button className="admin-submit-btn" onClick={handleCreateDaily}>
              Create Daily PBQ
            </button>
          </div>
        </div>

        {dailyLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading daily PBQs...</p>
          </div>
        )}

        {dailyError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {dailyError}
          </div>
        )}

        <div className="admin-data-table-container">
          <table className="admin-data-table">
            <thead>
              <tr>
                <th>Prompt</th>
                <th>Day Index</th>
                <th>Correct Index</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {dailyList.map((d) => (
                <tr key={d._id}>
                  <td>{d.prompt}</td>
                  <td>{d.dayIndex}</td>
                  <td>{d.correctIndex}</td>
                  <td>
                    <div className="admin-action-buttons">
                      <button 
                        onClick={() => handleDeleteDaily(d)}
                        className="admin-btn delete-btn"
                        title="Delete PBQ"
                      >
                        <FaTrash />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: SUPPORT
   *****************************************/
  const renderSupportTab = () => {
    return (
      <div className="admin-tab-content support-tab">
        <div className="admin-content-header">
          <h2><FaHeadset /> Support Management</h2>
          <div className="admin-filter-row">
            <input
              type="text"
              placeholder="Filter by status (open/closed)"
              value={threadStatusFilter}
              onChange={(e) => setThreadStatusFilter(e.target.value)}
              className="admin-filter-input"
            />
            <button className="admin-filter-btn" onClick={fetchThreads}>
              <FaSearch /> Filter
            </button>
          </div>
        </div>

        {threadsLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading support threads...</p>
          </div>
        )}

        {threadsError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {threadsError}
          </div>
        )}

        <div className="admin-support-container">
          <div className="admin-threads-panel">
            <h3>Support Threads</h3>
            <div className="admin-threads-list">
              {threads.length > 0 ? (
                threads.map((th) => (
                  <div 
                    key={th._id} 
                    className={`admin-thread-item ${th.status === 'closed' ? 'thread-closed' : ''} ${currentThread && currentThread._id === th._id ? 'active-thread' : ''}`}
                    onClick={() => handleViewThread(th._id)}
                  >
                    <div className="admin-thread-info">
                      <div className="admin-thread-subject">{th.subject || "Untitled Thread"}</div>
                      <div className="admin-thread-meta">
                        <span className={`admin-thread-status status-${th.status}`}>
                          {th.status}
                        </span>
                        <span className="admin-thread-date">
                          {formatTime(th.updatedAt)}
                        </span>
                      </div>
                    </div>
                    <div className="admin-thread-actions">
                      {th.status !== "closed" && (
                        <button 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCloseThread(th._id);
                          }}
                          className="admin-btn close-btn"
                          title="Close thread"
                        >
                          <FaTimes />
                        </button>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div className="admin-no-threads">No threads found matching your criteria</div>
              )}
            </div>
            
            <div className="admin-thread-actions-footer">
              <button 
                className="admin-danger-btn" 
                onClick={handleClearClosedThreads}
              >
                <FaTrash /> Clear All Closed Threads
              </button>
            </div>
          </div>

          <div className="admin-chat-panel">
            {currentThread ? (
              <>
                <div className="admin-chat-header">
                  <h3>{currentThread.subject || "Untitled Thread"}</h3>
                  <div className="admin-chat-meta">
                    <span className={`admin-thread-status status-${currentThread.status}`}>
                      {currentThread.status}
                    </span>
                    <span className="admin-thread-date">
                      Created: {formatTime(currentThread.createdAt)}
                    </span>
                  </div>
                </div>

                <div className="admin-chat-messages">
                  {currentThread.messages.length > 0 ? (
                    currentThread.messages.map((msg, idx) => (
                      <div 
                        key={idx} 
                        className={`admin-chat-message ${msg.sender === 'admin' ? 'admin-message' : msg.sender === 'system' ? 'system-message' : 'user-message'}`}
                      >
                        <div className="admin-message-sender">
                          {msg.sender === 'admin' ? 'Admin' : 
                           msg.sender === 'system' ? 'System' : 'User'}
                        </div>
                        <div 
                          className="admin-message-content"
                          dangerouslySetInnerHTML={{ __html: renderMessageContent(msg.content) }}
                        ></div>
                        <div className="admin-message-time">
                          {formatTime(msg.timestamp)}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="admin-empty-chat">No messages yet in this thread</div>
                  )}
                  {userIsTyping && (
                    <div className="admin-typing-indicator">
                      User is typing...
                    </div>
                  )}
                  <div ref={chatEndRef}></div>
                </div>

                {currentThread.status !== "closed" && (
                  <div className="admin-chat-input">
                    <textarea
                      rows={3}
                      placeholder="Type your reply here..."
                      value={adminReply}
                      onChange={(e) => {
                        setAdminReply(e.target.value);
                        handleAdminReplyTyping(currentThread._id);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault();
                          handleReplyToThread();
                        }
                      }}
                    ></textarea>
                    <button 
                      onClick={handleReplyToThread}
                      disabled={adminReply.trim() === ''}
                      className="admin-send-btn"
                    >
                      <FaPaperPlane />
                    </button>
                  </div>
                )}
              </>
            ) : (
              <div className="admin-no-thread-selected">
                <FaCommentDots className="admin-no-thread-icon" />
                <p>Select a thread to view the conversation</p>
              </div>
            )}
          </div>
        </div>

        <div className="admin-card create-thread-card">
          <h3><FaPlus /> Create Thread for User</h3>
          <div className="admin-form-grid">
            <div className="admin-form-group">
              <label>User ID:</label>
              <input
                type="text"
                value={adminTargetUserId}
                onChange={(e) => setAdminTargetUserId(e.target.value)}
                placeholder="Target user ID"
              />
            </div>
            <div className="admin-form-group">
              <label>Initial Message:</label>
              <input
                type="text"
                value={adminInitialMsg}
                onChange={(e) => setAdminInitialMsg(e.target.value)}
                placeholder="Initial message (optional)"
              />
            </div>
          </div>
          <div className="admin-form-actions">
            <button className="admin-submit-btn" onClick={handleAdminCreateThread}>
              Create Thread
            </button>
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
      <div className="admin-tab-content activity-tab">
        <div className="admin-content-header">
          <h2><FaHistory /> Activity & Audit Logs</h2>
          <button className="admin-refresh-btn" onClick={fetchActivityLogs}>
            <FaSync /> Refresh Logs
          </button>
        </div>

        {activityLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading activity logs...</p>
          </div>
        )}

        {activityError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {activityError}
          </div>
        )}

        <div className="admin-data-table-container">
          <table className="admin-data-table">
            <thead>
              <tr>
                <th>Timestamp (EST)</th>
                <th>IP</th>
                <th>User ID</th>
                <th>Success</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {activityLogs.map((log) => (
                <tr key={log._id} className={log.success ? "" : "error-row"}>
                  <td>{log.timestamp}</td>
                  <td>{log.ip}</td>
                  <td>{log.userId || ""}</td>
                  <td>
                    <span className={log.success ? "status-success" : "status-error"}>
                      {log.success ? "Yes" : "No"}
                    </span>
                  </td>
                  <td>{log.reason || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: DB LOGS
   *****************************************/
  const renderDbLogsTab = () => {
    return (
      <div className="admin-tab-content db-logs-tab">
        <div className="admin-content-header">
          <h2><FaDatabase /> Database Query Logs</h2>
          <button className="admin-refresh-btn" onClick={fetchDbLogs}>
            <FaSync /> Refresh Logs
          </button>
        </div>

        {dbLogsLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading database logs...</p>
          </div>
        )}

        {dbLogsError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {dbLogsError}
          </div>
        )}

        <div className="admin-data-table-container">
          <table className="admin-data-table">
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
              {dbLogs.map((log, index) => (
                <tr key={log._id || index} className={log.http_status >= 400 ? "error-row" : ""}>
                  <td>{log.timestamp}</td>
                  <td>{log.route}</td>
                  <td>{log.method}</td>
                  <td>{log.duration_ms}</td>
                  <td>{log.db_time_ms}</td>
                  <td>
                    <span className={log.http_status >= 400 ? "status-error" : "status-success"}>
                      {log.http_status}
                    </span>
                  </td>
                  <td>{log.response_bytes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: DB SHELL
   *****************************************/
  const renderDbShellTab = () => {
    return (
      <div className="admin-tab-content db-shell-tab">
        <div className="admin-content-header">
          <h2><FaTerminal /> Database Shell</h2>
        </div>

        <div className="admin-card">
          <h3><FaDatabase /> Read-Only Database Query</h3>
          <div className="admin-form-grid">
            <div className="admin-form-group">
              <label>Collection:</label>
              <input
                type="text"
                value={dbShellCollection}
                onChange={(e) => setDbShellCollection(e.target.value)}
                placeholder="Collection name"
              />
            </div>
            <div className="admin-form-group">
              <label>Filter (JSON):</label>
              <input
                type="text"
                value={dbShellFilter}
                onChange={(e) => setDbShellFilter(e.target.value)}
                placeholder='e.g. {"username": "test"}'
              />
            </div>
            <div className="admin-form-group">
              <label>Limit:</label>
              <input
                type="number"
                value={dbShellLimit}
                onChange={(e) => setDbShellLimit(e.target.valueAsNumber)}
                min={1}
                max={100}
              />
            </div>
          </div>
          <div className="admin-form-actions">
            <button 
              className="admin-submit-btn" 
              onClick={handleDbShellRead}
              disabled={dbShellLoading}
            >
              {dbShellLoading ? (
                <><FaSpinner className="admin-spinner" /> Executing...</>
              ) : (
                <>Execute Query</>
              )}
            </button>
          </div>
        </div>

        {dbShellError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {dbShellError}
          </div>
        )}

        <div className="admin-shell-results">
          <h3>Query Results</h3>
          <pre>{JSON.stringify(dbShellResults, null, 2)}</pre>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: HEALTH CHECKS
   *****************************************/
  const renderHealthChecksTab = () => {
    return (
      <div className="admin-tab-content health-checks-tab">
        <div className="admin-content-header">
          <h2><FaHeartbeat /> API Health Monitoring</h2>
          <button className="admin-refresh-btn" onClick={fetchHealthChecks}>
            <FaSync /> Refresh Health Checks
          </button>
        </div>

        {healthLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading health checks...</p>
          </div>
        )}

        {healthError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {healthError}
          </div>
        )}

        <div className="admin-stats-grid">
          <div className="admin-stat-card">
            <div className="admin-stat-icon health-icon">
              <FaHeartbeat />
            </div>
            <div className="admin-stat-content">
              <h3>API Status</h3>
              <div className="admin-stat-value status-success">Operational</div>
            </div>
          </div>

          <div className="admin-stat-card">
            <div className="admin-stat-icon db-icon">
              <FaDatabase />
            </div>
            <div className="admin-stat-content">
              <h3>Database</h3>
              <div className="admin-stat-value status-success">Connected</div>
            </div>
          </div>

          <div className="admin-stat-card">
            <div className="admin-stat-icon endpoints-icon">
              <FaCheckCircle />
            </div>
            <div className="admin-stat-content">
              <h3>Endpoints</h3>
              <div className="admin-stat-value">{healthChecks.length || 0} Monitored</div>
            </div>
          </div>

          <div className="admin-stat-card">
            <div className="admin-stat-icon time-icon">
              <FaHistory />
            </div>
            <div className="admin-stat-content">
              <h3>Last Check</h3>
              <div className="admin-stat-value">
                {healthChecks.length > 0 && healthChecks[0].checkedAt ? 
                  formatTime(healthChecks[0].checkedAt) : 
                  "No data"
                }
              </div>
            </div>
          </div>
        </div>

        <div className="admin-data-table-container">
          <table className="admin-data-table">
            <thead>
              <tr>
                <th>Checked At (EST)</th>
                <th>Endpoint</th>
                <th>Status</th>
                <th>OK</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {Array.isArray(healthChecks) && healthChecks.map((hc, idx) => {
                if (hc.results) {
                  // multi results block
                  return hc.results.map((r, j) => (
                    <tr key={`${hc._id}_${j}`} className={r.ok ? "" : "error-row"}>
                      <td>{hc.checkedAt}</td>
                      <td>{r.endpoint}</td>
                      <td>{r.status}</td>
                      <td>
                        <span className={r.ok ? "status-success" : "status-error"}>
                          {r.ok ? "Yes" : "No"}
                        </span>
                      </td>
                      <td>{r.error || ""}</td>
                    </tr>
                  ));
                } else {
                  // single item doc
                  return (
                    <tr key={idx} className={hc.ok ? "" : "error-row"}>
                      <td>{hc.checkedAt}</td>
                      <td>{hc.endpoint}</td>
                      <td>{hc.status}</td>
                      <td>
                        <span className={hc.ok ? "status-success" : "status-error"}>
                          {hc.ok ? "Yes" : "No"}
                        </span>
                      </td>
                      <td>{hc.error || ""}</td>
                    </tr>
                  );
                }
              })}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  /*****************************************
   * RENDER: NEWSLETTER
   *****************************************/
  const renderNewsletterTab = () => {
    return (
      <div className="admin-tab-content newsletter-tab">
        <div className="admin-content-header">
          <h2><FaEnvelope /> Newsletter Management</h2>
        </div>

        <div className="admin-newsletter-tabs">
          <button 
            className={activeNewsletterTab === "subscribers" ? "active" : ""}
            onClick={() => setActiveNewsletterTab("subscribers")}
          >
            Subscribers
          </button>
          <button 
            className={activeNewsletterTab === "campaigns" ? "active" : ""}
            onClick={() => setActiveNewsletterTab("campaigns")}
          >
            Campaigns
          </button>
          <button 
            className={activeNewsletterTab === "create" ? "active" : ""}
            onClick={() => setActiveNewsletterTab("create")}
          >
            Create New
          </button>
        </div>

        {newsletterLoading && (
          <div className="admin-loading">
            <FaSpinner className="admin-spinner" />
            <p>Loading newsletter data...</p>
          </div>
        )}

        {newsletterError && (
          <div className="admin-error-message">
            <FaExclamationTriangle /> Error: {newsletterError}
          </div>
        )}

        {/* Subscribers Tab */}
        {activeNewsletterTab === "subscribers" && (
          <div className="admin-newsletter-content">
            <div className="admin-card">
              <h3><FaUsers /> Email Subscribers</h3>
              <button className="admin-refresh-btn" onClick={fetchSubscribers}>
                <FaSync /> Refresh List
              </button>

              {subscribers.length > 0 ? (
                <div className="admin-data-table-container">
                  <table className="admin-data-table">
                    <thead>
                      <tr>
                        <th>Email</th>
                        <th>Subscribed At</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {subscribers.map((sub, index) => (
                        <tr key={sub._id || index}>
                          <td>{sub.email}</td>
                          <td>{formatTime(sub.subscribedAt)}</td>
                          <td>
                            <span className={sub.unsubscribed ? "status-inactive" : "status-active"}>
                              {sub.unsubscribed ? "Unsubscribed" : "Active"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="admin-no-data">
                  <p>No subscribers found. You can refresh the list or check back later.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Campaigns Tab */}
        {activeNewsletterTab === "campaigns" && (
          <div className="admin-newsletter-content">
            <div className="admin-card">
              <h3><FaEnvelope /> Newsletter Campaigns</h3>
              <button className="admin-refresh-btn" onClick={fetchCampaigns}>
                <FaSync /> Refresh List
              </button>

              {campaigns.length > 0 ? (
                <div className="admin-data-table-container">
                  <table className="admin-data-table">
                    <thead>
                      <tr>
                        <th>Title</th>
                        <th>Created At</th>
                        <th>Status</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {campaigns.map((campaign, index) => (
                        <tr key={campaign._id || index}>
                          <td>{campaign.title}</td>
                          <td>{formatTime(campaign.createdAt)}</td>
                          <td>
                            <span className={campaign.status === "sent" ? "status-success" : "status-waiting"}>
                              {campaign.status}
                            </span>
                          </td>
                          <td>
                            <div className="admin-action-buttons">
                              <button 
                                onClick={() => handleViewCampaign(campaign._id)}
                                className="admin-btn view-btn"
                                title="View campaign"
                              >
                                <FaInfoCircle />
                              </button>
                              {campaign.status !== "sent" && (
                                <button 
                                  onClick={() => handleSendCampaign(campaign._id)}
                                  className="admin-btn send-btn"
                                  title="Send campaign"
                                >
                                  <FaPaperPlane />
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="admin-no-data">
                  <p>No campaigns found. You can create a new campaign from the "Create New" tab.</p>
                </div>
              )}
            </div>

            {currentCampaign && (
              <div className="admin-card">
                <div className="admin-card-header">
                  <h3>{currentCampaign.title}</h3>
                  <button 
                    className="admin-close-btn"
                    onClick={() => setCurrentCampaign(null)}
                  >
                    <FaTimes />
                  </button>
                </div>
                <div className="admin-campaign-details">
                  <div className="admin-campaign-meta">
                    <div><strong>Created:</strong> {formatTime(currentCampaign.createdAt)}</div>
                    <div><strong>Status:</strong> {currentCampaign.status}</div>
                    {currentCampaign.sentAt && (
                      <div><strong>Sent At:</strong> {formatTime(currentCampaign.sentAt)}</div>
                    )}
                  </div>
                  <div className="admin-campaign-preview">
                    <h4>HTML Content Preview:</h4>
                    <div className="admin-html-preview">
                      <div dangerouslySetInnerHTML={{ __html: currentCampaign.contentHtml }}></div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Create New Campaign Tab */}
        {activeNewsletterTab === "create" && (
          <div className="admin-newsletter-content">
            <div className="admin-card">
              <h3><FaPlus /> Create New Newsletter Campaign</h3>
              <div className="admin-form-group">
                <label>Campaign Title:</label>
                <input
                  type="text"
                  value={newCampaign.title}
                  onChange={(e) => setNewCampaign({ ...newCampaign, title: e.target.value })}
                  placeholder="Enter newsletter title"
                />
              </div>
              <div className="admin-form-group">
                <label>HTML Content:</label>
                <textarea
                  value={newCampaign.contentHtml}
                  onChange={(e) => setNewCampaign({ ...newCampaign, contentHtml: e.target.value })}
                  placeholder="Enter newsletter HTML content"
                  rows={10}
                ></textarea>
              </div>
              <div className="admin-form-actions">
                <button 
                  className="admin-submit-btn" 
                  onClick={handleCreateCampaign}
                  disabled={!newCampaign.title || !newCampaign.contentHtml || newsletterLoading}
                >
                  {newsletterLoading ? (
                    <><FaSpinner className="admin-spinner" /> Creating...</>
                  ) : (
                    <>Create Campaign</>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  /*****************************************
   * MAIN RENDER
   *****************************************/
  return (
    <div className={`admin-dashboard ${isNavCollapsed ? 'nav-collapsed' : ''}`}>
              <div className="admin-sidebar">
        <div className="admin-sidebar-header">
          <div className="admin-logo">
            <FaDatabase />
            <h1>Admin</h1>
          </div>
          <button 
            className="admin-collapse-btn"
            onClick={() => setIsNavCollapsed(!isNavCollapsed)}
            title={isNavCollapsed ? "Expand Navigation" : "Collapse Navigation"}
          >
            {isNavCollapsed ? <FaChevronRight /> : <FaChevronDown />}
          </button>
        </div>
        
        <nav className="admin-nav">
          <ul className="admin-nav-list">
            <li className={activeTab === "overview" ? "active" : ""}>
              <button onClick={() => switchTab("overview")}>
                <FaHome />
                <span>Dashboard</span>
              </button>
            </li>
            <li className={activeTab === "users" ? "active" : ""}>
              <button onClick={() => switchTab("users")}>
                <FaUsers />
                <span>Users</span>
              </button>
            </li>
            <li className={activeTab === "tests" ? "active" : ""}>
              <button onClick={() => switchTab("tests")}>
                <FaClipboardList />
                <span>Tests</span>
              </button>
            </li>
            <li className={activeTab === "daily" ? "active" : ""}>
              <button onClick={() => switchTab("daily")}>
                <FaCalendarDay />
                <span>Daily PBQs</span>
              </button>
            </li>
            <li className={activeTab === "support" ? "active" : ""}>
              <button onClick={() => switchTab("support")}>
                <FaHeadset />
                <span>Support</span>
              </button>
            </li>
            <li className={activeTab === "newsletter" ? "active" : ""}>
              <button onClick={() => switchTab("newsletter")}>
                <FaEnvelope />
                <span>Newsletter</span>
              </button>
            </li>
            <li className={activeTab === "performance" ? "active" : ""}>
              <button onClick={() => switchTab("performance")}>
                <FaChartLine />
                <span>Performance</span>
              </button>
            </li>
            <li className={activeTab === "activity" ? "active" : ""}>
              <button onClick={() => switchTab("activity")}>
                <FaHistory />
                <span>Activity</span>
              </button>
            </li>
            <li className={activeTab === "dbLogs" ? "active" : ""}>
              <button onClick={() => switchTab("dbLogs")}>
                <FaDatabase />
                <span>DB Logs</span>
              </button>
            </li>
            <li className={activeTab === "dbShell" ? "active" : ""}>
              <button onClick={() => switchTab("dbShell")}>
                <FaTerminal />
                <span>DB Shell</span>
              </button>
            </li>
            <li className={activeTab === "healthChecks" ? "active" : ""}>
              <button onClick={() => switchTab("healthChecks")}>
                <FaHeartbeat />
                <span>Health Checks</span>
              </button>
            </li>
          </ul>
        </nav>
        
        <div className="admin-sidebar-footer">
          <button className="admin-logout-btn" onClick={handleLogout}>
            <FaSignOutAlt />
            <span>Logout</span>
          </button>
        </div>
      </div>
      
      {/* Mobile Header with menu toggle */}
      <div className="admin-mobile-header">
        <button 
          className="admin-mobile-menu-toggle"
          onClick={() => setMobileNavOpen(!mobileNavOpen)}
        >
          {mobileNavOpen ? <FaTimes /> : <FaBars />}
        </button>
        <div className="admin-mobile-logo">
          <FaDatabase />
          <h1>Admin Dashboard</h1>
        </div>
      </div>
      
      {/* Mobile Navigation Overlay */}
      <div className={`admin-mobile-nav ${mobileNavOpen ? 'active' : ''}`}>
        <nav>
          <ul>
            <li>
              <button onClick={() => switchTab("overview")}>
                <FaHome /> Dashboard
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("users")}>
                <FaUsers /> Users
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("tests")}>
                <FaClipboardList /> Tests
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("daily")}>
                <FaCalendarDay /> Daily PBQs
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("support")}>
                <FaHeadset /> Support
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("newsletter")}>
                <FaEnvelope /> Newsletter
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("performance")}>
                <FaChartLine /> Performance
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("activity")}>
                <FaHistory /> Activity
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("dbLogs")}>
                <FaDatabase /> DB Logs
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("dbShell")}>
                <FaTerminal /> DB Shell
              </button>
            </li>
            <li>
              <button onClick={() => switchTab("healthChecks")}>
                <FaHeartbeat /> Health Checks
              </button>
            </li>
            <li>
              <button onClick={handleLogout} className="mobile-logout-btn">
                <FaSignOutAlt /> Logout
              </button>
            </li>
          </ul>
        </nav>
      </div>
      
      {/* Main Content Area */}
      <div className="admin-main-content">
        {/* Active Tab Content */}
        {activeTab === "overview" && renderOverviewTab()}
        {activeTab === "users" && renderUsersTab()}
        {activeTab === "tests" && renderTestsTab()}
        {activeTab === "daily" && renderDailyTab()}
        {activeTab === "support" && renderSupportTab()}
        {activeTab === "newsletter" && renderNewsletterTab()}
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
