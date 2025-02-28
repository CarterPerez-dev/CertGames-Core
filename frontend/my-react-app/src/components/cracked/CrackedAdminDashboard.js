import React, { useState, useEffect, useCallback } from "react";
import "./CrackedAdminDashboard.css";

/**
 * This Admin Dashboard has multiple tabs:
 *  1) Overview
 *  2) Users
 *  3) Tests
 *  4) Daily PBQs
 *  5) Support Threads
 *  6) Performance
 * 
 * For each tab, we fetch data from the appropriate /cracked routes:
 *   - /cracked/dashboard       -> "Overview" stats
 *   - /cracked/performance     -> "Performance" metrics
 *   - /cracked/users           -> "Users"
 *   - /cracked/tests           -> "Tests"
 *   - /cracked/daily           -> "Daily PBQs"
 *   - /cracked/supportThreads  -> "Support Threads"
 * 
 * We'll manage local state for each part and implement some of the 
 * create/update/delete flows for each resource (like tests, daily PBQs, etc.).
 * 
 * We also demonstrate a rudimentary "search + pagination" for users, 
 * as your backend route supports "search, page, limit".
 */

function CrackedAdminDashboard() {
  const [activeTab, setActiveTab] = useState("overview");

  /*****************************************
   *  1) OVERVIEW states & fetch
   *****************************************/
  const [overviewData, setOverviewData] = useState(null);
  const [overviewLoading, setOverviewLoading] = useState(false);
  const [overviewError, setOverviewError] = useState(null);

  const fetchOverview = useCallback(async () => {
    setOverviewLoading(true);
    setOverviewError(null);
    try {
      const res = await fetch("/cracked/dashboard", {
        method: "GET",
        credentials: "include",
      });
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
   *  2) PERFORMANCE states & fetch
   *****************************************/
  const [performanceData, setPerformanceData] = useState(null);
  const [perfLoading, setPerfLoading] = useState(false);
  const [perfError, setPerfError] = useState(null);

  const fetchPerformance = useCallback(async () => {
    setPerfLoading(true);
    setPerfError(null);
    try {
      const res = await fetch("/cracked/performance", {
        credentials: "include",
      });
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
   *  3) USERS states & fetch
   *****************************************/
  const [users, setUsers] = useState([]);
  const [userTotal, setUserTotal] = useState(0);
  const [userSearch, setUserSearch] = useState("");
  const [userPage, setUserPage] = useState(1);
  const [userLimit] = useState(10); // or 20, up to you
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState(null);

  const [editUserId, setEditUserId] = useState(null); // For editing
  const [editUserData, setEditUserData] = useState({});

  // fetch user list
  const fetchUsers = useCallback(async () => {
    setUsersLoading(true);
    setUsersError(null);
    try {
      const params = new URLSearchParams({
        search: userSearch,
        page: userPage.toString(),
        limit: userLimit.toString(),
      });
      const res = await fetch(`/cracked/users?${params.toString()}`, {
        credentials: "include",
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
      suspended: !!u.suspended,
    });
  };

  const handleUserUpdateSubmit = async () => {
    if (!editUserId) return;
    try {
      const res = await fetch(`/cracked/users/${editUserId}`, {
        method: "PUT",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(editUserData),
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to update user");
        return;
      }
      alert("User updated!");
      // refetch users
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
      const res = await fetch(`/cracked/users/${userId}`, {
        method: "DELETE",
        credentials: "include",
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

  /*****************************************
   *  4) TEST MANAGEMENT states & fetch
   *****************************************/
  const [tests, setTests] = useState([]);
  const [testCategory, setTestCategory] = useState("");
  const [testsLoading, setTestsLoading] = useState(false);
  const [testsError, setTestsError] = useState(null);

  const fetchTests = useCallback(async () => {
    setTestsLoading(true);
    setTestsError(null);
    try {
      const params = new URLSearchParams();
      if (testCategory) {
        params.set("category", testCategory);
      }
      const res = await fetch(`/cracked/tests?${params.toString()}`, {
        credentials: "include",
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

  const [newTestData, setNewTestData] = useState({
    category: "",
    testId: "",
    testName: "",
    questions: [],
  });

  const handleCreateTest = async () => {
    // naive example with minimal validations
    try {
      const res = await fetch("/cracked/tests", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          category: newTestData.category,
          testId: Number(newTestData.testId),
          testName: newTestData.testName,
          questions: [],
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to create test");
        return;
      }
      alert("Test created!");
      // refresh
      fetchTests();
      setNewTestData({ category: "", testId: "", testName: "", questions: [] });
    } catch (err) {
      console.error("Create test error:", err);
    }
  };

  const handleDeleteTest = async (testObj) => {
    if (!window.confirm(`Delete test: ${testObj.testName}?`)) return;
    try {
      const res = await fetch(`/cracked/tests/${testObj._id}`, {
        method: "DELETE",
        credentials: "include",
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
   *  5) DAILY PBQs states & fetch
   *****************************************/
  const [dailyList, setDailyList] = useState([]);
  const [dailyLoading, setDailyLoading] = useState(false);
  const [dailyError, setDailyError] = useState(null);

  const fetchDailyPBQs = useCallback(async () => {
    setDailyLoading(true);
    setDailyError(null);
    try {
      const res = await fetch("/cracked/daily", {
        credentials: "include",
      });
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

  const [newDaily, setNewDaily] = useState({
    prompt: "",
    dayIndex: "",
    correctIndex: "",
    explanation: "",
  });

  const handleCreateDaily = async () => {
    try {
      const body = {
        prompt: newDaily.prompt,
        dayIndex: Number(newDaily.dayIndex) || 0,
        correctIndex: Number(newDaily.correctIndex) || 0,
        explanation: newDaily.explanation,
      };
      const res = await fetch("/cracked/daily", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
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
      const res = await fetch(`/cracked/daily/${pbq._id}`, {
        method: "DELETE",
        credentials: "include",
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
   *  6) SUPPORT THREADS states & fetch
   *****************************************/
  const [threads, setThreads] = useState([]);
  const [threadsLoading, setThreadsLoading] = useState(false);
  const [threadsError, setThreadsError] = useState(null);

  const [threadStatusFilter, setThreadStatusFilter] = useState("");
  const [currentThread, setCurrentThread] = useState(null);
  const [adminReply, setAdminReply] = useState("");

  const fetchThreads = useCallback(async () => {
    setThreadsLoading(true);
    setThreadsError(null);
    try {
      const params = new URLSearchParams();
      if (threadStatusFilter) {
        params.set("status", threadStatusFilter);
      }
      const res = await fetch(`/cracked/supportThreads?${params.toString()}`, {
        credentials: "include",
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch support threads");
      }
      setThreads(data);
      setCurrentThread(null);
    } catch (err) {
      setThreadsError(err.message);
    } finally {
      setThreadsLoading(false);
    }
  }, [threadStatusFilter]);

  useEffect(() => {
    if (activeTab === "support") {
      fetchThreads();
    }
  }, [activeTab, fetchThreads]);

  const handleViewThread = async (threadId) => {
    try {
      const res = await fetch(`/cracked/supportThreads/${threadId}`, {
        credentials: "include",
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to get thread");
        return;
      }
      setCurrentThread(data);
      setAdminReply("");
    } catch (err) {
      console.error("View thread error:", err);
    }
  };

  const handleReplyToThread = async () => {
    if (!currentThread || !currentThread._id) return;
    try {
      const res = await fetch(
        `/cracked/supportThreads/${currentThread._id}/reply`,
        {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: adminReply }),
        }
      );
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to reply");
        return;
      }
      alert("Reply sent!");
      // re-fetch thread
      handleViewThread(currentThread._id);
    } catch (err) {
      console.error("Reply thread error:", err);
    }
  };

  const handleCloseThread = async (threadId) => {
    const resolution = window.prompt("Enter a resolution note:", "Issue resolved.");
    if (resolution === null) return; // user canceled
    try {
      const res = await fetch(`/cracked/supportThreads/${threadId}/close`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ resolution }),
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

  /*****************************************
   *  Tab UI: We define a big switch ...
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
    return (
      <div className="tab-content overview-tab">
        <h2>Overview Stats</h2>
        <ul>
          <li>User Count: {overviewData.user_count}</li>
          <li>Test Attempts Count: {overviewData.test_attempts_count}</li>
          <li>Daily Bonus Claims Today: {overviewData.daily_bonus_claims}</li>
          <li>Avg Test Score (%): {overviewData.average_test_score_percent}</li>
          <li>Timestamp: {overviewData.timestamp}</li>
        </ul>
        <button onClick={fetchOverview}>Refresh Overview</button>
      </div>
    );
  };

  const renderUsersTab = () => {
    return (
      <div className="tab-content users-tab">
        <h2>User Management</h2>
        <div className="users-search-row">
          <input
            type="text"
            value={userSearch}
            placeholder="Search username/email..."
            onChange={(e) => setUserSearch(e.target.value)}
          />
          <button onClick={() => { setUserPage(1); fetchUsers(); }}>
            Search
          </button>
        </div>
        <div>
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
                        onChange={(e) =>
                          handleUpdateUserField("suspended", e.target.checked)
                        }
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
            onChange={(e) =>
              setNewTestData((prev) => ({ ...prev, category: e.target.value }))
            }
          />
          <input
            type="text"
            placeholder="Test ID (number)"
            value={newTestData.testId}
            onChange={(e) =>
              setNewTestData((prev) => ({ ...prev, testId: e.target.value }))
            }
          />
          <input
            type="text"
            placeholder="Test Name"
            value={newTestData.testName}
            onChange={(e) =>
              setNewTestData((prev) => ({ ...prev, testName: e.target.value }))
            }
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
                <td>{t.testName || "(Unnamed)"}</td>
                <td>{t.questions ? t.questions.length : 0}</td>
                <td>
                  {/* For brevity, let's do only 'delete' here. 
                      You can do an 'edit' flow similarly. */}
                  <button onClick={() => handleDeleteTest(t)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

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
            onChange={(e) =>
              setNewDaily((prev) => ({ ...prev, correctIndex: e.target.value }))
            }
          />
          <textarea
            placeholder="Explanation"
            value={newDaily.explanation}
            onChange={(e) =>
              setNewDaily((prev) => ({ ...prev, explanation: e.target.value }))
            }
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

  const renderSupportTab = () => {
    return (
      <div className="tab-content support-tab">
        <h2>Support Threads</h2>
        <div className="thread-filter-row">
          <label>Status Filter:</label>
          <input
            type="text"
            placeholder="open / closed?"
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
                    <button onClick={() => handleCloseThread(th._id)}>
                      Close
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </div>
          <div className="thread-details">
            {currentThread ? (
              <div>
                <h4>Thread: {currentThread._id}</h4>
                <p>Status: {currentThread.status}</p>
                <ul className="messages-list">
                  {currentThread.messages.map((m, idx) => (
                    <li key={idx}>
                      <strong>{m.sender}:</strong> {m.content} (
                      {m.timestamp || ""})
                    </li>
                  ))}
                </ul>
                {currentThread.status !== "closed" && (
                  <>
                    <textarea
                      rows={3}
                      placeholder="Type an admin reply..."
                      value={adminReply}
                      onChange={(e) => setAdminReply(e.target.value)}
                    />
                    <button onClick={handleReplyToThread}>Send Reply</button>
                  </>
                )}
              </div>
            ) : (
              <p>Select a thread to view details.</p>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderPerformanceTab = () => {
    return (
      <div className="tab-content perf-tab">
        <h2>Performance Metrics</h2>
        <button onClick={fetchPerformance}>Refresh Perf Data</button>
        {perfLoading && <p>Loading performance data...</p>}
        {perfError && <p className="error-msg">Error: {perfError}</p>}
        {performanceData && (
          <div className="perf-details">
            <p>Avg Request Time: {performanceData.avg_request_time}s</p>
            <p>Avg DB Query Time: {performanceData.avg_db_query_time}s</p>
            <p>Data Transfer Rate: {performanceData.data_transfer_rate}</p>
            <p>Throughput: {performanceData.throughput} req/min</p>
            <p>Error Rate: {performanceData.error_rate}</p>
            <p>Timestamp: {performanceData.timestamp}</p>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="cracked-admin-dashboard-container">
      <h1 className="admin-dashboard-title">Cracked Admin Dashboard</h1>

      {/* Tab Navigation */}
      <div className="admin-tabs">
        <button
          className={activeTab === "overview" ? "active" : ""}
          onClick={() => setActiveTab("overview")}
        >
          Overview
        </button>
        <button
          className={activeTab === "users" ? "active" : ""}
          onClick={() => setActiveTab("users")}
        >
          Users
        </button>
        <button
          className={activeTab === "tests" ? "active" : ""}
          onClick={() => setActiveTab("tests")}
        >
          Tests
        </button>
        <button
          className={activeTab === "daily" ? "active" : ""}
          onClick={() => setActiveTab("daily")}
        >
          Daily PBQs
        </button>
        <button
          className={activeTab === "support" ? "active" : ""}
          onClick={() => setActiveTab("support")}
        >
          Support
        </button>
        <button
          className={activeTab === "performance" ? "active" : ""}
          onClick={() => {
            setActiveTab("performance");
            fetchPerformance();
          }}
        >
          Performance
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === "overview" && renderOverviewTab()}
      {activeTab === "users" && renderUsersTab()}
      {activeTab === "tests" && renderTestsTab()}
      {activeTab === "daily" && renderDailyTab()}
      {activeTab === "support" && renderSupportTab()}
      {activeTab === "performance" && renderPerformanceTab()}
    </div>
  );
}

export default CrackedAdminDashboard;
