// src/components/cracked/tabs/TestsTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaClipboardList, FaSearch, FaTrash, FaPlus,
  FaSpinner, FaExclamationTriangle
} from "react-icons/fa";

const TestsTab = () => {
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
    fetchTests();
  }, [fetchTests]);

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

export default TestsTab;
