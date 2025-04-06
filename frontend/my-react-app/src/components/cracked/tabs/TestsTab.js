// src/components/cracked/tabs/TestsTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaClipboardList, FaSearch, FaTrash, FaPlus, FaEdit,
  FaSpinner, FaExclamationTriangle, FaSave, FaTimes
} from "react-icons/fa";

const TestsTab = () => {
  const [tests, setTests] = useState([]);
  const [testCategory, setTestCategory] = useState("");
  const [testsLoading, setTestsLoading] = useState(false);
  const [testsError, setTestsError] = useState(null);
  const [editingTestId, setEditingTestId] = useState(null);
  const [editingTestName, setEditingTestName] = useState("");

  // Keep existing state for new test data
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

  // New function to handle editing a test name
  const handleEditTestName = (test) => {
    setEditingTestId(test._id);
    setEditingTestName(test.testName || "");
  };

  // New function to save the edited test name
  const handleSaveTestName = async () => {
    if (!editingTestId) return;
    
    try {
      const res = await fetch(`/api/cracked/tests/${editingTestId}/update-name`, {
        method: "PUT",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ testName: editingTestName })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to update test name");
        return;
      }
      alert("Test name updated successfully!");
      setEditingTestId(null);
      setEditingTestName("");
      fetchTests();
    } catch (err) {
      console.error("Update test name error:", err);
    }
  };

  // Function to cancel editing
  const cancelEditing = () => {
    setEditingTestId(null);
    setEditingTestName("");
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

      {/* Keeping the create test functionality for reference but it's not needed */}
      <div className="admin-card" style={{ display: 'none' }}>
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
                <td>
                  {editingTestId === t._id ? (
                    <input
                      type="text"
                      value={editingTestName}
                      onChange={(e) => setEditingTestName(e.target.value)}
                      className="admin-edit-input"
                    />
                  ) : (
                    t.testName || "(Unnamed)"
                  )}
                </td>
                <td>{t.questions ? t.questions.length : 0}</td>
                <td>
                  <div className="admin-action-buttons">
                    {editingTestId === t._id ? (
                      <>
                        <button 
                          onClick={handleSaveTestName}
                          className="admin-btn save-btn"
                          title="Save test name"
                        >
                          <FaSave />
                        </button>
                        <button 
                          onClick={cancelEditing}
                          className="admin-btn cancel-btn"
                          title="Cancel editing"
                        >
                          <FaTimes />
                        </button>
                      </>
                    ) : (
                      <>
                        <button 
                          onClick={() => handleEditTestName(t)}
                          className="admin-btn edit-btn"
                          title="Edit test name"
                        >
                          <FaEdit />
                        </button>
                        <button 
                          onClick={() => handleDeleteTest(t)}
                          className="admin-btn delete-btn"
                          title="Delete test"
                        >
                          <FaTrash />
                        </button>
                      </>
                    )}
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
