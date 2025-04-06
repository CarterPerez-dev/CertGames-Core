// src/components/cracked/tabs/DailyTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaCalendarDay, FaPlus, FaTrash, FaSync,
  FaSpinner, FaExclamationTriangle
} from "react-icons/fa";

const DailyTab = () => {
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
    fetchDailyPBQs();
  }, [fetchDailyPBQs]);

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

export default DailyTab;
