// src/components/cracked/tabs/DailyTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaCalendarDay, FaPlus, FaTrash, FaSync,
  FaSpinner, FaExclamationTriangle, FaEye, FaTimes
} from "react-icons/fa";
import FormattedQuestion from "../../FormattedQuestion";

const DailyTab = () => {
  const [dailyList, setDailyList] = useState([]);
  const [dailyLoading, setDailyLoading] = useState(false);
  const [dailyError, setDailyError] = useState(null);
  const [previewQuestion, setPreviewQuestion] = useState(null);
  const [showPreview, setShowPreview] = useState(false);

  const [newDaily, setNewDaily] = useState({
    prompt: "",
    dayIndex: "",
    correctIndex: "",
    explanation: "",
    options: ["","","",""],  // Added an array of 4 empty strings for options
    examTip: ""  // Added exam tip field
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
        explanation: newDaily.explanation,
        options: newDaily.options,
        examTip: newDaily.examTip || "" // Include exam tip in the request
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
      setNewDaily({ 
        prompt: "", 
        dayIndex: "", 
        correctIndex: "", 
        explanation: "",
        options: ["","","",""],
        examTip: ""
      });
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

  // Handle updating the options array
  const handleOptionChange = (index, value) => {
    const newOptions = [...newDaily.options];
    newOptions[index] = value;
    setNewDaily({...newDaily, options: newOptions});
  };


  const handlePreviewQuestion = () => {

    const formattedQuestion = `## ${newDaily.prompt}

  ${newDaily.options.map((option, index) => `${index + 1}. ${option}`).join('\n')}

  ${ 
    newDaily.examTip
    ? `\n**Exam Tip:** ${newDaily.examTip}`
    : ''
  }
  `; 

  setPreviewQuestion(formattedQuestion);
  setShowPreview(true);
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
              placeholder="Correct answer index (0-3)"
            />
          </div>
        </div>
        
        {/* Options section */}
        <div className="admin-form-group full-width">
          <label>Options:</label>
          <div className="admin-options-grid">
            {newDaily.options.map((option, index) => (
              <div key={index} className="admin-option-input">
                <label>Option {index + 1}:</label>
                <input
                  type="text"
                  value={option}
                  onChange={(e) => handleOptionChange(index, e.target.value)}
                  placeholder={`Option ${index + 1}`}
                />
              </div>
            ))}
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
        
        {/* New exam tip field */}
        <div className="admin-form-group full-width">
          <label>Exam Tip:</label>
          <textarea
            value={newDaily.examTip}
            onChange={(e) => setNewDaily((prev) => ({ ...prev, examTip: e.target.value }))}
            placeholder="Optional exam tip to display"
            rows={2}
          ></textarea>
        </div>
        
        <div className="admin-form-actions">
          <button className="admin-preview-btn" onClick={handlePreviewQuestion}>
            <FaEye /> Preview Question
          </button>
          <button className="admin-submit-btn" onClick={handleCreateDaily}>
            Create Daily PBQ
          </button>
        </div>
      </div>

      {/* Preview Modal */}
      {showPreview && (
        <div className="admin-modal-overlay">
          <div className="admin-preview-modal">
            <div className="admin-modal-header">
              <h3>Question Preview</h3>
              <button className="admin-close-btn" onClick={() => setShowPreview(false)}>
                <FaTimes />
              </button>
            </div>
            <div className="admin-preview-content">
              <div className="admin-preview-wrapper">
                <FormattedQuestion questionText={previewQuestion} />
              </div>
            </div>
          </div>
        </div>
      )}

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
              <th>Has Exam Tip</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {dailyList.map((d) => (
              <tr key={d._id}>
                <td>{d.prompt}</td>
                <td>{d.dayIndex}</td>
                <td>{d.correctIndex}</td>
                <td>{d.examTip ? "Yes" : "No"}</td>
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
