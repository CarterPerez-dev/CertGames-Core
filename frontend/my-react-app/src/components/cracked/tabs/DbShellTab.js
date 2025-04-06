// src/components/cracked/tabs/DbShellTab.js
import React, { useState } from "react";
import {
  FaTerminal, FaSpinner, FaExclamationTriangle
} from "react-icons/fa";

const DbShellTab = () => {
  const [dbShellCollection, setDbShellCollection] = useState("");
  const [dbShellFilter, setDbShellFilter] = useState("");
  const [dbShellLimit, setDbShellLimit] = useState(5);
  const [dbShellResults, setDbShellResults] = useState([]);
  const [dbShellLoading, setDbShellLoading] = useState(false);
  const [dbShellError, setDbShellError] = useState(null);

  const handleDbShellRead = async () => {
    setDbShellLoading(true);
    setDbShellError(null);
    try {
      // We'll just pass the text filter directly
      const body = {
        collection: dbShellCollection,
        filterText: dbShellFilter,
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
      setDbShellError(err.message || "Error occurred while querying the database");
    } finally {
      setDbShellLoading(false);
    }
  };

  return (
    <div className="admin-tab-content db-shell-tab">
      <div className="admin-content-header">
        <h2><FaTerminal /> Database Shell</h2>
      </div>

      <div className="admin-card">
        <h3><FaTerminal /> Read-Only Database Query</h3>
        <div className="admin-form-grid">
          <div className="admin-form-group">
            <label>Collection:</label>
            <input
              type="text"
              value={dbShellCollection}
              onChange={(e) => setDbShellCollection(e.target.value)}
              placeholder="Collection name (e.g. mainusers)"
            />
          </div>
          <div className="admin-form-group">
            <label>Filter Text:</label>
            <input
              type="text"
              value={dbShellFilter}
              onChange={(e) => setDbShellFilter(e.target.value)}
              placeholder='e.g. username:john or email:example.com'
            />
            <small className="admin-filter-help">
              Simple filter format: field:value (e.g. username:john)
            </small>
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

export default DbShellTab;
