import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./styles/CrackedAdminLogin.css";

function CrackedAdminLoginPage() {
  const navigate = useNavigate();

  const [adminKey, setAdminKey] = useState("");
  const [role, setRole] = useState("basic");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await fetch("/api/cracked/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminKey, role }),
        credentials: "include",
      });

      const data = await response.json();
      if (!response.ok) {
        setError(data.error || "Unable to log in");
      } else {
        // On success, navigate to the admin dashboard
        navigate("/cracked/dashboard");
      }
    } catch (err) {
      console.error("Admin login error:", err);
      setError("Network error or server unavailable");
    } finally {
      setLoading(false);
    }
  };

  return (
    // Top-level wrapper for scoping:
    <div className="cracked-admin-login-wrapper">
      <div className="cracked-admin-login-container">
        <div className="cracked-admin-login-card">
          <h1 className="cracked-admin-login-title">Admin Login</h1>

          <form className="cracked-admin-login-form" onSubmit={handleLogin}>
            <div className="admin-input-row">
              <label htmlFor="adminKey">Admin Key:</label>
              <input
                type="password"
                id="adminKey"
                value={adminKey}
                onChange={(e) => setAdminKey(e.target.value)}
                placeholder="Authenticate"
              />
            </div>

            <div className="admin-input-row">
              <label htmlFor="role">Role (optional):</label>
              <select
                id="role"
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                <option value="basic">Basic</option>
                <option value="supervisor">Supervisor</option>
                <option value="superadmin">Superadmin</option>
              </select>
            </div>

            {error && <p className="admin-error-message">{error}</p>}

            <button
              type="submit"
              className="cracked-admin-login-button"
              disabled={loading}
            >
              {loading ? "Logging in..." : "Login"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

export default CrackedAdminLoginPage;
