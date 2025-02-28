import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./CrackedAdminLogin.css"; // unique CSS file

const CrackedAdminLoginPage = () => {
  const navigate = useNavigate();

  // Local state for the adminKey and role
  const [adminKey, setAdminKey] = useState("");
  const [role, setRole] = useState("basic"); // you can let the user pick or leave it
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await fetch("/cracked/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminKey, role }),
        credentials: "include", 
        // credentials include so cookies/sessions pass
      });

      const data = await response.json();
      if (!response.ok) {
        // e.g. 403 or 400
        setError(data.error || "Unable to log in");
      } else {
        // success -> you could navigate to your admin dashboard, e.g. "/cracked-admin/dashboard"
        navigate("/cracked-admin/dashboard");
      }
    } catch (err) {
      console.error("Admin login error:", err);
      setError("Network error or server unavailable");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="cracked-admin-login-container">
      <h1 className="cracked-admin-login-title">Cracked Admin Login</h1>

      <form className="cracked-admin-login-form" onSubmit={handleLogin}>
        <div className="admin-input-row">
          <label htmlFor="adminKey">Admin Key:</label>
          <input
            type="password"
            id="adminKey"
            value={adminKey}
            onChange={(e) => setAdminKey(e.target.value)}
            placeholder="Enter super-long admin key"
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
  );
};

export default CrackedAdminLoginPage;
