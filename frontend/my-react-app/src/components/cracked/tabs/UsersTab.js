// src/components/cracked/tabs/UsersTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaUsers, FaSearch, FaUserEdit, FaTrash, FaKey,
  FaSave, FaTimes, FaSpinner, FaExclamationTriangle
} from "react-icons/fa";

const UsersTab = () => {
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
    fetchUsers();
  }, [fetchUsers]);

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

export default UsersTab;
