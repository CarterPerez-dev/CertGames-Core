// src/components/cracked/tabs/UsersTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaUsers, FaSearch, FaUserEdit, FaTrash, FaKey, FaSave, FaTimes, 
  FaSpinner, FaExclamationTriangle, FaToggleOn, FaToggleOff, FaCircle,
  FaApple, FaGoogle, FaFacebook, FaWindowMaximize, FaMobileAlt, FaInfo
} from "react-icons/fa";
import { adminFetch } from '../csrfHelper';

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

  // State for viewing detailed information
  const [selectedUser, setSelectedUser] = useState(null);
  const [showDetails, setShowDetails] = useState(false);

  // Double confirmation states
  const [deleteConfirmStep, setDeleteConfirmStep] = useState(0);
  const [deleteUserId, setDeleteUserId] = useState(null);
  const [subscriptionConfirmStep, setSubscriptionConfirmStep] = useState(0);
  const [toggleSubscriptionId, setToggleSubscriptionId] = useState(null);
  const [toggleSubscriptionAction, setToggleSubscriptionAction] = useState("");

  const fetchUsers = useCallback(async () => {
    setUsersLoading(true);
    setUsersError(null);
    try {
      const params = new URLSearchParams({
        search: userSearch,
        page: userPage.toString(),
        limit: userLimit.toString()
      });
      const res = await adminFetch(`/api/cracked/users?${params.toString()}`);
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
      const res = await adminFetch(`/api/cracked/users/${editUserId}`, {
        method: "PUT",
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

  // Start the deletion process with confirmation steps
  const startUserDeleteProcess = (userId, username) => {
    setDeleteUserId(userId);
    setDeleteConfirmStep(1);
  };

  // Handle confirmation steps for user deletion
  const handleUserDeleteConfirm = async () => {
    if (!deleteUserId) return;
    
    if (deleteConfirmStep === 1) {
      // Move to second confirmation
      setDeleteConfirmStep(2);
      return;
    }
    
    if (deleteConfirmStep === 2) {
      // Proceed with deletion
      try {
        const res = await adminFetch(`/api/cracked/users/${deleteUserId}`, {
          method: "DELETE"
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
      } finally {
        // Reset confirmation state
        setDeleteUserId(null);
        setDeleteConfirmStep(0);
      }
    }
  };

  // Cancel the delete operation
  const cancelDeleteProcess = () => {
    setDeleteUserId(null);
    setDeleteConfirmStep(0);
  };

  // Start the subscription toggle process
  const startToggleSubscription = (userId, username, currentlyActive) => {
    const action = currentlyActive ? "deactivate" : "activate";
    setToggleSubscriptionId(userId);
    setToggleSubscriptionAction(action);
    setSubscriptionConfirmStep(1);
  };

  // Handle confirmation for subscription toggle
  const handleToggleSubscriptionConfirm = async () => {
    if (!toggleSubscriptionId) return;
    
    // For deactivation, we need double confirmation
    if (toggleSubscriptionAction === "deactivate") {
      if (subscriptionConfirmStep === 1) {
        // Move to second confirmation for deactivation
        setSubscriptionConfirmStep(2);
        return;
      }
    }
    
    // Proceed with the action
    try {
      const res = await adminFetch(`/api/cracked/users/${toggleSubscriptionId}/toggle-subscription`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          active: toggleSubscriptionAction === "activate" 
        })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to update subscription");
        return;
      }
      alert(`Subscription ${toggleSubscriptionAction}d successfully!`);
      fetchUsers();
    } catch (err) {
      console.error("Subscription toggle error:", err);
    } finally {
      // Reset confirmation state
      setToggleSubscriptionId(null);
      setSubscriptionConfirmStep(0);
      setToggleSubscriptionAction("");
    }
  };

  // Cancel the subscription toggle operation
  const cancelToggleSubscription = () => {
    setToggleSubscriptionId(null);
    setSubscriptionConfirmStep(0);
    setToggleSubscriptionAction("");
  };

  const handleResetPassword = async (userId) => {
    if (!window.confirm("Reset this user's password to a random token?")) return;
    try {
      const res = await adminFetch(`/api/cracked/users/${userId}/reset-password`, {
        method: "POST",
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

  // View user details
  const handleViewUserDetails = (user) => {
    setSelectedUser(user);
    setShowDetails(true);
  };

  // Close user details modal
  const closeUserDetails = () => {
    setShowDetails(false);
    setSelectedUser(null);
  };

  // Format date for display
  const formatDate = (dateString) => {
    if (!dateString) return "N/A";
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  // Helper to determine signup source icon
  const renderSignupSourceIcon = (user) => {
    if (user.signupSource === 'iOS') {
      return <FaMobileAlt className="admin-user-icon ios-icon" title="iOS signup" />;
    } else if (user.signupSource === 'Web') {
      return <FaWindowMaximize className="admin-user-icon web-icon" title="Web signup" />;
    }
    return null;
  };

  // Helper to render OAuth provider icon
  const renderOAuthIcon = (provider) => {
    if (!provider) return null;
    
    if (provider.toLowerCase().includes('google')) {
      return <FaGoogle className="admin-user-icon google-icon" title="Google OAuth" />;
    } else if (provider.toLowerCase().includes('apple')) {
      return <FaApple className="admin-user-icon apple-icon" title="Apple OAuth" />;
    } else if (provider.toLowerCase().includes('facebook')) {
      return <FaFacebook className="admin-user-icon facebook-icon" title="Facebook OAuth" />;
    }
    
    return null;
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
              placeholder="Search by username, email, ID, IP..."
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
              <th>Level</th>
              <th>Subscription</th>
              <th>Source</th>
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
                      <div className="admin-user-name-cell">
                        {u.username}
                        {u.isActive && (
                          <FaCircle className="admin-user-active-indicator" title="Currently active" />
                        )}
                      </div>
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
                        value={editUserData.level}
                        onChange={(e) => handleUpdateUserField("level", e.target.value)}
                        className="admin-edit-input"
                      />
                    ) : (
                      u.level
                    )}
                  </td>
                  <td>
                    <span className={u.subscriptionActive ? "status-active" : "status-inactive"}>
                      {u.subscriptionActive ? "Active" : "Inactive"}
                    </span>
                  </td>
                  <td className="admin-user-source-cell">
                    {renderOAuthIcon(u.oauth_provider)}
                    {renderSignupSourceIcon(u)}
                    <span className="admin-user-id">#{u.shortId}</span>
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
                          onClick={() => handleViewUserDetails(u)}
                          className="admin-btn view-btn"
                          title="View details"
                        >
                          <FaInfo />
                        </button>
                        <button 
                          onClick={() => startToggleSubscription(u._id, u.username, u.subscriptionActive)}
                          className={`admin-btn ${u.subscriptionActive ? "deactivate-btn" : "activate-btn"}`}
                          title={u.subscriptionActive ? "Deactivate subscription" : "Activate subscription"}
                        >
                          {u.subscriptionActive ? <FaToggleOff /> : <FaToggleOn />}
                        </button>
                        <button 
                          onClick={() => startUserDeleteProcess(u._id, u.username)}
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

      {/* Delete Confirmation Dialog */}
      {deleteConfirmStep > 0 && (
        <div className="admin-modal-overlay">
          <div className="admin-confirmation-dialog">
            <h3>Confirm User Deletion</h3>
            {deleteConfirmStep === 1 ? (
              <p>Are you sure you want to delete this user?</p>
            ) : (
              <p className="admin-warning-text">You are about to PERMANENTLY delete this user's account! This action cannot be undone. Proceed?</p>
            )}
            <div className="admin-confirmation-buttons">
              <button 
                className="admin-danger-btn" 
                onClick={handleUserDeleteConfirm}
              >
                {deleteConfirmStep === 1 ? "Confirm" : "Yes, Delete Permanently"}
              </button>
              <button 
                className="admin-cancel-btn" 
                onClick={cancelDeleteProcess}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Subscription Toggle Confirmation Dialog */}
      {subscriptionConfirmStep > 0 && (
        <div className="admin-modal-overlay">
          <div className="admin-confirmation-dialog">
            <h3>Confirm Subscription {toggleSubscriptionAction === "activate" ? "Activation" : "Deactivation"}</h3>
            {toggleSubscriptionAction === "activate" || subscriptionConfirmStep === 1 ? (
              <p>Are you sure you want to {toggleSubscriptionAction} this user's subscription?</p>
            ) : (
              <p className="admin-warning-text">Warning: Deactivating this subscription will revoke the user's premium access! Proceed?</p>
            )}
            <div className="admin-confirmation-buttons">
              <button 
                className={toggleSubscriptionAction === "activate" ? "admin-submit-btn" : "admin-danger-btn"} 
                onClick={handleToggleSubscriptionConfirm}
              >
                {subscriptionConfirmStep === 1 ? "Confirm" : "Yes, Deactivate"}
              </button>
              <button 
                className="admin-cancel-btn" 
                onClick={cancelToggleSubscription}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* User Details Modal */}
      {showDetails && selectedUser && (
        <div className="admin-modal-overlay">
          <div className="admin-details-modal">
            <div className="admin-modal-header">
              <h3>User Details: {selectedUser.username}</h3>
              <button className="admin-close-modal-btn" onClick={closeUserDetails}>
                <FaTimes />
              </button>
            </div>
            <div className="admin-user-details-content">
              <div className="admin-user-details-section">
                <h4>Basic Information</h4>
                <div className="admin-details-grid">
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">User ID:</span>
                    <span className="admin-detail-value">{selectedUser._id}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Username:</span>
                    <span className="admin-detail-value">{selectedUser.username}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Email:</span>
                    <span className="admin-detail-value">{selectedUser.email}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">IP Address:</span>
                    <span className="admin-detail-value">{selectedUser.ip || "N/A"}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Last Login:</span>
                    <span className="admin-detail-value">{formatDate(selectedUser.lastLoginAt)}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Status:</span>
                    <span className={`admin-detail-value ${selectedUser.isActive ? "status-active" : "status-inactive"}`}>
                      {selectedUser.isActive ? "Currently Active" : "Inactive"}
                    </span>
                  </div>
                </div>
              </div>

              <div className="admin-user-details-section">
                <h4>Account Statistics</h4>
                <div className="admin-details-grid">
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Coins:</span>
                    <span className="admin-detail-value">{selectedUser.coins}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">XP:</span>
                    <span className="admin-detail-value">{selectedUser.xp}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Level:</span>
                    <span className="admin-detail-value">{selectedUser.level}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Test Attempts:</span>
                    <span className="admin-detail-value">{selectedUser.testAttempts || 0}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Perfect Tests:</span>
                    <span className="admin-detail-value">{selectedUser.perfectTestsCount || 0}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Questions Answered:</span>
                    <span className="admin-detail-value">{selectedUser.totalQuestionsAnswered || 0}</span>
                  </div>
                </div>
              </div>

              <div className="admin-user-details-section">
                <h4>Subscription Information</h4>
                <div className="admin-details-grid">
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Status:</span>
                    <span className={`admin-detail-value ${selectedUser.subscriptionActive ? "status-active" : "status-inactive"}`}>
                      {selectedUser.subscriptionActive ? "Active" : "Inactive"}
                    </span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">State:</span>
                    <span className="admin-detail-value">{selectedUser.subscriptionStatus || "N/A"}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Platform:</span>
                    <span className="admin-detail-value">{selectedUser.subscriptionPlatform || "N/A"}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Sign-up Source:</span>
                    <span className="admin-detail-value">{selectedUser.signupSource || "Unknown"}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">OAuth Provider:</span>
                    <span className="admin-detail-value">{selectedUser.oauth_provider || "None"}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Start Date:</span>
                    <span className="admin-detail-value">{formatDate(selectedUser.subscriptionStartDate)}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">End Date:</span>
                    <span className="admin-detail-value">{formatDate(selectedUser.subscriptionEndDate)}</span>
                  </div>
                  <div className="admin-detail-item">
                    <span className="admin-detail-label">Canceled At:</span>
                    <span className="admin-detail-value">{formatDate(selectedUser.subscriptionCanceledAt)}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UsersTab;
