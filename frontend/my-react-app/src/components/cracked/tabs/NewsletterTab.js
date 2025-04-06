// src/components/cracked/tabs/NewsletterTab.js
import React, { useState, useEffect, useCallback } from "react";
import {
  FaEnvelope, FaUsers, FaSync, FaInfoCircle, 
  FaPaperPlane, FaPlus, FaTimes, FaSpinner, FaExclamationTriangle
} from "react-icons/fa";

const NewsletterTab = () => {
  const [subscribers, setSubscribers] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [newsletterLoading, setNewsletterLoading] = useState(false);
  const [newsletterError, setNewsletterError] = useState(null);
  const [activeNewsletterTab, setActiveNewsletterTab] = useState("subscribers");
  
  // New campaign form
  const [newCampaign, setNewCampaign] = useState({
    title: "",
    contentHtml: ""
  });
  
  // Current campaign being viewed/edited
  const [currentCampaign, setCurrentCampaign] = useState(null);

  const fetchSubscribers = async () => {
    setNewsletterLoading(true);
    setNewsletterError(null);
    try {
      const res = await fetch("/api/cracked/newsletter/subscribers", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch subscribers");
      }
      setSubscribers(data.subscribers || []);
    } catch (err) {
      setNewsletterError(err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  const fetchCampaigns = async () => {
    setNewsletterLoading(true);
    setNewsletterError(null);
    try {
      const res = await fetch("/api/cracked/newsletter/campaigns", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch campaigns");
      }
      setCampaigns(data.campaigns || []);
    } catch (err) {
      setNewsletterError(err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  useEffect(() => {
    if (activeNewsletterTab === "subscribers") {
      fetchSubscribers();
    } else if (activeNewsletterTab === "campaigns") {
      fetchCampaigns();
    }
  }, [activeNewsletterTab]);

  const handleCreateCampaign = async () => {
    if (!newCampaign.title || !newCampaign.contentHtml) {
      alert("Please provide both title and content");
      return;
    }
    
    setNewsletterLoading(true);
    try {
      const res = await fetch("/api/cracked/newsletter/create", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newCampaign)
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to create campaign");
      }
      alert("Newsletter campaign created successfully!");
      setNewCampaign({ title: "", contentHtml: "" });
      fetchCampaigns();
    } catch (err) {
      setNewsletterError(err.message);
      alert("Error creating campaign: " + err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  const handleViewCampaign = async (campaignId) => {
    setNewsletterLoading(true);
    try {
      const res = await fetch(`/api/cracked/newsletter/${campaignId}`, { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch campaign");
      }
      setCurrentCampaign(data);
    } catch (err) {
      setNewsletterError(err.message);
      alert("Error viewing campaign: " + err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  const handleSendCampaign = async (campaignId) => {
    if (!window.confirm("Are you sure you want to send this newsletter to all subscribers?")) {
      return;
    }
    
    setNewsletterLoading(true);
    try {
      const res = await fetch(`/api/cracked/newsletter/send/${campaignId}`, {
        method: "POST",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to send campaign");
      }
      alert(`Newsletter sent to ${data.recipientsCount} recipients!`);
      fetchCampaigns();
    } catch (err) {
      setNewsletterError(err.message);
      alert("Error sending campaign: " + err.message);
    } finally {
      setNewsletterLoading(false);
    }
  };

  // Format time in a user-friendly way
  const formatTime = (timestamp) => {
    if (!timestamp) return "";
    
    try {
      const date = new Date(timestamp);
      return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      }).format(date);
    } catch (e) {
      return timestamp;
    }
  };

  return (
    <div className="admin-tab-content newsletter-tab">
      <div className="admin-content-header">
        <h2><FaEnvelope /> Newsletter Management</h2>
      </div>

      <div className="admin-newsletter-tabs">
        <button 
          className={activeNewsletterTab === "subscribers" ? "active" : ""}
          onClick={() => setActiveNewsletterTab("subscribers")}
        >
          Subscribers
        </button>
        <button 
          className={activeNewsletterTab === "campaigns" ? "active" : ""}
          onClick={() => setActiveNewsletterTab("campaigns")}
        >
          Campaigns
        </button>
        <button 
          className={activeNewsletterTab === "create" ? "active" : ""}
          onClick={() => setActiveNewsletterTab("create")}
        >
          Create New
        </button>
      </div>

      {newsletterLoading && (
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading newsletter data...</p>
        </div>
      )}

      {newsletterError && (
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {newsletterError}
        </div>
      )}

      {/* Subscribers Tab */}
      {activeNewsletterTab === "subscribers" && (
        <div className="admin-newsletter-content">
          <div className="admin-card">
            <h3><FaUsers /> Email Subscribers</h3>
            <button className="admin-refresh-btn" onClick={fetchSubscribers}>
              <FaSync /> Refresh List
            </button>

            {subscribers.length > 0 ? (
              <div className="admin-data-table-container">
                <table className="admin-data-table">
                  <thead>
                    <tr>
                      <th>Email</th>
                      <th>Subscribed At</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {subscribers.map((sub, index) => (
                      <tr key={sub._id || index}>
                        <td>{sub.email}</td>
                        <td>{formatTime(sub.subscribedAt)}</td>
                        <td>
                          <span className={sub.unsubscribed ? "status-inactive" : "status-active"}>
                            {sub.unsubscribed ? "Unsubscribed" : "Active"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="admin-no-data">
                <p>No subscribers found. You can refresh the list or check back later.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Campaigns Tab */}
      {activeNewsletterTab === "campaigns" && (
        <div className="admin-newsletter-content">
          <div className="admin-card">
            <h3><FaEnvelope /> Newsletter Campaigns</h3>
            <button className="admin-refresh-btn" onClick={fetchCampaigns}>
              <FaSync /> Refresh List
            </button>

            {campaigns.length > 0 ? (
              <div className="admin-data-table-container">
                <table className="admin-data-table">
                  <thead>
                    <tr>
                      <th>Title</th>
                      <th>Created At</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {campaigns.map((campaign, index) => (
                      <tr key={campaign._id || index}>
                        <td>{campaign.title}</td>
                        <td>{formatTime(campaign.createdAt)}</td>
                        <td>
                          <span className={campaign.status === "sent" ? "status-success" : "status-waiting"}>
                            {campaign.status}
                          </span>
                        </td>
                        <td>
                          <div className="admin-action-buttons">
                            <button 
                              onClick={() => handleViewCampaign(campaign._id)}
                              className="admin-btn view-btn"
                              title="View campaign"
                            >
                              <FaInfoCircle />
                            </button>
                            {campaign.status !== "sent" && (
                              <button 
                                onClick={() => handleSendCampaign(campaign._id)}
                                className="admin-btn send-btn"
                                title="Send campaign"
                              >
                                <FaPaperPlane />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="admin-no-data">
                <p>No campaigns found. You can create a new campaign from the "Create New" tab.</p>
              </div>
            )}
          </div>

          {currentCampaign && (
            <div className="admin-card">
              <div className="admin-card-header">
                <h3>{currentCampaign.title}</h3>
                <button 
                  className="admin-close-btn"
                  onClick={() => setCurrentCampaign(null)}
                >
                  <FaTimes />
                </button>
              </div>
              <div className="admin-campaign-details">
                <div className="admin-campaign-meta">
                  <div><strong>Created:</strong> {formatTime(currentCampaign.createdAt)}</div>
                  <div><strong>Status:</strong> {currentCampaign.status}</div>
                  {currentCampaign.sentAt && (
                    <div><strong>Sent At:</strong> {formatTime(currentCampaign.sentAt)}</div>
                  )}
                </div>
                <div className="admin-campaign-preview">
                  <h4>HTML Content Preview:</h4>
                  <div className="admin-html-preview">
                    <div dangerouslySetInnerHTML={{ __html: currentCampaign.contentHtml }}></div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Create New Campaign Tab */}
      {activeNewsletterTab === "create" && (
        <div className="admin-newsletter-content">
          <div className="admin-card">
            <h3><FaPlus /> Create New Newsletter Campaign</h3>
            <div className="admin-form-group">
              <label>Campaign Title:</label>
              <input
                type="text"
                value={newCampaign.title}
                onChange={(e) => setNewCampaign({ ...newCampaign, title: e.target.value })}
                placeholder="Enter newsletter title"
              />
            </div>
            <div className="admin-form-group">
              <label>HTML Content:</label>
              <textarea
                value={newCampaign.contentHtml}
                onChange={(e) => setNewCampaign({ ...newCampaign, contentHtml: e.target.value })}
                placeholder="Enter newsletter HTML content"
                rows={10}
              ></textarea>
            </div>
            <div className="admin-form-actions">
              <button 
                className="admin-submit-btn" 
                onClick={handleCreateCampaign}
                disabled={!newCampaign.title || !newCampaign.contentHtml || newsletterLoading}
              >
                {newsletterLoading ? (
                  <><FaSpinner className="admin-spinner" /> Creating...</>
                ) : (
                  <>Create Campaign</>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default NewsletterTab;
