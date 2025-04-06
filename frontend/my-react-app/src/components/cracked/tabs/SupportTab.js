// src/components/cracked/tabs/SupportTab.js
import React, { useState, useEffect, useCallback, useRef } from "react";
import { io } from "socket.io-client";
import {
  FaHeadset, FaSearch, FaTimes, FaCommentDots, 
  FaPaperPlane, FaPlus, FaSpinner, FaExclamationTriangle
} from "react-icons/fa";

// We keep this as a top-level variable to maintain socket connection across component instances
let adminSocket = null;

const SupportTab = () => {
  const [threads, setThreads] = useState([]);
  const [threadsLoading, setThreadsLoading] = useState(false);
  const [threadsError, setThreadsError] = useState(null);
  const [threadStatusFilter, setThreadStatusFilter] = useState("");
  const [currentThread, setCurrentThread] = useState(null);
  const [adminReply, setAdminReply] = useState("");

  // We store all threads (including messages) so we can do real‐time merges
  const [allThreadMap, setAllThreadMap] = useState({});
  // Show "user is typing" in real time
  const [userIsTyping, setUserIsTyping] = useState(false);

  // Admin create thread for user
  const [adminTargetUserId, setAdminTargetUserId] = useState("");
  const [adminInitialMsg, setAdminInitialMsg] = useState("");

  const chatEndRef = useRef(null);

  const fetchThreads = useCallback(async () => {
    setThreadsLoading(true);
    setThreadsError(null);
    try {
      const params = new URLSearchParams();
      if (threadStatusFilter) {
        params.set("status", threadStatusFilter);
      }
      const res = await fetch(`/api/cracked/supportThreads?${params.toString()}`, {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch support threads");
      }
      setThreads(data);
      setCurrentThread(null);

      // Join all threads so we get real-time updates
      if (adminSocket && data.length > 0) {
        data.forEach((th) => {
          adminSocket.emit("join_thread", { threadId: th._id });
        });
      }
    } catch (err) {
      setThreadsError(err.message);
    } finally {
      setThreadsLoading(false);
    }
  }, [threadStatusFilter]);

  // Initialize adminSocket once
  useEffect(() => {
    if (!adminSocket) {
      const socket = io(window.location.origin, {
        path: "/api/socket.io",
        transports: ["websocket"]
      });
      adminSocket = socket;

      socket.on("connect", () => {
        console.log("Admin socket connected:", socket.id);
      });

      socket.on("disconnect", () => {
        console.log("Admin socket disconnected");
      });

      // Listen for new messages across ANY thread
      socket.on("new_message", (payload) => {
        const { threadId, message } = payload;
        setAllThreadMap((prev) => {
          const oldThread = prev[threadId] || { messages: [] };
          const oldMsgs = oldThread.messages;
          return {
            ...prev,
            [threadId]: {
              ...oldThread,
              messages: [...oldMsgs, message]
            }
          };
        });
        // If the currentThread is the same, append
        setCurrentThread((prev) => {
          if (prev && prev._id === threadId) {
            return {
              ...prev,
              messages: [...prev.messages, message]
            };
          }
          return prev;
        });
      });

      // user_typing / user_stop_typing
      socket.on("user_typing", (data) => {
        if (data.threadId && currentThread && currentThread._id === data.threadId) {
          setUserIsTyping(true);
        }
      });
      socket.on("user_stop_typing", (data) => {
        if (data.threadId && currentThread && currentThread._id === data.threadId) {
          setUserIsTyping(false);
        }
      });

      // Admin sees newly created threads in real-time
      socket.on("new_thread", (threadData) => {
        setThreads((prev) => [threadData, ...prev]);
        socket.emit("join_thread", { threadId: threadData._id });
      });
    }
  }, [currentThread]);

  useEffect(() => {
    fetchThreads();
  }, [fetchThreads]);

  const handleViewThread = async (threadId) => {
    try {
      const res = await fetch(`/api/cracked/supportThreads/${threadId}`, {
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to get thread");
        return;
      }
      setCurrentThread(data);
      setAdminReply("");
      setUserIsTyping(false);

      // Merge into allThreadMap
      setAllThreadMap((prev) => ({
        ...prev,
        [threadId]: data
      }));

      // Scroll to bottom of chat after a short delay to ensure render
      setTimeout(() => {
        if (chatEndRef.current) {
          chatEndRef.current.scrollIntoView({ behavior: "smooth" });
        }
      }, 100);
    } catch (err) {
      console.error("View thread error:", err);
    }
  };

  const handleReplyToThread = async () => {
    if (!currentThread || !currentThread._id || adminReply.trim() === "") return;
    try {
      const replyMessage = {
        sender: "admin",
        content: adminReply,
        timestamp: new Date().toISOString()
      };

      if (adminSocket) {
        adminSocket.emit("admin_stop_typing", {
          threadId: currentThread._id
        });
      }

      const res = await fetch(`/api/cracked/supportThreads/${currentThread._id}/reply`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: adminReply })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to reply");
        return;
      }

      // Update the local thread data directly
      setCurrentThread((prevThread) => {
        if (!prevThread) return null;
        return {
          ...prevThread,
          messages: [...prevThread.messages, replyMessage]
        };
      });

      // Update allThreadMap as well
      setAllThreadMap((prev) => {
        const oldThread = prev[currentThread._id] || { messages: [] };
        return {
          ...prev,
          [currentThread._id]: {
            ...oldThread,
            messages: [...oldThread.messages, replyMessage]
          }
        };
      });

      setAdminReply("");
      
      // Scroll to bottom of chat
      setTimeout(() => {
        if (chatEndRef.current) {
          chatEndRef.current.scrollIntoView({ behavior: "smooth" });
        }
      }, 100);
    } catch (err) {
      console.error("Reply thread error:", err);
    }
  };

  const handleAdminReplyTyping = (threadId) => {
    if (adminSocket && threadId) {
      adminSocket.emit("admin_typing", { threadId });
    }
  };

  const handleCloseThread = async (threadId) => {
    const resolution = window.prompt("Enter a resolution note:", "Issue resolved.");
    if (resolution === null) return;
    try {
      const res = await fetch(`/api/cracked/supportThreads/${threadId}/close`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ resolution })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to close thread");
        return;
      }
      alert("Thread closed!");
      fetchThreads();
    } catch (err) {
      console.error("Close thread error:", err);
    }
  };

  const handleClearClosedThreads = async () => {
    if (!window.confirm("Are you sure you want to permanently delete all closed threads?")) return;
    try {
      const res = await fetch("/api/cracked/supportThreads/clear-closed", {
        method: "DELETE",
        credentials: "include"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to clear closed threads");
        return;
      }
      alert(data.message || "Closed threads cleared");
      fetchThreads();
    } catch (err) {
      alert("Error clearing closed threads");
    }
  };

  const handleAdminCreateThread = async () => {
    if (!adminTargetUserId) {
      alert("Please enter a valid userId");
      return;
    }
    try {
      const body = {
        userId: adminTargetUserId,
        initialMessage: adminInitialMsg
      };
      const res = await fetch("/api/cracked/supportThreads/createFromAdmin", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to create thread from admin");
        return;
      }
      alert("Created new thread successfully!");
      setAdminTargetUserId("");
      setAdminInitialMsg("");
      fetchThreads();
    } catch (err) {
      console.error(err);
      alert("Error creating admin thread");
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

  // For rendering message content
  const renderMessageContent = (content) => {
    // Add URLs as clickable links
    return content.replace(
      /(https?:\/\/[^\s]+)/g, 
      '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>'
    );
  };

  return (
    <div className="admin-tab-content support-tab">
      <div className="admin-content-header">
        <h2><FaHeadset /> Support Management</h2>
        <div className="admin-filter-row">
          <input
            type="text"
            placeholder="Filter by status (open/closed)"
            value={threadStatusFilter}
            onChange={(e) => setThreadStatusFilter(e.target.value)}
            className="admin-filter-input"
          />
          <button className="admin-filter-btn" onClick={fetchThreads}>
            <FaSearch /> Filter
          </button>
        </div>
      </div>

      {threadsLoading && (
        <div className="admin-loading">
          <FaSpinner className="admin-spinner" />
          <p>Loading support threads...</p>
        </div>
      )}

      {threadsError && (
        <div className="admin-error-message">
          <FaExclamationTriangle /> Error: {threadsError}
        </div>
      )}

      <div className="admin-support-container">
        <div className="admin-threads-panel">
          <h3>Support Threads</h3>
          <div className="admin-threads-list">
            {threads.length > 0 ? (
              threads.map((th) => (
                <div 
                  key={th._id} 
                  className={`admin-thread-item ${th.status === 'closed' ? 'thread-closed' : ''} ${currentThread && currentThread._id === th._id ? 'active-thread' : ''}`}
                  onClick={() => handleViewThread(th._id)}
                >
                  <div className="admin-thread-info">
                    <div className="admin-thread-subject">{th.subject || "Untitled Thread"}</div>
                    <div className="admin-thread-meta">
                      <span className={`admin-thread-status status-${th.status}`}>
                        {th.status}
                      </span>
                      <span className="admin-thread-date">
                        {formatTime(th.updatedAt)}
                      </span>
                    </div>
                  </div>
                  <div className="admin-thread-actions">
                    {th.status !== "closed" && (
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCloseThread(th._id);
                        }}
                        className="admin-btn close-btn"
                        title="Close thread"
                      >
                        <FaTimes />
                      </button>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="admin-no-threads">No threads found matching your criteria</div>
            )}
          </div>
          
          <div className="admin-thread-actions-footer">
            <button 
              className="admin-danger-btn" 
              onClick={handleClearClosedThreads}
            >
              <FaTrash /> Clear All Closed Threads
            </button>
          </div>
        </div>

        <div className="admin-chat-panel">
          {currentThread ? (
            <>
              <div className="admin-chat-header">
                <h3>{currentThread.subject || "Untitled Thread"}</h3>
                <div className="admin-chat-meta">
                  <span className={`admin-thread-status status-${currentThread.status}`}>
                    {currentThread.status}
                  </span>
                  <span className="admin-thread-date">
                    Created: {formatTime(currentThread.createdAt)}
                  </span>
                </div>
              </div>

              <div className="admin-chat-messages">
                {currentThread.messages.length > 0 ? (
                  currentThread.messages.map((msg, idx) => (
                    <div 
                      key={idx} 
                      className={`admin-chat-message ${msg.sender === 'admin' ? 'admin-message' : msg.sender === 'system' ? 'system-message' : 'user-message'}`}
                    >
                      <div className="admin-message-sender">
                        {msg.sender === 'admin' ? 'Admin' : 
                         msg.sender === 'system' ? 'System' : 'User'}
                      </div>
                      <div 
                        className="admin-message-content"
                        dangerouslySetInnerHTML={{ __html: renderMessageContent(msg.content) }}
                      ></div>
                      <div className="admin-message-time">
                        {formatTime(msg.timestamp)}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="admin-empty-chat">No messages yet in this thread</div>
                )}
                {userIsTyping && (
                  <div className="admin-typing-indicator">
                    User is typing...
                  </div>
                )}
                <div ref={chatEndRef}></div>
              </div>

              {currentThread.status !== "closed" && (
                <div className="admin-chat-input">
                  <textarea
                    rows={3}
                    placeholder="Type your reply here..."
                    value={adminReply}
                    onChange={(e) => {
                      setAdminReply(e.target.value);
                      handleAdminReplyTyping(currentThread._id);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        handleReplyToThread();
                      }
                    }}
                  ></textarea>
                  <button 
                    onClick={handleReplyToThread}
                    disabled={adminReply.trim() === ''}
                    className="admin-send-btn"
                  >
                    <FaPaperPlane />
                  </button>
                </div>
              )}
            </>
          ) : (
            <div className="admin-no-thread-selected">
              <FaCommentDots className="admin-no-thread-icon" />
              <p>Select a thread to view the conversation</p>
            </div>
          )}
        </div>
      </div>

      <div className="admin-card create-thread-card">
        <h3><FaPlus /> Create Thread for User</h3>
        <div className="admin-form-grid">
          <div className="admin-form-group">
            <label>User ID:</label>
            <input
              type="text"
              value={adminTargetUserId}
              onChange={(e) => setAdminTargetUserId(e.target.value)}
              placeholder="Target user ID"
            />
          </div>
          <div className="admin-form-group">
            <label>Initial Message:</label>
            <input
              type="text"
              value={adminInitialMsg}
              onChange={(e) => setAdminInitialMsg(e.target.value)}
              placeholder="Initial message (optional)"
            />
          </div>
        </div>
        <div className="admin-form-actions">
          <button className="admin-submit-btn" onClick={handleAdminCreateThread}>
            Create Thread
          </button>
        </div>
      </div>
    </div>
  );
};

export default SupportTab;
