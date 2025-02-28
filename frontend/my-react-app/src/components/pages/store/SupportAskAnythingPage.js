import React, { useEffect, useState, useRef } from 'react';
import './SupportAskAnythingPage.css';


/**
 * Complex multi-thread support/ask-anything page:
 * - The user can have multiple "threads" or "topics" (like separate conversation channels).
 * - Each thread has its own messages. 
 * - We'll poll the server for:
 *     1) A list of threads (GET /api/test/support/threads).
 *     2) The messages in the currently selected thread (GET /api/test/support/threads/:threadId).
 * - The user can create a new thread with a subject, then post messages in it.
 * - We'll show a side panel with the thread list, and a main panel with the messages for the chosen thread.
 * - We poll every 10s for the new messages in the currently selected thread, 
 *   so if admin replies, user sees it promptly.
 * 
 * No CSS is inlined here. We provide class names for you to style in a separate .css file.
 * 
 * CRITICAL: In your backend, you need routes to handle multiple threads. 
 * Otherwise, adapt the single-thread approach as needed.
 */

function SupportAskAnythingPage() {
  // -----------------------------
  // States
  // -----------------------------
  const [threads, setThreads] = useState([]);         // array of user’s threads
  const [selectedThreadId, setSelectedThreadId] = useState(null); // the current topic
  const [messages, setMessages] = useState([]);       // messages in the current thread
  const [loadingThreads, setLoadingThreads] = useState(false);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [error, setError] = useState(null);

  // Creating new thread
  const [newThreadSubject, setNewThreadSubject] = useState('');

  // New message
  const [userMessage, setUserMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);

  // For auto-polling
  const pollIntervalRef = useRef(null);

  // For auto-scrolling the chat
  const chatEndRef = useRef(null);

  // -----------------------------
  // 1) Initial load: fetch threads
  //    and start poll
  // -----------------------------
  useEffect(() => {
    fetchThreads();

    // Start an interval that refreshes threads, 
    // and also refreshes messages for the current thread
    pollIntervalRef.current = setInterval(() => {
      refreshDataWithoutLoading();
    }, 10000); // every 10 seconds

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, []);

  // Quick method to do a forced refresh
  const refreshDataWithoutLoading = async () => {
    try {
      // fetch threads but do not set loading
      const res = await fetch('/api/test/support/threads', {
        credentials: 'include',
      });
      const data = await res.json();
      if (res.ok && Array.isArray(data)) {
        setThreads(data);
      }

      // If there's a selected thread, fetch messages 
      if (selectedThreadId) {
        const res2 = await fetch(`/api/test/support/threads/${selectedThreadId}`, {
          credentials: 'include',
        });
        const data2 = await res2.json();
        if (res2.ok && data2.messages) {
          setMessages(data2.messages);
          scrollToBottom();
        }
      }
    } catch (err) {
      // silently fail
    }
  };

  // -----------------------------
  // 2) fetchThreads
  // -----------------------------
  const fetchThreads = async () => {
    setLoadingThreads(true);
    setError(null);
    try {
      const res = await fetch('/api/test/support/threads', {
        credentials: 'include',
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to load threads');
      }
      setThreads(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingThreads(false);
    }
  };

  // -----------------------------
  // 3) Create new thread
  // -----------------------------
  const createNewThread = async () => {
    if (!newThreadSubject.trim()) return;
    setError(null);
    try {
      const body = { subject: newThreadSubject.trim() };
      const res = await fetch('/api/test/support/threads', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to create new thread');
      }
      // After creation, refresh threads
      setNewThreadSubject('');
      fetchThreads();
    } catch (err) {
      setError(err.message);
    }
  };

  // -----------------------------
  // 4) selectThread
  //    fetch that thread's messages
  // -----------------------------
  const selectThread = async (threadId) => {
    setSelectedThreadId(threadId);
    setMessages([]);
    setLoadingMessages(true);
    setError(null);

    try {
      const res = await fetch(`/api/test/support/threads/${threadId}`, {
        credentials: 'include',
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to load thread messages');
      }
      if (data.messages) {
        setMessages(data.messages);
        scrollToBottom();
      } else {
        setMessages([]);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingMessages(false);
    }
  };

  // -----------------------------
  // 5) Send a message in the selected thread
  // -----------------------------
  const sendMessage = async () => {
    if (!selectedThreadId) {
      alert('Please select a thread first.');
      return;
    }
    if (!userMessage.trim()) return;

    setError(null);
    try {
      const body = { content: userMessage.trim() };
      const res = await fetch(`/api/test/support/threads/${selectedThreadId}`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || 'Failed to send message');
        return;
      }
      // after sending, re-fetch messages (no loading spinner)
      setUserMessage('');
      setIsTyping(false);
      await refreshMessagesOnly();
    } catch (err) {
      setError(err.message);
    }
  };

  // utility to refresh messages for the selected thread only
  const refreshMessagesOnly = async () => {
    if (!selectedThreadId) return;
    try {
      const res = await fetch(`/api/test/support/threads/${selectedThreadId}`, {
        credentials: 'include',
      });
      const data = await res.json();
      if (res.ok && data.messages) {
        setMessages(data.messages);
        scrollToBottom();
      }
    } catch (err) {
      // ignore
    }
  };

  // -----------------------------
  // 6) handle text changes
  // -----------------------------
  const handleTyping = (e) => {
    setUserMessage(e.target.value);
    if (!isTyping) setIsTyping(true);
  };
  useEffect(() => {
    if (userMessage.trim().length === 0 && isTyping) {
      setIsTyping(false);
    }
  }, [userMessage, isTyping]);

  // -----------------------------
  // 7) scrollToBottom
  // -----------------------------
  const scrollToBottom = () => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  // -----------------------------
  // 8) formatTimestamp
  // -----------------------------
  const formatTimestamp = (ts) => {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toLocaleString();
  };

  // UI rendering
  return (
    <div className="support-container">
      <h2 className="support-title">Ask Anything / Support Chat</h2>

      {error && <div className="support-error-box">Error: {error}</div>}

      <div className="support-main-layout">
        {/* Left panel: threads */}
        <div className="support-left-panel">
          <div className="create-thread-section">
            <h3>Create New Thread</h3>
            <input
              type="text"
              className="new-thread-input"
              placeholder="Subject of new thread..."
              value={newThreadSubject}
              onChange={(e) => setNewThreadSubject(e.target.value)}
            />
            <button className="create-thread-button" onClick={createNewThread}>
              Create
            </button>
          </div>

          <div className="threads-list-wrapper">
            <h3>Your Threads</h3>
            {loadingThreads && <div className="threads-loading">Loading threads...</div>}
            {threads.length === 0 && !loadingThreads && (
              <div className="threads-empty">No threads yet</div>
            )}
            <ul className="threads-list">
              {threads.map((t) => (
                <li
                  key={t._id}
                  onClick={() => selectThread(t._id)}
                  className={
                    t._id === selectedThreadId
                      ? 'thread-item thread-item-active'
                      : 'thread-item'
                  }
                >
                  <div className="thread-subject">{t.subject || 'Untitled Thread'}</div>
                  <div className="thread-status">{t.status || 'open'}</div>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Right panel: current thread's messages */}
        <div className="support-right-panel">
          {!selectedThreadId ? (
            <div className="no-thread-selected">Select a thread or create a new one</div>
          ) : (
            <>
              <div className="messages-header">
                {loadingMessages ? (
                  <span>Loading messages...</span>
                ) : (
                  <button
                    className="refresh-messages-button"
                    onClick={refreshMessagesOnly}
                  >
                    Refresh
                  </button>
                )}
              </div>

              <div className="messages-container">
                {messages.length === 0 ? (
                  <div className="no-messages">No messages yet for this thread.</div>
                ) : (
                  messages.map((m, idx) => {
                    const isUser = m.sender === 'user';
                    return (
                      <div
                        key={idx}
                        className={`message-bubble ${
                          isUser ? 'message-user' : 'message-admin'
                        }`}
                      >
                        <div className="message-sender">
                          {isUser ? 'You' : 'Admin'}
                        </div>
                        <div className="message-content">{m.content}</div>
                        <div className="message-timestamp">
                          {formatTimestamp(m.timestamp)}
                        </div>
                      </div>
                    );
                  })
                )}
                <div ref={chatEndRef} />
              </div>

              {isTyping && <div className="typing-indicator">You are typing...</div>}

              <div className="send-message-area">
                <textarea
                  className="send-message-textarea"
                  rows={3}
                  placeholder="Type your message..."
                  value={userMessage}
                  onChange={handleTyping}
                />
                <button className="send-message-button" onClick={sendMessage}>
                  Send
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default SupportAskAnythingPage;
