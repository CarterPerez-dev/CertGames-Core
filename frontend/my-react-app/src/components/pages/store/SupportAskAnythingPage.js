import React, { useEffect, useState, useRef, useCallback } from 'react';
import { useSelector } from 'react-redux';
import { io } from 'socket.io-client';
import './css/SupportAskAnythingPage.css';
import { 
  FaPaperPlane, 
  FaPlus, 
  FaSync, 
  FaTimes, 
  FaInfoCircle,
  FaRegSmile,
  FaEnvelope,
  FaHourglassHalf,
  FaCommentDots,
  FaCheck,
  FaComments,
  FaCircleNotch,
  FaExclamationTriangle,
  FaCircle,
  FaArrowLeft,
  FaEllipsisH,
  FaUser,
  FaHeadset,
  FaRobot,
  FaCrown,
  FaSignal,
  FaLock,
  FaBolt
} from 'react-icons/fa';

// Keep a single socket instance at module level
let socket = null;

function SupportAskAnythingPage() {
  // Get user ID from Redux
  const userIdFromRedux = useSelector((state) => state.user.userId);
  
  // Thread and message states
  const [threads, setThreads] = useState([]);
  const [selectedThreadId, setSelectedThreadId] = useState(null);
  const [messages, setMessages] = useState([]);
  
  // UI states
  const [newThreadSubject, setNewThreadSubject] = useState('');
  const [userMessage, setUserMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [adminIsTyping, setAdminIsTyping] = useState(false);
  const [showSupportInfoPopup, setShowSupportInfoPopup] = useState(true);
  const [mobileThreadsVisible, setMobileThreadsVisible] = useState(true);
  
  // Loading and error states
  const [loadingThreads, setLoadingThreads] = useState(false);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [error, setError] = useState(null);
  const [socketStatus, setSocketStatus] = useState('disconnected');
  
  // Refs
  const chatEndRef = useRef(null);
  const messageInputRef = useRef(null);
  const processedMessagesRef = useRef(new Set()); // Track processed messages
  
  // Format timestamps
  const formatTimestamp = (ts) => {
    if (!ts) return '';
    const date = new Date(ts);
    
    // If it's today, just show the time
    const today = new Date();
    if (date.toDateString() === today.toDateString()) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    // Otherwise show date and time
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };
  
  // Get thread status icon and color
  const getStatusInfo = (status = 'open') => {
    const s = status.toLowerCase();
    
    if (s.includes('open')) {
      return { icon: <FaCircle />, label: 'Open', className: 'status-open' };
    }
    if (s.includes('pending')) {
      return { icon: <FaHourglassHalf />, label: 'Pending', className: 'status-pending' };
    }
    if (s.includes('resolved')) {
      return { icon: <FaCheck />, label: 'Resolved', className: 'status-resolved' };
    }
    if (s.includes('closed')) {
      return { icon: <FaLock />, label: 'Closed', className: 'status-closed' };
    }
    
    return { icon: <FaCircle />, label: 'Open', className: 'status-open' };
  };
  
  // Scroll to bottom of messages
  const scrollToBottom = useCallback(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, []);
  
  // Helper function to create a message signature for duplicate detection
  const createMessageSignature = (message) => {
    return `${message.sender}:${message.content}:${message.timestamp}`;
  };
  
  //////////////////////////////////////////////////////////////////////////
  // SOCKET SETUP - Initialize once and handle real-time events
  //////////////////////////////////////////////////////////////////////////
  useEffect(() => {
    // Initialize socket if not already done
    if (!socket) {
      console.log('Initializing Socket.IO for support chat...');
      socket = io(window.location.origin, {
        path: '/api/socket.io',
        transports: ['websocket'],
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000
      });
    }
    
    // Socket connection event handlers
    const handleConnect = () => {
      console.log('Support socket connected:', socket.id);
      setSocketStatus('connected');
      
      // Join user's personal room for notifications
      const userId = userIdFromRedux || localStorage.getItem('userId');
      if (userId) {
        socket.emit('join_user_room', { userId });
        console.log(`Joined user room: user_${userId}`);
      }
      
      // Re-join current thread room if there is one
      if (selectedThreadId) {
        socket.emit('join_thread', { threadId: selectedThreadId });
        console.log(`Rejoined thread room on connect: ${selectedThreadId}`);
      }
    };
    
    const handleDisconnect = () => {
      console.log('Support socket disconnected');
      setSocketStatus('disconnected');
    };
    
    const handleConnectError = (err) => {
      console.error('Socket connection error:', err);
      setSocketStatus('error');
    };
    
    const handleNewMessage = (payload) => {
      console.log('Received new_message event:', payload);
      const { threadId, message } = payload;
      
      // Add message to current thread if it's selected
      if (threadId === selectedThreadId) {
        const messageSignature = createMessageSignature(message);
        
        // Only add the message if we haven't processed it before
        if (!processedMessagesRef.current.has(messageSignature)) {
          processedMessagesRef.current.add(messageSignature);
          
          setMessages((prev) => [...prev, message]);
          scrollToBottom();
        } else {
          console.log('Duplicate message detected and ignored:', messageSignature);
        }
      }
      
      // Update thread's lastUpdated time
      setThreads((prev) =>
        prev.map((t) => {
          if (t._id === threadId) {
            return { ...t, lastUpdated: message.timestamp };
          }
          return t;
        })
      );
    };
    
    const handleNewThread = (threadData) => {
      console.log('Received new_thread event:', threadData);
      
      // Add to threads list if not already there
      setThreads((prev) => {
        if (prev.some((t) => t._id === threadData._id)) {
          return prev;
        }
        return [threadData, ...prev];
      });
      
      // Join the thread room
      socket.emit('join_thread', { threadId: threadData._id });
      console.log(`Joined new thread room: ${threadData._id}`);
    };
    
    const handleAdminTyping = (data) => {
      if (data.threadId === selectedThreadId) {
        setAdminIsTyping(true);
      }
    };
    
    const handleAdminStopTyping = (data) => {
      if (data.threadId === selectedThreadId) {
        setAdminIsTyping(false);
      }
    };
    
    // Register socket event listeners
    socket.on('connect', handleConnect);
    socket.on('disconnect', handleDisconnect);
    socket.on('connect_error', handleConnectError);
    socket.on('new_message', handleNewMessage);
    socket.on('new_thread', handleNewThread);
    socket.on('admin_typing', handleAdminTyping);
    socket.on('admin_stop_typing', handleAdminStopTyping);
    
    // If socket is already connected, manually trigger the connect handler
    if (socket.connected) {
      handleConnect();
    }
    
    // Cleanup function to remove event listeners
    return () => {
      socket.off('connect', handleConnect);
      socket.off('disconnect', handleDisconnect);
      socket.off('connect_error', handleConnectError);
      socket.off('new_message', handleNewMessage);
      socket.off('new_thread', handleNewThread);
      socket.off('admin_typing', handleAdminTyping);
      socket.off('admin_stop_typing', handleAdminStopTyping);
    };
  }, [selectedThreadId, userIdFromRedux, scrollToBottom]);
  
  //////////////////////////////////////////////////////////////////////////
  // FETCH THREADS - Get user's support threads on mount
  //////////////////////////////////////////////////////////////////////////
  const fetchUserThreads = useCallback(async () => {
    setLoadingThreads(true);
    setError(null);
    
    try {
      const res = await fetch('/api/support/my-chat', {
        method: 'GET',
        credentials: 'include'
      });
      
      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Failed to load threads');
        }
        
        const threadList = Array.isArray(data) ? data : [];
        setThreads(threadList);
        
        // Join all thread rooms if socket is connected
        if (socket && socket.connected) {
          threadList.forEach((t) => {
            socket.emit('join_thread', { threadId: t._id });
            console.log(`Joined thread room on load: ${t._id}`);
          });
        }
      } else {
        throw new Error('Server returned unexpected response format');
      }
    } catch (err) {
      setError(err.message);
      console.error('Error fetching threads:', err);
    } finally {
      setLoadingThreads(false);
    }
  }, []);
  
  useEffect(() => {
    fetchUserThreads();
  }, [fetchUserThreads]);
  
  //////////////////////////////////////////////////////////////////////////
  // CREATE THREAD - Start a new support thread
  //////////////////////////////////////////////////////////////////////////
  const createNewThread = async () => {
    if (!newThreadSubject.trim()) {
      setError('Please enter a subject for your thread');
      return;
    }
    
    setError(null);
    
    try {
      const res = await fetch('/api/support/my-chat', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject: newThreadSubject.trim() })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to create thread');
      }
      
      // Add new thread to state
      setThreads((prev) => [data, ...prev]);
      setNewThreadSubject('');
      
      // Select the newly created thread
      setSelectedThreadId(data._id);
      setMessages([]);
      
      // On mobile, show the messages panel after creating a thread
      setMobileThreadsVisible(false);
      
      // Join the thread room
      if (socket && socket.connected) {
        socket.emit('join_thread', { threadId: data._id });
        console.log(`Joined new thread: ${data._id}`);
      }
    } catch (err) {
      setError(err.message);
      console.error('Error creating thread:', err);
    }
  };
  
  //////////////////////////////////////////////////////////////////////////
  // SELECT THREAD - Load messages for a thread
  //////////////////////////////////////////////////////////////////////////
  const selectThread = async (threadId) => {
    // Skip if already selected
    if (threadId === selectedThreadId) {
      // On mobile, just toggle to messages view
      setMobileThreadsVisible(false);
      return;
    }
    
    // Leave current thread room if any
    if (selectedThreadId && socket && socket.connected) {
      socket.emit('leave_thread', { threadId: selectedThreadId });
      console.log(`Left thread room: ${selectedThreadId}`);
    }
    
    setSelectedThreadId(threadId);
    setMessages([]);
    setLoadingMessages(true);
    setError(null);
    
    // On mobile, show the messages panel
    setMobileThreadsVisible(false);
    
    // Clear the processed messages set when switching threads
    processedMessagesRef.current.clear();
    
    // Join new thread room
    if (socket && socket.connected) {
      socket.emit('join_thread', { threadId });
      console.log(`Joined thread room: ${threadId}`);
    }
    
    try {
      const res = await fetch(`/api/support/my-chat/${threadId}`, {
        method: 'GET',
        credentials: 'include'
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to load messages');
      }
      
      // Add all loaded messages to the processed messages set
      const loadedMessages = data.messages || [];
      loadedMessages.forEach(msg => {
        processedMessagesRef.current.add(createMessageSignature(msg));
      });
      
      setMessages(loadedMessages);
      scrollToBottom();
      
      // Focus on message input
      if (messageInputRef.current) {
        messageInputRef.current.focus();
      }
    } catch (err) {
      setError(err.message);
      console.error('Error loading thread messages:', err);
    } finally {
      setLoadingMessages(false);
    }
  };
  
  //////////////////////////////////////////////////////////////////////////
  // SEND MESSAGE - Send a message in the current thread
  //////////////////////////////////////////////////////////////////////////
  const sendMessage = async () => {
    if (!selectedThreadId) {
      setError('Please select a thread first');
      return;
    }
    
    if (!userMessage.trim()) {
      return;
    }
    
    setError(null);
    const messageToSend = userMessage.trim();
    
    // Optimistic update for better UX
    const optimisticMessage = {
      sender: 'user',
      content: messageToSend,
      timestamp: new Date().toISOString(),
      optimistic: true
    };
    
    setMessages((prev) => [...prev, optimisticMessage]);
    setUserMessage('');
    scrollToBottom();
    
    // Stop typing indicator
    if (socket && socket.connected && selectedThreadId) {
      socket.emit('user_stop_typing', { threadId: selectedThreadId });
    }
    setIsTyping(false);
    
    try {
      const res = await fetch(`/api/support/my-chat/${selectedThreadId}`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: messageToSend })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to send message');
      }
      
      // Update the thread's last updated time
      setThreads((prev) =>
        prev.map((t) => {
          if (t._id === selectedThreadId) {
            return { ...t, lastUpdated: new Date().toISOString() };
          }
          return t;
        })
      );
      
      // Replace optimistic message with confirmed one by refetching
      loadMessagesForThread(selectedThreadId);
    } catch (err) {
      setError(err.message);
      console.error('Error sending message:', err);
      
      // Remove optimistic message on error
      setMessages((prev) => prev.filter((msg) => !msg.optimistic));
    }
  };
  
  // Load messages for a thread
  const loadMessagesForThread = async (threadId) => {
    try {
      const res = await fetch(`/api/support/my-chat/${threadId}`, {
        credentials: 'include'
      });
      
      const data = await res.json();
      if (res.ok && data.messages) {
        // Clear previous processed messages when explicitly reloading
        processedMessagesRef.current.clear();
        
        // Add all loaded messages to the processed messages set
        data.messages.forEach(msg => {
          processedMessagesRef.current.add(createMessageSignature(msg));
        });
        
        setMessages(data.messages);
        scrollToBottom();
      }
    } catch (err) {
      console.error('Error reloading messages:', err);
    }
  };
  
  //////////////////////////////////////////////////////////////////////////
  // TYPING HANDLERS - Handle user typing events
  //////////////////////////////////////////////////////////////////////////
  const handleTyping = (e) => {
    const val = e.target.value;
    setUserMessage(val);
    
    // Emit typing events
    if (socket && socket.connected && selectedThreadId) {
      if (!isTyping && val.trim().length > 0) {
        socket.emit('user_typing', { threadId: selectedThreadId });
        setIsTyping(true);
      } else if (isTyping && val.trim().length === 0) {
        socket.emit('user_stop_typing', { threadId: selectedThreadId });
        setIsTyping(false);
      }
    }
  };
  
  // Handle message input keydown (for Enter key)
  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };
  
  // Close thread (user-initiated)
  const closeThread = async () => {
    if (!selectedThreadId) return;
    
    if (!window.confirm('Are you sure you want to close this thread?')) {
      return;
    }
    
    try {
      const res = await fetch(`/api/support/my-chat/${selectedThreadId}/close`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: 'Thread closed by user' })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to close thread');
      }
      
      // Update thread status in the list
      setThreads((prev) =>
        prev.map((t) => {
          if (t._id === selectedThreadId) {
            return { ...t, status: 'closed' };
          }
          return t;
        })
      );
      
      // Reload messages to show closure message
      loadMessagesForThread(selectedThreadId);
    } catch (err) {
      setError(err.message);
      console.error('Error closing thread:', err);
    }
  };
  
  // Get selected thread data
  const selectedThread = threads.find(t => t._id === selectedThreadId);
  const isThreadClosed = selectedThread?.status?.toLowerCase() === 'closed';
  
  // Handle back button on mobile
  const handleBackToThreads = () => {
    setMobileThreadsVisible(true);
  };
  
  return (
    <div className="support-container">
      <div className="support-header">
        <h1 className="support-title">
          <FaHeadset className="support-title-icon" />
          Support / Ask Anything
        </h1>
        
        {showSupportInfoPopup && (
          <div className="support-info-banner">
            <div className="support-info-content">
              <FaBolt className="support-info-icon" />
              <span>We typically respond within 1-24 hours (average ~3 hours)</span>
            </div>
            <button 
              className="support-info-close" 
              onClick={() => setShowSupportInfoPopup(false)}
              aria-label="Close information banner"
            >
              <FaTimes />
            </button>
          </div>
        )}
        
        <p className="support-subtitle">
          Ask us anything about exams, this website, or technical issues. We're here to help!
        </p>
      </div>
      
      {error && (
        <div className="support-error-alert">
          <FaExclamationTriangle className="support-error-icon" />
          <span>{error}</span>
          <button 
            onClick={() => setError(null)}
            aria-label="Dismiss error"
            className="support-error-close"
          >
            <FaTimes />
          </button>
        </div>
      )}
      
      <div className="support-connection-status">
        <span className={`status-indicator status-${socketStatus}`}></span>
        <span className="status-text">
          {socketStatus === 'connected' 
            ? 'Real-time connection active' 
            : socketStatus === 'disconnected'
              ? 'Connecting to real-time service...'
              : 'Connection error - messages may be delayed'}
        </span>
      </div>
      
      <div className={`support-layout ${mobileThreadsVisible ? 'show-threads-mobile' : 'show-messages-mobile'}`}>
        {/* THREADS PANEL */}
        <div className="support-threads-panel">
          <div className="threads-header">
            <h2><FaComments className="threads-header-icon" /> Your Conversations</h2>
            <button 
              className="refresh-button" 
              onClick={fetchUserThreads} 
              title="Refresh threads"
              aria-label="Refresh conversations"
            >
              <FaSync />
            </button>
          </div>
          
          <div className="create-thread-form">
            <input
              type="text"
              placeholder="New conversation subject..."
              value={newThreadSubject}
              onChange={(e) => setNewThreadSubject(e.target.value)}
              className="create-thread-input"
              aria-label="New conversation subject"
            />
            <button 
              className="create-thread-button" 
              onClick={createNewThread}
              disabled={!newThreadSubject.trim()}
              aria-label="Create new conversation"
            >
              <FaPlus />
              <span>Create</span>
            </button>
          </div>
          
          <div className="threads-list-container">
            {loadingThreads ? (
              <div className="threads-loading">
                <FaCircleNotch className="loading-icon spin" />
                <span>Loading conversations...</span>
              </div>
            ) : threads.length === 0 ? (
              <div className="threads-empty">
                <FaRegSmile className="empty-icon" />
                <p>No conversations yet</p>
                <p className="empty-hint">Create one to get started</p>
              </div>
            ) : (
              <ul className="threads-list">
                {threads.map((thread) => {
                  const statusInfo = getStatusInfo(thread.status);
                  
                  return (
                    <li 
                      key={thread._id}
                      className={`thread-item ${selectedThreadId === thread._id ? 'thread-item-active' : ''} ${thread.status?.toLowerCase() === 'closed' ? 'thread-item-closed' : ''}`}
                      onClick={() => selectThread(thread._id)}
                    >
                      <div className="thread-item-header">
                        <span className={`thread-status-indicator ${statusInfo.className}`}>
                          {statusInfo.icon}
                        </span>
                        <h3 className="thread-subject">{thread.subject}</h3>
                      </div>
                      <div className="thread-item-footer">
                        <span className={`thread-status ${statusInfo.className}`}>
                          {statusInfo.label}
                        </span>
                        <span className="thread-timestamp">
                          {thread.lastUpdated ? formatTimestamp(thread.lastUpdated) : 'New'}
                        </span>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
        
        {/* MESSAGES PANEL */}
        <div className="support-messages-panel">
          {!selectedThreadId ? (
            <div className="no-thread-selected">
              <FaEnvelope className="no-thread-icon" />
              <h3>No conversation selected</h3>
              <p>Choose a conversation from the list or create a new one</p>
            </div>
          ) : (
            <>
              <div className="messages-header">
                <button 
                  className="messages-back-button"
                  onClick={handleBackToThreads}
                  aria-label="Back to conversations"
                >
                  <FaArrowLeft />
                </button>
                
                <div className="selected-thread-info">
                  {selectedThread && (
                    <>
                      <span className={`selected-thread-status ${getStatusInfo(selectedThread.status).className}`}>
                        {getStatusInfo(selectedThread.status).icon}
                      </span>
                      <h2>{selectedThread.subject}</h2>
                    </>
                  )}
                </div>
                
                <div className="messages-actions">
                  {!isThreadClosed && selectedThread && (
                    <button 
                      className="close-thread-button" 
                      onClick={closeThread}
                      title="Close conversation"
                      aria-label="Close conversation"
                    >
                      <FaLock />
                      <span>Close</span>
                    </button>
                  )}
                </div>
              </div>
              
              <div className="messages-container">
                {loadingMessages ? (
                  <div className="messages-loading">
                    <FaCircleNotch className="loading-icon spin" />
                    <span>Loading messages...</span>
                  </div>
                ) : messages.length === 0 ? (
                  <div className="messages-empty">
                    <FaCommentDots className="empty-messages-icon" />
                    <p>No messages in this conversation yet</p>
                    <p className="empty-hint">Start the conversation by sending a message</p>
                  </div>
                ) : (
                  <div className="messages-list">
                    {messages.map((message, index) => {
                      const isUser = message.sender === 'user';
                      const isSystem = message.sender === 'system';
                      
                      return (
                        <div 
                          key={index}
                          className={`message ${isUser ? 'message-user' : isSystem ? 'message-system' : 'message-admin'}`}
                        >
                          <div className="message-avatar">
                            {isUser ? (
                              <FaUser className="avatar-icon user" />
                            ) : isSystem ? (
                              <FaRobot className="avatar-icon system" />
                            ) : (
                              <FaCrown className="avatar-icon admin" />
                            )}
                          </div>
                          
                          <div className="message-bubble">
                            {!isSystem && (
                              <div className="message-sender">
                                {isUser ? 'You' : 'Support Team'}
                              </div>
                            )}
                            
                            <div className="message-content">
                              {message.content}
                            </div>
                            
                            <div className="message-timestamp">
                              {formatTimestamp(message.timestamp)}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    
                    {adminIsTyping && (
                      <div className="admin-typing-indicator">
                        <FaCrown className="avatar-icon admin" />
                        <div className="typing-bubble">
                          <div className="typing-dots">
                            <span></span>
                            <span></span>
                            <span></span>
                          </div>
                          <span className="typing-text">Support Team is typing...</span>
                        </div>
                      </div>
                    )}
                    
                    <div ref={chatEndRef} />
                  </div>
                )}
              </div>
              
              <div className="message-input-container">
                {isThreadClosed ? (
                  <div className="thread-closed-notice">
                    <FaLock className="thread-closed-icon" />
                    <span>This conversation is closed. You can create a new one if needed.</span>
                  </div>
                ) : (
                  <>
                    <textarea
                      ref={messageInputRef}
                      className="message-input"
                      placeholder="Type your message here..."
                      value={userMessage}
                      onChange={handleTyping}
                      onKeyDown={handleKeyDown}
                      disabled={isThreadClosed}
                      aria-label="Message input"
                      rows={3}
                    />
                    
                    <button 
                      className="send-message-button" 
                      onClick={sendMessage}
                      disabled={!userMessage.trim() || isThreadClosed}
                      aria-label="Send message"
                    >
                      <FaPaperPlane />
                    </button>
                  </>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default SupportAskAnythingPage;
