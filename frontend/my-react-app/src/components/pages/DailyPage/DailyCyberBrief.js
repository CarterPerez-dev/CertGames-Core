import React, { useState, useEffect } from "react";
import axios from "axios";
import "./DailyCyberBrief.css";
import { 
  FaEnvelope, 
  FaShieldAlt, 
  FaCheck, 
  FaTimes, 
  FaInfoCircle, 
  FaExclamationTriangle,
  FaSpinner,
  FaLock,
  FaNewspaper,
  FaChartLine,
  FaToolbox,
  FaRegLightbulb,
  FaRocket,
  FaBell
} from "react-icons/fa";

function DailyCyberBrief() {
  const [email, setEmail] = useState("");
  const [statusMsg, setStatusMsg] = useState("");
  const [isError, setIsError] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [activeSection, setActiveSection] = useState("subscribe");
  const [showStatusMsg, setShowStatusMsg] = useState(false);
  const [formFocused, setFormFocused] = useState(false);

  // Clear status message after 5 seconds
  useEffect(() => {
    if (statusMsg) {
      setShowStatusMsg(true);
      const timer = setTimeout(() => {
        setShowStatusMsg(false);
        setTimeout(() => setStatusMsg(""), 300); // Clear message after fade-out animation
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [statusMsg]);

  // Animation delay for cards
  useEffect(() => {
    // Add different animation delays to cards
    const cards = document.querySelectorAll('.dcb-card');
    cards.forEach((card, index) => {
      card.style.animationDelay = `${0.1 + (index * 0.1)}s`;
    });
  }, []);

  // Email validation
  const isValidEmail = (email) => {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
  };

  async function handleSubscribe() {
    if (!email) {
      setIsError(true);
      setStatusMsg("Please enter your email address.");
      return;
    }

    if (!isValidEmail(email)) {
      setIsError(true);
      setStatusMsg("Please enter a valid email address.");
      return;
    }

    setIsSubmitting(true);
    setStatusMsg("");
    
    try {
      const response = await axios.post("/api/newsletter/subscribe", { email });
      setIsError(false);
      setStatusMsg(response.data.message || "Successfully subscribed to the Daily Cyber Brief!");
      // Clear email field on successful subscription
      setEmail("");
    } catch (err) {
      setIsError(true);
      const fallback = "Subscription failed. Please try again.";
      setStatusMsg(err?.response?.data?.error || err?.response?.data?.message || fallback);
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleUnsubscribe() {
    if (!email) {
      setIsError(true);
      setStatusMsg("Please enter your email address to unsubscribe.");
      return;
    }

    if (!isValidEmail(email)) {
      setIsError(true);
      setStatusMsg("Please enter a valid email address.");
      return;
    }

    setIsSubmitting(true);
    setStatusMsg("");
    
    try {
      const response = await axios.post("/api/newsletter/unsubscribe", { email });
      setIsError(false);
      setStatusMsg(response.data.message || "Successfully unsubscribed from the Daily Cyber Brief.");
      // Clear email field on successful unsubscription
      setEmail("");
    } catch (err) {
      setIsError(true);
      const fallback = "Unsubscribe failed. Please try again.";
      setStatusMsg(err?.response?.data?.error || err?.response?.data?.message || fallback);
    } finally {
      setIsSubmitting(false);
    }
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      if (activeSection === "subscribe") {
        handleSubscribe();
      } else {
        handleUnsubscribe();
      }
    }
  };

  return (
    <div className="dcb-container">
      <div className="dcb-wrapper">
        {/* Header Section */}
        <div className="dcb-header">
          <div className="dcb-header-content">
            <div className="dcb-logo">
              <FaNewspaper className="dcb-logo-icon" />
            </div>
            <div className="dcb-title">
              <h1>Daily Cyber Brief</h1>
              <p>Your essential cybersecurity intelligence, delivered daily</p>
            </div>
          </div>
        </div>

        {/* Main Content with Cards */}
        <div className="dcb-main-content">
          {/* Intro Card with Features */}
          <div className="dcb-card dcb-intro-card">
            <div className="dcb-card-header">
              <FaShieldAlt className="dcb-card-icon" />
              <h2>Stay Ahead of Cyber Threats</h2>
            </div>
            <div className="dcb-card-content">
              <p>
                The Daily Cyber Brief delivers curated, actionable cybersecurity intelligence 
                directly to your inbox. Stay informed about emerging threats, security best 
                practices, and industry trends.
              </p>
              
              <div className="dcb-features">
                <div className="dcb-feature">
                  <FaLock className="dcb-feature-icon" />
                  <h3>Threat Intelligence</h3>
                  <p>Get the latest on emerging cyber threats and vulnerabilities</p>
                </div>
                <div className="dcb-feature">
                  <FaChartLine className="dcb-feature-icon" />
                  <h3>Industry Trends</h3>
                  <p>Track industry trends and stay ahead of the curve</p>
                </div>
                <div className="dcb-feature">
                  <FaToolbox className="dcb-feature-icon" />
                  <h3>Security Tools</h3>
                  <p>Practical security tools and techniques for implementation</p>
                </div>
                <div className="dcb-feature">
                  <FaRegLightbulb className="dcb-feature-icon" />
                  <h3>Expert Insights</h3>
                  <p>Gain insights from security experts and thought leaders</p>
                </div>
              </div>
            </div>
          </div>

          {/* Signup Card */}
          <div className="dcb-card dcb-signup-card">
            <div className="dcb-card-header">
              <FaBell className="dcb-card-icon" />
              <h2>Join the Cyber Brief Community</h2>
            </div>
            <div className="dcb-card-content">
              <div className="dcb-tabs">
                <button 
                  className={`dcb-tab ${activeSection === "subscribe" ? "active" : ""}`}
                  onClick={() => setActiveSection("subscribe")}
                >
                  <FaCheck /> Subscribe
                </button>
                <button 
                  className={`dcb-tab ${activeSection === "unsubscribe" ? "active" : ""}`}
                  onClick={() => setActiveSection("unsubscribe")}
                >
                  <FaTimes /> Unsubscribe
                </button>
              </div>

              <div className="dcb-form">
                <div className="dcb-input-group">
                  <FaEnvelope className="dcb-input-icon" />
                  <input
                    type="email"
                    value={email}
                    placeholder="Enter your email address"
                    onChange={(e) => setEmail(e.target.value)}
                    onKeyPress={handleKeyPress}
                    disabled={isSubmitting}
                    onFocus={() => setFormFocused(true)}
                    onBlur={() => setFormFocused(false)}
                  />
                </div>

                {activeSection === "subscribe" ? (
                  <button 
                    className="dcb-submit-btn"
                    onClick={handleSubscribe}
                    disabled={isSubmitting}
                  >
                    {isSubmitting ? (
                      <>
                        <FaSpinner className="dcb-spinner" />
                        <span>Subscribing...</span>
                      </>
                    ) : (
                      <>
                        <FaRocket />
                        <span>Subscribe to Daily Updates</span>
                      </>
                    )}
                  </button>
                ) : (
                  <button 
                    className="dcb-submit-btn dcb-unsubscribe-btn"
                    onClick={handleUnsubscribe}
                    disabled={isSubmitting}
                  >
                    {isSubmitting ? (
                      <>
                        <FaSpinner className="dcb-spinner" />
                        <span>Processing...</span>
                      </>
                    ) : (
                      <>
                        <FaTimes />
                        <span>Unsubscribe from Updates</span>
                      </>
                    )}
                  </button>
                )}
              </div>

              {statusMsg && (
                <div className={`dcb-status-msg ${isError ? "error" : "success"} ${showStatusMsg ? "show" : ""}`}>
                  {isError ? (
                    <FaExclamationTriangle className="dcb-status-icon" />
                  ) : (
                    <FaCheck className="dcb-status-icon" />
                  )}
                  <span>{statusMsg}</span>
                </div>
              )}
            </div>
          </div>

          {/* Info Card */}
          <div className="dcb-card dcb-info-card">
            <div className="dcb-card-header">
              <FaInfoCircle className="dcb-card-icon" />
              <h2>About Our Newsletter</h2>
            </div>
            <div className="dcb-card-content">
              <p>
                The Daily Cyber Brief is sent every weekday morning. We respect your privacy
                and will never share your email address with third parties. Each newsletter includes
                an unsubscribe link for easy opt-out at any time.
              </p>
              <p>
                Our team of security experts curates the most important cybersecurity news and
                practical advice to help you protect your digital life and stay informed about
                the evolving threat landscape.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default DailyCyberBrief;
