// src/components/pages/PrivacyPolicy.js
import React, { useState, useEffect } from 'react';
import Footer from '../Footer';
import './PolicyPages.css';

const PrivacyPolicy = () => {
  const [showBackToTop, setShowBackToTop] = useState(false);

  // Function to handle printing
  const handlePrint = () => {
    window.print();
  };

  // Show/hide back to top button based on scroll position
  useEffect(() => {
    const handleScroll = () => {
      if (window.pageYOffset > 300) {
        setShowBackToTop(true);
      } else {
        setShowBackToTop(false);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);

  // Auto-scroll to section if hash is present in URL
  useEffect(() => {
    if (window.location.hash) {
      const id = window.location.hash.substring(1);
      const element = document.getElementById(id);
      if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
      }
    }
  }, []);

  const scrollToTop = () => {
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    });
  };

  // Sections for table of contents
  const sections = [
    { id: 'introduction', title: '1. Introduction' },
    { id: 'information', title: '2. Information We Collect' },
    { id: 'use', title: '3. How We Use Your Information' },
    { id: 'share', title: '4. How We Share Your Information' },
    { id: 'security', title: '5. Data Security' },
    { id: 'rights', title: '6. Your Data Rights' },
    { id: 'cookies', title: '7. Cookies and Similar Technologies' },
    { id: 'authentication', title: '8. Third-Party Authentication' },
    { id: 'children', title: '9. Children\'s Privacy' },
    { id: 'changes', title: '10. Changes to This Privacy Policy' },
    { id: 'contact', title: '11. Contact Us' },
  ];

  return (
    <div className="policy-container">
      <div className="policy-content">
        <h1>Privacy Policy</h1>
        <p className="policy-date">Last updated: March 7, 2025</p>
        
        {/* Table of Contents */}
        <div className="policy-toc">
          <div className="policy-toc-title">Table of Contents</div>
          <ul className="policy-toc-list">
            {sections.map((section) => (
              <li key={section.id}>
                <a href={`#${section.id}`}>{section.title}</a>
              </li>
            ))}
          </ul>
        </div>
        
        <section id="introduction" className="policy-section">
          <h2>1. Introduction</h2>
          <p>
            This Privacy Policy explains how Cert Games ("we", "us", or "our") collects, uses, and shares your information when you use our website and services at certgames.com.
          </p>
          <p>
            We take your privacy seriously and are committed to protecting your personal information. Please read this policy carefully to understand our practices regarding your data.
          </p>
        </section>
        
        <section id="information" className="policy-section">
          <h2>2. Information We Collect</h2>
          <p>We collect several types of information from and about users of our website, including:</p>
          <ul>
            <li><strong>Personal Information:</strong> This includes your name, email address, and username when you register for an account.</li>
            <li><strong>Authentication Information:</strong> When you sign in using Google or Apple authentication services, we receive basic profile information such as your name and email address.</li>
            <li><strong>Usage Data:</strong> Information about how you interact with our website, including tests taken, scores, achievements, and usage patterns.</li>
            <li><strong>Payment Information:</strong> When you purchase a subscription, payment information is processed by our payment provider. We do not store complete payment details on our servers.</li>
          </ul>
        </section>
        
        <section id="use" className="policy-section">
          <h2>3. How We Use Your Information</h2>
          <p>We use the information we collect to:</p>
          <ul>
            <li>Provide, maintain, and improve our services</li>
            <li>Process your account registration and maintain your account</li>
            <li>Track your progress, achievements, and leaderboard status</li>
            <li>Communicate with you about your account, updates, or support requests</li>
            <li>Personalize your experience and deliver relevant content</li>
          </ul>
        </section>
        
        <section id="share" className="policy-section">
          <h2>4. How We Share Your Information</h2>
          <p>We do not sell your personal information to third parties. We may share your information in the following circumstances:</p>
          <ul>
            <li>With service providers who perform services on our behalf (such as hosting providers and payment processors)</li>
            <li>To comply with legal obligations</li>
            <li>To protect and defend our rights and property</li>
            <li>With your consent or at your direction</li>
          </ul>
        </section>
        
        <section id="security" className="policy-section">
          <h2>5. Data Security</h2>
          <p>
            We implement appropriate security measures to protect your personal information from unauthorized access, alteration, disclosure, or destruction. However, no method of transmission over the Internet or electronic storage is 100% secure, and we cannot guarantee absolute security.
          </p>
        </section>
        
        <section id="rights" className="policy-section">
          <h2>6. Your Data Rights</h2>
          <p>Depending on your location, you may have certain rights regarding your personal information, including:</p>
          <ul>
            <li>Accessing your personal information</li>
            <li>Correcting inaccurate information</li>
            <li>Deleting your information</li>
            <li>Restricting or objecting to certain processing</li>
            <li>Requesting portability of your information</li>
          </ul>
          <p>To exercise these rights, please contact us using the information provided in the "Contact Us" section.</p>
        </section>
        
        <section id="cookies" className="policy-section">
          <h2>7. Cookies and Similar Technologies</h2>
          <p>
            We use cookies and similar tracking technologies to track activity on our website and hold certain information. You can instruct your browser to refuse all cookies or to indicate when a cookie is being sent.
          </p>
        </section>
        
        <section id="authentication" className="policy-section">
          <h2>8. Third-Party Authentication</h2>
          <p>
            Our service offers sign-in through Google and Apple authentication services. When you choose to sign in using these services:
          </p>
          <ul>
            <li>We receive basic profile information including your name and email address</li>
            <li>We do not receive your password or account details</li>
            <li>We store a unique identifier to recognize your account</li>
          </ul>
          <p>
            Your use of Google or Apple sign-in is also subject to their respective privacy policies:
          </p>
          <ul>
            <li><a href="https://policies.google.com/privacy" target="_blank" rel="noopener noreferrer">Google Privacy Policy</a></li>
            <li><a href="https://www.apple.com/legal/privacy/" target="_blank" rel="noopener noreferrer">Apple Privacy Policy</a></li>
          </ul>
        </section>
        
        <section id="children" className="policy-section">
          <h2>9. Children's Privacy</h2>
          <p>
            Our services are not intended for children under 13, and we do not knowingly collect personal information from children under 13. If you are a parent or guardian and believe that your child has provided us with personal information, please contact us.
          </p>
        </section>
        
        <section id="changes" className="policy-section">
          <h2>10. Changes to This Privacy Policy</h2>
          <p>
            We may update our Privacy Policy from time to time. We will notify you of any changes by posting the new Privacy Policy on this page and updating the "Last updated" date.
          </p>
        </section>
        
        <section id="contact" className="policy-section">
          <h2>11. Contact Us</h2>
          <p>
            If you have any questions about this Privacy Policy, please contact us at:
          </p>
          <p>
            Email: <a href="mailto:support@certgames.com">support@certgames.com</a>
          </p>
        </section>
        
        {/* Print button */}
        <div className="policy-actions">
          <button onClick={handlePrint} className="policy-print-btn">
            <span role="img" aria-label="print">🖨️</span> Print this document
          </button>
        </div>
      </div>
      
      {/* Back to top button */}
      {showBackToTop && (
        <button
          className={`back-to-top ${showBackToTop ? 'visible' : ''}`}
          onClick={scrollToTop}
          aria-label="Back to top"
        >
          ↑
        </button>
      )}
      
      <Footer />
    </div>
  );
};

export default PrivacyPolicy;
