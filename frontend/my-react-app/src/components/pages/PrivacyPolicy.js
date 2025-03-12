// src/components/pages/PrivacyPolicy.js
import React, { useState, useEffect } from 'react';
import Footer from '../Footer';
import SEOHelmet from '../SEOHelmet';
import './LegalPages.css';
import { FaAngleUp, FaPrint, FaExternalLinkAlt, FaBook, FaArrowLeft, FaInfoCircle, FaLock } from 'react-icons/fa';

const PrivacyPolicy = () => {
  const [showBackToTop, setShowBackToTop] = useState(false);
  const [activeSection, setActiveSection] = useState('');

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
      
      // Update active section based on scroll position
      const sections = document.querySelectorAll('.legal-section');
      let currentSection = '';
      
      sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.offsetHeight;
        
        if (window.pageYOffset >= sectionTop - 100 && 
            window.pageYOffset < sectionTop + sectionHeight - 100) {
          currentSection = section.id;
        }
      });
      
      if (currentSection !== activeSection) {
        setActiveSection(currentSection);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, [activeSection]);

  // Auto-scroll to section if hash is present in URL
  useEffect(() => {
    if (window.location.hash) {
      const id = window.location.hash.substring(1);
      const element = document.getElementById(id);
      if (element) {
        setTimeout(() => {
          element.scrollIntoView({ behavior: 'smooth' });
        }, 500);
      }
    }
  }, []);

  const scrollToTop = () => {
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    });
  };

  // Navigate back
  const goBack = () => {
    window.history.back();
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
    { id: 'international', title: '10. International Data Transfers' },
    { id: 'retention', title: '11. Data Retention' },
    { id: 'changes', title: '12. Changes to This Privacy Policy' },
    { id: 'contact', title: '13. Contact Us' },
  ];

  return (
    <div className="legal-container">
      <div className="legal-header-accent"></div>
      <div className="legal-content">
        <button className="legal-back-button" onClick={goBack}>
          <FaArrowLeft /> Back
        </button>
        
        <div className="legal-document-header">
          <FaLock className="legal-header-icon" />
          <div className="legal-title-wrapper">
            <h1 className="legal-title">Privacy Policy</h1>
            <p className="legal-date">Last updated: March 7, 2025</p>
          </div>
        </div>
        
        <div className="legal-summary-card">
          <div className="legal-summary-header">
            <FaInfoCircle className="legal-summary-icon" />
            <h3>Document Summary</h3>
          </div>
          <p>
            This Privacy Policy explains how we collect, use, and protect your personal information. 
            We value your privacy and are committed to transparency about our data practices.
          </p>
        </div>
        
        {/* Table of Contents */}
        <div className="legal-toc-container">
          <div className="legal-toc">
            <div className="legal-toc-header">
              <FaBook className="legal-toc-icon" />
              <div className="legal-toc-title">Table of Contents</div>
            </div>
            <ul className="legal-toc-list">
              {sections.map((section) => (
                <li key={section.id} className={activeSection === section.id ? 'legal-active-section' : ''}>
                  <a href={`#${section.id}`}>{section.title}</a>
                </li>
              ))}
            </ul>
          </div>
        </div>
        
        <div className="legal-document-body">
          <section id="introduction" className="legal-section">
            <h2>1. Introduction</h2>
            <div className="legal-section-content">
              <p>
                This Privacy Policy explains how Cert Games ("we", "us", or "our") collects, uses, and shares your information when you use our website and services at certgames.com.
              </p>
              <p>
                We take your privacy seriously and are committed to protecting your personal information. Please read this policy carefully to understand our practices regarding your data.
              </p>
            </div>
          </section>
          
          <section id="information" className="legal-section">
            <h2>2. Information We Collect</h2>
            <div className="legal-section-content">
              <p>We collect several types of information from and about users of our website, including:</p>
              <ul className="legal-list">
                <li><strong>Personal Information:</strong> This includes your name, email address, and username when you register for an account.</li>
                <li><strong>Authentication Information:</strong> When you sign in using Google or Apple authentication services, we receive basic profile information such as your name and email address.</li>
                <li><strong>Usage Data:</strong> Information about how you interact with our website, including tests taken, scores, achievements, and usage patterns.</li>
                <li><strong>Payment Information:</strong> When you purchase a subscription, payment information is processed by our payment provider. We do not store complete payment details on our servers.</li>
                <li><strong>Device Information:</strong> We may collect information about your device, including your IP address, browser type, operating system, and other technical details.</li>
              </ul>
            </div>
          </section>
          
          <section id="use" className="legal-section">
            <h2>3. How We Use Your Information</h2>
            <div className="legal-section-content">
              <p>We use the information we collect to:</p>
              <ul className="legal-list">
                <li>Provide, maintain, and improve our services</li>
                <li>Process your account registration and maintain your account</li>
                <li>Track your progress, achievements, and leaderboard status</li>
                <li>Communicate with you about your account, updates, or support requests</li>
                <li>Personalize your experience and deliver relevant content</li>
                <li>Process transactions and manage your subscription</li>
                <li>Analyze usage patterns to improve our website and services</li>
                <li>Protect the security and integrity of our platform</li>
              </ul>
            </div>
          </section>
          
          <section id="share" className="legal-section">
            <h2>4. How We Share Your Information</h2>
            <div className="legal-section-content">
              <p>We do not sell your personal information to third parties. We may share your information in the following circumstances:</p>
              <ul className="legal-list">
                <li>With service providers who perform services on our behalf (such as hosting providers and payment processors)</li>
                <li>To comply with legal obligations</li>
                <li>To protect and defend our rights and property</li>
                <li>With your consent or at your direction</li>
              </ul>
              <div className="legal-callout">
                <strong>Note:</strong> When information is shared with service providers, we ensure they have appropriate data protection measures in place.
              </div>
            </div>
          </section>
          
          <section id="security" className="legal-section">
            <h2>5. Data Security</h2>
            <div className="legal-section-content">
              <p>
                We implement appropriate security measures to protect your personal information from unauthorized access, alteration, disclosure, or destruction. These measures include:
              </p>
              <ul className="legal-list">
                <li>Encryption of sensitive data in transit and at rest</li>
                <li>Regular security assessments and testing</li>
                <li>Access controls and authentication requirements</li>
                <li>Monitoring for suspicious activities</li>
              </ul>
              <p>
                However, no method of transmission over the Internet or electronic storage is 100% secure, and we cannot guarantee absolute security.
              </p>
            </div>
          </section>
          
          <section id="rights" className="legal-section">
            <h2>6. Your Data Rights</h2>
            <div className="legal-section-content">
              <p>Depending on your location, you may have certain rights regarding your personal information, including:</p>
              <ul className="legal-list">
                <li>Accessing your personal information</li>
                <li>Correcting inaccurate information</li>
                <li>Deleting your information</li>
                <li>Restricting or objecting to certain processing</li>
                <li>Requesting portability of your information</li>
                <li>Withdrawing consent (where processing is based on consent)</li>
              </ul>
              <p>To exercise these rights, please contact us using the information provided in the "Contact Us" section.</p>
            </div>
          </section>
          
          <section id="cookies" className="legal-section">
            <h2>7. Cookies and Similar Technologies</h2>
            <div className="legal-section-content">
              <p>
                We use cookies and similar tracking technologies to track activity on our website and hold certain information. Cookies are small data files that are placed on your device when you visit our website.
              </p>
              <p>
                We use cookies for the following purposes:
              </p>
              <ul className="legal-list">
                <li>To maintain your session and authentication status</li>
                <li>To remember your preferences and settings</li>
                <li>To analyze how our website is used</li>
                <li>To personalize your experience</li>
              </ul>
              <p>
                You can instruct your browser to refuse all cookies or to indicate when a cookie is being sent. However, if you do not accept cookies, some parts of our website may not function properly.
              </p>
            </div>
          </section>
          
          <section id="authentication" className="legal-section">
            <h2>8. Third-Party Authentication</h2>
            <div className="legal-section-content">
              <p>
                Our service offers sign-in through Google and Apple authentication services. When you choose to sign in using these services:
              </p>
              <ul className="legal-list">
                <li>We receive basic profile information including your name and email address</li>
                <li>We do not receive your password or account details</li>
                <li>We store a unique identifier to recognize your account</li>
              </ul>
              <p>
                Your use of Google or Apple sign-in is also subject to their respective privacy policies:
              </p>
              <ul className="legal-list">
                <li>
                  <a href="https://policies.google.com/privacy" target="_blank" rel="noopener noreferrer">
                    Google Privacy Policy <FaExternalLinkAlt className="legal-external-link-icon" />
                  </a>
                </li>
                <li>
                  <a href="https://www.apple.com/legal/privacy/" target="_blank" rel="noopener noreferrer">
                    Apple Privacy Policy <FaExternalLinkAlt className="legal-external-link-icon" />
                  </a>
                </li>
              </ul>
            </div>
          </section>
          
          <section id="children" className="legal-section">
            <h2>9. Children's Privacy</h2>
            <div className="legal-section-content">
              <p>
                Our services are not intended for children under 13, and we do not knowingly collect personal information from children under 13. If you are a parent or guardian and believe that your child has provided us with personal information, please contact us so that we can take appropriate steps.
              </p>
            </div>
          </section>
          
          <section id="international" className="legal-section">
            <h2>10. International Data Transfers</h2>
            <div className="legal-section-content">
              <p>
                Your information may be transferred to and processed in countries other than the one in which you reside. These countries may have data protection laws that are different from the laws of your country.
              </p>
              <p>
                Whenever we transfer your information, we take appropriate safeguards to ensure that your information remains protected in accordance with this Privacy Policy and applicable data protection laws.
              </p>
            </div>
          </section>
          
          <section id="retention" className="legal-section">
            <h2>11. Data Retention</h2>
            <div className="legal-section-content">
              <p>
                We retain your personal information for as long as necessary to fulfill the purposes for which we collected it, including to satisfy any legal, accounting, or reporting requirements.
              </p>
              <p>
                To determine the appropriate retention period, we consider the amount, nature, and sensitivity of the personal information, the potential risk of harm from unauthorized use or disclosure, and the applicable legal requirements.
              </p>
              <p>
                When we no longer need your personal information, we will securely delete or anonymize it.
              </p>
            </div>
          </section>
          
          <section id="changes" className="legal-section">
            <h2>12. Changes to This Privacy Policy</h2>
            <div className="legal-section-content">
              <p>
                We may update our Privacy Policy from time to time. We will notify you of any changes by posting the new Privacy Policy on this page and updating the "Last updated" date.
              </p>
              <p>
                We encourage you to review this Privacy Policy periodically for any changes. Changes to this Privacy Policy are effective when they are posted on this page.
              </p>
            </div>
          </section>
          
          <section id="contact" className="legal-section">
            <h2>13. Contact Us</h2>
            <div className="legal-section-content">
              <p>
                If you have any questions about this Privacy Policy, please contact us at:
              </p>
              <div className="legal-contact-info">
                <p>
                  Email: <a href="mailto:support@certgames.com">support@certgames.com</a>
                </p>
              </div>
            </div>
          </section>
        </div>
        
        {/* Print button */}
        <div className="legal-actions">
          <button onClick={handlePrint} className="legal-print-btn">
            <FaPrint className="legal-print-icon" /> Print this document
          </button>
        </div>
      </div>
      
      {/* Back to top button */}
      <button
        className={`legal-back-to-top ${showBackToTop ? 'visible' : ''}`}
        onClick={scrollToTop}
        aria-label="Back to top"
      >
        <FaAngleUp />
      </button>
      
      <Footer />
    </div>
  );
};

export default PrivacyPolicy;
