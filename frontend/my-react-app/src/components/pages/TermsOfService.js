// src/components/pages/TermsOfService.js
import React, { useState, useEffect } from 'react';
import Footer from '../Footer';
import './LegalPages.css';
import { FaAngleUp, FaPrint, FaExternalLinkAlt, FaBook, FaArrowLeft, FaInfoCircle, FaScroll } from 'react-icons/fa';

const TermsOfService = () => {
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
    { id: 'acceptance', title: '1. Acceptance of Terms' },
    { id: 'changes', title: '2. Changes to Terms' },
    { id: 'registration', title: '3. Account Registration' },
    { id: 'subscription', title: '4. Subscription and Payment' },
    { id: 'conduct', title: '5. User Conduct' },
    { id: 'ip', title: '6. Intellectual Property' },
    { id: 'third-party', title: '7. Third-Party Services' },
    { id: 'disclaimer', title: '8. Disclaimer of Warranties' },
    { id: 'liability', title: '9. Limitation of Liability' },
    { id: 'termination', title: '10. Termination' },
    { id: 'governing-law', title: '11. Governing Law' },
    { id: 'contact', title: '12. Contact Us' },
  ];

  return (
    <div className="legal-container">
      <div className="legal-header-accent"></div>
      <div className="legal-content">
        <button className="legal-back-button" onClick={goBack}>
          <FaArrowLeft /> Back
        </button>
        
        <div className="legal-document-header">
          <FaScroll className="legal-header-icon" />
          <div className="legal-title-wrapper">
            <h1 className="legal-title">Terms of Service</h1>
            <p className="legal-date">Last updated: March 7, 2025</p>
          </div>
        </div>
        
        <div className="legal-summary-card">
          <div className="legal-summary-header">
            <FaInfoCircle className="legal-summary-icon" />
            <h3>Document Summary</h3>
          </div>
          <p>
            This document outlines the terms governing your use of our services, including your responsibilities, 
            our obligations, subscription terms, and your rights. By using our platform, you agree to these terms.
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
          <section id="acceptance" className="legal-section">
            <h2>1. Acceptance of Terms</h2>
            <div className="legal-section-content">
              <p>
                Welcome to Cert Games! These Terms of Service ("Terms") govern your access to and use of certgames.com and all related services (collectively, the "Services"). By accessing or using our Services, you agree to be bound by these Terms. If you do not agree to these Terms, you may not access or use the Services.
              </p>
            </div>
          </section>
          
          <section id="changes" className="legal-section">
            <h2>2. Changes to Terms</h2>
            <div className="legal-section-content">
              <p>
                We may modify these Terms at any time. We will provide notice of any material changes by posting the updated Terms on our website and updating the "Last updated" date. Your continued use of the Services after any such changes constitutes your acceptance of the new Terms.
              </p>
            </div>
          </section>
          
          <section id="registration" className="legal-section">
            <h2>3. Account Registration</h2>
            <div className="legal-section-content">
              <p>
                To access certain features of our Services, you must register for an account. You may register directly or through Google or Apple authentication services. You agree to provide accurate, current, and complete information during the registration process and to update such information to keep it accurate, current, and complete.
              </p>
              <p>
                You are responsible for safeguarding your account credentials and for all activities that occur under your account. You agree to notify us immediately of any unauthorized use of your account.
              </p>
            </div>
          </section>
          
          <section id="subscription" className="legal-section">
            <h2>4. Subscription and Payment</h2>
            <div className="legal-section-content">
              <p>
                Some aspects of our Services are available on a subscription basis. By subscribing, you agree to pay the applicable fees. Subscriptions automatically renew unless canceled before the renewal date.
              </p>
              <p>
                All payments are processed through third-party payment processors. Your use of their services is subject to their terms and conditions.
              </p>
              <div className="legal-callout">
                <strong>Note:</strong> You can cancel your subscription at any time through your account settings. Refunds are provided in accordance with our refund policy.
              </div>
            </div>
          </section>
          
          <section id="conduct" className="legal-section">
            <h2>5. User Conduct</h2>
            <div className="legal-section-content">
              <p>
                You agree not to:
              </p>
              <ul className="legal-list">
                <li>Use the Services in any manner that could disable, overburden, damage, or impair the Services</li>
                <li>Use any robot, spider, or other automatic device to access the Services</li>
                <li>Introduce any viruses, trojan horses, worms, or other malicious code</li>
                <li>Attempt to gain unauthorized access to any part of the Services</li>
                <li>Interfere with any other user's use of the Services</li>
                <li>Use the Services for any illegal or unauthorized purpose</li>
                <li>Impersonate or attempt to impersonate Cert Games, a Cert Games employee, another user, or any other person or entity</li>
                <li>Engage in any other conduct that restricts or inhibits anyone's use of the Services</li>
              </ul>
            </div>
          </section>
          
          <section id="ip" className="legal-section">
            <h2>6. Intellectual Property</h2>
            <div className="legal-section-content">
              <p>
                The Services and all content, features, and functionality (including but not limited to text, graphics, software, images, videos, and audio) are owned by Cert Games or its licensors and are protected by copyright, trademark, and other intellectual property laws.
              </p>
              <p>
                We grant you a limited, non-exclusive, non-transferable, and revocable license to use the Services for your personal, non-commercial use only.
              </p>
            </div>
          </section>
          
          <section id="third-party" className="legal-section">
            <h2>7. Third-Party Services</h2>
            <div className="legal-section-content">
              <p>
                Our Services may contain links to third-party websites or services that are not owned or controlled by Cert Games. We have no control over, and assume no responsibility for, the content, privacy policies, or practices of any third-party websites or services.
              </p>
              <p>
                When you use Google or Apple authentication, your use is subject to their terms of service and privacy policies:
              </p>
              <ul className="legal-list">
                <li>
                  <a href="https://policies.google.com/terms" target="_blank" rel="noopener noreferrer">
                    Google Terms of Service <FaExternalLinkAlt className="legal-external-link-icon" />
                  </a>
                </li>
                <li>
                  <a href="https://www.apple.com/legal/internet-services/itunes/us/terms.html" target="_blank" rel="noopener noreferrer">
                    Apple Terms of Service <FaExternalLinkAlt className="legal-external-link-icon" />
                  </a>
                </li>
              </ul>
            </div>
          </section>
          
          <section id="disclaimer" className="legal-section">
            <h2>8. Disclaimer of Warranties</h2>
            <div className="legal-section-content">
              <p className="legal-important">
                THE SERVICES ARE PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED. TO THE FULLEST EXTENT PERMISSIBLE UNDER APPLICABLE LAW, WE DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.
              </p>
            </div>
          </section>
          
          <section id="liability" className="legal-section">
            <h2>9. Limitation of Liability</h2>
            <div className="legal-section-content">
              <p className="legal-important">
                TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL CERT GAMES BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, INCLUDING WITHOUT LIMITATION, LOSS OF PROFITS, DATA, USE, GOODWILL, OR OTHER INTANGIBLE LOSSES.
              </p>
            </div>
          </section>
          
          <section id="termination" className="legal-section">
            <h2>10. Termination</h2>
            <div className="legal-section-content">
              <p>
                We may terminate or suspend your account and access to the Services immediately, without prior notice or liability, for any reason whatsoever, including without limitation if you breach these Terms.
              </p>
              <p>
                Upon termination, your right to use the Services will immediately cease. All provisions of the Terms which by their nature should survive termination shall survive termination.
              </p>
            </div>
          </section>
          
          <section id="governing-law" className="legal-section">
            <h2>11. Governing Law</h2>
            <div className="legal-section-content">
              <p>
                These Terms shall be governed by and construed in accordance with the laws of the United States, without regard to its conflict of law provisions.
              </p>
              <p>
                Any disputes arising under or in connection with these Terms shall be subject to the exclusive jurisdiction of the courts located within the United States.
              </p>
            </div>
          </section>
          
          <section id="contact" className="legal-section">
            <h2>12. Contact Us</h2>
            <div className="legal-section-content">
              <p>
                If you have any questions about these Terms, please contact us at:
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

export default TermsOfService;
