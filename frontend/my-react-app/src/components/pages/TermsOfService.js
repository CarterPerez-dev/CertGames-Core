// src/components/pages/TermsOfService.js
import React, { useState, useEffect } from 'react';
import Footer from '../Footer';
import './PolicyPages.css';

const TermsOfService = () => {
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
    <div className="policy-container">
      <div className="policy-content">
        <h1>Terms of Service</h1>
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
        
        <section id="acceptance" className="policy-section">
          <h2>1. Acceptance of Terms</h2>
          <p>
            Welcome to Cert Games! These Terms of Service ("Terms") govern your access to and use of certgames.com and all related services (collectively, the "Services"). By accessing or using our Services, you agree to be bound by these Terms. If you do not agree to these Terms, you may not access or use the Services.
          </p>
        </section>
        
        <section id="changes" className="policy-section">
          <h2>2. Changes to Terms</h2>
          <p>
            We may modify these Terms at any time. We will provide notice of any material changes by posting the updated Terms on our website and updating the "Last updated" date. Your continued use of the Services after any such changes constitutes your acceptance of the new Terms.
          </p>
        </section>
        
        <section id="registration" className="policy-section">
          <h2>3. Account Registration</h2>
          <p>
            To access certain features of our Services, you must register for an account. You may register directly or through Google or Apple authentication services. You agree to provide accurate, current, and complete information during the registration process and to update such information to keep it accurate, current, and complete.
          </p>
          <p>
            You are responsible for safeguarding your account credentials and for all activities that occur under your account. You agree to notify us immediately of any unauthorized use of your account.
          </p>
        </section>
        
        <section id="subscription" className="policy-section">
          <h2>4. Subscription and Payment</h2>
          <p>
            Some aspects of our Services are available on a subscription basis. By subscribing, you agree to pay the applicable fees. Subscriptions automatically renew unless canceled before the renewal date.
          </p>
          <p>
            All payments are processed through third-party payment processors. Your use of their services is subject to their terms and conditions.
          </p>
        </section>
        
        <section id="conduct" className="policy-section">
          <h2>5. User Conduct</h2>
          <p>
            You agree not to:
          </p>
          <ul>
            <li>Use the Services in any manner that could disable, overburden, damage, or impair the Services</li>
            <li>Use any robot, spider, or other automatic device to access the Services</li>
            <li>Introduce any viruses, trojan horses, worms, or other malicious code</li>
            <li>Attempt to gain unauthorized access to any part of the Services</li>
            <li>Interfere with any other user's use of the Services</li>
            <li>Use the Services for any illegal or unauthorized purpose</li>
          </ul>
        </section>
        
        <section id="ip" className="policy-section">
          <h2>6. Intellectual Property</h2>
          <p>
            The Services and all content, features, and functionality (including but not limited to text, graphics, software, images, videos, and audio) are owned by Cert Games or its licensors and are protected by copyright, trademark, and other intellectual property laws.
          </p>
          <p>
            We grant you a limited, non-exclusive, non-transferable, and revocable license to use the Services for your personal, non-commercial use only.
          </p>
        </section>
        
        <section id="third-party" className="policy-section">
          <h2>7. Third-Party Services</h2>
          <p>
            Our Services may contain links to third-party websites or services that are not owned or controlled by Cert Games. We have no control over, and assume no responsibility for, the content, privacy policies, or practices of any third-party websites or services.
          </p>
          <p>
            When you use Google or Apple authentication, your use is subject to their terms of service and privacy policies:
          </p>
          <ul>
            <li><a href="https://policies.google.com/terms" target="_blank" rel="noopener noreferrer">Google Terms of Service</a></li>
            <li><a href="https://www.apple.com/legal/internet-services/itunes/us/terms.html" target="_blank" rel="noopener noreferrer">Apple Terms of Service</a></li>
          </ul>
        </section>
        
        <section id="disclaimer" className="policy-section">
          <h2>8. Disclaimer of Warranties</h2>
          <p>
            THE SERVICES ARE PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED. TO THE FULLEST EXTENT PERMISSIBLE UNDER APPLICABLE LAW, WE DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.
          </p>
        </section>
        
        <section id="liability" className="policy-section">
          <h2>9. Limitation of Liability</h2>
          <p>
            TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL CERT GAMES BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, INCLUDING WITHOUT LIMITATION, LOSS OF PROFITS, DATA, USE, GOODWILL, OR OTHER INTANGIBLE LOSSES.
          </p>
        </section>
        
        <section id="termination" className="policy-section">
          <h2>10. Termination</h2>
          <p>
            We may terminate or suspend your account and access to the Services immediately, without prior notice or liability, for any reason whatsoever, including without limitation if you breach these Terms.
          </p>
          <p>
            Upon termination, your right to use the Services will immediately cease. All provisions of the Terms which by their nature should survive termination shall survive termination.
          </p>
        </section>
        
        <section id="governing-law" className="policy-section">
          <h2>11. Governing Law</h2>
          <p>
            These Terms shall be governed by and construed in accordance with the laws of the United States, without regard to its conflict of law provisions.
          </p>
        </section>
        
        <section id="contact" className="policy-section">
          <h2>12. Contact Us</h2>
          <p>
            If you have any questions about these Terms, please contact us at:
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

export default TermsOfService;
