// src/components/pages/PrivacyPolicy.js
import React from 'react';
import Footer from '../Footer';
import './PolicyPages.css';

const PrivacyPolicy = () => {
  return (
    <div className="policy-container">
      <div className="policy-content">
        <h1>Privacy Policy</h1>
        <p className="policy-date">Last updated: March 7, 2025</p>
        
        <section className="policy-section">
          <h2>1. Introduction</h2>
          <p>
            This Privacy Policy explains how Cert Games ("we", "us", or "our") collects, uses, and shares your information when you use our website and services at certgames.com.
          </p>
          <p>
            We take your privacy seriously and are committed to protecting your personal information. Please read this policy carefully to understand our practices regarding your data.
          </p>
        </section>
        
        <section className="policy-section">
          <h2>2. Information We Collect</h2>
          <p>We collect several types of information from and about users of our website, including:</p>
          <ul>
            <li><strong>Personal Information:</strong> This includes your name, email address, and username when you register for an account.</li>
            <li><strong>Authentication Information:</strong> When you sign in using Google or Apple authentication services, we receive basic profile information such as your name and email address.</li>
            <li><strong>Usage Data:</strong> Information about how you interact with our website, including tests taken, scores, achievements, and usage patterns.</li>
            <li><strong>Payment Information:</strong> When you purchase a subscription, payment information is processed by our payment provider. We do not store complete payment details on our servers.</li>
          </ul>
        </section>
        
        <section className="policy-section">
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
        
        <section className="policy-section">
          <h2>4. How We Share Your Information</h2>
          <p>We do not sell your personal information to third parties. We may share your information in the following circumstances:</p>
          <ul>
            <li>With service providers who perform services on our behalf (such as hosting providers and payment processors)</li>
            <li>To comply with legal obligations</li>
            <li>To protect and defend our rights and property</li>
            <li>With your consent or at your direction</li>
          </ul>
        </section>
        
        <section className="policy-section">
          <h2>5. Data Security</h2>
          <p>
            We implement appropriate security measures to protect your personal information from unauthorized access, alteration, disclosure, or destruction. However, no method of transmission over the Internet or electronic storage is 100% secure, and we cannot guarantee absolute security.
          </p>
        </section>
        
        <section className="policy-section">
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
        
        <section className="policy-section">
          <h2>7. Cookies and Similar Technologies</h2>
          <p>
            We use cookies and similar tracking technologies to track activity on our website and hold certain information. You can instruct your browser to refuse all cookies or to indicate when a cookie is being sent.
          </p>
        </section>
        
        <section className="policy-section">
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
        
        <section className="policy-section">
          <h2>9. Children's Privacy</h2>
          <p>
            Our services are not intended for children under 13, and we do not knowingly collect personal information from children under 13. If you are a parent or guardian and believe that your child has provided us with personal information, please contact us.
          </p>
        </section>
        
        <section className="policy-section">
          <h2>10. Changes to This Privacy Policy</h2>
          <p>
            We may update our Privacy Policy from time to time. We will notify you of any changes by posting the new Privacy Policy on this page and updating the "Last updated" date.
          </p>
        </section>
        
        <section className="policy-section">
          <h2>11. Contact Us</h2>
          <p>
            If you have any questions about this Privacy Policy, please contact us at:
          </p>
          <p>
            Email: support@certgames.com
          </p>
        </section>
      </div>
      
      <Footer />
    </div>
  );
};

export default PrivacyPolicy;
