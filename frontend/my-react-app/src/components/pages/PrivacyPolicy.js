// src/components/pages/PrivacyPolicy.js
import React from 'react';
import { Link } from 'react-router-dom';
import InfoNavbar from './Info/InfoNavbar';
import Footer from '../Footer';
import SEOHelmet from '../SEOHelmet';
import StructuredData from '../StructuredData';
import './PrivacyPolicy.css';

const PrivacyPolicy = () => {
  // Breadcrumb schema for SEO
  const breadcrumbSchema = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    "itemListElement": [
      {
        "@type": "ListItem",
        "position": 1,
        "name": "Home",
        "item": "https://certgames.com/"
      },
      {
        "@type": "ListItem",
        "position": 2,
        "name": "Privacy Policy",
        "item": "https://certgames.com/privacy"
      }
    ]
  };

  return (
    <>
      <SEOHelmet 
        title="Privacy Policy | CertGames"
        description="CertGames privacy policy. Learn how we protect your data while providing cybersecurity certification training."
        canonicalUrl="/privacy"
      />
      <StructuredData data={breadcrumbSchema} />
      <div className="privacy-policy-container">
        <InfoNavbar />
        
        <main className="privacy-content">
          <header>
            <h1>Privacy Policy</h1>
            <p>Last Updated: February 1, 2023</p>
          </header>
          
          <section className="privacy-section">
            <h2>1. Introduction</h2>
            <p>Welcome to CertGames ("we," "our," or "us"). We are committed to protecting your privacy and ensuring the security of your personal information. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use our website and services.</p>
            <p>By accessing or using CertGames, you consent to the practices described in this Privacy Policy. If you do not agree with our policies and practices, please do not use our services.</p>
          </section>
          
          <section className="privacy-section">
            <h2>2. Information We Collect</h2>
            
            <h3>2.1 Information You Provide</h3>
            <p>We collect information that you voluntarily provide when using our services, including:</p>
            <ul>
              <li>Account information: name, email address, username, password</li>
              <li>Profile information: professional background, certifications, avatar</li>
              <li>Payment information: billing details, transaction history</li>
              <li>User-generated content: responses to practice questions, notes, progress data</li>
              <li>Communications: messages sent to our support team or through our contact forms</li>
            </ul>
            
            <h3>2.2 Automatically Collected Information</h3>
            <p>When you use our services, we may automatically collect certain information, including:</p>
            <ul>
              <li>Device information: IP address, browser type, operating system</li>
              <li>Usage data: pages visited, features used, time spent on platform</li>
              <li>Performance data: interaction with questions, test scores, study patterns</li>
              <li>Cookies and similar technologies: as described in our Cookie Policy</li>
            </ul>
          </section>
          
          <section className="privacy-section">
            <h2>3. How We Use Your Information</h2>
            <p>We use the information we collect for various purposes, including to:</p>
            <ul>
              <li>Provide, maintain, and improve our services</li>
              <li>Process your subscriptions and transactions</li>
              <li>Create and manage your account</li>
              <li>Track your progress and personalize your learning experience</li>
              <li>Respond to your inquiries and provide customer support</li>
              <li>Send you updates, promotional materials, and other communications</li>
              <li>Analyze usage patterns to enhance our services</li>
              <li>Ensure the security and integrity of our platform</li>
              <li>Comply with legal obligations</li>
            </ul>
          </section>
          
          <section className="privacy-section">
            <h2>4. Sharing of Your Information</h2>
            <p>We may share your information with third parties in the following circumstances:</p>
            <ul>
              <li>Service providers: Companies that assist us in providing our services (e.g., payment processors, hosting providers)</li>
              <li>Business transfers: In connection with a merger, acquisition, or sale of assets</li>
              <li>Legal requirements: To comply with applicable laws, regulations, or legal processes</li>
              <li>Protection: To protect our rights, property, or the safety of our users or others</li>
            </ul>
            <p>We do not sell or rent your personal information to third parties for their marketing purposes without your explicit consent.</p>
          </section>
          
          <section className="privacy-section">
            <h2>5. Data Security</h2>
            <p>We implement appropriate technical and organizational measures to protect your personal information from unauthorized access, disclosure, alteration, or destruction. However, no method of transmission over the Internet or electronic storage is 100% secure, and we cannot guarantee absolute security.</p>
          </section>
          
          <section className="privacy-section">
            <h2>6. Your Rights and Choices</h2>
            <p>Depending on your location, you may have certain rights regarding your personal information, including:</p>
            <ul>
              <li>Access: Request access to your personal information</li>
              <li>Correction: Update or correct inaccurate information</li>
              <li>Deletion: Request deletion of your personal information</li>
              <li>Restriction: Request restriction of processing of your information</li>
              <li>Data portability: Request transfer of your information</li>
              <li>Object: Object to the processing of your information</li>
            </ul>
            <p>To exercise any of these rights, please contact us at <a href="mailto:privacy@certgames.com">privacy@certgames.com</a>.</p>
          </section>
          
          <section className="privacy-section">
            <h2>7. International Data Transfers</h2>
            <p>Your information may be transferred to and processed in countries other than the one in which you reside. These countries may have different data protection laws than your country of residence. We take appropriate measures to ensure that your personal information receives an adequate level of protection wherever it is processed.</p>
          </section>
          
          <section className="privacy-section">
            <h2>8. Children's Privacy</h2>
            <p>Our services are not directed to children under the age of 16. We do not knowingly collect personal information from children under 16. If you believe we might have any information from or about a child under 16, please contact us at <a href="mailto:privacy@certgames.com">privacy@certgames.com</a>.</p>
          </section>
          
          <section className="privacy-section">
            <h2>9. Changes to This Privacy Policy</h2>
            <p>We may update our Privacy Policy from time to time. We will notify you of any changes by posting the new Privacy Policy on this page and updating the "Last Updated" date. You are advised to review this Privacy Policy periodically for any changes.</p>
          </section>
          
          <section className="privacy-section">
            <h2>10. Contact Us</h2>
            <p>If you have any questions or concerns about this Privacy Policy or our privacy practices, please contact us at:</p>
            <p>Email: <a href="mailto:privacy@certgames.com">privacy@certgames.com</a></p>
            <p>Address: 123 Certification Way, Suite 456, Tech City, CA 98765</p>
          </section>
        </main>
        
        <nav className="privacy-navigation">
          <Link to="/terms" className="privacy-nav-link">View Terms of Service</Link>
          <Link to="/contact" className="privacy-nav-link">Contact Us</Link>
        </nav>
        
        <Footer />
      </div>
    </>
  );
};

export default PrivacyPolicy;
