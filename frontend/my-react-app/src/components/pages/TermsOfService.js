// src/components/pages/TermsOfService.js
import React from 'react';
import { Link } from 'react-router-dom';
import InfoNavbar from './Info/InfoNavbar';
import Footer from '../Footer';
import SEOHelmet from '../SEOHelmet';
import StructuredData from '../StructuredData';
import './LegalPages.css';

const TermsOfService = () => {
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
        "name": "Terms of Service",
        "item": "https://certgames.com/terms"
      }
    ]
  };

  return (
    <>
      <SEOHelmet 
        title="Terms of Service | CertGames"
        description="CertGames terms of service. Review our terms and conditions for using our cybersecurity certification training platform."
        canonicalUrl="/terms"
      />
      <StructuredData data={breadcrumbSchema} />
      <div className="terms-container">
        <InfoNavbar />
        
        <main className="terms-content">
          <header>
            <h1>Terms of Service</h1>
            <p>Last Updated: February 1, 2023</p>
          </header>
          
          <section className="terms-section">
            <h2>1. Agreement to Terms</h2>
            <p>By accessing or using CertGames services, you agree to be bound by these Terms of Service. If you do not agree to these terms, please do not use our platform.</p>
            <p>These Terms of Service ("Terms") govern your access to and use of the CertGames website, applications, and services (collectively, the "Services") provided by CertGames ("we," "us," or "our").</p>
          </section>
          
          <section className="terms-section">
            <h2>2. Eligibility</h2>
            <p>You must be at least 16 years old to use our Services. By using our Services, you represent and warrant that you meet this eligibility requirement. If you are using the Services on behalf of an organization, you represent and warrant that you have the authority to bind that organization to these Terms.</p>
          </section>
          
          <section className="terms-section">
            <h2>3. Accounts and Registration</h2>
            <p>To access certain features of our Services, you may need to create an account. When you create an account, you must provide accurate and complete information. You are solely responsible for the activity that occurs on your account, and you must keep your account password secure. You must notify us immediately of any breach of security or unauthorized use of your account.</p>
            <p>We reserve the right to suspend or terminate your account if any information provided proves to be inaccurate, false, or outdated.</p>
          </section>
          
          <section className="terms-section">
            <h2>4. Subscriptions and Payments</h2>
            <h3>4.1 Subscription Plans</h3>
            <p>We offer subscription-based access to our Services. Details of available subscription plans, fees, and features are provided on our website. We reserve the right to modify our subscription plans, pricing, and features at any time.</p>
            
            <h3>4.2 Payment Terms</h3>
            <p>By subscribing to our Services, you agree to pay the applicable subscription fees. All payments are non-refundable except as expressly provided in these Terms or as required by applicable law. Subscription fees are charged at the beginning of each billing period.</p>
            
            <h3>4.3 Automatic Renewal</h3>
            <p>Unless you cancel your subscription before the end of the current billing period, your subscription will automatically renew, and you authorize us to charge your payment method for the renewal term.</p>
            
            <h3>4.4 Cancellation</h3>
            <p>You may cancel your subscription at any time through your account settings or by contacting our support team. Upon cancellation, you will continue to have access to the Services until the end of your current billing period.</p>
          </section>
          
          <section className="terms-section">
            <h2>5. Intellectual Property Rights</h2>
            <h3>5.1 Our Intellectual Property</h3>
            <p>All content, features, and functionality of our Services, including but not limited to text, graphics, logos, icons, images, audio clips, video clips, data compilations, and software, are owned by us, our licensors, or other providers and are protected by copyright, trademark, patent, trade secret, and other intellectual property laws.</p>
            
            <h3>5.2 Limited License</h3>
            <p>Subject to these Terms, we grant you a limited, non-exclusive, non-transferable, and revocable license to access and use our Services for your personal, non-commercial use. You may not copy, modify, distribute, sell, or lease any part of our Services or included software.</p>
          </section>
          
          <section className="terms-section">
            <h2>6. User Conduct</h2>
            <p>You agree not to use our Services to:</p>
            <ul>
              <li>Violate any applicable law or regulation</li>
              <li>Infringe upon or violate our intellectual property rights or the intellectual property rights of others</li>
              <li>Transmit any material that is defamatory, offensive, or otherwise objectionable</li>
              <li>Interfere with or disrupt the Services or servers or networks connected to the Services</li>
              <li>Attempt to gain unauthorized access to any portion of the Services</li>
              <li>Collect or store personal data about other users without their consent</li>
              <li>Impersonate any person or entity, or falsely state or otherwise misrepresent your affiliation with a person or entity</li>
              <li>Upload, post, or otherwise transmit any content that contains software viruses or any other computer code designed to disrupt, damage, or limit the functionality of any computer software or hardware</li>
            </ul>
          </section>
          
          <section className="terms-section">
            <h2>7. Content and Submissions</h2>
            <p>Any feedback, comments, suggestions, ideas, or other information that you provide to us regarding our Services ("Submissions") will be treated as non-confidential and non-proprietary. By providing any Submission, you grant us a worldwide, perpetual, irrevocable, royalty-free, transferable, and sublicensable right to use, reproduce, modify, adapt, publish, translate, create derivative works from, distribute, and display such Submission in any media.</p>
          </section>
          
          <section className="terms-section">
            <h2>8. Disclaimer of Warranties</h2>
            <p>OUR SERVICES ARE PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT ANY WARRANTIES OF ANY KIND, EXPRESS OR IMPLIED. TO THE FULLEST EXTENT PERMITTED BY APPLICABLE LAW, WE DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.</p>
            <p>We do not guarantee that our Services will be uninterrupted, timely, secure, or error-free, or that any defects will be corrected. We do not warrant the accuracy, completeness, or usefulness of any information provided through our Services.</p>
          </section>
          
          <section className="terms-section">
            <h2>9. Limitation of Liability</h2>
            <p>TO THE FULLEST EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT WILL WE, OUR AFFILIATES, OR OUR LICENSORS, SERVICE PROVIDERS, EMPLOYEES, AGENTS, OFFICERS, OR DIRECTORS BE LIABLE FOR DAMAGES OF ANY KIND, UNDER ANY LEGAL THEORY, ARISING OUT OF OR IN CONNECTION WITH YOUR USE OF THE SERVICES, INCLUDING BUT NOT LIMITED TO DIRECT, INDIRECT, INCIDENTAL, SPECIAL, PUNITIVE, OR CONSEQUENTIAL DAMAGES, EVEN IF WE HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.</p>
          </section>
          
          <section className="terms-section">
            <h2>10. Indemnification</h2>
            <p>You agree to defend, indemnify, and hold harmless us, our affiliates, licensors, and service providers, and our and their respective officers, directors, employees, contractors, agents, licensors, suppliers, successors, and assigns from and against any claims, liabilities, damages, judgments, awards, losses, costs, expenses, or fees (including reasonable attorneys' fees) arising out of or relating to your violation of these Terms or your use of the Services.</p>
          </section>
          
          <section className="terms-section">
            <h2>11. Termination</h2>
            <p>We may terminate or suspend your account and access to the Services immediately, without prior notice or liability, for any reason, including but not limited to a breach of these Terms. Upon termination, your right to use the Services will immediately cease.</p>
          </section>
          
          <section className="terms-section">
            <h2>12. Governing Law</h2>
            <p>These Terms shall be governed by and construed in accordance with the laws of the State of California, without regard to its conflict of law provisions. Any dispute arising from or relating to these Terms or your use of the Services shall be subject to the exclusive jurisdiction of the state and federal courts located in San Francisco County, California.</p>
          </section>
          
          <section className="terms-section">
            <h2>13. Changes to These Terms</h2>
            <p>We may revise these Terms at any time by posting an updated version on our website. Your continued use of the Services after any such changes constitutes your acceptance of the new Terms. You are expected to check this page periodically to be aware of any changes.</p>
          </section>
          
          <section className="terms-section">
            <h2>14. Contact Information</h2>
            <p>If you have any questions about these Terms, please contact us at:</p>
            <p>Email: <a href="mailto:terms@certgames.com">terms@certgames.com</a></p>
            <p>Address: 123 Certification Way, Suite 456, Tech City, CA 98765</p>
          </section>
        </main>
        
        <nav className="terms-navigation">
          <Link to="/privacy" className="terms-nav-link">View Privacy Policy</Link>
          <Link to="/contact" className="terms-nav-link">Contact Us</Link>
        </nav>
        
        <Footer />
      </div>
    </>
  );
};

export default TermsOfService;
