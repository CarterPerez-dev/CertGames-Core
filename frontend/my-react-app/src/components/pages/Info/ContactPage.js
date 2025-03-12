// src/components/pages/Info/ContactPage.js
import React, { useState } from 'react';
import { 
  FaEnvelope, 
  FaPaperPlane, 
  FaLinkedin, 
  FaTwitter, 
  FaInstagram, 
  FaReddit, 
  FaFacebook,
  FaCheck,
  FaExclamationTriangle
} from 'react-icons/fa';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import SEOHelmet from '../../SEOHelmet';
import StructuredData from '../../StructuredData';
import './ContactPage.css';

const ContactPage = () => {
  const [formData, setFormData] = useState({
    email: '',
    message: ''
  });
  const [formErrors, setFormErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState(null); // 'success', 'error', or null

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
        "name": "Contact",
        "item": "https://certgames.com/contact"
      }
    ]
  };

  const validateForm = () => {
    const errors = {};
    
    // Email validation
    if (!formData.email) {
      errors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      errors.email = 'Email address is invalid';
    }
    
    // Message validation
    if (!formData.message) {
      errors.message = 'Message is required';
    } else if (formData.message.length < 10) {
      errors.message = 'Message must be at least 10 characters';
    }
    
    return errors;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
    
    // Clear error for this field when user starts typing
    if (formErrors[name]) {
      setFormErrors({
        ...formErrors,
        [name]: ''
      });
    }
  };

// Updated handleSubmit function for ContactPage.js
const handleSubmit = async (e) => {
  e.preventDefault();
  
  // Validate form
  const errors = validateForm();
  if (Object.keys(errors).length > 0) {
    setFormErrors(errors);
    return;
  }
  
  setIsSubmitting(true);
  setSubmitStatus(null);
  
  try {
    // Call the actual API endpoint
    const response = await fetch('/api/contact-form/submit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: formData.email,
        message: formData.message
      })
    });
    
    const data = await response.json();
    
    if (response.ok && data.success) {
      // Success case
      setSubmitStatus('success');
      
      // Reset form
      setFormData({
        email: '',
        message: ''
      });
      
      // Reset success message after 5 seconds
      setTimeout(() => {
        setSubmitStatus(null);
      }, 5000);
    } else {
      // API returned an error
      console.error('Error submitting form:', data.error);
      setSubmitStatus('error');
    }
  } catch (error) {
    console.error('Network error submitting form:', error);
    setSubmitStatus('error');
  } finally {
    setIsSubmitting(false);
  }
};

  return (
    <>
      <SEOHelmet 
        title="Contact CertGames | Support & Inquiries"
        description="Get in touch with the CertGames team. Questions about our cybersecurity training platform? Need technical support? We're here to help."
        canonicalUrl="/contact"
      />
      <StructuredData data={breadcrumbSchema} />
    <div className="contact-container">
      <InfoNavbar />
      
      <main className="contact-content">
        <header className="contact-header">
          <h1 className="contact-title">
            <FaEnvelope className="title-icon" aria-hidden="true" />
            Contact Us
          </h1>
          <p className="contact-subtitle">
            Have questions or feedback? We'd love to hear from you!
          </p>
        </header>
        
        <div className="contact-grid">
          <section className="contact-form-container">
            <div className="contact-form-card">
              <h2>Send us a message</h2>
              
              {submitStatus === 'success' && (
                <div className="form-success" role="alert">
                  <FaCheck className="success-icon" aria-hidden="true" />
                  <p>Message sent successfully! We'll get back to you soon.</p>
                </div>
              )}
              
              {submitStatus === 'error' && (
                <div className="form-error" role="alert">
                  <FaExclamationTriangle className="error-icon" aria-hidden="true" />
                  <p>There was an error sending your message. Please try again later.</p>
                </div>
              )}
              
              <form className="contact-form" onSubmit={handleSubmit}>
                <div className="form-group">
                  <label htmlFor="email">Email Address</label>
                  <input
                    type="email"
                    id="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="Enter your email address"
                    disabled={isSubmitting}
                    className={formErrors.email ? 'input-error' : ''}
                    aria-required="true"
                    aria-invalid={formErrors.email ? "true" : "false"}
                  />
                  {formErrors.email && (
                    <div className="error-message" role="alert">{formErrors.email}</div>
                  )}
                </div>
                
                <div className="form-group">
                  <label htmlFor="message">Message</label>
                  <textarea
                    id="message"
                    name="message"
                    value={formData.message}
                    onChange={handleChange}
                    placeholder="What would you like to tell us?"
                    rows="6"
                    disabled={isSubmitting}
                    className={formErrors.message ? 'input-error' : ''}
                    aria-required="true"
                    aria-invalid={formErrors.message ? "true" : "false"}
                  ></textarea>
                  {formErrors.message && (
                    <div className="error-message" role="alert">{formErrors.message}</div>
                  )}
                </div>
                
                <button 
                  type="submit" 
                  className="send-button"
                  disabled={isSubmitting}
                  aria-busy={isSubmitting ? "true" : "false"}
                >
                  {isSubmitting ? (
                    <span className="submitting">
                      <span className="spinner" aria-hidden="true"></span>
                      Sending...
                    </span>
                  ) : (
                    <span className="send-text">
                      <FaPaperPlane className="send-icon" aria-hidden="true" />
                      Send Message
                    </span>
                  )}
                </button>
              </form>
            </div>
          </section>
          
          <section className="contact-info-container">
            <div className="contact-info-card">
              <h2>Get in Touch</h2>
              
              <div className="contact-channels">
                <div className="contact-channel">
                  <div className="channel-icon">
                    <FaEnvelope aria-hidden="true" />
                  </div>
                  <div className="channel-details">
                    <h3>Support Email</h3>
                    <p>support@certgames.com</p>
                    <p className="response-time">Usually responds within 24 hours</p>
                  </div>
                </div>
                
                <div className="contact-channel">
                  <div className="channel-icon business">
                    <FaEnvelope aria-hidden="true" />
                  </div>
                  <div className="channel-details">
                    <h3>Business Inquiries</h3>
                    <p>inquiry@certgames.com</p>
                    <p className="response-time">For partnership opportunities</p>
                  </div>
                </div>
              </div>
              
              <div className="social-links">
                <h3>Connect With Us</h3>
                <div className="social-icons">
                  <a href="https://www.linkedin.com/company/certgames/?viewAsMember=true" target="_blank" rel="noopener noreferrer" className="social-icon linkedin" aria-label="CertGames on LinkedIn">
                    <FaLinkedin aria-hidden="true" />
                  </a>
                  <a href="https://x.com/CertsGamified" target="_blank" rel="noopener noreferrer" className="social-icon twitter" aria-label="CertGames on X (formerly Twitter)">
                    <FaTwitter aria-hidden="true" />
                  </a>
                  <a href="https://www.instagram.com/certsgamified/" target="_blank" rel="noopener noreferrer" className="social-icon instagram" aria-label="CertGames on Instagram">
                    <FaInstagram aria-hidden="true" />
                  </a>
                  <a href="https://www.reddit.com/user/Hopeful_Beat7161/" target="_blank" rel="noopener noreferrer" className="social-icon reddit" aria-label="CertGames on Reddit">
                    <FaReddit aria-hidden="true" />
                  </a>
                  <a href="https://www.facebook.com/people/CertGames/61574087485497/" target="_blank" rel="noopener noreferrer" className="social-icon facebook" aria-label="CertGames on Facebook">
                    <FaFacebook aria-hidden="true" />
                  </a>
                </div>
              </div>
            </div>
            
            <section className="faq-section">
              <h3>Frequently Asked Questions</h3>
              
              <article className="faq-item">
                <h4>How do I reset my password?</h4>
                <p>You can reset your password by clicking on the "Forgot Password" link on the login page and following the instructions sent to your email.</p>
              </article>
              
              <article className="faq-item">
                <h4>How do I cancel my subscription?</h4>
                <p>You can cancel your subscription at any time from your account settings. Your access will continue until the end of your current billing period.</p>
              </article>
              
              <article className="faq-item">
                <h4>Can I access CertGames on my mobile device?</h4>
                <p>Yes! CertGames is fully responsive and works on all devices, including mobile phones and tablets.</p>
              </article>
            </section>
          </section>
        </div>
      </main>
      
      <Footer />
    </div>
    </>
  );
};

export default ContactPage;
