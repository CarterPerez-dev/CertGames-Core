// src/components/pages/games/PhishingPhrenzy/PhishingCard.js
import React from 'react';
import { 
  FaEnvelope, 
  FaGlobe, 
  FaCommentAlt, 
  FaLink, 
  FaDownload, 
  FaQrcode, 
  FaFacebook, 
  FaBriefcase,
  FaDesktop, 
  FaFileAlt, 
  FaCreditCard, 
  FaExclamationTriangle 
} from 'react-icons/fa';
import './PhishingCard.css';

const PhishingCard = ({ item }) => {
  if (!item) return null;

  const renderContent = () => {
    switch (item.type) {
      case 'email':
        return (
          <div className="phishingphrenzy_phishing_email">
            <div className="phishingphrenzy_email_header">
              <div className="phishingphrenzy_email_from">
                <strong>From:</strong> {item.from}
              </div>
              <div className="phishingphrenzy_email_subject">
                <strong>Subject:</strong> {item.subject}
              </div>
              {item.date && (
                <div className="phishingphrenzy_email_date">
                  <strong>Date:</strong> {item.date}
                </div>
              )}
            </div>
            <div className="phishingphrenzy_email_body">
              {item.body}
            </div>
            {item.links && item.links.length > 0 && (
              <div className="phishingphrenzy_email_links">
                <div className="phishingphrenzy_link_label">Links in email:</div>
                {item.links.map((link, idx) => (
                  <div className="phishingphrenzy_email_link" key={idx}>
                    <FaLink /> <span className="phishingphrenzy_link_text">{link}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      
      case 'website':
        return (
          <div className="phishingphrenzy_phishing_website">
            <div className="phishingphrenzy_website_url">
              {item.url}
            </div>
            <div className="phishingphrenzy_website_preview">
              <div className="phishingphrenzy_website_header">
                <h3>{item.title}</h3>
              </div>
              <div className="phishingphrenzy_website_content">
                {item.content}
              </div>
              {item.formFields && (
                <div className="phishingphrenzy_website_form">
                  {item.formFields.map((field, idx) => (
                    <div className="phishingphrenzy_form_field" key={idx}>
                      <label>{field.label}</label>
                      <input 
                        type={field.type} 
                        placeholder={field.placeholder}
                        disabled 
                      />
                    </div>
                  ))}
                  <button className="phishingphrenzy_form_submit" disabled>
                    {item.submitButton || "Submit"}
                  </button>
                </div>
              )}
            </div>
          </div>
        );
      
      case 'sms':
        return (
          <div className="phishingphrenzy_phishing_sms">
            <div className="phishingphrenzy_sms_from">
              From: {item.from}
            </div>
            <div className="phishingphrenzy_sms_message">
              {item.message}
            </div>
            {item.links && item.links.length > 0 && (
              <div className="phishingphrenzy_sms_links">
                {item.links.map((link, idx) => (
                  <div className="phishingphrenzy_sms_link" key={idx}>
                    {link}
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      
      case 'app_download':
        return (
          <div className="phishingphrenzy_phishing_app">
            <div className="phishingphrenzy_app_header">
              <div className="phishingphrenzy_app_name_rating">
                <h3 className="phishingphrenzy_app_name">{item.app_name}</h3>
                <span className="phishingphrenzy_app_rating">{item.rating}</span>
              </div>
              <div className="phishingphrenzy_app_developer">
                By: {item.developer}
              </div>
              <div className="phishingphrenzy_app_platform">
                <span className="phishingphrenzy_platform_tag">{item.platform}</span>
                <span className="phishingphrenzy_installs">{item.installs} downloads</span>
              </div>
            </div>
            
            <div className="phishingphrenzy_app_description">
              {item.description}
            </div>
            
            <div className="phishingphrenzy_app_permissions">
              <div className="phishingphrenzy_permissions_title">Permissions Required:</div>
              <div className="phishingphrenzy_permissions_list">
                {item.permissions.map((permission, idx) => (
                  <span key={idx} className="phishingphrenzy_permission_badge">
                    {permission}
                  </span>
                ))}
              </div>
            </div>
            
            <div className="phishingphrenzy_app_reviews">
              <div className="phishingphrenzy_reviews_title">User Reviews:</div>
              {item.reviewHighlights.map((review, idx) => (
                <div key={idx} className="phishingphrenzy_review">
                  <div className="phishingphrenzy_review_header">
                    <span className="phishingphrenzy_reviewer">{review.user}</span>
                    <span className="phishingphrenzy_review_rating">
                      {"★".repeat(review.rating) + "☆".repeat(5-review.rating)}
                    </span>
                  </div>
                  <div className="phishingphrenzy_review_text">{review.text}</div>
                </div>
              ))}
            </div>
            
            <div className="phishingphrenzy_app_download">
              <a href="#" className="phishingphrenzy_download_button" onClick={(e) => e.preventDefault()}>
                Download App
              </a>
              <div className="phishingphrenzy_download_url">{item.downloadUrl}</div>
            </div>
          </div>
        );

      case 'qr_code':
        return (
          <div className="phishingphrenzy_qr_container">
            <div className="phishingphrenzy_qr_title">
              {item.title}
            </div>
            <div className="phishingphrenzy_qr_context">
              {item.context}
            </div>
            <div className="phishingphrenzy_qr_code_wrapper">
              <div className="phishingphrenzy_qr_image">
                <div className="phishingphrenzy_qr_placeholder">
                  <FaQrcode />
                  <div className="phishingphrenzy_qr_scan_me">Scan Me</div>
                </div>
              </div>
              {item.caption && (
                <div className="phishingphrenzy_qr_caption">
                  {item.caption}
                </div>
              )}
            </div>
            <div className="phishingphrenzy_qr_destination">
              <div className="phishingphrenzy_qr_destination_label">Scan destination:</div>
              <div className="phishingphrenzy_qr_url">{item.url}</div>
            </div>
          </div>
        );

      case 'social_media':
        return (
          <div className="phishingphrenzy_social_media">
            <div className="phishingphrenzy_social_header">
              <div className="phishingphrenzy_social_platform">
                <span className="phishingphrenzy_platform_icon">{item.platform === 'Facebook' ? <FaFacebook /> : item.platform}</span>
                {item.platform}
              </div>
              <div className="phishingphrenzy_social_time">{item.timestamp}</div>
            </div>
            <div className="phishingphrenzy_social_profile">
              <div className="phishingphrenzy_profile_pic" 
                style={item.profilePic ? {backgroundImage: `url(${item.profilePic})`} : {}}>
                {!item.profilePic && item.sender[0]}
              </div>
              <div className="phishingphrenzy_profile_info">
                <div className="phishingphrenzy_sender_name">{item.sender}</div>
                <div className="phishingphrenzy_sender_handle">{item.handle}</div>
              </div>
              {item.verified && (
                <div className="phishingphrenzy_verified_badge">✓</div>
              )}
            </div>
            <div className="phishingphrenzy_social_message">
              {item.message}
            </div>
            {item.image && (
              <div className="phishingphrenzy_social_image">
                <img src={item.image} alt="Social media attachment" />
              </div>
            )}
            {item.link && (
              <div className="phishingphrenzy_social_link">
                <a href="#" onClick={(e) => e.preventDefault()}>
                  {item.link}
                </a>
              </div>
            )}
            <div className="phishingphrenzy_social_interactions">
              <div className="phishingphrenzy_interaction">
                <span className="phishingphrenzy_interaction_icon">♥</span>
                <span className="phishingphrenzy_interaction_count">{item.likes || 0}</span>
              </div>
              <div className="phishingphrenzy_interaction">
                <span className="phishingphrenzy_interaction_icon">↺</span>
                <span className="phishingphrenzy_interaction_count">{item.shares || 0}</span>
              </div>
              <div className="phishingphrenzy_interaction">
                <span className="phishingphrenzy_interaction_icon">💬</span>
                <span className="phishingphrenzy_interaction_count">{item.comments || 0}</span>
              </div>
            </div>
          </div>
        );

      case 'job_offer':
        return (
          <div className="phishingphrenzy_job_offer">
            <div className="phishingphrenzy_job_header">
              <div className="phishingphrenzy_job_company_logo">
                {item.companyLogo ? (
                  <img src={item.companyLogo} alt={`${item.company} logo`} />
                ) : (
                  <div className="phishingphrenzy_job_logo_placeholder">
                    {item.company[0]}
                  </div>
                )}
              </div>
              <div className="phishingphrenzy_job_title_info">
                <h3 className="phishingphrenzy_job_position">{item.position}</h3>
                <div className="phishingphrenzy_job_company">{item.company}</div>
                <div className="phishingphrenzy_job_location">{item.location}</div>
              </div>
            </div>
            <div className="phishingphrenzy_job_details">
              <div className="phishingphrenzy_job_section">
                <div className="phishingphrenzy_job_section_title">Salary Range:</div>
                <div className="phishingphrenzy_job_salary">{item.salary}</div>
              </div>
              <div className="phishingphrenzy_job_section">
                <div className="phishingphrenzy_job_section_title">Description:</div>
                <div className="phishingphrenzy_job_description">{item.description}</div>
              </div>
              <div className="phishingphrenzy_job_section">
                <div className="phishingphrenzy_job_section_title">Requirements:</div>
                <ul className="phishingphrenzy_job_requirements">
                  {item.requirements.map((req, idx) => (
                    <li key={idx}>{req}</li>
                  ))}
                </ul>
              </div>
            </div>
            <div className="phishingphrenzy_job_action">
              <div className="phishingphrenzy_job_application_method">
                <div className="phishingphrenzy_apply_label">Apply via:</div>
                <div className="phishingphrenzy_apply_email">{item.applyEmail}</div>
              </div>
              <button className="phishingphrenzy_apply_button" disabled>
                Apply Now
              </button>
            </div>
          </div>
        );

      case 'tech_support':
        return (
          <div className="phishingphrenzy_tech_support">
            <div className="phishingphrenzy_popup_header">
              <div className="phishingphrenzy_popup_icon">
                <FaExclamationTriangle />
              </div>
              <div className="phishingphrenzy_popup_title">{item.title}</div>
              <div className="phishingphrenzy_popup_close">×</div>
            </div>
            <div className="phishingphrenzy_popup_body">
              <div className="phishingphrenzy_alert_message">
                {item.alertMessage}
              </div>
              {item.technicalDetails && (
                <div className="phishingphrenzy_technical_details">
                  <div className="phishingphrenzy_tech_details_title">Technical Details:</div>
                  <div className="phishingphrenzy_tech_details_content">
                    {item.technicalDetails}
                  </div>
                </div>
              )}
              {item.steps && (
                <div className="phishingphrenzy_steps">
                  <div className="phishingphrenzy_steps_title">Recommended Steps:</div>
                  <ol className="phishingphrenzy_steps_list">
                    {item.steps.map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ol>
                </div>
              )}
            </div>
            <div className="phishingphrenzy_popup_footer">
              <div className="phishingphrenzy_contact_info">
                {item.contactInfo}
              </div>
              <div className="phishingphrenzy_popup_buttons">
                <button className="phishingphrenzy_popup_ignore" disabled>Ignore</button>
                <button className="phishingphrenzy_popup_action" disabled>{item.actionButton || "Get Help Now"}</button>
              </div>
            </div>
          </div>
        );

      case 'document':
        return (
          <div className="phishingphrenzy_document">
            <div className="phishingphrenzy_document_header">
              <div className="phishingphrenzy_document_icon">
                <FaFileAlt />
              </div>
              <div className="phishingphrenzy_document_info">
                <div className="phishingphrenzy_document_name">{item.fileName}</div>
                <div className="phishingphrenzy_document_type">{item.fileType}</div>
              </div>
            </div>
            <div className="phishingphrenzy_document_preview">
              <div className="phishingphrenzy_document_preview_header">
                <div className="phishingphrenzy_document_sender">From: {item.sender}</div>
                {item.companyLogo && (
                  <div className="phishingphrenzy_document_company_logo">
                    <img src={item.companyLogo} alt="Company logo" />
                  </div>
                )}
              </div>
              <div className="phishingphrenzy_document_placeholder">
                <div className="phishingphrenzy_document_contents_preview">
                  {item.contentsPreview}
                </div>
                {item.secured && (
                  <div className="phishingphrenzy_document_secured_message">
                    <FaExclamationTriangle />
                    <span>This document is secured. Please enable macros to view its contents.</span>
                  </div>
                )}
              </div>
            </div>
            <div className="phishingphrenzy_document_footer">
              <div className="phishingphrenzy_document_source">{item.source}</div>
              <div className="phishingphrenzy_document_buttons">
                <button className="phishingphrenzy_document_button enable_content" disabled>
                  {item.enableButton || "Enable Content"}
                </button>
                <button className="phishingphrenzy_document_button cancel" disabled>Cancel</button>
              </div>
            </div>
          </div>
        );

      case 'payment_confirmation':
        return (
          <div className="phishingphrenzy_payment">
            <div className="phishingphrenzy_payment_header">
              <div className="phishingphrenzy_payment_logo">
                {item.companyLogo ? (
                  <img src={item.companyLogo} alt={`${item.company} logo`} />
                ) : (
                  <div className="phishingphrenzy_payment_logo_text">
                    {item.company}
                  </div>
                )}
              </div>
              <div className="phishingphrenzy_payment_title">
                {item.title || "Payment Confirmation"}
              </div>
            </div>
            <div className="phishingphrenzy_payment_info">
              <div className="phishingphrenzy_payment_message">
                {item.message}
              </div>
              <div className="phishingphrenzy_payment_details">
                <div className="phishingphrenzy_payment_row">
                  <div className="phishingphrenzy_payment_label">Transaction ID:</div>
                  <div className="phishingphrenzy_payment_value">{item.transactionId}</div>
                </div>
                <div className="phishingphrenzy_payment_row">
                  <div className="phishingphrenzy_payment_label">Date:</div>
                  <div className="phishingphrenzy_payment_value">{item.date}</div>
                </div>
                <div className="phishingphrenzy_payment_row">
                  <div className="phishingphrenzy_payment_label">Amount:</div>
                  <div className="phishingphrenzy_payment_value amount">{item.amount}</div>
                </div>
                <div className="phishingphrenzy_payment_row">
                  <div className="phishingphrenzy_payment_label">Payment Method:</div>
                  <div className="phishingphrenzy_payment_value">{item.paymentMethod}</div>
                </div>
              </div>
            </div>
            <div className="phishingphrenzy_payment_actions">
              <div className="phishingphrenzy_payment_warning">
                {item.warning || "If you did not authorize this payment, please click 'Dispute' below."}
              </div>
              <div className="phishingphrenzy_payment_buttons">
                <button className="phishingphrenzy_payment_button confirm" disabled>Confirm</button>
                <button className="phishingphrenzy_payment_button dispute" disabled>Dispute</button>
              </div>
            </div>
          </div>
        );

      case 'security_alert':
        return (
          <div className="phishingphrenzy_security_alert">
            <div className="phishingphrenzy_security_header">
              <div className="phishingphrenzy_security_icon">
                <FaExclamationTriangle />
              </div>
              <div className="phishingphrenzy_security_title">
                {item.title || "Security Alert"}
              </div>
            </div>
            <div className="phishingphrenzy_security_content">
              <div className="phishingphrenzy_security_message">
                {item.message}
              </div>
              {item.details && (
                <div className="phishingphrenzy_security_details">
                  <div className="phishingphrenzy_security_details_title">Alert Details:</div>
                  <div className="phishingphrenzy_security_details_list">
                    {Object.entries(item.details).map(([key, value], idx) => (
                      <div className="phishingphrenzy_security_detail_item" key={idx}>
                        <div className="phishingphrenzy_security_detail_key">{key}:</div>
                        <div className="phishingphrenzy_security_detail_value">{value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {item.actions && (
                <div className="phishingphrenzy_security_recommended_actions">
                  <div className="phishingphrenzy_security_actions_title">Recommended Actions:</div>
                  <ul className="phishingphrenzy_security_actions_list">
                    {item.actions.map((action, idx) => (
                      <li key={idx}>{action}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
            <div className="phishingphrenzy_security_footer">
              <div className="phishingphrenzy_security_reference">
                Reference ID: {item.referenceId || "SEC-" + Math.floor(Math.random() * 100000)}
              </div>
              <div className="phishingphrenzy_security_buttons">
                <button className="phishingphrenzy_security_button ignore" disabled>Dismiss</button>
                <button className="phishingphrenzy_security_button action" disabled>
                  {item.actionButton || "Secure Account Now"}
                </button>
              </div>
            </div>
          </div>
        );
      
      default:
        return <div>Unknown content type</div>;
    }
  };

  const getCardIcon = () => {
    switch (item.type) {
      case 'email':
        return <FaEnvelope className="phishingphrenzy_card_icon" />;
      case 'website':
        return <FaGlobe className="phishingphrenzy_card_icon" />;
      case 'sms':
        return <FaCommentAlt className="phishingphrenzy_card_icon" />;
      case 'app_download':
        return <FaDownload className="phishingphrenzy_card_icon" />;
      case 'qr_code':
        return <FaQrcode className="phishingphrenzy_card_icon" />;
      case 'social_media':
        return <FaFacebook className="phishingphrenzy_card_icon" />;
      case 'job_offer':
        return <FaBriefcase className="phishingphrenzy_card_icon" />;
      case 'tech_support':
        return <FaDesktop className="phishingphrenzy_card_icon" />;
      case 'document':
        return <FaFileAlt className="phishingphrenzy_card_icon" />;
      case 'payment_confirmation':
        return <FaCreditCard className="phishingphrenzy_card_icon" />;
      case 'security_alert':
        return <FaExclamationTriangle className="phishingphrenzy_card_icon" />;
      default:
        return null;
    }
  };

  return (
    <div className={`phishingphrenzy_card_container ${item.type}-card`}>
      <div className="phishingphrenzy_card_header">
        {getCardIcon()}
        <span className="phishingphrenzy_card_type">
          {item.type === 'email' ? 'Email Message' : 
           item.type === 'website' ? 'Website' : 
           item.type === 'sms' ? 'SMS Message' : 
           item.type === 'app_download' ? 'App Download' :
           item.type === 'qr_code' ? 'QR Code' :
           item.type === 'social_media' ? 'Social Media Post' :
           item.type === 'job_offer' ? 'Job Opportunity' :
           item.type === 'tech_support' ? 'Technical Support Alert' :
           item.type === 'document' ? 'Document Download' :
           item.type === 'payment_confirmation' ? 'Payment Confirmation' :
           item.type === 'security_alert' ? 'Security Alert' : 'Unknown'}
        </span>
      </div>
      <div className="phishingphrenzy_card_content">
        {renderContent()}
      </div>
      <div className="phishingphrenzy_card_instruction">
        <strong>Is this a phishing attempt?</strong>
      </div>
    </div>
  );
};

export default PhishingCard;
