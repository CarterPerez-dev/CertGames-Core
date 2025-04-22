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
  FaExclamationTriangle,
  FaAd,
  FaUserAlt,
  FaClipboard,
  FaPoll,
  FaWifi,
  FaCalendarAlt,
  FaCertificate,
  FaPuzzlePiece,
  FaCamera,
  FaShareAlt,
  FaMicrochip,
  FaLock,
  FaUniversity,
  FaBitcoin,
  FaChartLine,
  FaShieldAlt,
  FaTrophy,
  FaHandHoldingHeart,
  FaShippingFast,
  FaCloud,
  FaHeart,
  FaUser,
  FaCheckCircle,
  FaStar,
  FaBox,
  FaGift,
  FaHospital,
  FaClipboardCheck,
  FaIdCard,
  FaNewspaper,
  FaBookmark,
  FaClock,
  FaExclamationCircle,
  FaMoneyCheckAlt,
  FaGamepad,  
} from 'react-icons/fa';
import './PhishingCard.css';
import './PhishingCard2.css';
import './PhishingCard3.css';
import './PhishingCard4.css';
import './PhishingCard5.css';
// From PhishingCard.css to PhishingCard5.css we have 35 unique styles/css....dont ask me why it starts at -11 
import cardTypeNames from './cardTypeNames.js';

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
      
      
    
      case 'advertisement':
        return (
          <div className="phishingphrenzy_advertisement">
            <div className="phishingphrenzy_ad_header">
              <div className="phishingphrenzy_ad_sponsored">Sponsored</div>
              <div className="phishingphrenzy_ad_close">×</div>
            </div>
            <div className="phishingphrenzy_ad_content">
              {item.image && (
                <div className="phishingphrenzy_ad_image">
                  <div className="phishingphrenzy_ad_image_placeholder">
                    {item.imageText || "SPECIAL OFFER"}
                  </div>
                </div>
              )}
              <div className="phishingphrenzy_ad_text">
                <div className="phishingphrenzy_ad_title">{item.title}</div>
                <div className="phishingphrenzy_ad_description">{item.description}</div>
                <div className="phishingphrenzy_ad_url">{item.displayUrl}</div>
              </div>
            </div>
            <div className="phishingphrenzy_ad_footer">
              <button className="phishingphrenzy_ad_button" disabled>
                {item.buttonText || "Learn More"}
              </button>
              <div className="phishingphrenzy_ad_destination">
                <span>Destination: </span>
                <span className="phishingphrenzy_ad_dest_url">{item.actualUrl}</span>
              </div>
            </div>
          </div>
        );
      
  
      case 'browser_extension':
        return (
          <div className="phishingphrenzy_extension">
            <div className="phishingphrenzy_extension_header">
              <div className="phishingphrenzy_extension_icon">
                <div className="phishingphrenzy_extension_icon_placeholder">{item.name ? item.name[0] : 'E'}</div>
              </div>
              <div className="phishingphrenzy_extension_info">
                <div className="phishingphrenzy_extension_name">{item.name || "Browser Extension"}</div>
                <div className="phishingphrenzy_extension_developer">by {item.developer}</div>
                <div className="phishingphrenzy_extension_stats">
                  <span>{item.users || "10K+"} users</span>
                  <span>{item.rating || "★★★★☆"}</span>
                </div>
              </div>
            </div>
            <div className="phishingphrenzy_extension_body">
              <div className="phishingphrenzy_extension_description">
                {item.description}
              </div>
              <div className="phishingphrenzy_extension_permissions">
                <div className="phishingphrenzy_extension_section_title">Required Permissions:</div>
                <ul className="phishingphrenzy_extension_permission_list">
                  {item.permissions.map((permission, idx) => (
                    <li key={idx} className="phishingphrenzy_extension_permission_item">
                      {permission}
                    </li>
                  ))}
                </ul>
              </div>
              {item.reviewQuote && (
                <div className="phishingphrenzy_extension_review">
                  <div className="phishingphrenzy_extension_section_title">Featured Review:</div>
                  <div className="phishingphrenzy_extension_review_content">
                    "{item.reviewQuote}"
                  </div>
                </div>
              )}
            </div>
            <div className="phishingphrenzy_extension_footer">
              <button className="phishingphrenzy_extension_button" disabled>
                Add to Browser
              </button>
              <div className="phishingphrenzy_extension_source">
                Source: {item.source || "Chrome Web Store"}
              </div>
            </div>
          </div>
        );
      
     
      case 'event_invitation':
        return (
          <div className="phishingphrenzy_event">
            <div className="phishingphrenzy_event_header">
              <div className="phishingphrenzy_event_title">{item.title}</div>
              <div className="phishingphrenzy_event_organizer">Organized by: {item.organizer}</div>
            </div>
            <div className="phishingphrenzy_event_details">
              <div className="phishingphrenzy_event_datetime">
                <div className="phishingphrenzy_event_date">
                  <FaCalendarAlt /> {item.date}
                </div>
                <div className="phishingphrenzy_event_time">{item.time}</div>
              </div>
              <div className="phishingphrenzy_event_location">
                <div className="phishingphrenzy_event_location_name">{item.location}</div>
                {item.address && (
                  <div className="phishingphrenzy_event_address">{item.address}</div>
                )}
              </div>
              <div className="phishingphrenzy_event_description">
                {item.description}
              </div>
              {item.speakers && (
                <div className="phishingphrenzy_event_speakers">
                  <div className="phishingphrenzy_event_section_title">Featured Speakers:</div>
                  <ul className="phishingphrenzy_event_speaker_list">
                    {item.speakers.map((speaker, idx) => (
                      <li key={idx} className="phishingphrenzy_event_speaker_item">
                        {speaker.name} - {speaker.title}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
            <div className="phishingphrenzy_event_footer">
              <div className="phishingphrenzy_event_registration">
                <div className="phishingphrenzy_event_price">{item.price || "Free"}</div>
                <button className="phishingphrenzy_event_register_button" disabled>
                  {item.registerText || "Register Now"}
                </button>
              </div>
              <div className="phishingphrenzy_event_link">
                Registration link: <span className="phishingphrenzy_event_url">{item.registrationUrl}</span>
              </div>
            </div>
          </div>
        );
      

      case 'survey':
        return (
          <div className="phishingphrenzy_survey">
            <div className="phishingphrenzy_survey_header">
              <div className="phishingphrenzy_survey_logo">
                {item.companyLogo ? (
                  <img src={item.companyLogo} alt="Survey logo" />
                ) : (
                  <div className="phishingphrenzy_survey_logo_placeholder">
                    <FaPoll />
                  </div>
                )}
              </div>
              <div className="phishingphrenzy_survey_title">{item.title}</div>
              <div className="phishingphrenzy_survey_sponsor">
                {item.sponsoredBy ? `Sponsored by ${item.sponsoredBy}` : ''}
              </div>
            </div>
            <div className="phishingphrenzy_survey_body">
              <div className="phishingphrenzy_survey_description">
                {item.description}
              </div>
              <div className="phishingphrenzy_survey_details">
                <div className="phishingphrenzy_survey_detail">
                  <span className="phishingphrenzy_survey_detail_label">Time Required:</span>
                  <span>{item.timeRequired || "5 minutes"}</span>
                </div>
                <div className="phishingphrenzy_survey_detail">
                  <span className="phishingphrenzy_survey_detail_label">Questions:</span>
                  <span>{item.questionCount || "10"}</span>
                </div>
                <div className="phishingphrenzy_survey_detail">
                  <span className="phishingphrenzy_survey_detail_label">Reward:</span>
                  <span>{item.reward || "None"}</span>
                </div>
              </div>
              <div className="phishingphrenzy_survey_preview">
                <div className="phishingphrenzy_survey_question">
                  {item.sampleQuestion || "How satisfied are you with your recent purchase?"}
                </div>
                <div className="phishingphrenzy_survey_options">
                  {(item.sampleOptions || ["Very Satisfied", "Satisfied", "Neutral", "Dissatisfied", "Very Dissatisfied"]).map((option, idx) => (
                    <div key={idx} className="phishingphrenzy_survey_option">
                      <input type="radio" id={`option_${idx}`} name="sample_question" disabled />
                      <label htmlFor={`option_${idx}`}>{option}</label>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div className="phishingphrenzy_survey_footer">
              <div className="phishingphrenzy_survey_disclaimer">
                {item.disclaimer || "Your answers will be anonymous and used for market research."}
              </div>
              <div className="phishingphrenzy_survey_buttons">
                <button className="phishingphrenzy_survey_button" disabled>
                  {item.buttonText || "Start Survey"}
                </button>
              </div>
              <div className="phishingphrenzy_survey_url">
                Survey URL: {item.url}
              </div>
            </div>
          </div>
        );
      
   
      case 'wifi_portal':
        return (
          <div className="phishingphrenzy_wifi_portal">
            <div className="phishingphrenzy_wifi_header">
              <div className="phishingphrenzy_wifi_icon">
                <FaWifi />
              </div>
              <div className="phishingphrenzy_wifi_title">
                {item.title || "Free WiFi Login"}
              </div>
              <div className="phishingphrenzy_wifi_network">
                Network: {item.networkName || "PublicWiFi"}
              </div>
            </div>
            <div className="phishingphrenzy_wifi_body">
              <div className="phishingphrenzy_wifi_message">
                {item.message || "Please log in to access the internet."}
              </div>
              <div className="phishingphrenzy_wifi_form">
                {item.loginMethod === 'social' ? (
                  <div className="phishingphrenzy_wifi_social_login">
                    <div className="phishingphrenzy_wifi_social_title">Log in with:</div>
                    <div className="phishingphrenzy_wifi_social_buttons">
                      <button className="phishingphrenzy_wifi_social_button" disabled>
                        <FaFacebook /> Facebook
                      </button>
                      <button className="phishingphrenzy_wifi_social_button" disabled>
                        <FaUserAlt /> Google
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="phishingphrenzy_wifi_credentials">
                    <div className="phishingphrenzy_wifi_input">
                      <label>Email or Phone:</label>
                      <input type="text" placeholder="Enter email or phone" disabled />
                    </div>
                    {!item.skipPassword && (
                      <div className="phishingphrenzy_wifi_input">
                        <label>Password:</label>
                        <input type="password" placeholder="Enter password" disabled />
                      </div>
                    )}
                    {item.requiresAgreement && (
                      <div className="phishingphrenzy_wifi_agreement">
                        <input type="checkbox" id="terms_agree" disabled />
                        <label htmlFor="terms_agree">
                          I agree to the <a href="#" onClick={(e) => e.preventDefault()}>Terms & Conditions</a>
                        </label>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
            <div className="phishingphrenzy_wifi_footer">
              <button className="phishingphrenzy_wifi_button" disabled>
                {item.buttonText || "Connect"}
              </button>
              <div className="phishingphrenzy_wifi_footer_text">
                {item.footerText || "By connecting, you agree to our terms of service."}
              </div>
              <div className="phishingphrenzy_wifi_url">
                Portal URL: {item.portalUrl || "wifi-login.example.com"}
              </div>
            </div>
          </div>
        );
      
     
      case 'certificate_error':
        return (
          <div className="phishingphrenzy_certificate">
            <div className="phishingphrenzy_certificate_header">
              <div className="phishingphrenzy_certificate_icon">
                <FaLock />
              </div>
              <div className="phishingphrenzy_certificate_title">
                {item.title || "Your connection is not private"}
              </div>
            </div>
            <div className="phishingphrenzy_certificate_body">
              <div className="phishingphrenzy_certificate_message">
                {item.message || "Attackers might be trying to steal your information from this site (for example, passwords, messages, or credit cards)."}
              </div>
              <div className="phishingphrenzy_certificate_details">
                <div className="phishingphrenzy_certificate_detail_title">
                  Error details:
                </div>
                <div className="phishingphrenzy_certificate_detail_text">
                  {item.errorDetails || "NET::ERR_CERT_AUTHORITY_INVALID"}
                </div>
                <div className="phishingphrenzy_certificate_url">
                  <span className="phishingphrenzy_certificate_url_label">URL:</span>
                  <span className="phishingphrenzy_certificate_url_value">{item.url}</span>
                </div>
              </div>
              <div className="phishingphrenzy_certificate_help">
                <div className="phishingphrenzy_certificate_help_title">What can you do?</div>
                <ul className="phishingphrenzy_certificate_help_list">
                  {(item.helpList || [
                    "Go back to the previous page",
                    "Try again later",
                    "Check your internet connection",
                    "Check your computer's date and time"
                  ]).map((help, idx) => (
                    <li key={idx}>{help}</li>
                  ))}
                </ul>
              </div>
              {item.customMessage && (
                <div className="phishingphrenzy_certificate_custom">
                  {item.customMessage}
                </div>
              )}
            </div>
            <div className="phishingphrenzy_certificate_footer">
              <button className="phishingphrenzy_certificate_back_button" disabled>
                Back to safety
              </button>
              <button className="phishingphrenzy_certificate_advanced_button" disabled>
                Advanced
              </button>
              <button className="phishingphrenzy_certificate_proceed_button" disabled>
                {item.proceedText || "Proceed anyway (unsafe)"}
              </button>
            </div>
          </div>
        );
      
   
      case 'software_update':
        return (
          <div className="phishingphrenzy_update">
            <div className="phishingphrenzy_update_header">
              <div className="phishingphrenzy_update_logo">
                {item.logo ? (
                  <img src={item.logo} alt="Software logo" />
                ) : (
                  <div className="phishingphrenzy_update_logo_placeholder">
                    <FaMicrochip />
                  </div>
                )}
              </div>
              <div className="phishingphrenzy_update_title">
                {item.title || "Software Update Available"}
              </div>
            </div>
            <div className="phishingphrenzy_update_body">
              <div className="phishingphrenzy_update_message">
                {item.message || "A new version of the software is available. Please update now to get the latest features and security improvements."}
              </div>
              <div className="phishingphrenzy_update_details">
                <div className="phishingphrenzy_update_detail">
                  <span className="phishingphrenzy_update_detail_label">Current Version:</span>
                  <span>{item.currentVersion || "1.2.1"}</span>
                </div>
                <div className="phishingphrenzy_update_detail">
                  <span className="phishingphrenzy_update_detail_label">New Version:</span>
                  <span>{item.newVersion || "1.3.0"}</span>
                </div>
                <div className="phishingphrenzy_update_detail">
                  <span className="phishingphrenzy_update_detail_label">Size:</span>
                  <span>{item.size || "24.5 MB"}</span>
                </div>
              </div>
              {item.releaseNotes && (
                <div className="phishingphrenzy_update_notes">
                  <div className="phishingphrenzy_update_notes_title">Release Notes:</div>
                  <div className="phishingphrenzy_update_notes_content">
                    {item.releaseNotes}
                  </div>
                </div>
              )}
            </div>
            <div className="phishingphrenzy_update_footer">
              <div className="phishingphrenzy_update_warning">
                {item.warningMessage}
              </div>
              <div className="phishingphrenzy_update_buttons">
                <button className="phishingphrenzy_update_later_button" disabled>
                  {item.laterText || "Remind me later"}
                </button>
                <button className="phishingphrenzy_update_now_button" disabled>
                  {item.updateText || "Update Now"}
                </button>
              </div>
              <div className="phishingphrenzy_update_source">
                Download source: {item.downloadSource || "official-update-server.com"}
              </div>
            </div>
          </div>
        );
      
     
      case 'puzzle_game':
        return (
          <div className="phishingphrenzy_puzzle">
            <div className="phishingphrenzy_puzzle_header">
              <div className="phishingphrenzy_puzzle_icon">
                <FaGamepad />
              </div>
              <div className="phishingphrenzy_puzzle_title">
                {item.title || "Win a Prize!"}
              </div>
            </div>
            <div className="phishingphrenzy_puzzle_body">
              <div className="phishingphrenzy_puzzle_message">
                {item.message || "Congratulations! You've been selected to play our prize game!"}
              </div>
              <div className="phishingphrenzy_puzzle_game">
                <div className="phishingphrenzy_puzzle_challenge">
                  {item.challenge || "Find the hidden object in the image below:"}
                </div>
                <div className="phishingphrenzy_puzzle_image">
                  <div className="phishingphrenzy_puzzle_image_placeholder">
                    [Interactive Game Image]
                  </div>
                </div>
              </div>
              <div className="phishingphrenzy_puzzle_prizes">
                <div className="phishingphrenzy_puzzle_prizes_title">Prizes you can win:</div>
                <ul className="phishingphrenzy_puzzle_prizes_list">
                  {(item.prizes || [
                    "iPhone 15 Pro Max",
                    "$500 Amazon Gift Card",
                    "Bluetooth Headphones",
                    "Smart Watch"
                  ]).map((prize, idx) => (
                    <li key={idx} className="phishingphrenzy_puzzle_prize_item">
                      {prize}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="phishingphrenzy_puzzle_timer">
                <div className="phishingphrenzy_puzzle_timer_label">Time remaining:</div>
                <div className="phishingphrenzy_puzzle_timer_value">
                  {item.timeRemaining || "02:59"}
                </div>
              </div>
            </div>
            <div className="phishingphrenzy_puzzle_footer">
              <div className="phishingphrenzy_puzzle_participation">
                <div className="phishingphrenzy_puzzle_attempts">
                  Attempts remaining: {item.attemptsRemaining || "3"}
                </div>
                <button className="phishingphrenzy_puzzle_play_button" disabled>
                  {item.playButtonText || "Play Now"}
                </button>
              </div>
              <div className="phishingphrenzy_puzzle_terms">
                * {item.terms || "To claim your prize, you must provide your contact information."}
              </div>
              <div className="phishingphrenzy_puzzle_url">
                Game URL: {item.gameUrl || "prize-game-winner.com/play"}
              </div>
            </div>
          </div>
        );
      
     
      case 'video_conference':
        return (
          <div className="phishingphrenzy_conference">
            <div className="phishingphrenzy_conference_header">
              <div className="phishingphrenzy_conference_logo">
                {item.logo ? (
                  <img src={item.logo} alt="Conference platform logo" />
                ) : (
                  <div className="phishingphrenzy_conference_logo_placeholder">
                    <FaCamera />
                  </div>
                )}
              </div>
              <div className="phishingphrenzy_conference_platform">
                {item.platform || "Video Meeting"}
              </div>
            </div>
            <div className="phishingphrenzy_conference_body">
              <div className="phishingphrenzy_conference_title">
                {item.title || "You've been invited to a meeting"}
              </div>
              <div className="phishingphrenzy_conference_organizer">
                <span className="phishingphrenzy_conference_from">From:</span>
                <span className="phishingphrenzy_conference_organizer_name">{item.organizer || "John Smith"}</span>
                <span className="phishingphrenzy_conference_organizer_email">{item.organizerEmail || "john.smith@example.com"}</span>
              </div>
              <div className="phishingphrenzy_conference_details">
                <div className="phishingphrenzy_conference_topic">
                  <span className="phishingphrenzy_conference_label">Topic:</span>
                  <span>{item.topic || "Project Review Meeting"}</span>
                </div>
                <div className="phishingphrenzy_conference_time">
                  <span className="phishingphrenzy_conference_label">Time:</span>
                  <span>{item.time || "Apr 23, 2025, 3:00 PM"}</span>
                </div>
                <div className="phishingphrenzy_conference_duration">
                  <span className="phishingphrenzy_conference_label">Duration:</span>
                  <span>{item.duration || "1 hour"}</span>
                </div>
              </div>
              <div className="phishingphrenzy_conference_join_info">
                <div className="phishingphrenzy_conference_join_title">
                  Join information:
                </div>
                <div className="phishingphrenzy_conference_link">
                  <div className="phishingphrenzy_conference_link_label">Meeting link:</div>
                  <div className="phishingphrenzy_conference_link_url">
                    {item.meetingLink || "https://meet.example.com/abc-xyz-123"}
                  </div>
                </div>
                <div className="phishingphrenzy_conference_id">
                  <span className="phishingphrenzy_conference_label">Meeting ID:</span>
                  <span>{item.meetingId || "123 456 789"}</span>
                </div>
                <div className="phishingphrenzy_conference_passcode">
                  <span className="phishingphrenzy_conference_label">Passcode:</span>
                  <span>{item.passcode || "123456"}</span>
                </div>
              </div>
            </div>
            <div className="phishingphrenzy_conference_footer">
              <button className="phishingphrenzy_conference_join_button" disabled>
                {item.joinButtonText || "Join Meeting"}
              </button>
              <div className="phishingphrenzy_conference_note">
                {item.note || "By joining, you agree to the terms of service."}
              </div>
              <div className="phishingphrenzy_conference_url">
                Host domain: {item.hostDomain || "meet.example.com"}
              </div>
            </div>
          </div>
        );
      
     
      case 'file_sharing':
        return (
          <div className="phishingphrenzy_file_sharing">
            <div className="phishingphrenzy_file_sharing_header">
              <div className="phishingphrenzy_file_sharing_logo">
                {item.logo ? (
                  <img src={item.logo} alt="File sharing platform logo" />
                ) : (
                  <div className="phishingphrenzy_file_sharing_logo_placeholder">
                    <FaShareAlt />
                  </div>
                )}
              </div>
              <div className="phishingphrenzy_file_sharing_platform">
                {item.platform || "File Sharing"}
              </div>
            </div>
            <div className="phishingphrenzy_file_sharing_body">
              <div className="phishingphrenzy_file_sharing_title">
                {item.title || "Shared file with you"}
              </div>
              <div className="phishingphrenzy_file_sharing_from">
                <div className="phishingphrenzy_file_sharing_user_info">
                  <div className="phishingphrenzy_file_sharing_user_avatar">
                    {item.userName ? item.userName[0] : 'U'}
                  </div>
                  <div className="phishingphrenzy_file_sharing_user_details">
                    <div className="phishingphrenzy_file_sharing_user_name">
                      {item.userName || "James Wilson"}
                    </div>
                    <div className="phishingphrenzy_file_sharing_user_email">
                      {item.userEmail || "james.wilson@example.com"}
                    </div>
                  </div>
                </div>
                <div className="phishingphrenzy_file_sharing_message">
                  {item.message || "I've shared an important document with you. Please review it as soon as possible."}
                </div>
              </div>
              <div className="phishingphrenzy_file_sharing_file">
                <div className="phishingphrenzy_file_sharing_file_icon">
                  <FaFileAlt />
                </div>
                <div className="phishingphrenzy_file_sharing_file_info">
                  <div className="phishingphrenzy_file_sharing_file_name">
                    {item.fileName || "Confidential_Document.pdf"}
                  </div>
                  <div className="phishingphrenzy_file_sharing_file_details">
                    <span>{item.fileSize || "2.4 MB"}</span>
                    <span>{item.fileType || "PDF Document"}</span>
                  </div>
                </div>
              </div>
              <div className="phishingphrenzy_file_sharing_expires">
                This link expires in {item.expirationPeriod || "7 days"}
              </div>
            </div>
            <div className="phishingphrenzy_file_sharing_footer">
              <button className="phishingphrenzy_file_sharing_button" disabled>
                {item.buttonText || "View Document"}
              </button>
              <div className="phishingphrenzy_file_sharing_note">
                {item.note || "You'll need to sign in to access this file."}
              </div>
              <div className="phishingphrenzy_file_sharing_url">
                File URL: {item.fileUrl || "https://docs-share.example.com/f/abcxyz123"}
              </div>
            </div>
          </div>
        );
      
      // # Extra types (variations of existing types)
      

      case 'modern_email':
        return (
          <div className="phishingphrenzy_modern_email">
            <div className="phishingphrenzy_modern_email_sender">
              <div className="phishingphrenzy_modern_email_avatar">
                {item.from ? item.from[0] : 'S'}
              </div>
              <div className="phishingphrenzy_modern_email_sender_info">
                <div className="phishingphrenzy_modern_email_sender_name">
                  {item.senderName || item.from || "Sender"}
                </div>
                <div className="phishingphrenzy_modern_email_sender_address">
                  {item.from || "sender@example.com"}
                </div>
              </div>
              <div className="phishingphrenzy_modern_email_date">
                {item.date || "Today, 10:45 AM"}
              </div>
            </div>
            <div className="phishingphrenzy_modern_email_subject">
              {item.subject}
            </div>
            <div className="phishingphrenzy_modern_email_content">
              <div className="phishingphrenzy_modern_email_body">
                {item.body}
              </div>
              {item.callToAction && (
                <div className="phishingphrenzy_modern_email_cta">
                  <a href="#" onClick={(e) => e.preventDefault()} className="phishingphrenzy_modern_email_cta_button">
                    {item.callToAction}
                  </a>
                </div>
              )}
              {item.links && item.links.length > 0 && (
                <div className="phishingphrenzy_modern_email_links">
                  <div className="phishingphrenzy_modern_email_links_label">Links in email:</div>
                  {item.links.map((link, idx) => (
                    <div className="phishingphrenzy_modern_email_link" key={idx}>
                      <FaLink /> <span className="phishingphrenzy_modern_email_link_text">{link}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="phishingphrenzy_modern_email_footer">
              <div className="phishingphrenzy_modern_email_actions">
                <button className="phishingphrenzy_modern_email_action_button" disabled>Reply</button>
                <button className="phishingphrenzy_modern_email_action_button" disabled>Forward</button>
                <button className="phishingphrenzy_modern_email_action_button" disabled>Reply</button>
                <button className="phishingphrenzy_modern_email_action_button" disabled>Forward</button>
                <button className="phishingphrenzy_modern_email_action_button" disabled>Delete</button>
              </div>
            </div>
          </div>
        );
      
      case 'bank_notification':
        return (
          <div className="phishingphrenzy_bank_notification">
            <div className="phishingphrenzy_bank_header">
              <div className="phishingphrenzy_bank_logo">
                <div className="phishingphrenzy_bank_logo_placeholder">B</div>
              </div>
              <div className="phishingphrenzy_bank_title">
                {item.bankName || "Online Banking Alert"}
              </div>
            </div>
            <div className="phishingphrenzy_bank_body">
              <div className="phishingphrenzy_bank_alert">
                <div className="phishingphrenzy_bank_alert_icon">
                  <FaExclamationTriangle />
                </div>
                <div className="phishingphrenzy_bank_alert_text">
                  {item.alertMessage || "Important account notification requires your attention."}
                </div>
              </div>
              <div className="phishingphrenzy_bank_message">
                {item.message || "We have detected unusual activity on your account that requires verification. Please review the details below and take action to secure your account."}
              </div>
              <div className="phishingphrenzy_bank_details">
                <div className="phishingphrenzy_bank_detail">
                  <div className="phishingphrenzy_bank_detail_label">Account Number:</div>
                  <div className="phishingphrenzy_bank_detail_value">{item.accountNumber || "XXXX-XXXX-XXXX-3857"}</div>
                </div>
                <div className="phishingphrenzy_bank_detail">
                  <div className="phishingphrenzy_bank_detail_label">Alert Type:</div>
                  <div className="phishingphrenzy_bank_detail_value">{item.alertType || "Security Verification"}</div>
                </div>
                <div className="phishingphrenzy_bank_detail">
                  <div className="phishingphrenzy_bank_detail_label">Date Detected:</div>
                  <div className="phishingphrenzy_bank_detail_value">{item.dateDetected || "April 22, 2025"}</div>
                </div>
                <div className="phishingphrenzy_bank_detail">
                  <div className="phishingphrenzy_bank_detail_label">Status:</div>
                  <div className="phishingphrenzy_bank_detail_value">{item.status || "Pending Verification"}</div>
                </div>
              </div>
              <div className="phishingphrenzy_bank_actions">
                <div className="phishingphrenzy_bank_action_message">
                  Please verify your identity to maintain full access to your online banking services.
                </div>
                <div className="phishingphrenzy_bank_buttons">
                  <button className="phishingphrenzy_bank_button primary" disabled>
                    Verify Identity
                  </button>
                  <button className="phishingphrenzy_bank_button secondary" disabled>
                    Contact Support
                  </button>
                </div>
              </div>
            </div>
            <div className="phishingphrenzy_bank_footer">
              <div className="phishingphrenzy_bank_footer_text">
                For security reasons, this notification will expire in 24 hours.
              </div>
              <div className="phishingphrenzy_bank_url">
                {item.url || "https://secure-bank-verify.com/auth/login"}
              </div>
            </div>
          </div>
        );
      
      case 'crypto_investment':
        return (
          <div className="phishingphrenzy_crypto_investment">
            <div className="phishingphrenzy_crypto_header">
              <div className="phishingphrenzy_crypto_logo">
                <FaBitcoin />
              </div>
              <div className="phishingphrenzy_crypto_title">
                {item.platform || "CryptoWealth Investments"}
              </div>
              <div className="phishingphrenzy_crypto_subtitle">
                {item.slogan || "The Future of Financial Freedom"}
              </div>
            </div>
            <div className="phishingphrenzy_crypto_body">
              <div className="phishingphrenzy_crypto_opportunity">
                <div className="phishingphrenzy_crypto_opportunity_title">
                  <span className="phishingphrenzy_crypto_opportunity_icon">
                    <FaChartLine />
                  </span>
                  {item.opportunityTitle || "Exclusive Investment Opportunity"}
                </div>
                <div className="phishingphrenzy_crypto_opportunity_text">
                  {item.opportunityText || "Our proprietary trading algorithm has consistently delivered 35% monthly returns for our investors. For a limited time, we're opening access to our platform for select new investors with a minimum investment of only $500."}
                </div>
              </div>
              <div className="phishingphrenzy_crypto_stats">
                <div className="phishingphrenzy_crypto_stat">
                  <div className="phishingphrenzy_crypto_stat_value">35%</div>
                  <div className="phishingphrenzy_crypto_stat_label">Monthly Return</div>
                </div>
                <div className="phishingphrenzy_crypto_stat">
                  <div className="phishingphrenzy_crypto_stat_value">$500</div>
                  <div className="phishingphrenzy_crypto_stat_label">Min Investment</div>
                </div>
                <div className="phishingphrenzy_crypto_stat">
                  <div className="phishingphrenzy_crypto_stat_value">24/7</div>
                  <div className="phishingphrenzy_crypto_stat_label">Live Support</div>
                </div>
              </div>
              <div className="phishingphrenzy_crypto_testimonials">
                <div className="phishingphrenzy_crypto_testimonials_title">
                  What Our Investors Say
                </div>
                <div className="phishingphrenzy_crypto_testimonial">
                  <div className="phishingphrenzy_crypto_testimonial_text">
                    "I invested $2,000 just 3 months ago and have already made over $7,000 in profits. This platform changed my life!"
                  </div>
                  <div className="phishingphrenzy_crypto_testimonial_author">
                    - James R., London
                  </div>
                </div>
                <div className="phishingphrenzy_crypto_testimonial">
                  <div className="phishingphrenzy_crypto_testimonial_text">
                    "After trying multiple crypto platforms, this is the only one that consistently delivers results. 10/10 would recommend."
                  </div>
                  <div className="phishingphrenzy_crypto_testimonial_author">
                    - Sarah M., Toronto
                  </div>
                </div>
              </div>
            </div>
            <div className="phishingphrenzy_crypto_action">
              <button className="phishingphrenzy_crypto_action_button" disabled>
                Start Investing Now
              </button>
              <div className="phishingphrenzy_crypto_disclaimer">
                Limited spots available. Offer ends in 24 hours.
              </div>
              <div className="phishingphrenzy_crypto_url">
                {item.url || "https://crypto-wealth-platform.io/special-offer"}
              </div>
            </div>
          </div>
        );
      
      case 'account_verification':
        return (
          <div className="phishingphrenzy_account_verification">
            <div className="phishingphrenzy_verification_header">
              <div className="phishingphrenzy_verification_logo">
                <div className="phishingphrenzy_verification_logo_placeholder">
                  <FaShieldAlt />
                </div>
              </div>
              <div className="phishingphrenzy_verification_title">
                {item.serviceName || "Account Verification Required"}
              </div>
            </div>
            <div className="phishingphrenzy_verification_body">
              <div className="phishingphrenzy_verification_message">
                {item.message || "For your security, we need to verify your account information to ensure continued access to all services. This verification is required by updated security protocols."}
              </div>
              <div className="phishingphrenzy_verification_status">
                <div className="phishingphrenzy_verification_status_icon">
                  <FaExclamationCircle />
                </div>
                <div className="phishingphrenzy_verification_status_text">
                  {item.statusMessage || "Your account access will be limited until verification is completed."}
                </div>
              </div>
              <div className="phishingphrenzy_verification_steps">
                <div className="phishingphrenzy_verification_steps_title">
                  Complete These Steps to Verify Your Account:
                </div>
                <div className="phishingphrenzy_verification_step">
                  <div className="phishingphrenzy_verification_step_number">1</div>
                  <div className="phishingphrenzy_verification_step_text">
                    Click the "Verify Account" button below to access the secure verification portal.
                  </div>
                </div>
                <div className="phishingphrenzy_verification_step">
                  <div className="phishingphrenzy_verification_step_number">2</div>
                  <div className="phishingphrenzy_verification_step_text">
                    Sign in with your existing credentials.
                  </div>
                </div>
                <div className="phishingphrenzy_verification_step">
                  <div className="phishingphrenzy_verification_step_number">3</div>
                  <div className="phishingphrenzy_verification_step_text">
                    Confirm your personal information and update if necessary.
                  </div>
                </div>
                <div className="phishingphrenzy_verification_step">
                  <div className="phishingphrenzy_verification_step_number">4</div>
                  <div className="phishingphrenzy_verification_step_text">
                    Complete the security questions and verification process.
                  </div>
                </div>
              </div>
              <div className="phishingphrenzy_verification_deadline">
                <div className="phishingphrenzy_verification_deadline_icon">
                  <FaClock />
                </div>
                <div className="phishingphrenzy_verification_deadline_text">
                  {item.deadline || "This verification request expires in 48 hours. After this period, account limitations may be applied."}
                </div>
              </div>
            </div>
            <div className="phishingphrenzy_verification_footer">
              <button className="phishingphrenzy_verification_button" disabled>
                Verify Account Now
              </button>
              <div className="phishingphrenzy_verification_note">
                Verification typically takes less than 5 minutes to complete.
              </div>
              <div className="phishingphrenzy_verification_url">
                {item.url || "https://account-verification-secure.com/verify"}
              </div>
            </div>
          </div>
        );
      
      case 'lottery_winner':
        return (
          <div className="phishingphrenzy_lottery_winner">
            <div className="phishingphrenzy_lottery_header">
              <div className="phishingphrenzy_lottery_logo">
                <FaTrophy />
              </div>
              <div className="phishingphrenzy_lottery_title">
                {item.lotteryName || "International Lottery Commission"}
              </div>
              <div className="phishingphrenzy_lottery_subtitle">
                {item.subtitle || "Official Winner Notification"}
              </div>
            </div>
            <div className="phishingphrenzy_lottery_body">
              <div className="phishingphrenzy_lottery_congratulations">
                <div className="phishingphrenzy_lottery_congrats_title">
                  Congratulations!
                </div>
                <div className="phishingphrenzy_lottery_congrats_text">
                  {item.congratsMessage || "Your email address has been selected as a winner in our international electronic lottery draw held on April 15, 2025."}
                </div>
                <div className="phishingphrenzy_lottery_amount">
                  {item.prizeAmount || "$1,500,000.00 USD"}
                </div>
              </div>
              <div className="phishingphrenzy_lottery_details">
                <div className="phishingphrenzy_lottery_details_title">
                  Winner Details:
                </div>
                <div className="phishingphrenzy_lottery_detail">
                  <div className="phishingphrenzy_lottery_detail_label">Reference Number:</div>
                  <div className="phishingphrenzy_lottery_detail_value">{item.referenceNumber || "ILC/92735/2025"}</div>
                </div>
                <div className="phishingphrenzy_lottery_detail">
                  <div className="phishingphrenzy_lottery_detail_label">Batch Number:</div>
                  <div className="phishingphrenzy_lottery_detail_value">{item.batchNumber || "BN/173/8926/ILC"}</div>
                </div>
                <div className="phishingphrenzy_lottery_detail">
                  <div className="phishingphrenzy_lottery_detail_label">Draw Date:</div>
                  <div className="phishingphrenzy_lottery_detail_value">{item.drawDate || "April 15, 2025"}</div>
                </div>
                <div className="phishingphrenzy_lottery_detail">
                  <div className="phishingphrenzy_lottery_detail_label">Winner Number:</div>
                  <div className="phishingphrenzy_lottery_detail_value">{item.winnerNumber || "23 out of 50 winners"}</div>
                </div>
              </div>
              <div className="phishingphrenzy_lottery_instructions">
                <div className="phishingphrenzy_lottery_instructions_title">
                  To Claim Your Prize:
                </div>
                <ol className="phishingphrenzy_lottery_instructions_list">
                  <li className="phishingphrenzy_lottery_instructions_item">
                    Contact our claims agent immediately with your reference number.
                  </li>
                  <li className="phishingphrenzy_lottery_instructions_item">
                    Complete the verification process to confirm your identity.
                  </li>
                  <li className="phishingphrenzy_lottery_instructions_item">
                    Provide necessary information for prize transfer to your bank account.
                  </li>
                  <li className="phishingphrenzy_lottery_instructions_item">
                    Keep your winning information confidential for security purposes.
                  </li>
                </ol>
                <div className="phishingphrenzy_lottery_warning">
                  Your prize must be claimed within 14 days or it will be forfeited.
                </div>
              </div>
            </div>
            <div className="phishingphrenzy_lottery_footer">
              <button className="phishingphrenzy_lottery_button" disabled>
                Claim Your Prize Now
              </button>
              <div className="phishingphrenzy_lottery_disclaimer">
                A processing fee of $93.50 may apply to verify international transfers.
              </div>
              <div className="phishingphrenzy_lottery_url">
                {item.url || "https://intl-lottery-commission.org/claim-prize"}
              </div>
            </div>
          </div>
        );
      
          
          case 'charity_donation':
            return (
              <div className="phishingphrenzy_charity_donation">
                <div className="phishingphrenzy_charity_header">
                  <div className="phishingphrenzy_charity_logo">
                    <FaHandHoldingHeart />
                  </div>
                  <div className="phishingphrenzy_charity_title">
                    {item.charityName || "Global Relief Foundation"}
                  </div>
                  <div className="phishingphrenzy_charity_subtitle">
                    {item.slogan || "Help Us Make a Difference Today"}
                  </div>
                </div>
                <div className="phishingphrenzy_charity_body">
                  <div className="phishingphrenzy_charity_message">
                    {item.appealMessage || "Our organization is currently responding to a humanitarian crisis affecting millions of people. Your donation today can provide immediate relief to families in desperate need of food, water, shelter, and medical care."}
                  </div>
                  <div className="phishingphrenzy_charity_impact">
                    <div className="phishingphrenzy_charity_impact_item">
                      <div className="phishingphrenzy_charity_donate">
                        <div className="phishingphrenzy_charity_donate_title">
                          Make a Donation Today
                        </div>
                        <div className="phishingphrenzy_charity_amount_buttons">
                          <button className="phishingphrenzy_charity_amount_button" disabled>$10</button>
                          <button className="phishingphrenzy_charity_amount_button" disabled>$25</button>
                          <button className="phishingphrenzy_charity_amount_button active" disabled>$50</button>
                          <button className="phishingphrenzy_charity_amount_button" disabled>$100</button>
                        </div>
                        <div className="phishingphrenzy_charity_custom_amount">
                          <div className="phishingphrenzy_charity_custom_label">Custom Amount:</div>
                          <input type="text" className="phishingphrenzy_charity_custom_input" placeholder="Enter amount" disabled />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="phishingphrenzy_charity_footer">
                  <button className="phishingphrenzy_charity_button" disabled>
                    Donate Now
                  </button>
                  <div className="phishingphrenzy_charity_secure">
                    <span className="phishingphrenzy_charity_secure_icon">
                      <FaLock />
                    </span>
                    Secure donation processing
                  </div>
                  <div className="phishingphrenzy_charity_url">
                    {item.url || "https://global-relief-foundation.org/donate"}
                  </div>
                </div>
              </div>
            );
          
          
          case 'package_delivery':
            return (
              <div className="phishingphrenzy_package_delivery">
                <div className="phishingphrenzy_package_header">
                  <div className="phishingphrenzy_package_logo">
                    <div className="phishingphrenzy_package_logo_placeholder">
                      <FaShippingFast />
                    </div>
                  </div>
                  <div className="phishingphrenzy_package_title">
                    {item.courierName || "Package Delivery Notification"}
                  </div>
                </div>
                <div className="phishingphrenzy_package_body">
                  <div className="phishingphrenzy_package_message">
                    {item.message || "We attempted to deliver your package today but we were unable to complete the delivery due to an incorrect delivery address."}
                  </div>
                  <div className="phishingphrenzy_package_status">
                    <div className="phishingphrenzy_package_status_icon">
                      <FaExclamationTriangle />
                    </div>
                    <div className="phishingphrenzy_package_status_text">
                      {item.statusMessage || "Action Required: Please update your delivery information to receive your package."}
                    </div>
                  </div>
                  <div className="phishingphrenzy_package_details">
                    <div className="phishingphrenzy_package_details_title">
                      Shipment Details:
                    </div>
                    <div className="phishingphrenzy_package_detail">
                      <div className="phishingphrenzy_package_detail_label">Tracking Number:</div>
                      <div className="phishingphrenzy_package_detail_value">{item.trackingNumber || "DX785421936"}</div>
                    </div>
                    <div className="phishingphrenzy_package_detail">
                      <div className="phishingphrenzy_package_detail_label">Delivery Attempt:</div>
                      <div className="phishingphrenzy_package_detail_value">{item.deliveryAttempt || "April 22, 2025, 10:45 AM"}</div>
                    </div>
                    <div className="phishingphrenzy_package_detail">
                      <div className="phishingphrenzy_package_detail_label">Carrier:</div>
                      <div className="phishingphrenzy_package_detail_value">{item.carrier || "Express Delivery Service"}</div>
                    </div>
                    <div className="phishingphrenzy_package_detail">
                      <div className="phishingphrenzy_package_detail_label">Status:</div>
                      <div className="phishingphrenzy_package_detail_value">{item.status || "Delivery Failed - Address Error"}</div>
                    </div>
                  </div>
                  <div className="phishingphrenzy_package_actions">
                    <div className="phishingphrenzy_package_action_message">
                      Please update your delivery address within 24 hours to schedule redelivery.
                    </div>
                    <div className="phishingphrenzy_package_action_note">
                      After 3 days, your package will be returned to the sender.
                    </div>
                  </div>
                </div>
                <div className="phishingphrenzy_package_footer">
                  <button className="phishingphrenzy_package_button" disabled>
                    Update Delivery Address
                  </button>
                  <div className="phishingphrenzy_package_contact">
                    Customer Support: 1-800-555-0123
                  </div>
                  <div className="phishingphrenzy_package_url">
                    {item.url || "https://delivery-tracking.info/update-address"}
                  </div>
                </div>
              </div>
            );
          
          case 'cloud_storage':
            return (
              <div className="phishingphrenzy_cloud_storage">
                <div className="phishingphrenzy_cloud_header">
                  <div className="phishingphrenzy_cloud_logo">
                    <FaCloud />
                  </div>
                  <div className="phishingphrenzy_cloud_title">
                    {item.serviceName || "Cloud Storage Alert"}
                  </div>
                </div>
                <div className="phishingphrenzy_cloud_body">
                  <div className="phishingphrenzy_cloud_alert">
                    <div className="phishingphrenzy_cloud_alert_icon">
                      <FaExclamationCircle />
                    </div>
                    <div className="phishingphrenzy_cloud_alert_text">
                      {item.alertMessage || "Your cloud storage is almost full. You've used 95% of your free storage quota. Upgrade now to prevent data loss and service interruptions."}
                    </div>
                  </div>
                  <div className="phishingphrenzy_cloud_usage">
                    <div className="phishingphrenzy_cloud_usage_title">
                      Storage Usage:
                    </div>
                    <div className="phishingphrenzy_cloud_usage_bar_container">
                      <div className="phishingphrenzy_cloud_usage_bar"></div>
                    </div>
                    <div className="phishingphrenzy_cloud_usage_stats">
                      <div className="phishingphrenzy_cloud_usage_used">
                        {item.storageUsed || "19.0 GB used"}
                      </div>
                      <div className="phishingphrenzy_cloud_usage_total">
                        {item.storageTotal || "of 20 GB"}
                      </div>
                    </div>
                  </div>
                  <div className="phishingphrenzy_cloud_upgrade">
                    <div className="phishingphrenzy_cloud_upgrade_title">
                      Upgrade Options:
                    </div>
                    <div className="phishingphrenzy_cloud_plans">
                      <div className="phishingphrenzy_cloud_plan">
                        <div className="phishingphrenzy_cloud_plan_name">Basic</div>
                        <div className="phishingphrenzy_cloud_plan_storage">100GB</div>
                        <div className="phishingphrenzy_cloud_plan_price">$1.99/month</div>
                        <button className="phishingphrenzy_cloud_plan_button" disabled>
                          Select
                        </button>
                      </div>
                      <div className="phishingphrenzy_cloud_plan phishingphrenzy_cloud_recommended">
                        <div className="phishingphrenzy_cloud_plan_name">Premium</div>
                        <div className="phishingphrenzy_cloud_plan_storage">1TB</div>
                        <div className="phishingphrenzy_cloud_plan_price">$9.99/month</div>
                        <button className="phishingphrenzy_cloud_plan_button" disabled>
                          Select
                        </button>
                      </div>
                      <div className="phishingphrenzy_cloud_plan">
                        <div className="phishingphrenzy_cloud_plan_name">Business</div>
                        <div className="phishingphrenzy_cloud_plan_storage">5TB</div>
                        <div className="phishingphrenzy_cloud_plan_price">$29.99/month</div>
                        <button className="phishingphrenzy_cloud_plan_button" disabled>
                          Select
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="phishingphrenzy_cloud_footer">
                  <button className="phishingphrenzy_cloud_button" disabled>
                    Upgrade Storage Now
                  </button>
                  <div className="phishingphrenzy_cloud_secure">
                    <span className="phishingphrenzy_cloud_secure_icon">
                      <FaLock />
                    </span>
                    Secure payment processing
                  </div>
                  <div className="phishingphrenzy_cloud_url">
                    {item.url || "https://secure-cloud-storage.com/upgrade"}
                  </div>
                </div>
              </div>
            );
          
          case 'dating_profile':
            return (
              <div className="phishingphrenzy_dating_profile">
                <div className="phishingphrenzy_dating_header">
                  <div className="phishingphrenzy_dating_logo">
                    <FaHeart />
                  </div>
                  <div className="phishingphrenzy_dating_title">
                    {item.appName || "ConnectMatch"}
                  </div>
                </div>
                <div className="phishingphrenzy_dating_body">
                  <div className="phishingphrenzy_dating_profile_section">
                    <div className="phishingphrenzy_dating_profile_pic">
                      {item.profilePic || <FaUser />}
                    </div>
                    <div className="phishingphrenzy_dating_profile_info">
                      <div className="phishingphrenzy_dating_profile_name">
                        {item.name || "Jessica, 28"}
                        <span className="phishingphrenzy_dating_profile_verified">
                          <FaCheckCircle />
                        </span>
                      </div>
                      <div className="phishingphrenzy_dating_profile_details">
                        <span className="phishingphrenzy_dating_profile_detail">
                          {item.location || "2 miles away"}
                        </span>
                        <span className="phishingphrenzy_dating_profile_detail">
                          {item.occupation || "Model / Influencer"}
                        </span>
                      </div>
                      <div className="phishingphrenzy_dating_profile_bio">
                        {item.bio || "Just moved to this area! Looking to make new friends and maybe find someone special. I love traveling, fitness, and photography. Message me if you want to chat! 😊"}
                      </div>
                    </div>
                  </div>
                  <div className="phishingphrenzy_dating_message_section">
                    <div className="phishingphrenzy_dating_message">
                      {item.message || "Hey there! I saw your profile and thought you seemed interesting. I'm fairly new here and don't fully understand how this app works yet. Can we chat on my Instagram instead? It's @jessica_model92 or you can check out my pics here:"} 
                      <span className="phishingphrenzy_dating_link">{item.link || "https://photo-view.me/jessica92"}</span>
                      <div className="phishingphrenzy_dating_message_time">
                        Just now
                      </div>
                    </div>
                  </div>
                </div>
                <div className="phishingphrenzy_dating_footer">
                  <div className="phishingphrenzy_dating_reply" disabled>
                    Type a message...
                  </div>
                  <div className="phishingphrenzy_dating_buttons">
                    <button className="phishingphrenzy_dating_button" disabled>
                      <FaHeart />
                    </button>
                    <button className="phishingphrenzy_dating_button secondary" disabled>
                      <FaCamera />
                    </button>
                  </div>
                </div>
                <div className="phishingphrenzy_dating_app_url">
                  {item.appUrl || "connectmatch-app.com/messages"}
                </div>
              </div>
            );
          
          case 'review_request':
            return (
              <div className="phishingphrenzy_review_request">
                <div className="phishingphrenzy_review_header">
                  <div className="phishingphrenzy_review_logo">
                    <div className="phishingphrenzy_review_logo_placeholder">
                      <FaStar />
                    </div>
                  </div>
                  <div className="phishingphrenzy_review_title">
                    {item.storeName || "Product Review Request"}
                  </div>
                </div>
                <div className="phishingphrenzy_review_body">
                  <div className="phishingphrenzy_review_message">
                    {item.message || "Thank you for your recent purchase! We would appreciate if you could take a moment to share your feedback. Your review helps other customers make informed decisions and helps us improve our products and services."}
                  </div>
                  <div className="phishingphrenzy_review_product">
                    <div className="phishingphrenzy_review_product_image">
                      <FaBox />
                    </div>
                    <div className="phishingphrenzy_review_product_info">
                      <div className="phishingphrenzy_review_product_name">
                        {item.productName || "Premium Wireless Bluetooth Headphones"}
                      </div>
                      <div className="phishingphrenzy_review_product_details">
                        {item.orderDetails || "Order #39285 • Delivered April 18, 2025"}
                      </div>
                      <div className="phishingphrenzy_review_product_date">
                        {item.purchaseDate || "Purchased on April 15, 2025"}
                      </div>
                    </div>
                  </div>
                  <div className="phishingphrenzy_review_stars">
                    <div className="phishingphrenzy_review_stars_title">
                      Rate your experience:
                    </div>
                    <div className="phishingphrenzy_review_stars_buttons">
                      <span className="phishingphrenzy_review_star active">★</span>
                      <span className="phishingphrenzy_review_star active">★</span>
                      <span className="phishingphrenzy_review_star active">★</span>
                      <span className="phishingphrenzy_review_star active">★</span>
                      <span className="phishingphrenzy_review_star">★</span>
                    </div>
                  </div>
                  <div className="phishingphrenzy_review_feedback">
                    <div className="phishingphrenzy_review_feedback_label">
                      Share your thoughts (optional):
                    </div>
                    <textarea 
                      className="phishingphrenzy_review_feedback_input" 
                      placeholder="Tell us what you liked or what we can improve..." 
                      disabled
                    ></textarea>
                  </div>
                  <div className="phishingphrenzy_review_incentive">
                    <div className="phishingphrenzy_review_incentive_icon">
                      <FaGift />
                    </div>
                    <div className="phishingphrenzy_review_incentive_text">
                      {item.incentiveText || "As a token of our appreciation, we'll send you a $15 gift card after submitting your review!"}
                    </div>
                  </div>
                </div>
                <div className="phishingphrenzy_review_footer">
                  <button className="phishingphrenzy_review_button skip" disabled>
                    Later
                  </button>
                  <button className="phishingphrenzy_review_button submit" disabled>
                    Submit Review
                  </button>
                </div>
                <div className="phishingphrenzy_review_url">
                  {item.url || "https://customer-reviews.shop/submit-review?code=RT7392"}
                </div>
              </div>
            );
          
          case 'medical_alert':
            return (
              <div className="phishingphrenzy_medical_alert">
                <div className="phishingphrenzy_medical_header">
                  <div className="phishingphrenzy_medical_logo">
                    <FaHospital />
                  </div>
                  <div className="phishingphrenzy_medical_title">
                    {item.facilityName || "Medical Center Patient Portal"}
                  </div>
                </div>
                <div className="phishingphrenzy_medical_body">
                  <div className="phishingphrenzy_medical_alert_box">
                    <div className="phishingphrenzy_medical_alert_icon">
                      <FaClipboardCheck />
                    </div>
                    <div className="phishingphrenzy_medical_alert_text">
                      {item.alertMessage || "Important: Your recent laboratory test results are now available for review."}
                    </div>
                  </div>
                  <div className="phishingphrenzy_medical_patient">
                    <div className="phishingphrenzy_medical_patient_title">
                      Patient Information:
                    </div>
                    <div className="phishingphrenzy_medical_patient_info">
                      <div className="phishingphrenzy_medical_patient_row">
                        <div className="phishingphrenzy_medical_patient_label">Patient ID:</div>
                        <div className="phishingphrenzy_medical_patient_value">{item.patientId || "P-78345219"}</div>
                      </div>
                      <div className="phishingphrenzy_medical_patient_row">
                        <div className="phishingphrenzy_medical_patient_label">Name:</div>
                        <div className="phishingphrenzy_medical_patient_value">{item.patientName || "[Patient Name]"}</div>
                      </div>
                      <div className="phishingphrenzy_medical_patient_row">
                        <div className="phishingphrenzy_medical_patient_label">Test Date:</div>
                        <div className="phishingphrenzy_medical_patient_value">{item.testDate || "April 15, 2025"}</div>
                      </div>
                      <div className="phishingphrenzy_medical_patient_row">
                        <div className="phishingphrenzy_medical_patient_label">Results Available:</div>
                        <div className="phishingphrenzy_medical_patient_value">{item.resultsDate || "April 22, 2025"}</div>
                      </div>
                    </div>
                  </div>
                  <div className="phishingphrenzy_medical_results">
                    <div className="phishingphrenzy_medical_results_title">
                      Test Results Summary:
                    </div>
                    <div className="phishingphrenzy_medical_results_message">
                      {item.resultsMessage || "Your recent laboratory test has shown some values outside the normal reference range. These results require timely attention and may require follow-up testing or consultation."}
                    </div>
                  </div>
                  <div className="phishingphrenzy_medical_action">
                    <div className="phishingphrenzy_medical_action_title">
                      Required Action:
                    </div>
                    <div className="phishingphrenzy_medical_action_text">
                      {item.actionText || "Please log in to your Patient Portal to view your complete test results and recommendations from your healthcare provider. If you have any questions, contact your healthcare provider."}
                    </div>
                    <div className="phishingphrenzy_medical_note">
                      For your privacy, test details cannot be displayed in this message.
                    </div>
                  </div>
                </div>
                <div className="phishingphrenzy_medical_footer">
                  <button className="phishingphrenzy_medical_button" disabled>
                    Access Patient Portal
                  </button>
                  <div className="phishingphrenzy_medical_confidential">
                    CONFIDENTIAL: This message contains protected health information.
                  </div>
                  <div className="phishingphrenzy_medical_url">
                    {item.url || "https://patient-portal-medicalcenter.org/login"}
                  </div>
                </div>
              </div>
            );
          
          case 'membership_renewal':
            return (
              <div className="phishingphrenzy_membership_renewal">
                <div className="phishingphrenzy_membership_header">
                  <div className="phishingphrenzy_membership_logo">
                    <div className="phishingphrenzy_membership_logo_placeholder">
                      <FaIdCard />
                    </div>
                  </div>
                  <div className="phishingphrenzy_membership_title">
                    {item.serviceName || "Premium Membership Renewal"}
                  </div>
                </div>
                <div className="phishingphrenzy_membership_body">
                  <div className="phishingphrenzy_membership_message">
                    {item.message || "Your premium membership is about to expire. To ensure uninterrupted access to exclusive benefits and services, please renew your subscription before the expiration date."}
                  </div>
                  <div className="phishingphrenzy_membership_status">
                    <div className="phishingphrenzy_membership_status_icon">
                      <FaExclamationCircle />
                    </div>
                    <div className="phishingphrenzy_membership_status_text">
                      {item.statusMessage || "Membership Status: Expiring in 3 days"}
                    </div>
                  </div>
                  <div className="phishingphrenzy_membership_details">
                    <div className="phishingphrenzy_membership_details_title">
                      Membership Information:
                    </div>
                    <div className="phishingphrenzy_membership_detail">
                      <div className="phishingphrenzy_membership_detail_label">Member ID:</div>
                      <div className="phishingphrenzy_membership_detail_value">{item.memberId || "MEM-7834591"}</div>
                    </div>
                    <div className="phishingphrenzy_membership_detail">
                      <div className="phishingphrenzy_membership_detail_label">Current Plan:</div>
                      <div className="phishingphrenzy_membership_detail_value">{item.currentPlan || "Premium Annual"}</div>
                    </div>
                    <div className="phishingphrenzy_membership_detail">
                      <div className="phishingphrenzy_membership_detail_label">Expiration Date:</div>
                      <div className="phishingphrenzy_membership_detail_value">{item.expirationDate || "April 25, 2025"}</div>
                    </div>
                    <div className="phishingphrenzy_membership_detail">
                      <div className="phishingphrenzy_membership_detail_label">Renewal Price:</div>
                      <div className="phishingphrenzy_membership_detail_value phishingphrenzy_membership_value">{item.renewalPrice || "$99.99/year"}</div>
                    </div>
                  </div>
                  <div className="phishingphrenzy_membership_benefits">
                    <div className="phishingphrenzy_membership_benefits_title">
                      Premium Benefits You'll Continue to Enjoy:
                    </div>
                    <ul className="phishingphrenzy_membership_benefits_list">
                      <li className="phishingphrenzy_membership_benefit">
                        Unlimited access to all premium content
                      </li>
                      <li className="phishingphrenzy_membership_benefit">
                        Priority customer support 24/7
                      </li>
                      <li className="phishingphrenzy_membership_benefit">
                        Exclusive member-only discounts and offers
                      </li>
                      <li className="phishingphrenzy_membership_benefit">
                        No advertisements or interruptions
                      </li>
                      <li className="phishingphrenzy_membership_benefit">
                        Early access to new features and content
                      </li>
                    </ul>
                  </div>
                </div>
                <div className="phishingphrenzy_membership_footer">
                  <button className="phishingphrenzy_membership_button" disabled>
                    Renew Membership Now
                  </button>
                  <div className="phishingphrenzy_membership_secure">
                    <span className="phishingphrenzy_membership_secure_icon">
                      <FaLock />
                    </span>
                    Secure payment processing
                  </div>
                  <div className="phishingphrenzy_membership_url">
                    {item.url || "https://premium-membership-renewal.com/renew"}
                  </div>
                </div>
              </div>
            );
          
          case 'news_alert':
            return (
              <div className="phishingphrenzy_news_alert">
                <div className="phishingphrenzy_news_header">
                  <div className="phishingphrenzy_news_logo">
                    <FaNewspaper />
                  </div>
                  <div className="phishingphrenzy_news_title">
                    {item.newsSource || "Breaking News Alert"}
                  </div>
                </div>
                <div className="phishingphrenzy_news_body">
                  <div className="phishingphrenzy_news_breaking">
                    <div className="phishingphrenzy_news_breaking_label">
                      Breaking
                    </div>
                    <div className="phishingphrenzy_news_breaking_text">
                      {item.headline || "Major Economic Shift Could Affect Your Investments"}
                    </div>
                  </div>
                  <div className="phishingphrenzy_news_content">
                    {item.content || "Financial experts are warning about a significant market correction expected in the coming weeks following recent changes in international trade policies. This shift could potentially affect various investment portfolios, particularly those heavily invested in technology and energy sectors."}
                  </div>
                  <div className="phishingphrenzy_news_image">
                    [News Image Placeholder]
                  </div>
                  <div className="phishingphrenzy_news_caption">
                    {item.imageCaption || "Market analysts discussing the potential impact of new economic policies."}
                  </div>
                  <div className="phishingphrenzy_news_more">
                    <div className="phishingphrenzy_news_more_title">
                      Read the full analysis:
                    </div>
                    <a href="#" onClick={(e) => e.preventDefault()} className="phishingphrenzy_news_more_link">
                      {item.link || "https://financial-news-alert.com/market-correction-2025"}
                    </a>
                  </div>
                  <div className="phishingphrenzy_news_related">
                    <div className="phishingphrenzy_news_related_title">
                      Related Stories:
                    </div>
                    <div className="phishingphrenzy_news_related_item">
                      <div className="phishingphrenzy_news_related_image">
                        [Img]
                      </div>
                      <div className="phishingphrenzy_news_related_text">
                        How to protect your investments during market volatility
                      </div>
                    </div>
                    <div className="phishingphrenzy_news_related_item">
                      <div className="phishingphrenzy_news_related_image">
                        [Img]
                      </div>
                      <div className="phishingphrenzy_news_related_text">
                        Expert advice: Top 5 investment strategies for uncertain times
                      </div>
                    </div>
                  </div>
                </div>
                <div className="phishingphrenzy_news_footer">
                  <div className="phishingphrenzy_news_actions">
                    <button className="phishingphrenzy_news_button" disabled>
                      <FaShareAlt /> Share
                    </button>
                    <button className="phishingphrenzy_news_button secondary" disabled>
                      <FaBookmark /> Save
                    </button>
                  </div>
                  <div className="phishingphrenzy_news_source">
                    {item.source || "Source: Financial News Network"}
                  </div>
                </div>
                <div className="phishingphrenzy_news_url">
                  {item.url || "https://financial-news-alert.com/breaking"}
                </div>
              </div>
            );
          
          case 'government_notice':
            return (
              <div className="phishingphrenzy_government_notice">
                <div className="phishingphrenzy_government_header">
                  <div className="phishingphrenzy_government_logo">
                    <div className="phishingphrenzy_government_logo_placeholder">
                      <FaUniversity />
                    </div>
                  </div>
                  <div className="phishingphrenzy_government_title">
                    {item.department || "Department of Treasury"}
                  </div>
                </div>
                <div className="phishingphrenzy_government_body">
                  <div className="phishingphrenzy_government_notice_header">
                    <div className="phishingphrenzy_government_notice_title">
                      {item.noticeTitle || "Official Notice of Action Required"}
                    </div>
                    <div className="phishingphrenzy_government_notice_subtitle">
                      {item.noticeSubtitle || "Reference Number: GOV-2025-78534-TX"}
                    </div>
                  </div>
                  <div className="phishingphrenzy_government_recipient">
                    <div className="phishingphrenzy_government_recipient_title">
                      Recipient Information:
                    </div>
                    <div className="phishingphrenzy_government_recipient_info">
                      <div className="phishingphrenzy_government_recipient_row">
                        <div className="phishingphrenzy_government_recipient_label">Name:</div>
                        <div className="phishingphrenzy_government_recipient_value">{item.recipientName || "[Name]"}</div>
                      </div>
                      <div className="phishingphrenzy_government_recipient_row">
                        <div className="phishingphrenzy_government_recipient_label">Tax ID:</div>
                        <div className="phishingphrenzy_government_recipient_value">{item.taxId || "XXX-XX-1234"}</div>
                      </div>
                      <div className="phishingphrenzy_government_recipient_row">
                        <div className="phishingphrenzy_government_recipient_label">Notice Date:</div>
                        <div className="phishingphrenzy_government_recipient_value">{item.noticeDate || "April 22, 2025"}</div>
                      </div>
                    </div>
                  </div>
                  <div className="phishingphrenzy_government_message">
                    {item.message || "Our records indicate that you may be eligible for a tax refund of $1,483.27 from your 2024 tax filing. Due to an error in the processing system, this refund was not automatically issued with your original tax return. To claim this refund, you must verify your information through our secure online portal."}
                  </div>
                  <div className="phishingphrenzy_government_action">
                    <div className="phishingphrenzy_government_action_title">
                      Required Action:
                    </div>
                    <div className="phishingphrenzy_government_action_text">
                      {item.actionText || "Please access our secure verification portal using the button below. You will need to confirm your identity and provide updated direct deposit information to receive your refund."}
                    </div>
                  </div>
                  <div className="phishingphrenzy_government_deadline">
                    <div className="phishingphrenzy_government_deadline_icon">
                      <FaClock />
                    </div>
                    <div className="phishingphrenzy_government_deadline_text">
                      {item.deadline || "This notice requires action within 14 days of the notice date. After this period, you may need to file an amended return to claim your refund."}
                    </div>
                  </div>
                </div>
                <div className="phishingphrenzy_government_footer">
                  <button className="phishingphrenzy_government_button" disabled>
                    Verify Identity & Claim Refund
                  </button>
                  <div className="phishingphrenzy_government_official">
                    This is an official government communication. Do not discard.
                  </div>
                  <div className="phishingphrenzy_government_url">
                    {item.url || "https://tax-refund-verification.gov.us/verify"}
                  </div>
                </div>
              </div>
            );
              
      // Adding more in the future
           
      default:
        return <div>Unknown content type</div>;
    }
  };

  const getCardIcon = () => {
    switch (item.type) {
      case 'email':
      case 'modern_email':
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
      case 'advertisement':
        return <FaAd className="phishingphrenzy_card_icon" />;
      case 'browser_extension':
        return <FaPuzzlePiece className="phishingphrenzy_card_icon" />;
      case 'event_invitation':
        return <FaCalendarAlt className="phishingphrenzy_card_icon" />;
      case 'survey':
        return <FaPoll className="phishingphrenzy_card_icon" />;
      case 'wifi_portal':
        return <FaWifi className="phishingphrenzy_card_icon" />;
      case 'certificate_error':
        return <FaLock className="phishingphrenzy_card_icon" />;
      case 'software_update':
        return <FaMicrochip className="phishingphrenzy_card_icon" />;
      case 'puzzle_game':
        return <FaGamepad className="phishingphrenzy_card_icon" />;
      case 'video_conference':
        return <FaCamera className="phishingphrenzy_card_icon" />;
      case 'file_sharing':
        return <FaShareAlt className="phishingphrenzy_card_icon" />;
      case 'bank_notification':
        return <FaMoneyCheckAlt className="phishingphrenzy_card_icon" />;
      case 'crypto_investment':
        return <FaBitcoin className="phishingphrenzy_card_icon" />;
      case 'account_verification':
        return <FaShieldAlt className="phishingphrenzy_card_icon" />;
      case 'lottery_winner':
        return <FaTrophy className="phishingphrenzy_card_icon" />;
      case 'charity_donation':
        return <FaHandHoldingHeart className="phishingphrenzy_card_icon" />;
      case 'package_delivery':
        return <FaShippingFast className="phishingphrenzy_card_icon" />;
      case 'cloud_storage':
        return <FaCloud className="phishingphrenzy_card_icon" />;
      case 'dating_profile':
        return <FaHeart className="phishingphrenzy_card_icon" />;
      case 'review_request':
        return <FaStar className="phishingphrenzy_card_icon" />;
      case 'medical_alert':
        return <FaHospital className="phishingphrenzy_card_icon" />;
      case 'membership_renewal':
        return <FaIdCard className="phishingphrenzy_card_icon" />;
      case 'news_alert':
        return <FaNewspaper className="phishingphrenzy_card_icon" />;
      case 'government_notice':
        return <FaUniversity className="phishingphrenzy_card_icon" />;
      default:
        return null;
    }
  };

  return (
    <div className={`phishingphrenzy_card_container ${item.type}-card`}>
      <div className="phishingphrenzy_card_header">
        {getCardIcon()}
        <span className="phishingphrenzy_card_type">
          {cardTypeNames[item.type] || 'Unknown'}
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
