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
  FaVideoCamera,
  FaShareAlt,
  FaMicrochip,
  FaLock
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
                <FaPuzzlePiece />
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
                    <FaVideoCamera />
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
      
      // Adding more
      
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
        return <FaPuzzlePiece className="phishingphrenzy_card_icon" />;
      case 'video_conference':
        return <FaVideoCamera className="phishingphrenzy_card_icon" />;
      case 'file_sharing':
        return <FaShareAlt className="phishingphrenzy_card_icon" />;
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
           item.type === 'modern_email' ? 'Email Message' :
           item.type === 'website' ? 'Website' : 
           item.type === 'sms' ? 'SMS Message' : 
           item.type === 'app_download' ? 'App Download' :
           item.type === 'qr_code' ? 'QR Code' :
           item.type === 'social_media' ? 'Social Media Post' :
           item.type === 'job_offer' ? 'Job Opportunity' :
           item.type === 'tech_support' ? 'Technical Support Alert' :
           item.type === 'document' ? 'Document Download' :
           item.type === 'payment_confirmation' ? 'Payment Confirmation' :
           item.type === 'security_alert' ? 'Security Alert' :
           item.type === 'advertisement' ? 'Online Advertisement' :
           item.type === 'browser_extension' ? 'Browser Extension' :
           item.type === 'event_invitation' ? 'Event Invitation' :
           item.type === 'survey' ? 'Survey or Quiz' :
           item.type === 'wifi_portal' ? 'WiFi Login Portal' :
           item.type === 'certificate_error' ? 'Security Certificate Error' :
           item.type === 'software_update' ? 'Software Update' :
           item.type === 'puzzle_game' ? 'Online Game' :
           item.type === 'video_conference' ? 'Video Meeting Invitation' :
           item.type === 'file_sharing' ? 'File Sharing Link' : 'Unknown'}
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
