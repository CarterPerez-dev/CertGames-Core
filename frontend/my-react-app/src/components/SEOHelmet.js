// src/components/SEOHelmet.js
import React from 'react';
import { Helmet } from 'react-helmet';
import defaultOgImage from './og-default.jpg';

const SEOHelmet = ({ 
  title, 
  description, 
  canonicalUrl,
  ogImage = 'defaultOgImage', // Default image
  ogType = 'website'
}) => {
  // Base URL - update with your actual domain
  const baseUrl = 'https://certgames.com';
  
  // Full canonical URL
  const fullCanonicalUrl = canonicalUrl ? `${baseUrl}${canonicalUrl}` : baseUrl;
  
  return (
    <Helmet>
      {/* Basic Metadata */}
      <title>{title}</title>
      <meta name="description" content={description} />
      <link rel="canonical" href={fullCanonicalUrl} />
      
      {/* Open Graph / Facebook */}
      <meta property="og:type" content={ogType} />
      <meta property="og:url" content={fullCanonicalUrl} />
      <meta property="og:title" content={title} />
      <meta property="og:description" content={description} />
      <meta property="og:image" content={ogImage} />
      
      {/* Twitter */}
      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:url" content={fullCanonicalUrl} />
      <meta name="twitter:title" content={title} />
      <meta name="twitter:description" content={description} />
      <meta name="twitter:image" content={ogImage} />
    </Helmet>
  );
};

export default SEOHelmet;
