// src/components/pages/Info/ExamsPage.js
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { FaSearch, FaFilter, FaChevronDown, FaChevronUp, FaCheckCircle } from 'react-icons/fa';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import SEOHelmet from '../../SEOHelmet';
import StructuredData from '../../StructuredData';
import './ExamsPage.css';
import aplusLogo from './images/aplus.webp';
import awscloudLogo from './images/awscloud.webp';
import cisspLogo from './images/cissp.webp';
import cloudLogo from './images/cloud.webp';
import cyssaLogo from './images/cysa.webp';
import dataLogo from './images/data.webp';
import linuxLogo from './images/linux.webp';
import networkLogo from './images/network.webp';
import pentestLogo from './images/pentest.webp';
import securityLogo from './images/security.webp';
import securityxLogo from './images/securityx.webp';
import serverLogo from './images/server.webp';


const ExamsPage = () => {
  const [activeCategory, setActiveCategory] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [expandedCert, setExpandedCert] = useState(null);

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
        "name": "Certification Exams",
        "item": "https://certgames.com/exams"
      }
    ]
  };

  // Product schema for SEO
const examProductSchema = {
  "@context": "https://schema.org",
  "@type": "Course",
  "name": "CertGames Certification Exam Prep",
  "description": "Practice tests for 12 cybersecurity and IT certifications with over 13,000 questions",
  "provider": {
    "@type": "Organization",
    "name": "CertGames",
    "sameAs": "https://certgames.com"
  },
  "image": "https://certgames.com/images/certification-exam-prep.webp", // Add image field
  "offers": {
    "@type": "Offer",
    "price": "9.99",
    "priceCurrency": "USD",
    "availability": "https://schema.org/InStock",
    "url": "https://certgames.com/register",
    "priceValidUntil": "2025-12-31",  // Fix missing priceValidUntil
    "hasMerchantReturnPolicy": {      // Fix missing hasMerchantReturnPolicy
      "@type": "MerchantReturnPolicy",
      "applicableCountry": "US",
      "returnPolicyCategory": "https://schema.org/MerchantReturnFiniteReturnWindow",
      "merchantReturnDays": 30,
      "returnMethod": "https://schema.org/ReturnByMail",
      "returnFees": "https://schema.org/FreeReturn"
    }
  },
  "hasCourseInstance": {
    "@type": "CourseInstance",
    "courseMode": "online",
    "courseWorkload": "PT10H",
    "startDate": "2023-01-01"
  },
  "review": {
    "@type": "Review",
    "reviewRating": {
      "@type": "Rating",
      "ratingValue": "4.8",
      "bestRating": "5"
    },
    "author": {
      "@type": "Person",
      "name": "Security Professional"
    }
  }
};

  // TechArticle schema for SEO
  const securityArticleSchema = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "headline": "Cybersecurity Certification Practice Tests",
    "description": "Comprehensive guide to cybersecurity certification preparation including CompTIA, ISC2, and AWS",
    "keywords": "CompTIA Security+, CISSP, CompTIA CySa+, CompTIA A+, CompTIA Network+, CompTIA Pentest+, CompTIA CASP, AWS Cloud Practitioner, cybersecurity certification, practice tests, game",
    "mainEntityOfPage": {
      "@type": "WebPage",
      "@id": "https://certgames.com/exams"
    }
  };


const generateCertSchema = (cert) => {
  return {
    "@context": "https://schema.org",
    "@type": "Course",
    "name": `${cert.title} Certification Training`,
    "description": cert.description,
    "provider": {
      "@type": "Organization",
      "name": "CertGames",
      "sameAs": "https://certgames.com"
    },
    // Use the certification logo images you already have in your app
    "image": cert.logo, // This uses the logo property that's already in your certification data
    "offers": {
      // Other offer properties remain the same...
      "price": "9.99",
      "priceCurrency": "USD",
      "availability": "https://schema.org/InStock",
      "url": `https://certgames.com/register?cert=${cert.id}`,
      "priceValidUntil": "2025-12-31",
      "hasMerchantReturnPolicy": {
        "@type": "MerchantReturnPolicy",
        "applicableCountry": "US",
        "returnPolicyCategory": "https://schema.org/MerchantReturnFiniteReturnWindow",
        "merchantReturnDays": 30,
        "returnMethod": "https://schema.org/ReturnByMail",
        "returnFees": "https://schema.org/FreeReturn"
      }
    },
    "hasCourseInstance": {
      "@type": "CourseInstance",
      "courseMode": "online",
      "courseWorkload": "PT10H",
      "startDate": "2023-01-01"
    }
  };
};




  // Mock data for certifications
  const certifications = [
    {
      id: 'aplus-core1',
      title: 'CompTIA A+ Core 1',
      code: '220-1101',
      logo: aplusLogo,
      category: 'comptia',
      level: 'beginner',
      questionCount: 1000,
      description: 'Mobile devices, networking technology, hardware, virtualization and cloud computing and hardware and network troubleshooting.',
      skills: ['Hardware', 'Network Troubleshooting', 'Mobile Devices', 'Virtualization'],
      popular: true
    },
    {
      id: 'aplus-core2',
      title: 'CompTIA A+ Core 2',
      code: '220-1102',
      logo: aplusLogo,
      category: 'comptia',
      level: 'beginner',
      questionCount: 1000,
      description: 'Operating systems, security, software troubleshooting and operational procedures.',
      skills: ['Windows', 'Security', 'Troubleshooting', 'Operational Procedures'],
      popular: true
    },
    {
      id: 'network-plus',
      title: 'CompTIA Network+',
      code: 'N10-009',
      logo: networkLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Design and implement functional networks, configure, manage, and maintain essential network devices.',
      skills: ['Networking', 'Subnetting', 'Routing', 'Troubleshooting'],
      popular: true
    },
    {
      id: 'security-plus',
      title: 'CompTIA Security+',
      code: 'SY0-701',
      logo: securityLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Assess the security posture of an enterprise environment and recommend and implement appropriate security solutions.',
      skills: ['Security', 'Cryptography', 'Risk Management', 'Identity Management'],
      popular: true
    },
    {
      id: 'cysa-plus',
      title: 'CompTIA CySA+',
      code: 'CS0-003',
      logo: cyssaLogo,
      category: 'comptia',
      level: 'advanced',
      questionCount: 1000,
      description: 'Apply behavioral analytics to networks to improve the overall state of IT security.',
      skills: ['Threat Detection', 'Security Analytics', 'Vulnerability Management', 'Incident Response'],
      popular: false
    },
    {
      id: 'pentest-plus',
      title: 'CompTIA PenTest+',
      code: 'PT0-003',
      logo: pentestLogo,
      category: 'comptia',
      level: 'advanced',
      questionCount: 1000,
      description: 'Plan and scope a penetration testing engagement, understand legal and compliance requirements.',
      skills: ['Penetration Testing', 'Vulnerability Scanning', 'Exploitation', 'Reporting'],
      popular: false
    },
    {
      id: 'security-x',
      title: 'CompTIA Security X (formerly CASP+)',
      code: 'CAS-005',
      logo: securityxLogo,
      category: 'comptia',
      level: 'expert',
      questionCount: 1000,
      description: 'Security advanced security concepts, principles, and implementations that pertain to enterprise environments.',
      skills: ['Enterprise Security', 'Risk Management', 'Integration', 'Security Architecture'],
      popular: false
    },
    {
      id: 'linux-plus',
      title: 'CompTIA Linux+',
      code: 'XK0-005',
      logo: linuxLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Using Linux command line for maintenance and troubleshooting, as well as system configuration of the OS.',
      skills: ['Linux', 'Command Line', 'System Administration', 'Scripting'],
      popular: false
    },
    {
      id: 'data-plus',
      title: 'CompTIA Data+',
      code: 'DA0-001',
      logo: dataLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Data mining, visualization techniques, building data models, and manipulating data.',
      skills: ['Data Analysis', 'Data Mining', 'Visualization', 'Data Modeling'],
      popular: false
    },
    {
      id: 'server-plus',
      title: 'CompTIA Server+',
      code: 'SK0-005',
      logo: serverLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Server hardware and software technologies, as well as disaster recovery.',
      skills: ['Server Administration', 'Storage', 'Security', 'Virtualization'],
      popular: false
    },
    {
      id: 'cloud-plus',
      title: 'CompTIA Cloud+',
      code: 'CV0-004',
      logo: cloudLogo,
      category: 'comptia',
      level: 'intermediate',
      questionCount: 1000,
      description: 'Deploy, secure, and automate cloud environments and understand how to use cloud computing to accomplish business objectives.',
      skills: ['Cloud Computing', 'Deployment', 'Security', 'Automation'],
      popular: false
    },
    {
      id: 'cissp',
      title: 'ISC2 CISSP',
      code: 'CISSP',
      logo: cisspLogo,
      category: 'isc2',
      level: 'expert',
      questionCount: 1000,
      description: 'Security and risk management, asset security, security architecture and engineering, and more.',
      skills: ['Security Management', 'Asset Security', 'Security Engineering', 'Communications'],
      popular: true
    },
    {
      id: 'aws-cloud',
      title: 'AWS Cloud Practitioner',
      code: 'CLF-C02',
      logo: awscloudLogo,
      category: 'aws',
      level: 'beginner',
      questionCount: 1000,
      description: 'Understanding of the AWS Cloud, security and compliance within the AWS Cloud, and core AWS services.',
      skills: ['Cloud Concepts', 'Security', 'AWS Services', 'Billing and Pricing'],
      popular: true
    }
  ];
  
  // Filter certifications based on active category and search term
  const filteredCerts = certifications.filter(cert => {
    // Filter by category
    if (activeCategory !== 'all' && cert.category !== activeCategory) return false;
    
    // Filter by search term
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      return (
        cert.title.toLowerCase().includes(searchLower) ||
        cert.code.toLowerCase().includes(searchLower) ||
        cert.description.toLowerCase().includes(searchLower) ||
        cert.skills.some(skill => skill.toLowerCase().includes(searchLower))
      );
    }
    
    return true;
  });
  
  // Toggle expanded certification
  const toggleExpand = (certId) => {
    if (expandedCert === certId) {
      setExpandedCert(null);
    } else {
      setExpandedCert(certId);
    }
  };
  
  return (
    <>
      <SEOHelmet 
        title="CompTIA, CISSP & AWS Certification Practice Tests | CertGames"
        description="Prepare for 13 top cybersecurity certifications including CompTIA Security+, Network+, CISSP and AWS with 13,000+ gamified practice questions. Performance-based challenges and detailed explanations."
        canonicalUrl="/exams"
      />
      <StructuredData data={examProductSchema} />
      <StructuredData data={breadcrumbSchema} />
      <StructuredData data={securityArticleSchema} />
      {certifications.map(cert => (
        <StructuredData key={cert.id} data={generateCertSchema(cert)} />
      ))}
          
    <div className="exams-container">
      <InfoNavbar />
      
      <main className="exams-content">
        <header className="exams-header">
          <h1 className="exams-title">
            <span className="exams-icon" aria-hidden="true">🎓</span>
            Certification Exam Prep
          </h1>
          <p className="exams-subtitle">
            Access to all exams with a single subscription — 13,000+ practice questions across 12 certifications
          </p>
          
          <div className="exams-access-notice">
            <FaCheckCircle className="notice-icon" aria-hidden="true" />
            <p>Your subscription includes unlimited access to all certification practice tests</p>
          </div>
        </header>
        
        {/* Search and Filter */}
        <section className="exams-search-filters">
          <div className="exams-search">
            <FaSearch className="search-icon" aria-hidden="true" />
            <input
              type="text"
              placeholder="Search certifications..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input"
              aria-label="Search certifications"
            />
          </div>
          
          <div className="exams-filters">
            <div 
              className="filters-toggle" 
              onClick={() => setFiltersOpen(!filtersOpen)}
              role="button"
              aria-expanded={filtersOpen}
              tabIndex="0"
            >
              <FaFilter className="filter-icon" aria-hidden="true" />
              <span>Filter</span>
              {filtersOpen ? <FaChevronUp aria-hidden="true" /> : <FaChevronDown aria-hidden="true" />}
            </div>
            
            {filtersOpen && (
              <div className="filters-dropdown">
                <div className="filter-group">
                  <h4>Vendor</h4>
                  <div className="filter-options" role="radiogroup" aria-label="Filter by vendor">
                    <button 
                      className={`filter-option ${activeCategory === 'all' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('all')}
                      aria-checked={activeCategory === 'all'}
                      role="radio"
                    >
                      All
                    </button>
                    <button 
                      className={`filter-option ${activeCategory === 'comptia' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('comptia')}
                      aria-checked={activeCategory === 'comptia'}
                      role="radio"
                    >
                      CompTIA
                    </button>
                    <button 
                      className={`filter-option ${activeCategory === 'isc2' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('isc2')}
                      aria-checked={activeCategory === 'isc2'}
                      role="radio"
                    >
                      ISC2
                    </button>
                    <button 
                      className={`filter-option ${activeCategory === 'aws' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('aws')}
                      aria-checked={activeCategory === 'aws'}
                      role="radio"
                    >
                      AWS
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>
        
        {/* Certifications Grid */}
        <section className="exams-grid" aria-label="Available certification exams">
          {filteredCerts.length > 0 ? (
            filteredCerts.map((cert) => (
              <article 
                key={cert.id} 
                className={`cert-card ${expandedCert === cert.id ? 'expanded' : ''} ${cert.popular ? 'popular' : ''}`}
              >
                {cert.popular && <div className="popular-badge">Popular</div>}
                
                <div className="cert-header">
                  <div className="cert-logo">
                    <img src={cert.logo} alt={`${cert.title} certification logo`} />
                  </div>
                  <div className="cert-title-info">
                    <h3>{cert.title}</h3>
                    <div className="cert-meta">
                      <span className="cert-code">{cert.code}</span>
                      <span className={`cert-level ${cert.level}`}>
                        {cert.level.charAt(0).toUpperCase() + cert.level.slice(1)}
                      </span>
                    </div>
                  </div>
                  <button 
                    className="expand-button"
                    onClick={() => toggleExpand(cert.id)}
                    aria-expanded={expandedCert === cert.id}
                    aria-label={expandedCert === cert.id ? `Collapse ${cert.title} details` : `Expand ${cert.title} details`}
                  >
                    {expandedCert === cert.id ? <FaChevronUp aria-hidden="true" /> : <FaChevronDown aria-hidden="true" />}
                  </button>
                </div>
                
                <div className="cert-content">
                  <p className="cert-description">{cert.description}</p>
                  
                  <div className="cert-stats">
                    <div className="cert-stat">
                      <span className="stat-value">{cert.questionCount.toLocaleString()}</span>
                      <span className="stat-label">Questions</span>
                    </div>
                    <div className="cert-stat">
                      <span className="stat-value">10</span>
                      <span className="stat-label">Practice Tests</span>
                    </div>
                    <div className="cert-stat">
                      <span className="stat-value">100%</span>
                      <span className="stat-label">Coverage</span>
                    </div>
                  </div>
                  
                  {expandedCert === cert.id && (
                    <div className="cert-details">
                      <div className="cert-skills">
                        <h4>Key Skills Covered:</h4>
                        <div className="skills-list">
                          {cert.skills.map((skill, index) => (
                            <span key={index} className="skill-tag">{skill}</span>
                          ))}
                        </div>
                      </div>
                      
                      <div className="cert-features">
                        <div className="feature-item">
                          <FaCheckCircle className="feature-icon" aria-hidden="true" />
                          <span>Performance-based Questions</span>
                        </div>
                        <div className="feature-item">
                          <FaCheckCircle className="feature-icon" aria-hidden="true" />
                          <span>Detailed Explanations</span>
                        </div>
                        <div className="feature-item">
                          <FaCheckCircle className="feature-icon" aria-hidden="true" />
                          <span>Progress Tracking</span>
                        </div>
                        <div className="feature-item">
                          <FaCheckCircle className="feature-icon" aria-hidden="true" />
                          <span>Exam Simulation Mode</span>
                        </div>
                      </div>
                    </div>
                  )}
                  
                  <div className="cert-actions">
                    <Link to="/register" className="try-cert-button">Try This Exam</Link>
                  </div>
                </div>
              </article>
            ))
          ) : (
            <div className="no-results" role="alert">
              <h3>No certifications found</h3>
              <p>Try adjusting your search or filters</p>
              <button 
                className="reset-button"
                onClick={() => {
                  setSearchTerm('');
                  setActiveCategory('all');
                }}
              >
                Reset Filters
              </button>
            </div>
          )}
        </section>
        
        {/* Subscribe CTA */}
        <section className="exams-subscribe-cta">
          <div className="subscribe-card">
            <div className="subscribe-content">
              <h2>Ready to pass your certification exams?</h2>
              <p>Get unlimited access to all 12 certification paths with 13,000+ practice questions</p>
              <div className="price-section">
                <div className="price">
                  <span className="currency">$</span>
                  <span className="amount">9</span>
                  <span className="decimal">.99</span>
                  <span className="period">/month</span>
                </div>
                <p className="price-note">Cancel anytime. No long-term commitment.</p>
              </div>
              <Link to="/register" className="subscribe-button">
                Start Your Journey
              </Link>
            </div>
            
            <div className="subscribe-features">
              <div className="feature">
                <FaCheckCircle className="feature-icon" aria-hidden="true" />
                <span>12 Certification Paths</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" aria-hidden="true" />
                <span>13,000+ Practice Questions</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" aria-hidden="true" />
                <span>All Learning Tools Included</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" aria-hidden="true" />
                <span>24/7 Support</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" aria-hidden="true" />
                <span>Gamified Learning Experience</span>
              </div>
            </div>
          </div>
        </section>
      </main>
      
      <Footer />
    </div>
    </>
  );
};

export default ExamsPage;
