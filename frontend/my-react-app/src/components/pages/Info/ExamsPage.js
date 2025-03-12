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
  

  const examProductSchema = {
    "@context": "https://schema.org",
    "@type": "Product",
    "name": "CertGames Certification Exam Prep",
    "description": "Practice tests for 13 cybersecurity certifications with over 13,000 questions",
    "offers": {
      "@type": "Offer",
      "price": "14.99",
      "priceCurrency": "USD",
      "availability": "https://schema.org/InStock"
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


  return (
    <>
      <SEOHelmet 
        title="Certification Exam Practice Tests | CertGames"
        description="Prepare for 13 top cybersecurity certifications including CompTIA, ISC2, and AWS with 13,000+ practice questions. Performance-based questions, exam simulations, and detailed explanations."
        canonicalUrl="/exams"
      />
      <StructuredData data={examProductSchema} />
          
    <div className="exams-container">
      <InfoNavbar />
      
      <div className="exams-content">
        <div className="exams-header">
          <h1 className="exams-title">
            <span className="exams-icon">🎓</span>
            Certification Exam Prep
          </h1>
          <p className="exams-subtitle">
            Access to all exams with a single subscription — 13,000+ practice questions across 13 certifications
          </p>
          
          <div className="exams-access-notice">
            <FaCheckCircle className="notice-icon" />
            <p>Your subscription includes unlimited access to all certification practice tests</p>
          </div>
        </div>
        
        {/* Search and Filter */}
        <div className="exams-search-filters">
          <div className="exams-search">
            <FaSearch className="search-icon" />
            <input
              type="text"
              placeholder="Search certifications..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input"
            />
          </div>
          
          <div className="exams-filters">
            <div 
              className="filters-toggle" 
              onClick={() => setFiltersOpen(!filtersOpen)}
            >
              <FaFilter className="filter-icon" />
              <span>Filter</span>
              {filtersOpen ? <FaChevronUp /> : <FaChevronDown />}
            </div>
            
            {filtersOpen && (
              <div className="filters-dropdown">
                <div className="filter-group">
                  <h4>Vendor</h4>
                  <div className="filter-options">
                    <button 
                      className={`filter-option ${activeCategory === 'all' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('all')}
                    >
                      All
                    </button>
                    <button 
                      className={`filter-option ${activeCategory === 'comptia' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('comptia')}
                    >
                      CompTIA
                    </button>
                    <button 
                      className={`filter-option ${activeCategory === 'isc2' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('isc2')}
                    >
                      ISC2
                    </button>
                    <button 
                      className={`filter-option ${activeCategory === 'aws' ? 'active' : ''}`}
                      onClick={() => setActiveCategory('aws')}
                    >
                      AWS
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
        
        {/* Certifications Grid */}
        <div className="exams-grid">
          {filteredCerts.length > 0 ? (
            filteredCerts.map((cert) => (
              <div 
                key={cert.id} 
                className={`cert-card ${expandedCert === cert.id ? 'expanded' : ''} ${cert.popular ? 'popular' : ''}`}
              >
                {cert.popular && <div className="popular-badge">Popular</div>}
                
                <div className="cert-header">
                  <div className="cert-logo">
                    <img src={cert.logo} alt={`${cert.title} logo`} />
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
                  >
                    {expandedCert === cert.id ? <FaChevronUp /> : <FaChevronDown />}
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
                          <FaCheckCircle className="feature-icon" />
                          <span>Performance-based Questions</span>
                        </div>
                        <div className="feature-item">
                          <FaCheckCircle className="feature-icon" />
                          <span>Detailed Explanations</span>
                        </div>
                        <div className="feature-item">
                          <FaCheckCircle className="feature-icon" />
                          <span>Progress Tracking</span>
                        </div>
                        <div className="feature-item">
                          <FaCheckCircle className="feature-icon" />
                          <span>Exam Simulation Mode</span>
                        </div>
                      </div>
                    </div>
                  )}
                  
                  <div className="cert-actions">
                    <Link to="/register" className="try-cert-button">Try This Exam</Link>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="no-results">
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
        </div>
        
        {/* Subscribe CTA */}
        <div className="exams-subscribe-cta">
          <div className="subscribe-card">
            <div className="subscribe-content">
              <h2>Ready to pass your certification exams?</h2>
              <p>Get unlimited access to all 13 certification paths with 13,000+ practice questions</p>
              <div className="price-section">
                <div className="price">
                  <span className="currency">$</span>
                  <span className="amount">14</span>
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
                <FaCheckCircle className="feature-icon" />
                <span>13 Certification Paths</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" />
                <span>13,000+ Practice Questions</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" />
                <span>All Learning Tools Included</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" />
                <span>24/7 Support</span>
              </div>
              <div className="feature">
                <FaCheckCircle className="feature-icon" />
                <span>Gamified Learning Experience</span>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <Footer />
    </div>
  );
};

export default ExamsPage;
