// src/components/pages/Info/BlogPage.js
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { FaBook, FaSearch, FaCalendarAlt, FaUser, FaTag, FaArrowRight } from 'react-icons/fa';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import SEOHelmet from '../../SEOHelmet';
import StructuredData from '../../StructuredData';
import './BlogPage.css';

// Sample blog post data - you would replace this with your real content
const blogPosts = [
  {
    id: 'comptia-security-plus-exam-tips',
    title: 'Top 10 Tips to Pass the CompTIA Security+ Exam on Your First Try',
    excerpt: 'Preparing for the CompTIA Security+ certification? Learn our proven strategies and tips to ace the exam on your first attempt.',
    content: `
      <p>The CompTIA Security+ certification is one of the most sought-after entry-level cybersecurity certifications. With over 900,000 Security+ certified professionals worldwide, this certification validates the baseline skills necessary to perform core security functions.</p>
      
      <h2>Why Security+ Matters in Today's Job Market</h2>
      <p>According to the latest cybersecurity workforce study, there are over 3.5 million unfilled cybersecurity positions globally. Security+ certified professionals are in high demand across industries, with an average salary of $82,000 for those with 0-3 years of experience.</p>
      
      <h2>Our Top 10 Tips for Exam Success</h2>
      
      <h3>1. Understand the exam objectives thoroughly</h3>
      <p>CompTIA provides a detailed exam objectives document. This should be your roadmap for study. Each major section carries a specific percentage weight of the exam questions.</p>
      
      <h3>2. Practice performance-based questions (PBQs)</h3>
      <p>The Security+ exam includes performance-based questions that test your ability to solve problems in simulated environments. These are not simple multiple-choice questions and require hands-on knowledge.</p>
      
      <h3>3. Learn security terminology</h3>
      <p>Cybersecurity is filled with terminology, acronyms, and concepts. Create flashcards for terms like CIA triad, MITM attacks, RBAC, and cryptographic protocols.</p>
      
      <h3>4. Take practice tests</h3>
      <p>Our gamified platform offers over 1,000 Security+ practice questions that mirror the actual exam format. Studies show that students who complete at least 500 practice questions have a 95% pass rate.</p>
      
      <h3>5. Focus on weak areas</h3>
      <p>Use our analytics to identify your weak areas and spend extra time mastering those topics. Most candidates struggle with cryptography and risk management concepts.</p>
      
      <h3>6. Understand the "why" behind security controls</h3>
      <p>Don't just memorize security controls – understand why they're implemented in specific scenarios. The exam tests your ability to apply knowledge, not just recall facts.</p>
      
      <h3>7. Join study groups</h3>
      <p>Collaborative learning significantly improves retention. Our platform's leaderboards and community features help you connect with fellow certification seekers.</p>
      
      <h3>8. Use the process of elimination</h3>
      <p>For difficult questions, eliminate obviously wrong answers first. This technique can increase your chances of selecting the correct answer even when unsure.</p>
      
      <h3>9. Practice time management</h3>
      <p>The exam gives you 90 minutes to answer about 90 questions. That's roughly one minute per question. Our exam simulation mode helps you practice under timed conditions.</p>
      
      <h3>10. Rest before the exam</h3>
      <p>Cognitive fatigue is real. Take the day before your exam to relax rather than cramming. A well-rested mind performs better on analytical and problem-solving tasks.</p>
      
      <h2>Ready to Start Your Security+ Journey?</h2>
      <p>With CertGames' gamified approach to certification prep, you'll build knowledge while earning XP, unlocking achievements, and competing on leaderboards. Our users report a 35% increase in study motivation compared to traditional methods.</p>
      
      <p>Sign up today and take the first step toward your Security+ certification!</p>
    `,
    author: 'Sarah Johnson, CISSP',
    date: 'March 10, 2025',
    category: 'CompTIA',
    tags: ['Security+', 'Certification', 'CompTIA', 'Exam Tips'],
    image: 'security-plus.webp'
  },
  {
    id: 'cissp-vs-cism-comparison',
    title: 'CISSP vs. CISM: Which Advanced Security Certification Is Right for You?',
    excerpt: 'Confused about whether to pursue CISSP or CISM? We break down the key differences to help you choose the right path for your cybersecurity career.',
    content: `
      <p>For cybersecurity professionals looking to advance their careers, two certifications often rise to the top of consideration: CISSP (Certified Information Systems Security Professional) and CISM (Certified Information Security Manager). Both are prestigious and can significantly impact your career trajectory, but they serve different purposes.</p>
      
      <h2>Certification Overview</h2>
      
      <h3>CISSP: The Technical Security Expert</h3>
      <p>Offered by (ISC)², CISSP is designed for security practitioners who design, implement, and manage cybersecurity programs. It has a more technical focus and covers eight domains:</p>
      <ul>
        <li>Security and Risk Management</li>
        <li>Asset Security</li>
        <li>Security Architecture and Engineering</li>
        <li>Communication and Network Security</li>
        <li>Identity and Access Management</li>
        <li>Security Assessment and Testing</li>
        <li>Security Operations</li>
        <li>Software Development Security</li>
      </ul>
      
      <h3>CISM: The Security Management Professional</h3>
      <p>Offered by ISACA, CISM focuses on management and strategic aspects of information security. It covers four domains:</p>
      <ul>
        <li>Information Security Governance</li>
        <li>Information Risk Management</li>
        <li>Information Security Program Development and Management</li>
        <li>Information Security Incident Management</li>
      </ul>
      
      <h2>Key Differences</h2>
      
      <h3>Career Path Alignment</h3>
      <p>CISSP is ideal for those pursuing technical security roles like Security Architect, Security Engineer, or Security Consultant. CISM aligns better with management roles like CISO, Security Manager, or IT Director.</p>
      
      <h3>Experience Requirements</h3>
      <p>CISSP requires at least 5 years of full-time paid work experience in at least two of the eight domains. CISM requires at least 5 years of experience in information security management, with at least 3 years in security management.</p>
      
      <h3>Exam Difficulty</h3>
      <p>Both exams are challenging, but in different ways. CISSP covers more domains and technical content, requiring a broader knowledge base. The CISSP exam has 250 questions over 6 hours. CISM is more focused but goes deeper into management concepts, with 150 questions over 4 hours.</p>
      
      <h3>Salary Potential</h3>
      <p>According to the latest salary surveys, the average CISSP holder earns about $125,000 annually, while CISM holders average around $128,000. However, these figures vary significantly based on location, industry, and specific job role.</p>
      
      <h2>Which Should You Choose?</h2>
      
      <p>Consider these factors:</p>
      
      <h3>Choose CISSP if:</h3>
      <ul>
        <li>You enjoy the technical aspects of security</li>
        <li>You want flexibility to move between different security roles</li>
        <li>You're looking for a broadly recognized certification with global appeal</li>
        <li>You prefer hands-on implementation rather than policy development</li>
      </ul>
      
      <h3>Choose CISM if:</h3>
      <ul>
        <li>You're aiming for a management position</li>
        <li>You prefer working with business strategy rather than technical implementation</li>
        <li>You're interested in governance, compliance, and risk management</li>
        <li>You want to bridge the gap between IT security and business objectives</li>
      </ul>
      
      <h2>Preparation Strategy</h2>
      
      <p>Regardless of which certification you choose, preparation is key. CertGames offers specialized practice tests for both CISSP and CISM, featuring:</p>
      
      <ul>
        <li>Domain-specific question banks</li>
        <li>Performance-based scenarios</li>
        <li>Adaptive learning technology</li>
        <li>Gamified elements to increase engagement</li>
      </ul>
      
      <p>Our analytics show that users who complete at least 750 practice questions achieve a 92% pass rate on these advanced certifications.</p>
      
      <h2>Start Your Certification Journey Today</h2>
      
      <p>Whether you choose CISSP or CISM, CertGames offers the tools you need to succeed. Sign up today and gain access to comprehensive question banks, realistic exam simulations, and a supportive community of cybersecurity professionals.</p>
    `,
    author: 'Michael Chen, CISSP, CISM',
    date: 'March 5, 2025',
    category: 'Advanced Certifications',
    tags: ['CISSP', 'CISM', 'ISC2', 'ISACA', 'Career Development'],
    image: 'cissp-cism.webp'
  },
  {
    id: 'gamified-learning-benefits',
    title: 'The Science Behind Gamified Learning: Why It Works for Cybersecurity Training',
    excerpt: 'Discover how gamification techniques can boost retention, motivation, and overall success in your certification journey.',
    content: `
      <p>Traditional certification prep often involves monotonous reading and memorization, leading to burnout and reduced information retention. Gamified learning changes this paradigm by introducing game mechanics into the educational process, making it more engaging and effective.</p>
      
      <h2>The Psychology of Gamification</h2>
      <p>Gamification taps into fundamental psychological principles that drive human behavior:</p>
      
      <h3>1. Dopamine-Driven Engagement</h3>
      <p>Every time you earn points, level up, or unlock an achievement, your brain releases dopamine - the "feel-good" neurotransmitter. This creates a positive association with learning activities and motivates continued engagement. A study published in the Journal of Educational Psychology found that students using gamified learning platforms studied 40% longer than those using traditional methods.</p>
      
      <h3>2. Progressive Challenge Curve</h3>
      <p>Well-designed gamified systems gradually increase difficulty, keeping users in what psychologists call the "flow state" - the perfect balance between challenge and skill level where engagement is highest. At CertGames, our adaptive difficulty system adjusts question complexity based on your performance, ensuring you're always appropriately challenged.</p>
      
      <h3>3. Immediate Feedback Loops</h3>
      <p>Unlike traditional learning where feedback might come days or weeks later, gamified platforms provide instant feedback. This accelerates the learning process by allowing immediate correction of misconceptions. Research shows that immediate feedback can improve knowledge retention by up to 60%.</p>
      
      <h2>Key Gamification Elements in Certification Prep</h2>
      
      <h3>Experience Points (XP) and Levels</h3>
      <p>As you answer questions correctly and complete challenges, you earn XP and progress through levels. This creates a sense of advancement and provides a clear visualization of your learning journey. Our data shows that users who reach level 20 have a 94% pass rate on their certification exams.</p>
      
      <h3>Achievements and Badges</h3>
      <p>Achievements recognize specific accomplishments, from answering consecutive questions correctly to mastering entire domains. These digital badges serve as mile markers in your learning journey and can be powerful motivators. Users who unlock at least 15 achievements study an average of 3 more hours per week than those who don't.</p>
      
      <h3>Leaderboards and Social Competition</h3>
      <p>Friendly competition can significantly boost motivation. Our global and certification-specific leaderboards let you see how you stack up against peers. The ability to compare progress creates accountability and drives continued engagement. A recent internal study showed that users who regularly check leaderboards complete 35% more practice questions.</p>
      
      <h3>Streaks and Consistency Rewards</h3>
      <p>Daily streaks reward consistent study habits - crucial for certification success. By incentivizing regular practice through streak bonuses, we help users develop the discipline needed for long-term retention. Users who maintain a 30-day streak have a 78% higher completion rate for their study plans.</p>
      
      <h2>Real-World Results from Gamified Learning</h2>
      
      <p>The effectiveness of gamification isn't just theoretical. We've collected data from thousands of successful certification candidates:</p>
      
      <ul>
        <li>89% of users report higher motivation when using gamified methods versus traditional study</li>
        <li>Average study time increases by 47% when gamification elements are introduced</li>
        <li>Knowledge retention, as measured by practice test performance over time, improves by 32%</li>
        <li>First-attempt pass rates are 24% higher for users who fully engage with gamification features</li>
      </ul>
      
      <h2>How CertGames Implements These Principles</h2>
      
      <p>Our platform is designed from the ground up with these psychological principles in mind:</p>
      
      <ul>
        <li><strong>XP System:</strong> Earn experience points by answering questions correctly, with bonuses for streak accuracy and difficulty</li>
        <li><strong>Achievement System:</strong> Unlock over 50 unique badges across different certification paths</li>
        <li><strong>Leaderboards:</strong> Compare your progress with the global community or filter by certification</li>
        <li><strong>Daily Challenges:</strong> Special questions and scenarios refresh daily to encourage regular practice</li>
        <li><strong>Virtual Economy:</strong> Earn coins to unlock special features, cosmetic upgrades, and study aids</li>
      </ul>
      
      <h2>Start Your Gamified Learning Journey</h2>
      
      <p>The science is clear: gamification works, especially for challenging subjects like cybersecurity. By leveraging these psychological principles, CertGames has helped thousands of professionals achieve certification success while actually enjoying the process.</p>
      
      <p>Ready to experience the difference? Sign up today and transform your certification preparation from a chore into an engaging journey.</p>
    `,
    author: 'Dr. Amanda Rodriguez, Learning Psychologist',
    date: 'March 1, 2025',
    category: 'Learning Science',
    tags: ['Gamification', 'Learning Psychology', 'Study Techniques', 'Certification Prep'],
    image: 'gamified-learning.webp'
  }
];

const BlogPage = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  
  // Filter blog posts based on search term and category
  const filteredPosts = blogPosts.filter(post => {
    const matchesSearch = post.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
                         post.excerpt.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         post.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesCategory = selectedCategory === 'All' || post.category === selectedCategory;
    
    return matchesSearch && matchesCategory;
  });
  
  // Get unique categories for the filter
  const categories = ['All', ...new Set(blogPosts.map(post => post.category))];

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
        "name": "Blog",
        "item": "https://certgames.com/blog"
      }
    ]
  };

  // Blog structured data for SEO
  const blogSchema = {
    "@context": "https://schema.org",
    "@type": "Blog",
    "name": "CertGames Cybersecurity Blog",
    "description": "Expert tips, guides, and resources for cybersecurity certification exam preparation and IT security careers.",
    "url": "https://certgames.com/blog",
    "publisher": {
      "@type": "Organization",
      "name": "CertGames",
      "logo": {
        "@type": "ImageObject",
        "url": "https://certgames.com/logo.png"
      }
    },
    "blogPost": blogPosts.map(post => ({
      "@type": "BlogPosting",
      "headline": post.title,
      "description": post.excerpt,
      "author": {
        "@type": "Person",
        "name": post.author.split(',')[0]
      },
      "datePublished": post.date,
      "mainEntityOfPage": {
        "@type": "WebPage",
        "@id": `https://certgames.com/blog/${post.id}`
      },
      "keywords": post.tags.join(", ")
    }))
  };

  return (
    <>
      <SEOHelmet 
        title="Cybersecurity Certification Blog | Expert Tips & Guides | CertGames"
        description="Expert tips, guides and resources for CompTIA, CISSP, CEH certification exam preparation. Boost your cybersecurity career with our comprehensive training articles."
        canonicalUrl="/blog"
      />
      <StructuredData data={breadcrumbSchema} />
      <StructuredData data={blogSchema} />
      
      <div className="blog-container">
        <InfoNavbar />
        
        <main className="blog-content">
          <header className="blog-header">
            <h1 className="blog-title">
              <FaBook className="title-icon" aria-hidden="true" />
              CertGames Cybersecurity Blog
            </h1>
            <p className="blog-subtitle">
              Expert insights, tips, and resources to help you succeed in your certification journey
            </p>
          </header>

          {/* Search and Filter Section */}
          <section className="blog-filters">
            <div className="search-box">
              <FaSearch className="search-icon" aria-hidden="true" />
              <input 
                type="text" 
                placeholder="Search articles..." 
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="search-input"
                aria-label="Search blog articles"
              />
            </div>
            
            <div className="category-filters">
              {categories.map(category => (
                <button 
                  key={category}
                  className={`category-button ${selectedCategory === category ? 'active' : ''}`}
                  onClick={() => setSelectedCategory(category)}
                >
                  {category}
                </button>
              ))}
            </div>
          </section>

          {/* Featured Article */}
          {filteredPosts.length > 0 && (
            <section className="featured-article">
              <div className="featured-content">
                <div className="featured-meta">
                  <span className="featured-category">{filteredPosts[0].category}</span>
                  <span className="featured-date"><FaCalendarAlt /> {filteredPosts[0].date}</span>
                </div>
                <h2 className="featured-title">{filteredPosts[0].title}</h2>
                <p className="featured-excerpt">{filteredPosts[0].excerpt}</p>
                <div className="featured-author">
                  <FaUser className="author-icon" /> 
                  <span>{filteredPosts[0].author}</span>
                </div>
                <div className="featured-tags">
                  {filteredPosts[0].tags.map(tag => (
                    <span key={tag} className="tag"><FaTag /> {tag}</span>
                  ))}
                </div>
                <Link to={`/blog/${filteredPosts[0].id}`} className="read-more-btn">
                  Read Full Article <FaArrowRight />
                </Link>
              </div>
              <div className="featured-image">
                {/* This would be a real image in production */}
                <div className="placeholder-image">
                  <span>Featured Image</span>
                </div>
              </div>
            </section>
          )}

          {/* Article Grid */}
          <section className="article-grid">
            {filteredPosts.length > 0 ? (
              filteredPosts.slice(1).map(post => (
                <article key={post.id} className="article-card">
                  <div className="article-image">
                    {/* This would be a real image in production */}
                    <div className="placeholder-image small">
                      <span>Article Image</span>
                    </div>
                  </div>
                  <div className="article-meta">
                    <span className="article-category">{post.category}</span>
                    <span className="article-date"><FaCalendarAlt /> {post.date}</span>
                  </div>
                  <h3 className="article-title">{post.title}</h3>
                  <p className="article-excerpt">{post.excerpt}</p>
                  <div className="article-footer">
                    <div className="article-author">
                      <FaUser className="author-icon" /> 
                      <span>{post.author}</span>
                    </div>
                    <Link to={`/blog/${post.id}`} className="read-more-link">
                      Read More <FaArrowRight />
                    </Link>
                  </div>
                </article>
              ))
            ) : (
              <div className="no-results">
                <h3>No articles found</h3>
                <p>Try adjusting your search criteria</p>
                <button 
                  className="reset-button"
                  onClick={() => {
                    setSearchTerm('');
                    setSelectedCategory('All');
                  }}
                >
                  Reset Filters
                </button>
              </div>
            )}
          </section>

          {/* Newsletter Signup */}
          <section className="blog-newsletter">
            <div className="newsletter-content">
              <h2>Stay Updated with Certification News</h2>
              <p>Get the latest cybersecurity certification tips, exam updates, and exclusive content straight to your inbox.</p>
              <form className="newsletter-form">
                <input 
                  type="email" 
                  placeholder="Your email address" 
                  className="newsletter-input"
                  aria-label="Newsletter email input"
                />
                <button type="submit" className="newsletter-button">
                  Subscribe
                </button>
              </form>
              <p className="newsletter-privacy">We respect your privacy. Unsubscribe at any time.</p>
            </div>
          </section>
        </main>
        
        <Footer />
      </div>
    </>
  );
};

export default BlogPage;
