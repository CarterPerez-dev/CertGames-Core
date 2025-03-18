// src/components/pages/Info/BlogPostPage.js
import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { FaArrowLeft, FaCalendarAlt, FaUser, FaTag, FaShare, FaFacebook, FaTwitter, FaLinkedin } from 'react-icons/fa';
import InfoNavbar from './InfoNavbar';
import Footer from '../../Footer';
import SEOHelmet from '../../SEOHelmet';
import StructuredData from '../../StructuredData';
import './BlogPage.css';

// Import the blog posts data (this would come from a real API in production)
// This is a simplified version for this example
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

const BlogPostPage = () => {
  const { postId } = useParams();
  const [post, setPost] = useState(null);
  const [relatedPosts, setRelatedPosts] = useState([]);
  const navigate = useNavigate();
  
  useEffect(() => {
    // Find the post that matches the ID
    const foundPost = blogPosts.find(post => post.id === postId);
    
    if (foundPost) {
      setPost(foundPost);
      
      // Find related posts (same category or tags)
      const related = blogPosts
        .filter(p => p.id !== postId) // Exclude current post
        .filter(p => 
          p.category === foundPost.category || 
          p.tags.some(tag => foundPost.tags.includes(tag))
        )
        .slice(0, 3); // Get up to 3 related posts
      
      setRelatedPosts(related);
    } else {
      // If post not found, redirect to the blog index
      navigate('/blog');
    }
  }, [postId, navigate]);
  
  // If post is still loading or not found
  if (!post) {
    return (
      <div className="blog-container">
        <InfoNavbar />
        <main className="blog-content">
          <div className="loading-container">
            <div className="spinner"></div>
            <p>Loading article...</p>
          </div>
        </main>
        <Footer />
      </div>
    );
  }
  
  // Article Schema for SEO
  const articleSchema = {
    "@context": "https://schema.org",
    "@type": "BlogPosting",
    "headline": post.title,
    "description": post.excerpt,
    "author": {
      "@type": "Person",
      "name": post.author.split(',')[0]
    },
    "publisher": {
      "@type": "Organization",
      "name": "CertGames",
      "logo": {
        "@type": "ImageObject",
        "url": "https://certgames.com/logo.png"
      }
    },
    "image": `https://certgames.com/images/${post.image}`,
    "datePublished": post.date,
    "dateModified": post.date,
    "mainEntityOfPage": {
      "@type": "WebPage",
      "@id": `https://certgames.com/blog/${post.id}`
    },
    "keywords": post.tags.join(", ")
  };
  
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
      },
      {
        "@type": "ListItem",
        "position": 3,
        "name": post.title,
        "item": `https://certgames.com/blog/${post.id}`
      }
    ]
  };

  // FAQ Schema based on subheadings in the article
  const getFaqSchema = () => {
    // Extract H3 headers and following paragraphs as FAQs
    const content = post.content;
    const h3Regex = /<h3>(.*?)<\/h3>\s*<p>(.*?)<\/p>/g;
    const matches = [...content.matchAll(h3Regex)];
    
    if (matches.length > 0) {
      return {
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": matches.map(match => ({
          "@type": "Question",
          "name": match[1],
          "acceptedAnswer": {
            "@type": "Answer",
            "text": match[2]
          }
        }))
      };
    }
    
    return null;
  };
  
  const faqSchema = getFaqSchema();

  return (
    <>
      <SEOHelmet 
        title={`${post.title} | CertGames Cybersecurity Blog`}
        description={post.excerpt}
        canonicalUrl={`/blog/${post.id}`}
      />
      <StructuredData data={articleSchema} />
      <StructuredData data={breadcrumbSchema} />
      {faqSchema && <StructuredData data={faqSchema} />}
      
      <div className="blog-container">
        <InfoNavbar />
        
        <main className="blog-post-content">
          <div className="blog-post-header">
            <div className="post-navigation">
              <Link to="/blog" className="back-to-blog">
                <FaArrowLeft /> Back to Blog
              </Link>
            </div>
            
            <div className="post-meta">
              <span className="post-category">{post.category}</span>
              <span className="post-date"><FaCalendarAlt /> {post.date}</span>
            </div>
            
            <h1 className="post-title">{post.title}</h1>
            
            <div className="post-author">
              <FaUser className="author-icon" /> 
              <span>{post.author}</span>
            </div>
            
            <div className="post-tags">
              {post.tags.map(tag => (
                <span key={tag} className="tag"><FaTag /> {tag}</span>
              ))}
            </div>
          </div>
          
          <div className="post-featured-image">
            {/* This would be a real image in production */}
            <div className="placeholder-image large">
              <span>Featured Image</span>
            </div>
          </div>
          
          <article className="post-content" dangerouslySetInnerHTML={{ __html: post.content }}></article>
          
          <div className="post-footer">
            <div className="post-share">
              <span>Share this article:</span>
              <div className="share-buttons">
                <button className="share-button facebook">
                  <FaFacebook /> Facebook
                </button>
                <button className="share-button twitter">
                  <FaTwitter /> Twitter
                </button>
                <button className="share-button linkedin">
                  <FaLinkedin /> LinkedIn
                </button>
              </div>
            </div>
            
            <div className="post-cta">
              <h3>Ready to ace your cybersecurity certification?</h3>
              <p>Join thousands of IT professionals who have boosted their exam scores with our gamified learning platform.</p>
              <Link to="/register" className="cta-button">
                Start Your Free Trial
              </Link>
            </div>
          </div>
          
          {relatedPosts.length > 0 && (
            <div className="related-posts">
              <h3>Related Articles</h3>
              <div className="related-posts-grid">
                {relatedPosts.map(relatedPost => (
                  <div key={relatedPost.id} className="related-post-card">
                    <div className="related-post-image">
                      {/* This would be a real image in production */}
                      <div className="placeholder-image small">
                        <span>Article Image</span>
                      </div>
                    </div>
                    <h4 className="related-post-title">
                      <Link to={`/blog/${relatedPost.id}`}>{relatedPost.title}</Link>
                    </h4>
                    <div className="related-post-meta">
                      <span className="related-post-date">{relatedPost.date}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>
        
        <Footer />
      </div>
    </>
  );
};

export default BlogPostPage;
