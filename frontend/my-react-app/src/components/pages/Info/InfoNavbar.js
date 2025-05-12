// src/components/pages/Info/InfoNavbar.js
import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { FaHome, FaUserPlus, FaPlayCircle, FaList, FaTrophy, FaEnvelope, FaSignInAlt, FaBars, FaTimes, FaBook, FaLinux } from 'react-icons/fa';
import { setupScrollListener } from './navbarScrollUtils';
import './css/InfoNavbar.css';

const InfoNavbar = () => {
  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [activeTab, setActiveTab] = useState('home');
  const location = useLocation();

  // Handle scroll effects for navbar appearance
  useEffect(() => {
    const handleScroll = () => {
      const isScrolled = window.scrollY > 50;
      if (isScrolled !== scrolled) {
        setScrolled(isScrolled);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, [scrolled]);

  // Set active tab based on current route when component mounts
  useEffect(() => {
    const path = location.pathname;
    if (path === '/') {
      setActiveTab('home');
    } else if (path === '/demos') {
      setActiveTab('demos');
    } else if (path === '/exams') {
      setActiveTab('exams');
    } else if (path === '/public-leaderboard') {
      setActiveTab('leaderboard');
    } else if (path === '/contact') {
      setActiveTab('contact');
    } else if (path === '/register') {
      setActiveTab('register');
    } else if (path === '/login') {
      setActiveTab('login');
    } else if (path === '/blog') {
      setActiveTab('blog');
    } else if (path === '/angela') {
      setActiveTab('angela');      
    }
  }, [location]);

  // Set up scroll-based active tab highlighting, but only on the home page
  useEffect(() => {
    if (location.pathname === '/') {
      const cleanup = setupScrollListener(setActiveTab);
      return cleanup;
    }
  }, [location.pathname]);

  const toggleMenu = () => {
    setMenuOpen(!menuOpen);
  };

  const closeMenu = () => {
    setMenuOpen(false);
  };

  const handleTabClick = (tab) => {
    setActiveTab(tab);
    closeMenu();
  };

  return (
    <nav className={`info-navbar ${scrolled ? 'scrolled' : ''}`}>
      <div className="info-navbar-container">
        <div className="info-navbar-logo">
          <Link to="/" onClick={() => handleTabClick('home')}>
            <span className="logo-text">Cert<span className="logo-highlight">Games</span></span>
          </Link>
        </div>

        <div className="info-navbar-toggle" onClick={toggleMenu}>
          {menuOpen ? <FaTimes /> : <FaBars />}
        </div>

        <div className={`info-navbar-links ${menuOpen ? 'active' : ''}`}>
          <ul>
            <li className={activeTab === 'home' ? 'active' : ''}>
              <Link to="/" onClick={() => handleTabClick('home')}>
                <FaHome className="nav-icon" />
                <span>Home</span>
              </Link>
            </li>
            <li className={activeTab === 'register' ? 'active' : ''}>
              <Link to="/register" onClick={() => handleTabClick('register')}>
                <FaUserPlus className="nav-icon" />
                <span>Register</span>
              </Link>
            </li>
            <li className={activeTab === 'demos' ? 'active' : ''}>
              <Link to="/demos" onClick={() => handleTabClick('demos')}>
                <FaPlayCircle className="nav-icon" />
                <span>Demos</span>
              </Link>
            </li>
            <li className={activeTab === 'exams' ? 'active' : ''}>
              <Link to="/exams" onClick={() => handleTabClick('exams')}>
                <FaList className="nav-icon" />
                <span>All Exams</span>
              </Link>
            </li>
            <li className={activeTab === 'leaderboard' ? 'active' : ''}>
              <Link to="/public-leaderboard" onClick={() => handleTabClick('leaderboard')}>
                <FaTrophy className="nav-icon" />
                <span>Leaderboard</span>
              </Link>
            </li>
            <li className={activeTab === 'blog' ? 'active' : ''}>
              <Link to="/blog" onClick={() => handleTabClick('blog')}>
                <FaBook className="nav-icon" />
                <span>Blog</span>
              </Link>
            </li>
            <li className={activeTab === 'contact' ? 'active' : ''}>
              <Link to="/contact" onClick={() => handleTabClick('contact')}>
                <FaEnvelope className="nav-icon" />
                <span>Contact</span>
              </Link>
            </li>
            <li className={activeTab === 'login' ? 'active' : ''}>
              <Link to="/login" onClick={() => handleTabClick('login')}>
                <FaSignInAlt className="nav-icon" />
                <span>Login</span>
              </Link>
            </li>
            <li className={activeTab === 'angela' ? 'active' : ''}>
              <Link to="/angela" onClick={() => handleTabClick('angela')}>
                <FaLinux className="nav-icon" />
                <span>Angela-CLI</span>
              </Link>                
            </li>
          </ul>
        </div>
      </div>
      
      {/* Animated background elements */}
      <div className="navbar-matrix-background">
        <div className="code-rain"></div>
      </div>
    </nav>
  );
};

export default InfoNavbar;
