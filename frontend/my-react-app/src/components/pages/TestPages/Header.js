import React, { useState, useEffect } from 'react';
import './Header.css';

// Header component with navigation links
const Header = ({ name }) => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // Effect to handle scroll event for styling the header
  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  const closeMobileMenu = () => {
    setIsMobileMenuOpen(false);
  };

  return (
    <header className={`header ${isScrolled ? 'scrolled' : ''}`}>
      <div className="container header-container">
        <a href="#hero" className="logo" onClick={closeMobileMenu}>{name}</a>
        <nav className={`nav-menu ${isMobileMenuOpen ? 'active' : ''}`}>
          <ul>
            <li><a href="#hero" onClick={closeMobileMenu}>Home</a></li>
            <li><a href="#about" onClick={closeMobileMenu}>About</a></li>
            <li><a href="#education" onClick={closeMobileMenu}>Education</a></li>
            <li><a href="#experience" onClick={closeMobileMenu}>Experience</a></li>
            <li><a href="#skills" onClick={closeMobileMenu}>Skills</a></li>
            <li><a href="#projects" onClick={closeMobileMenu}>Projects</a></li>
            <li><a href="#contact" onClick={closeMobileMenu}>Contact</a></li>
          </ul>
        </nav>
        <button className="mobile-menu-toggle" onClick={toggleMobileMenu} aria-label="Toggle menu">
          <span className="bar"></span>
          <span className="bar"></span>
          <span className="bar"></span>
        </button>
      </div>
    </header>
  );
};

export default Header;
