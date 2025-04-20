// src/components/Footer.js
import React from 'react';
import { Link } from 'react-router-dom';
import './footer.css'

const Footer = () => {
  return (
    <footer className="site-footer">
      <div className="footer-content">
        <div className="footer-links">
          <Link to="/">Home</Link>
          <Link to="/privacy">Privacy Policy</Link>
          <Link to="/terms">Terms of Service</Link>
        </div>
        <p className="footer-copyright">© {new Date().getFullYear()} CertGames.com ® AngelaMoss.</p>
      </div>
    </footer>
  );
};

export default Footer;
