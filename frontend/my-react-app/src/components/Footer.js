// src/components/Footer.js
import React from 'react';
import { Link } from 'react-router-dom';
import '../global.css'

const Footer = () => {
  return (
    <footer className="site-footer">
      <div className="footer-links">
        <Link to="/">Info</Link>
        <Link to="/privacy">Privacy Policy</Link>
        <Link to="/terms">Terms of Service</Link>
      </div>
      <p>© {new Date().getFullYear()} Certgames.com. All rights reserved.</p>
    </footer>
  );
};

export default Footer;
