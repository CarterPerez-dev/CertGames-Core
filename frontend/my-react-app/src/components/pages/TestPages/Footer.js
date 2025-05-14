import React from 'react';
import './Footer.css';

// Footer component
const Footer = ({ name }) => {
  const currentYear = new Date().getFullYear();
  return (
    <footer className="footer">
      <div className="container">
        <p>&copy; {currentYear} {name}. All rights reserved.</p>
        {/* Optional: Add social media icons or other links here */}
        {/* <div className="footer-social-links">
          <a href="#linkedin">LinkedIn</a> | <a href="#github">GitHub</a>
        </div> */}
      </div>
    </footer>
  );
};

export default Footer;
