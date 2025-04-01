// src/components/auth/PasswordRequirements.js
import React from 'react';
import { FaCheck, FaTimes } from 'react-icons/fa';
import './css/PasswordRequirements.css';

const PasswordRequirements = ({ password }) => {
  // Length check
  const hasMinimumLength = password.length >= 6;
  const hasMaximumLength = password.length <= 64;
  
  // Character type checks
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecialChar = /[!@#$%^&*()\-_=+[\]{}|;:'",<.>/?`~\\]/.test(password);
  
  // Additional security checks
  const hasNoWhitespace = !/\s/.test(password);
  const hasNoRepeatingChars = !/(.)\1{2,}/.test(password);
  
  // Common passwords check (simplified)
  const commonPasswords = ['password', '123456', 'qwerty', 'welcome', 'admin'];
  const isNotCommon = !commonPasswords.includes(password.toLowerCase());
  
  return (
    <div className="password-requirements">
      <h4 className="password-requirements-title">Password Requirements:</h4>
      
      <ul className="password-requirements-list">
        <li className={hasMinimumLength ? 'valid' : 'invalid'}>
          {hasMinimumLength ? <FaCheck className="icon-check" /> : <FaTimes className="icon-times" />}
          <span>At least 6 characters long</span>
        </li>
        
        <li className={hasUpperCase ? 'valid' : 'invalid'}>
          {hasUpperCase ? <FaCheck className="icon-check" /> : <FaTimes className="icon-times" />}
          <span>At least one uppercase letter</span>
        </li>
        
        <li className={hasLowerCase ? 'valid' : 'invalid'}>
          {hasLowerCase ? <FaCheck className="icon-check" /> : <FaTimes className="icon-times" />}
          <span>At least one lowercase letter</span>
        </li>
        
        <li className={hasNumber ? 'valid' : 'invalid'}>
          {hasNumber ? <FaCheck className="icon-check" /> : <FaTimes className="icon-times" />}
          <span>At least one number</span>
        </li>
        
        <li className={hasSpecialChar ? 'valid' : 'invalid'}>
          {hasSpecialChar ? <FaCheck className="icon-check" /> : <FaTimes className="icon-times" />}
          <span>At least one special character</span>
        </li>
      </ul>
    </div>
  );
};

export default PasswordRequirements;
