// PasswordRequirements.js
import React from 'react';
import { FaCheckCircle, FaTimesCircle, FaInfoCircle } from 'react-icons/fa';
import './PasswordRequirements.css';

const PasswordRequirements = ({ password }) => {
  const requirements = [
    {
      text: "12–128 characters long",
      test: (pwd) => pwd.length >= 12 && pwd.length <= 128
    },
    {
      text: "At least one uppercase letter",
      test: (pwd) => /[A-Z]/.test(pwd)
    },
    {
      text: "At least one lowercase letter",
      test: (pwd) => /[a-z]/.test(pwd)
    },
    {
      text: "At least one digit",
      test: (pwd) => /\d/.test(pwd)
    },
    {
      text: "At least one special character",
      test: (pwd) => /[!@#$%^&*()\-_=+\[\]{}|;:'",.<>/?`~\\]/.test(pwd)
    },
  ];

  return (
    <div className="password-requirements">
      <p><FaInfoCircle /> Your password must meet the following criteria:</p>
      <ul>
        {requirements.map((req, index) => {
          const isValid = req.test(password);
          return (
            <li key={index} className={isValid ? "valid" : "invalid"}>
              {isValid ? <FaCheckCircle /> : <FaTimesCircle />} {req.text}
            </li>
          );
        })}
      </ul>
    </div>
  );
};

export default PasswordRequirements;
