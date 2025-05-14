import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css'; // Global styles
import Apptest from './Apptest';

// Create a root for rendering the React application
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <Apptest />
  </React.StrictMode>
);
