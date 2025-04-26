// src/components/cracked/csrfHelper.js

/**
 * Helper to manage CSRF tokens for admin requests
 */
export const getCsrfToken = () => {

  const metaTag = document.querySelector('meta[name="csrf-token"]');
  if (metaTag) {
    return metaTag.getAttribute('content');
  }
  

  return localStorage.getItem('csrf_token');
};

export const setCsrfToken = (token) => {
  if (token) {
    localStorage.setItem('csrf_token', token);
  }
};

/**
 * Fetch wrapper that automatically adds CSRF token headers for admin routes
 */
export const adminFetch = async (url, options = {}) => {

  const method = options.method || 'GET';
  
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase())) {
    // Get the current token
    const token = getCsrfToken();
    
    // Add CSRF header
    const headers = {
      ...options.headers || {},
      'X-CSRF-TOKEN': token
    };
    
    // Return fetch with added headers
    return fetch(url, {
      ...options,
      headers,
      credentials: 'include' 
    });
  }
  
  // For GET requests, just add credentials
  return fetch(url, {
    ...options,
    credentials: 'include'
  });
};


