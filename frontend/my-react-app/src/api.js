// frontend/my-react-app/src/utils/api.js
import axios from 'axios';
import store from './components/pages/store/store';
import { refreshToken, logout } from './components/pages/store/slice/userSlice';

// Create axios instance
const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Request interceptor
api.interceptors.request.use(
  async (config) => {
    // Get token from localStorage
    const token = localStorage.getItem('accessToken');
    
    // If token exists, add to headers
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    
    // Fallback to user ID
    const userId = localStorage.getItem('userId');
    if (userId && !token) {
      config.headers['X-User-Id'] = userId;
    }
    
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    // Prevent infinite loops
    if (originalRequest._retry) {
      return Promise.reject(error);
    }
    
    // Check if error is due to expired token
    if (error.response?.status === 401 && 
        error.response?.data?.error?.includes('expired')) {
      
      originalRequest._retry = true;
      
      try {
        // Dispatch refresh token action
        const result = await store.dispatch(refreshToken()).unwrap();
        
        // Update header with new token
        if (result.access_token) {
          originalRequest.headers['Authorization'] = `Bearer ${result.access_token}`;
        }
        
        // Retry original request
        return api(originalRequest);
      } catch (refreshError) {
        // If refresh fails, logout
        store.dispatch(logout());
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

export default api;
