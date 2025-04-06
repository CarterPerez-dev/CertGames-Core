import { onCLS, onFID, onFCP, onLCP, onTTFB, onINP } from 'web-vitals';

const reportWebVitals = onPerfEntry => {
  if (onPerfEntry && onPerfEntry instanceof Function) {
    // Collect Core Web Vitals
    onCLS(onPerfEntry);
    onFCP(onPerfEntry);
    onLCP(onPerfEntry);
    onTTFB(onPerfEntry);
    
    // Collect additional metrics
    onINP(onPerfEntry);
    onFID(onPerfEntry);
    
    // Send metrics to backend if the user is authenticated
    const userId = localStorage.getItem('userId');
    if (userId) {
      // Create a collector that sends batches of metrics to backend
      const metrics = {};
      
      const reportToBackend = async (name, value) => {
        metrics[name] = value;
        
        // Send the metrics back to our API
        if (Object.keys(metrics).length >= 3) { // Send after collecting at least 3 metrics
          try {
            await fetch('/api/cracked/report-web-vitals', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                userId,
                metrics,
                page: window.location.pathname,
                timestamp: new Date().toISOString()
              }),
            });
            
            // Clear metrics after sending
            Object.keys(metrics).forEach(key => delete metrics[key]);
          } catch (error) {
            console.error('Failed to send web vitals:', error);
          }
        }
      };
      
      // Use this custom reporter function
      onCLS(({ name, value }) => reportToBackend(name, value));
      onFCP(({ name, value }) => reportToBackend(name, value));
      onLCP(({ name, value }) => reportToBackend(name, value));
      onTTFB(({ name, value }) => reportToBackend(name, value));
      onINP(({ name, value }) => reportToBackend(name, value));
      onFID(({ name, value }) => reportToBackend(name, value));
    }
  }
};

export default reportWebVitals;
