// src/components/pages/Info/navbarScrollUtils.js

/**
 * Updates the active tab in the navbar based on scroll position
 * This can be imported and used in InfoNavbar.js to highlight the active section
 */

// Determine which section is currently in view
export const getActiveSection = () => {
  // Get all sections we want to track
  const sections = {
    home: document.querySelector('.info-hero-section'),
    features: document.querySelector('.info-gamified-section'),
    exams: document.querySelector('.info-tests-section'),
    tools: document.querySelector('.info-tools-section'),
    resources: document.querySelector('.info-resources-section'),
    support: document.querySelector('.info-support-section'),
    pricing: document.querySelector('.info-pricing-section')
  };
  
  // Calculate which section is most visible
  let maxVisibleSection = null;
  let maxVisibleHeight = 0;
  
  Object.entries(sections).forEach(([id, element]) => {
    if (!element) return;
    
    const rect = element.getBoundingClientRect();
    const windowHeight = window.innerHeight;
    
    // Calculate how much of the section is visible
    let visibleHeight = 0;
    
    if (rect.top <= 0 && rect.bottom >= 0) {
      // Section starts above viewport and extends into it
      visibleHeight = Math.min(rect.bottom, windowHeight);
    } else if (rect.top >= 0 && rect.top < windowHeight) {
      // Section starts in the viewport
      visibleHeight = Math.min(rect.height, windowHeight - rect.top);
    }
    
    // Adjust weight for the first section (home) to make it active only when truly at the top
    if (id === 'home') {
      // Make home section active only when it's at the very top
      if (rect.top > -100) {
        visibleHeight += 1000; // Add significant weight to keep it active at the top
      } else {
        visibleHeight = 0; // Otherwise don't count it
      }
    }
    
    // Update the most visible section
    if (visibleHeight > maxVisibleHeight) {
      maxVisibleHeight = visibleHeight;
      maxVisibleSection = id;
    }
  });
  
  return maxVisibleSection || 'home';
};

// Map section IDs to nav tab IDs
export const mapSectionToTab = (sectionId) => {
  const mapping = {
    'home': 'home',
    'features': 'home',  // These sections are all part of the home page
    'exams': 'exams',
    'tools': 'demos',    // Tools section maps to demos page
    'resources': 'home',
    'support': 'contact',
    'pricing': 'home',
  };
  
  return mapping[sectionId] || 'home';
};

// Set up scroll event listener to update active tab
export const setupScrollListener = (setActiveTab) => {
  const handleScroll = () => {
    const activeSection = getActiveSection();
    const activeTab = mapSectionToTab(activeSection);
    setActiveTab(activeTab);
  };
  
  window.addEventListener('scroll', handleScroll);
  handleScroll(); // Initialize on load
  
  // Return cleanup function
  return () => {
    window.removeEventListener('scroll', handleScroll);
  };
};
