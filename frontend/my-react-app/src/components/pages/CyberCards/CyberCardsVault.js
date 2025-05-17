// frontend/my-react-app/src/components/pages/CyberCards/CyberCardsVault.js
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import axios from 'axios';
import { 
  FaLock, 
  FaUnlock, 
  FaInfoCircle, 
  FaChevronRight, 
  FaSpinner,
  FaTerminal,
  FaCertificate
} from 'react-icons/fa';
import './CyberCards.css';

const CyberCardsVault = () => {
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [hoveredVault, setHoveredVault] = useState(null);
  
  const { userId } = useSelector((state) => state.user);
  const navigate = useNavigate();
  
  useEffect(() => {
    const fetchCategories = async () => {
      try {
        setLoading(true);
        const response = await axios.get('/api/test/flashcards/categories');
        setCategories(response.data);
        setError(null);
      } catch (err) {
        console.error('Error fetching flashcard categories:', err);
        setError('Failed to load flashcard categories. Please try again later.');
      } finally {
        setLoading(false);
      }
    };
    
    fetchCategories();
  }, []);
  
  const handleVaultClick = (categoryId) => {
    navigate(`/cybercards/vault/${categoryId}`);
  };
  
  return (
    <div className="cybercards-container">
      <div className="cybercards-background">
        <div className="cybercards-grid"></div>
        <div className="cybercards-glow"></div>
      </div>
      
      <div className="cybercards-header">
        <h1 className="cybercards-title">
          <FaTerminal className="cybercards-title-icon" />
          The Cyber Vault
        </h1>
        <p className="cybercards-subtitle">Unlock your potential with interactive flashcards for cybersecurity certifications</p>
      </div>
      
      {loading ? (
        <div className="cybercards-loading">
          <FaSpinner className="cybercards-spinner" />
          <p>Decrypting vault contents...</p>
        </div>
      ) : error ? (
        <div className="cybercards-error">
          <p>{error}</p>
          <button className="cybercards-button" onClick={() => window.location.reload()}>Try Again</button>
        </div>
      ) : (
        <div className="cybercards-vaults-grid">
          {categories.map((category) => (
            <div 
              key={category._id} 
              className="cybercards-vault"
              onClick={() => handleVaultClick(category._id)}
              onMouseEnter={() => setHoveredVault(category._id)}
              onMouseLeave={() => setHoveredVault(null)}
            >
              <div className="cybercards-vault-icon">
                {category.locked ? <FaLock /> : <FaUnlock />}
              </div>
              <div className="cybercards-vault-content">
                <h3 className="cybercards-vault-title">
                  <FaCertificate className="cybercards-vault-cert-icon" />
                  {category.title}
                </h3>
                <p className="cybercards-vault-count">{category.cardCount || 0} Cards</p>
                <div className="cybercards-vault-footer">
                  <span className="cybercards-vault-difficulty">
                    {category.difficulty || 'Mixed'}
                  </span>
                  <FaChevronRight className="cybercards-vault-arrow" />
                </div>
              </div>
              
              {hoveredVault === category._id && (
                <div className="cybercards-vault-tooltip">
                  <p>{category.description || 'Master the concepts for this certification.'}</p>
                </div>
              )}
              
              <div className="cybercards-vault-overlay"></div>
              <div className="cybercards-vault-scanning-line"></div>
            </div>
          ))}
        </div>
      )}
      
      <div className="cybercards-info-section">
        <div className="cybercards-info-card">
          <div className="cybercards-info-header">
            <FaInfoCircle className="cybercards-info-icon" />
            <h3>About Cyber Cards</h3>
          </div>
          <p>Interactive flashcards to help you master cybersecurity concepts and prepare for certification exams. Flip through cards, save your favorites, and track your progress.</p>
          <ul className="cybercards-features-list">
            <li>Review key concepts for 13 popular certifications</li>
            <li>Save challenging cards for focused study sessions</li>
            <li>Terminal-style interface for an authentic cyber experience</li>
            <li>Earn XP and coins as you learn</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default CyberCardsVault;
