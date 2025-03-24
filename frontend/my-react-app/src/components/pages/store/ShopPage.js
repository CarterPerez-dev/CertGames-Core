// src/components/pages/store/ShopPage.js
import React, { useEffect, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { fetchShopItems } from '../store/shopSlice';
import { fetchUserData } from '../store/userSlice';
import './ShopPage.css';
import { 
  FaCoins, 
  FaShoppingCart,
  FaLevelUpAlt,
  FaRocket,
  FaUserCircle,
  FaCheckCircle,
  FaLock,
  FaTimes,
  FaStar,
  FaSync,
  FaExchangeAlt,
  FaChevronRight
} from 'react-icons/fa';

const ShopPage = () => {
  const dispatch = useDispatch();

  // Grab shop data from Redux
  const { items, status, error } = useSelector((state) => state.shop);
  // Grab user data from Redux
  const {
    userId,
    coins,
    level,
    xpBoost,
    currentAvatar,
    purchasedItems = []
  } = useSelector((state) => state.user);

  // Local state
  const [purchaseStatus, setPurchaseStatus] = useState(null);
  const [statusType, setStatusType] = useState(''); // 'success', 'error', 'info'
  const [activeTab, setActiveTab] = useState('avatar'); // 'avatar', 'xpboost'
  const [sortBy, setSortBy] = useState('price-asc'); // 'price-asc', 'price-desc', 'level-asc', 'level-desc'
  const [previewAvatar, setPreviewAvatar] = useState(null);
  const [showStatusMessage, setShowStatusMessage] = useState(false);
  const [actionInProgress, setActionInProgress] = useState(false);

  // On mount or if status is idle, fetch items
  useEffect(() => {
    if (status === 'idle') {
      dispatch(fetchShopItems());
    }
  }, [status, dispatch]);

  // Clear status message after 5 seconds
  useEffect(() => {
    if (purchaseStatus) {
      setShowStatusMessage(true);
      const timer = setTimeout(() => {
        setShowStatusMessage(false);
        setTimeout(() => {
          setPurchaseStatus(null);
          setStatusType('');
        }, 300); // Wait for fade-out animation
      }, 5000);
      
      return () => clearTimeout(timer);
    }
  }, [purchaseStatus]);

  // Filter items by type
  const xpBoostItems = items.filter((item) => item.type === 'xpBoost');
  const avatarItems = items.filter((item) => item.type === 'avatar');

  // Sort items based on the current sortBy value
  const sortItems = (itemsToSort) => {
    return [...itemsToSort].sort((a, b) => {
      const aCost = a.cost === null ? 0 : a.cost;
      const bCost = b.cost === null ? 0 : b.cost;
      
      switch (sortBy) {
        case 'price-asc':
          return aCost - bCost;
        case 'price-desc':
          return bCost - aCost;
        case 'level-asc':
          return (a.unlockLevel || 0) - (b.unlockLevel || 0);
        case 'level-desc':
          return (b.unlockLevel || 0) - (a.unlockLevel || 0);
        case 'name-asc':
          return a.title.localeCompare(b.title);
        case 'name-desc':
          return b.title.localeCompare(a.title);
        default:
          return aCost - bCost;
      }
    });
  };

  const sortedXpBoostItems = sortItems(xpBoostItems);
  const sortedAvatarItems = sortItems(avatarItems);

  // Check if user owns an item
  const isPurchased = (itemId) => purchasedItems.includes(itemId);

  // Purchase handler
  const handlePurchase = async (itemId) => {
    if (actionInProgress) return;
    
    if (!userId) {
      setPurchaseStatus('Please log in to make a purchase.');
      setStatusType('error');
      return;
    }
    
    setActionInProgress(true);
    setPurchaseStatus('Processing your purchase...');
    setStatusType('info');
    
    try {
      const response = await fetch(`/api/test/shop/purchase/${itemId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        // Refresh user data
        dispatch(fetchUserData(userId));
        setPurchaseStatus(data.message || 'Purchase successful!');
        setStatusType('success');
      } else {
        setPurchaseStatus(data.message || 'Purchase failed.');
        setStatusType('error');
      }
    } catch (err) {
      setPurchaseStatus('Error: ' + err.message);
      setStatusType('error');
    } finally {
      setActionInProgress(false);
    }
  };

  // Equip handler
  const handleEquip = async (itemId) => {
    if (actionInProgress) return;
    
    if (!userId) {
      setPurchaseStatus('Please log in to equip an avatar.');
      setStatusType('error');
      return;
    }
    
    setActionInProgress(true);
    setPurchaseStatus('Equipping avatar...');
    setStatusType('info');
    
    try {
      const response = await fetch('/api/test/shop/equip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, itemId })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        dispatch(fetchUserData(userId));
        setPurchaseStatus(data.message || 'Avatar equipped!');
        setStatusType('success');
      } else {
        setPurchaseStatus(data.message || 'Failed to equip avatar.');
        setStatusType('error');
      }
    } catch (err) {
      setPurchaseStatus('Error: ' + err.message);
      setStatusType('error');
    } finally {
      setActionInProgress(false);
    }
  };
  
  // Preview hover handler
  const handlePreviewEnter = (avatarUrl) => {
    setPreviewAvatar(avatarUrl);
  };
  
  const handlePreviewLeave = () => {
    setPreviewAvatar(null);
  };

  // Calculate if user can afford item
  const canAfford = (cost) => {
    const costValue = cost === null ? 0 : cost;
    return coins >= costValue;
  };

  // Get user's current avatar URL
  const getCurrentAvatarUrl = () => {
    if (!currentAvatar) return null;
    const avatarItem = items.find(item => item._id === currentAvatar);
    return avatarItem ? avatarItem.imageUrl : null;
  };

  // Render shop items grid
  const renderShopItems = (itemsToRender, itemType) => {
    if (!itemsToRender.length) {
      return (
        <div className="shop-empty-state">
          <p>No items found in this category.</p>
        </div>
      );
    }

    return (
      <div className="shop-grid">
        {itemsToRender.map((item) => {
          const isAvatarItem = itemType === 'avatar';
          const costVal = item.cost === null ? 0 : item.cost;
          const autoUnlocked = item.cost === null;
          const levelUnlocked = isAvatarItem ? level >= item.unlockLevel : true;
          const purchased = isPurchased(item._id);
          const unlocked = autoUnlocked || levelUnlocked || purchased;
          const isEquipped = isAvatarItem && currentAvatar === item._id;
          const userCanAfford = canAfford(costVal);
          
          let buttonText = '';
          let buttonDisabled = false;
          let onClickAction = null;
          let itemClassName = `shop-item ${isAvatarItem ? 'avatar-item' : 'boost-item'}`;
          
          if (isAvatarItem) {
            // Avatar logic
            if (!unlocked) {
              buttonText = 'Purchase';
              // Key change: Only disable if user can't afford (allow purchase even if level req not met)
              buttonDisabled = !userCanAfford;
              onClickAction = () => handlePurchase(item._id);
              
              // Add locked class if level requirement not met
              if (level < item.unlockLevel) {
                itemClassName += ' level-locked';
              }
              
              // Add unaffordable class if can't afford
              if (!userCanAfford) {
                itemClassName += ' unaffordable';
              }
            } else {
              // Already unlocked
              if (isEquipped) {
                buttonText = 'Equipped';
                buttonDisabled = true;
                itemClassName += ' equipped';
              } else {
                buttonText = 'Equip';
                onClickAction = () => handleEquip(item._id);
              }
            }
          } else {
            // XP Boost logic - unchanged
            const isActiveBoost = xpBoost === item.effectValue;
            
            if (isActiveBoost) {
              buttonText = 'Active';
              buttonDisabled = true;
              itemClassName += ' active-boost';
            } else {
              buttonText = 'Purchase';
              buttonDisabled = !userCanAfford;
              onClickAction = () => handlePurchase(item._id);
              
              if (!userCanAfford) {
                itemClassName += ' unaffordable';
              }
            }
          }
          
          return (
            <div 
              className={itemClassName} 
              key={item._id}
              onMouseEnter={isAvatarItem ? () => handlePreviewEnter(item.imageUrl) : undefined}
              onMouseLeave={isAvatarItem ? handlePreviewLeave : undefined}
            >
              <div className="shop-item-content">
                <div className="shop-item-image-container">
                  <img
                    src={item.imageUrl}
                    alt={item.title}
                    className="shop-item-image"
                  />
                  
                  {isEquipped && (
                    <div className="equipped-badge">
                      <FaCheckCircle />
                    </div>
                  )}
                  
                  {!unlocked && !userCanAfford && (
                    <div className="unaffordable-overlay">
                      <FaCoins />
                    </div>
                  )}
                  
                  {!unlocked && level < item.unlockLevel && (
                    <div className="locked-overlay">
                      <FaLock />
                      <span>{item.unlockLevel}</span>
                    </div>
                  )}
                </div>
                
                <div className="shop-item-info">
                  <h3 className="shop-item-title">{item.title}</h3>
                  <p className="shop-item-description">{item.description}</p>
                  
                  <div className="shop-item-details">
                    {isAvatarItem && (
                      <div className="shop-item-requirement">
                        <FaLevelUpAlt className="shop-icon" />
                        <span>Level {item.unlockLevel}</span>
                      </div>
                    )}
                    
                    {!autoUnlocked && (
                      <div className={`shop-item-cost ${!userCanAfford ? 'unaffordable' : ''}`}>
                        <FaCoins className="shop-icon" />
                        <span>{costVal}</span>
                      </div>
                    )}
                    
                    {itemType === 'xpboost' && (
                      <div className="shop-item-effect">
                        <FaRocket className="shop-icon" />
                        <span>+{((item.effectValue - 1) * 100).toFixed(2)}% XP</span>
                      </div>
                    )}
                  </div>
                  
                  <button
                    className={`shop-item-button ${buttonDisabled ? 'disabled' : 'enabled'}`}
                    disabled={buttonDisabled || actionInProgress}
                    onClick={onClickAction}
                  >
                    {actionInProgress ? (
                      <>
                        <FaSync className="spin-icon" />
                        <span>Processing...</span>
                      </>
                    ) : (
                      <>
                        {isEquipped ? (
                          <FaCheckCircle className="button-icon" />
                        ) : unlocked ? (
                          <FaExchangeAlt className="button-icon" />
                        ) : (
                          <FaShoppingCart className="button-icon" />
                        )}
                        <span>{buttonText}</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  // Main content based on status
  let content;
  if (status === 'loading') {
    content = (
      <div className="shop-loading">
        <FaSync className="shop-loading-icon spin-icon" />
        <p>Loading shop items...</p>
      </div>
    );
  } else if (status === 'failed') {
    content = (
      <div className="shop-error">
        <FaTimes className="shop-error-icon" />
        <p>Error loading shop items: {error}</p>
        <button 
          className="shop-retry-button"
          onClick={() => dispatch(fetchShopItems())}
        >
          <FaSync /> Try Again
        </button>
      </div>
    );
  } else {
    content = (
      <div className="shop-content">
        <div className="shop-controls">
          <div className="shop-tabs">
            <button 
              className={`shop-tab ${activeTab === 'avatar' ? 'active' : ''}`}
              onClick={() => setActiveTab('avatar')}
            >
              <FaUserCircle className="tab-icon" />
              <span>Avatars</span>
            </button>
            <button 
              className={`shop-tab ${activeTab === 'xpboost' ? 'active' : ''}`}
              onClick={() => setActiveTab('xpboost')}
            >
              <FaRocket className="tab-icon" />
              <span>XP Boosts</span>
            </button>
          </div>
          
          <div className="shop-sort">
            <label htmlFor="sort-select">Sort By:</label>
            <div className="shop-select-wrapper">
              <select 
                id="sort-select"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="shop-select"
              >
                <option value="price-asc">Price: Low to High</option>
                <option value="price-desc">Price: High to Low</option>
                <option value="level-asc">Level: Low to High</option>
                <option value="level-desc">Level: High to Low</option>
                <option value="name-asc">Name: A to Z</option>
                <option value="name-desc">Name: Z to A</option>
              </select>
              <FaChevronRight className="select-arrow" />
            </div>
          </div>
        </div>
        
        {activeTab === 'avatar' && (
          <div className="shop-section avatar-section">
            <div className="shop-section-header">
              <h2 className="shop-section-title">
                <FaUserCircle className="section-icon" />
                <span>Avatars</span>
              </h2>
              
              <div className="shop-section-info">
                <div className="unlocked-info">
                  <FaCheckCircle className="info-icon" />
                  <span>{purchasedItems.filter(id => 
                    avatarItems.some(item => item._id === id)
                  ).length} / {avatarItems.length} Unlocked</span>
                </div>
              </div>
            </div>
            
            {renderShopItems(sortedAvatarItems, 'avatar')}
          </div>
        )}
        
        {activeTab === 'xpboost' && (
          <div className="shop-section xpboost-section">
            <div className="shop-section-header">
              <h2 className="shop-section-title">
                <FaRocket className="section-icon" />
                <span>XP Boosts</span>
              </h2>
              
              <div className="shop-section-info">
                <div className="current-boost">
                  <FaStar className="info-icon" />
                  <span>Current Boost: {((xpBoost - 1) * 100).toFixed(2)}%</span>
                </div>
              </div>
            </div>
            
            {renderShopItems(sortedXpBoostItems, 'xpboost')}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="shop-page-container">
      <div className="shop-header">
        <div className="shop-title">
          <h1>Item Shop</h1>
          <p>Enhance your experience with unique avatars and boosts!</p>
        </div>
        
        <div className="shop-user-stats">
          <div className="shop-user-stat">
            <FaCoins className="shop-stat-icon" />
            <div className="shop-stat-value">
              <span className="stat-value">{coins}</span>
              <span className="stat-label">Coins</span>
            </div>
          </div>
          
          <div className="shop-user-stat">
            <FaLevelUpAlt className="shop-stat-icon" />
            <div className="shop-stat-value">
              <span className="stat-value">{level}</span>
              <span className="stat-label">Level</span>
            </div>
          </div>
        </div>
      </div>
      
      {showStatusMessage && purchaseStatus && (
        <div className={`shop-status-message ${statusType}`}>
          <p>{purchaseStatus}</p>
          <button 
            className="status-close-btn"
            onClick={() => setShowStatusMessage(false)}
          >
            <FaTimes />
          </button>
        </div>
      )}
      
      {content}
      
      {previewAvatar && (
        <div className="avatar-preview">
          <div className="preview-container">
            <div className="preview-header">
              <h3>Avatar Preview</h3>
            </div>
            <div className="preview-content">
              <div className="preview-avatar-container">
                <img src={previewAvatar} alt="Avatar Preview" className="preview-avatar" />
              </div>
              <div className="preview-current-container">
                <h4>Current Avatar</h4>
                <img src={getCurrentAvatarUrl()} alt="Current Avatar" className="preview-current" />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ShopPage;
