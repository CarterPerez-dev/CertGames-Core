// src/components/pages/store/ShopPage.js
import React, { useEffect, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { fetchShopItems } from '../store/shopSlice';
import { fetchUserData } from '../store/userSlice';
import './ShopPage.css';

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

  // Local state for purchase/equip messages
  const [purchaseStatus, setPurchaseStatus] = useState(null);

  // On mount or if status is idle, fetch items
  useEffect(() => {
    if (status === 'idle') {
      dispatch(fetchShopItems());
    }
  }, [status, dispatch]);

  // Filter + Sort items by cost ASC (cost null => 0)
  const xpBoostItems = items
    .filter((item) => item.type === 'xpBoost')
    .sort((a, b) => ((a.cost ?? 0) - (b.cost ?? 0)));
  const avatarItems = items
    .filter((item) => item.type === 'avatar')
    .sort((a, b) => ((a.cost ?? 0) - (b.cost ?? 0)));

  // Check if user owns an item
  const isPurchased = (itemId) => purchasedItems.includes(itemId);

  // Purchase handler
  const handlePurchase = async (itemId) => {
    if (!userId) {
      setPurchaseStatus('Please log in to make a purchase.');
      return;
    }
    setPurchaseStatus('Purchasing...');
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
      } else {
        setPurchaseStatus(data.message || 'Purchase failed.');
      }
    } catch (err) {
      setPurchaseStatus('Error: ' + err.message);
    }
  };

  // Equip handler
  const handleEquip = async (itemId) => {
    if (!userId) {
      setPurchaseStatus('Please log in to equip an avatar.');
      return;
    }
    setPurchaseStatus('Equipping avatar...');
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
      } else {
        setPurchaseStatus(data.message || 'Equip failed.');
      }
    } catch (err) {
      setPurchaseStatus('Error: ' + err.message);
    }
  };

  // Render XP Boosts
  const renderXpBoosts = () => {
    if (!xpBoostItems.length) return null;
    return (
      <div className="shop-section xpboost-section">
        <h2 className="section-title">XP Boosts</h2>
        <div className="shop-grid">
          {xpBoostItems.map((boost) => {
            const costVal = boost.cost ?? 0;
            const canAfford = coins >= costVal;
            const isActiveBoost = xpBoost === boost.effectValue;
            const buttonText = isActiveBoost ? 'Active' : 'Buy';
            const buttonDisabled = isActiveBoost || !canAfford;

            const handleClick = () => {
              if (!canAfford || isActiveBoost) return;
              handlePurchase(boost._id);
            };

            return (
              <div className="shop-item boost-item" key={boost._id}>
                <img
                  src={boost.imageUrl}
                  alt={boost.title}
                  className="shop-item-image"
                />
                <div className="shop-item-info">
                  <h3>{boost.title}</h3>
                  <p>{boost.description}</p>
                  <p className="cost">Cost: {costVal} coins</p>
                  <button
                    disabled={buttonDisabled}
                    onClick={handleClick}
                    className="purchase-button"
                  >
                    {buttonText}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  // Render Avatars
  const renderAvatars = () => {
    if (!avatarItems.length) return null;
    return (
      <div className="shop-section avatar-section">
        <h2 className="section-title">Avatars</h2>
        {/* 
          Here's the only structural change:
          we add "avatar-grid" alongside "shop-grid" 
          so you can target it in your CSS. 
        */}
        <div className="shop-grid avatar-grid">
          {avatarItems.map((avatar) => {
            const costVal = avatar.cost ?? 0;
            const autoUnlocked = (avatar.cost === null);
            const levelUnlocked = level >= avatar.unlockLevel;
            const purchased = isPurchased(avatar._id);

            const unlocked = autoUnlocked || levelUnlocked || purchased;
            const isEquipped = currentAvatar === avatar._id;

            let buttonText = '';
            let buttonDisabled = false;
            let onClickAction = null;

            if (!unlocked) {
              // Must buy
              buttonText = 'Buy';
              buttonDisabled = coins < costVal;
              onClickAction = () => handlePurchase(avatar._id);
            } else {
              // Already unlocked (cost=0/null) or purchased
              if (isEquipped) {
                buttonText = 'Equipped';
                buttonDisabled = true;
              } else {
                buttonText = 'Equip';
                onClickAction = () => handleEquip(avatar._id);
              }
            }

            return (
              <div className="shop-item avatar-item" key={avatar._id}>
                <img
                  src={avatar.imageUrl}
                  alt={avatar.title}
                  className="shop-item-image"
                />
                <div className="shop-item-info">
                  <h3>{avatar.title}</h3>
                  <p>{avatar.description}</p>
                  <p className="unlock-level">Unlock Level: {avatar.unlockLevel}</p>
                  {(!autoUnlocked && !unlocked) && (
                    <p className="cost">Cost: {costVal} coins</p>
                  )}
                  {autoUnlocked && (
                    <p className="default-tag">(Default Avatar)</p>
                  )}
                  <button
                    disabled={buttonDisabled}
                    onClick={onClickAction}
                    className="purchase-button"
                  >
                    {buttonText}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  // Determine content based on status
  let content;
  if (status === 'loading') {
    content = <p className="loading-text">Loading shop items...</p>;
  } else if (status === 'failed') {
    content = <p className="error-text">Error loading shop items: {error}</p>;
  } else {
    content = (
      <>
        {renderXpBoosts()}
        {renderAvatars()}
      </>
    );
  }

  return (
    <div className="shop-page mario-kart-theme">
      <header className="shop-header">
        <h1 className="main-title">Shop</h1>
        <div className="shop-user-info">
          <p className="user-stat">Coins: {coins}</p>
          <p className="user-stat">Level: {level}</p>
        </div>
      </header>

      {purchaseStatus && (
        <div className="purchase-status">{purchaseStatus}</div>
      )}

      {content}
    </div>
  );
};

export default ShopPage;

