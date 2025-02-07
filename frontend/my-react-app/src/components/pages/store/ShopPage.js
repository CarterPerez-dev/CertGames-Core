// src/components/pages/store/ShopPage.js
import React, { useEffect, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { fetchShopItems } from '../store/shopSlice'; // Adjust path if needed
import { fetchUserData } from '../store/userSlice';   // Adjust path if needed
import './ShopPage.css';

const ShopPage = () => {
  const dispatch = useDispatch();

  // Get shop items and status from the shop slice
  const { items, status, error } = useSelector((state) => state.shop);

  // Get user details from the user slice
  const {
    userId,
    coins,
    level,
    xpBoost,
    currentAvatar,
    purchasedItems = [] // Ensure we have an array of purchased item IDs
  } = useSelector((state) => state.user);

  // Define xpBoostItems and avatarItems by filtering the shop items
  const xpBoostItems = items.filter((item) => item.type === 'xpBoost');
  const avatarItems  = items.filter((item) => item.type === 'avatar');

  // Local state for displaying purchase/equip status messages
  const [purchaseStatus, setPurchaseStatus] = useState(null);

  // On component mount, fetch shop items if not already fetched
  useEffect(() => {
    if (status === 'idle') {
      dispatch(fetchShopItems());
    }
  }, [status, dispatch]);

  // Helper: Check if an item is already purchased
  const isPurchased = (itemId) => {
    return purchasedItems.includes(itemId);
  };

  // Handler: Purchase an item
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
        // Refresh user data to update coins, purchasedItems, xpBoost, etc.
        dispatch(fetchUserData(userId));
        setPurchaseStatus(data.message || 'Purchase successful!');
      } else {
        setPurchaseStatus(data.message || 'Purchase failed.');
      }
    } catch (err) {
      setPurchaseStatus('Error: ' + err.message);
    }
  };

  // Handler: Equip an avatar
  const handleEquip = async (itemId) => {
    if (!userId) {
      setPurchaseStatus('Please log in to equip an avatar.');
      return;
    }
    setPurchaseStatus('Equipping avatar...');
    try {
      const response = await fetch(`/api/test/shop/equip`, {
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

  // Render XP Boost Items
  const renderXpBoosts = () => {
    if (!xpBoostItems.length) return null;
    return (
      <div className="shop-section xp-boost-section">
        <h2 className="shop-section-title">XP Boosts</h2>
        <div className="shop-grid">
          {xpBoostItems.map((boost) => {
            const canAfford = coins >= boost.cost;
            const isActiveBoost = xpBoost === boost.effectValue;
            const buttonText = isActiveBoost ? 'Active' : 'Buy';
            const buttonDisabled = isActiveBoost || !canAfford;

            const handleClick = () => {
              if (!canAfford || isActiveBoost) return;
              handlePurchase(boost._id);
            };

            return (
              <div
                className="shop-item xp-boost-item"
                key={boost._id}
              >
                <img
                  src={boost.imageUrl}
                  alt={boost.title}
                  className="shop-item-image xpboost-image"
                />
                <div className="shop-item-info">
                  <h3 className="shop-item-title">{boost.title}</h3>
                  <p className="shop-item-description">{boost.description}</p>
                  <p className="shop-item-cost">Cost: {boost.cost} coins</p>
                  <button
                    disabled={buttonDisabled}
                    onClick={handleClick}
                    className="shop-item-button"
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

  // Render Avatar Items with unlock and equip logic
  const renderAvatars = () => {
    if (!avatarItems.length) return null;
    return (
      <div className="shop-section avatar-section">
        <h2 className="shop-section-title">Avatars</h2>
        <div className="shop-grid">
          {avatarItems.map((avatar) => {
            const autoUnlocked = avatar.cost === null || avatar.cost === 0;
            const levelUnlocked = level >= avatar.unlockLevel;
            const purchased = isPurchased(avatar._id);
            const unlocked = autoUnlocked || levelUnlocked || purchased;
            const isEquipped = currentAvatar === avatar._id;

            let buttonText = '';
            let buttonDisabled = false;
            let onClickAction = null;

            if (!unlocked) {
              // Not unlocked: show "Buy" button
              buttonText = 'Buy';
              buttonDisabled = coins < avatar.cost;
              onClickAction = () => handlePurchase(avatar._id);
            } else {
              // Unlocked
              if (isEquipped) {
                buttonText = 'Equipped';
                buttonDisabled = true;
              } else {
                buttonText = 'Equip';
                buttonDisabled = false;
                onClickAction = () => handleEquip(avatar._id);
              }
            }

            return (
              <div
                className="shop-item avatar-item"
                key={avatar._id}
              >
                <img
                  src={avatar.imageUrl}
                  alt={avatar.title}
                  className="shop-item-image avatar-image"
                />
                <div className="shop-item-info">
                  <h3 className="shop-item-title">{avatar.title}</h3>
                  <p className="shop-item-description">{avatar.description}</p>
                  <p className="shop-item-unlock">Unlock Level: {avatar.unlockLevel}</p>
                  {(!autoUnlocked && !unlocked) && (
                    <p className="shop-item-cost">Cost: {avatar.cost} coins</p>
                  )}
                  {autoUnlocked && (
                    <p className="shop-item-default">(Default Avatar)</p>
                  )}
                  <button
                    disabled={buttonDisabled}
                    onClick={onClickAction}
                    className="shop-item-button"
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

  // Determine content based on the shop status
  let content;
  if (status === 'loading') {
    content = <p className="shop-loading">Loading shop items...</p>;
  } else if (status === 'failed') {
    content = <p className="shop-error">Error loading shop items: {error}</p>;
  } else {
    content = (
      <>
        {renderXpBoosts()}
        {renderAvatars()}
      </>
    );
  }

  return (
    <div className="shop-page cyber-shop-page">
      <header className="shop-header">
        <h1 className="shop-title">Shop</h1>
        <div className="shop-user-info">
          <p className="shop-user-coins">Coins: {coins}</p>
          <p className="shop-user-level">Level: {level}</p>
        </div>
      </header>

      {purchaseStatus && (
        <div className="purchase-status">
          {purchaseStatus}
        </div>
      )}

      {content}
    </div>
  );
};

export default ShopPage;

