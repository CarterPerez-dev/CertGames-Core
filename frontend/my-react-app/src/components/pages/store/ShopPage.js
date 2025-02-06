// src/components/pages/store/ShopPage.js
import React, { useEffect, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { fetchShopItems } from '../../../store/shopSlice'; // Adjust path if needed
import { fetchUserData } from '../../../store/userSlice';   // Adjust path if needed
import './ShopPage.css';  // We'll do CSS in a separate step

const ShopPage = () => {
  const dispatch = useDispatch();

  // Select shop state from store
  const { items, status, error } = useSelector((state) => state.shop);

  // Select user data from store
  const {
    userId,
    coins,
    level,
    achievements,
    xpBoost,
    currentAvatar,
    nameColor,
    // If your user doc has purchasedItems in Redux, select it here.
    // Otherwise, we can re-check "already purchased" by looking at the user doc from the backend each time.
  } = useSelector((state) => state.user);

  // Local state to store a loading indicator or error message for purchases
  const [purchaseStatus, setPurchaseStatus] = useState(null);

  // On component mount, fetch shop items
  useEffect(() => {
    if (status === 'idle') {
      dispatch(fetchShopItems());
    }
  }, [status, dispatch]);

  // Group shop items by type
  const xpBoostItems = items.filter((item) => item.type === 'xpBoost');
  const avatarItems  = items.filter((item) => item.type === 'avatar');
  // Later, if you add more types (e.g. "nameColor"), you can filter them similarly.

  // Helper: Check if the user has purchased an item
  const hasPurchased = (itemId) => {
    // If your user doc includes purchasedItems in Redux, do:
    // return purchasedItems?.some(id => id === itemId);
    // or if user doesn't have purchasedItems in Redux, use another approach:
    return false; // We'll replace this if you store purchasedItems in Redux
  };

  // Handler to purchase an item
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
        // Purchase successful: refresh user data (so coins, purchasedItems, xpBoost, etc. update)
        dispatch(fetchUserData(userId));
        setPurchaseStatus(data.message || 'Purchase successful!');
      } else {
        // Purchase failed
        setPurchaseStatus(data.message || 'Purchase failed.');
      }
    } catch (err) {
      setPurchaseStatus('Error: ' + err.message);
    }
  };

  const renderXpBoosts = () => {
    if (!xpBoostItems.length) return null;
    return (
      <div className="shop-section">
        <h2>XP Boosts</h2>
        <div className="shop-grid">
          {xpBoostItems.map((boost) => {
            const canAfford = coins >= boost.cost;
            // If you store purchased items in Redux, check if purchased here
            const alreadyPurchased = hasPurchased(boost._id);

            const handleClick = () => {
              if (!canAfford) return;
              if (alreadyPurchased) return;
              handlePurchase(boost._id);
            };

            return (
              <div className="shop-item" key={boost._id}>
                <img src={boost.imageUrl} alt={boost.title} className="shop-item-image" />
                <div className="shop-item-info">
                  <h3>{boost.title}</h3>
                  <p>{boost.description}</p>
                  <p>Cost: {boost.cost} coins</p>
                  {alreadyPurchased ? (
                    <button className="purchased-button" disabled>
                      Purchased
                    </button>
                  ) : (
                    <button
                      disabled={!canAfford}
                      onClick={handleClick}
                    >
                      Buy
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  const renderAvatars = () => {
    if (!avatarItems.length) return null;
    return (
      <div className="shop-section">
        <h2>Avatars</h2>
        <div className="shop-grid">
          {avatarItems.map((avatar) => {
            const canAfford = coins >= avatar.cost;
            // If the user's level < unlockLevel, disable purchase
            const meetsLevel = level >= avatar.unlockLevel;
            // If user doc includes purchased items, check that
            const alreadyPurchased = hasPurchased(avatar._id);

            const handleClick = () => {
              if (!canAfford || !meetsLevel || alreadyPurchased) return;
              handlePurchase(avatar._id);
            };

            return (
              <div className="shop-item" key={avatar._id}>
                <img src={avatar.imageUrl} alt={avatar.title} className="shop-item-image" />
                <div className="shop-item-info">
                  <h3>{avatar.title}</h3>
                  <p>{avatar.description}</p>
                  <p>Unlock Level: {avatar.unlockLevel}</p>
                  <p>Cost: {avatar.cost} coins</p>
                  {alreadyPurchased ? (
                    <button className="purchased-button" disabled>
                      Purchased
                    </button>
                  ) : (
                    <button
                      disabled={!canAfford || !meetsLevel}
                      onClick={handleClick}
                    >
                      Buy
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  // If you want to handle different states: loading, error, etc.
  let content;
  if (status === 'loading') {
    content = <p>Loading shop items...</p>;
  } else if (status === 'failed') {
    content = <p>Error loading shop items: {error}</p>;
  } else {
    content = (
      <>
        {renderXpBoosts()}
        {renderAvatars()}
      </>
    );
  }

  return (
    <div className="shop-page">
      <header className="shop-header">
        <h1>Shop</h1>
        <div className="shop-user-info">
          <p>Coins: {coins}</p>
          <p>Level: {level}</p>
          {/* Optionally show xpBoost, currentAvatar, etc. */}
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
