// store.js
import { configureStore } from '@reduxjs/toolkit';

// Import all reducers
import userReducer from './slice/userSlice';
import achievementsReducer from './slice/achievementsSlice';
import cipherChallengeReducer from './slice/cipherChallengeSlice';
import incidentResponderReducer from './slice/incidentResponderSlice';
import phishingPhrenzyReducer from './slice/phishingPhrenzySlice';
import shopReducer from './slice/shopSlice';
import threatHunterReducer from './slice/threatHunterSlice';

// Configure the store with all reducers
export const store = configureStore({
  reducer: {
    user: userReducer,
    achievements: achievementsReducer,
    cipherChallenge: cipherChallengeReducer,
    incidentResponder: incidentResponderReducer,
    phishingPhrenzy: phishingPhrenzyReducer,
    shop: shopReducer,
    threatHunter: threatHunterReducer
  },
});

