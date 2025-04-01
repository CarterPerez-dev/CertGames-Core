// store.js
import { configureStore } from '@reduxjs/toolkit';
import userReducer from './slice/userSlice';
import shopReducer from './slice/shopSlice';
import achievementsReducer from './slice/achievementsSlice';

export const store = configureStore({
  reducer: {
    user: userReducer,
    shop: shopReducer,
    achievements: achievementsReducer
  }
});

