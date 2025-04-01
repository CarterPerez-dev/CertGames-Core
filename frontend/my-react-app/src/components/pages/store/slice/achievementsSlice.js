// src/store/achievementsSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { registerUser, loginUser, dailyLoginBonus, addXP, addCoins, fetchUserData, logout, setCurrentUserId } from './userSlice';


export const fetchAchievements = createAsyncThunk(
  'achievements/fetchAchievements',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/test/achievements');
      if (!response.ok) throw new Error('Failed to fetch achievements');
      return await response.json();
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

const achievementsSlice = createSlice({
  name: 'achievements',
  initialState: {
    all: [],
    status: 'idle',
    error: null,
    popups: []  // This can be used for temporary popup notifications
  },
  reducers: {
    // If you want to push a new achievement popup (for example, after unlocking an achievement)
    addPopup: (state, action) => {
      state.popups.push(action.payload);
    },
    removePopup: (state) => {
      state.popups.shift();
    }
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchAchievements.pending, (state) => {
        state.status = 'loading';
      })
      .addCase(fetchAchievements.fulfilled, (state, action) => {
        state.all = action.payload;
        state.status = 'succeeded';
      })
      .addCase(fetchAchievements.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      });
  }
});

export const { addPopup, removePopup } = achievementsSlice.actions;
export default achievementsSlice.reducer;

