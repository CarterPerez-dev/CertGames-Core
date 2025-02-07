// src/store/userSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';

const initialUserId = localStorage.getItem('userId');

// Extend the initial state with xpBoost, currentAvatar, nameColor, and purchasedItems
const initialState = {
  userId: initialUserId ? initialUserId : null,
  username: '',
  xp: 0,
  level: 1,
  coins: 0,
  achievements: [], // Unlocked achievement IDs
  xpBoost: 1.0,
  currentAvatar: null,
  nameColor: null,
  purchasedItems: [], // Newly added: array of purchased shop item IDs

  status: 'idle',   // e.g., 'idle', 'loading', 'succeeded'
  loading: false,   // For register/login operations
  error: null,
};

// 1) Register User
export const registerUser = createAsyncThunk(
  'user/registerUser',
  async (formData, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/test/user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Registration failed');
      }
      // Expected: { message, user_id }
      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// 2) Login User
export const loginUser = createAsyncThunk(
  'user/loginUser',
  async (credentials, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/test/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }
      // Expected server response includes:
      // { user_id, username, coins, xp, level, achievements, xpBoost, currentAvatar, nameColor, purchasedItems }
      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// 3) Fetch User Data
export const fetchUserData = createAsyncThunk(
  'user/fetchUserData',
  async (userId, { rejectWithValue }) => {
    try {
      const response = await fetch(`/api/test/user/${userId}`);
      if (!response.ok) throw new Error('Failed to fetch user data');
      const data = await response.json();
      // Expected: includes xpBoost, currentAvatar, nameColor, purchasedItems
      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// 4) Daily Login Bonus
export const dailyLoginBonus = createAsyncThunk(
  'user/dailyLoginBonus',
  async (userId, { rejectWithValue }) => {
    try {
      const response = await fetch(`/api/test/user/${userId}/daily-bonus`, {
        method: 'POST',
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || 'Daily bonus failed');
      }
      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// 5) Add XP
export const addXP = createAsyncThunk(
  'user/addXP',
  async ({ userId, xp }, { rejectWithValue }) => {
    try {
      const response = await fetch(`/api/test/user/${userId}/add-xp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ xp }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || 'Add XP failed');
      }
      // Expected: { xp, level, newAchievements? }
      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// 6) Add Coins
export const addCoins = createAsyncThunk(
  'user/addCoins',
  async ({ userId, coins }, { rejectWithValue }) => {
    try {
      const response = await fetch(`/api/test/user/${userId}/add-coins`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ coins }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || 'Add coins failed');
      }
      // Expected: { coinsToAdd: number }
      return { coinsToAdd: coins };
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

const userSlice = createSlice({
  name: 'user',
  initialState,
  reducers: {
    setCurrentUserId(state, action) {
      state.userId = action.payload;
    },
    logout(state) {
      state.userId = null;
      state.username = '';
      state.xp = 0;
      state.level = 1;
      state.coins = 0;
      state.achievements = [];
      // Reset optional shop fields:
      state.xpBoost = 1.0;
      state.currentAvatar = null;
      state.nameColor = null;
      state.purchasedItems = [];

      state.status = 'idle';
      localStorage.removeItem('userId');
    },
    setXPAndCoins(state, action) {
      const { xp, coins } = action.payload;
      state.xp = xp;
      state.coins = coins;
    }
  },
  extraReducers: (builder) => {
    builder
      // Register User
      .addCase(registerUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(registerUser.fulfilled, (state) => {
        state.loading = false;
        state.error = null;
      })
      .addCase(registerUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // Login User
      .addCase(loginUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loginUser.fulfilled, (state, action) => {
        state.loading = false;
        state.error = null;

        const {
          user_id,
          username,
          coins,
          xp,
          level,
          achievements,
          xpBoost,
          currentAvatar,
          nameColor,
          purchasedItems
        } = action.payload;

        state.userId = user_id;
        state.username = username;
        state.coins = coins;
        state.xp = xp;
        state.level = level;
        state.achievements = achievements || [];

        // Also store xpBoost, currentAvatar, nameColor, purchasedItems from the server
        state.xpBoost = xpBoost !== undefined ? xpBoost : 1.0;
        state.currentAvatar = currentAvatar || null;
        state.nameColor = nameColor || null;
        state.purchasedItems = purchasedItems || [];

        // Persist userId 
        localStorage.setItem('userId', user_id);
      })
      .addCase(loginUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // Fetch User Data
      .addCase(fetchUserData.pending, (state) => {
        state.status = 'loading';
      })
      .addCase(fetchUserData.fulfilled, (state, action) => {
        state.status = 'succeeded';
        state.error = null;
        const userDoc = action.payload;

        state.userId = userDoc._id;
        state.username = userDoc.username;
        state.xp = userDoc.xp || 0;
        state.level = userDoc.level || 1;
        state.coins = userDoc.coins || 0;
        state.achievements = userDoc.achievements || [];

        // Also store optional fields if present
        state.xpBoost = userDoc.xpBoost !== undefined ? userDoc.xpBoost : 1.0;
        state.currentAvatar = userDoc.currentAvatar || null;
        state.nameColor = userDoc.nameColor || null;
        state.purchasedItems = userDoc.purchasedItems || [];
      })
      .addCase(fetchUserData.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      })

      // Daily Login Bonus
      .addCase(dailyLoginBonus.fulfilled, (state, action) => {
        if (action.payload.coins) {
          state.coins += action.payload.coins;
        }
      })

      // Add XP
      .addCase(addXP.fulfilled, (state, action) => {
        state.xp = action.payload.xp;
        state.level = action.payload.level;
        if (action.payload.newAchievements) {
          state.achievements = Array.from(
            new Set([...state.achievements, ...action.payload.newAchievements])
          );
        }
      })

      // Add Coins
      .addCase(addCoins.fulfilled, (state, action) => {
        state.coins += action.payload.coinsToAdd;
      });
  },
});

export const { setCurrentUserId, logout, setXPAndCoins } = userSlice.actions;
export default userSlice.reducer;

