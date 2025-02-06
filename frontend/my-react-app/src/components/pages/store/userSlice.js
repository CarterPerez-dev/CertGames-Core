// src/store/userSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';

const initialUserId = localStorage.getItem('userId');

const initialState = {
  userId: initialUserId ? initialUserId : null,
  username: '',
  xp: 0,
  level: 1,
  coins: 0,
  achievements: [], // Unlocked achievement IDs
  status: 'idle',   // e.g., 'idle', 'loading', 'succeeded'
  loading: false,   // For register/login operations
  error: null,
};

// 1) Register a new user
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
      // { message, user_id }
      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// 2) Login user
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
      // { user_id, username, coins, xp, level, achievements }
      return data;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

// 3) Fetch user data
export const fetchUserData = createAsyncThunk(
  'user/fetchUserData',
  async (userId, { rejectWithValue }) => {
    try {
      const response = await fetch(`/api/test/user/${userId}`);
      if (!response.ok) throw new Error('Failed to fetch user data');
      return await response.json();
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// 4) Daily bonus
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

// 5) Add XP (e.g., from daily bonus or other events)
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
      // { xp, level, newAchievements? }
      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// 6) Add coins
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
      // { coinsToAdd: number }
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
      state.status = 'idle';
      localStorage.removeItem('userId');
    },
  },
  extraReducers: (builder) => {
    builder
      // registerUser
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
      // loginUser
      .addCase(loginUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loginUser.fulfilled, (state, action) => {
        state.loading = false;
        state.error = null;
        const { user_id, username, coins, xp, level, achievements } = action.payload;
        state.userId = user_id;
        state.username = username;
        state.coins = coins;
        state.xp = xp;
        state.level = level;
        state.achievements = achievements || [];
        localStorage.setItem('userId', user_id);
      })
      .addCase(loginUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      // fetchUserData
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
      })
      .addCase(fetchUserData.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      })
      // dailyLoginBonus
      .addCase(dailyLoginBonus.fulfilled, (state, action) => {
        // If the daily bonus includes coins, increment
        if (action.payload.coins) {
          state.coins += action.payload.coins;
        }
      })
      // addXP
      .addCase(addXP.fulfilled, (state, action) => {
        state.xp = action.payload.xp;
        state.level = action.payload.level;
        if (action.payload.newAchievements) {
          state.achievements = Array.from(new Set([
            ...state.achievements,
            ...action.payload.newAchievements
          ]));
        }
      })
      // addCoins
      .addCase(addCoins.fulfilled, (state, action) => {
        state.coins += action.payload.coinsToAdd;
      });
  },
});

export const { setCurrentUserId, logout } = userSlice.actions;
export default userSlice.reducer;
