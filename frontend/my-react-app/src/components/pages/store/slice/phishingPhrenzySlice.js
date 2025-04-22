// src/components/pages/store/slice/phishingPhrenzySlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { fetchUserData } from './userSlice';

// Thunk to fetch phishing examples from the backend
export const fetchPhishingData = createAsyncThunk(
  'phishingPhrenzy/fetchPhishingData',
  async (params = {}, { rejectWithValue, getState }) => {
    try {
      // Getting userId from params or state if available
      const { userId, limit = 100 } = params;
      const state = getState();
      const actualUserId = userId || state.user.userId;
      

      let url = '/api/phishing/examples';
      const queryParams = [];
      
      if (actualUserId) {
        queryParams.push(`userId=${actualUserId}`);
      }
      
      if (limit) {
        queryParams.push(`limit=${limit}`);
      }
      
      if (queryParams.length > 0) {
        url += '?' + queryParams.join('&');
      }
      
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error('Failed to fetch phishing examples');
      }
      const data = await response.json();
      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Thunk to submit game results to backend
export const submitGameResults = createAsyncThunk(
  'phishingPhrenzy/submitGameResults',
  async ({ userId, score, timestamp }, { rejectWithValue, dispatch }) => {
    try {
      const response = await fetch('/api/phishing/submit-score', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId,
          score,
          timestamp
        }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to submit game results');
      }
      
      const data = await response.json();
      
      // Fetching updated user data to refresh coins/XP
      await dispatch(fetchUserData(userId));
      
      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

const initialState = {
  phishingItems: [],
  gameStatus: 'idle', // 'idle', 'playing', 'finished'
  score: 0,
  highScore: parseInt(localStorage.getItem('phishingPhrenzyHighScore') || '0', 10),
  loading: false,
  error: null,
  lastSubmittedScore: null,
  achievements: [],
};

const phishingPhrenzySlice = createSlice({
  name: 'phishingPhrenzy',
  initialState,
  reducers: {
    startGame: (state) => {
      state.gameStatus = 'playing';
      state.score = 0;
    },
    endGame: (state, action) => {
      state.gameStatus = 'finished';
      // Update high score if current score is higher
      if (state.score > state.highScore) {
        state.highScore = state.score;
        localStorage.setItem('phishingPhrenzyHighScore', state.score.toString());
      }
      

      const userId = action.payload;
      if (userId) {
        state.lastSubmittedScore = {
          score: state.score,
          timestamp: new Date().toISOString()
        };
      }
    },
    incrementScore: (state, action) => {
      state.score += action.payload;
    },
    decrementScore: (state, action) => {
      state.score = Math.max(0, state.score - action.payload);
    },
    resetGame: (state) => {
      // IMPORTANT
      state.score = 0;
      // reset phishingItems avoiding unnecessary refetching
    },
    // Add this new action to clear phishing items and force a refetch
    clearPhishingItems: (state) => {
      state.phishingItems = [];
    }
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchPhishingData.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchPhishingData.fulfilled, (state, action) => {
        state.loading = false;
        state.phishingItems = action.payload;
        // The backend handles the smart shuffling
      })
      .addCase(fetchPhishingData.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })      
      .addCase(submitGameResults.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(submitGameResults.fulfilled, (state, action) => {
        state.loading = false;
        state.lastSubmittedScore = null;
        

        if (action.payload.achievements) {
          state.achievements = action.payload.achievements;
        }
        
        // IMPORTANT

      })
      .addCase(submitGameResults.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;

      });
  },
});

export const { 
  startGame, 
  endGame, 
  incrementScore, 
  decrementScore, 
  resetGame,
  clearPhishingItems
} = phishingPhrenzySlice.actions;

export default phishingPhrenzySlice.reducer;
