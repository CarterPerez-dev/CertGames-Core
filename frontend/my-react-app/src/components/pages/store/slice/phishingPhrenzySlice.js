// src/components/pages/store/slice/phishingPhrenzySlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { fetchUserData } from './userSlice';

// Thunk to fetch phishing examples from the backend
export const fetchPhishingData = createAsyncThunk(
  'phishingPhrenzy/fetchPhishingData',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/phishing/examples');
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
      
      // Fetch updated user data to refresh coins/XP
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
      // Shuffle phishing items when starting a new game
      state.phishingItems = [...state.phishingItems]
        .sort(() => Math.random() - 0.5)
        .map(item => ({ ...item }));
    },
    endGame: (state, action) => {
      state.gameStatus = 'finished';
      // Update high score if current score is higher
      if (state.score > state.highScore) {
        state.highScore = state.score;
        localStorage.setItem('phishingPhrenzyHighScore', state.score.toString());
      }
      
      // Submit score to backend if userId is provided
      const userId = action.payload;
      if (userId) {
        // This will be handled by the submitGameResults thunk
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
      // IMPORTANT: Don't reset to 'idle' automatically
      // This will be done explicitly by the component 
      // at the right time to avoid race conditions
      state.score = 0;
      // Don't reset phishingItems here to avoid unnecessary refetching
    }
  },
  extraReducers: (builder) => {
    builder
      // Fetch phishing data
      .addCase(fetchPhishingData.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchPhishingData.fulfilled, (state, action) => {
        state.loading = false;
        state.phishingItems = action.payload;
        // Ensure items are shuffled
        state.phishingItems = [...state.phishingItems]
          .sort(() => Math.random() - 0.5)
          .map(item => ({ ...item }));
      })
      .addCase(fetchPhishingData.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // Submit game results
      .addCase(submitGameResults.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(submitGameResults.fulfilled, (state, action) => {
        state.loading = false;
        state.lastSubmittedScore = null;
        
        // If the server returned any achievements, store them
        if (action.payload.achievements) {
          state.achievements = action.payload.achievements;
        }
        
        // IMPORTANT: DO NOT reset the game state here
        // This allows the game over modal to remain visible
      })
      .addCase(submitGameResults.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
        // We keep the lastSubmittedScore in case we want to retry
      });
  },
});

export const { 
  startGame, 
  endGame, 
  incrementScore, 
  decrementScore, 
  resetGame 
} = phishingPhrenzySlice.actions;

export default phishingPhrenzySlice.reducer;
