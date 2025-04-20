// src/components/pages/store/slice/threatHunterSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';

// Async thunks
export const fetchLogScenarios = createAsyncThunk(
  'threatHunter/fetchLogScenarios',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/threat-hunter/scenarios');
      if (!response.ok) {
        throw new Error('Failed to fetch scenarios');
      }
      const data = await response.json();
      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const startScenario = createAsyncThunk(
  'threatHunter/startScenario',
  async (scenarioData, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/threat-hunter/start-scenario', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(scenarioData),
      });
      if (!response.ok) {
        throw new Error('Failed to start scenario');
      }
      const data = await response.json();
      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const submitAnalysis = createAsyncThunk(
  'threatHunter/submitAnalysis',
  async (analysisData, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/threat-hunter/submit-analysis', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(analysisData),
      });
      if (!response.ok) {
        throw new Error('Failed to submit analysis');
      }
      const data = await response.json();
      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Initial state
const initialState = {
  scenarios: [], // This is the key property that's missing
  currentScenario: null,
  gameStatus: 'selecting', // 'selecting', 'playing', 'completed'
  selectedLog: null,
  timeLeft: null,
  score: 0,
  results: null,
  loading: false,
  error: null
};

// Slice
const threatHunterSlice = createSlice({
  name: 'threatHunter',
  initialState,
  reducers: {
    resetGame: (state) => {
      state.gameStatus = 'selecting';
      state.currentScenario = null;
      state.selectedLog = null;
      state.timeLeft = null;
      state.score = 0;
      state.results = null;
      state.error = null;
    },
    // Add other reducers as needed
  },
  extraReducers: (builder) => {
    builder
      // fetchLogScenarios
      .addCase(fetchLogScenarios.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchLogScenarios.fulfilled, (state, action) => {
        state.loading = false;
        state.scenarios = action.payload;
      })
      .addCase(fetchLogScenarios.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // startScenario
      .addCase(startScenario.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(startScenario.fulfilled, (state, action) => {
        state.loading = false;
        state.currentScenario = action.payload.scenario;
        state.timeLeft = action.payload.timeLimit;
        state.gameStatus = 'playing';
      })
      .addCase(startScenario.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // submitAnalysis
      .addCase(submitAnalysis.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(submitAnalysis.fulfilled, (state, action) => {
        state.loading = false;
        state.results = action.payload;
        state.gameStatus = 'completed';
      })
      .addCase(submitAnalysis.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      });
  },
});

export const { resetGame } = threatHunterSlice.actions;
export default threatHunterSlice.reducer;
