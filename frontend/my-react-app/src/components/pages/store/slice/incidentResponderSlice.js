// src/components/pages/store/slice/incidentResponderSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { addCoins, fetchUserData } from './userSlice';


// Fetch incident responder scenarios
export const fetchScenarios = createAsyncThunk(
  'incidentResponder/fetchScenarios',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/incident/scenarios');
      
      if (!response.ok) {
        throw new Error('Failed to fetch incident scenarios');
      }
      return await response.json();
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Start a scenario
export const startScenario = createAsyncThunk(
  'incidentResponder/startScenario',
  async ({ scenarioId, userId, difficulty }, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/incident/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scenarioId,
          userId,
          difficulty
        }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to start scenario');
      }
      
      return await response.json();
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Select an action in a stage
export const selectAction = createAsyncThunk(
  'incidentResponder/selectAction',
  async ({ actionId, stageId, userId }, { dispatch, getState, rejectWithValue }) => {
    // If action is 'start', just move to the first stage
    if (actionId === 'start' && stageId === 'intro') {
      // Start the scenario
      const currentScenario = getState().incidentResponder.currentScenario;
      const stages = currentScenario.stages || [];
      
      if (stages.length > 0) {
        return {
          nextStage: stages[0],
          action: { id: 'start' },
          isComplete: false
        };
      } else {
        return rejectWithValue('No stages found in scenario');
      }
    }
    
    // If action is 'continue', just move to the next stage
    if (actionId === 'continue') {
      const { currentStage, currentScenario, selectedActions, score } = getState().incidentResponder;
      
      // Find the next stage
      const stages = currentScenario.stages || [];
      const currentIndex = stages.findIndex(stage => stage.id === currentStage.id);
      const isLastStage = currentIndex === stages.length - 1;
      
      if (isLastStage) {
        // Scenario is complete, submit results
        try {
          const response = await fetch('/api/incident/complete', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              userId,
              scenarioId: currentScenario.id,
              selectedActions,
              score
            }),
          });
          
          if (!response.ok) {
            throw new Error('Failed to complete scenario');
          }
          
          const results = await response.json();
          
          // If the backend awarded coins, update user state
          if (results.coinsAwarded > 0) {
            dispatch(addCoins({ 
              userId, 
              amount: results.coinsAwarded 
            }));
          }
          
          // Fetch updated user data (for XP, etc.)
          dispatch(fetchUserData(userId));
          
          return {
            results,
            isComplete: true
          };
        } catch (error) {
          return rejectWithValue(error.message);
        }
      } else {
        // Move to the next stage
        return {
          nextStage: stages[currentIndex + 1],
          action: { id: 'continue' },
          isComplete: false
        };
      }
    }
    
    // For regular actions, send to backend
    try {
      const { currentStage, currentScenario } = getState().incidentResponder;
      
      const response = await fetch('/api/incident/action', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId,
          scenarioId: currentScenario.id,
          stageId,
          actionId
        }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to process action');
      }
      
      const data = await response.json();
      
      // FIXED: Handle stage transition locally since server returns nextStage: null
      // Find the action from the current stage's actions array
      const action = currentStage.actions.find(a => a.id === actionId);
      
      // Return enhanced data with the same stage (we'll show explanation before continuing)
      return {
        nextStage: currentStage,  // Keep same stage but show explanation
        action: action || { id: actionId },
        points: data.points || 0,
        isComplete: false,
        showExplanation: true  // Flag to show the explanation
      };
      
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);


export const toggleBookmark = createAsyncThunk(
  'incidentResponder/toggleBookmark',
  async ({ userId, scenarioId }, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/incident/bookmark', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ userId, scenarioId })
      });
      
      if (!response.ok) {
        throw new Error('Failed to toggle bookmark');
      }
      
      const data = await response.json();
      return { scenarioId, bookmarked: data.bookmarked };
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// New thunk for fetching bookmarks
export const fetchBookmarks = createAsyncThunk(
  'incidentResponder/fetchBookmarks',
  async (userId, { rejectWithValue }) => {
    try {
      const response = await fetch(`/api/incident/bookmarks/${userId}`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch bookmarks');
      }
      
      const data = await response.json();
      return data.bookmarkedScenarios;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);


const initialState = {
  scenarios: [],
  currentScenario: null,
  currentStage: null,
  selectedActions: {},
  gameStatus: 'selecting', // 'selecting', 'intro', 'playing', 'completed'
  score: 0,
  results: null,
  loading: false,
  error: null,
  showExplanation: false,
  bookmarkedScenarios: [],
  bookmarksLoading: false,
  bookmarksError: null,
};

const incidentResponderSlice = createSlice({
  name: 'incidentResponder',
  initialState,
  reducers: {
    resetGame: (state) => {
      state.currentScenario = null;
      state.currentStage = null;
      state.selectedActions = {};
      state.gameStatus = 'selecting';
      state.score = 0;
      state.results = null;
      state.error = null;
      state.showExplanation = false;
    }
  },
  extraReducers: (builder) => {
    // Existing reducers for fetchScenarios
    builder
      .addCase(fetchScenarios.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchScenarios.fulfilled, (state, action) => {
        state.loading = false;
        state.scenarios = action.payload;
      })
      .addCase(fetchScenarios.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // Existing reducers for startScenario
      .addCase(startScenario.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(startScenario.fulfilled, (state, action) => {
        state.loading = false;
        state.currentScenario = action.payload;
        state.gameStatus = 'intro';
        state.selectedActions = {};
        state.score = 0;
      })
      .addCase(startScenario.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // Existing reducers for selectAction
      .addCase(selectAction.pending, (state) => {
        state.loading = true;
      })
      .addCase(selectAction.fulfilled, (state, action) => {
        state.loading = false;
        
        const { actionId, stageId, nextStage, score, showExplanation } = action.payload;
        
        // Handle special action IDs
        if (actionId === 'start') {
          state.gameStatus = 'playing';
          state.currentStage = action.payload.stage;
        } else if (actionId === 'continue') {
          if (nextStage) {
            state.currentStage = nextStage;
            state.showExplanation = false;
          } else {
            // Game completed
            state.gameStatus = 'completed';
          }
        } else {
          // Regular action selection
          state.selectedActions[stageId] = actionId;
          state.showExplanation = showExplanation || false;
          if (score !== undefined) {
            state.score = score;
          }
        }
      })
      .addCase(selectAction.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // NEW CODE - Add these bookmark-related reducers
      
      // Toggle bookmark
      .addCase(toggleBookmark.pending, (state) => {
        state.bookmarksLoading = true;
      })
      .addCase(toggleBookmark.fulfilled, (state, action) => {
        state.bookmarksLoading = false;
        const { scenarioId, bookmarked } = action.payload;
        
        if (bookmarked) {
          // Add to bookmarked scenarios
          if (!state.bookmarkedScenarios.includes(scenarioId)) {
            state.bookmarkedScenarios.push(scenarioId);
          }
        } else {
          // Remove from bookmarked scenarios
          state.bookmarkedScenarios = state.bookmarkedScenarios.filter(id => id !== scenarioId);
        }
      })
      .addCase(toggleBookmark.rejected, (state, action) => {
        state.bookmarksLoading = false;
        state.bookmarksError = action.payload;
      })
      
      // Fetch bookmarks
      .addCase(fetchBookmarks.pending, (state) => {
        state.bookmarksLoading = true;
      })
      .addCase(fetchBookmarks.fulfilled, (state, action) => {
        state.bookmarksLoading = false;
        state.bookmarkedScenarios = action.payload;
      })
      .addCase(fetchBookmarks.rejected, (state, action) => {
        state.bookmarksLoading = false;
        state.bookmarksError = action.payload;
      });
  },
});

export const { resetGame } = incidentResponderSlice.actions;
export default incidentResponderSlice.reducer;
