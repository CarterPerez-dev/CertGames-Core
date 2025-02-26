// src/store/shopSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';

// Async thunk to fetch shop items from the backend
export const fetchShopItems = createAsyncThunk(
  'shop/fetchShopItems',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/test/shop');
      if (!response.ok) {
        throw new Error('Failed to fetch shop items');
      }
      const data = await response.json();
      return data; // Expected to be an array of shop item objects
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

const initialState = {
  items: [],
  status: 'idle', // 'idle' | 'loading' | 'succeeded' | 'failed'
  error: null,
};

const shopSlice = createSlice({
  name: 'shop',
  initialState,
  reducers: {
    // Optionally add reducers for filtering items or updating local shop state
    // e.g., setFilter(state, action) { state.filter = action.payload; }
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchShopItems.pending, (state) => {
        state.status = 'loading';
      })
      .addCase(fetchShopItems.fulfilled, (state, action) => {
        state.status = 'succeeded';
        state.items = action.payload;
      })
      .addCase(fetchShopItems.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      });
  },
});

export default shopSlice.reducer;
