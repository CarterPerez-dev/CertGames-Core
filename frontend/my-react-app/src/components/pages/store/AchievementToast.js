// src/components/pages/store/AchievementToast.js
import React from 'react';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './css/AchievementToast.css';

export const showAchievementToast = (achievement) => {
  toast.info(
    <div style={{ display: 'flex', alignItems: 'center' }}>
      {achievement.icon && (
        <span style={{ marginRight: '0.5rem', fontSize: '1.5rem', color: achievement.color }}>
          {achievement.icon}
        </span>
      )}
      <div>
        <div style={{ fontWeight: 'bold', fontSize: '1.1rem' }}>{achievement.title}</div>
        <div style={{ fontSize: '0.9rem' }}>{achievement.description}</div>
      </div>
    </div>,
    {
      position: "top-right",
      autoClose: 4000,
      hideProgressBar: false,
      closeOnClick: true,
      pauseOnHover: true,
      draggable: true,
      progress: undefined,
      style: { background: '#333', color: '#fff', borderRadius: '8px' },
    }
  );
};

