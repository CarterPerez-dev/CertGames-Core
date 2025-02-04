// src/components/pages/store/AchievementPage.js
import React, { useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { fetchAchievements } from '../store/achievementsSlice';
import { 
  FaTrophy, 
  FaMedal, 
  FaStar, 
  FaCrown, 
  FaBolt, 
  FaBook, 
  FaBrain, 
  FaCheckCircle, 
  FaRegSmile,
  FaMagic
} from 'react-icons/fa';
import { showAchievementToast } from './AchievementToast';
import './AchievementPage.css';

// Mapping achievement IDs to icon components.
const iconMapping = {
  "test_rookie": FaTrophy,
  "accuracy_king": FaMedal,
  "bronze_grinder": FaBook,
  "silver_scholar": FaStar,
  "gold_god": FaCrown,
  "platinum_pro": FaMagic,
  "walking_encyclopedia": FaBrain,
  "redemption_arc": FaBolt,
  "memory_master": FaRegSmile,
  "coin_collector_5000": FaBook,
  "coin_hoarder_10000": FaBook,
  "coin_tycoon_50000": FaBook,
  "perfectionist_1": FaCheckCircle,
  "double_trouble_2": FaCheckCircle,
  "error404_failure_not_found": FaCheckCircle,
  "level_up_5": FaTrophy,
  "mid_tier_grinder_25": FaMedal,
  "elite_scholar_50": FaStar,
  "ultimate_master_100": FaCrown,
  "category_perfectionist": FaBolt,
  "absolute_perfectionist": FaBolt,
  "exam_conqueror": FaMedal,
  "subject_specialist": FaMedal,
  "answer_machine_1000": FaBook,
  "knowledge_beast_5000": FaBrain,
  "question_terminator": FaBrain,
  "test_finisher": FaCheckCircle,
  "subject_finisher": FaCheckCircle
};

// Mapping achievement IDs to colors.
const colorMapping = {
  "test_rookie": "#ff5555",
  "accuracy_king": "#ffa500",
  "bronze_grinder": "#cd7f32",
  "silver_scholar": "#c0c0c0",
  "gold_god": "#ffd700",
  "platinum_pro": "#e5e4e2",
  "walking_encyclopedia": "#00fa9a",
  "redemption_arc": "#ff4500",
  "memory_master": "#8a2be2",
  "coin_collector_5000": "#ff69b4",
  "coin_hoarder_10000": "#ff1493",
  "coin_tycoon_50000": "#ff0000",
  "perfectionist_1": "#adff2f",
  "double_trouble_2": "#7fff00",
  "error404_failure_not_found": "#00ffff",
  "level_up_5": "#f08080",
  "mid_tier_grinder_25": "#ff8c00",
  "elite_scholar_50": "#ffd700",
  "ultimate_master_100": "#ff4500",
  "category_perfectionist": "#00ced1",
  "absolute_perfectionist": "#32cd32",
  "exam_conqueror": "#1e90ff",
  "subject_specialist": "#8a2be2",
  "answer_machine_1000": "#ff69b4",
  "knowledge_beast_5000": "#00fa9a",
  "question_terminator": "#ff1493",
  "test_finisher": "#adff2f",
  "subject_finisher": "#7fff00"
};

const AchievementPage = () => {
  const dispatch = useDispatch();
  const achievements = useSelector((state) => state.achievements.all);
  const userAchievements = useSelector((state) => state.user.achievements) || [];

  useEffect(() => {
    if (!achievements || achievements.length === 0) {
      dispatch(fetchAchievements());
    }
  }, [dispatch, achievements]);

  // Temporary function to test a popup.
  const testPopup = (achievementId) => {
    const achievement = achievements.find((ach) => ach.achievementId === achievementId);
    if (achievement) {
      const IconComponent = iconMapping[achievement.achievementId] || null;
      const color = colorMapping[achievement.achievementId] || "#fff";
      showAchievementToast({
        title: achievement.title,
        description: achievement.description,
        icon: IconComponent ? <IconComponent /> : null,
        color: color
      });
    }
  };

  return (
    <div className="achievement-page">
      <header className="achievement-header">
        <h1>Achievements</h1>
        <p>Discover your milestones and track your progress on our gamified platform!</p>
        {/* Temporary test buttons for simulating achievement popups */}
        <div className="test-popup-buttons">
          <button onClick={() => testPopup("test_rookie")}>Test Popup: Test Rookie</button>
          <button onClick={() => testPopup("gold_god")}>Test Popup: Gold God</button>
        </div>
      </header>
      <div className="achievement-grid">
        {achievements.map((ach) => {
          const isUnlocked = userAchievements.includes(ach.achievementId);
          const IconComponent = iconMapping[ach.achievementId] || FaTrophy;
          const iconColor = colorMapping[ach.achievementId] || "#ffffff";
          return (
            <div key={ach.achievementId} className={`achievement-card ${isUnlocked ? 'unlocked' : 'locked'}`}>
              <div className="achievement-icon" style={{ color: iconColor }}>
                <IconComponent />
              </div>
              <h2 className="achievement-title">{ach.title}</h2>
              <p className="achievement-description">{ach.description}</p>
              {!isUnlocked && <div className="lock-overlay">Incomplete</div>}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default AchievementPage;

