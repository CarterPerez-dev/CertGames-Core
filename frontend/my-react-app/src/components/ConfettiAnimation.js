// lvl up animation.(Simplified)
import React from "react";
import "./test.css";

const ConfettiAnimation = ({ trigger, level }) => {
  if (!trigger) return null;
  return (
    <div className="simple-level-up-overlay">
      <div className="simple-level-up-content">
        LEVEL UP! <br /> You are now Level {level}
      </div>
    </div>
  );
};

export default ConfettiAnimation;

