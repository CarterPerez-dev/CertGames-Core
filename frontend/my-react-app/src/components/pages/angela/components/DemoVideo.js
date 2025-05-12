// frontend/my-react-app/src/components/pages/angela/components/DemoVideo.js
import React, { useState, useEffect, useRef } from 'react';
import styled from '@emotion/styled';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

// Container for the video with retro styling
const VideoContainer = styled.div`
  position: relative;
  width: 100%;
  max-width: 800px;
  margin: 2rem auto;
  border: 2px solid ${THEME.colors.borderPrimary};
  background-color: ${THEME.colors.bgSecondary};
  
  // Pixelated corners
  &::after {
    content: "";
    position: absolute;
    top: -2px;
    left: -2px;
    right: -2px;
    bottom: -2px;
    z-index: -1;
    border: 2px solid ${THEME.colors.bgSecondary};
    clip-path: polygon(
      0% 8px, 8px 8px, 8px 0%, calc(100% - 8px) 0%, calc(100% - 8px) 8px, 100% 8px, 
      100% calc(100% - 8px), calc(100% - 8px) calc(100% - 8px), calc(100% - 8px) 100%, 
      8px 100%, 8px calc(100% - 8px), 0% calc(100% - 8px)
    );
  }
`;

// Video header with title
const VideoHeader = styled.div`
  background-color: ${THEME.colors.bgTertiary};
  padding: 0.75rem 1rem;
  display: flex;
  align-items: center;
  border-bottom: 1px solid ${THEME.colors.borderPrimary};
  
  .title {
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 1rem;
    color: ${THEME.colors.textSecondary};
    flex-grow: 1;
  }
  
  .buttons {
    display: flex;
    gap: 8px;
  }
  
  .button {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    
    &.red {
      background-color: ${THEME.colors.errorRed};
    }
    
    &.yellow {
      background-color: ${THEME.colors.terminalYellow};
    }
    
    &.green {
      background-color: ${THEME.colors.terminalGreen};
    }
  }
`;

// Video aspect ratio container
const VideoAspectRatio = styled.div`
  position: relative;
  padding-bottom: 56.25%; // 16:9 aspect ratio
`;

// The iframe or placeholder for YouTube
const VideoFrame = styled.iframe`
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  border: none;
  background-color: ${THEME.colors.bgPrimary};
`;

// Placeholder when video isn't loaded
const VideoPlaceholder = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background-color: ${THEME.colors.bgPrimary};
  cursor: pointer;
  
  .play-button {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    background-color: ${THEME.colors.accentPrimary}80;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 1rem;
    transition: all 0.3s ease;
    
    &::before {
      content: "";
      width: 0;
      height: 0;
      border-style: solid;
      border-width: 15px 0 15px 25px;
      border-color: transparent transparent transparent ${THEME.colors.textPrimary};
      margin-left: 5px;
    }
    
    &:hover {
      transform: scale(1.1);
      background-color: ${THEME.colors.accentPrimary};
    }
  }
  
  .text {
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 1rem;
    color: ${THEME.colors.textSecondary};
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    .play-button {
      width: 60px;
      height: 60px;
      
      &::before {
        border-width: 10px 0 10px 20px;
      }
    }
    
    .text {
      font-size: 0.9rem;
    }
  }
`;

// Glitch scanlines effect overlay
const ScanlineOverlay = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  background: linear-gradient(
    to bottom,
    transparent 50%,
    rgba(32, 32, 32, 0.05) 50%
  );
  background-size: 100% 4px;
  z-index: 1;
  opacity: 0.3;
`;

/**
 * DemoVideo Component
 * 
 * Displays a YouTube video with retro terminal styling.
 * Shows a placeholder with play button until clicked.
 * 
 * @param {string} videoId - YouTube video ID
 * @param {string} title - Title to display in the header
 */
const DemoVideo = ({ videoId = 'dQw4w9WgXcQ', title = 'Angela CLI Demo' }) => {
  const [showVideo, setShowVideo] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const videoRef = useRef(null);
  
  // Handle click on placeholder to show video
  const handleShowVideo = () => {
    setIsLoading(true);
    setShowVideo(true);
  };
  
  // Handle video loaded
  const handleVideoLoaded = () => {
    setIsLoading(false);
  };
  
  return (
    <VideoContainer>
      <VideoHeader>
        <div className="buttons">
          <div className="button red"></div>
          <div className="button yellow"></div>
          <div className="button green"></div>
        </div>
        <div className="title">{title}</div>
      </VideoHeader>
      
      <VideoAspectRatio>
        {showVideo ? (
          <>
            <VideoFrame
              ref={videoRef}
              src={`https://www.youtube.com/embed/${videoId}?autoplay=1&rel=0`}
              title="Angela CLI Demo"
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
              allowFullScreen
              onLoad={handleVideoLoaded}
            />
            {isLoading && <ScanlineOverlay />}
          </>
        ) : (
          <VideoPlaceholder onClick={handleShowVideo}>
            <div className="play-button"></div>
            <div className="text">Click to watch demo</div>
            <ScanlineOverlay />
          </VideoPlaceholder>
        )}
      </VideoAspectRatio>
    </VideoContainer>
  );
};

export default DemoVideo;
