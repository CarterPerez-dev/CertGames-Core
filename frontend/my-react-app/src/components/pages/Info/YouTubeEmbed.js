// src/components/pages/Info/YouTubeEmbed.js

import React from 'react';

const YouTubeEmbed = ({ videoId, title }) => {
  if (!videoId) return null;

  // Using the most reliable responsive embed approach with inline styles
  // This avoids any potential CSS conflicts
  return (
    <div style={{
      position: 'relative',
      paddingBottom: '56.25%', /* 16:9 aspect ratio */
      height: 0,
      overflow: 'hidden',
      width: '100%',
      backgroundColor: '#000'
    }}>
      <iframe
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          border: 'none'
        }}
        src={`https://www.youtube.com/embed/${videoId}?rel=0&modestbranding=1`}
        title={title || "YouTube video player"}
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
        allowFullScreen
      ></iframe>
    </div>
  );
};

export default YouTubeEmbed;
