import React from 'react';
import { CyberThreatGlobe } from './CyberThreatGlobe';

export const ThreatHeroGlobe: React.FC = () => {
  return (
    <div className="relative w-full py-1 flex items-center justify-center overflow-hidden">
      {/* Ambient Cyber Light Flare */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[280px] sm:w-[440px] h-[280px] sm:h-[440px] bg-[#f95721]/10 rounded-full blur-3xl pointer-events-none" />

      {/* Seamless 3D Sphere Viewport with no enclosing box, card border, or background */}
      <div className="relative w-full h-[280px] sm:h-[380px] md:h-[480px] flex items-center justify-center">
        <CyberThreatGlobe
          height="100%"
          className="w-full h-full"
          threatPointsCount={64}
          interactive={true}
          mode="advanced"
          showControls={false}
          sizeMultiplier={1.2}
          speedMultiplier={0.9}
        />
      </div>
    </div>
  );
};
