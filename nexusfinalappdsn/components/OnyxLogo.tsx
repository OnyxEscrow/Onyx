import React from 'react';

const OnyxLogo: React.FC = () => {
  const letters = ['O', 'N', 'Y', 'X'];

  return (
    <div className="flex select-none">
      <style>{`
        @keyframes onyx-shine {
          0%, 100% { color: #000000; }
          50% { color: #4B5563; } /* Gray-600 (Anthracite-ish) */
        }
      `}</style>
      {letters.map((char, i) => (
        <span
          key={i}
          className="inline-block"
          style={{
            animation: 'onyx-shine 3s ease-in-out infinite',
            animationDelay: `${i * 0.3}s` // Staggered delay
          }}
        >
          {char}
        </span>
      ))}
    </div>
  );
};

export default OnyxLogo;