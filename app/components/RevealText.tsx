import React from 'react';

interface RevealTextProps {
  text: string;
  className?: string;
  delay?: number; // Base delay in seconds
  stagger?: number; // Stagger per letter in seconds
}

const RevealText: React.FC<RevealTextProps> = ({ 
  text, 
  className = "", 
  delay = 0,
  stagger = 0.05 
}) => {
  return (
    <span className={`inline-flex ${className}`}>
      {text.split('').map((char, i) => (
        <span 
          key={i} 
          className="inline-block overflow-hidden pb-1 -mb-1" /* Padding bottom ensures descenders don't get clipped weirdly if font is tight */
          style={{ verticalAlign: 'bottom' }}
        >
          <span 
            className="inline-block animate-text-slide-down"
            style={{ 
              animationDelay: `${delay + (i * stagger)}s`,
              willChange: 'transform'
            }}
          >
            {char === ' ' ? '\u00A0' : char}
          </span>
        </span>
      ))}
    </span>
  );
};

export default RevealText;