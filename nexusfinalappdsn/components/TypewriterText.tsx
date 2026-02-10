import React, { useState, useEffect } from 'react';

interface TypewriterTextProps {
  text: string;
  speed?: number;
}

const TypewriterText: React.FC<TypewriterTextProps> = ({ text, speed = 20 }) => {
  const [displayedText, setDisplayedText] = useState('');

  // Reset when text changes
  useEffect(() => {
    setDisplayedText('');
  }, [text]);

  // Animate character by character using derived index from state length
  useEffect(() => {
    if (displayedText.length >= text.length) return;

    const timer = setTimeout(() => {
      setDisplayedText((prev) => prev + text.charAt(prev.length));
    }, speed);

    return () => clearTimeout(timer);
  }, [text, speed, displayedText.length]);

  return <span>{displayedText}</span>;
};

export default TypewriterText;