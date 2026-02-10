import React from 'react';
import { Loader2, ArrowUpRight } from 'lucide-react';

interface ActionButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  isLoading?: boolean;
}

const ActionButton: React.FC<ActionButtonProps> = ({ 
  children, 
  variant = 'primary', 
  isLoading, 
  className = '', 
  disabled,
  ...props 
}) => {
  // Base: Minimalist, Bold, Geometric
  const baseStyles = "relative group font-display font-bold text-sm tracking-wide transition-all duration-500 flex items-center justify-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed overflow-hidden";
  
  const variants = {
    // Primary: Custom structure handles background to allow for border beam
    primary: "text-white rounded-full px-8 py-4 hover:scale-105 hover:shadow-xl hover:shadow-black/10",
    // Secondary: Minimal outline
    secondary: "bg-transparent border border-black/10 text-black rounded-full px-6 py-3 hover:bg-white hover:border-black",
    // Danger: Red minimalist
    danger: "bg-red-50 text-red-600 border border-red-100 rounded-full px-6 py-3 hover:bg-red-100",
    ghost: "text-black underline decoration-black/30 underline-offset-4 hover:decoration-black"
  };

  return (
    <button 
      className={`${baseStyles} ${variants[variant]} ${className}`}
      disabled={isLoading || disabled}
      {...props}
    >
      {/* --- PRIMARY VARIANT SPECIAL LAYERS --- */}
      {variant === 'primary' && (
        <>
          {/* 1. Beam Animation Layer (Underlay) */}
          <span className="absolute inset-0 rounded-full overflow-hidden">
            <span className="absolute inset-[-100%] bg-[conic-gradient(from_0deg,transparent_0_340deg,white_360deg)] animate-[spin_3s_linear_infinite] opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          </span>

          {/* 2. Main Background (Inset 1px to reveal beam as border) */}
          <span className="absolute inset-[1px] rounded-full bg-black transition-colors duration-500 z-0" />
        </>
      )}

      {/* --- CONTENT LAYER --- */}
      <span className="relative z-10 flex items-center gap-3">
        {isLoading && <Loader2 className="animate-spin" size={16} />}
        {!isLoading && children}
        {variant === 'primary' && !isLoading && (
           <div className="bg-white text-black rounded-full p-1 transition-transform duration-300 group-hover:-translate-y-1 group-hover:translate-x-1">
              <ArrowUpRight size={14} strokeWidth={3} />
           </div>
        )}
      </span>
    </button>
  );
};

export default ActionButton;