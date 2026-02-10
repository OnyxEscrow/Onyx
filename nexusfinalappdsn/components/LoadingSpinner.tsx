import React from 'react';
import { Loader2 } from 'lucide-react';

interface LoadingSpinnerProps {
  message?: string;
}

const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ message = 'Loading...' }) => {
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-[#F3F2EE]">
      <div className="flex flex-col items-center gap-4">
        <Loader2 size={48} className="animate-spin text-black/60" />
        <p className="text-sm font-mono text-black/40 uppercase tracking-widest">{message}</p>
      </div>
    </div>
  );
};

export default LoadingSpinner;
