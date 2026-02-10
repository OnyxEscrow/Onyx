import React, { useState, useEffect } from 'react';
import { Role } from '../types';
import { LayoutDashboard, Activity } from 'lucide-react';

interface TrustMonitorProps {
  role?: Role | null;
  onDashboardClick?: () => void;
  showLobby?: boolean;
}

const TrustMonitor: React.FC<TrustMonitorProps> = ({ role, onDashboardClick, showLobby }) => {
  const [ping, setPing] = useState(32);

  useEffect(() => {
    const interval = setInterval(() => {
      setPing(Math.floor(Math.random() * (45 - 20 + 1) + 20));
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="hidden md:flex fixed top-8 right-8 z-50 items-center gap-4 bg-white/80 backdrop-blur-md px-6 py-3 rounded-full border border-black/5 shadow-sm text-[10px] font-sans font-bold uppercase tracking-widest text-black">
      {role && (
        <>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-art-accent animate-pulse"></span>
            <span>{role}</span>
          </div>
          <span className="text-black/20">|</span>
        </>
      )}
      <div className="flex items-center gap-2">
        <span className={`w-1.5 h-1.5 rounded-full ${role ? 'bg-black' : 'bg-gray-300'}`}></span>
        <span>WASM Ready</span>
      </div>
      <span className="text-black/20">|</span>
      <div className="flex items-center gap-3">
        <span>Nodes: 3/3</span>
        <div className="flex items-center gap-1 text-black/40 font-mono">
           <Activity size={10} />
           <span>{ping}ms</span>
        </div>
      </div>
      {onDashboardClick && (
        <>
          <span className="text-black/20">|</span>
          <button
            onClick={onDashboardClick}
            className={`flex items-center gap-2 px-4 py-1.5 rounded-full transition-all duration-300 font-bold tracking-wider ${showLobby ? 'bg-black text-white shadow-lg scale-105' : 'bg-black text-white hover:bg-black/80 hover:shadow-md hover:scale-105'}`}
            title="Escrow Dashboard"
          >
            <LayoutDashboard size={14} />
            <span>Lobby</span>
          </button>
        </>
      )}
    </div>
  );
};

export default TrustMonitor;