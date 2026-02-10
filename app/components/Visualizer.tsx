import React from 'react';
import { EscrowStep, Role } from '../types';
import { Lock, Unlock, ShieldCheck, Key, Package, Scale, User, Store } from 'lucide-react';
import ScrambleText from './ScrambleText';
import { getPhaseLabel } from '../utils/phaseLabels';

interface VisualizerProps {
  step: EscrowStep;
  role: Role | null;
  dkgPhase?: string;
}

const Visualizer: React.FC<VisualizerProps> = ({ step, role, dkgPhase }) => {
  const isDKG = step === EscrowStep.DKG_RUNNING || step === EscrowStep.DKG_WAITING;
  const isFunded = [EscrowStep.ACTIVE, EscrowStep.DELIVERED, EscrowStep.RELEASE_SIGNING, EscrowStep.COMPLETED, EscrowStep.DISPUTE, EscrowStep.DISPUTE_RESOLVED].includes(step);
  const isCompleted = step === EscrowStep.COMPLETED;
  
  // Protocol Colors
  const colors = {
    buyer: '#3B82F6',   // Blue
    seller: '#10B981',  // Green
    arbiter: '#8B5CF6', // Purple
    locked: '#F59E0B',  // Orange
    void: '#E5E5E5'
  };

  if (step === EscrowStep.IDLE || step === EscrowStep.INITIATING) {
    return (
      <div className="w-full h-full flex flex-col items-center justify-center animate-in fade-in duration-1000">
        <div className="relative w-48 h-48 sm:w-64 sm:h-64 flex items-center justify-center group">
           {/* Static Base Border */}
           <div className="absolute inset-0 border border-black/5 rounded-full"></div>

           {/* Hover Border Beam Effect */}
           <svg className="absolute inset-0 w-full h-full opacity-0 group-hover:opacity-100 transition-opacity duration-700 pointer-events-none" viewBox="0 0 256 256">
             <defs>
               <linearGradient id="beam-grad" x1="0%" y1="0%" x2="100%" y2="0%">
                 <stop offset="0%" stopColor="transparent" />
                 <stop offset="20%" stopColor="transparent" />
                 <stop offset="100%" stopColor="black" stopOpacity="0.8" />
               </linearGradient>
             </defs>
             <circle 
               cx="128" 
               cy="128" 
               r="127.5" 
               fill="none" 
               stroke="url(#beam-grad)" 
               strokeWidth="1" 
               strokeLinecap="round"
               className="animate-[spin_3s_linear_infinite] origin-center"
             />
           </svg>

           {/* Inner Subtle Spinner */}
           <div className="absolute inset-0 border-t border-black/20 rounded-full animate-spin-slow"></div>
           
           <div className="text-center relative z-10">
             <div className="font-display font-bold text-4xl sm:text-6xl tracking-tighter opacity-10 transition-opacity duration-500 group-hover:opacity-20 cursor-default">
               <ScrambleText text="NXS" />
             </div>
             <div className="text-[10px] font-mono uppercase tracking-widest mt-2 text-black/40">
               <ScrambleText text="Protocol Idle" />
             </div>
           </div>
        </div>
      </div>
    );
  }

  if (isDKG) {
    return (
      <div className="relative w-full h-full flex items-center justify-center">
         {/* Background Connecting Lines */}
         <svg viewBox="0 0 200 200" className="absolute inset-0 w-full h-full animate-in fade-in duration-700 pointer-events-none">
            <line x1="100" y1="40" x2="40" y2="160" stroke="black" strokeWidth="0.5" strokeDasharray="4 2" className="animate-pulse" />
            <line x1="100" y1="40" x2="160" y2="160" stroke="black" strokeWidth="0.5" strokeDasharray="4 2" className="animate-pulse" />
            <line x1="40" y1="160" x2="160" y2="160" stroke="black" strokeWidth="0.5" strokeDasharray="4 2" className="animate-pulse" />
            
            {/* Central Circle Ring */}
            <circle cx="100" cy="110" r="25" fill="none" stroke="black" strokeWidth="0.5" className="animate-[spin_10s_linear_infinite]" />
         </svg>

         {/* Central DKG Label */}
         <div className="absolute top-[55%] left-1/2 -translate-x-1/2 -translate-y-1/2 bg-white px-2 py-1 z-10">
            <span className="font-mono font-bold text-[10px]">DKG</span>
         </div>

         {/* Node: Arbiter (Top) */}
         <div className="absolute top-[15%] sm:top-[20%] left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center gap-1 sm:gap-2">
            <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-full bg-white border border-black flex items-center justify-center shadow-sm z-20">
               <Scale size={12} className="text-black sm:hidden" />
               <Scale size={14} className="text-black hidden sm:block" />
            </div>
            <span className="font-mono text-[7px] sm:text-[8px] uppercase tracking-widest bg-white/80 px-1 backdrop-blur-sm">Arbiter</span>
         </div>

         {/* Node: Buyer (Left) */}
         <div className="absolute top-[80%] left-[15%] sm:left-[20%] -translate-x-1/2 -translate-y-1/2 flex flex-col items-center gap-1 sm:gap-2">
            <div className={`w-7 h-7 sm:w-8 sm:h-8 rounded-full border flex items-center justify-center shadow-sm z-20 transition-colors duration-300 ${role === Role.BUYER ? 'bg-black border-black text-white' : 'bg-white border-black text-black'}`}>
               <User size={12} className="sm:hidden" />
               <User size={14} className="hidden sm:block" />
            </div>
            <span className="font-mono text-[7px] sm:text-[8px] uppercase tracking-widest bg-white/80 px-1 backdrop-blur-sm">Buyer</span>
         </div>

         {/* Node: Vendor (Right) */}
         <div className="absolute top-[80%] left-[85%] sm:left-[80%] -translate-x-1/2 -translate-y-1/2 flex flex-col items-center gap-1 sm:gap-2">
            <div className={`w-7 h-7 sm:w-8 sm:h-8 rounded-full border flex items-center justify-center shadow-sm z-20 transition-colors duration-300 ${role === Role.VENDOR ? 'bg-black border-black text-white' : 'bg-white border-black text-black'}`}>
               <Store size={12} className="sm:hidden" />
               <Store size={14} className="hidden sm:block" />
            </div>
            <span className="font-mono text-[7px] sm:text-[8px] uppercase tracking-widest bg-white/80 px-1 backdrop-blur-sm">Vendor</span>
         </div>

         <div className="absolute bottom-4 text-center">
            <span className="text-[10px] font-mono uppercase tracking-widest bg-black text-white px-2 py-1 rounded group relative cursor-help">
               {getPhaseLabel(dkgPhase).long}
               {getPhaseLabel(dkgPhase).tooltip && (
                 <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 bg-black text-white text-[9px] font-mono rounded-lg opacity-0 group-hover:opacity-100 transition-opacity whitespace-normal max-w-[250px] text-center pointer-events-none shadow-xl z-30">
                   {getPhaseLabel(dkgPhase).tooltip}
                 </span>
               )}
            </span>
         </div>
      </div>
    );
  }

  return (
    <div className="relative w-full h-full flex items-center justify-center">
      
      {/* Central Lock State */}
      <div className={`relative z-10 transition-all duration-1000 ${isCompleted ? 'scale-110' : 'scale-100'}`}>
         {isCompleted ? (
            <div className="flex flex-col items-center">
               <div className="relative">
                  {/* Expanding ripple rings */}
                  {[0, 1, 2].map(i => (
                    <div key={i}
                      className="absolute inset-0 rounded-full border border-black/10"
                      style={{ animation: `ripple 2s ease-out ${i * 0.4}s infinite` }}
                    />
                  ))}
                  <div className="w-24 h-24 rounded-full bg-black text-white flex items-center justify-center shadow-2xl mb-4 relative z-10"
                    style={{ animation: 'scale-bounce 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) both' }}>
                     <Unlock size={40} strokeWidth={1.5} />
                  </div>
               </div>
               <div className="font-display font-bold text-2xl tracking-tight mt-2">
                  <ScrambleText text="SETTLED" />
               </div>
               <div className="px-4 py-2 bg-black/5 rounded-full text-[10px] font-mono uppercase tracking-widest mt-2">
                  Funds Released
               </div>
            </div>
         ) : step === EscrowStep.DISPUTE ? (
             <div className="flex flex-col items-center animate-pulse">
               <div className="w-24 h-24 rounded-full bg-red-500 text-white flex items-center justify-center shadow-2xl mb-4">
                  <ShieldCheck size={40} strokeWidth={1.5} />
               </div>
               <div className="px-4 py-2 bg-red-100 text-red-600 rounded-full text-[10px] font-mono uppercase tracking-widest font-bold">
                  Arbiter Intervention
               </div>
            </div>
         ) : step === EscrowStep.DISPUTE_RESOLVED ? (
             <div className="flex flex-col items-center">
               <div className="w-24 h-24 rounded-full bg-green-500 text-white flex items-center justify-center shadow-2xl mb-4 animate-pulse">
                  <Unlock size={40} strokeWidth={1.5} />
               </div>
               <div className="px-4 py-2 bg-green-100 text-green-600 rounded-full text-[10px] font-mono uppercase tracking-widest font-bold">
                  Claiming Funds
               </div>
            </div>
         ) : (
            <div className="flex flex-col items-center">
               <div className="relative">
                  {/* Outer Progress Ring */}
                  <svg className="w-32 h-32 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 -rotate-90">
                     <circle cx="64" cy="64" r="60" fill="none" stroke="#E5E5E5" strokeWidth="4" />
                     {isFunded && (
                        <circle cx="64" cy="64" r="60" fill="none" stroke="black" strokeWidth="4" 
                           strokeDasharray="377" 
                           strokeDashoffset={step === EscrowStep.RELEASE_SIGNING ? "188" : step === EscrowStep.DELIVERED ? "94" : "0"} 
                           className="transition-all duration-1000 ease-out" 
                        />
                     )}
                  </svg>
                  
                  <div className={`w-24 h-24 rounded-full border flex items-center justify-center shadow-xl transition-colors duration-500 ${step === EscrowStep.DELIVERED ? 'bg-black text-white border-black' : 'bg-white text-black border-black/10'}`}>
                     {step === EscrowStep.DELIVERED ? (
                       <Package size={32} strokeWidth={1.5} />
                     ) : (
                       <Lock size={32} className={isFunded ? "" : "text-gray-300"} />
                     )}
                  </div>
               </div>
               
               <div className="mt-8 flex gap-2">
                  {/* Key Shard Indicators */}
                  <div className={`w-8 h-10 border rounded flex items-center justify-center transition-colors ${role === Role.BUYER && step === EscrowStep.RELEASE_SIGNING ? 'bg-black text-white border-black' : 'bg-white border-black/20 text-black/20'}`}>
                     <Key size={12} className={role === Role.BUYER && step === EscrowStep.RELEASE_SIGNING ? "-rotate-45" : ""} />
                  </div>
                  <div className={`w-8 h-10 border rounded flex items-center justify-center transition-colors ${role === Role.VENDOR && step === EscrowStep.RELEASE_SIGNING ? 'bg-black text-white border-black' : 'bg-white border-black/20 text-black/20'}`}>
                     <Key size={12} />
                  </div>
                  <div className={`w-8 h-10 border rounded flex items-center justify-center transition-colors ${step === EscrowStep.DISPUTE ? 'bg-red-500 text-white border-red-500' : 'bg-white border-black/20 text-black/20'}`}>
                     <span className="text-[10px] font-bold">3</span>
                  </div>
               </div>
               
               <div className="mt-4 text-[10px] font-mono text-black/40 uppercase tracking-wider">
                  Threshold: 2-of-3
               </div>
            </div>
         )}
      </div>

    </div>
  );
};

export default Visualizer;