import React, { useState } from 'react';
import { Role } from '../types';
import { Shield, Coins, Fingerprint, AlertCircle, UserPlus, Terminal, ArrowRight, Activity } from 'lucide-react';
import ActionButton from './ActionButton';
import { useAuth } from '../hooks/useAuth';
import ScrambleText from './ScrambleText';

interface AuthModalProps {
  onAuthenticated?: () => void;
}

const AuthModal: React.FC<AuthModalProps> = ({ onAuthenticated }) => {
  const { login, register, error, isLoading, clearError } = useAuth();
  const [step, setStep] = useState<'LOGIN' | 'REGISTER' | 'ROLE'>('LOGIN');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) return;
    setLocalError(null);
    clearError();
    try {
      await login(username, password);
      onAuthenticated?.();
    } catch { }
  };

  const handleRegister = async (role: Role) => {
    if (!username || !password) return;
    if (password !== confirmPassword) {
      setLocalError('PASSWORDS_MISMATCH');
      return;
    }
    if (password.length < 8) {
      setLocalError('PASSWORD_TOO_SHORT_MIN_8');
      return;
    }
    setLocalError(null);
    clearError();
    try {
      await register(username, password, role.toLowerCase());
      onAuthenticated?.();
    } catch { }
  };

  const displayError = localError || error;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      {/* Technical Backdrop */}
      <div className="absolute inset-0 bg-white/80 backdrop-blur-xl">
         <div className="absolute inset-0 opacity-10 bg-[url('https://grainy-gradients.vercel.app/noise.svg')]"></div>
      </div>

      {/* Main Card */}
      <div className="relative bg-white w-full max-w-lg shadow-[0_0_0_1px_rgba(0,0,0,0.1),0_20px_40px_-10px_rgba(0,0,0,0.1)] overflow-hidden animate-in fade-in zoom-in-95 duration-500">
        
        {/* Header Bar */}
        <div className="flex items-center justify-between px-8 py-4 border-b border-black/5 bg-black/[0.02]">
           <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-black animate-pulse"></div>
              <span className="font-mono text-[10px] uppercase tracking-widest text-black/50">Secure Enclave v3.0</span>
           </div>
           <Terminal size={12} className="text-black/30" />
        </div>

        <div className="p-8 md:p-12">

          {/* Title Section */}
          <div className="mb-8 group/title cursor-default">
            <h2 className="font-display font-bold text-xl md:text-2xl text-black tracking-[0.15em] uppercase mb-1 leading-none transition-colors group-hover/title:text-black/70">
              <ScrambleText 
                text={step === 'LOGIN' ? 'Authenticate' : step === 'REGISTER' ? 'New_Identity' : 'Select_Role'} 
              />
            </h2>
            <div className="flex flex-col gap-1">
               <p className="font-mono text-[9px] text-black/30 uppercase tracking-[0.2em]">
                 {step === 'LOGIN' ? '// ENTER CREDENTIALS TO ACCESS' : '// ESTABLISH NEW PROTOCOL LINK'}
               </p>
               <p className="font-mono text-[9px] text-black/60 uppercase tracking-widest mt-2 animate-pulse">
                 &gt; INITIALIZING SECURE ENCLAVE... LOCAL STORAGE DETECTED.
               </p>
            </div>
          </div>

          {/* Error Banner */}
          {displayError && (
            <div className="mb-8 p-3 bg-red-50 border-l-2 border-red-500 flex items-center gap-3 animate-in slide-in-from-top-2">
              <AlertCircle size={14} className="text-red-600" />
              <span className="text-xs font-mono text-red-600 uppercase tracking-wide">{displayError}</span>
            </div>
          )}

          {step === 'LOGIN' ? (
            <form onSubmit={handleLogin} className="space-y-8">
              <div className="space-y-6">
                <InputGroup 
                   label="Session Alias" 
                   value={username} 
                   onChange={setUsername} 
                   placeholder="USER.ID" 
                   help="Local identifier. Not shared with server."
                />
                <InputGroup 
                   label="Access Key" 
                   value={password} 
                   onChange={setPassword} 
                   type="password" 
                   placeholder="••••••••" 
                   help="Encrypts your keys in this browser."
                />
              </div>

              <div className="pt-4 space-y-3">
                <button
                  type="submit"
                  disabled={!username || !password || isLoading}
                  className="group w-full bg-black text-white h-12 flex items-center justify-center gap-3 font-mono text-xs font-bold uppercase tracking-widest hover:bg-black/90 transition-all disabled:opacity-50"
                >
                  {isLoading ? <Activity className="animate-spin" size={14} /> : <span>Initialize Session</span>}
                  {!isLoading && <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />}
                </button>

                <button
                  type="button"
                  onClick={() => { setStep('REGISTER'); clearError(); setLocalError(null); }}
                  className="w-full h-10 flex items-center justify-center font-mono text-[10px] text-black/40 uppercase tracking-widest hover:text-black hover:bg-black/5 transition-colors"
                >
                  [ Create New Identity ]
                </button>
              </div>
            </form>
          ) : step === 'REGISTER' ? (
            <form onSubmit={(e) => { e.preventDefault(); setStep('ROLE'); }} className="space-y-8 animate-in fade-in slide-in-from-right-4">
              <div className="space-y-6">
                <InputGroup 
                   label="New Session Alias" 
                   value={username} 
                   onChange={setUsername} 
                   placeholder="DESIRED.ALIAS" 
                   help="Public name visible to counter-parties."
                />
                <InputGroup 
                   label="Set Access Key" 
                   value={password} 
                   onChange={setPassword} 
                   type="password" 
                   placeholder="MIN 8 CHARS" 
                   help="Used to encrypt your local keychain."
                />
                <InputGroup 
                   label="Confirm Key" 
                   value={confirmPassword} 
                   onChange={setConfirmPassword} 
                   type="password" 
                   placeholder="REPEAT KEY" 
                />
              </div>

              <div className="pt-4 space-y-3">
                <button
                  type="submit"
                  disabled={!username || !password || !confirmPassword}
                  className="group w-full bg-black text-white h-12 flex items-center justify-center gap-3 font-mono text-xs font-bold uppercase tracking-widest hover:bg-black/90 transition-all disabled:opacity-50"
                >
                  <span>Proceed to Assignment</span>
                  <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
                </button>

                <button
                  type="button"
                  onClick={() => { setStep('LOGIN'); clearError(); setLocalError(null); }}
                  className="w-full h-10 flex items-center justify-center font-mono text-[10px] text-black/40 uppercase tracking-widest hover:text-black hover:bg-black/5 transition-colors"
                >
                  [ Return to Login ]
                </button>
              </div>
            </form>
          ) : (
            <div className="animate-in fade-in slide-in-from-right-4">
              <div className="mb-8 p-4 bg-black/5 border border-black/10">
                 <p className="font-mono text-[10px] text-black/50 uppercase tracking-wide mb-1">Identity Created</p>
                 <p className="font-mono text-xl font-bold">{username}</p>
              </div>

              <div className="grid grid-cols-2 gap-4 mb-6">
                <RoleCard 
                   role="BUYER" 
                   icon={Coins} 
                   desc="Initiates Contracts" 
                   onClick={() => handleRegister(Role.BUYER)} 
                   loading={isLoading}
                />
                <RoleCard 
                   role="VENDOR" 
                   icon={Shield} 
                   desc="Fulfills Orders" 
                   onClick={() => handleRegister(Role.VENDOR)} 
                   loading={isLoading}
                />
              </div>

              <button
                type="button"
                onClick={() => { setStep('REGISTER'); clearError(); setLocalError(null); }}
                className="w-full h-10 flex items-center justify-center font-mono text-[10px] text-black/40 uppercase tracking-widest hover:text-black hover:bg-black/5 transition-colors"
              >
                [ Back to Config ]
              </button>
            </div>
          )}
        </div>
        
        {/* Decorative Footer */}
        <div className="h-1 w-full bg-black/5 flex">
           <div className="w-1/3 bg-black"></div>
           <div className="w-1/3 bg-transparent"></div>
           <div className="w-1/3 bg-black/20"></div>
        </div>
      </div>
    </div>
  );
};

const InputGroup = ({ label, value, onChange, type = "text", placeholder, help }: any) => (
  <div className="group relative">
    <div className="flex items-center justify-between mb-2">
       <label className="block text-[9px] font-mono font-bold uppercase tracking-widest text-black/40 group-focus-within:text-black transition-colors">
         {label}
       </label>
       {help && (
         <div className="relative group/help cursor-help">
            <span className="text-[9px] font-mono text-black/20 border border-black/10 px-1 rounded hover:bg-black hover:text-white transition-colors">?</span>
            <div className="absolute right-0 bottom-full mb-2 w-48 bg-black text-white text-[9px] font-mono p-2 rounded opacity-0 group-hover/help:opacity-100 transition-opacity pointer-events-none z-10">
               {help}
               <div className="absolute bottom-[-4px] right-2 w-2 h-2 bg-black rotate-45"></div>
            </div>
         </div>
       )}
    </div>
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full bg-black/[0.02] border-b border-black/10 py-3 px-3 font-mono text-sm focus:outline-none focus:border-black focus:bg-black/[0.05] transition-all placeholder:text-black/20 uppercase caret-black"
      placeholder={placeholder}
      autoComplete="off"
    />
  </div>
);

const RoleCard = ({ role, icon: Icon, desc, onClick, loading }: any) => (
   <button
      onClick={onClick}
      disabled={loading}
      className="group relative flex flex-col items-start p-5 border border-black/10 hover:border-black hover:bg-black hover:text-white transition-all duration-300 text-left disabled:opacity-50"
   >
      <Icon size={20} strokeWidth={1} className="mb-4 text-black group-hover:text-white transition-colors" />
      <span className="font-display font-bold text-lg tracking-tight mb-1">{role}</span>
      <span className="font-mono text-[9px] uppercase tracking-widest opacity-50">{desc}</span>
      
      {/* Corner Accent */}
      <div className="absolute top-0 right-0 w-0 h-0 border-t-[8px] border-r-[8px] border-t-transparent border-r-black opacity-0 group-hover:opacity-100 group-hover:border-r-white transition-opacity"></div>
   </button>
);

export default AuthModal;