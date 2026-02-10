/**
 * WalletWizard Component
 *
 * Step-by-step UI for FROST DKG (Distributed Key Generation).
 * Guides users through the 3-round threshold key generation process.
 */

import React, { useState, useCallback, useEffect } from 'react';
import { Shield, Check, Loader2, AlertTriangle, Lock, Key, Users, Zap, Terminal } from 'lucide-react';
import { useFrostDkg, DkgPhase } from '../../hooks/useFrostDkg';
import { LogEntry } from '../../types';
import DKGProgress from './DKGProgress';

interface WalletWizardProps {
  escrowId: string;
  role: string;
  onComplete: () => void;
  onError: (error: string) => void;
  onLog?: (log: LogEntry) => void;
}

const WalletWizard: React.FC<WalletWizardProps> = ({
  escrowId,
  role,
  onComplete,
  onError,
  onLog,
}) => {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [step, setStep] = useState<'password' | 'generating' | 'complete'>('password');

  // Log handler
  const handleLog = useCallback(
    (log: LogEntry) => {
      if (onLog) {
        onLog(log);
      }
    },
    [onLog]
  );

  // FROST DKG hook
  const { state: dkgState, startDkg, retryFromPhase, reset } = useFrostDkg(handleLog);

  // Watch DKG state
  useEffect(() => {
    if (dkgState.phase === 'complete') {
      setStep('complete');
      onComplete();
    } else if (dkgState.phase === 'error') {
      onError(dkgState.error || 'Unknown error');
    }
  }, [dkgState.phase, dkgState.error, onComplete, onError]);

  // Validate password
  const validatePassword = useCallback((): boolean => {
    if (password.length < 8) {
      setPasswordError('KEY_LENGTH_ERROR_MIN_8');
      return false;
    }
    if (password !== confirmPassword) {
      setPasswordError('KEY_MISMATCH_ERROR');
      return false;
    }
    setPasswordError(null);
    return true;
  }, [password, confirmPassword]);

  // Start DKG
  const handleStartDKG = useCallback(async () => {
    if (!validatePassword()) return;

    setStep('generating');
    await startDkg(escrowId, role, password);
  }, [validatePassword, startDkg, escrowId, role, password]);

  // Retry
  const handleRetry = useCallback(async () => {
    setPasswordError(null);
    await retryFromPhase();
  }, [retryFromPhase]);

  // Get phase display info
  const getPhaseInfo = (phase: DkgPhase) => {
    const phases: Record<DkgPhase, { label: string; subtitle: string; icon: React.ReactNode }> = {
      idle: { label: 'SYSTEM_READY', subtitle: 'Ready to initialize secure circuit', icon: <Shield className="w-4 h-4" /> },
      initializing: { label: 'INIT_PROTOCOL', subtitle: 'Establishing secure channel...', icon: <Loader2 className="w-4 h-4 animate-spin" /> },
      round1_generating: { label: 'GEN_SHARD_1', subtitle: 'Generating your secret key part...', icon: <Key className="w-4 h-4" /> },
      round1_submitting: { label: 'BROADCAST_1', subtitle: 'Commitment hash broadcast...', icon: <Loader2 className="w-4 h-4 animate-spin" /> },
      round1_waiting: { label: 'AWAIT_PEERS_1', subtitle: 'Waiting for counterparties...', icon: <Users className="w-4 h-4" /> },
      round2_generating: { label: 'GEN_SHARD_2', subtitle: 'Computing shared secret...', icon: <Key className="w-4 h-4" /> },
      round2_submitting: { label: 'BROADCAST_2', subtitle: 'Exchanging encrypted shares...', icon: <Loader2 className="w-4 h-4 animate-spin" /> },
      round2_waiting: { label: 'AWAIT_PEERS_2', subtitle: 'Syncing with network...', icon: <Users className="w-4 h-4" /> },
      round3_finalizing: { label: 'FINALIZE_KEY', subtitle: 'Verifying group signature...', icon: <Zap className="w-4 h-4" /> },
      storing_key: { label: 'ENCRYPT_STORE', subtitle: 'Encrypting local backup...', icon: <Lock className="w-4 h-4" /> },
      complete: { label: 'DKG_COMPLETE', subtitle: 'Secure circuit established', icon: <Check className="w-4 h-4" /> },
      error: { label: 'FATAL_ERROR', subtitle: 'Protocol deviation detected', icon: <AlertTriangle className="w-4 h-4" /> },
    };
    return phases[phase] || phases.idle;
  };

  const phaseInfo = getPhaseInfo(dkgState.phase);

  return (
    <div className="bg-black border border-white/10 rounded-xl overflow-hidden shadow-2xl max-w-md w-full relative group">
      {/* Decorative Corner */}
      <div className="absolute top-0 right-0 w-8 h-8 border-t border-r border-white/20 rounded-tr-xl"></div>
      
      {/* Header */}
      <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-white/5 rounded-md flex items-center justify-center border border-white/10">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-widest">Key Generation</h2>
            <p className="text-[10px] font-mono text-white/40">FROST-RFC9591 // 2-of-3</p>
          </div>
        </div>
        <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse shadow-[0_0_10px_rgba(34,197,94,0.5)]"></div>
      </div>

      {/* Content */}
      <div className="p-6">
        {step === 'password' && (
          <div className="space-y-6 animate-in fade-in slide-in-from-right-4">
            {/* Info */}
            <div className="p-4 bg-white/[0.03] border border-white/10 rounded-lg">
              <p className="text-xs font-mono text-white/60 leading-relaxed">
                <span className="text-white font-bold">WARNING:</span> This password encrypts your local key share. 
                If lost, funds cannot be recovered.
              </p>
            </div>

            {/* Password Input */}
            <div className="space-y-4">
              <div className="group">
                <label className="block text-[9px] font-mono font-bold uppercase tracking-widest text-white/40 mb-2">
                  Backup Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="SET_SECURE_PHRASE"
                  className="w-full bg-black border border-white/10 rounded-lg px-4 py-3 text-white font-mono text-sm focus:outline-none focus:border-white/40 transition-colors placeholder:text-white/20 uppercase"
                />
              </div>

              <div className="group">
                <label className="block text-[9px] font-mono font-bold uppercase tracking-widest text-white/40 mb-2">
                  Confirm Password
                </label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="CONFIRM_PHRASE"
                  className="w-full bg-black border border-white/10 rounded-lg px-4 py-3 text-white font-mono text-sm focus:outline-none focus:border-white/40 transition-colors placeholder:text-white/20 uppercase"
                />
              </div>

              {passwordError && (
                <div className="p-3 bg-red-500/10 border-l-2 border-red-500 text-red-400 font-mono text-[10px] flex items-center gap-2 uppercase tracking-wide">
                  <AlertTriangle className="w-3 h-3" />
                  {passwordError}
                </div>
              )}
            </div>

            {/* Start Button */}
            <button
              onClick={handleStartDKG}
              disabled={!password || !confirmPassword}
              className="w-full py-4 bg-white text-black font-bold font-mono text-xs uppercase tracking-widest rounded-lg hover:bg-white/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-3 group/btn"
            >
              <Key className="w-4 h-4" />
              <span>Initialize DKG Protocol</span>
              <Terminal className="w-3 h-3 opacity-0 group-hover/btn:opacity-100 transition-opacity" />
            </button>
          </div>
        )}

        {step === 'generating' && (
          <div className="space-y-8 animate-in fade-in">
            {/* Progress */}
            <DKGProgress
              phase={dkgState.phase}
              participants={dkgState.serverStatus?.participants}
            />

            {/* Current Status */}
            <div className="flex flex-col items-center justify-center gap-3 py-6 border border-dashed border-white/10 rounded-lg bg-white/[0.02]">
              <div className="w-10 h-10 bg-white/5 rounded-full flex items-center justify-center animate-pulse">
                 {phaseInfo.icon}
              </div>
              <div className="text-center">
                 <div className="font-mono text-xs text-white uppercase tracking-widest animate-pulse mb-1">{phaseInfo.label}</div>
                 <div className="text-[10px] font-mono text-white/40">{phaseInfo.subtitle}</div>
              </div>
            </div>

            {/* Error State */}
            {dkgState.phase === 'error' && (
              <div className="space-y-4 animate-in slide-in-from-bottom-2">
                <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 font-mono text-xs uppercase">
                  Error: {dkgState.error || 'PROTOCOL_FAILURE'}
                </div>
                <button
                  onClick={handleRetry}
                  className="w-full py-3 border border-white/20 text-white hover:bg-white hover:text-black rounded-lg transition-all font-mono text-xs uppercase tracking-widest"
                >
                  Retry Sequence
                </button>
              </div>
            )}

            {/* Waiting Info */}
            {(dkgState.phase === 'round1_waiting' || dkgState.phase === 'round2_waiting') && (
              <div className="flex items-center gap-3 p-4 bg-yellow-500/5 border-l-2 border-yellow-500/50">
                <Loader2 className="w-4 h-4 text-yellow-500 animate-spin shrink-0" />
                <p className="text-[10px] font-mono text-yellow-200 uppercase tracking-wide">
                  Waiting for peer synchronization...
                </p>
              </div>
            )}
          </div>
        )}

        {step === 'complete' && (
          <div className="space-y-8 text-center animate-in zoom-in-95">
            <div className="w-24 h-24 mx-auto bg-green-500/10 rounded-full flex items-center justify-center border border-green-500/20 relative">
              <div className="absolute inset-0 rounded-full animate-ping bg-green-500/5"></div>
              <Check className="w-10 h-10 text-green-500" />
            </div>

            <div>
              <h3 className="font-display font-bold text-2xl text-white mb-2 uppercase tracking-wide">Secure Link Est.</h3>
              <p className="font-mono text-xs text-white/40 uppercase">
                Threshold Key Generation Successful
              </p>
            </div>

            {dkgState.groupPublicKey && (
              <div className="p-4 bg-white/[0.03] border border-white/10 rounded-lg text-left">
                <p className="text-[9px] font-mono font-bold text-white/30 uppercase tracking-widest mb-2">Group Public Key</p>
                <p className="font-mono text-[10px] text-white break-all">
                  {dkgState.groupPublicKey.slice(0, 48)}...
                </p>
              </div>
            )}

            <button
              onClick={onComplete}
              className="w-full py-4 bg-white text-black font-bold font-mono text-xs uppercase tracking-widest rounded-lg hover:bg-white/90 transition-all flex items-center justify-center gap-2"
            >
              <span>Proceed to Funding</span>
              <Terminal className="w-3 h-3" />
            </button>
          </div>
        )}
      </div>

      {/* Footer Info */}
      <div className="px-6 pb-4 pt-2 border-t border-white/5 bg-black">
        <div className="flex items-center justify-between text-[10px] text-white/30 font-mono">
           <span className="uppercase">{role} NODE</span>
           <span>ID: {escrowId.slice(0, 8)}</span>
        </div>
      </div>
    </div>
  );
};

export default WalletWizard;
