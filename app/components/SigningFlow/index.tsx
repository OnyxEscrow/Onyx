/**
 * SigningFlow Component
 *
 * Handles the FROST threshold signing UI for release/refund operations.
 * Shows signature collection progress and broadcast status.
 */

import React, { useState, useCallback, useEffect } from 'react';
import {
  Key,
  Loader2,
  Check,
  AlertTriangle,
  Send,
  Users,
  Lock,
  CheckCircle,
  Radio,
} from 'lucide-react';
import { useFrostSigning, SigningPhase } from '../../hooks/useFrostSigning';
import { LogEntry } from '../../types';

interface SigningFlowProps {
  escrowId: string;
  role: string;
  action: 'release' | 'refund';
  coSignerRole: string;
  onComplete: (txHash: string) => void;
  onError: (error: string) => void;
  onLog?: (log: LogEntry) => void;
}

const SigningFlow: React.FC<SigningFlowProps> = ({
  escrowId,
  role,
  action,
  coSignerRole,
  onComplete,
  onError,
  onLog,
}) => {
  const [password, setPassword] = useState('');
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [step, setStep] = useState<'password' | 'signing' | 'complete'>('password');

  // Log handler
  const handleLog = useCallback(
    (log: LogEntry) => {
      if (onLog) {
        onLog(log);
      }
    },
    [onLog]
  );

  // FROST Signing hook
  const { state: signingState, startSigning, retry, reset } = useFrostSigning(handleLog);

  // Watch signing state
  useEffect(() => {
    if (signingState.phase === 'complete' && signingState.txHash) {
      setStep('complete');
      onComplete(signingState.txHash);
    } else if (signingState.phase === 'error') {
      onError(signingState.error || 'Unknown error');
    }
  }, [signingState.phase, signingState.txHash, signingState.error, onComplete, onError]);

  // Start signing
  const handleStartSigning = useCallback(async () => {
    if (!password) {
      setPasswordError('Please enter your backup password');
      return;
    }

    setPasswordError(null);
    setStep('signing');
    await startSigning(escrowId, role, action, password, coSignerRole);
  }, [password, startSigning, escrowId, role, action, coSignerRole]);

  // Get phase display info
  const getPhaseInfo = (phase: SigningPhase) => {
    const phases: Record<
      SigningPhase,
      { label: string; icon: React.ReactNode; color: string }
    > = {
      idle: { label: 'Ready', icon: <Key className="w-5 h-5" />, color: 'text-gray-400' },
      loading_key: {
        label: 'Decrypting Key',
        icon: <Lock className="w-5 h-5" />,
        color: 'text-blue-400',
      },
      generating_signature: {
        label: 'Generating Signature',
        icon: <Loader2 className="w-5 h-5 animate-spin" />,
        color: 'text-blue-400',
      },
      submitting: {
        label: 'Submitting',
        icon: <Loader2 className="w-5 h-5 animate-spin" />,
        color: 'text-blue-400',
      },
      waiting_cosigner: {
        label: 'Waiting for Co-Signer',
        icon: <Users className="w-5 h-5" />,
        color: 'text-yellow-400',
      },
      aggregating: {
        label: 'Aggregating Signatures',
        icon: <Loader2 className="w-5 h-5 animate-spin" />,
        color: 'text-purple-400',
      },
      broadcasting: {
        label: 'Broadcasting',
        icon: <Radio className="w-5 h-5 animate-pulse" />,
        color: 'text-green-400',
      },
      complete: {
        label: 'Complete',
        icon: <Check className="w-5 h-5" />,
        color: 'text-green-400',
      },
      error: {
        label: 'Error',
        icon: <AlertTriangle className="w-5 h-5" />,
        color: 'text-red-400',
      },
    };
    return phases[phase] || phases.idle;
  };

  const phaseInfo = getPhaseInfo(signingState.phase);
  const actionLabel = action === 'release' ? 'Release Funds' : 'Refund Buyer';
  const actionColor = action === 'release' ? 'from-green-600 to-green-500' : 'from-orange-600 to-orange-500';

  return (
    <div className="bg-[#0F1115] border border-white/10 rounded-3xl overflow-hidden shadow-2xl max-w-md w-full">
      {/* Header */}
      <div className="bg-white/5 px-6 py-4 border-b border-white/10">
        <div className="flex items-center gap-3">
          <div
            className={`w-10 h-10 rounded-xl flex items-center justify-center ${
              action === 'release' ? 'bg-green-500/20' : 'bg-orange-500/20'
            }`}
          >
            <Send
              className={`w-5 h-5 ${
                action === 'release' ? 'text-green-400' : 'text-orange-400'
              }`}
            />
          </div>
          <div>
            <h2 className="text-lg font-medium text-white">{actionLabel}</h2>
            <p className="text-xs text-gray-500">FROST 2-of-3 Threshold Signing</p>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        {step === 'password' && (
          <div className="space-y-6">
            {/* Info */}
            <div
              className={`p-4 border rounded-xl ${
                action === 'release'
                  ? 'bg-green-500/10 border-green-500/20'
                  : 'bg-orange-500/10 border-orange-500/20'
              }`}
            >
              <p
                className={`text-sm ${
                  action === 'release' ? 'text-green-200' : 'text-orange-200'
                }`}
              >
                {action === 'release'
                  ? 'You are about to release funds to the vendor. This requires your signature and the vendor\'s signature (2-of-3).'
                  : 'You are about to refund the buyer. This requires your signature and a co-signer\'s approval (2-of-3).'}
              </p>
            </div>

            {/* Signing Parties */}
            <div className="space-y-2">
              <p className="text-xs text-gray-500">Signing Parties</p>
              <div className="flex gap-2">
                <span className="px-3 py-1.5 bg-white/5 rounded-lg text-sm text-white capitalize">
                  {role}
                </span>
                <span className="text-gray-500">+</span>
                <span className="px-3 py-1.5 bg-white/5 rounded-lg text-sm text-gray-400 capitalize">
                  {coSignerRole}
                </span>
              </div>
            </div>

            {/* Password Input */}
            <div className="space-y-2">
              <label className="block text-xs font-medium text-gray-400">
                Backup Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your key backup password..."
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-cyan-500/50 transition-colors"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleStartSigning();
                }}
              />
              {passwordError && (
                <p className="text-sm text-red-400">{passwordError}</p>
              )}
            </div>

            {/* Sign Button */}
            <button
              onClick={handleStartSigning}
              disabled={!password}
              className={`w-full py-4 bg-gradient-to-r ${actionColor} hover:opacity-90 disabled:from-gray-600 disabled:to-gray-500 disabled:cursor-not-allowed text-white font-medium rounded-xl transition-all flex items-center justify-center gap-2`}
            >
              <Key className="w-5 h-5" />
              Sign Transaction
            </button>
          </div>
        )}

        {step === 'signing' && (
          <div className="space-y-6">
            {/* Progress Steps */}
            <div className="space-y-4">
              <SigningStep
                label="Decrypt Key"
                status={getStepStatus('loading_key', signingState.phase)}
              />
              <SigningStep
                label="Generate Partial Signature"
                status={getStepStatus('generating_signature', signingState.phase)}
              />
              <SigningStep
                label="Submit to Server"
                status={getStepStatus('submitting', signingState.phase)}
              />
              <SigningStep
                label={`Wait for ${coSignerRole}`}
                status={getStepStatus('waiting_cosigner', signingState.phase)}
              />
              <SigningStep
                label="Aggregate & Broadcast"
                status={getStepStatus('broadcasting', signingState.phase)}
              />
            </div>

            {/* Current Status */}
            <div
              className={`flex items-center justify-center gap-3 p-4 bg-white/5 rounded-xl ${phaseInfo.color}`}
            >
              {phaseInfo.icon}
              <span className="font-medium">{phaseInfo.label}</span>
            </div>

            {/* Server Status */}
            {signingState.serverStatus && (
              <div className="bg-white/5 rounded-xl p-3 space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-gray-500">Signatures</span>
                  <span className="text-white">
                    {signingState.serverStatus.signatures_collected} /{' '}
                    {signingState.serverStatus.signatures_required}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Status</span>
                  <span className="text-white capitalize">
                    {signingState.serverStatus.status}
                  </span>
                </div>
              </div>
            )}

            {/* Error State */}
            {signingState.phase === 'error' && (
              <div className="space-y-4">
                <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-red-300 text-sm">
                  {signingState.error || 'An error occurred during signing.'}
                </div>
                <button
                  onClick={retry}
                  className="w-full py-3 border border-white/10 text-gray-300 hover:text-white hover:border-white/20 rounded-xl transition-all"
                >
                  Retry
                </button>
              </div>
            )}

            {/* Waiting Info */}
            {signingState.phase === 'waiting_cosigner' && (
              <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-xl text-yellow-200 text-sm text-center">
                Waiting for {coSignerRole} to sign.
                <br />
                This window can stay open in the background.
              </div>
            )}
          </div>
        )}

        {step === 'complete' && (
          <div className="space-y-6 text-center">
            <div className="w-20 h-20 mx-auto bg-green-500/20 rounded-full flex items-center justify-center">
              <CheckCircle className="w-10 h-10 text-green-400" />
            </div>

            <div>
              <h3 className="text-xl font-bold text-white mb-2">
                Transaction Broadcast!
              </h3>
              <p className="text-sm text-gray-400">
                The funds are being transferred to the{' '}
                {action === 'release' ? 'vendor' : 'buyer'}.
              </p>
            </div>

            {signingState.txHash && (
              <div className="p-3 bg-white/5 rounded-xl">
                <p className="text-xs text-gray-500 mb-1">Transaction Hash</p>
                <p className="font-mono text-xs text-gray-300 break-all">
                  {signingState.txHash}
                </p>
              </div>
            )}

            <button
              onClick={() => onComplete(signingState.txHash || '')}
              className="w-full py-4 bg-gradient-to-r from-green-600 to-green-500 hover:from-green-500 hover:to-green-400 text-white font-medium rounded-xl transition-all"
            >
              Done
            </button>
          </div>
        )}
      </div>

      {/* Role Badge */}
      <div className="px-6 pb-4">
        <div className="flex items-center justify-center gap-2 text-xs text-gray-500">
          <span className="px-2 py-1 bg-white/5 rounded-full capitalize">{role}</span>
          <span>•</span>
          <span className="font-mono">{escrowId.slice(0, 8)}...</span>
        </div>
      </div>
    </div>
  );
};

// Helper component for signing steps
interface SigningStepProps {
  label: string;
  status: 'pending' | 'active' | 'complete';
}

const SigningStep: React.FC<SigningStepProps> = ({ label, status }) => {
  return (
    <div className="flex items-center gap-3">
      <div
        className={`w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 ${
          status === 'complete'
            ? 'bg-green-500/20 text-green-400'
            : status === 'active'
            ? 'bg-cyan-500/20 text-cyan-400'
            : 'bg-white/5 text-gray-500'
        }`}
      >
        {status === 'complete' ? (
          <Check className="w-3 h-3" />
        ) : status === 'active' ? (
          <Loader2 className="w-3 h-3 animate-spin" />
        ) : (
          <div className="w-1.5 h-1.5 rounded-full bg-current" />
        )}
      </div>
      <span
        className={`text-sm ${
          status === 'complete'
            ? 'text-green-400'
            : status === 'active'
            ? 'text-white'
            : 'text-gray-500'
        }`}
      >
        {label}
      </span>
    </div>
  );
};

// Helper to determine step status
function getStepStatus(
  targetPhase: SigningPhase,
  currentPhase: SigningPhase
): 'pending' | 'active' | 'complete' {
  const phaseOrder: SigningPhase[] = [
    'idle',
    'loading_key',
    'generating_signature',
    'submitting',
    'waiting_cosigner',
    'aggregating',
    'broadcasting',
    'complete',
  ];

  const targetIndex = phaseOrder.indexOf(targetPhase);
  const currentIndex = phaseOrder.indexOf(currentPhase);

  // Handle error state - show active on current step
  if (currentPhase === 'error') {
    return 'pending';
  }

  if (currentIndex > targetIndex) {
    return 'complete';
  } else if (currentIndex === targetIndex) {
    return 'active';
  }
  return 'pending';
}

export default SigningFlow;
