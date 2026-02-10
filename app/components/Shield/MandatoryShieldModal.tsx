import React, { useState, useEffect, useCallback } from 'react';
import { useShield } from '../../hooks/useShield';
import { getWasmModule } from '../../services/wasmService';
import { storeKey } from '../../services/keyStorage';
import {
  Shield, Download, AlertTriangle, CheckCircle, Loader2,
  Lock, Eye, EyeOff, FileDown, Terminal
} from 'lucide-react';

// Helper to convert Uint8Array to hex
const uint8ArrayToHex = (arr: Uint8Array): string => {
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

interface MandatoryShieldModalProps {
  escrowId: string;
  role: 'buyer' | 'vendor' | 'arbiter';
  keyPackage: Uint8Array;
  groupPubkey: string;
  onComplete: () => void;
}

type Step = 'info' | 'generating' | 'download' | 'verifying' | 'complete';

export const MandatoryShieldModal: React.FC<MandatoryShieldModalProps> = ({
  escrowId,
  role,
  keyPackage,
  groupPubkey,
  onComplete,
}) => {
  const [step, setStep] = useState<Step>('info');
  const [shieldBlob, setShieldBlob] = useState<Blob | null>(null);
  const [backupId, setBackupId] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [downloadCount, setDownloadCount] = useState(0);

  // Password state
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);

  const { generateShield, registerShield, isGenerating } = useShield();

  // Validate password before generation
  const validatePassword = (): boolean => {
    setPasswordError(null);

    if (password.length < 8) {
      setPasswordError('Password must be at least 8 characters');
      return false;
    }

    if (password !== confirmPassword) {
      setPasswordError('Passwords do not match');
      return false;
    }

    return true;
  };

  // Generate shield on mount
  const handleGenerate = useCallback(async () => {
    console.log('[Shield] Button clicked!');
    console.log('[Shield] Props:', { escrowId, role, keyPackageLen: keyPackage?.length, groupPubkey: groupPubkey?.slice(0, 16) });

    // Validate password
    if (!validatePassword()) {
      return;
    }

    setStep('generating');
    setError(null);

    try {
      console.log('[Shield] Starting generation with user password...');

      // CRITICAL: Store the key locally with the user's chosen password
      // This overwrites any temporary password used during DKG
      const keyPackageHex = uint8ArrayToHex(keyPackage);
      await storeKey(escrowId, role, keyPackageHex, password);
      console.log('[Shield] Key stored locally with user password.');

      const blob = await generateShield(escrowId, role, keyPackage, password);
      console.log('[Shield] Generated blob:', blob?.size, 'bytes');
      setShieldBlob(blob);

      // Derive backup ID
      const wasm = getWasmModule();
      console.log('[Shield] WASM module:', wasm ? 'loaded' : 'NOT LOADED');
      if (wasm?.derive_backup_id) {
        const id = wasm.derive_backup_id(escrowId, role);
        console.log('[Shield] Backup ID:', id);
        setBackupId(id);
      }

      setStep('download');
    } catch (err) {
      console.error('[Shield] Generation error:', err);
      setError(err instanceof Error ? err.message : 'Failed to generate Shield');
      setStep('info');
    }
  }, [escrowId, role, keyPackage, generateShield, password, confirmPassword]);

  // Download handler
  const handleDownload = useCallback(() => {
    if (!shieldBlob) return;

    const url = URL.createObjectURL(shieldBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `onyx-shield-${escrowId.slice(0, 8)}-${role}.nxshld`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setDownloadCount((c) => c + 1);
  }, [shieldBlob, escrowId, role]);

  // Verify and complete
  const handleVerifyAndComplete = useCallback(async () => {
    if (downloadCount === 0) {
      setError('DOWNLOAD_REQUIRED');
      return;
    }

    setStep('verifying');
    setError(null);

    try {
      await registerShield(escrowId, backupId, role);
      setStep('complete');

      // Auto-complete after animation
      setTimeout(() => {
        onComplete();
      }, 1500);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to register Shield');
      setStep('download');
    }
  }, [downloadCount, escrowId, backupId, role, registerShield, onComplete]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 backdrop-blur-sm p-2 sm:p-4 overflow-y-auto">
      <div className="w-full max-w-lg mx-2 sm:mx-4 bg-black border border-white/10 rounded-xl shadow-2xl relative group my-auto">
        <div className="absolute top-0 right-0 w-16 h-16 bg-gradient-to-bl from-white/5 to-transparent rounded-tr-xl"></div>
        
        {/* Header - Cannot close */}
        <div className="p-4 sm:p-6 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-3 sm:gap-4">
            <div className="w-8 h-8 sm:w-10 sm:h-10 bg-white/5 rounded-md flex items-center justify-center border border-white/10">
              <Shield className="h-4 w-4 sm:h-5 sm:w-5 text-white" />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-white uppercase tracking-widest leading-none mb-1">Mandatory Shield</h2>
              <div className="flex items-center gap-2">
                 <div className="w-1.5 h-1.5 bg-amber-500 rounded-full animate-pulse"></div>
                 <p className="text-[10px] text-white/40 font-mono uppercase tracking-widest">Protocol Requirement</p>
              </div>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="p-4 sm:p-6">
          {/* Step: Info */}
          {step === 'info' && (
            <div className="space-y-6">
              {error && (
                <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-red-400 text-xs font-mono">
                  Error: {error}
                </div>
              )}
              <div className="p-4 bg-amber-500/5 border-l-2 border-amber-500 rounded-r-lg">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-4 w-4 text-amber-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <h3 className="font-mono text-[10px] font-bold text-amber-500 uppercase tracking-widest mb-1">Critical Notice</h3>
                    <p className="text-amber-500/80 text-xs leading-relaxed font-mono">
                      Your signing key is stored ONLY in this browser session.
                      A recovery file is required to prevent permanent fund loss.
                    </p>
                  </div>
                </div>
              </div>

              {/* Password Input Section */}
              <div className="space-y-4">
                <div className="p-4 bg-white/[0.03] border border-white/10 rounded-lg">
                  <h4 className="font-mono text-[10px] font-bold text-white/60 uppercase tracking-widest mb-4">
                    Choose Encryption Password
                  </h4>

                  {passwordError && (
                    <div className="mb-3 p-2 bg-red-500/10 border border-red-500/30 rounded text-red-400 text-[10px] font-mono">
                      {passwordError}
                    </div>
                  )}

                  <div className="space-y-3">
                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Min 8 chars..."
                        className="w-full px-3 py-2.5 sm:px-4 sm:py-3 bg-black border border-white/20 rounded-lg text-white font-mono text-xs placeholder:text-white/30 focus:outline-none focus:border-white/40 pr-10"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-white/40 hover:text-white/60"
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>

                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Confirm password..."
                        className="w-full px-4 py-3 bg-black border border-white/20 rounded-lg text-white font-mono text-xs placeholder:text-white/30 focus:outline-none focus:border-white/40"
                      />
                    </div>
                  </div>

                  <p className="mt-3 text-[9px] text-white/30 font-mono uppercase tracking-wider">
                    Remember this password — you'll need it to sign transactions
                  </p>
                </div>
              </div>

              <div className="space-y-3 pl-2">
                <div className="flex items-center gap-3 text-white/60">
                  <Lock className="h-3 w-3" />
                  <span className="text-xs font-mono uppercase tracking-wide">Encrypted with Your Password</span>
                </div>
                <div className="flex items-center gap-3 text-white/60">
                  <Shield className="h-3 w-3" />
                  <span className="text-xs font-mono uppercase tracking-wide">Contains FROST Key Package</span>
                </div>
                <div className="flex items-center gap-3 text-white/60">
                  <FileDown className="h-3 w-3" />
                  <span className="text-xs font-mono uppercase tracking-wide">Download Mandatory</span>
                </div>
              </div>

              <button
                type="button"
                onClick={() => {
                  console.log('[Shield] Button onClick fired');
                  handleGenerate();
                }}
                disabled={password.length < 8 || !confirmPassword}
                className={`w-full py-4 font-bold font-mono text-xs uppercase tracking-widest rounded-lg transition-all flex items-center justify-center gap-2 mt-4 ${
                  password.length >= 8 && confirmPassword
                    ? 'bg-white text-black hover:bg-white/90'
                    : 'bg-white/10 text-white/30 cursor-not-allowed'
                }`}
              >
                <Shield className="h-4 w-4" />
                Generate Shield File
              </button>
            </div>
          )}

          {/* Step: Generating */}
          {step === 'generating' && (
            <div className="flex flex-col items-center justify-center py-12 space-y-4">
              <div className="relative">
                 <div className="w-12 h-12 border border-white/10 rounded-full animate-spin"></div>
                 <div className="absolute inset-0 flex items-center justify-center">
                    <Loader2 className="h-4 w-4 text-white animate-pulse" />
                 </div>
              </div>
              <p className="text-white/40 font-mono text-xs uppercase tracking-widest animate-pulse">Encrypting Data...</p>
            </div>
          )}

          {/* Step: Download */}
          {step === 'download' && (
            <div className="space-y-6 animate-in fade-in slide-in-from-right-4">
              {error && (
                <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-red-400 text-xs font-mono uppercase">
                  {error}
                </div>
              )}

              {/* Password Reminder Box */}
              <div className="p-4 bg-green-500/5 border border-green-500/30 rounded-lg">
                <div className="flex items-start gap-3">
                  <Lock className="h-4 w-4 text-green-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-mono text-[10px] font-bold text-green-500 uppercase tracking-widest mb-2">
                      Save Your Password
                    </h4>
                    <div className="flex items-center gap-2 bg-black/50 px-3 py-2 rounded border border-green-500/20">
                      <code className="text-green-400 font-mono text-xs flex-1 select-all">
                        {showPassword ? password : '••••••••••••'}
                      </code>
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="text-green-500/60 hover:text-green-500"
                      >
                        {showPassword ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                      </button>
                    </div>
                    <p className="mt-2 text-[9px] text-green-500/60 font-mono">
                      You will need this password to sign transactions later
                    </p>
                  </div>
                </div>
              </div>

              <div className="p-4 bg-white/[0.03] border border-white/10 rounded-lg group hover:border-white/30 transition-colors">
                <div className="flex items-center justify-between gap-4">
                  <div className="overflow-hidden">
                    <div className="flex items-center gap-2 mb-1">
                       <FileDown className="h-3 w-3 text-white/40" />
                       <p className="text-white font-mono text-xs truncate font-bold">
                         onyx-shield-{escrowId.slice(0, 8)}-{role}.nxshld
                       </p>
                    </div>
                    <p className="text-white/30 text-[9px] font-mono uppercase tracking-widest truncate">
                      ID: {backupId.slice(0, 16)}...
                    </p>
                  </div>
                  <button
                    onClick={handleDownload}
                    className="p-3 bg-white text-black rounded-lg hover:bg-white/90 transition-transform active:scale-95 shrink-0"
                  >
                    <Download className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {downloadCount > 0 && (
                <div className="flex items-center justify-center gap-2 text-green-500">
                  <CheckCircle className="h-3 w-3" />
                  <span className="text-[10px] font-mono uppercase tracking-widest">Download Verified</span>
                </div>
              )}

              <button
                onClick={handleVerifyAndComplete}
                disabled={downloadCount === 0}
                className={`w-full py-4 rounded-lg font-mono text-xs uppercase tracking-widest font-bold transition-all flex items-center justify-center gap-2 ${
                  downloadCount > 0
                    ? 'bg-white text-black hover:bg-white/90'
                    : 'bg-white/5 text-white/20 cursor-not-allowed border border-white/5'
                }`}
              >
                {downloadCount > 0 ? (
                    <>
                       <CheckCircle className="h-4 w-4" />
                       <span>Confirm Backup Secured</span>
                    </>
                ) : (
                    <span>Awaiting Download...</span>
                )}
              </button>
            </div>
          )}

          {/* Step: Verifying */}
          {step === 'verifying' && (
             <div className="flex flex-col items-center justify-center py-12 space-y-4">
              <Loader2 className="h-8 w-8 text-white animate-spin" />
              <p className="text-white/40 font-mono text-xs uppercase tracking-widest">Verifying Hash...</p>
            </div>
          )}

          {/* Step: Complete */}
          {step === 'complete' && (
            <div className="flex flex-col items-center py-12 animate-in zoom-in-95">
              <div className="w-16 h-16 bg-white rounded-full flex items-center justify-center mb-6 shadow-[0_0_30px_rgba(255,255,255,0.2)]">
                <CheckCircle className="h-8 w-8 text-black" />
              </div>
              <p className="text-white font-bold text-xl uppercase tracking-widest mb-2">Shield Secured</p>
              <p className="text-white/40 font-mono text-xs">Protocol Proceeding...</p>
            </div>
          )}
        </div>

        {/* Footer - Role indicator */}
        <div className="px-4 pb-4 sm:px-6 sm:pb-6 pt-2 border-t border-white/5 bg-black/50">
          <div className="flex items-center justify-between text-[9px] text-white/20 font-mono uppercase tracking-widest">
            <span>SID: {escrowId.slice(0, 12)}</span>
            <span>{role} NODE</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MandatoryShieldModal;
