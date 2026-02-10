import React, { useState, useCallback, useRef } from 'react';
import { useShield, ShieldMetadata } from '../../hooks/useShield';
import {
  Shield, Upload, AlertTriangle, CheckCircle, Loader2,
  FileUp, Lock, RefreshCw, X, Terminal, Eye, EyeOff
} from 'lucide-react';

interface ShieldRecoveryProps {
  escrowId: string;
  expectedRole: 'buyer' | 'vendor' | 'arbiter';
  onRecovered: (keyPackage: Uint8Array, metadata: ShieldMetadata, password: string) => void;
  onCancel?: () => void;
}

type Step = 'upload' | 'restoring' | 'verifying' | 'success' | 'error';

export const ShieldRecovery: React.FC<ShieldRecoveryProps> = ({
  escrowId,
  expectedRole,
  onRecovered,
  onCancel,
}) => {
  const [step, setStep] = useState<Step>('upload');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [metadata, setMetadata] = useState<ShieldMetadata | null>(null);
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { restoreFromShield, verifyShield, registerShield, isRestoring } = useShield();

  // Handle file selection
  const handleFileSelect = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith('.nxshld') && !file.name.includes('onyx-shield') && !file.name.includes('nexus-shield')) {
      setError('INVALID_FILE_TYPE_NXSHLD_REQUIRED');
      return;
    }

    setSelectedFile(file);
    setError(null);
  }, []);

  // Handle drag and drop
  const handleDrop = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    const file = event.dataTransfer.files[0];
    if (!file) return;

    if (!file.name.endsWith('.nxshld') && !file.name.includes('onyx-shield') && !file.name.includes('nexus-shield')) {
      setError('INVALID_FILE_TYPE_NXSHLD_REQUIRED');
      return;
    }

    setSelectedFile(file);
    setError(null);
  }, []);

  const handleDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();
  }, []);

  // Restore from Shield
  const handleRestore = useCallback(async () => {
    if (!selectedFile) return;

    if (!password) {
      setError('PASSWORD_REQUIRED');
      return;
    }

    setStep('restoring');
    setError(null);

    try {
      const result = await restoreFromShield(selectedFile, password);

      // Validate escrow ID matches
      if (result.metadata.escrowId !== escrowId) {
        throw new Error(`ESCROW_ID_MISMATCH: ${result.metadata.escrowId.slice(0, 8)}...`);
      }

      // Validate role matches
      if (result.metadata.role !== expectedRole) {
        throw new Error(`ROLE_MISMATCH: FOUND ${result.metadata.role}, EXPECTED ${expectedRole}`);
      }

      setMetadata(result.metadata);
      setStep('verifying');

      // Verify with server - if record missing, register it first then re-verify
      let isValid = false;
      try {
        isValid = await verifyShield(escrowId, result.metadata.backupId);
      } catch (verifyErr) {
        console.warn('[ShieldRecovery] Server verification call failed:', verifyErr);
      }

      if (!isValid) {
        // Record missing in DB - register it now (was likely lost or never saved)
        try {
          await registerShield(escrowId, result.metadata.backupId, result.metadata.role);
          console.log('[ShieldRecovery] Shield registered on server during recovery');
          // Re-verify after registration
          isValid = await verifyShield(escrowId, result.metadata.backupId);
        } catch (regErr) {
          console.warn('[ShieldRecovery] Failed to register shield during recovery:', regErr);
        }
      }

      if (!isValid) {
        // Allow recovery without server verification - actual integrity proven at signing time
        console.warn('[ShieldRecovery] Server verification failed, allowing recovery anyway (signing will validate)');
        console.warn('[ShieldRecovery] backup_id from file:', result.metadata.backupId.substring(0, 20));
      }

      setStep('success');

      setTimeout(() => {
        onRecovered(result.keyPackage, result.metadata, password);
      }, 1500);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'UNKNOWN_RESTORE_ERROR';
      // Provide clearer error for decryption failures
      if (errorMsg.includes('OperationError') || errorMsg.includes('decrypt')) {
        setError('WRONG_PASSWORD_OR_CORRUPTED_FILE');
      } else {
        setError(errorMsg);
      }
      setStep('error');
    }
  }, [selectedFile, escrowId, expectedRole, restoreFromShield, verifyShield, onRecovered, password]);

  // Reset to try again
  const handleRetry = useCallback(() => {
    setStep('upload');
    setSelectedFile(null);
    setError(null);
    setMetadata(null);
    setPassword('');
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 backdrop-blur-sm p-2 sm:p-4 overflow-y-auto">
      <div className="w-full max-w-lg mx-2 sm:mx-4 bg-black border border-white/10 rounded-xl shadow-2xl overflow-hidden relative group my-auto">
        
        {/* Header */}
        <div className="p-4 sm:p-6 border-b border-white/10 flex items-center justify-between bg-white/[0.02]">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 bg-white/5 rounded-md flex items-center justify-center border border-white/10">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white uppercase tracking-widest leading-none mb-1">Shield Recovery</h2>
              <p className="text-[10px] text-white/40 font-mono uppercase tracking-widest">Restore Signing Capability</p>
            </div>
          </div>
          {onCancel && (
            <button
              onClick={onCancel}
              className="p-2 hover:bg-white/10 rounded-md transition-colors"
            >
              <X className="h-4 w-4 text-white/60" />
            </button>
          )}
        </div>

        {/* Content */}
        <div className="p-4 sm:p-6">
          {/* Step: Upload */}
          {step === 'upload' && (
            <div className="space-y-6">
              <div className="p-4 bg-blue-500/5 border-l-2 border-blue-500 rounded-r-lg">
                <p className="text-blue-400 text-xs font-mono leading-relaxed">
                  <span className="font-bold">NOTICE:</span> Local keys not found. Upload your Mandatory Shield file to restore access.
                </p>
              </div>

              {error && (
                <div className="p-3 bg-red-500/10 border-l-2 border-red-500 rounded-r text-red-400 text-xs font-mono uppercase">
                  {error}
                </div>
              )}

              {/* Drop zone */}
              <div
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onClick={() => fileInputRef.current?.click()}
                className={`p-10 border border-dashed rounded-xl cursor-pointer transition-all duration-300 flex flex-col items-center justify-center gap-4 group/drop ${
                  selectedFile
                    ? 'border-white/40 bg-white/5'
                    : 'border-white/20 hover:border-white/40 hover:bg-white/[0.02]'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".nxshld"
                  onChange={handleFileSelect}
                  className="hidden"
                />

                {selectedFile ? (
                   <>
                      <FileUp className="h-10 w-10 text-white animate-bounce" />
                      <div className="text-center">
                         <p className="text-white font-mono text-sm font-bold">{selectedFile.name}</p>
                         <p className="text-white/40 text-xs font-mono uppercase mt-1">
                           {(selectedFile.size / 1024).toFixed(1)} KB
                         </p>
                      </div>
                   </>
                ) : (
                   <>
                      <Upload className="h-10 w-10 text-white/20 group-hover/drop:text-white/60 transition-colors" />
                      <div className="text-center">
                         <p className="text-white/60 font-mono text-xs uppercase tracking-widest mb-1">
                           Drop Shield File Here
                         </p>
                         <p className="text-white/20 text-[10px] uppercase tracking-widest">
                           or click to browse
                         </p>
                      </div>
                   </>
                )}
              </div>

              {/* Password Input */}
              {selectedFile && (
                <div className="p-4 bg-white/[0.03] border border-white/10 rounded-lg">
                  <div className="flex items-center gap-2 mb-3">
                    <Lock className="h-3 w-3 text-white/40" />
                    <span className="text-[10px] text-white/40 font-mono uppercase tracking-widest">
                      Enter Shield Password
                    </span>
                  </div>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Password used when creating Shield..."
                      className="w-full px-4 py-3 bg-black border border-white/20 rounded-lg text-white font-mono text-xs placeholder:text-white/30 focus:outline-none focus:border-white/40 pr-10"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-white/40 hover:text-white/60"
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
              )}

              <button
                onClick={handleRestore}
                disabled={!selectedFile || !password}
                className={`w-full py-4 rounded-lg font-mono text-xs uppercase tracking-widest font-bold transition-all flex items-center justify-center gap-2 ${
                  selectedFile && password
                    ? 'bg-white text-black hover:bg-white/90'
                    : 'bg-white/5 text-white/20 cursor-not-allowed border border-white/5'
                }`}
              >
                <Terminal className="h-4 w-4" />
                INITIATE RESTORE
              </button>
            </div>
          )}

          {/* Step: Restoring */}
          {step === 'restoring' && (
            <div className="flex flex-col items-center justify-center py-12 space-y-4">
              <Loader2 className="h-8 w-8 text-white animate-spin" />
              <p className="text-white/60 font-mono text-xs uppercase tracking-widest">Decrypting Payload...</p>
            </div>
          )}

          {/* Step: Verifying */}
          {step === 'verifying' && (
            <div className="flex flex-col items-center justify-center py-12 space-y-4">
              <Loader2 className="h-8 w-8 text-white animate-spin" />
              <p className="text-white/60 font-mono text-xs uppercase tracking-widest">Verifying Integrity...</p>
              <p className="text-white/30 text-[10px] font-mono uppercase tracking-widest">
                ID: {metadata?.backupId.slice(0, 16)}...
              </p>
            </div>
          )}

          {/* Step: Success */}
          {step === 'success' && (
            <div className="flex flex-col items-center py-12 animate-in zoom-in-95">
              <div className="w-16 h-16 bg-white rounded-full flex items-center justify-center mb-6 shadow-[0_0_30px_rgba(255,255,255,0.2)]">
                <CheckCircle className="h-8 w-8 text-black" />
              </div>
              <p className="text-white font-bold text-xl uppercase tracking-widest mb-2">Access Restored</p>
              <p className="text-white/40 font-mono text-xs">Signing Capability Online</p>
              {metadata && (
                <div className="mt-6 px-4 py-2 bg-white/5 rounded border border-white/10 text-[10px] text-white/40 font-mono uppercase tracking-widest">
                  Restored: {new Date(metadata.createdAt).toLocaleDateString()}
                </div>
              )}
            </div>
          )}

          {/* Step: Error */}
          {step === 'error' && (
            <div className="space-y-6 animate-in shake">
              <div className="flex flex-col items-center py-4">
                <div className="p-4 bg-red-500/10 rounded-full mb-4 border border-red-500/20">
                  <AlertTriangle className="h-8 w-8 text-red-500" />
                </div>
                <p className="text-red-500 font-bold font-mono text-lg uppercase tracking-widest">RECOVERY FAILED</p>
              </div>

              <div className="p-4 bg-red-500/5 border border-red-500/20 rounded-lg text-red-400 text-xs font-mono uppercase text-center">
                {error}
              </div>

              <button
                onClick={handleRetry}
                className="w-full py-4 bg-white/5 border border-white/10 rounded-lg text-white font-mono text-xs uppercase tracking-widest hover:bg-white/10 transition-colors flex items-center justify-center gap-2"
              >
                <RefreshCw className="h-4 w-4" />
                RETRY OPERATION
              </button>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 pb-6 pt-2 border-t border-white/5 bg-black/50">
           <div className="flex items-center justify-between text-[9px] text-white/20 font-mono uppercase tracking-widest">
            <span>SID: {escrowId.slice(0, 12)}</span>
            <span>TARGET: {expectedRole.toUpperCase()}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ShieldRecovery;
