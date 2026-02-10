/**
 * QR Backup Export Component
 *
 * Generates a QR code for encrypted FROST key backup data.
 * Uses the qrcode library for proper QR code generation.
 */

import React, { useRef, useCallback, useState, useEffect } from 'react';
import QRCode from 'qrcode';
import { Download, Copy, Check, AlertTriangle, X, QrCode } from 'lucide-react';

interface QRBackupExportProps {
  encryptedData: string;
  escrowId?: string;
  onDownload?: () => void;
  onClose?: () => void;
  isOpen?: boolean;
}

const QRBackupExport: React.FC<QRBackupExportProps> = ({
  encryptedData,
  escrowId,
  onDownload,
  onClose,
  isOpen = true,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isVisible, setIsVisible] = useState(false);
  const [copied, setCopied] = useState(false);
  const [qrError, setQrError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) setIsVisible(true);
    else setTimeout(() => setIsVisible(false), 300);
  }, [isOpen]);

  // Generate QR code when data changes
  useEffect(() => {
    if (!canvasRef.current || !encryptedData) return;

    setQrError(null);

    QRCode.toCanvas(canvasRef.current, encryptedData, {
      width: 256,
      margin: 2,
      color: {
        dark: '#FFFFFF',
        light: '#0F1115',
      },
      errorCorrectionLevel: 'L', // Low error correction for max capacity
    })
      .then(() => {
        console.log('[QR] Generated successfully');
      })
      .catch((err) => {
        console.error('[QR] Generation failed:', err);
        setQrError(err.message || 'Failed to generate QR code');
      });
  }, [encryptedData]);

  const handleDownload = useCallback(() => {
    if (!canvasRef.current) return;

    const link = document.createElement('a');
    const timestamp = Date.now();
    const prefix = escrowId ? `${escrowId.slice(0, 8)}-` : '';
    link.download = `onyx-frost-backup-${prefix}${timestamp}.png`;
    link.href = canvasRef.current.toDataURL('image/png');
    link.click();

    onDownload?.();
  }, [escrowId, onDownload]);

  const handleCopyData = useCallback(() => {
    navigator.clipboard.writeText(encryptedData);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [encryptedData]);

  if (!isVisible && !isOpen) return null;

  const dataLength = encryptedData.length;
  const isValidSize = dataLength <= 2953; // QR version 40-L max

  return (
    <div
      className={`fixed inset-0 z-[100] flex items-center justify-center p-4 transition-opacity duration-300 ${
        isOpen ? 'opacity-100' : 'opacity-0'
      }`}
    >
      <div className="absolute inset-0 bg-black/80 backdrop-blur-md" onClick={onClose} />

      <div
        className={`relative w-full max-w-[calc(100vw-2rem)] sm:max-w-md bg-[#0F1115] border border-white/10 rounded-2xl sm:rounded-3xl overflow-hidden shadow-2xl transition-all duration-300 transform ${
          isOpen ? 'scale-100 translate-y-0' : 'scale-95 translate-y-8'
        }`}
      >
        {/* Header */}
        <div className="bg-white/5 px-4 py-3 sm:px-6 sm:py-4 border-b border-white/10 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center">
              <QrCode className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-lg font-medium text-white">FROST Key Backup</h2>
              <p className="text-xs text-gray-500">Scan to restore your key share</p>
            </div>
          </div>
          {onClose && (
            <button
              onClick={onClose}
              className="text-gray-500 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Content */}
        <div className="p-4 sm:p-6 space-y-4 sm:space-y-6">
          {/* Security Warning */}
          <div className="p-3 bg-orange-500/10 border border-orange-500/30 rounded-xl text-orange-200 text-xs flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>
              Store this QR code securely. Anyone with access can restore your key
              share. Use password-protected storage.
            </span>
          </div>

          {/* QR Code Display */}
          <div className="flex justify-center">
            <div className="bg-[#0F1115] p-4 rounded-2xl border border-white/5 shadow-lg">
              {qrError ? (
                <div className="w-48 h-48 sm:w-64 sm:h-64 flex items-center justify-center text-red-400 text-sm text-center p-4">
                  <div>
                    <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
                    {qrError}
                  </div>
                </div>
              ) : (
                <canvas
                  ref={canvasRef}
                  className="rounded-lg"
                  style={{ imageRendering: 'pixelated' }}
                />
              )}
            </div>
          </div>

          {/* Data Info */}
          <div className="bg-white/5 rounded-xl p-3 space-y-2">
            <div className="flex justify-between items-center text-xs">
              <span className="text-gray-500">Data Size</span>
              <span
                className={`font-mono ${
                  isValidSize ? 'text-green-400' : 'text-red-400'
                }`}
              >
                {dataLength} chars
              </span>
            </div>
            <div className="flex justify-between items-center text-xs">
              <span className="text-gray-500">Encryption</span>
              <span className="text-gray-300 font-mono">Argon2id + ChaCha20</span>
            </div>
            {escrowId && (
              <div className="flex justify-between items-center text-xs">
                <span className="text-gray-500">Escrow ID</span>
                <span className="text-gray-300 font-mono">{escrowId.slice(0, 8)}...</span>
              </div>
            )}
          </div>

          {/* Truncated Data Preview */}
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-xs text-gray-500">Encrypted Data</span>
              <button
                onClick={handleCopyData}
                className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1"
              >
                {copied ? (
                  <>
                    <Check className="w-3 h-3" />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    Copy
                  </>
                )}
              </button>
            </div>
            <div className="bg-black/40 rounded-lg p-3 font-mono text-xs text-gray-400 break-all max-h-20 overflow-y-auto">
              {encryptedData.substring(0, 100)}...
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3">
            <button
              onClick={handleDownload}
              className="flex-1 py-3 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white font-medium rounded-xl transition-all flex items-center justify-center gap-2"
            >
              <Download className="w-4 h-4" />
              Download PNG
            </button>
            {onClose && (
              <button
                onClick={onClose}
                className="px-6 py-3 border border-white/10 text-gray-400 hover:text-white hover:border-white/20 rounded-xl transition-all"
              >
                Close
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default QRBackupExport;
