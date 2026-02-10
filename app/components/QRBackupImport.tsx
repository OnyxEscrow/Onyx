/**
 * QR Backup Import Component
 *
 * Scans QR codes for FROST key backup restoration.
 * Uses jsQR for QR code decoding.
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import jsQR from 'jsqr';
import { Camera, Upload, X, AlertCircle, Scan, Check } from 'lucide-react';

interface QRBackupImportProps {
  onScan: (data: string) => void;
  onError: (error: Error) => void;
  onClose?: () => void;
  isOpen?: boolean;
}

type ScanMode = 'camera' | 'file';

const QRBackupImport: React.FC<QRBackupImportProps> = ({
  onScan,
  onError,
  onClose,
  isOpen = true,
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [scanMode, setScanMode] = useState<ScanMode>('camera');
  const [hasPermission, setHasPermission] = useState<boolean | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [manualInput, setManualInput] = useState('');

  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const animationFrameRef = useRef<number | null>(null);

  useEffect(() => {
    if (isOpen) setIsVisible(true);
    else {
      setTimeout(() => setIsVisible(false), 300);
      stopCamera();
    }
  }, [isOpen]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      stopCamera();
    };
  }, []);

  const stopCamera = useCallback(() => {
    if (animationFrameRef.current) {
      cancelAnimationFrame(animationFrameRef.current);
      animationFrameRef.current = null;
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
    }
    setIsScanning(false);
  }, []);

  const startCamera = useCallback(async () => {
    try {
      setError(null);
      setIsScanning(true);

      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: 'environment',
          width: { ideal: 1280 },
          height: { ideal: 720 },
        },
      });

      streamRef.current = stream;
      setHasPermission(true);

      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.play();

        // Start scanning loop after video is ready
        videoRef.current.onloadedmetadata = () => {
          scanFrame();
        };
      }
    } catch (err) {
      setHasPermission(false);
      setIsScanning(false);
      const message = err instanceof Error ? err.message : 'Camera access denied';
      setError(message);
      onError(new Error(message));
    }
  }, [onError]);

  const scanFrame = useCallback(() => {
    if (!videoRef.current || !canvasRef.current || !isScanning) return;

    const video = videoRef.current;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');

    if (!ctx || video.readyState !== video.HAVE_ENOUGH_DATA) {
      animationFrameRef.current = requestAnimationFrame(scanFrame);
      return;
    }

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    // Use jsQR for decoding
    const code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'dontInvert',
    });

    if (code) {
      stopCamera();
      handleScannedData(code.data);
    } else {
      animationFrameRef.current = requestAnimationFrame(scanFrame);
    }
  }, [isScanning, stopCamera]);

  const handleFileUpload = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (!file) return;

      setError(null);

      const reader = new FileReader();
      reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
          const canvas = document.createElement('canvas');
          canvas.width = img.width;
          canvas.height = img.height;
          const ctx = canvas.getContext('2d');
          if (!ctx) {
            setError('Failed to process image');
            return;
          }

          ctx.drawImage(img, 0, 0);
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

          // Use jsQR for decoding
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'attemptBoth',
          });

          if (code) {
            handleScannedData(code.data);
          } else {
            setError('No QR code found in image');
            onError(new Error('No QR code found in image'));
          }
        };
        img.onerror = () => {
          setError('Failed to load image');
          onError(new Error('Failed to load image'));
        };
        img.src = e.target?.result as string;
      };
      reader.readAsDataURL(file);

      // Reset input so same file can be selected again
      event.target.value = '';
    },
    [onError]
  );

  const handleScannedData = useCallback(
    (data: string) => {
      // Validate hex format (encrypted backup is hex)
      if (!isValidHex(data)) {
        setError('Invalid backup format: not valid hex data');
        onError(new Error('Invalid backup format: not valid hex data'));
        return;
      }

      // Check size constraints
      if (data.length < 100 || data.length > 2000) {
        setError(`Invalid backup size: ${data.length} chars (expected 100-2000)`);
        onError(new Error(`Invalid backup size: ${data.length} chars`));
        return;
      }

      onScan(data);
    },
    [onScan, onError]
  );

  const handleManualSubmit = useCallback(() => {
    const trimmed = manualInput.trim();
    if (!trimmed) {
      setError('Please enter backup data');
      return;
    }
    handleScannedData(trimmed);
  }, [manualInput, handleScannedData]);

  if (!isVisible && !isOpen) return null;

  return (
    <div
      className={`fixed inset-0 z-[100] flex items-center justify-center p-4 transition-opacity duration-300 ${
        isOpen ? 'opacity-100' : 'opacity-0'
      }`}
    >
      <div className="absolute inset-0 bg-black/80 backdrop-blur-md" onClick={onClose} />

      <div
        className={`relative w-full max-w-lg bg-[#0F1115] border border-white/10 rounded-3xl overflow-hidden shadow-2xl transition-all duration-300 transform ${
          isOpen ? 'scale-100 translate-y-0' : 'scale-95 translate-y-8'
        }`}
      >
        {/* Header */}
        <div className="bg-white/5 px-6 py-4 border-b border-white/10 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center">
              <Scan className="w-4 h-4 text-purple-400" />
            </div>
            <div>
              <h2 className="text-lg font-medium text-white">Restore Key Backup</h2>
              <p className="text-xs text-gray-500">Scan QR code or upload image</p>
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

        {/* Mode Selector */}
        <div className="p-4 border-b border-white/5">
          <div className="flex bg-white/5 rounded-xl p-1">
            <button
              onClick={() => {
                setScanMode('camera');
                setError(null);
              }}
              className={`flex-1 py-2 px-4 rounded-lg text-sm font-medium transition-all flex items-center justify-center gap-2 ${
                scanMode === 'camera'
                  ? 'bg-purple-500/20 text-purple-300'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              <Camera className="w-4 h-4" />
              Camera
            </button>
            <button
              onClick={() => {
                setScanMode('file');
                stopCamera();
                setError(null);
              }}
              className={`flex-1 py-2 px-4 rounded-lg text-sm font-medium transition-all flex items-center justify-center gap-2 ${
                scanMode === 'file'
                  ? 'bg-purple-500/20 text-purple-300'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              <Upload className="w-4 h-4" />
              Upload
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          {/* Error Display */}
          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-300 text-sm flex items-start gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Camera Mode */}
          {scanMode === 'camera' && (
            <div className="space-y-4">
              {!isScanning ? (
                <div className="space-y-4">
                  {hasPermission === false && (
                    <div className="p-4 bg-orange-500/10 border border-orange-500/30 rounded-xl text-orange-200 text-sm text-center">
                      <p className="mb-2">Camera permission denied</p>
                      <p className="text-xs text-gray-400">
                        Please enable camera access in your browser settings, or use
                        the file upload option.
                      </p>
                    </div>
                  )}

                  <button
                    onClick={startCamera}
                    className="w-full py-4 bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 text-white font-medium rounded-xl transition-all flex items-center justify-center gap-2"
                  >
                    <Camera className="w-5 h-5" />
                    Start Camera Scan
                  </button>
                </div>
              ) : (
                <div className="relative">
                  {/* Video Preview */}
                  <div className="relative rounded-2xl overflow-hidden bg-black aspect-video">
                    <video
                      ref={videoRef}
                      autoPlay
                      playsInline
                      muted
                      className="w-full h-full object-cover"
                    />

                    {/* Scanning Overlay */}
                    <div className="absolute inset-0 pointer-events-none">
                      {/* Corner markers */}
                      <div className="absolute top-4 left-4 w-12 h-12 border-l-2 border-t-2 border-purple-400" />
                      <div className="absolute top-4 right-4 w-12 h-12 border-r-2 border-t-2 border-purple-400" />
                      <div className="absolute bottom-4 left-4 w-12 h-12 border-l-2 border-b-2 border-purple-400" />
                      <div className="absolute bottom-4 right-4 w-12 h-12 border-r-2 border-b-2 border-purple-400" />

                      {/* Center target */}
                      <div className="absolute inset-0 flex items-center justify-center">
                        <div className="w-48 h-48 border-2 border-purple-400/50 rounded-xl animate-pulse" />
                      </div>
                    </div>

                    {/* Scanning indicator */}
                    <div className="absolute bottom-4 left-1/2 -translate-x-1/2 bg-black/60 backdrop-blur-sm px-4 py-2 rounded-full flex items-center gap-2">
                      <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse" />
                      <span className="text-xs text-white">Scanning...</span>
                    </div>
                  </div>

                  {/* Hidden canvas for image processing */}
                  <canvas ref={canvasRef} className="hidden" />

                  {/* Stop Button */}
                  <button
                    onClick={stopCamera}
                    className="mt-4 w-full py-3 border border-white/10 text-gray-400 hover:text-white hover:border-white/20 rounded-xl transition-all"
                  >
                    Stop Camera
                  </button>
                </div>
              )}
            </div>
          )}

          {/* File Upload Mode */}
          {scanMode === 'file' && (
            <div className="space-y-4">
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={handleFileUpload}
                className="hidden"
              />

              <button
                onClick={() => fileInputRef.current?.click()}
                className="w-full py-12 border-2 border-dashed border-white/10 hover:border-purple-400/50 rounded-2xl transition-all flex flex-col items-center justify-center gap-3 group"
              >
                <div className="w-12 h-12 rounded-xl bg-white/5 group-hover:bg-purple-500/20 flex items-center justify-center transition-all">
                  <Upload className="w-6 h-6 text-gray-500 group-hover:text-purple-400 transition-colors" />
                </div>
                <div className="text-center">
                  <p className="text-gray-300 text-sm">
                    Click to upload QR code image
                  </p>
                  <p className="text-gray-500 text-xs mt-1">PNG, JPG, or WEBP</p>
                </div>
              </button>

              {/* Manual Input */}
              <div className="pt-4 border-t border-white/5">
                <p className="text-xs text-gray-500 mb-2">
                  Or paste backup data manually:
                </p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={manualInput}
                    onChange={(e) => setManualInput(e.target.value)}
                    placeholder="Paste hex backup data..."
                    className="flex-1 bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white font-mono text-xs focus:outline-none focus:border-purple-500/50 transition-colors"
                  />
                  <button
                    onClick={handleManualSubmit}
                    disabled={!manualInput.trim()}
                    className="px-4 py-3 bg-purple-500/20 text-purple-300 rounded-xl hover:bg-purple-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                  >
                    Restore
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Help Text */}
          <div className="pt-4 text-center">
            <p className="text-xs text-gray-500">
              Position the QR code within the frame. The scanner will
              automatically detect and import your backup.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

/**
 * Validate hex string format
 */
function isValidHex(str: string): boolean {
  if (!str || str.length === 0) return false;
  return /^[0-9a-fA-F]+$/.test(str) && str.length % 2 === 0;
}

export default QRBackupImport;
