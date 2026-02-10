import React, { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { QrCode, Copy, Check, ExternalLink } from 'lucide-react';

interface PaymentQRCodeProps {
  address: string;
  amount: string;
  recipientName?: string;
  description?: string;
  size?: number;
}

export const PaymentQRCode: React.FC<PaymentQRCodeProps> = ({
  address,
  amount,
  recipientName,
  description,
  size = 200,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedUri, setCopiedUri] = useState(false);
  const [copiedAddress, setCopiedAddress] = useState(false);

  // Build Monero URI according to BIP-21 style format
  // Format: monero:<address>?tx_amount=<amount>&recipient_name=<name>&tx_description=<desc>
  const buildMoneroUri = (): string => {
    const params = new URLSearchParams();

    // Amount in XMR (not atomic units)
    if (amount) {
      params.set('tx_amount', amount);
    }

    // Optional recipient name
    if (recipientName) {
      params.set('recipient_name', recipientName);
    }

    // Optional description
    if (description) {
      params.set('tx_description', description);
    }

    const queryString = params.toString();
    return queryString ? `monero:${address}?${queryString}` : `monero:${address}`;
  };

  const moneroUri = address ? buildMoneroUri() : '';

  useEffect(() => {
    if (!canvasRef.current || !address) return;

    QRCode.toCanvas(canvasRef.current, moneroUri, {
      width: size,
      margin: 2,
      color: {
        dark: '#000000',
        light: '#FFFFFF',
      },
      errorCorrectionLevel: 'M', // Medium error correction for balance of size/reliability
    })
      .then(() => {
        setError(null);
        console.log('[PaymentQR] Generated successfully for:', address.slice(0, 12) + '...');
      })
      .catch((err) => {
        console.error('[PaymentQR] Generation failed:', err);
        setError(err.message || 'Failed to generate QR code');
      });
  }, [moneroUri, address, size]);

  const handleCopyUri = async () => {
    if (!moneroUri) return;
    try {
      await navigator.clipboard.writeText(moneroUri);
      setCopiedUri(true);
      setTimeout(() => setCopiedUri(false), 2000);
    } catch (err) {
      console.error('[PaymentQR] Copy failed:', err);
    }
  };

  const handleCopyAddress = async () => {
    if (!address) return;
    try {
      await navigator.clipboard.writeText(address);
      setCopiedAddress(true);
      setTimeout(() => setCopiedAddress(false), 2000);
    } catch (err) {
      console.error('[PaymentQR] Copy address failed:', err);
    }
  };

  // Loading state - no address yet
  if (!address) {
    return (
      <div
        className="bg-art-bg rounded-xl flex flex-col items-center justify-center"
        style={{ width: size, height: size }}
      >
        <QrCode className="w-12 h-12 text-black/20 animate-pulse" />
        <span className="text-[10px] text-black/30 mt-2 font-mono">Generating...</span>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-3">
      {/* QR Code Container */}
      <div className="p-4 bg-white rounded-2xl shadow-lg border border-black/5 relative group">
        {error ? (
          <div
            className="flex flex-col items-center justify-center text-red-500"
            style={{ width: size, height: size }}
          >
            <QrCode className="w-8 h-8 mb-2 opacity-50" />
            <span className="text-xs text-center">QR Error</span>
          </div>
        ) : (
          <>
            <canvas ref={canvasRef} className="rounded-lg" />
            {/* Overlay on hover */}
            <div className="absolute inset-0 bg-black/80 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity flex flex-col items-center justify-center gap-2 p-4">
              <span className="text-white text-xs font-mono text-center">
                Scan with Monero wallet
              </span>
              <div className="flex gap-2">
                <button
                  onClick={handleCopyUri}
                  className="px-3 py-1.5 bg-white/10 hover:bg-white/20 rounded-lg text-white text-[10px] font-mono flex items-center gap-1 transition-colors"
                >
                  {copiedUri ? <Check size={10} className="text-green-400" /> : <Copy size={10} />}
                  {copiedUri ? 'Copied!' : 'Copy URI'}
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Amount Display */}
      <div className="text-center">
        <div className="text-xl sm:text-2xl font-display font-bold text-black">
          {parseFloat(amount || '0').toFixed(4)} <span className="text-sm text-black/40">XMR</span>
        </div>
      </div>

      {/* Address Display */}
      <div className="w-full max-w-xs">
        <div className="bg-art-bg p-3 rounded-xl">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[9px] font-mono uppercase tracking-widest text-black/40">
              Multisig Address
            </span>
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 font-mono text-[10px] text-black break-all leading-relaxed select-all">
              {address}
            </code>
            <button
              onClick={handleCopyAddress}
              className="p-1.5 hover:bg-black/10 rounded-lg transition-colors shrink-0"
              title="Copy address"
            >
              {copiedAddress ? (
                <Check size={12} className="text-green-500" />
              ) : (
                <Copy size={12} className="text-black/40" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Helper Text */}
      <p className="text-[10px] text-black/40 text-center max-w-xs">
        Send the exact amount to this address. Payment will be confirmed automatically.
      </p>
    </div>
  );
};

export default PaymentQRCode;
