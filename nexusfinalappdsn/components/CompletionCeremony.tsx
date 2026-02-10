import React, { useState, useEffect, useCallback } from 'react';
import { CheckCircle, Download, Copy, Check } from 'lucide-react';
import { Role } from '../types';
import ScrambleText from './ScrambleText';

interface CompletionCeremonyProps {
  escrowId: string;
  amount: string;
  txHash: string | null;
  role: Role;
  onClose: () => void;
}

interface Particle {
  x: number;
  y: number;
  delay: number;
  size: number;
  color: string;
}

const PARTICLE_COLORS = [
  'bg-white', 'bg-white/80', 'bg-white/60',
  'bg-emerald-400', 'bg-emerald-300',
  'bg-amber-300',
];

const CompletionCeremony: React.FC<CompletionCeremonyProps> = ({
  escrowId,
  amount,
  txHash,
  role,
  onClose,
}) => {
  const [showReceipt, setShowReceipt] = useState(false);
  const [particles, setParticles] = useState<Particle[]>([]);
  const [copiedHash, setCopiedHash] = useState(false);

  useEffect(() => {
    // Generate confetti particles
    const pts: Particle[] = Array.from({ length: 50 }, () => ({
      x: Math.random() * 100,
      y: 30 + Math.random() * 60, // spread across middle-to-bottom
      delay: Math.random() * 1.5,
      size: 1 + Math.random() * 3,
      color: PARTICLE_COLORS[Math.floor(Math.random() * PARTICLE_COLORS.length)],
    }));
    setParticles(pts);

    // Stagger receipt card reveal
    const timer = setTimeout(() => setShowReceipt(true), 600);
    return () => clearTimeout(timer);
  }, []);

  const copyTxHash = useCallback(() => {
    if (txHash) {
      navigator.clipboard.writeText(txHash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  }, [txHash]);

  const handleDownloadReceipt = useCallback(() => {
    const timestamp = new Date().toISOString();
    const sessionShort = escrowId.replace('esc_', '').slice(-8).toUpperCase();
    const content = [
      '═══════════════════════════════════════════',
      '           ONYX ESCROW RECEIPT',
      '═══════════════════════════════════════════',
      '',
      `  Date:       ${timestamp}`,
      `  Session:    ${sessionShort} (${escrowId})`,
      `  Role:       ${role}`,
      `  Amount:     ${amount} XMR`,
      `  Protocol:   FROST RFC-9591 / CLSAG`,
      '',
      txHash ? `  TX Hash:    ${txHash}` : '  TX Hash:    (pending confirmation)',
      '',
      '───────────────────────────────────────────',
      '  Status:     SETTLED',
      '  Custody:    Non-custodial (2-of-3 multisig)',
      '  Server:     Blind relay — cannot spend funds',
      '───────────────────────────────────────────',
      '',
      '  This receipt confirms a completed escrow',
      '  transaction on the Monero blockchain.',
      '  The server never held custody of funds.',
      '',
      '  Powered by ONYX / NEXUS',
      '═══════════════════════════════════════════',
    ].join('\n');

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `onyx-receipt-${sessionShort}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }, [escrowId, amount, role, txHash]);

  return (
    <div className="fixed inset-0 z-50 bg-black flex items-center justify-center overflow-hidden">

      {/* Confetti particles — pure CSS */}
      {particles.map((p, i) => (
        <div
          key={i}
          className={`absolute rounded-full ${p.color} pointer-events-none`}
          style={{
            left: `${p.x}%`,
            top: `${p.y}%`,
            width: `${p.size}px`,
            height: `${p.size}px`,
            animation: `confetti ${2 + Math.random()}s ease-out ${p.delay}s forwards`,
            opacity: 0,
          }}
        />
      ))}

      {/* Central receipt card */}
      <div
        className={`transition-all duration-1000 ease-out ${
          showReceipt ? 'opacity-100 scale-100 translate-y-0' : 'opacity-0 scale-95 translate-y-4'
        }`}
      >
        <div className="bg-white text-black rounded-[2rem] p-8 md:p-12 max-w-md w-full mx-4 shadow-[0_0_120px_rgba(255,255,255,0.08)]">

          {/* Animated checkmark */}
          <div className="flex justify-center mb-8">
            <div className="relative w-20 h-20">
              {/* Circle draws itself */}
              <svg className="w-20 h-20" viewBox="0 0 80 80">
                <circle
                  cx="40" cy="40" r="36"
                  fill="none" stroke="#E5E5E5" strokeWidth="3"
                />
                <circle
                  cx="40" cy="40" r="36"
                  fill="none" stroke="black" strokeWidth="3"
                  strokeDasharray="226"
                  strokeDashoffset="226"
                  strokeLinecap="round"
                  style={{
                    animation: 'draw-circle 1s ease-out 0.3s forwards',
                    transformOrigin: 'center',
                    transform: 'rotate(-90deg)',
                  }}
                />
              </svg>
              {/* CheckCircle icon fades in after circle draws */}
              <div
                className="absolute inset-0 flex items-center justify-center"
                style={{ animation: 'scale-bounce 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) 1.1s both' }}
              >
                <CheckCircle className="w-8 h-8 text-black" strokeWidth={2} />
              </div>
            </div>
          </div>

          {/* Heading */}
          <h2 className="font-display font-bold text-3xl text-center tracking-tight mb-1">
            <ScrambleText text="SETTLED" />
          </h2>
          <p className="text-center text-black/40 font-mono text-[10px] uppercase tracking-widest mb-8">
            Non-custodial escrow complete
          </p>

          {/* Receipt data */}
          <div className="space-y-3 border-t border-b border-black/5 py-6">
            <ReceiptRow label="Amount" value={`${amount} XMR`} mono />
            <ReceiptRow label="Session" value={escrowId.replace('esc_', '').slice(-8).toUpperCase()} />
            <ReceiptRow label="Role" value={role} />
            {txHash && (
              <div className="flex justify-between items-center">
                <span className="text-[10px] font-mono uppercase tracking-widest text-black/40">TX Hash</span>
                <button
                  onClick={copyTxHash}
                  className="flex items-center gap-1.5 text-[10px] font-mono text-black/70 hover:text-black transition-colors group"
                >
                  <span>{txHash.slice(0, 12)}...{txHash.slice(-6)}</span>
                  {copiedHash ? (
                    <Check size={10} className="text-emerald-500" />
                  ) : (
                    <Copy size={10} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                  )}
                </button>
              </div>
            )}
            <ReceiptRow label="Protocol" value="FROST / CLSAG" />
          </div>

          {/* Actions */}
          <div className="flex gap-3 mt-8">
            <button
              onClick={handleDownloadReceipt}
              className="flex-1 py-3 bg-black text-white rounded-xl font-mono text-[10px] uppercase tracking-wider font-bold hover:bg-black/80 transition-colors flex items-center justify-center gap-2"
            >
              <Download size={14} />
              Receipt
            </button>
            <button
              onClick={onClose}
              className="flex-1 py-3 bg-black/5 text-black rounded-xl font-mono text-[10px] uppercase tracking-wider font-bold hover:bg-black/10 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Sub-component for receipt rows
const ReceiptRow: React.FC<{ label: string; value: string; mono?: boolean }> = ({ label, value, mono }) => (
  <div className="flex justify-between items-center">
    <span className="text-[10px] font-mono uppercase tracking-widest text-black/40">{label}</span>
    <span className={`text-xs ${mono ? 'font-mono' : 'font-display font-bold'} text-black/80`}>{value}</span>
  </div>
);

export default CompletionCeremony;
