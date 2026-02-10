import React, { useState, useEffect, useRef } from 'react';

const QUIPS = [
  'Multisig your potatoes',
  'Funds somewhere between here and there',
  'Escrow for your thoughts',
  'Mining your own business',
  'Proof of steak',
  'Consensus among vegetables',
  'Hashing it out with reality',
  'Your keys are probably fine',
  'Wallet.exe has stopped caring',
  'Nodes nodding off',
  'Transaction pending since birth',
  'Signatures collecting dust',
  'The blockchain suggests therapy',
  'Zero knowledge, zero problems',
  'Fork in the road ahead',
  'Mining for compliments',
  'Your balance is conceptually yours',
  'Escrow is just friendship with paperwork',
  'Three of three shrugging',
  'Cryptographically secure feelings',
  'Funds temporarily eternal',
  'The mempool of consciousness',
  'Validating your parking',
  'Keys under the digital doormat',
  'Consensus is a social construct',
  'Your coins exist theoretically',
  'Escrow in the middle of nowhere',
  'Multisig your vegetables first',
  'Proof of work-life balance',
  'Hashing out the details later',
  'Nodes having a moment',
  'Transaction lost in translation',
  'Signatures but no autographs',
  'The blockchain of command',
  'Zero confirmations, maximum doubt',
  'Fork it, we\'ll do it live',
  'Mining for meaning',
  'Your balance is having doubts',
  'Escrow with extra steps',
  'Two of three ain\'t bad',
  'Cryptographically probable',
  'Funds in a quantum state',
  'The mempool of broken dreams',
  'Validating your existence',
  'Keys to the kingdom of nothing',
  'Mining for approval',
  'Your coins in witness protection',
  'Escrow as a lifestyle choice',
  'Multisig your expectations',
  'Proof of trying',
  'Hashing browns for breakfast',
  'Nodes knowing nothing',
  'Transaction in a relationship',
  'Signatures without commitment',
  'The blockchain of memories',
  'Zero balance, full vibes',
  'Fork around and find out',
  'Your balance on vacation',
  'Escrow is just spicy holding',
  'Three signatures, no witnesses',
  'Cryptographically confused',
  'Funds having an identity crisis',
  'The mempool of regret',
  'Keys to someone else\'s car',
  'Consensus among chaos',
  'Your coins taking a break',
  'Escrow without the crow',
  'Multisig your feelings',
  'Proof of stake in society',
  'Nodes pretending to care',
  'Transaction having second thoughts',
  'Signatures with commitment issues',
  'Zero effort, maximum security',
  'Mining compliments from strangers',
  'Your balance needs balance',
  'Three blind signatures',
  'Cryptographically challenged',
  'Funds fundamentally misunderstood',
  'The mempool of destiny',
  'Validating the validators',
  'Consensus consensually',
  'Your coins flipping themselves',
  'Escrow is tomorrow',
  'Multisig your sandwich',
  'Proof of pudding',
  'Nodes anonymously famous',
  'Transaction attracting inaction',
  'Signatures significantly insignificant',
  'The blockchain of jokes',
  'Zero to hero to zero',
  'Your balance imbalanced',
  'Escrow? More like es-later',
  'Three amigos, no signatures',
  'Funds fun while they lasted',
  'The mempool of maybe',
  'Your coins in coin heaven',
  'Multisig your multisig',
  'Proof of poof',
  'Nodes known to be unknown',
  'Transaction transacting badly',
  'Signatures signing in cursive',
];

interface FundingQuipsProps {
  active: boolean;
}

const FundingQuips: React.FC<FundingQuipsProps> = ({ active }) => {
  const [text, setText] = useState('');
  const [quipIndex, setQuipIndex] = useState(() => Math.floor(Math.random() * QUIPS.length));
  const [phase, setPhase] = useState<'typing' | 'pause' | 'erasing'>('typing');
  const charIndex = useRef(0);

  useEffect(() => {
    if (!active) {
      setText('');
      charIndex.current = 0;
      setPhase('typing');
      return;
    }

    const quip = QUIPS[quipIndex];

    if (phase === 'typing') {
      if (charIndex.current >= quip.length) {
        setPhase('pause');
        return;
      }
      const timer = setTimeout(() => {
        charIndex.current++;
        setText(quip.slice(0, charIndex.current));
      }, 45 + Math.random() * 30);
      return () => clearTimeout(timer);
    }

    if (phase === 'pause') {
      const timer = setTimeout(() => setPhase('erasing'), 2000);
      return () => clearTimeout(timer);
    }

    if (phase === 'erasing') {
      if (charIndex.current <= 0) {
        setQuipIndex((prev) => {
          let next = prev + 1 + Math.floor(Math.random() * 3);
          return next % QUIPS.length;
        });
        setPhase('typing');
        return;
      }
      const timer = setTimeout(() => {
        charIndex.current--;
        setText(QUIPS[quipIndex].slice(0, charIndex.current));
      }, 20);
      return () => clearTimeout(timer);
    }
  }, [active, phase, text, quipIndex]);

  if (!active || !text) return null;

  return (
    <span className="text-[11px] font-mono text-black/25 italic">
      {text}<span className="animate-pulse">|</span>
    </span>
  );
};

export default FundingQuips;
