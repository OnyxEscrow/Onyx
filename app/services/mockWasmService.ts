import { LogEntry } from '../types';

// Helper to generate a random hex string
const genHex = (length: number) => {
  let result = '';
  const characters = '0123456789ABCDEF';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
};

// Returns a promise that resolves after 'ms' milliseconds
export const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export const generateLog = (level: LogEntry['level'], message: string, hash?: string): LogEntry => ({
  id: crypto.randomUUID(),
  timestamp: new Date().toISOString().split('T')[1].slice(0, 8),
  level,
  message,
  hash
});

// Simulates the Distributed Key Generation ritual with "Labor Illusion" pacing
export const simulateDKG = async (onLog: (log: LogEntry) => void): Promise<boolean> => {
  // 0ms - 500ms: Secure Enclave
  onLog(generateLog('INFO', 'INITIATING SECURE ENCLAVE...'));
  await delay(600);
  
  // Handshake visualization support
  onLog(generateLog('INFO', 'SYNCHRONIZING NODES [3/3]...'));
  await delay(500);

  // 500ms - 1000ms: ZK Proofs (Math visualization)
  onLog(generateLog('INFO', 'GENERATING ZK-PROOFS...', `zk_proof_${genHex(8)}`));
  await delay(800);

  // 1000ms - 1500ms: Ring Signatures verification
  onLog(generateLog('INFO', 'VERIFYING POLYNOMIAL COMMITMENTS...'));
  await delay(600);

  onLog(generateLog('SUCCESS', 'DKG SEQUENCE COMPLETE. SHARDS DISTRIBUTED.'));
  return true;
};

// Simulates the Signing ritual with precise "Ceremony" timing
export const simulateSigning = async (onLog: (log: LogEntry) => void): Promise<boolean> => {
  onLog(generateLog('INFO', 'CONSTRUCTING ROUND-ROBIN CLSAG...'));
  await delay(500);

  onLog(generateLog('INFO', 'AGGREGATING PARTIAL SIGNATURES...'));
  await delay(800);

  onLog(generateLog('INFO', 'VERIFYING RING SIGNATURE COMPONENTS...'));
  await delay(600);

  onLog(generateLog('SUCCESS', 'TRANSACTION SIGNED & BROADCAST.', `tx_${genHex(16)}`));
  return true;
};