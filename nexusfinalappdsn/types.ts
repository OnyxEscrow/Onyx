export enum EscrowStep {
  IDLE = 'IDLE',
  INITIATING = 'INITIATING',
  DKG_WAITING = 'DKG_WAITING',
  DKG_RUNNING = 'DKG_RUNNING',
  FUNDING = 'FUNDING',
  ACTIVE = 'ACTIVE',
  DELIVERED = 'DELIVERED',
  DISPUTE = 'DISPUTE',
  DISPUTE_RESOLVED = 'DISPUTE_RESOLVED',
  RELEASE_SIGNING = 'RELEASE_SIGNING',
  COMPLETED = 'COMPLETED'
}

export enum Role {
  BUYER = 'BUYER',
  VENDOR = 'VENDOR',
  ARBITER = 'ARBITER'
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'INFO' | 'WARN' | 'SUCCESS' | 'CRITICAL';
  message: string;
  hash?: string;
}

export interface PeerStatus {
  role: Role;
  connected: boolean;
  hasKeyShare: boolean;
}