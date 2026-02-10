import { useState, useCallback } from 'react';
import { getWasmModule } from '../services/wasmService';

const SHIELD_MAGIC = 'NXSHLD\x02\x00';

export interface ShieldMetadata {
  escrowId: string;
  role: 'buyer' | 'vendor' | 'arbiter';
  backupId: string;
  groupPubkey: string;
  createdAt: number;
}

export interface ShieldStatus {
  hasShield: boolean;
  backupId?: string;
  createdAt?: string;
  verified: boolean;
  downloadCount: number;
}

export interface UseShieldResult {
  isGenerating: boolean;
  isRestoring: boolean;
  error: Error | null;
  generateShield: (escrowId: string, role: string, keyPackage: Uint8Array, password: string) => Promise<Blob>;
  restoreFromShield: (file: File, password: string) => Promise<{ keyPackage: Uint8Array; metadata: ShieldMetadata }>;
  registerShield: (escrowId: string, backupId: string, role: string) => Promise<void>;
  verifyShield: (escrowId: string, backupId: string) => Promise<boolean>;
  getShieldStatus: (escrowId: string) => Promise<ShieldStatus>;
}

const API_BASE = '/api';

export function useShield(): UseShieldResult {
  const [isGenerating, setIsGenerating] = useState(false);
  const [isRestoring, setIsRestoring] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Get encryption key for shield file
  // Uses session_key if available, otherwise derives from escrow context
  const getEncryptionKey = (escrowId: string, role: string): string => {
    // Try to get stored session key first
    const sessionKey = localStorage.getItem('session_key');
    if (sessionKey) {
      return sessionKey;
    }

    // Fallback: derive a deterministic key from escrow context
    // This is less secure but allows the feature to work
    // User should use the same browser/device to restore
    const derivedKey = `nexus-shield-${escrowId}-${role}-${navigator.userAgent.slice(0, 20)}`;
    console.warn('[Shield] Using derived encryption key - store session_key for better security');
    return derivedKey;
  };

  const generateShield = useCallback(
    async (escrowId: string, role: string, keyPackage: Uint8Array, password: string): Promise<Blob> => {
      console.log('[useShield] generateShield called:', { escrowId, role, keyPackageLen: keyPackage?.length });
      setIsGenerating(true);
      setError(null);

      try {
        // Use user-provided password as encryption key
        if (!password || password.length < 8) {
          throw new Error('Password must be at least 8 characters');
        }
        const encryptionKey = password;
        console.log('[useShield] Using user-provided password as encryption key');

        const wasm = getWasmModule();
        console.log('[useShield] WASM module:', wasm ? 'loaded' : 'NOT LOADED');

        if (!wasm) {
          throw new Error('WASM module not loaded');
        }

        // Derive deterministic backup ID
        console.log('[useShield] Deriving backup ID...');
        const backupId = wasm.derive_backup_id(escrowId, role);
        console.log('[useShield] Backup ID:', backupId);

        // Encrypt key package with encryption key
        console.log('[useShield] Encrypting key package...');
        const encryptedPayload = wasm.encrypt_key_for_backup(keyPackage, encryptionKey);
        console.log('[useShield] Encrypted payload length:', encryptedPayload?.length);

        // Build header (128 bytes)
        const header = new Uint8Array(128);
        const encoder = new TextEncoder();

        // Magic (8 bytes)
        const magic = encoder.encode(SHIELD_MAGIC);
        header.set(magic, 0);

        // Escrow ID (36 bytes)
        const escrowIdBytes = encoder.encode(escrowId.padEnd(36, '\0'));
        header.set(escrowIdBytes, 8);

        // Role (1 byte)
        const roleMap: Record<string, number> = { buyer: 1, vendor: 2, arbiter: 3 };
        header[44] = roleMap[role] || 0;

        // Backup ID (32 bytes)
        const backupIdBytes = encoder.encode(backupId.substring(0, 32));
        header.set(backupIdBytes, 45);

        // Created timestamp (8 bytes)
        const timestamp = BigInt(Date.now());
        const timestampView = new DataView(header.buffer);
        timestampView.setBigInt64(77, timestamp, true);

        // Combine header and encrypted payload
        const shieldFile = new Uint8Array(header.length + encryptedPayload.length);
        shieldFile.set(header);
        shieldFile.set(encryptedPayload, header.length);

        return new Blob([shieldFile], { type: 'application/x-nexus-shield' });
      } catch (err) {
        console.error('[useShield] ERROR:', err);
        const error = err instanceof Error ? err : new Error(String(err));
        setError(error);
        throw error;
      } finally {
        console.log('[useShield] Generation finished (success or error)');
        setIsGenerating(false);
      }
    },
    []
  );

  const restoreFromShield = useCallback(
    async (file: File, password: string): Promise<{ keyPackage: Uint8Array; metadata: ShieldMetadata }> => {
      setIsRestoring(true);
      setError(null);

      try {
        const wasm = getWasmModule();

        if (!wasm) {
          throw new Error('WASM module not loaded');
        }

        if (!password) {
          throw new Error('Password is required to decrypt Shield file');
        }

        const arrayBuffer = await file.arrayBuffer();
        const data = new Uint8Array(arrayBuffer);

        // Validate magic
        const decoder = new TextDecoder();
        const magic = decoder.decode(data.slice(0, 8));
        if (magic !== SHIELD_MAGIC) {
          throw new Error('Invalid Shield file format');
        }

        // Parse header
        const escrowId = decoder.decode(data.slice(8, 44)).replace(/\0/g, '');
        const roleNum = data[44];
        const roleMap: Record<number, 'buyer' | 'vendor' | 'arbiter'> = {
          1: 'buyer',
          2: 'vendor',
          3: 'arbiter',
        };
        const role = roleMap[roleNum];
        if (!role) {
          throw new Error('Invalid role in Shield file');
        }

        const backupId = decoder.decode(data.slice(45, 77));
        const timestampView = new DataView(data.buffer);
        const createdAt = Number(timestampView.getBigInt64(77, true));

        // Use user-provided password as encryption key
        const encryptionKey = password;

        // Decrypt
        const encryptedPayload = data.slice(128);
        const keyPackage = wasm.decrypt_key_from_backup(encryptedPayload, encryptionKey);

        return {
          keyPackage,
          metadata: { escrowId, role, backupId, groupPubkey: '', createdAt },
        };
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        setError(error);
        throw error;
      } finally {
        setIsRestoring(false);
      }
    },
    []
  );

  const registerShield = useCallback(async (escrowId: string, backupId: string, role: string): Promise<void> => {
    const response = await fetch(`${API_BASE}/escrow/frost/${escrowId}/shield/register`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ backup_id: backupId, role: role }),
    });

    if (!response.ok) {
      throw new Error(`Failed to register shield: ${response.statusText}`);
    }
  }, []);

  const verifyShield = useCallback(async (escrowId: string, backupId: string): Promise<boolean> => {
    const response = await fetch(`${API_BASE}/escrow/frost/${escrowId}/shield/verify`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ backup_id: backupId }),
    });

    if (!response.ok) return false;
    const data = await response.json();
    return data.valid === true;
  }, []);

  const getShieldStatus = useCallback(async (escrowId: string): Promise<ShieldStatus> => {
    const response = await fetch(`${API_BASE}/escrow/frost/${escrowId}/shield/status`, {
      credentials: 'include',
    });

    if (!response.ok) {
      throw new Error(`Failed to get shield status: ${response.statusText}`);
    }

    return response.json();
  }, []);

  return {
    isGenerating,
    isRestoring,
    error,
    generateShield,
    restoreFromShield,
    registerShield,
    verifyShield,
    getShieldStatus,
  };
}
