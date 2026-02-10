/**
 * useFrostDkg - React hook for FROST DKG orchestration
 *
 * Handles the complete DKG flow:
 * 1. Initialize WASM + API
 * 2. Generate Round 1 package (WASM)
 * 3. Submit Round 1 to server
 * 4. Wait for all parties
 * 5. Process Round 2 (WASM)
 * 6. Submit Round 2 to server
 * 7. Wait for all parties
 * 8. Finalize (WASM Round 3)
 * 9. Store encrypted key locally
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import {
  initWasm,
  isWasmReady,
  frostDkgPart1,
  frostDkgPart2,
  frostDkgPart3,
  frostDeriveAddress,
  roleToParticipantIndex,
} from '../services/wasmService';
import {
  initFrostDkg,
  submitRound1,
  getRound1Packages,
  submitRound2,
  getRound2Packages,
  completeDkg,
  getDkgStatus,
  DkgStatus,
  createWebSocket,
  WebSocketMessage,
} from '../services/apiService';
import { storeKey } from '../services/keyStorage';
import { LogEntry } from '../types';

export type DkgPhase =
  | 'idle'
  | 'initializing'
  | 'round1_generating'
  | 'round1_submitting'
  | 'round1_waiting'
  | 'round2_generating'
  | 'round2_submitting'
  | 'round2_waiting'
  | 'round3_finalizing'
  | 'storing_key'
  | 'complete'
  | 'error';

export interface DkgState {
  phase: DkgPhase;
  escrowId: string | null;
  role: string | null;
  participantIndex: number | null;
  secretPackage: string | null;
  round1Package: string | null;
  round2Secret: string | null;
  keyPackage: string | null;
  groupPublicKey: string | null;
  multisigAddress: string | null;
  serverStatus: DkgStatus | null;
  error: string | null;
}

export interface UseFrostDkgResult {
  state: DkgState;
  startDkg: (escrowId: string, role: string, backupPassword: string) => Promise<void>;
  retryFromPhase: () => Promise<void>;
  reset: () => void;
}

const initialState: DkgState = {
  phase: 'idle',
  escrowId: null,
  role: null,
  participantIndex: null,
  secretPackage: null,
  round1Package: null,
  round2Secret: null,
  keyPackage: null,
  groupPublicKey: null,
  multisigAddress: null,
  serverStatus: null,
  error: null,
};

export function useFrostDkg(
  onLog: (log: LogEntry) => void
): UseFrostDkgResult {
  const [state, setState] = useState<DkgState>(initialState);
  const wsRef = useRef<WebSocket | null>(null);
  const backupPasswordRef = useRef<string>('');

  // Refs for synchronous access (React state updates are async)
  const escrowIdRef = useRef<string | null>(null);
  const roleRef = useRef<string | null>(null);
  const participantIndexRef = useRef<number | null>(null);
  const secretPackageRef = useRef<string | null>(null);
  const round2SecretRef = useRef<string | null>(null);

  // Function refs to avoid circular dependencies
  const processRound2Ref = useRef<() => Promise<void>>();
  const finalizeRound3Ref = useRef<() => Promise<void>>();

  // Generate log entry
  const log = useCallback(
    (level: LogEntry['level'], message: string, hash?: string) => {
      onLog({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString().split('T')[1].slice(0, 8),
        level,
        message,
        hash,
      });
    },
    [onLog]
  );

  // Update state helper - also updates refs for synchronous access
  const updateState = useCallback((updates: Partial<DkgState>) => {
    // Update refs synchronously
    if (updates.escrowId !== undefined) escrowIdRef.current = updates.escrowId;
    if (updates.role !== undefined) roleRef.current = updates.role;
    if (updates.participantIndex !== undefined) participantIndexRef.current = updates.participantIndex;
    if (updates.secretPackage !== undefined) secretPackageRef.current = updates.secretPackage;
    if (updates.round2Secret !== undefined) round2SecretRef.current = updates.round2Secret;
    // Update React state (async)
    setState((prev) => ({ ...prev, ...updates }));
  }, []);

  // Finalize Round 3 (called when all Round 2 packages are available)
  // MUST be defined before processRound2 since processRound2 calls it
  const finalizeRound3 = useCallback(async () => {
    const escrowId = escrowIdRef.current;
    const role = roleRef.current;
    const round2Secret = round2SecretRef.current;
    const participantIndex = participantIndexRef.current;

    if (!escrowId || !role || !round2Secret) {
      log('WARN', 'finalizeRound3 called but missing required data');
      return;
    }

    try {
      updateState({ phase: 'round3_finalizing' });
      log('INFO', 'Finalizing key generation (Round 3)...');

      // Get all Round 1 and Round 2 packages
      const round1Response = await getRound1Packages(escrowId);
      const round2Response = await getRound2Packages(escrowId, role);

      if (!round1Response.success || !round1Response.data) {
        throw new Error(round1Response.error || 'Failed to get Round 1 packages');
      }
      if (!round2Response.success || !round2Response.data) {
        throw new Error(round2Response.error || 'Failed to get Round 2 packages');
      }

      // FROST DKG Part 3 expects only OTHER participants' Round 1 packages (not our own)
      const myIndex = participantIndex?.toString() || roleToParticipantIndex(role).toString();
      const otherRound1Packages: Record<string, string> = {};
      for (const [idx, pkg] of Object.entries(round1Response.data)) {
        if (idx !== myIndex) {
          otherRound1Packages[idx] = pkg;
        }
      }

      // Finalize DKG using WASM
      const finalResult = frostDkgPart3(
        round2Secret,
        otherRound1Packages,
        round2Response.data
      );

      log('SUCCESS', 'Key share generated!', finalResult.group_public_key.slice(0, 16));

      // Derive the Monero address and view key from the group public key
      // CRITICAL: This must match what the UI displays to the user!
      const derivedAddress = frostDeriveAddress(finalResult.group_public_key, escrowId, 'mainnet');
      log('INFO', `Derived address: ${derivedAddress.address.slice(0, 20)}...`);

      // Store key locally with encryption
      updateState({
        phase: 'storing_key',
        keyPackage: finalResult.key_package,
        groupPublicKey: finalResult.group_public_key,
      });
      log('INFO', 'Encrypting and storing key locally...');

      await storeKey(
        escrowId,
        role,
        finalResult.key_package,
        backupPasswordRef.current
      );
      log('SUCCESS', 'Key securely stored in browser.');

      // Notify server that DKG is complete with the REAL address and view key
      // This fixes the critical bug where server-derived values differed from WASM-derived values
      const completeResponse = await completeDkg(
        escrowId,
        finalResult.group_public_key,
        derivedAddress.address,           // Real address from WASM
        derivedAddress.view_key_private   // Real view key from WASM
      );

      if (!completeResponse.success) {
        throw new Error(completeResponse.error || 'Failed to complete DKG on server');
      }

      updateState({
        phase: 'complete',
        serverStatus: completeResponse.data || null,
      });
      log('SUCCESS', 'DKG Complete! Multisig wallet is ready.');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      log('CRITICAL', `Finalization failed: ${message}`);
      updateState({ phase: 'error', error: message });
    }
  }, [log, updateState]);

  // Store in ref for access from other callbacks
  finalizeRound3Ref.current = finalizeRound3;

  // Process Round 2 (called when all Round 1 packages are available)
  const processRound2 = useCallback(async () => {
    const escrowId = escrowIdRef.current;
    const role = roleRef.current;
    const secretPackage = secretPackageRef.current;
    const participantIndex = participantIndexRef.current;

    if (!escrowId || !role || !secretPackage) {
      log('WARN', 'processRound2 called but missing required data');
      return;
    }

    try {
      updateState({ phase: 'round2_generating' });
      log('INFO', 'Generating Round 2 packages...');

      // Get all Round 1 packages from server
      const round1Response = await getRound1Packages(escrowId);
      if (!round1Response.success || !round1Response.data) {
        throw new Error(round1Response.error || 'Failed to get Round 1 packages');
      }

      // FROST DKG Part 2 expects only OTHER participants' packages (not our own)
      const myIndex = participantIndex?.toString() || roleToParticipantIndex(role).toString();
      const otherRound1Packages: Record<string, string> = {};
      for (const [idx, pkg] of Object.entries(round1Response.data)) {
        if (idx !== myIndex) {
          otherRound1Packages[idx] = pkg;
        }
      }
      log('INFO', `Processing ${Object.keys(otherRound1Packages).length} other Round 1 packages...`);

      // DEBUG: Log inputs to WASM
      console.log('[DKG DEBUG] secretPackage length:', secretPackage.length);
      console.log('[DKG DEBUG] otherRound1Packages keys:', Object.keys(otherRound1Packages));
      console.log('[DKG DEBUG] otherRound1Packages value lengths:',
        Object.entries(otherRound1Packages).map(([k, v]) => `${k}:${v.length}`));

      // Generate Round 2 packages using WASM
      const round2Result = frostDkgPart2(secretPackage, otherRound1Packages);

      // DEBUG: Log WASM output
      console.log('[DKG DEBUG] round2Result:', round2Result);
      console.log('[DKG DEBUG] round2_packages keys:', Object.keys(round2Result.round2_packages || {}));
      console.log('[DKG DEBUG] round2_packages:', JSON.stringify(round2Result.round2_packages));
      console.log('[DKG DEBUG] round2_secret length:', round2Result.round2_secret?.length || 0);

      log('SUCCESS', 'Round 2 packages generated.');

      updateState({
        phase: 'round2_submitting',
        round2Secret: round2Result.round2_secret,
      });
      log('INFO', 'Submitting Round 2 packages to server...');

      // DEBUG: What we're about to send
      console.log('[DKG DEBUG] Submitting to server:');
      console.log('[DKG DEBUG]   escrowId:', escrowId);
      console.log('[DKG DEBUG]   role:', role);
      console.log('[DKG DEBUG]   packages:', JSON.stringify(round2Result.round2_packages));

      // Submit Round 2 packages
      const submitResponse = await submitRound2(
        escrowId,
        role,
        round2Result.round2_packages
      );

      console.log('[DKG DEBUG] Submit response:', submitResponse);
      if (!submitResponse.success) {
        throw new Error(submitResponse.error || 'Failed to submit Round 2');
      }

      updateState({
        phase: 'round2_waiting',
        serverStatus: submitResponse.data || null,
      });

      if (submitResponse.data?.round2_complete) {
        log('SUCCESS', 'Round 2 complete! Proceeding to finalization...');
        // Use ref to call finalizeRound3
        if (finalizeRound3Ref.current) {
          await finalizeRound3Ref.current();
        }
      } else {
        log('INFO', 'Waiting for other parties to submit Round 2...');
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      log('CRITICAL', `Round 2 failed: ${message}`);
      updateState({ phase: 'error', error: message });
    }
  }, [log, updateState]);

  // Store in ref for access from other callbacks
  processRound2Ref.current = processRound2;

  // WebSocket message handler
  const handleWsMessage = useCallback(
    async (message: WebSocketMessage) => {
      const escrowId = escrowIdRef.current;
      if (!escrowId) return;

      // Handle DKG-related events
      if (message.type === 'FrostDkgRound1Complete' && message.escrow_id === escrowId) {
        log('SUCCESS', 'All parties submitted Round 1. Proceeding to Round 2...');
        if (processRound2Ref.current) {
          await processRound2Ref.current();
        }
      } else if (message.type === 'FrostDkgRound2Complete' && message.escrow_id === escrowId) {
        log('SUCCESS', 'All parties submitted Round 2. Finalizing DKG...');
        if (finalizeRound3Ref.current) {
          await finalizeRound3Ref.current();
        }
      } else if (message.type === 'FrostDkgComplete' && message.escrow_id === escrowId) {
        log('SUCCESS', 'DKG Complete! Multisig wallet ready.');
        updateState({ phase: 'complete' });
      }
    },
    [log, updateState]
  );

  // Main DKG entry point
  const startDkg = useCallback(
    async (escrowId: string, role: string, backupPassword: string) => {
      try {
        backupPasswordRef.current = backupPassword;

        // Phase: Initializing
        updateState({
          ...initialState,
          phase: 'initializing',
          escrowId,
          role,
          participantIndex: roleToParticipantIndex(role),
        });
        log('INFO', 'Initializing FROST Protocol...');

        // Initialize WASM if needed
        if (!isWasmReady()) {
          await initWasm();
          log('SUCCESS', 'Cryptographic module loaded.');
        }

        // Initialize DKG on server
        const initResponse = await initFrostDkg(escrowId);
        if (!initResponse.success) {
          throw new Error(initResponse.error || 'Failed to initialize DKG');
        }
        updateState({ serverStatus: initResponse.data || null });

        // Phase: Round 1 Generation
        updateState({ phase: 'round1_generating' });
        log('INFO', 'Generating Round 1 commitment...');

        const participantIndex = roleToParticipantIndex(role);
        const round1Result = frostDkgPart1(participantIndex, 2, 3);
        log('SUCCESS', 'Round 1 package generated.', round1Result.round1_package.slice(0, 16));

        updateState({
          secretPackage: round1Result.secret_package,
          round1Package: round1Result.round1_package,
          phase: 'round1_submitting',
        });

        // Phase: Submit Round 1
        log('INFO', 'Submitting Round 1 to server...');
        const submitResponse = await submitRound1(escrowId, role, round1Result.round1_package);
        if (!submitResponse.success) {
          throw new Error(submitResponse.error || 'Failed to submit Round 1');
        }

        updateState({ serverStatus: submitResponse.data || null });

        // Check if all parties have submitted
        if (submitResponse.data?.round1_complete) {
          log('SUCCESS', 'All parties submitted Round 1. Proceeding to Round 2...');
          if (processRound2Ref.current) {
            await processRound2Ref.current();
          }
        } else {
          updateState({ phase: 'round1_waiting' });
          log('INFO', 'Waiting for other parties to submit Round 1...');

          // Set up WebSocket for real-time updates
          if (!wsRef.current) {
            wsRef.current = createWebSocket(handleWsMessage);
          }
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log('CRITICAL', `DKG initialization failed: ${message}`);
        updateState({ phase: 'error', error: message });
      }
    },
    [log, updateState, handleWsMessage]
  );

  // Retry from current phase
  const retryFromPhase = useCallback(async () => {
    const escrowId = escrowIdRef.current;
    const role = roleRef.current;

    if (!escrowId || !role) {
      log('WARN', 'Cannot retry: no active DKG session.');
      return;
    }

    log('INFO', `Retrying from phase: ${state.phase}...`);
    updateState({ error: null });

    switch (state.phase) {
      case 'error':
      case 'round1_waiting':
        if (processRound2Ref.current) {
          await processRound2Ref.current();
        }
        break;
      case 'round2_waiting':
        if (finalizeRound3Ref.current) {
          await finalizeRound3Ref.current();
        }
        break;
      default:
        log('WARN', 'Cannot retry from this phase. Please restart DKG.');
    }
  }, [state.phase, log, updateState]);

  // Reset state
  const reset = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    // Clear all refs
    backupPasswordRef.current = '';
    escrowIdRef.current = null;
    roleRef.current = null;
    participantIndexRef.current = null;
    secretPackageRef.current = null;
    round2SecretRef.current = null;
    setState(initialState);
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  // Poll for status updates when waiting
  useEffect(() => {
    if (state.phase !== 'round1_waiting' && state.phase !== 'round2_waiting') {
      return;
    }

    const escrowId = escrowIdRef.current;
    if (!escrowId) return;

    const pollInterval = setInterval(async () => {
      try {
        const statusResponse = await getDkgStatus(escrowId);
        if (!statusResponse.success || !statusResponse.data) return;

        const status = statusResponse.data;
        updateState({ serverStatus: status });

        // Check if we can proceed
        if (state.phase === 'round1_waiting' && status.round1_complete) {
          clearInterval(pollInterval);
          log('SUCCESS', 'All Round 1 packages received!');
          if (processRound2Ref.current) {
            await processRound2Ref.current();
          }
        } else if (state.phase === 'round2_waiting' && status.round2_complete) {
          clearInterval(pollInterval);
          log('SUCCESS', 'All Round 2 packages received!');
          if (finalizeRound3Ref.current) {
            await finalizeRound3Ref.current();
          }
        }
      } catch (error) {
        console.error('[DKG Poll] Error:', error);
      }
    }, 3000); // Poll every 3 seconds

    return () => clearInterval(pollInterval);
  }, [state.phase, log, updateState]);

  return {
    state,
    startDkg,
    retryFromPhase,
    reset,
  };
}
