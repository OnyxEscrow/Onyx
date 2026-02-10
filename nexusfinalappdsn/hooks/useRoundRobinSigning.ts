/**
 * useRoundRobinSigning - React hook for non-custodial round-robin signing
 *
 * This hook orchestrates the round-robin signing flow where:
 * 1. First signer creates multisig_txset on their LOCAL wallet
 * 2. Server relays txset to second signer
 * 3. Second signer signs on their LOCAL wallet
 * 4. First signer completes and broadcasts
 *
 * Requirements:
 * - Each participant must have monero-wallet-rpc running locally
 * - Wallet must be synced and have the multisig keys
 *
 * This is 100% NON-CUSTODIAL - the server never touches private keys.
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import {
  initiateRoundRobinSigning,
  submitMultisigTxset,
  submitRoundRobinSignature,
  confirmRoundRobinBroadcast,
  getRoundRobinStatus,
  RoundRobinStatus,
  createWebSocket,
  WebSocketMessage,
} from '../services/apiService';
import { LogEntry } from '../types';

export type RRSigningPhase =
  | 'idle'
  | 'initiating'
  | 'waiting_txset'       // Waiting for first signer to create txset
  | 'txset_submitted'     // First signer submitted txset
  | 'waiting_signature'   // Waiting for second signer
  | 'signature_submitted' // Second signer submitted
  | 'broadcasting'        // First signer broadcasting
  | 'complete'
  | 'error';

export interface RRSigningState {
  phase: RRSigningPhase;
  escrowId: string | null;
  role: string | null;
  isFirstSigner: boolean;
  destinationAddress: string | null;
  serverStatus: RoundRobinStatus | null;
  dataToSign: string | null;  // multisig_txset or partial_signed_txset
  txHash: string | null;
  error: string | null;
}

export interface UseRoundRobinSigningResult {
  state: RRSigningState;
  // Actions for first signer
  initiateSigning: (escrowId: string, role: 'buyer' | 'vendor', destinationAddress: string) => Promise<void>;
  submitTxset: (multisigTxset: string) => Promise<void>;
  confirmBroadcast: (txHash: string) => Promise<void>;
  // Actions for second signer
  submitSignature: (partialSignedTxset: string) => Promise<void>;
  // Common
  refreshStatus: () => Promise<void>;
  reset: () => void;
}

const initialState: RRSigningState = {
  phase: 'idle',
  escrowId: null,
  role: null,
  isFirstSigner: false,
  destinationAddress: null,
  serverStatus: null,
  dataToSign: null,
  txHash: null,
  error: null,
};

export function useRoundRobinSigning(
  onLog?: (log: LogEntry) => void
): UseRoundRobinSigningResult {
  const [state, setState] = useState<RRSigningState>(initialState);
  const wsRef = useRef<WebSocket | null>(null);

  // Log helper
  const log = useCallback(
    (level: LogEntry['level'], message: string, hash?: string) => {
      if (onLog) {
        onLog({
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString().split('T')[1].slice(0, 8),
          level,
          message,
          hash,
        });
      }
    },
    [onLog]
  );

  // State update helper
  const updateState = useCallback((updates: Partial<RRSigningState>) => {
    setState((prev) => ({ ...prev, ...updates }));
  }, []);

  // Refresh status from server
  const refreshStatus = useCallback(async () => {
    if (!state.escrowId) return;

    try {
      const response = await getRoundRobinStatus(state.escrowId);
      if (!response.success || !response.data) {
        return;
      }

      const status = response.data;
      updateState({ serverStatus: status });

      // Update phase based on server status
      if (status.is_complete) {
        updateState({
          phase: 'complete',
          txHash: status.tx_hash,
        });
        log('SUCCESS', 'Transaction broadcast confirmed!', status.tx_hash?.slice(0, 16));
      } else if (status.phase === 'waiting_for_txset') {
        updateState({ phase: 'waiting_txset' });
      } else if (status.phase === 'waiting_for_second_signature') {
        updateState({
          phase: 'waiting_signature',
          dataToSign: status.data_to_sign,
        });
      } else if (status.phase === 'waiting_for_completion') {
        updateState({
          phase: 'signature_submitted',
          dataToSign: status.data_to_sign,
        });
      }
    } catch (error) {
      console.error('[RoundRobinSigning] Status refresh error:', error);
    }
  }, [state.escrowId, updateState, log]);

  // Handle WebSocket messages
  const handleWsMessage = useCallback(
    async (message: WebSocketMessage) => {
      if (!state.escrowId) return;

      if (message.escrow_id === state.escrowId) {
        if (message.type === 'RoundRobinTxsetSubmitted') {
          log('SUCCESS', 'First signer submitted txset. Ready for second signature.');
          await refreshStatus();
        } else if (message.type === 'RoundRobinSignatureSubmitted') {
          log('SUCCESS', 'Second signer submitted. Ready for broadcast.');
          await refreshStatus();
        } else if (message.type === 'BroadcastConfirmed') {
          const data = message.data as { tx_hash?: string };
          log('SUCCESS', 'Transaction confirmed!', data?.tx_hash?.slice(0, 16));
          updateState({
            phase: 'complete',
            txHash: data?.tx_hash || null,
          });
        }
      }
    },
    [state.escrowId, log, updateState, refreshStatus]
  );

  // Set up WebSocket connection
  useEffect(() => {
    if (state.escrowId && !wsRef.current) {
      wsRef.current = createWebSocket(handleWsMessage);
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [state.escrowId, handleWsMessage]);

  // Poll for status updates
  useEffect(() => {
    if (state.phase === 'idle' || state.phase === 'complete' || state.phase === 'error') {
      return;
    }

    const pollInterval = setInterval(refreshStatus, 5000);
    return () => clearInterval(pollInterval);
  }, [state.phase, refreshStatus]);

  // Initiate signing (first signer)
  const initiateSigning = useCallback(
    async (escrowId: string, role: 'buyer' | 'vendor', destinationAddress: string) => {
      try {
        updateState({
          ...initialState,
          phase: 'initiating',
          escrowId,
          role,
          isFirstSigner: true,
          destinationAddress,
        });
        log('INFO', `Initiating ${role === 'vendor' ? 'release' : 'refund'} signing...`);

        const response = await initiateRoundRobinSigning(escrowId, destinationAddress, role);
        if (!response.success) {
          throw new Error(response.error || 'Failed to initiate signing');
        }

        updateState({ phase: 'waiting_txset' });
        log('INFO', 'Signing initialized. Create multisig_txset on your LOCAL wallet.');
        log('INFO', 'Use: monero-wallet-rpc transfer <address> <amount>');

      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log('CRITICAL', `Initiation failed: ${message}`);
        updateState({ phase: 'error', error: message });
      }
    },
    [updateState, log]
  );

  // Submit txset (first signer)
  const submitTxset = useCallback(
    async (multisigTxset: string) => {
      if (!state.escrowId) {
        log('WARN', 'No active signing session');
        return;
      }

      try {
        updateState({ phase: 'txset_submitted' });
        log('INFO', 'Submitting multisig_txset to server...');

        const response = await submitMultisigTxset(state.escrowId, multisigTxset);
        if (!response.success) {
          throw new Error(response.error || 'Failed to submit txset');
        }

        log('SUCCESS', 'Txset submitted. Waiting for second signer...');
        updateState({ phase: 'waiting_signature' });

      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log('CRITICAL', `Txset submission failed: ${message}`);
        updateState({ phase: 'error', error: message });
      }
    },
    [state.escrowId, updateState, log]
  );

  // Submit signature (second signer)
  const submitSignature = useCallback(
    async (partialSignedTxset: string) => {
      if (!state.escrowId) {
        log('WARN', 'No active signing session');
        return;
      }

      try {
        log('INFO', 'Submitting partial signature to server...');

        const response = await submitRoundRobinSignature(state.escrowId, partialSignedTxset);
        if (!response.success) {
          throw new Error(response.error || 'Failed to submit signature');
        }

        log('SUCCESS', 'Signature submitted. First signer can now broadcast.');
        updateState({ phase: 'signature_submitted' });

      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log('CRITICAL', `Signature submission failed: ${message}`);
        updateState({ phase: 'error', error: message });
      }
    },
    [state.escrowId, updateState, log]
  );

  // Confirm broadcast (first signer)
  const confirmBroadcast = useCallback(
    async (txHash: string) => {
      if (!state.escrowId) {
        log('WARN', 'No active signing session');
        return;
      }

      try {
        updateState({ phase: 'broadcasting' });
        log('INFO', 'Confirming broadcast...');

        const response = await confirmRoundRobinBroadcast(state.escrowId, txHash);
        if (!response.success) {
          throw new Error(response.error || 'Failed to confirm broadcast');
        }

        log('SUCCESS', 'Transaction confirmed on blockchain!', txHash.slice(0, 16));
        updateState({
          phase: 'complete',
          txHash,
        });

      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log('CRITICAL', `Broadcast confirmation failed: ${message}`);
        updateState({ phase: 'error', error: message });
      }
    },
    [state.escrowId, updateState, log]
  );

  // Reset state
  const reset = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setState(initialState);
  }, []);

  return {
    state,
    initiateSigning,
    submitTxset,
    submitSignature,
    confirmBroadcast,
    refreshStatus,
    reset,
  };
}
