/**
 * useFrostSigning - React hook for FROST signing orchestration
 *
 * Handles the threshold signing flow:
 * 1. Load key from storage
 * 2. Compute Lagrange coefficient
 * 3. Generate partial key image
 * 4. Generate nonce commitment
 * 5. Submit to server
 * 6. Wait for other signer
 * 7. Aggregate and broadcast
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import {
  initWasm,
  isWasmReady,
  computeLagrangeCoefficient,
  computePartialKeyImage,
  computePartialKeyImageWithDerivation,
  aggregateKeyImages,
  generateNonceCommitment,
  aggregateNonces,
  roleToParticipantIndex,
  frostExtractSecretShare,
  frostDeriveAddress,
  createPartialTx,
  createPartialTxWithDerivation,
  completePartialTx,
  signClsagPartial,
  verifyClsag,
  type ClsagSignature,
  type PartialTxData,
} from '../services/wasmService';
import {
  initiateSigningSession,
  submitPartialSignature,
  getSigningStatus,
  broadcastTransaction,
  getLagrangeCoefficients,
  prepareSign,
  submitSignature,
  SigningSession,
  createWebSocket,
  WebSocketMessage,
  type PrepareSignResponse,
} from '../services/apiService';
import { loadKey } from '../services/keyStorage';
import { LogEntry } from '../types';

export type SigningPhase =
  | 'idle'
  | 'loading_key'
  | 'generating_signature'
  | 'submitting'
  | 'waiting_cosigner'
  | 'aggregating'
  | 'broadcasting'
  | 'complete'
  | 'error';

export interface SigningState {
  phase: SigningPhase;
  escrowId: string | null;
  role: string | null;
  action: 'release' | 'refund' | null;
  partialSignature: ClsagSignature | null;
  partialKeyImage: string | null;
  nonceCommitment: string | null;
  txHash: string | null;
  serverStatus: SigningSession | null;
  error: string | null;
  // Signing data for round-robin flow
  secretShare: string | null;
  groupPublicKey: string | null;
  partialTxData: PartialTxData | null;
}

export interface UseFrostSigningResult {
  state: SigningState;
  startSigning: (
    escrowId: string,
    role: string,
    action: 'release' | 'refund',
    password: string,
    coSignerRole: string
  ) => Promise<void>;
  retry: () => Promise<void>;
  reset: () => void;
}

const initialState: SigningState = {
  phase: 'idle',
  escrowId: null,
  role: null,
  action: null,
  partialSignature: null,
  partialKeyImage: null,
  nonceCommitment: null,
  txHash: null,
  serverStatus: null,
  error: null,
  secretShare: null,
  groupPublicKey: null,
  partialTxData: null,
};

export function useFrostSigning(
  onLog: (log: LogEntry) => void
): UseFrostSigningResult {
  const [state, setState] = useState<SigningState>(initialState);
  const wsRef = useRef<WebSocket | null>(null);
  const passwordRef = useRef<string>('');
  const coSignerRef = useRef<string>('');

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

  // Update state helper
  const updateState = useCallback((updates: Partial<SigningState>) => {
    setState((prev) => ({ ...prev, ...updates }));
  }, []);

  // Handle WebSocket messages
  const handleWsMessage = useCallback(
    async (message: WebSocketMessage) => {
      if (!state.escrowId) return;

      if (message.type === 'SignatureSubmitted' && message.escrow_id === state.escrowId) {
        log('SUCCESS', 'Co-signer submitted their signature!');
        await checkForAggregation();
      } else if (message.type === 'ReadyToBroadcast' && message.escrow_id === state.escrowId) {
        log('SUCCESS', 'Signatures aggregated. Broadcasting transaction...');
        await broadcast();
      } else if (message.type === 'BroadcastSuccess' && message.escrow_id === state.escrowId) {
        const data = message.data as { tx_hash?: string };
        log('SUCCESS', 'Transaction broadcast!', data?.tx_hash?.slice(0, 16));
        updateState({
          phase: 'complete',
          txHash: data?.tx_hash || null,
        });
      }
    },
    [state.escrowId, log, updateState]
  );

  // Check if we can aggregate signatures
  const checkForAggregation = useCallback(async () => {
    if (!state.escrowId) return;

    try {
      const statusResponse = await getSigningStatus(state.escrowId);
      if (!statusResponse.success || !statusResponse.data) return;

      const session = statusResponse.data;
      updateState({ serverStatus: session });

      if (session.signatures_collected >= session.signatures_required) {
        log('SUCCESS', 'All signatures collected. Aggregating...');
        await broadcast();
      }
    } catch (error) {
      console.error('[Signing] Check aggregation error:', error);
    }
  }, [state.escrowId, log, updateState]);

  // Broadcast transaction
  const broadcast = useCallback(async () => {
    if (!state.escrowId) return;

    try {
      updateState({ phase: 'broadcasting' });
      log('INFO', 'Broadcasting transaction to Monero network...');

      const response = await broadcastTransaction(state.escrowId);
      if (!response.success) {
        throw new Error(response.error || 'Broadcast failed');
      }

      log('SUCCESS', 'Transaction confirmed!', response.data?.tx_hash?.slice(0, 16));
      updateState({
        phase: 'complete',
        txHash: response.data?.tx_hash || null,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      log('CRITICAL', `Broadcast failed: ${message}`);
      updateState({ phase: 'error', error: message });
    }
  }, [state.escrowId, log, updateState]);

  // Main signing entry point
  const startSigning = useCallback(
    async (
      escrowId: string,
      role: string,
      action: 'release' | 'refund',
      password: string,
      coSignerRole: string
    ) => {
      try {
        passwordRef.current = password;
        coSignerRef.current = coSignerRole;

        updateState({
          ...initialState,
          phase: 'loading_key',
          escrowId,
          role,
          action,
        });
        log('INFO', 'Loading encrypted key share...');

        // Ensure WASM is ready
        if (!isWasmReady()) {
          await initWasm();
        }

        // Load key from storage
        const keyPackageHex = await loadKey(escrowId, password);
        if (!keyPackageHex) {
          throw new Error('Key not found or wrong password');
        }
        log('SUCCESS', 'Key decrypted successfully.');

        // Extract secret share from key package
        const secretShare = frostExtractSecretShare(keyPackageHex);
        log('INFO', 'Secret share extracted from key package.');

        // Get signing data from server (ring, tx_prefix_hash, etc.)
        log('INFO', 'Fetching signing data from server...');
        const prepareResponse = await prepareSign(escrowId);
        if (!prepareResponse.success || !prepareResponse.data) {
          throw new Error(prepareResponse.error || 'Failed to prepare signing data');
        }

        const signingData = prepareResponse.data;
        log('SUCCESS', 'Signing data received from server.');

        updateState({
          secretShare,
          groupPublicKey: signingData.multisig_spend_pub_key || null,
        });

        // Generate signature
        updateState({ phase: 'generating_signature' });
        log('INFO', 'Computing partial signature using WASM...');

        // Get participant indices
        const myIndex = roleToParticipantIndex(role);
        const coSignerIndex = roleToParticipantIndex(coSignerRole);

        // Use Lagrange coefficient from server if available, otherwise compute
        const lagrangeCoeff = signingData.lagrange_coefficient ||
          computeLagrangeCoefficient(myIndex, myIndex, coSignerIndex);
        log('INFO', 'Lagrange coefficient ready.');

        // Get the group public key (multisig address public key)
        const groupPubKey = signingData.multisig_spend_pub_key;
        if (!groupPubKey) {
          throw new Error('Missing multisig_spend_pub_key from server');
        }

        // Use the CLSAG message if available, otherwise fall back to tx_prefix_hash
        const signingMessage = signingData.clsag_message || signingData.tx_prefix_hash;
        if (!signingMessage) {
          throw new Error('Missing signing message (clsag_message or tx_prefix_hash)');
        }

        // Generate nonce commitment (MuSig2-style)
        const nonceResult = generateNonceCommitment(signingMessage, groupPubKey);
        log('INFO', 'Nonce commitment generated.');

        // Get the aggregated key image
        const aggregatedKeyImage = signingData.key_image;
        if (!aggregatedKeyImage) {
          throw new Error('Missing aggregated key_image from server. Submit partial key images first via /submit-partial-key-image');
        }

        // Prepare input data for CLSAG signing
        const inputData: Record<string, unknown> = {};
        if (signingData.inputs && signingData.inputs.length > 0) {
          const input = signingData.inputs[0]; // For single-input transactions
          inputData.ring_public_keys = input.ring_public_keys;
          inputData.ring_commitments = input.ring_commitments;
          inputData.signer_index = input.signer_index;
          inputData.real_global_index = input.real_global_index;
          inputData.pseudo_out_mask = input.pseudo_out_mask;
        }

        // Determine if we're first or second signer based on server data
        const isFirstSigner = !signingData.first_signer_c1;

        let partialSignature: ClsagSignature;

        if (isFirstSigner) {
          log('INFO', 'Creating partial signature as first signer...');

          // First signer: use signClsagPartial without first signer data
          const signResult = signClsagPartial(
            secretShare,
            inputData,
            signingMessage,
            groupPubKey,
            aggregatedKeyImage,
            null, // No first signer data (we ARE the first signer)
            lagrangeCoeff
          );

          partialSignature = signResult.signature;
          updateState({
            partialKeyImage: signResult.partialKeyImage,
          });
          log('SUCCESS', 'Partial signature created. Waiting for co-signer.');
        } else {
          log('INFO', 'Completing signature as second signer...');

          // Second signer: include first signer's data for proper aggregation
          const firstSignerData = {
            c1: signingData.first_signer_c1!,
            sValues: signingData.first_signer_s || [],
            D: signingData.first_signer_d || '',
            muP: signingData.mu_P || '',
            muC: signingData.mu_C || '',
            pseudoOut: signingData.first_signer_pseudo_out || '',
            usedRAgg: signingData.first_signer_used_r_agg || false,
          };

          const signResult = signClsagPartial(
            secretShare,
            inputData,
            signingMessage,
            groupPubKey,
            aggregatedKeyImage,
            firstSignerData,
            lagrangeCoeff
          );

          partialSignature = signResult.signature;

          // Verify the completed signature locally
          if (signingData.inputs && signingData.inputs.length > 0) {
            const ring = signingData.inputs[0].ring_public_keys.map((pk, i) => [
              pk,
              signingData.inputs![0].ring_commitments[i],
            ]);

            const verifyResult = verifyClsag(partialSignature, ring, signingMessage);
            if (verifyResult.valid) {
              log('SUCCESS', 'Signature verified locally!');
            } else {
              log('WARN', `Local verification: ${verifyResult.error || 'pending server verification'}`);
            }
          }
        }

        // Submit to server
        updateState({ phase: 'submitting' });
        log('INFO', 'Submitting signature to server...');

        // Use the newer submitSignature endpoint
        const submitResponse = await submitSignature(
          escrowId,
          role,
          JSON.stringify(partialSignature),
          aggregatedKeyImage
        );

        if (!submitResponse.success) {
          throw new Error(submitResponse.error || 'Failed to submit signature');
        }

        // Check if ready to broadcast
        if (submitResponse.data?.ready_to_broadcast) {
          log('SUCCESS', 'All signatures collected!');
          await broadcast();
        } else {
          updateState({
            phase: 'waiting_cosigner',
            partialSignature,
            nonceCommitment: nonceResult.commitment_hash,
          });
          log('INFO', `Waiting for co-signer (${submitResponse.data?.signatures_collected}/${submitResponse.data?.signatures_required})...`);

          // Set up WebSocket for updates
          if (!wsRef.current) {
            wsRef.current = createWebSocket(handleWsMessage);
          }
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log('CRITICAL', `Signing failed: ${message}`);
        updateState({ phase: 'error', error: message });
      }
    },
    [log, updateState, broadcast, handleWsMessage]
  );

  // Retry signing
  const retry = useCallback(async () => {
    if (!state.escrowId || !state.role || !state.action) {
      log('WARN', 'Cannot retry: no active signing session.');
      return;
    }

    log('INFO', 'Retrying signing...');
    updateState({ error: null });

    if (state.phase === 'waiting_cosigner') {
      await checkForAggregation();
    } else if (state.phase === 'error') {
      // Try to broadcast if we have signatures
      await checkForAggregation();
    }
  }, [state.escrowId, state.role, state.action, state.phase, log, updateState, checkForAggregation]);

  // Reset state
  const reset = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    passwordRef.current = '';
    coSignerRef.current = '';
    setState(initialState);
  }, []);

  // Cleanup
  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  // Poll for status updates
  useEffect(() => {
    if (state.phase !== 'waiting_cosigner') return;

    const pollInterval = setInterval(async () => {
      if (!state.escrowId) return;

      try {
        const statusResponse = await getSigningStatus(state.escrowId);
        if (!statusResponse.success || !statusResponse.data) return;

        const session = statusResponse.data;
        updateState({ serverStatus: session });

        if (session.signatures_collected >= session.signatures_required) {
          clearInterval(pollInterval);
          log('SUCCESS', 'All signatures collected!');
          await broadcast();
        }
      } catch (error) {
        console.error('[Signing Poll] Error:', error);
      }
    }, 3000);

    return () => clearInterval(pollInterval);
  }, [state.phase, state.escrowId, log, updateState, broadcast]);

  return {
    state,
    startSigning,
    retry,
    reset,
  };
}
