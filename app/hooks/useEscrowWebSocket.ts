/**
 * useEscrowWebSocket - React hook for escrow WebSocket events
 *
 * Provides real-time updates for:
 * - DKG progress (Round 1/2 complete, parties online)
 * - Signing events (signature required, submitted, broadcast)
 * - Escrow status changes
 * - Party presence indicators
 */

import { useState, useEffect, useRef, useCallback } from 'react';

// ============================================================================
// Types
// ============================================================================

export interface PartyPresence {
  role: string;
  online: boolean;
  lastSeen: number;
}

export interface DkgProgress {
  round1Complete: boolean;
  round2Complete: boolean;
  dkgComplete: boolean;
  partiesSubmittedRound1: string[];
  partiesSubmittedRound2: string[];
}

export interface SigningProgress {
  signaturesRequired: number;
  signaturesCollected: number;
  signers: string[];
  readyToBroadcast: boolean;
}

export interface EscrowWebSocketState {
  connected: boolean;
  escrowId: string | null;
  parties: PartyPresence[];
  dkgProgress: DkgProgress | null;
  signingProgress: SigningProgress | null;
  lastEvent: WebSocketEvent | null;
  error: string | null;
}

export interface WebSocketEvent {
  type: string;
  escrow_id?: string;
  data?: Record<string, unknown>;
  timestamp: number;
}

export interface UseEscrowWebSocketResult {
  state: EscrowWebSocketState;
  connect: (escrowId: string) => void;
  disconnect: () => void;
  isPartyOnline: (role: string) => boolean;
}

// ============================================================================
// Constants
// ============================================================================

const RECONNECT_DELAY = 3000; // 3 seconds
const MAX_RECONNECT_ATTEMPTS = 5;
const HEARTBEAT_INTERVAL = 30000; // 30 seconds
const PRESENCE_TIMEOUT = 60000; // Consider offline after 60 seconds

// ============================================================================
// Hook Implementation
// ============================================================================

const initialState: EscrowWebSocketState = {
  connected: false,
  escrowId: null,
  parties: [],
  dkgProgress: null,
  signingProgress: null,
  lastEvent: null,
  error: null,
};

export function useEscrowWebSocket(): UseEscrowWebSocketResult {
  const [state, setState] = useState<EscrowWebSocketState>(initialState);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const heartbeatIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const escrowIdRef = useRef<string | null>(null);

  // Update state helper
  const updateState = useCallback((updates: Partial<EscrowWebSocketState>) => {
    setState((prev) => ({ ...prev, ...updates }));
  }, []);

  // Update party presence
  const updatePartyPresence = useCallback((role: string, online: boolean) => {
    setState((prev) => {
      const existingIndex = prev.parties.findIndex((p) => p.role === role);
      const newParty: PartyPresence = {
        role,
        online,
        lastSeen: Date.now(),
      };

      if (existingIndex >= 0) {
        const parties = [...prev.parties];
        parties[existingIndex] = newParty;
        return { ...prev, parties };
      } else {
        return { ...prev, parties: [...prev.parties, newParty] };
      }
    });
  }, []);

  // Handle incoming WebSocket messages
  const handleMessage = useCallback(
    (event: MessageEvent) => {
      try {
        const raw = JSON.parse(event.data);

        // Normalize event format:
        // Backend sends Rust serde enum format: {"VariantName": {"field": value}}
        // Frontend expects flat format: {"type": "VariantName", "field": value}
        let eventType: string;
        let data: Record<string, unknown>;

        if (raw.type) {
          // Already flat format (e.g. from handlers that manually build JSON)
          eventType = raw.type;
          data = raw;
        } else {
          // Rust serde enum format: single top-level key is the variant name
          const keys = Object.keys(raw);
          if (keys.length === 1 && typeof raw[keys[0]] === 'object') {
            eventType = keys[0];
            data = raw[keys[0]] as Record<string, unknown>;
          } else {
            eventType = 'unknown';
            data = raw;
          }
        }

        const wsEvent: WebSocketEvent = {
          type: eventType,
          escrow_id: data.escrow_id as string | undefined,
          data: data,
          timestamp: Date.now(),
        };

        updateState({ lastEvent: wsEvent });

        // Handle different event types
        switch (eventType) {
          // ========== DKG Events ==========
          case 'FrostDkgRound1Required':
            updateState({
              dkgProgress: {
                round1Complete: false,
                round2Complete: false,
                dkgComplete: false,
                partiesSubmittedRound1: data.parties_submitted || [],
                partiesSubmittedRound2: [],
              },
            });
            break;

          case 'FrostDkgRound1Complete':
            setState((prev) => ({
              ...prev,
              dkgProgress: prev.dkgProgress
                ? {
                    ...prev.dkgProgress,
                    round1Complete: true,
                    partiesSubmittedRound1: ['buyer', 'vendor', 'arbiter'],
                  }
                : {
                    round1Complete: true,
                    round2Complete: false,
                    dkgComplete: false,
                    partiesSubmittedRound1: ['buyer', 'vendor', 'arbiter'],
                    partiesSubmittedRound2: [],
                  },
            }));
            break;

          case 'FrostDkgRound2Required':
            setState((prev) => ({
              ...prev,
              dkgProgress: prev.dkgProgress
                ? {
                    ...prev.dkgProgress,
                    round2Complete: false,
                    partiesSubmittedRound2:
                      (data.packages_submitted as number) > 0
                        ? calculateSubmittedParties(data.packages_submitted as number)
                        : [],
                  }
                : null,
            }));
            break;

          case 'FrostDkgRound2Complete':
            setState((prev) => ({
              ...prev,
              dkgProgress: prev.dkgProgress
                ? {
                    ...prev.dkgProgress,
                    round2Complete: true,
                    partiesSubmittedRound2: ['buyer', 'vendor', 'arbiter'],
                  }
                : null,
            }));
            break;

          case 'FrostDkgComplete':
            setState((prev) => ({
              ...prev,
              dkgProgress: prev.dkgProgress
                ? {
                    ...prev.dkgProgress,
                    dkgComplete: true,
                  }
                : {
                    round1Complete: true,
                    round2Complete: true,
                    dkgComplete: true,
                    partiesSubmittedRound1: ['buyer', 'vendor', 'arbiter'],
                    partiesSubmittedRound2: ['buyer', 'vendor', 'arbiter'],
                  },
            }));
            break;

          // ========== Signing Events ==========
          case 'SignatureRequired':
            updateState({
              signingProgress: {
                signaturesRequired: data.signatures_required || 2,
                signaturesCollected: data.signatures_collected || 0,
                signers: data.signers || [],
                readyToBroadcast: false,
              },
            });
            break;

          case 'SignatureSubmitted':
            setState((prev) => ({
              ...prev,
              signingProgress: prev.signingProgress
                ? {
                    ...prev.signingProgress,
                    signaturesCollected:
                      (prev.signingProgress.signaturesCollected || 0) + 1,
                    signers: [
                      ...(prev.signingProgress.signers || []),
                      data.signer_role,
                    ],
                  }
                : null,
            }));
            break;

          case 'ReadyToBroadcast':
            setState((prev) => ({
              ...prev,
              signingProgress: prev.signingProgress
                ? {
                    ...prev.signingProgress,
                    readyToBroadcast: true,
                  }
                : null,
            }));
            break;

          case 'BroadcastSuccess':
            setState((prev) => ({
              ...prev,
              signingProgress: prev.signingProgress
                ? {
                    ...prev.signingProgress,
                    readyToBroadcast: false,
                  }
                : null,
            }));
            break;

          // ========== Presence Events ==========
          case 'PartyOnline':
            if (data.party_role) {
              updatePartyPresence(data.party_role, true);
            }
            break;

          case 'PartyOffline':
            if (data.party_role) {
              updatePartyPresence(data.party_role, false);
            }
            break;

          // ========== Escrow Funding Events ==========
          case 'PaymentDetected':
            console.log('[WebSocket] Payment detected:', data);
            // Passed to caller via lastEvent - App.tsx handles UI transition
            break;

          case 'EscrowFunded':
            console.log('[WebSocket] Escrow funded:', data);
            // Passed to caller via lastEvent - App.tsx handles UI transition
            break;

          case 'EscrowShipped':
            console.log('[WebSocket] Escrow shipped:', data);
            // Passed to caller via lastEvent - App.tsx handles UI transition
            break;

          // ========== Dispute Events ==========
          case 'DisputeResolved':
            // Passed to caller via lastEvent — App.tsx handles auto-claim
            console.log('[WebSocket] Dispute resolved:', data);
            break;

          // ========== Escrow Status Events ==========
          case 'EscrowStatusChanged':
            // These events don't need special handling in state
            // They're passed to the caller via lastEvent
            break;

          default:
            console.log('[WebSocket] Unhandled event:', eventType);
        }
      } catch (error) {
        console.error('[WebSocket] Failed to parse message:', error);
      }
    },
    [updateState, updatePartyPresence]
  );

  // Connect to WebSocket
  const connect = useCallback(
    (escrowId: string) => {
      // Close existing connection
      if (wsRef.current) {
        wsRef.current.close();
      }

      escrowIdRef.current = escrowId;
      updateState({ escrowId, error: null });

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws?escrow=${escrowId}`;

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          console.log('[WebSocket] Connected for escrow:', escrowId);
          updateState({ connected: true, error: null });
          reconnectAttemptsRef.current = 0;

          // Start heartbeat
          if (heartbeatIntervalRef.current) {
            clearInterval(heartbeatIntervalRef.current);
          }
          heartbeatIntervalRef.current = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: 'ping' }));
            }
          }, HEARTBEAT_INTERVAL);
        };

        ws.onmessage = handleMessage;

        ws.onerror = (error) => {
          console.error('[WebSocket] Error:', error);
          updateState({ error: 'Connection error' });
        };

        ws.onclose = (event) => {
          console.log('[WebSocket] Closed:', event.code, event.reason);
          updateState({ connected: false });

          // Clear heartbeat
          if (heartbeatIntervalRef.current) {
            clearInterval(heartbeatIntervalRef.current);
            heartbeatIntervalRef.current = null;
          }

          // Attempt reconnect if not intentional close
          if (
            event.code !== 1000 &&
            escrowIdRef.current &&
            reconnectAttemptsRef.current < MAX_RECONNECT_ATTEMPTS
          ) {
            reconnectAttemptsRef.current++;
            console.log(
              `[WebSocket] Reconnecting in ${RECONNECT_DELAY}ms (attempt ${reconnectAttemptsRef.current})`
            );
            reconnectTimeoutRef.current = setTimeout(() => {
              if (escrowIdRef.current) {
                connect(escrowIdRef.current);
              }
            }, RECONNECT_DELAY);
          }
        };
      } catch (error) {
        console.error('[WebSocket] Failed to connect:', error);
        updateState({
          connected: false,
          error: error instanceof Error ? error.message : 'Connection failed',
        });
      }
    },
    [handleMessage, updateState]
  );

  // Disconnect from WebSocket
  const disconnect = useCallback(() => {
    escrowIdRef.current = null;

    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
      heartbeatIntervalRef.current = null;
    }

    if (wsRef.current) {
      wsRef.current.close(1000, 'User disconnect');
      wsRef.current = null;
    }

    setState(initialState);
  }, []);

  // Check if a party is online
  const isPartyOnline = useCallback(
    (role: string): boolean => {
      const party = state.parties.find((p) => p.role === role);
      if (!party) return false;
      return party.online && Date.now() - party.lastSeen < PRESENCE_TIMEOUT;
    },
    [state.parties]
  );

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      disconnect();
    };
  }, [disconnect]);

  return {
    state,
    connect,
    disconnect,
    isPartyOnline,
  };
}

// ============================================================================
// Helper Functions
// ============================================================================

function calculateSubmittedParties(packagesSubmitted: number): string[] {
  // Each party submits 2 packages, so:
  // 0 = none, 2 = 1 party, 4 = 2 parties, 6 = all 3
  const parties: string[] = [];
  const partyOrder = ['buyer', 'vendor', 'arbiter'];

  for (let i = 0; i < Math.min(Math.floor(packagesSubmitted / 2), 3); i++) {
    parties.push(partyOrder[i]);
  }

  return parties;
}

export default useEscrowWebSocket;
