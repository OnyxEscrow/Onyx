import { useState, useEffect, useCallback, useRef } from 'react';
import { getDkgStatus, getEscrow } from '../services/apiService';

export interface EscrowStatusData {
  status: string;
  balance_received: number;
  confirmations: number;
  amount: number;
  multisig_address?: string;
  // DKG-specific fields
  dkg_status?: string;
  group_pubkey?: string;
}

interface UseEscrowStatusOptions {
  pollInterval?: number; // milliseconds, default 5000
  onStatusChange?: (newStatus: string, prevStatus: string | null) => void;
}

export function useEscrowStatus(
  escrowId: string | null,
  enabled: boolean = true,
  options: UseEscrowStatusOptions = {}
) {
  const { pollInterval = 5000, onStatusChange } = options;

  const [escrowStatus, setEscrowStatus] = useState<EscrowStatusData | null>(null);
  const [isPolling, setIsPolling] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const prevStatusRef = useRef<string | null>(null);

  const pollStatus = useCallback(async () => {
    if (!escrowId) return;

    try {
      // Try FROST DKG status first (for FROST-based escrows like esc_xxx)
      const dkgResponse = await getDkgStatus(escrowId);

      let dkgStatus: string | undefined;
      if (dkgResponse.success && dkgResponse.data) {
        // DkgStatus has booleans, not a status string
        const dkgData = dkgResponse.data;
        dkgStatus = deriveDkgStatus(dkgData);
      }

      // ALWAYS fetch the actual escrow status to know if it's funded
      // DKG endpoint only tells us about key generation, not funding
      const escrowResponse = await getEscrow(escrowId);

      if (escrowResponse.success && escrowResponse.data) {
        const escrowData = escrowResponse.data;

        // Use actual escrow status if available, otherwise use DKG-derived status
        const actualStatus = escrowData.status || dkgStatus || 'unknown';

        const newStatus: EscrowStatusData = {
          status: actualStatus,
          balance_received: escrowData.balance_received || 0,
          confirmations: escrowData.confirmations || 0,
          amount: escrowData.amount || 0,
          multisig_address: escrowData.multisig_address,
          dkg_status: dkgStatus,
        };

        setEscrowStatus(newStatus);
        setError(null);

        // Trigger callback if status changed
        if (onStatusChange && prevStatusRef.current !== newStatus.status) {
          onStatusChange(newStatus.status, prevStatusRef.current);
        }
        prevStatusRef.current = newStatus.status;
        return;
      }

      // Fallback: only DKG data available (no escrow record yet)
      if (dkgStatus) {
        const newStatus: EscrowStatusData = {
          status: dkgStatus,
          balance_received: 0,
          confirmations: 0,
          amount: 0,
          dkg_status: dkgStatus,
        };

        setEscrowStatus(newStatus);
        setError(null);

        if (onStatusChange && prevStatusRef.current !== newStatus.status) {
          onStatusChange(newStatus.status, prevStatusRef.current);
        }
        prevStatusRef.current = newStatus.status;
        return;
      }

      // If we reach here, neither DKG nor escrow data was available
      console.warn('[EscrowStatus] No status data available for escrow:', escrowId);
    } catch (err) {
      // Don't log 404s during polling - escrow may not exist yet
      if (!(err instanceof Error && err.message.includes('404'))) {
        console.error('[EscrowStatus] Poll error:', err);
      }
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }, [escrowId, onStatusChange]);

  useEffect(() => {
    if (!enabled || !escrowId) {
      setIsPolling(false);
      return;
    }

    setIsPolling(true);
    pollStatus(); // Initial fetch

    const interval = setInterval(pollStatus, pollInterval);

    return () => {
      clearInterval(interval);
      setIsPolling(false);
    };
  }, [escrowId, enabled, pollStatus, pollInterval]);

  // Reset when escrowId changes
  useEffect(() => {
    if (!escrowId) {
      setEscrowStatus(null);
      prevStatusRef.current = null;
    }
  }, [escrowId]);

  return {
    escrowStatus,
    isPolling,
    error,
    refetch: pollStatus,
  };
}

// Helper to check if escrow is funded
export function isFunded(status: string | undefined): boolean {
  if (!status) return false;
  return ['funded', 'active', 'shipped', 'delivered', 'releasing', 'completed'].includes(status);
}

// Helper to check if payment has been detected but not yet fully confirmed
export function isPaymentDetected(status: string | undefined): boolean {
  return status === 'payment_detected';
}

// Helper to check if escrow is underfunded
export function isUnderfunded(status: string | undefined): boolean {
  return status === 'underfunded';
}

// Helper to format balance for display
export function formatBalance(atomicUnits: number): string {
  return (atomicUnits / 1e12).toFixed(4);
}

// Derive status from DKG boolean fields
// DkgStatus has: round1_complete, round2_complete, dkg_complete
interface DkgStatusBooleans {
  round1_complete?: boolean;
  round2_complete?: boolean;
  dkg_complete?: boolean;
}

function deriveDkgStatus(dkg: DkgStatusBooleans): string {
  if (dkg.dkg_complete) {
    // DKG is complete - escrow is ready for funding
    // Return 'awaiting_funding' - NOT 'active' (which would skip funding step)
    // The actual funded/active status should come from escrow endpoint, not DKG
    return 'awaiting_funding';
  }
  if (dkg.round2_complete) {
    return 'dkg_round2_complete';
  }
  if (dkg.round1_complete) {
    return 'dkg_round1_complete';
  }
  return 'dkg_in_progress';
}
