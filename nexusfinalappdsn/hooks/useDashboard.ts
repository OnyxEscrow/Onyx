import { useState, useEffect, useCallback } from 'react';

export interface DashboardEscrow {
  id: string;
  status: string;
  amount: number;
  role: 'buyer' | 'vendor' | 'arbiter';
  counterparty?: {
    id: string;
    username: string;
  };
  created_at: string;
  updated_at: string;
  multisig_phase: string;
  frost_dkg_complete: boolean;
  has_shield: boolean;
  unread_messages: number;
  external_reference?: string;
  description?: string;
  // Additional fields
  multisig_address?: string;
  dkg_phase?: 'pending' | 'round1' | 'round2' | 'complete' | 'failed';
  funded_amount?: number;
  confirmations?: number;
  timeout_at?: string;
  broadcast_tx_hash?: string;
}

export interface DashboardStats {
  total: number;
  active: number;
  completed: number;
  disputed: number;
  total_volume: number;
  as_buyer: number;
  as_vendor: number;
  as_arbiter: number;
}

export interface PaginationMeta {
  page: number;
  per_page: number;
  total: number;
}

export interface DashboardFilters {
  status?: string[];
  role?: string[];
  sortBy?: string;
  page?: number;
  perPage?: number;
}

export interface UseDashboardResult {
  escrows: DashboardEscrow[];
  stats: DashboardStats | null;
  pagination: PaginationMeta | null;
  isLoading: boolean;
  error: Error | null;
  refetch: () => void;
}

const API_BASE = '/api';

export function useDashboard(filters: DashboardFilters = {}): UseDashboardResult {
  const [escrows, setEscrows] = useState<DashboardEscrow[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchDashboard = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams();

      if (filters.status?.length) {
        params.set('status', filters.status.join(','));
      }
      if (filters.role?.length) {
        params.set('role', filters.role.join(','));
      }
      if (filters.sortBy) {
        params.set('sort_by', filters.sortBy);
      }
      params.set('page', String(filters.page || 1));
      params.set('per_page', String(filters.perPage || 10));

      const response = await fetch(
        `${API_BASE}/user/escrows/dashboard?${params.toString()}`,
        {
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setEscrows(data.escrows || []);
      setStats(data.statistics || null);
      setPagination(data.pagination || null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [
    filters.status?.join(','),
    filters.role?.join(','),
    filters.sortBy,
    filters.page,
    filters.perPage,
  ]);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  return {
    escrows,
    stats,
    pagination,
    isLoading,
    error,
    refetch: fetchDashboard,
  };
}

// Helper to format XMR amount
export function formatXmr(atomic: number): string {
  const xmr = atomic / 1e12;
  return xmr.toFixed(4);
}

// Helper to get status badge info
export function getStatusBadge(status: string): { text: string; color: string } {
  const badges: Record<string, { text: string; color: string }> = {
    pending_counterparty: { text: 'Pending Partner', color: 'text-yellow-400' },
    pending_dkg: { text: 'Pending DKG', color: 'text-blue-400' },
    dkg_in_progress: { text: 'DKG Active', color: 'text-blue-400' },
    dkg_complete: { text: 'DKG Complete', color: 'text-green-400' },
    awaiting_funding: { text: 'Awaiting Funds', color: 'text-orange-400' },
    payment_detected: { text: 'Payment Incoming', color: 'text-green-400' },
    funded: { text: 'Funded', color: 'text-green-400' },
    shipped: { text: 'Shipped', color: 'text-blue-400' },
    releasing: { text: 'Releasing', color: 'text-purple-400' },
    awaiting_release: { text: 'Awaiting Release', color: 'text-purple-400' },
    released: { text: 'Released', color: 'text-green-400' },
    disputed: { text: 'Disputed', color: 'text-red-400' },
    resolved_buyer: { text: 'Resolved → Buyer', color: 'text-green-400' },
    resolved_vendor: { text: 'Resolved → Vendor', color: 'text-green-400' },
    refunded: { text: 'Refunded', color: 'text-orange-400' },
    completed: { text: 'Completed', color: 'text-green-400' },
    cancelled: { text: 'Cancelled', color: 'text-gray-400' },
    expired: { text: 'Expired', color: 'text-gray-500' },
  };
  return badges[status] || { text: status, color: 'text-gray-400' };
}
