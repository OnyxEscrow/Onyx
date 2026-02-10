import OnyxLogo from './components/OnyxLogo';
import FundingQuips from './components/FundingQuips';
import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { EscrowStep, LogEntry, Role } from './types';
import { generateLog, delay } from './services/mockWasmService';
import { initWasm, isWasmReady, frostDeriveAddress, frostExtractSecretShare } from './services/wasmService';
import { useFrostDkg } from './hooks/useFrostDkg';
import { useFrostSigning } from './hooks/useFrostSigning';
import { useAuth } from './hooks/useAuth';
import { createEscrowLobby, joinEscrow, getLobbyStatus, markDelivered, confirmShipped, confirmReceipt, confirmDelivery, releaseFunds, listApiKeys, createApiKey, revokeApiKey, deleteApiKey, getCurrentUser, getArbiterDisputes, resolveDispute, initiateDispute, submitDisputeShare } from './services/apiService';
import type { ApiKeyInfo, ApiKeyCreationResponse, ArbiterDispute } from './services/apiService';
import {
  loadKeyPackage,
  computeAndSubmitPartialKeyImage,
  fetchTxDataForSigning,
  generateNonceCommitment,
  submitNonceCommitment,
  pollForPeerNonce,
  signClsagPartial,
  submitPartialSignature,
  submitFrostShare,
  pollForFirstSignerData,
  pollForBroadcast,
  type SigningProgress,
} from './services/frostSigningService';
import Terminal from './components/Terminal';
import TrustMonitor from './components/TrustMonitor';
import Visualizer from './components/Visualizer';
import ActionButton from './components/ActionButton';
import AuthModal from './components/AuthModal';
import { EscrowChat } from './components/Messaging/EscrowChat';
import RevealText from './components/RevealText';
import LoadingSpinner from './components/LoadingSpinner';
import { MandatoryShieldModal } from './components/Shield/MandatoryShieldModal';
import { ShieldRecovery } from './components/Shield/ShieldRecovery';
import { EscrowDashboard } from './components/Dashboard/EscrowDashboard';
import CompletionCeremony from './components/CompletionCeremony';
import ProgressStepper from './components/ProgressStepper';
import { playTone } from './services/audioFeedback';
import { humanizeError } from './utils/errorHumanizer';
import { hasKey, storeKey } from './services/keyStorage';
import { PaymentQRCode } from './components/PaymentQRCode';
import { useEscrowStatus, isFunded, isPaymentDetected, isUnderfunded, formatBalance } from './hooks/useEscrowStatus';
import { useEscrowWebSocket } from './hooks/useEscrowWebSocket';
import { Copy, Shield, ArrowDown, Network, Lock, FileKey, ScanLine, MessageSquareLock, AlertTriangle, Scale, Activity, CheckCircle, ArrowRight, Package, LogOut, LayoutDashboard, QrCode, Clock, User, Store } from 'lucide-react';

// Helper to decode hex string to Uint8Array
// Note: FROST DKG returns hex-encoded key packages, not base64
function hexToUint8Array(hex: string): Uint8Array {
  if (!hex || hex.length === 0) {
    console.warn('[App] hexToUint8Array: empty input');
    return new Uint8Array(0);
  }
  // Remove 0x prefix if present
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

const App: React.FC = () => {
  // Auth state from context
  const { user, isLoading: authLoading, logout } = useAuth();

  // Stealth Onboarding: Initial State (No Role)
  useEffect(() => {
    if (!user && !authLoading) {
       // Small delay for effect
       const timer = setTimeout(() => {
          setLogs(prev => {
             if (prev.length === 0) {
                return [
                   generateLog('INFO', 'SYSTEM DETECTED NEW USER.'),
                   generateLog('WARN', 'RECOMMENDATION: GENERATE IDENTITY.'),
                ];
             }
             return prev;
          });
       }, 500);
       return () => clearTimeout(timer);
    }
  }, [user, authLoading]);

  // Stealth Onboarding: Identity Confirmed
  useEffect(() => {
    if (user?.username && user?.role) {
      setLogs(prev => {
         // Avoid duplicates if already logged
         if (prev.some(l => l.message === 'IDENTITY CONFIRMED.')) return prev;
         return [
            ...prev,
            generateLog('SUCCESS', 'IDENTITY CONFIRMED.'),
            generateLog('INFO', 'WAITING FOR CONTRACT INITIATION...'),
         ];
      });
    }
  }, [user?.username, user?.role]);

  // Derive role from user
  const role = useMemo((): Role | null => {
    if (!user?.role) return null;
    const roleStr = user.role.toUpperCase();
    if (roleStr === 'BUYER') return Role.BUYER;
    if (roleStr === 'SELLER' || roleStr === 'VENDOR') return Role.VENDOR;
    if (roleStr === 'ARBITER') return Role.ARBITER;
    return null;
  }, [user?.role]);

  const username = user?.username || '';

  const [step, setStep] = useState<EscrowStep>(EscrowStep.IDLE);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [sessionId, setSessionId] = useState<string>('');
  const [inputSessionId, setInputSessionId] = useState<string>('');
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [wasmReady, setWasmReady] = useState(false);
  const [backupPassword, setBackupPassword] = useState<string>('');
  const [escrowAmount, setEscrowAmount] = useState<string>('1.0');
  const [multisigAddress, setMultisigAddress] = useState<string>('');
  const [showShieldModal, setShowShieldModal] = useState(false);
  const [shieldComplete, setShieldComplete] = useState(false);
  const [showLobby, setShowLobby] = useState(false);
  // Dynamic TX ticker — persisted in localStorage
  const [tickerTxHashes, setTickerTxHashes] = useState<{hash: string, label: string}[]>(() => {
    try {
      const stored = localStorage.getItem('nexus_ticker_txs');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch { /* ignore */ }
    return [
      { hash: 'c92605f1ae2c9e7287bd0c60a0d1d78da254adcc90f5841fde42a14c0f7c3e88', label: 'CLSAG' },
      { hash: '80c131432ac6ae44b3b5e28bfedd91d25e5a4430c24abff2f06997d52502e626', label: 'CLSAG' },
    ];
  });
  const [bothPartiesConnected, setBothPartiesConnected] = useState(false);
  const [vendorPayoutAddress, setVendorPayoutAddress] = useState<string>('');
  const [signingProgress, setSigningProgress] = useState<SigningProgress>({
    stage: 'idle',
    message: '',
  });
  const [showShieldRecovery, setShowShieldRecovery] = useState(false);
  const [showDocs, setShowDocs] = useState(false);
  const [showApiPanel, setShowApiPanel] = useState(false);
  const [apiKeys, setApiKeys] = useState<ApiKeyInfo[]>([]);
  const [apiKeysLoading, setApiKeysLoading] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [createdKey, setCreatedKey] = useState<ApiKeyCreationResponse | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null);
  const [showContact, setShowContact] = useState(false);
  const [contactEmail, setContactEmail] = useState('');
  const [contactSubject, setContactSubject] = useState('');
  const [contactMessage, setContactMessage] = useState('');
  const [contactSent, setContactSent] = useState(false);
  const [hasLocalKey, setHasLocalKey] = useState<boolean | null>(null);
  // Arbiter Panel
  const [showArbiterPanel, setShowArbiterPanel] = useState(false);
  const [arbiterDisputes, setArbiterDisputes] = useState<ArbiterDispute[]>([]);
  const [arbiterLoading, setArbiterLoading] = useState(false);
  const [arbiterError, setArbiterError] = useState<string | null>(null);
  const [selectedDispute, setSelectedDispute] = useState<ArbiterDispute | null>(null);
  const [resolveAddress, setResolveAddress] = useState('');
  const [resolveLoading, setResolveLoading] = useState(false);
  const [disputeReason, setDisputeReason] = useState('');
  const [disputeLoading, setDisputeLoading] = useState(false);
  // Dispute auto-claim state
  const [disputeClaimStatus, setDisputeClaimStatus] = useState<
    'idle' | 'loading_key' | 'extracting' | 'submitting' | 'polling' | 'completed' | 'needs_password' | 'needs_restore' | 'error'
  >('idle');
  const [disputeClaimError, setDisputeClaimError] = useState<string | null>(null);
  const [disputeClaimTxHash, setDisputeClaimTxHash] = useState<string | null>(null);
  const [disputeShieldPassword, setDisputeShieldPassword] = useState('');
  const disputeClaimRef = useRef(false); // prevent double-fire

  // Add TX to ticker (deduplicates, persists to localStorage)
  const addTickerTx = useCallback((hash: string, label: string) => {
    setTickerTxHashes(prev => {
      if (prev.some(t => t.hash === hash)) return prev;
      const next = [{ hash, label }, ...prev];
      try { localStorage.setItem('nexus_ticker_txs', JSON.stringify(next)); } catch { /* ignore */ }
      return next;
    });
  }, []);

  // Display-friendly session ID (last 8 chars, uppercase)
  const displaySessionId = useMemo(() => {
    if (!sessionId) return '';
    const cleanId = sessionId.replace('esc_', '');
    return cleanId.slice(-8).toUpperCase();
  }, [sessionId]);

  // Initialize FROST DKG hook
  const addLog = useCallback((log: LogEntry) => {
    setLogs(prev => [...prev, log]);
  }, []);

  const { state: dkgState, startDkg, reset: resetDkg } = useFrostDkg(addLog);
  const { state: signingState, startSigning, reset: resetSigning } = useFrostSigning(addLog);

  // WebSocket for real-time events (PaymentDetected, EscrowFunded, etc.)
  const { state: wsState, connect: wsConnect, disconnect: wsDisconnect } = useEscrowWebSocket();

  // Connect WebSocket when we have a session
  useEffect(() => {
    if (sessionId && step !== EscrowStep.IDLE && step !== EscrowStep.COMPLETED) {
      wsConnect(sessionId);
    }
    return () => {
      if (!sessionId) wsDisconnect();
    };
  }, [sessionId, step, wsConnect, wsDisconnect]);

  // Poll escrow status for:
  // 1. Auto-detection during FUNDING phase
  // 2. State restoration when IDLE with sessionId (after selecting from lobby)
  const shouldPollStatus = step === EscrowStep.FUNDING || (step === EscrowStep.IDLE && !!sessionId);
  const { escrowStatus, isPolling: isFundingPolling } = useEscrowStatus(
    sessionId,
    shouldPollStatus
  );

  // Initialize WASM on mount
  useEffect(() => {
    initWasm()
      .then(() => {
        setWasmReady(true);
        console.log('[App] WASM initialized');
      })
      .catch((error) => {
        console.error('[App] WASM init failed:', error);
        addLog(generateLog('CRITICAL', 'CRYPTO MODULE FAILED. REFRESH REQUIRED.'));
      });
  }, [addLog]);



  // Handle logout
  const handleLogout = useCallback(async () => {
    await logout();
    setStep(EscrowStep.IDLE);
    setSessionId('');
    setLogs([]);
    setShowLobby(false);
    setShieldComplete(false);
  }, [logout]);

  // ── API Key Management ──────────────────────────────────────────────
  const loadApiKeys = useCallback(async () => {
    setApiKeysLoading(true);
    setApiError(null);
    try {
      const resp = await listApiKeys();
      if (resp.success && resp.data) {
        setApiKeys(resp.data.keys || []);
      } else {
        setApiError(resp.error || 'Failed to load API keys');
      }
    } catch {
      setApiError('Network error loading API keys');
    } finally {
      setApiKeysLoading(false);
    }
  }, []);

  const handleCreateApiKey = useCallback(async () => {
    if (!newKeyName.trim()) {
      setApiError('Key name is required');
      return;
    }
    setApiError(null);
    try {
      // Fetch fresh CSRF token from whoami before creating key
      const whoami = await getCurrentUser();
      const csrfToken = whoami.data?.csrf_token || '';
      if (!csrfToken) {
        setApiError('Session expired. Please log in again.');
        return;
      }
      const resp = await createApiKey(newKeyName.trim(), csrfToken);
      if (resp.success && resp.data) {
        setCreatedKey(resp.data.key);
        setNewKeyName('');
        await loadApiKeys();
      } else {
        setApiError(resp.error || 'Failed to create API key');
      }
    } catch {
      setApiError('Network error creating API key');
    }
  }, [newKeyName, user, loadApiKeys]);

  const handleRevokeKey = useCallback(async (keyId: string) => {
    setApiError(null);
    try {
      const resp = await revokeApiKey(keyId);
      if (resp.success) {
        await loadApiKeys();
      } else {
        setApiError(resp.error || 'Failed to revoke key');
      }
    } catch {
      setApiError('Network error revoking key');
    }
  }, [loadApiKeys]);

  const handleDeleteKey = useCallback(async (keyId: string) => {
    setApiError(null);
    try {
      const resp = await deleteApiKey(keyId);
      if (resp.success) {
        await loadApiKeys();
      } else {
        setApiError(resp.error || 'Failed to delete key');
      }
    } catch {
      setApiError('Network error deleting key');
    }
  }, [loadApiKeys]);

  const copyToClipboard = useCallback((text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKeyId(id);
    setTimeout(() => setCopiedKeyId(null), 2000);
  }, []);

  // Load API keys when panel opens
  useEffect(() => {
    if (showApiPanel && user) {
      loadApiKeys();
    }
  }, [showApiPanel, user, loadApiKeys]);

  // Arbiter: load disputes
  const loadArbiterDisputes = useCallback(async () => {
    setArbiterLoading(true);
    setArbiterError(null);
    try {
      const resp = await getArbiterDisputes();
      if (resp.success && resp.data) {
        setArbiterDisputes(resp.data.disputes || []);
      } else {
        setArbiterError(resp.error || 'Failed to load disputes');
      }
    } catch {
      setArbiterError('Network error loading disputes');
    } finally {
      setArbiterLoading(false);
    }
  }, []);

  const handleResolveDispute = useCallback(async (escrowId: string, resolution: 'buyer' | 'vendor') => {
    if (!resolveAddress || resolveAddress.length !== 95 || !resolveAddress.startsWith('4')) {
      setArbiterError('Invalid Monero address. Must be 95 characters starting with 4.');
      return;
    }
    setResolveLoading(true);
    setArbiterError(null);
    try {
      const resp = await resolveDispute(escrowId, resolution, resolveAddress);
      if (resp.success) {
        setSelectedDispute(null);
        setResolveAddress('');
        loadArbiterDisputes();
      } else {
        setArbiterError(resp.error || 'Failed to resolve dispute');
      }
    } catch {
      setArbiterError('Network error resolving dispute');
    } finally {
      setResolveLoading(false);
    }
  }, [resolveAddress, loadArbiterDisputes]);

  // Load arbiter disputes when panel opens
  useEffect(() => {
    if (showArbiterPanel && user && role === Role.ARBITER) {
      loadArbiterDisputes();
    }
  }, [showArbiterPanel, user, role, loadArbiterDisputes]);

  // Handle shield backup complete
  const handleShieldComplete = useCallback(() => {
    setShowShieldModal(false);
    setShieldComplete(true);
    setStep(EscrowStep.FUNDING);
    addLog(generateLog('SUCCESS', 'SHIELD SECURED. INITIATING FUNDING PHASE.'));
  }, [addLog]);

  // Handle escrow selection from lobby
  const handleSelectEscrow = useCallback((escrowId: string, _role?: string, status?: string, amount?: number) => {
    setSessionId(escrowId);
    setShowLobby(false);
    // Restore escrow amount if available from lobby
    if (amount && amount > 0) {
      setEscrowAmount((amount / 1e12).toString());
    }
    addLog(generateLog('INFO', `LOADING ESCROW STATE: ${escrowId.slice(0, 12)}...`));

    // Immediately restore step based on status from lobby
    if (status) {
      const statusLower = status.toLowerCase();
      console.log('[App] Restoring step from lobby status:', statusLower);

      switch (statusLower) {
        // --- Pre-DKG: waiting for participants ---
        case 'pending':
        case 'pending_counterparty':
          addLog(generateLog('INFO', 'WAITING FOR COUNTERPARTY TO JOIN.'));
          setStep(EscrowStep.INITIATING);
          break;
        // --- DKG in progress ---
        case 'pending_dkg':
        case 'dkg_round1':
        case 'dkg_round2':
          addLog(generateLog('INFO', 'DKG IN PROGRESS. KEY GENERATION ACTIVE.'));
          setStep(EscrowStep.DKG_RUNNING);
          break;
        // --- Funding: DKG complete, awaiting payment ---
        case 'created':
        case 'awaiting_funding':
        case 'dkg_complete':
          addLog(generateLog('INFO', 'AWAITING FUNDING. SEND XMR TO MULTISIG ADDRESS.'));
          setStep(EscrowStep.FUNDING);
          break;
        case 'payment_detected':
        case 'underfunded':
          addLog(generateLog('SUCCESS', 'PAYMENT DETECTED. WAITING FOR CONFIRMATIONS.'));
          setStep(EscrowStep.FUNDING);
          break;
        // --- Active: funds locked ---
        case 'funded':
        case 'active':
          addLog(generateLog('SUCCESS', 'ESCROW ACTIVE. FUNDS LOCKED.'));
          setStep(EscrowStep.ACTIVE);
          break;
        // --- Delivery ---
        case 'shipped':
        case 'delivered':
          addLog(generateLog('INFO', 'AWAITING BUYER CONFIRMATION.'));
          setStep(EscrowStep.DELIVERED);
          break;
        // --- Signing / Release ---
        case 'releasing':
        case 'signing':
        case 'signing_initiated':
        case 'ready_to_broadcast':
        case 'awaiting_key_image':
        case 'refunding':
          addLog(generateLog('INFO', 'SIGNING IN PROGRESS.'));
          setStep(EscrowStep.RELEASE_SIGNING);
          break;
        // --- Completed ---
        case 'completed':
        case 'released':
          addLog(generateLog('SUCCESS', 'ESCROW COMPLETED.'));
          setStep(EscrowStep.COMPLETED);
          break;
        // --- Dispute ---
        case 'disputed':
          addLog(generateLog('WARN', 'ESCROW IN DISPUTE.'));
          setStep(EscrowStep.DISPUTE);
          break;
        case 'resolved_buyer':
        case 'resolved_vendor':
          addLog(generateLog('WARN', 'DISPUTE RESOLVED. CLAIMING FUNDS...'));
          setStep(EscrowStep.DISPUTE_RESOLVED);
          break;
        default:
          addLog(generateLog('INFO', `LOADING ESCROW (${statusLower})...`));
          setStep(EscrowStep.FUNDING);
          break;
      }
    }
  }, [addLog]);

  // Handle new escrow from lobby
  const handleCreateNewFromLobby = useCallback(() => {
    setShowLobby(false);
    setStep(EscrowStep.IDLE);
    setSessionId('');
    resetDkg();
    resetSigning();
  }, [resetDkg, resetSigning]);

  // Watch DKG state changes to update UI
  useEffect(() => {
    if (dkgState.phase === 'complete') {
      setIsLoading(false);
      playTone('success');

      // Derive multisig address from group public key
      if (dkgState.groupPublicKey && sessionId) {
        try {
          const result = frostDeriveAddress(dkgState.groupPublicKey, sessionId);
          // frostDeriveAddress returns { address, view_key_private, view_key_public }
          const addr = typeof result === 'string' ? result : result.address;
          setMultisigAddress(addr);
          addLog(generateLog('SUCCESS', 'MULTISIG ADDRESS DERIVED.', addr.slice(0, 12) + '...'));
        } catch (error) {
          console.error('[App] Failed to derive address:', error);
          addLog(generateLog('WARN', 'ERROR: ADDR DERIVATION FAILED.'));
        }
      }

      // Show MandatoryShieldModal before proceeding to FUNDING
      // Only show if shield hasn't been completed yet
      if (!shieldComplete && dkgState.keyPackage) {
        setShowShieldModal(true);
        addLog(generateLog('INFO', 'MANDATORY SHIELD REQUIRED.'));
      } else if (shieldComplete) {
        // Shield already complete, proceed to funding
        setStep(EscrowStep.FUNDING);
      }
    } else if (dkgState.phase === 'error') {
      setIsLoading(false);
    } else if (
      dkgState.phase === 'round1_waiting' ||
      dkgState.phase === 'round2_waiting'
    ) {
      setIsLoading(false);
    }
  }, [dkgState.phase, dkgState.groupPublicKey, dkgState.keyPackage, sessionId, addLog, shieldComplete]);

  // Watch signing state changes
  useEffect(() => {
    if (signingState.phase === 'complete') {
      setStep(EscrowStep.COMPLETED);
      setIsLoading(false);
      playTone('complete');
      if (signingState.txHash) {
        addLog(generateLog('SUCCESS', 'TRANSACTION BROADCAST.', signingState.txHash.slice(0, 16)));
        addTickerTx(signingState.txHash, 'CLSAG');
      }
    } else if (signingState.phase === 'error') {
      setIsLoading(false);
    } else if (signingState.phase === 'waiting_cosigner') {
      setIsLoading(false);
      addLog(generateLog('INFO', 'AWAITING CO-SIGNER...'));
    }
  }, [signingState.phase, signingState.txHash, addLog, addTickerTx]);

  // Poll lobby status when buyer is waiting for vendor
  useEffect(() => {
    if (step !== EscrowStep.DKG_WAITING || !sessionId || role !== Role.BUYER) {
      return;
    }

    const pollLobby = async () => {
      try {
        const response = await getLobbyStatus(sessionId);
        if (response.success && response.data?.vendor_joined) {
          addLog(generateLog('SUCCESS', 'VENDOR CONNECTED. STARTING KEYGEN...'));
          // Both parties now connected - enable chat
          setBothPartiesConnected(true);
          // Vendor has joined, start DKG
          handleRunDKG();
        }
      } catch (error) {
        console.error('[Lobby Poll] Error:', error);
      }
    };

    const interval = setInterval(pollLobby, 3000);
    return () => clearInterval(interval);
  }, [step, sessionId, role, addLog]);


  // Track whether we already logged the payment_detected message
  const paymentDetectedLoggedRef = useRef(false);

  // Auto-transition when funding is detected by blockchain monitor (polling)
  useEffect(() => {
    if (step !== EscrowStep.FUNDING || !escrowStatus) return;

    // Check if fully funded (10+ confirmations)
    if (isFunded(escrowStatus.status)) {
      paymentDetectedLoggedRef.current = false; // Reset for next escrow
      addLog(generateLog('SUCCESS', 'PAYMENT CONFIRMED. FUNDS LOCKED IN MULTISIG.'));
      addLog(generateLog('INFO', 'Vendor has been notified. Awaiting shipment.'));
      setStep(EscrowStep.ACTIVE);
    }
    // Check if payment detected (1-9 confirmations, visible but locked)
    else if (isPaymentDetected(escrowStatus.status) && !paymentDetectedLoggedRef.current) {
      paymentDetectedLoggedRef.current = true;
      playTone('alert');
      const received = formatBalance(escrowStatus.balance_received);
      addLog(generateLog('SUCCESS', `PAYMENT DETECTED: ${received} XMR incoming`));
      addLog(generateLog('INFO', 'Transaction visible on blockchain. Waiting for confirmations...'));
      addLog(generateLog('INFO', 'Vendor has been notified of incoming payment.'));
    }
    // Check if underfunded (partial payment confirmed)
    else if (isUnderfunded(escrowStatus.status)) {
      const received = formatBalance(escrowStatus.balance_received);
      const required = formatBalance(escrowStatus.amount);
      addLog(generateLog('WARN', `Partial payment: ${received} / ${required} XMR received`));
    }
  }, [escrowStatus, step, addLog]);

  // Sync escrowAmount and multisigAddress from escrowStatus when available
  useEffect(() => {
    if (escrowStatus && escrowStatus.amount > 0) {
      setEscrowAmount((escrowStatus.amount / 1e12).toString());
    }
    if (escrowStatus?.multisig_address && !multisigAddress) {
      setMultisigAddress(escrowStatus.multisig_address);
    }
  }, [escrowStatus?.amount, escrowStatus?.multisig_address, multisigAddress]);

  // Auto-transition when escrow is shipped (polling fallback for buyer)
  useEffect(() => {
    if (step !== EscrowStep.ACTIVE || !escrowStatus) return;

    const status = escrowStatus.status?.toLowerCase();
    if (status === 'shipped' || status === 'delivered') {
      addLog(generateLog('SUCCESS', 'VENDOR HAS MARKED ORDER AS SHIPPED.'));
      addLog(generateLog('INFO', 'Please confirm delivery when you receive the goods.'));
      setStep(EscrowStep.DELIVERED);
    }
  }, [escrowStatus, step, addLog]);

  // React to WebSocket events for instant updates (no polling delay)
  useEffect(() => {
    if (!wsState.lastEvent || step !== EscrowStep.FUNDING) return;

    const { type, data } = wsState.lastEvent;

    if (type === 'PaymentDetected' && data && !paymentDetectedLoggedRef.current) {
      paymentDetectedLoggedRef.current = true;
      const amountXmr = ((data.amount_detected as number) || 0) / 1e12;
      addLog(generateLog('SUCCESS', `PAYMENT DETECTED: ${amountXmr.toFixed(4)} XMR incoming`));
      addLog(generateLog('INFO', 'Transaction visible on blockchain. Waiting for confirmations...'));
      addLog(generateLog('INFO', 'Vendor has been notified of incoming payment.'));
    }

    if (type === 'EscrowFunded') {
      paymentDetectedLoggedRef.current = false;
      addLog(generateLog('SUCCESS', 'PAYMENT CONFIRMED. FUNDS LOCKED IN MULTISIG.'));
      addLog(generateLog('INFO', 'Vendor has been notified. Awaiting shipment.'));
      setStep(EscrowStep.ACTIVE);
    }

    if (type === 'EscrowShipped' && (step === EscrowStep.ACTIVE || step === EscrowStep.FUNDING)) {
      const trackingInfo = data?.tracking_info as string | undefined;
      addLog(generateLog('SUCCESS', 'VENDOR HAS MARKED ORDER AS SHIPPED.'));
      if (trackingInfo) {
        addLog(generateLog('INFO', `Tracking info: ${trackingInfo}`));
      }
      addLog(generateLog('INFO', 'Please confirm delivery when you receive the goods.'));
      setStep(EscrowStep.DELIVERED);
    }
  }, [wsState.lastEvent, step, addLog]);

  // React to BuyerConfirmedReceipt WebSocket event (vendor-side)
  // Transitions vendor from DELIVERED → RELEASE_SIGNING so they can co-sign
  useEffect(() => {
    if (!wsState.lastEvent) return;
    if (step !== EscrowStep.DELIVERED && step !== EscrowStep.ACTIVE) return;

    const { type } = wsState.lastEvent;

    if (type === 'BuyerConfirmedReceipt' && role === Role.VENDOR) {
      addLog(generateLog('SUCCESS', 'BUYER CONFIRMED RECEIPT. CO-SIGNING REQUIRED.'));
      addLog(generateLog('INFO', 'Enter your Shield password and co-sign to release funds.'));
      setStep(EscrowStep.RELEASE_SIGNING);
    }
  }, [wsState.lastEvent, step, role, addLog]);

  // Check for local key when entering signing-relevant steps
  useEffect(() => {
    if (!sessionId) return;
    if (step === EscrowStep.ACTIVE || step === EscrowStep.DELIVERED || step === EscrowStep.RELEASE_SIGNING || step === EscrowStep.DISPUTE_RESOLVED) {
      hasKey(sessionId).then(found => {
        setHasLocalKey(found);
        if (!found && step !== EscrowStep.DISPUTE_RESOLVED) {
          addLog(generateLog('WARN', 'LOCAL KEY NOT FOUND. Shield recovery required to sign transactions.'));
        }
      });
    }
  }, [sessionId, step, addLog]);

  // Handle Shield recovery completion
  const handleShieldRecovered = useCallback(async (keyPackage: Uint8Array, metadata: { role: string }, password: string) => {
    setShowShieldRecovery(false);
    if (sessionId) {
      try {
        const keyHex = Array.from(keyPackage).map(b => b.toString(16).padStart(2, '0')).join('');
        await storeKey(sessionId, metadata.role, keyHex, password);
        setHasLocalKey(true);
        addLog(generateLog('SUCCESS', 'SHIELD RESTORED. Key stored in browser. Signing capability online.'));

        // If we're in dispute resolution, reset claim state to trigger auto-retry via useEffect
        if (step === EscrowStep.DISPUTE_RESOLVED) {
          addLog(generateLog('INFO', 'Key restored. Retrying dispute auto-claim...'));
          setDisputeShieldPassword(password);
          setDisputeClaimStatus('idle');
          disputeClaimRef.current = false;
        }
      } catch (err) {
        addLog(generateLog('CRITICAL', `Failed to store key: ${err instanceof Error ? err.message : String(err)}`));
      }
    }
  }, [addLog, sessionId, step]);

  // ========== DISPUTE AUTO-CLAIM LOGIC ==========

  // Core auto-claim function: load key → extract share → submit
  const executeDisputeClaim = useCallback(async (password?: string) => {
    if (!sessionId || !role || disputeClaimRef.current) return;
    disputeClaimRef.current = true;
    setDisputeClaimError(null);

    const roleStr = role === Role.BUYER ? 'buyer' : 'vendor';

    try {
      // Step 1: Load key package
      setDisputeClaimStatus('loading_key');
      addLog(generateLog('INFO', 'Loading cryptographic key from local storage...'));
      const keyPackageHex = await loadKeyPackage(sessionId, roleStr, password);

      // Step 2: Extract signing share via WASM
      setDisputeClaimStatus('extracting');
      addLog(generateLog('INFO', 'Extracting FROST signing share...'));
      const secretShare = frostExtractSecretShare(keyPackageHex);

      if (!secretShare || secretShare.length !== 64) {
        throw new Error(`Invalid secret share (got ${secretShare?.length || 0} chars, expected 64)`);
      }
      addLog(generateLog('SUCCESS', `Signing share extracted: ${secretShare.slice(0, 12)}...`));

      // Step 3: Submit to server
      setDisputeClaimStatus('submitting');
      addLog(generateLog('INFO', 'Submitting share to escrow network...'));
      const resp = await submitDisputeShare(sessionId, secretShare, roleStr);

      if (resp.data?.success && resp.data?.tx_hash) {
        // Immediate broadcast success
        playTone('complete');
        setDisputeClaimStatus('completed');
        setDisputeClaimTxHash(resp.data.tx_hash);
        addTickerTx(resp.data.tx_hash, 'DISPUTE');
        addLog(generateLog('SUCCESS', `DISPUTE CLAIM BROADCAST. TX: ${resp.data.tx_hash}`));
        setStep(EscrowStep.COMPLETED);
      } else if (resp.data?.status === 'waiting') {
        // Share stored, waiting for arbiter share (watchdog handles this)
        setDisputeClaimStatus('polling');
        addLog(generateLog('INFO', 'Share submitted. Waiting for arbiter co-signature...'));

        // Poll for completion every 5 seconds
        const pollInterval = setInterval(async () => {
          try {
            const checkResp = await submitDisputeShare(sessionId, secretShare, roleStr);
            if (checkResp.data?.success && checkResp.data?.tx_hash) {
              clearInterval(pollInterval);
              setDisputeClaimStatus('completed');
              setDisputeClaimTxHash(checkResp.data.tx_hash);
              addTickerTx(checkResp.data.tx_hash, 'DISPUTE');
              addLog(generateLog('SUCCESS', `FUNDS CLAIMED. TX: ${checkResp.data.tx_hash}`));
              setStep(EscrowStep.COMPLETED);
            }
          } catch {
            // Silently retry
          }
        }, 5000);

        // Stop polling after 2 minutes
        setTimeout(() => {
          clearInterval(pollInterval);
          if (disputeClaimStatus === 'polling') {
            addLog(generateLog('INFO', 'Auto-poll timeout. Arbiter watchdog will process in background.'));
          }
        }, 120000);
      } else if (resp.error) {
        throw new Error(resp.error);
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      if (errMsg.includes('Key package not found') || errMsg.includes('Please restore from Shield')) {
        setDisputeClaimStatus('needs_restore');
        addLog(generateLog('WARN', 'Key not found in this browser. Upload your Shield backup (.nxshld) to restore.'));
      } else if (errMsg.includes('Shield password required') || errMsg.includes('key not found in storage')) {
        setDisputeClaimStatus('needs_password');
        addLog(generateLog('WARN', 'Shield password required to unlock signing key.'));
      } else {
        setDisputeClaimStatus('error');
        const h = humanizeError(errMsg);
        setDisputeClaimError(h.message);
        addLog(generateLog('CRITICAL', `${h.message} ${h.action}`));
      }
    } finally {
      disputeClaimRef.current = false;
    }
  }, [sessionId, role, addLog, disputeClaimStatus]);

  // Trigger auto-claim when step transitions to DISPUTE_RESOLVED
  useEffect(() => {
    if (step !== EscrowStep.DISPUTE_RESOLVED) return;
    if (disputeClaimStatus !== 'idle') return; // Already in progress
    if (!sessionId || !role) return;
    if (role === Role.ARBITER) return; // Arbiter doesn't claim

    // Small delay to let UI render first
    const timer = setTimeout(() => {
      // Pass Shield password if available (e.g. after Shield restore)
      executeDisputeClaim(disputeShieldPassword || undefined);
    }, 500);
    return () => clearTimeout(timer);
  }, [step, disputeClaimStatus, sessionId, role, executeDisputeClaim, disputeShieldPassword]);

  // React to WebSocket DisputeResolved event
  useEffect(() => {
    if (!wsState.lastEvent || wsState.lastEvent.type !== 'DisputeResolved') return;
    if (!role || role === Role.ARBITER) return;

    const resolution = wsState.lastEvent.data?.resolution as string | undefined;
    const isWinner = (resolution === 'buyer' && role === Role.BUYER) ||
                     (resolution === 'vendor' && role === Role.VENDOR);

    if (isWinner) {
      addLog(generateLog('SUCCESS', 'Dispute resolved in your favor. Auto-claiming funds...'));
      setDisputeClaimStatus('idle'); // Reset so the effect triggers
      disputeClaimRef.current = false;
      setStep(EscrowStep.DISPUTE_RESOLVED);
    } else {
      addLog(generateLog('WARN', 'Dispute resolved. Funds awarded to other party.'));
      setStep(EscrowStep.COMPLETED);
    }
  }, [wsState.lastEvent, role, addLog]);

  // ========== END DISPUTE AUTO-CLAIM LOGIC ==========

  // Restore step from backend status on page load/refresh
  useEffect(() => {
    if (!escrowStatus || !sessionId) return;

    // Only restore if currently IDLE (fresh page load)
    if (step !== EscrowStep.IDLE) return;

    const backendStatus = escrowStatus.status?.toLowerCase();
    console.log('[App] Restoring step from backend status:', backendStatus);

    // Map backend status to frontend step
    switch (backendStatus) {
      case 'active':
      case 'funded':
        addLog(generateLog('INFO', 'Restored session: Escrow is ACTIVE'));
        setStep(EscrowStep.ACTIVE);
        break;
      case 'delivered':
      case 'shipped':
        addLog(generateLog('INFO', 'Restored session: Awaiting buyer confirmation'));
        setStep(EscrowStep.DELIVERED);
        break;
      case 'releasing':
      case 'signing':
        addLog(generateLog('INFO', 'Restored session: Release in progress'));
        setStep(EscrowStep.RELEASE_SIGNING);
        break;
      case 'completed':
      case 'released':
        addLog(generateLog('SUCCESS', 'Restored session: Escrow completed'));
        setStep(EscrowStep.COMPLETED);
        break;
      case 'disputed':
        addLog(generateLog('WARN', 'Restored session: Escrow in dispute'));
        setStep(EscrowStep.DISPUTE);
        break;
      case 'resolved_buyer':
      case 'resolved_vendor':
        addLog(generateLog('WARN', 'Restored session: Dispute resolved. Claiming funds...'));
        setStep(EscrowStep.DISPUTE_RESOLVED);
        break;
      case 'payment_detected':
        addLog(generateLog('SUCCESS', 'Restored session: Payment detected, awaiting confirmations'));
        setStep(EscrowStep.FUNDING);
        break;
      case 'created':
      case 'pending':
        // Check DKG status
        if (escrowStatus.dkg_status === 'complete') {
          addLog(generateLog('INFO', 'Restored session: Awaiting funding'));
          setStep(EscrowStep.FUNDING);
        }
        break;
      default:
        console.log('[App] Unknown backend status:', backendStatus);
    }
  }, [escrowStatus, sessionId, step, addLog]);

  // Show loading spinner while checking session
  if (authLoading) {
    return <LoadingSpinner message="Restoring session..." />;
  }

  // Show auth modal if not authenticated
  if (!user) {
    return <AuthModal />;
  }

  // --- PHASE 1: CREATION ---
  const handleBuyerInitiate = async () => {
    setIsLoading(true);
    setStep(EscrowStep.INITIATING);
    addLog(generateLog('INFO', 'INITIALIZING 2-OF-3 THRESHOLD CIRCUIT...'));

    try {
      // Convert XMR to atomic units (1 XMR = 10^12 atomic)
      const amountAtomic = Math.floor(parseFloat(escrowAmount || '1.0') * 1e12);

      // Create escrow on backend
      const response = await createEscrowLobby(amountAtomic, 'buyer', 'Onyx Escrow');

      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to create escrow');
      }

      const escrowId = response.data.escrow_id;
      // Use last 8 chars of escrow_id as display ID
      const displayId = escrowId.replace('esc_', '').slice(-8).toUpperCase();

      setSessionId(escrowId); // Store full escrow_id for API calls
      addLog(generateLog('SUCCESS', 'CONTRACT SHELL CREATED.', `SID: ${displayId}`));
      addLog(generateLog('INFO', 'AWAITING VENDOR HANDSHAKE...'));
      setStep(EscrowStep.DKG_WAITING);
    } catch (error) {
      addLog(generateLog('CRITICAL', `ERROR: FAILED TO CREATE ESCROW: ${error instanceof Error ? error.message : String(error)}`));
      setStep(EscrowStep.IDLE);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSellerJoin = async () => {
    if (!inputSessionId || inputSessionId.length < 3) {
      addLog(generateLog('WARN', 'ERROR: INVALID SESSION ID FORMAT.'));
      return;
    }

    setIsLoading(true);
    // Normalize the input - could be full escrow_id or just the short code
    const escrowId = inputSessionId.startsWith('esc_')
      ? inputSessionId
      : `esc_${inputSessionId.toLowerCase()}`;

    addLog(generateLog('INFO', 'LOCATING UPLINK SIGNAL...', `TARGET: ${inputSessionId.toUpperCase()}`));

    try {
      // Join the escrow on backend
      const response = await joinEscrow(escrowId);

      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to join escrow');
      }

      const joinedEscrowId = response.data.escrow_id;
      setSessionId(joinedEscrowId);
      addLog(generateLog('SUCCESS', 'UPLINK ESTABLISHED. HANDSHAKE VALID.'));
      addLog(generateLog('INFO', `ROLE ASSIGNED: ${response.data.role.toUpperCase()}. STATUS: ${response.data.status.toUpperCase()}.`));

      // Fetch escrow amount from lobby status (vendor doesn't set it)
      try {
        const lobbyResp = await getLobbyStatus(joinedEscrowId);
        if (lobbyResp.success && lobbyResp.data?.amount) {
          const amountXmr = (lobbyResp.data.amount / 1e12).toString();
          setEscrowAmount(amountXmr);
        }
      } catch { /* non-critical, amount display only */ }

      // Both parties now connected - enable chat
      setBothPartiesConnected(true);

      // Automatically start DKG since both parties are now connected
      // Pass escrowId directly to avoid React async state timing issue
      setStep(EscrowStep.DKG_RUNNING);
      await handleRunDKG(joinedEscrowId);
    } catch (error) {
      addLog(generateLog('CRITICAL', `ERROR: CONNECTION FAILED: ${error instanceof Error ? error.message : String(error)}`));
      setStep(EscrowStep.IDLE);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyUplink = async () => {
    try {
      await navigator.clipboard.writeText(sessionId);
      addLog(generateLog('SUCCESS', 'UPLINK ID COPIED.'));
      // Chat opens only when both parties connected, not on copy
    } catch (err) {
      addLog(generateLog('WARN', 'ERROR: CLIPBOARD ACCESS DENIED.'));
    }
  };

  // --- PHASE 2: DKG (Key Generation) ---
  const handleRunDKG = async (escrowIdOverride?: string) => {
    if (!wasmReady) {
      addLog(generateLog('CRITICAL', 'CRYPTO MODULE FAILED. REFRESH REQUIRED.'));
      return;
    }

    // Use override if provided (for immediate calls after state update)
    const effectiveSessionId = escrowIdOverride || sessionId;

    if (!role || !effectiveSessionId) {
      addLog(generateLog('CRITICAL', 'ERROR: SESSION NOT INITIALIZED.'));
      return;
    }

    // NOTE: We don't generate a password here anymore.
    // The user will choose their password in MandatoryShieldModal,
    // which will then store the key locally with that password.
    // Using a temporary placeholder that will be overwritten when user sets their real password.
    const tempPassword = 'temp_' + crypto.randomUUID().slice(0, 8);

    setIsLoading(true);
    setStep(EscrowStep.DKG_RUNNING);

    addLog(generateLog('INFO', 'FROST PROTOCOL INITIATED (RFC 9591).'));
    addLog(generateLog('INFO', 'ASSIGNING ARBITER NODE (SHARD 3)...'));

    try {
      // Use the real FROST DKG - temporary password will be replaced by user's chosen password in Shield modal
      await startDkg(effectiveSessionId, role.toLowerCase(), tempPassword);

      // DKG state machine will handle the rest via the hook
      // When complete, transition to funding
      if (dkgState.phase === 'complete') {
        setStep(EscrowStep.FUNDING);
      }
    } catch (error) {
      const dkgErr = humanizeError(error instanceof Error ? error.message : String(error));
      addLog(generateLog('CRITICAL', `${dkgErr.message} ${dkgErr.action}`));
      setStep(EscrowStep.DKG_WAITING);
    } finally {
      setIsLoading(false);
    }
  };

  // --- PHASE 3: FUNDING ---
  const handleBuyerDeposit = async () => {
    setIsLoading(true);
    const amount = parseFloat(escrowAmount || '1.0').toFixed(2);
    addLog(generateLog('INFO', 'BROADCASTING FUNDING TX (XMR)...'));
    await delay(2000);
    addLog(generateLog('SUCCESS', 'FUNDS LOCKED IN MULTISIG.', `${amount} XMR`));
    addLog(generateLog('INFO', 'STATE: 2-OF-3 SIGNATURES REQUIRED.'));
    setStep(EscrowStep.ACTIVE);
    setIsLoading(false);
  };

  // --- PHASE 4: DELIVERY & RELEASE ---

  const handleSellerDelivery = async () => {
    // Validate payout address
    if (!vendorPayoutAddress || vendorPayoutAddress.length !== 95) {
      addLog(generateLog('CRITICAL', 'Invalid payout address. Must be 95 characters.'));
      return;
    }
    if (!vendorPayoutAddress.startsWith('4')) {
      addLog(generateLog('CRITICAL', 'Invalid address. Must start with 4 (mainnet).'));
      return;
    }
    if (!sessionId) {
      addLog(generateLog('CRITICAL', 'No active escrow session.'));
      return;
    }
    if (!backupPassword) {
      addLog(generateLog('CRITICAL', 'Shield password required to pre-sign key image.'));
      return;
    }

    setIsLoading(true);
    addLog(generateLog('INFO', 'VENDOR INITIATING SHIPMENT PROTOCOL...'));
    addLog(generateLog('INFO', `Payout address: ${vendorPayoutAddress.slice(0, 12)}...${vendorPayoutAddress.slice(-8)}`));

    try {
      // 1. Store vendor payout address and mark as shipped
      const deliverResponse = await markDelivered(sessionId, vendorPayoutAddress);
      if (!deliverResponse.success) {
        throw new Error(deliverResponse.error || 'Failed to confirm shipment');
      }

      addLog(generateLog('SUCCESS', 'STATUS: SHIPPED.'));

      // 2. Pre-submit vendor PKI so buyer release aggregates instantly
      addLog(generateLog('INFO', 'Pre-computing partial key image...'));
      const keyPackageHex = await loadKeyPackage(sessionId, 'vendor', backupPassword);
      await computeAndSubmitPartialKeyImage(sessionId, 'vendor', keyPackageHex);
      addLog(generateLog('SUCCESS', 'VENDOR PKI PRE-SUBMITTED. Buyer can release instantly.'));

      addLog(generateLog('INFO', 'Release TX will have 2 outputs: your wallet + platform fee.'));
      setStep(EscrowStep.DELIVERED);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      // If PKI fails but shipment was already marked, still transition to DELIVERED
      if (msg.includes('PKI') || msg.includes('key image') || msg.includes('Key package')) {
        addLog(generateLog('WARN', `PKI pre-submission failed: ${msg}. You can co-sign later.`));
        setStep(EscrowStep.DELIVERED);
      } else {
        addLog(generateLog('CRITICAL', `Failed to confirm shipment: ${msg}`));
      }
    } finally {
      setIsLoading(false);
    }
  };
  
  // Happy Path: Buyer confirms receipt → FROST Signing → Arbiter Watchdog auto-signs → Complete
  // Release TX has 2 outputs: vendor_payout_address + platform_fee_wallet
  const handleBuyerRelease = async () => {
    if (!sessionId || !backupPassword) {
      addLog(generateLog('CRITICAL', 'ERROR: MISSING SESSION OR PASSWORD'));
      return;
    }

    setIsLoading(true);
    setSigningProgress({ stage: 'loading_key', message: 'Loading key package...' });

    try {
      // STEP 0: Confirm receipt to change status shipped → releasing
      // Skip if: already in RELEASE_SIGNING step, status is already releasing, or role is VENDOR
      const currentStatus = escrowStatus?.status?.toLowerCase();
      const isAlreadyReleasing = step === EscrowStep.RELEASE_SIGNING ||
        currentStatus === 'releasing' || currentStatus === 'signing' || currentStatus === 'signing_initiated';

      if (role === Role.VENDOR) {
        // Vendor never calls confirmReceipt - that's a buyer-only action
        addLog(generateLog('INFO', 'Vendor co-signing release...'));
      } else if (!isAlreadyReleasing) {
        addLog(generateLog('INFO', 'Confirming receipt...'));
        await confirmReceipt(sessionId);
        addLog(generateLog('SUCCESS', 'Receipt confirmed - status: releasing'));
      } else {
        addLog(generateLog('INFO', 'Status already releasing - resuming signing...'));
      }

      // STEP 1: Load key package
      addLog(generateLog('INFO', 'Loading FROST key package...'));
      const keyPackageHex = await loadKeyPackage(sessionId, role === Role.BUYER ? 'buyer' : 'vendor', backupPassword);

      // STEP 1.5: Compute and submit partial key image (required for init_signing)
      addLog(generateLog('INFO', 'Computing partial key image...'));
      setSigningProgress({ stage: 'loading_key', message: 'Computing key image...' });
      const aggregatedKI = await computeAndSubmitPartialKeyImage(
        sessionId,
        role === Role.BUYER ? 'buyer' : 'vendor',
        keyPackageHex
      );
      addLog(generateLog('SUCCESS', `Key image aggregated: ${aggregatedKI.slice(0, 16)}...`));

      // STEP 2: Init signing session on server (builds TX, ring, BP+)
      addLog(generateLog('INFO', 'Initializing signing session...'));
      setSigningProgress({ stage: 'generating_nonce', message: 'Preparing transaction...' });
      await fetchTxDataForSigning(sessionId);
      addLog(generateLog('SUCCESS', 'Signing session initialized'));

      // STEP 3: Extract FROST secret share and submit for ATOMIC server-side CLSAG
      // Server reconstructs x_total = d + λ₁*b₁ + λ₂*b₂ and signs atomically
      // (identical to commit 835ccd0 which produced first confirmed mainnet TX)
      addLog(generateLog('INFO', 'Extracting FROST secret share...'));
      setSigningProgress({ stage: 'signing', message: 'Submitting secret share...' });

      const { frostExtractSecretShare } = await import('./services/wasmService');
      const secretShare = frostExtractSecretShare(keyPackageHex);
      addLog(generateLog('INFO', `Secret share extracted: ${secretShare.slice(0, 16)}...`));

      // STEP 4: Submit FROST share to server
      const roleStr = role === Role.BUYER ? 'buyer' : 'vendor';
      addLog(generateLog('INFO', `Submitting FROST share as ${roleStr}...`));
      await submitFrostShare(sessionId, roleStr, secretShare);
      addLog(generateLog('SUCCESS', 'FROST share submitted — waiting for peer + server CLSAG'));

      setSigningProgress({ stage: 'aggregating', message: 'Server signing CLSAG atomically...' });

      // STEP 8: Wait for broadcast
      addLog(generateLog('INFO', 'Waiting for server aggregation + broadcast...'));
      const txHash = await pollForBroadcast(sessionId);

      addLog(generateLog('SUCCESS', `TX BROADCASTED: ${txHash.slice(0, 16)}...`));
      addTickerTx(txHash, 'CLSAG');
      setSigningProgress({ stage: 'completed', message: 'Transaction completed!' });
      setStep(EscrowStep.COMPLETED);

    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      const sigErr = humanizeError(errorMsg);
      addLog(generateLog('CRITICAL', `${sigErr.message} ${sigErr.action}`));
      setSigningProgress({ stage: 'failed', message: 'Signing failed', error: errorMsg });
      setStep(EscrowStep.DELIVERED); // Allow retry
    } finally {
      setIsLoading(false);
      setBackupPassword(''); // Zeroize password
    }
  };

  return (
    <div className="relative min-h-screen bg-art-bg text-art-black font-sans selection:bg-black selection:text-white overflow-hidden">
      {/* Input Cursor Styles */}
      <style>{`
        input, textarea {
          caret-color: black;
        }
      `}</style>

      {/* E2E Encrypted Chat - Available whenever escrow is active */}
      {isChatOpen && sessionId && role && step !== EscrowStep.IDLE && (
        <div className="fixed bottom-20 left-2 right-2 sm:left-8 sm:right-auto sm:bottom-24 w-auto sm:w-96 max-w-[calc(100vw-1rem)] h-[60vh] sm:h-[500px] z-50 shadow-2xl rounded-lg overflow-hidden animate-in slide-in-from-bottom-4">
          <EscrowChat
            escrowId={sessionId}
            userRole={role === Role.BUYER ? 'buyer' : role === Role.VENDOR ? 'vendor' : 'arbiter'}
            onClose={() => setIsChatOpen(false)}
          />
        </div>
      )}

      {/* ShieldRecovery - Upload .nxshld file to restore key */}
      {showShieldRecovery && sessionId && role && (
        <ShieldRecovery
          escrowId={sessionId}
          expectedRole={role === Role.BUYER ? 'buyer' : role === Role.VENDOR ? 'vendor' : 'arbiter'}
          onRecovered={handleShieldRecovered}
          onCancel={() => setShowShieldRecovery(false)}
        />
      )}

      {/* MandatoryShieldModal - Shown after DKG completion */}
      {showShieldModal && dkgState.keyPackage && role && sessionId && (
        <MandatoryShieldModal
          escrowId={sessionId}
          role={role === Role.BUYER ? 'buyer' : role === Role.VENDOR ? 'vendor' : 'arbiter'}
          keyPackage={hexToUint8Array(dkgState.keyPackage)}
          groupPubkey={dkgState.groupPublicKey || ''}
          onComplete={handleShieldComplete}
        />
      )}

      {/* Escrow Dashboard / Lobby */}
      {showLobby && (
        <div className="fixed inset-0 z-40 overflow-y-auto">
          <EscrowDashboard
            onSelectEscrow={handleSelectEscrow}
            onCreateNew={handleCreateNewFromLobby}
            onClose={() => setShowLobby(false)}
            onBroadcastTxFound={addTickerTx}
          />
        </div>
      )}

      {/* Documentation Page */}
      {showDocs && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-art-bg animate-in fade-in duration-500">

          {/* Home Button (Top Left) */}
          <button
            onClick={() => setShowDocs(false)}
            className="fixed top-4 left-4 sm:top-8 sm:left-8 z-[60] group flex items-center gap-2 sm:gap-3 focus:outline-none"
            title="Return to Home"
          >
            <div className="w-8 h-8 sm:w-10 sm:h-10 bg-black text-white flex items-center justify-center rounded-lg sm:rounded-xl shadow-lg group-hover:rotate-90 transition-transform duration-500 ease-out">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" className="sm:w-5 sm:h-5">
                 <polygon points="12 2 2 12 12 22 22 12 12 2" />
              </svg>
            </div>
            <div className="hidden sm:flex flex-col h-8 overflow-hidden text-left">
               <span className="font-display font-extrabold text-2xl tracking-tighter leading-8 group-hover:-translate-y-8 transition-transform duration-500 ease-in-out block">
                 <OnyxLogo />
               </span>
               <span className="font-display font-bold text-2xl tracking-tighter leading-8 group-hover:-translate-y-8 transition-transform duration-500 ease-in-out block text-black/40">
                 HOME
               </span>
            </div>
          </button>

          {/* Close button - more refined */}
          <button
            onClick={() => setShowDocs(false)}
            className="fixed top-4 right-4 sm:top-8 sm:right-8 z-[60] w-10 h-10 sm:w-12 sm:h-12 bg-white border border-black/10 text-black rounded-full flex items-center justify-center hover:bg-black hover:text-white transition-all duration-300 shadow-xl group"
          >
            <span className="text-xl sm:text-2xl group-hover:rotate-90 transition-transform duration-300">&times;</span>
          </button>

          <div className="max-w-4xl mx-auto px-4 py-20 sm:px-8 sm:py-32">

            <header className="text-center mb-16 sm:mb-24">
              <div className="inline-block px-3 py-1 bg-black text-white text-[10px] font-mono font-bold uppercase tracking-[0.2em] mb-6 rounded">Technical Documentation</div>
              <h1 className="font-display text-4xl sm:text-5xl md:text-7xl font-extrabold tracking-tighter mb-4 text-black">How It Works</h1>
              <p className="text-black/40 font-mono text-xs uppercase tracking-widest">Non-Custodial Monero Escrow // FROST-RFC9591</p>
            </header>


            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 sm:gap-16 mb-16 sm:mb-24">
              {/* The Problem */}
              <section>
                <h2 className="font-display text-sm font-bold uppercase tracking-widest text-black/30 mb-6 flex items-center gap-3">
                  <div className="w-8 h-px bg-black/10"></div>
                  The Problem
                </h2>
                <p className="font-sans text-black/70 leading-relaxed text-sm">
                  Online transactions between strangers require trust. Traditional escrow services solve this by holding funds,
                  but this creates a <span className="text-black font-bold">single point of failure</span>: if the escrow is compromised, funds are lost. 
                  Monero's native multisig requires desktop software, manual coordination, and suffers from key-overlap issues that prevent browser-based use.
                </p>
              </section>

              {/* The Solution */}
              <section>
                <h2 className="font-display text-sm font-bold uppercase tracking-widest text-black/30 mb-6 flex items-center gap-3">
                  <div className="w-8 h-px bg-black/10"></div>
                  The Solution
                </h2>
                <p className="font-sans text-black/70 leading-relaxed text-sm">
                  ONYX uses <span className="text-black font-bold">threshold cryptography</span> to split control of an escrow wallet across three parties. 
                  Any 2-of-3 participants must agree to release funds. No single party — including ONYX — can spend unilaterally.
                </p>
              </section>
            </div>

            {/* Threshold Participants Cards */}
            <section className="mb-16 sm:mb-32">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6">
                {[
                  { title: 'Buyer', icon: <User size={24} />, desc: 'Key share 1 of 3' },
                  { title: 'Vendor', icon: <Store size={24} />, desc: 'Key share 2 of 3' },
                  { title: 'Arbiter', icon: <Scale size={24} />, desc: 'Key share 3 of 3' }
                ].map((item) => (
                  <div key={item.title} className="bg-white border border-black/5 rounded-2xl sm:rounded-3xl p-6 sm:p-8 flex flex-col items-center text-center shadow-sm hover:shadow-xl hover:-translate-y-1 transition-all duration-500 group">
                    <div className="w-16 h-16 bg-art-bg rounded-2xl flex items-center justify-center mb-6 group-hover:bg-black group-hover:text-white transition-colors duration-500">
                      {item.icon}
                    </div>
                    <div className="font-display font-bold text-lg mb-1">{item.title}</div>
                    <div className="font-mono text-[10px] text-black/40 uppercase tracking-widest">{item.desc}</div>
                  </div>
                ))}
              </div>
            </section>

            {/* How an Escrow Works */}
            <section className="mb-16 sm:mb-32">
              <h2 className="font-display text-2xl sm:text-3xl font-bold tracking-tight mb-10 sm:mb-16 text-center italic">Escrow Lifecycle</h2>
              <div className="space-y-8 sm:space-y-12">
                {[
                  { step: '01', title: 'Escrow Creation', desc: 'A buyer or vendor creates an escrow, specifying the amount and description. A unique link is generated for the counterparty to join.' },
                  { step: '02', title: 'Key Generation', desc: 'When both parties join, a Distributed Key Generation (DKG) protocol runs automatically in their browsers in under 1 second. Each participant receives a unique cryptographic key share. The full spending key never exists in any single location.' },
                  { step: '03', title: 'Funding', desc: 'The buyer sends Monero to the escrow address. ONYX monitors the blockchain and confirms when the payment arrives (typically 10 confirmations, ~20 minutes).' },
                  { step: '04', title: 'Fulfillment', desc: 'The vendor delivers the goods or services as agreed.' },
                  { step: '05', title: 'Release', desc: 'The buyer confirms receipt. Two key holders collaborate to sign a release transaction, sending funds to the vendor. Signing happens client-side — private keys never touch the server.' },
                  { step: '06', title: 'Disputes', desc: 'If there\'s a disagreement, the arbiter reviews evidence and decides whether to release or refund. The arbiter\'s key share combined with one party\'s share executes the decision.' },
                ].map(({ step, title, desc }) => (
                  <div key={step} className="flex gap-4 sm:gap-10 group">
                    <div className="font-display text-3xl sm:text-5xl font-extrabold text-black/5 leading-none pt-1 group-hover:text-black/10 transition-colors duration-500 shrink-0">{step}</div>
                    <div className="pt-2 border-t border-black/5 flex-1">
                      <h3 className="font-display font-bold text-xl mb-3">{title}</h3>
                      <p className="font-sans text-black/50 text-sm leading-relaxed">{desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* Security */}
            <section className="mb-16 sm:mb-32">
              <h2 className="font-display text-2xl sm:text-3xl font-bold tracking-tight mb-8 sm:mb-12 text-center italic">Privacy Architecture</h2>
              <div className="bg-black rounded-2xl sm:rounded-[3rem] p-6 sm:p-12 text-white mb-8 shadow-2xl relative overflow-hidden group">
                {/* Decorative glow */}
                <div className="absolute top-0 right-0 w-64 h-64 bg-white/5 rounded-full -translate-y-1/2 translate-x-1/2 blur-3xl group-hover:bg-white/10 transition-colors duration-1000"></div>
                
                <h3 className="font-display font-bold text-2xl mb-6 text-white relative z-10">The Server is a Blind Relay</h3>
                <p className="font-sans text-white/60 text-base leading-relaxed mb-10 max-w-2xl relative z-10">
                  The ONYX server coordinates communication between participants but never sees private keys, amounts, or plaintext transaction data.
                  It receives only <span className="text-white font-bold italic">opaque cryptographic packages</span> that are useless without the corresponding key shares.
                </p>
                
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4 relative z-10">
                  {[
                    { label: 'Server holds keys', value: 'Never' },
                    { label: 'Server can spend', value: 'Impossible' },
                    { label: 'Keys leave browser', value: 'Never' },
                    { label: 'TX Traceable', value: 'No' },
                  ].map(({ label, value }) => (
                    <div key={label} className="bg-white/5 border border-white/10 rounded-xl sm:rounded-2xl px-4 py-3 sm:px-6 sm:py-4 backdrop-blur-sm">
                      <span className="block font-mono text-[9px] uppercase tracking-widest text-white/30 mb-1">{label}</span>
                      <span className="block font-display font-bold text-lg text-white">{value}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-white border border-black/5 rounded-2xl sm:rounded-[2rem] p-6 sm:p-10 shadow-sm">
                <h3 className="font-display font-bold text-xl mb-4 text-black">What If ONYX Goes Down?</h3>
                <p className="font-sans text-black/60 text-sm leading-relaxed">
                  Because key shares are held by participants (not the server), funds are always recoverable.
                  Two participants can coordinate independently to sign a transaction.
                  Shield Backup allows encrypted recovery data export.
                  The escrow address and its funds remain on the Monero blockchain regardless of ONYX availability.
                </p>
              </div>
            </section>

            {/* Technical Foundation */}
            <section className="mb-16 sm:mb-32">
              <h2 className="font-display text-2xl sm:text-3xl font-bold tracking-tight mb-8 sm:mb-12 text-center italic">Protocol Stack</h2>
              <div className="overflow-x-auto rounded-2xl sm:rounded-3xl border border-black/5 bg-white shadow-sm">
                <table className="w-full text-left border-collapse min-w-[500px]">
                  <thead>
                    <tr className="bg-black/5 border-b border-black/5">
                      <th className="px-4 py-3 sm:px-8 sm:py-5 font-display font-bold text-[10px] uppercase tracking-widest text-black/40">Component</th>
                      <th className="px-4 py-3 sm:px-8 sm:py-5 font-display font-bold text-[10px] uppercase tracking-widest text-black/40">Standard</th>
                      <th className="px-4 py-3 sm:px-8 sm:py-5 font-display font-bold text-[10px] uppercase tracking-widest text-black/40">Purpose</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-black/5">
                    {[
                      ['Key Generation', 'FROST (RFC 9591)', 'Distributed key generation without trusted dealer'],
                      ['Signatures', 'CLSAG', 'Monero ring signatures (audited, production since 2020)'],
                      ['Privacy', 'RingCT + Bulletproofs+', 'Amount hiding and range proofs'],
                      ['Client Crypto', 'WebAssembly', 'Browser-native cryptographic execution'],
                      ['Threshold', 'Shamir Secret Sharing', '2-of-3 key splitting with Lagrange interpolation'],
                    ].map(([component, standard, purpose]) => (
                      <tr key={component} className="hover:bg-art-bg/50 transition-colors">
                        <td className="px-4 py-3 sm:px-8 sm:py-5 font-display font-bold text-xs sm:text-sm">{component}</td>
                        <td className="px-4 py-3 sm:px-8 sm:py-5 font-mono text-[10px] sm:text-xs text-black/40 italic">{standard}</td>
                        <td className="px-4 py-3 sm:px-8 sm:py-5 text-black/60 text-xs sm:text-sm leading-relaxed">{purpose}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="font-mono text-[9px] text-black/30 uppercase tracking-[0.2em] mt-6 text-center">
                Threshold signatures are indistinguishable from standard Monero transactions.
              </p>
            </section>

            {/* FAQ */}
            <section className="mb-16 sm:mb-32">
              <h2 className="font-display text-2xl sm:text-3xl font-bold tracking-tight mb-10 sm:mb-16 text-center italic">Common Inquiries</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 sm:gap-x-16 gap-y-8 sm:gap-y-12">
                {[
                  { q: 'What if the arbiter colludes with one party?', a: 'In standard flows, the arbiter is automated and signs only when both parties agree. For disputes, evidence is submitted and arbiter decisions are logged.' },
                  { q: 'What cryptocurrencies are supported?', a: 'Monero (XMR) only. Ring signatures, stealth addresses, and confidential transactions are essential to the privacy guarantees.' },
                  { q: 'What fees does ONYX charge?', a: 'A 5% platform fee is deducted upon release, or 3% upon refund. B2B API clients benefit from reduced rates (starting at 1.5%). Standard Monero network fees (~0.0001 XMR) also apply.' },
                  { q: 'How fast is signing?', a: 'Key generation: < 1 second. Transaction signing: < 100ms. The main delay is Monero confirmation time (~2 min/block, 10+ confirmations recommended).' },
                ].map(({ q, a }) => (
                  <div key={q} className="group">
                    <h3 className="font-display font-bold text-base mb-3 group-hover:text-black transition-colors">{q}</h3>
                    <p className="font-sans text-black/50 text-sm leading-relaxed">{a}</p>
                  </div>
                ))}
              </div>
            </section>

            <footer className="text-center pb-32 border-t border-black/5 pt-16">
              <p className="font-display font-bold text-black/10 text-xl tracking-[0.5em] uppercase">Non-custodial by math, not by promise.</p>
            </footer>
          </div>
        </div>
      )}

      {/* ── API Key Management Panel ────────────────────────────────────── */}
      {showApiPanel && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-art-bg animate-in fade-in duration-500">

          {/* Home Button */}
          <button
            onClick={() => setShowApiPanel(false)}
            className="fixed top-4 left-4 sm:top-8 sm:left-8 z-[60] group flex items-center gap-2 sm:gap-3 focus:outline-none"
            title="Return to Home"
          >
            <div className="w-8 h-8 sm:w-10 sm:h-10 bg-black text-white flex items-center justify-center rounded-lg sm:rounded-xl shadow-lg group-hover:rotate-90 transition-transform duration-500 ease-out">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" className="sm:w-5 sm:h-5">
                 <polygon points="12 2 2 12 12 22 22 12 12 2" />
              </svg>
            </div>
            <div className="hidden sm:flex flex-col h-8 overflow-hidden text-left">
               <span className="font-display font-extrabold text-2xl tracking-tighter leading-8 group-hover:-translate-y-8 transition-transform duration-500 ease-in-out block">
                 <OnyxLogo />
               </span>
               <span className="font-display font-bold text-2xl tracking-tighter leading-8 group-hover:-translate-y-8 transition-transform duration-500 ease-in-out block text-black/40">
                 HOME
               </span>
            </div>
          </button>

          {/* Close button */}
          <button
            onClick={() => setShowApiPanel(false)}
            className="fixed top-4 right-4 sm:top-8 sm:right-8 z-[60] w-10 h-10 sm:w-12 sm:h-12 bg-white border border-black/10 text-black rounded-full flex items-center justify-center hover:bg-black hover:text-white transition-all duration-300 shadow-xl group"
          >
            <span className="text-xl sm:text-2xl group-hover:rotate-90 transition-transform duration-300">&times;</span>
          </button>

          <div className="max-w-4xl mx-auto px-4 py-20 sm:px-8 sm:py-32">

            <header className="text-center mb-16 sm:mb-24">
              <div className="inline-block px-3 py-1 bg-black text-white text-[10px] font-mono font-bold uppercase tracking-[0.2em] mb-6 rounded">B2B Integration</div>
              <h1 className="font-display text-4xl sm:text-5xl md:text-7xl font-extrabold tracking-tighter mb-4 text-black">API Keys</h1>
              <p className="text-black/40 font-mono text-xs uppercase tracking-widest">Programmatic Escrow Access // EaaS REST API</p>
            </header>

            {/* Create New Key */}
            <section className="mb-12 sm:mb-16">
              <h2 className="font-display text-sm font-bold uppercase tracking-widest text-black/30 mb-6 flex items-center gap-3">
                <div className="w-8 h-px bg-black/10"></div>
                Generate New Key
              </h2>
              <div className="bg-white border border-black/5 rounded-2xl sm:rounded-3xl p-6 sm:p-8 shadow-sm">
                <div className="flex flex-col sm:flex-row gap-3 sm:gap-4">
                  <input
                    type="text"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    placeholder="Key name (e.g. Production, Staging)"
                    className="flex-1 px-4 py-3 bg-art-bg border border-black/5 rounded-xl font-mono text-sm focus:outline-none focus:ring-2 focus:ring-black/20 transition-all"
                    maxLength={100}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleCreateApiKey(); }}
                  />
                  <button
                    onClick={handleCreateApiKey}
                    disabled={!newKeyName.trim()}
                    className="px-6 py-3 bg-black text-white rounded-xl font-display font-bold text-sm uppercase tracking-wider hover:bg-black/80 disabled:opacity-30 disabled:cursor-not-allowed transition-all duration-300 shrink-0"
                  >
                    Generate
                  </button>
                </div>

                {apiError && (
                  <div className="mt-4 px-4 py-3 bg-red-50 border border-red-200 rounded-xl text-red-700 text-sm font-mono">
                    {apiError}
                  </div>
                )}

                {/* Newly Created Key (shown once) */}
                {createdKey && (
                  <div className="mt-6 p-6 bg-black rounded-2xl text-white relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-white/5 rounded-full -translate-y-1/2 translate-x-1/2 blur-2xl"></div>
                    <div className="relative z-10">
                      <div className="flex items-center gap-2 mb-3">
                        <AlertTriangle size={16} className="text-yellow-400" />
                        <span className="font-display font-bold text-xs uppercase tracking-widest text-yellow-400">Save this key — it won't be shown again</span>
                      </div>
                      <div className="flex items-center gap-3 bg-white/10 rounded-xl px-4 py-3 font-mono text-sm break-all">
                        <span className="flex-1 select-all">{createdKey.raw_key}</span>
                        <button
                          onClick={() => copyToClipboard(createdKey.raw_key, 'new-key')}
                          className="shrink-0 p-2 hover:bg-white/10 rounded-lg transition-colors"
                          title="Copy to clipboard"
                        >
                          {copiedKeyId === 'new-key' ? <CheckCircle size={16} className="text-green-400" /> : <Copy size={16} />}
                        </button>
                      </div>
                      <div className="mt-3 flex gap-4 text-[10px] font-mono uppercase tracking-widest text-white/40">
                        <span>Name: {createdKey.name}</span>
                        <span>Tier: {createdKey.tier}</span>
                        <span>Prefix: {createdKey.key_prefix}</span>
                      </div>
                      <button
                        onClick={() => setCreatedKey(null)}
                        className="mt-4 px-4 py-2 bg-white/10 hover:bg-white/20 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors"
                      >
                        I've saved this key
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </section>

            {/* Existing Keys */}
            <section className="mb-12 sm:mb-16">
              <h2 className="font-display text-sm font-bold uppercase tracking-widest text-black/30 mb-6 flex items-center gap-3">
                <div className="w-8 h-px bg-black/10"></div>
                Your API Keys
                <span className="text-[10px] font-mono text-black/20 ml-auto">{apiKeys.length}/10</span>
              </h2>

              {apiKeysLoading ? (
                <div className="flex justify-center py-16">
                  <div className="w-8 h-8 border-2 border-black/10 border-t-black rounded-full animate-spin"></div>
                </div>
              ) : apiKeys.length === 0 ? (
                <div className="bg-white border border-black/5 rounded-2xl sm:rounded-3xl p-10 sm:p-16 text-center shadow-sm">
                  <div className="w-16 h-16 bg-art-bg rounded-2xl flex items-center justify-center mx-auto mb-6">
                    <FileKey size={24} className="text-black/20" />
                  </div>
                  <p className="font-display font-bold text-lg text-black/30 mb-2">No API keys yet</p>
                  <p className="font-sans text-sm text-black/30">Generate your first key to start integrating ONYX escrow into your platform.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {apiKeys.map((key) => (
                    <div
                      key={key.id}
                      className={`bg-white border rounded-2xl p-5 sm:p-6 shadow-sm transition-all duration-300 hover:shadow-md ${
                        key.is_active ? 'border-black/5' : 'border-red-200 bg-red-50/30 opacity-60'
                      }`}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-6">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-3 mb-1">
                            <span className="font-display font-bold text-base truncate">{key.name}</span>
                            <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider ${
                              key.is_active
                                ? 'bg-green-100 text-green-700'
                                : 'bg-red-100 text-red-700'
                            }`}>
                              {key.is_active ? 'Active' : 'Revoked'}
                            </span>
                            <span className="px-2 py-0.5 bg-black/5 rounded-full text-[9px] font-mono uppercase tracking-wider text-black/40">
                              {key.tier}
                            </span>
                          </div>
                          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-mono text-black/30 uppercase tracking-wider">
                            <span>Prefix: {key.key_prefix}...</span>
                            <span>Created: {new Date(key.created_at).toLocaleDateString()}</span>
                            {key.last_used_at && <span>Last used: {new Date(key.last_used_at).toLocaleDateString()}</span>}
                            <span>Requests: {(key.total_requests || 0).toLocaleString()}</span>
                            {key.expires_at && <span>Expires: {new Date(key.expires_at).toLocaleDateString()}</span>}
                          </div>
                        </div>
                        <div className="flex gap-2 shrink-0">
                          {key.is_active && (
                            <button
                              onClick={() => handleRevokeKey(key.id)}
                              className="px-3 py-2 bg-black/5 hover:bg-red-100 hover:text-red-700 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors"
                            >
                              Revoke
                            </button>
                          )}
                          {!key.is_active && (
                            <button
                              onClick={() => handleDeleteKey(key.id)}
                              className="px-3 py-2 bg-red-50 hover:bg-red-100 text-red-600 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors"
                            >
                              Delete
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {/* Quick Start Guide */}
            <section className="mb-16 sm:mb-32">
              <h2 className="font-display text-sm font-bold uppercase tracking-widest text-black/30 mb-6 flex items-center gap-3">
                <div className="w-8 h-px bg-black/10"></div>
                Quick Start
              </h2>
              <div className="bg-black rounded-2xl sm:rounded-[3rem] p-6 sm:p-12 text-white shadow-2xl relative overflow-hidden">
                <div className="absolute top-0 right-0 w-64 h-64 bg-white/5 rounded-full -translate-y-1/2 translate-x-1/2 blur-3xl"></div>
                <div className="relative z-10">
                  <h3 className="font-display font-bold text-2xl mb-8">Integration in 3 Steps</h3>
                  <div className="space-y-6">
                    {[
                      {
                        step: '01',
                        title: 'Authenticate',
                        code: 'curl -H "Authorization: Bearer YOUR_API_KEY" \\\n  https://your-onyx-instance/api/v1/escrows/create',
                      },
                      {
                        step: '02',
                        title: 'Create Escrow',
                        code: 'curl -X POST /api/v1/escrows/create \\\n  -H "Authorization: Bearer YOUR_API_KEY" \\\n  -d \'{"amount": 1000000000000, "role": "buyer"}\'',
                      },
                      {
                        step: '03',
                        title: 'Register Webhooks',
                        code: 'curl -X POST /api/v1/webhooks \\\n  -H "Authorization: Bearer YOUR_API_KEY" \\\n  -d \'{"url": "https://you.com/hook", "events": ["escrow.funded"]}\'',
                      },
                    ].map(({ step, title, code }) => (
                      <div key={step} className="flex gap-6 group">
                        <div className="font-display text-3xl font-extrabold text-white/10 leading-none pt-1 shrink-0">{step}</div>
                        <div className="flex-1">
                          <h4 className="font-display font-bold text-lg mb-2">{title}</h4>
                          <pre className="bg-white/5 border border-white/10 rounded-xl px-4 py-3 font-mono text-xs text-white/60 overflow-x-auto whitespace-pre">{code}</pre>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>

            {/* Pricing Tiers */}
            <section className="mb-16 sm:mb-32">
              <h2 className="font-display text-2xl sm:text-3xl font-bold tracking-tight mb-10 sm:mb-16 text-center italic">API Tiers</h2>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6">
                {[
                  { tier: 'Free', rate: '100 req/min', fee: '1.5%', desc: 'Development & testing' },
                  { tier: 'Pro', rate: '500 req/min', fee: '1.25%', desc: 'Production workloads' },
                  { tier: 'Enterprise', rate: '2000 req/min', fee: 'Custom', desc: 'High-volume partners' },
                ].map((t) => (
                  <div key={t.tier} className="bg-white border border-black/5 rounded-2xl sm:rounded-3xl p-6 sm:p-8 flex flex-col items-center text-center shadow-sm hover:shadow-xl hover:-translate-y-1 transition-all duration-500 group">
                    <div className="w-16 h-16 bg-art-bg rounded-2xl flex items-center justify-center mb-6 group-hover:bg-black group-hover:text-white transition-colors duration-500">
                      <Network size={24} />
                    </div>
                    <div className="font-display font-bold text-lg mb-1">{t.tier}</div>
                    <div className="font-mono text-[10px] text-black/40 uppercase tracking-widest mb-3">{t.desc}</div>
                    <div className="flex gap-4 text-xs font-mono text-black/50">
                      <span>{t.rate}</span>
                      <span>Fee: {t.fee}</span>
                    </div>
                  </div>
                ))}
              </div>
              <p className="font-mono text-[9px] text-black/30 uppercase tracking-[0.2em] mt-6 text-center">
                New keys start at Free tier. Contact us to upgrade.
              </p>
            </section>

            {/* Available Events */}
            <section className="mb-16 sm:mb-32">
              <h2 className="font-display text-2xl sm:text-3xl font-bold tracking-tight mb-8 sm:mb-12 text-center italic">Webhook Events</h2>
              <div className="overflow-x-auto rounded-2xl sm:rounded-3xl border border-black/5 bg-white shadow-sm">
                <table className="w-full text-left border-collapse min-w-[500px]">
                  <thead>
                    <tr className="bg-black/5 border-b border-black/5">
                      <th className="px-4 py-3 sm:px-8 sm:py-5 font-display font-bold text-[10px] uppercase tracking-widest text-black/40">Event</th>
                      <th className="px-4 py-3 sm:px-8 sm:py-5 font-display font-bold text-[10px] uppercase tracking-widest text-black/40">Trigger</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-black/5">
                    {[
                      ['escrow.created', 'New escrow initialized via API'],
                      ['escrow.funded', 'Payment confirmed on blockchain (10+ confirmations)'],
                      ['escrow.shipped', 'Vendor marks goods as shipped'],
                      ['escrow.released', 'Funds released to vendor'],
                      ['escrow.refunded', 'Funds returned to buyer'],
                      ['escrow.disputed', 'Dispute opened by either party'],
                      ['escrow.resolved', 'Dispute resolved by arbiter'],
                      ['escrow.cancelled', 'Escrow timed out or cancelled'],
                    ].map(([event, trigger]) => (
                      <tr key={event} className="hover:bg-art-bg/50 transition-colors">
                        <td className="px-4 py-3 sm:px-8 sm:py-5 font-mono text-xs sm:text-sm font-bold">{event}</td>
                        <td className="px-4 py-3 sm:px-8 sm:py-5 text-black/60 text-xs sm:text-sm">{trigger}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <footer className="text-center pb-32 border-t border-black/5 pt-16">
              <p className="font-display font-bold text-black/10 text-xl tracking-[0.5em] uppercase">Escrow-as-a-Service</p>
            </footer>
          </div>
        </div>
      )}

      {/* ── Contact Modal ─────────────────────────────────────────────── */}
      {showContact && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm animate-in fade-in duration-300" onClick={() => setShowContact(false)}>
          <div
            className="bg-white rounded-3xl shadow-2xl w-full max-w-lg mx-4 p-8 sm:p-10 relative animate-in zoom-in-95 duration-300"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Close */}
            <button
              onClick={() => setShowContact(false)}
              className="absolute top-4 right-4 w-8 h-8 bg-black/5 text-black/40 rounded-full flex items-center justify-center hover:bg-black hover:text-white transition-all duration-300"
            >
              <span className="text-lg">&times;</span>
            </button>

            {!contactSent ? (
              <>
                <div className="text-center mb-8">
                  <div className="inline-block px-3 py-1 bg-black text-white text-[10px] font-mono font-bold uppercase tracking-[0.2em] mb-4 rounded">Get in Touch</div>
                  <h2 className="font-display text-3xl font-extrabold tracking-tighter text-black">Contact Us</h2>
                  <p className="text-black/40 font-mono text-[10px] uppercase tracking-widest mt-2">contact@onyx-escrow.com</p>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block font-mono text-[10px] font-bold uppercase tracking-widest text-black/30 mb-2">Your Email</label>
                    <input
                      type="email"
                      value={contactEmail}
                      onChange={(e) => setContactEmail(e.target.value)}
                      placeholder="you@company.com"
                      className="w-full px-4 py-3 bg-art-bg border border-black/5 rounded-xl font-mono text-sm focus:outline-none focus:ring-2 focus:ring-black/20 transition-all"
                    />
                  </div>
                  <div>
                    <label className="block font-mono text-[10px] font-bold uppercase tracking-widest text-black/30 mb-2">Subject</label>
                    <select
                      value={contactSubject}
                      onChange={(e) => setContactSubject(e.target.value)}
                      className="w-full px-4 py-3 bg-art-bg border border-black/5 rounded-xl font-mono text-sm focus:outline-none focus:ring-2 focus:ring-black/20 transition-all appearance-none"
                    >
                      <option value="">Select a topic...</option>
                      <option value="B2B Partnership">B2B Partnership / API Integration</option>
                      <option value="Enterprise Tier">Enterprise Tier Request</option>
                      <option value="Technical Support">Technical Support</option>
                      <option value="Dispute Resolution">Dispute Resolution</option>
                      <option value="General Inquiry">General Inquiry</option>
                    </select>
                  </div>
                  <div>
                    <label className="block font-mono text-[10px] font-bold uppercase tracking-widest text-black/30 mb-2">Message</label>
                    <textarea
                      value={contactMessage}
                      onChange={(e) => setContactMessage(e.target.value)}
                      placeholder="Tell us how we can help..."
                      rows={4}
                      className="w-full px-4 py-3 bg-art-bg border border-black/5 rounded-xl font-mono text-sm focus:outline-none focus:ring-2 focus:ring-black/20 transition-all resize-none"
                    />
                  </div>
                </div>

                <button
                  onClick={() => {
                    const subject = encodeURIComponent(contactSubject || 'ONYX Inquiry');
                    const body = encodeURIComponent(`From: ${contactEmail}\n\n${contactMessage}`);
                    window.open(`mailto:contact@onyx-escrow.com?subject=${subject}&body=${body}`, '_blank');
                    setContactSent(true);
                  }}
                  disabled={!contactEmail.trim() || !contactMessage.trim()}
                  className="w-full mt-6 px-6 py-3.5 bg-black text-white rounded-xl font-display font-bold text-sm uppercase tracking-wider hover:bg-black/80 disabled:opacity-30 disabled:cursor-not-allowed transition-all duration-300"
                >
                  Send Message
                </button>

                <p className="text-center text-[10px] font-mono text-black/20 uppercase tracking-widest mt-4">
                  Opens your default email client
                </p>
              </>
            ) : (
              <div className="text-center py-8">
                <div className="w-16 h-16 bg-green-100 rounded-2xl flex items-center justify-center mx-auto mb-6">
                  <CheckCircle size={28} className="text-green-600" />
                </div>
                <h3 className="font-display font-bold text-2xl mb-2">Message Ready</h3>
                <p className="text-black/40 text-sm mb-6">Your email client should have opened with the message pre-filled.</p>
                <button
                  onClick={() => { setContactSent(false); setContactEmail(''); setContactMessage(''); setContactSubject(''); setShowContact(false); }}
                  className="px-6 py-2.5 bg-black/5 hover:bg-black hover:text-white rounded-xl text-sm font-bold uppercase tracking-wider transition-all duration-300"
                >
                  Close
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Arbiter Panel ─────────────────────────────────────────────── */}
      {showArbiterPanel && (
        <div className="fixed inset-0 z-50 bg-white overflow-y-auto animate-in fade-in duration-300">
          <div className="max-w-4xl mx-auto px-6 py-20">
            {/* Header */}
            <div className="flex items-center justify-between mb-12">
              <div>
                <div className="inline-block px-3 py-1 bg-red-600 text-white text-[10px] font-mono font-bold uppercase tracking-[0.2em] mb-4 rounded">Arbiter</div>
                <h1 className="font-display text-4xl font-extrabold tracking-tighter text-black">Dispute Resolution</h1>
                <p className="text-black/40 font-mono text-xs mt-2">Review and resolve escrow disputes</p>
              </div>
              <button
                onClick={() => setShowArbiterPanel(false)}
                className="w-10 h-10 bg-black/5 text-black/40 rounded-full flex items-center justify-center hover:bg-black hover:text-white transition-all duration-300"
              >
                <span className="text-xl">&times;</span>
              </button>
            </div>

            {arbiterError && (
              <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-2xl text-red-700 text-sm font-mono">
                {arbiterError}
                <button onClick={() => setArbiterError(null)} className="ml-4 text-red-400 hover:text-red-600">&times;</button>
              </div>
            )}

            {/* Selected Dispute Detail */}
            {selectedDispute ? (
              <div className="mb-8">
                <button onClick={() => { setSelectedDispute(null); setResolveAddress(''); }} className="mb-6 text-sm font-mono text-black/40 hover:text-black flex items-center gap-2">
                  &larr; Back to disputes
                </button>

                <div className="bg-white border border-black/10 rounded-3xl p-8 shadow-sm">
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="font-display text-2xl font-bold tracking-tight">Dispute {selectedDispute.id}</h2>
                    <span className="px-3 py-1 bg-red-100 text-red-700 text-[10px] font-mono font-bold uppercase rounded-full">{selectedDispute.status}</span>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mb-6">
                    <div className="p-4 bg-black/[0.02] rounded-2xl">
                      <label className="block font-mono text-[9px] uppercase tracking-widest text-black/40 mb-1">Buyer</label>
                      <div className="font-bold text-sm">{selectedDispute.buyer_username}</div>
                    </div>
                    <div className="p-4 bg-black/[0.02] rounded-2xl">
                      <label className="block font-mono text-[9px] uppercase tracking-widest text-black/40 mb-1">Vendor</label>
                      <div className="font-bold text-sm">{selectedDispute.vendor_username}</div>
                    </div>
                    <div className="p-4 bg-black/[0.02] rounded-2xl">
                      <label className="block font-mono text-[9px] uppercase tracking-widest text-black/40 mb-1">Amount</label>
                      <div className="font-bold text-sm font-mono">{(selectedDispute.amount / 1e12).toFixed(6)} XMR</div>
                    </div>
                    <div className="p-4 bg-black/[0.02] rounded-2xl">
                      <label className="block font-mono text-[9px] uppercase tracking-widest text-black/40 mb-1">Disputed At</label>
                      <div className="font-bold text-sm font-mono">{selectedDispute.dispute_created_at || selectedDispute.created_at}</div>
                    </div>
                  </div>

                  {selectedDispute.reason && (
                    <div className="mb-6 p-4 bg-yellow-50 border border-yellow-200 rounded-2xl">
                      <label className="block font-mono text-[9px] uppercase tracking-widest text-yellow-600 mb-2">Dispute Reason</label>
                      <p className="text-sm text-yellow-900">{selectedDispute.reason}</p>
                    </div>
                  )}

                  {/* Resolve Actions */}
                  <div className="border-t border-black/5 pt-6">
                    <h3 className="font-display font-bold text-lg mb-4">Resolve Dispute</h3>

                    <div className="mb-4">
                      <label className="block font-mono text-[10px] uppercase tracking-widest text-black/40 mb-2">Recipient Monero Address</label>
                      <input
                        type="text"
                        value={resolveAddress}
                        onChange={(e) => setResolveAddress(e.target.value)}
                        placeholder="4... (95 character Monero address)"
                        className="w-full px-4 py-3 bg-black/[0.02] border border-black/10 rounded-xl font-mono text-xs focus:outline-none focus:border-black/30 transition-colors"
                      />
                      {resolveAddress && resolveAddress.length !== 95 && (
                        <p className="text-red-500 text-[10px] font-mono mt-1">{resolveAddress.length}/95 characters</p>
                      )}
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <button
                        onClick={() => handleResolveDispute(selectedDispute.escrow_id, 'buyer')}
                        disabled={resolveLoading || !resolveAddress}
                        className="p-4 bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-2xl transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        <div className="font-bold text-blue-700 text-sm mb-1">Refund Buyer</div>
                        <div className="text-blue-500 text-[10px] font-mono">Funds returned to buyer address</div>
                      </button>
                      <button
                        onClick={() => handleResolveDispute(selectedDispute.escrow_id, 'vendor')}
                        disabled={resolveLoading || !resolveAddress}
                        className="p-4 bg-green-50 hover:bg-green-100 border border-green-200 rounded-2xl transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        <div className="font-bold text-green-700 text-sm mb-1">Release to Vendor</div>
                        <div className="text-green-500 text-[10px] font-mono">Funds sent to vendor address</div>
                      </button>
                    </div>

                    {resolveLoading && (
                      <div className="mt-4 text-center">
                        <div className="inline-flex items-center gap-2 px-4 py-2 bg-black/5 rounded-full">
                          <div className="w-3 h-3 border-2 border-black/20 border-t-black rounded-full animate-spin"></div>
                          <span className="text-xs font-mono">Processing resolution...</span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              /* Disputes List */
              <div>
                <div className="flex items-center justify-between mb-6">
                  <h2 className="font-display text-xl font-bold">Active Disputes ({arbiterDisputes.length})</h2>
                  <button
                    onClick={loadArbiterDisputes}
                    disabled={arbiterLoading}
                    className="px-4 py-2 bg-black/5 hover:bg-black hover:text-white rounded-xl text-xs font-bold uppercase tracking-wider transition-all duration-300 disabled:opacity-50"
                  >
                    {arbiterLoading ? 'Loading...' : 'Refresh'}
                  </button>
                </div>

                {arbiterDisputes.length === 0 ? (
                  <div className="text-center py-16 bg-black/[0.02] rounded-3xl">
                    <div className="text-4xl mb-4 opacity-20">&#9878;</div>
                    <p className="font-display font-bold text-lg text-black/30">No Active Disputes</p>
                    <p className="text-black/20 text-sm mt-2">Disputes assigned to you will appear here</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {arbiterDisputes.map((dispute) => (
                      <button
                        key={dispute.id}
                        onClick={() => setSelectedDispute(dispute)}
                        className="w-full text-left bg-white border border-black/10 rounded-2xl p-6 hover:border-black/20 hover:shadow-md transition-all duration-300"
                      >
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-3">
                            <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></span>
                            <span className="font-display font-bold text-sm">{dispute.id}</span>
                          </div>
                          <span className="px-2 py-0.5 bg-red-100 text-red-700 text-[10px] font-mono font-bold uppercase rounded">{dispute.status}</span>
                        </div>
                        <div className="grid grid-cols-3 gap-4 text-xs">
                          <div>
                            <span className="text-black/40 font-mono text-[9px] uppercase">Buyer</span>
                            <div className="font-bold mt-0.5">{dispute.buyer_username}</div>
                          </div>
                          <div>
                            <span className="text-black/40 font-mono text-[9px] uppercase">Vendor</span>
                            <div className="font-bold mt-0.5">{dispute.vendor_username}</div>
                          </div>
                          <div>
                            <span className="text-black/40 font-mono text-[9px] uppercase">Amount</span>
                            <div className="font-bold font-mono mt-0.5">{(dispute.amount / 1e12).toFixed(4)} XMR</div>
                          </div>
                        </div>
                        {dispute.reason && (
                          <p className="mt-3 text-xs text-black/50 truncate">{dispute.reason}</p>
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      <TrustMonitor role={role} onDashboardClick={() => setShowLobby(!showLobby)} showLobby={showLobby} />

      {/* Navigation - Minimalist */}
      <nav className="fixed top-0 left-0 w-full px-4 py-3 sm:px-6 sm:py-4 md:p-8 flex justify-between items-center z-40 bg-art-bg/80 backdrop-blur-sm">
        <button
          onClick={() => {
            setStep(EscrowStep.IDLE);
            setSessionId('');
            setShowLobby(false);
          }}
          className="group flex items-center gap-2 sm:gap-3 focus:outline-none"
          title="Return to Home"
        >
          <div className="w-8 h-8 sm:w-10 sm:h-10 bg-black text-white flex items-center justify-center rounded-lg sm:rounded-xl shadow-lg group-hover:rotate-90 transition-transform duration-500 ease-out">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" className="sm:w-5 sm:h-5">
               <polygon points="12 2 2 12 12 22 22 12 12 2" />
            </svg>
          </div>
          <div className="hidden sm:flex flex-col h-8 overflow-hidden text-left">
             <span className="font-display font-extrabold text-2xl tracking-tighter leading-8 group-hover:-translate-y-8 transition-transform duration-500 ease-in-out block">
               <OnyxLogo />
             </span>
             <span className="font-display font-bold text-2xl tracking-tighter leading-8 group-hover:-translate-y-8 transition-transform duration-500 ease-in-out block text-black/40">
               HOME
             </span>
          </div>
        </button>
        <div className="hidden md:flex gap-8 lg:gap-12 font-sans font-medium text-sm text-black/60">
           <button onClick={() => { setShowDocs(!showDocs); setShowApiPanel(false); }} className={`hover:text-black transition-colors ${showDocs ? 'text-black font-semibold' : ''}`}>Docs</button>
           <button onClick={() => { setShowApiPanel(!showApiPanel); setShowDocs(false); }} className={`hover:text-black transition-colors ${showApiPanel ? 'text-black font-semibold' : ''}`}>API</button>
           <button onClick={() => { setShowContact(!showContact); setShowDocs(false); setShowApiPanel(false); }} className={`hover:text-black transition-colors ${showContact ? 'text-black font-semibold' : ''}`}>Contact</button>
           {role === Role.ARBITER && (
             <button onClick={() => { setShowArbiterPanel(!showArbiterPanel); setShowDocs(false); setShowApiPanel(false); setShowContact(false); }} className={`hover:text-red-600 transition-colors ${showArbiterPanel ? 'text-red-600 font-semibold' : 'text-red-500'}`}>Disputes</button>
           )}
        </div>
        <div className="flex items-center gap-2 sm:gap-4">
           <div className="hidden sm:flex items-center gap-2 font-bold text-sm">
              <span className={`w-2 h-2 rounded-full ${step === EscrowStep.IDLE ? 'bg-gray-300' : 'bg-green-500 animate-pulse'}`}></span>
              <span className="hidden lg:inline">Status:</span> {step.replace('_', ' ')}
           </div>
           <button
             onClick={() => setShowLobby(!showLobby)}
             className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full transition-all duration-300 text-[10px] font-bold uppercase tracking-wider ${showLobby ? 'bg-black text-white shadow-lg' : 'bg-black text-white hover:bg-black/80'}`}
             title="Escrow Dashboard"
           >
             <LayoutDashboard size={14} />
             <span className="hidden sm:inline">Lobby</span>
           </button>
           <div className="flex items-center gap-1 sm:gap-2 text-sm">
              <span className="text-black/60 font-mono hidden sm:inline">{username}</span>
              <button
                onClick={handleLogout}
                className="p-2 hover:bg-black/5 rounded-lg transition-colors"
                title="Logout"
              >
                <LogOut size={16} className="text-black/60" />
              </button>
           </div>
        </div>
      </nav>

      {/* Global Progress Stepper */}
      {role && step !== EscrowStep.IDLE && (
        <ProgressStepper step={step} shieldComplete={shieldComplete} />
      )}

      {/* Main Hero Section */}
      <main className={`relative min-h-screen flex flex-col justify-center items-center pt-16 pb-16 sm:pt-20 sm:pb-20 px-4 sm:px-6 md:px-0 transition-opacity duration-1000 ${!role ? 'opacity-20 blur-sm pointer-events-none' : 'opacity-100'}`}>
        
        {/* Giant Background Typography */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full text-center pointer-events-none select-none z-0 animate-reveal-mask">
           <h1 className="font-display font-bold text-[20vw] sm:text-[18vw] leading-none text-outline opacity-50 uppercase tracking-tighter">
             {role === Role.BUYER ? 'INITIATOR' : role === Role.VENDOR ? 'VENDOR' : 'PROTOCOL'}
           </h1>
        </div>

        {/* Central Composition */}
        <div className="relative z-10 w-full max-w-6xl h-auto min-h-[400px] sm:h-[600px] flex items-center justify-center animate-hero-enter" style={{ animationDelay: '200ms' }}>

           {/* Center Sculptural Visualizer - Hidden during FUNDING step to avoid overlap with QR code */}
           <div className="w-[250px] h-[250px] sm:w-[300px] sm:h-[300px] md:w-[500px] md:h-[500px] relative">
              {step !== EscrowStep.FUNDING && (
                <Visualizer step={step} role={role} dkgPhase={dkgState.phase} />
              )}
              
              {/* --- ACTION LAYER: Based on Role and Step --- */}
              <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-full max-w-md flex flex-col items-center gap-4 translate-y-12">
                   
                   {/* STEP 1: IDLE / JOIN */}
                   {step === EscrowStep.IDLE && (
                      <>
                        {role === Role.VENDOR ? (
                            <div className="bg-white p-6 rounded-[2rem] shadow-2xl animate-float w-full">
                                <label className="text-[10px] font-bold uppercase tracking-widest text-black/40 mb-2 block ml-2">Contract Uplink ID</label>
                                <div className="flex gap-2 mb-4 border-b border-black/10 pb-2">
                                <ScanLine size={16} className="text-black/30 mt-1" />
                                <input 
                                    type="text" 
                                    placeholder="Paste Session ID..."
                                    className="w-full bg-transparent font-mono text-lg outline-none placeholder:text-black/20 uppercase"
                                    value={inputSessionId}
                                    onChange={(e) => setInputSessionId(e.target.value)}
                                />
                                </div>
                                <ActionButton onClick={handleSellerJoin} isLoading={isLoading} className="w-full">
                                Connect to Buyer
                                </ActionButton>
                            </div>
                        ) : (
                            <div className="bg-white p-6 rounded-[2rem] shadow-2xl animate-float w-full max-w-xs">
                                <label className="text-[10px] font-bold uppercase tracking-widest text-black/40 mb-2 block ml-2">Escrow Amount (XMR)</label>
                                <div className="flex gap-2 mb-4 border-b border-black/10 pb-2">
                                <input
                                    type="number"
                                    step="0.01"
                                    min="0.001"
                                    placeholder="1.0"
                                    className="w-full bg-transparent font-mono text-lg outline-none placeholder:text-black/20"
                                    value={escrowAmount}
                                    onChange={(e) => setEscrowAmount(e.target.value)}
                                />
                                <span className="text-black/40 font-mono text-lg">XMR</span>
                                </div>
                                {escrowAmount && parseFloat(escrowAmount) > 0 && (
                                  <div className="mb-4 space-y-1">
                                    <div className="flex justify-between text-[10px] font-mono text-black/40 px-1">
                                      <span>Platform fee (5%)</span>
                                      <span>{(parseFloat(escrowAmount) * 0.05).toFixed(4)} XMR</span>
                                    </div>
                                    <div className="flex justify-between text-[10px] font-mono text-black/60 px-1 border-t border-black/5 pt-1">
                                      <span className="font-bold">Vendor receives</span>
                                      <span className="font-bold">{(parseFloat(escrowAmount) * 0.95).toFixed(4)} XMR</span>
                                    </div>
                                  </div>
                                )}
                                <ActionButton onClick={handleBuyerInitiate} isLoading={isLoading} className="w-full">
                                New Escrow Contract
                                </ActionButton>
                            </div>
                        )}
                      </>
                   )}

                   {/* STEP 2: BUYER WAITS FOR SELLER */}
                   {step === EscrowStep.DKG_WAITING && role === Role.BUYER && (
                      <div className="bg-white p-6 rounded-3xl shadow-xl border border-black/5 text-center min-w-[300px]">
                         <p className="font-bold mb-4">Share Uplink with Vendor</p>
                         <div className="flex gap-2 justify-center mb-4">
                            <input readOnly value={displaySessionId} className="bg-art-bg px-4 py-2 rounded-lg text-lg font-mono font-bold w-full text-center tracking-widest" />
                            <button onClick={handleCopyUplink} className="bg-black text-white p-2 rounded-lg hover:bg-black/80 transition-colors" title="Copy Full ID">
                               <Copy size={20}/>
                            </button>
                         </div>
                         <p className="text-[10px] text-black/40 mb-2">Full ID copied: {sessionId}</p>
                         <div className="flex items-center justify-center gap-2 text-xs text-black/30 mb-2">
                           <MessageSquareLock size={12} />
                           <span>Chat available once vendor connects</span>
                         </div>
                         <div className="mt-4 pt-4 border-t border-black/5">
                            <span className="flex items-center justify-center gap-2 text-xs text-black/50 animate-pulse">
                               <div className="w-2 h-2 bg-black/50 rounded-full"></div>
                               Waiting for connection...
                            </span>
                         </div>
                      </div>
                   )}

                   {/* STEP 3: FUNDING - Auto-detection with QR Code */}
                   {step === EscrowStep.FUNDING && (
                      <div className="bg-white p-8 rounded-[2rem] shadow-2xl text-center max-w-md w-full animate-in slide-in-from-bottom-4">
                         <h3 className="font-display font-bold text-2xl mb-2">
                            {role === Role.BUYER ? "Deposit Funds" : "Awaiting Deposit"}
                         </h3>

                         <p className="text-xs text-black/60 mb-6">
                            {role === Role.BUYER
                              ? "Scan the QR code or copy the address below"
                              : "Waiting for buyer's deposit"
                            }
                         </p>

                         {/* QR Code for Payment */}
                         <div className="flex justify-center mb-6">
                            <PaymentQRCode
                              address={multisigAddress}
                              amount={(escrowStatus && escrowStatus.amount > 0) ? (escrowStatus.amount / 1e12).toString() : (escrowAmount || '1.0')}
                              description={`Escrow ${sessionId?.slice(0, 12) || ''}`}
                            />
                         </div>

                         {/* Payment Detection Status */}
                         {escrowStatus && isPaymentDetected(escrowStatus.status) ? (
                           <div className="py-4 px-6 bg-green-50 border border-green-200 rounded-xl mb-4 animate-in slide-in-from-bottom-2">
                             <div className="flex items-center gap-3 mb-2">
                               <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
                               <span className="text-sm font-bold text-green-700">
                                 Payment Detected
                               </span>
                             </div>
                             <div className="text-xs font-mono text-green-600 space-y-1 ml-6">
                               <div>
                                 Amount: <span className="font-bold">{formatBalance(escrowStatus.balance_received)} XMR</span>
                               </div>
                               <div className="text-green-500">
                                 Waiting for blockchain confirmations...
                               </div>
                               <div className="flex items-center gap-2 mt-2">
                                 <div className="flex gap-1">
                                   {[...Array(10)].map((_, i) => (
                                     <div
                                       key={i}
                                       className={`w-2 h-2 rounded-full ${
                                         i < 3 ? 'bg-green-400 animate-pulse' : 'bg-green-100'
                                       }`}
                                       style={{ animationDelay: `${i * 200}ms` }}
                                     />
                                   ))}
                                 </div>
                                 <span className="text-[10px] text-green-400">~10 blocks needed</span>
                               </div>
                             </div>
                           </div>
                         ) : (
                           <div className="flex items-center justify-center gap-3 py-4 px-6 bg-art-bg rounded-xl mb-4">
                              {isFundingPolling ? (
                                <>
                                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                                  <span className="text-xs font-mono text-black/60">
                                    Monitoring blockchain for payment...
                                  </span>
                                </>
                              ) : (
                                <>
                                  <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
                                  <span className="text-xs font-mono text-black/40">
                                    Waiting for address generation...
                                  </span>
                                </>
                              )}
                           </div>
                         )}

                         {/* Absurd quips while waiting */}
                         {(!escrowStatus || !isPaymentDetected(escrowStatus.status)) && (
                           <div className="text-center mb-3">
                             <FundingQuips active={step === EscrowStep.FUNDING} />
                           </div>
                         )}

                         {/* Escrow Status Info */}
                         {escrowStatus && !isPaymentDetected(escrowStatus.status) && (
                            <div className="text-[10px] font-mono text-black/40 space-y-1">
                              <div>Status: <span className="text-black">{escrowStatus.status}</span></div>
                              {escrowStatus.balance_received > 0 && (
                                <div>
                                  Received: <span className="text-green-600">{formatBalance(escrowStatus.balance_received)} XMR</span>
                                </div>
                              )}
                              {escrowStatus.confirmations > 0 && (
                                <div>
                                  Confirmations: <span className="text-black">{escrowStatus.confirmations}</span>
                                </div>
                              )}
                            </div>
                         )}

                      </div>
                   )}

                   {/* STEP 4: ACTIVE (LOCKED) */}
                   {step === EscrowStep.ACTIVE && (
                      <div className="flex flex-col gap-4 animate-in slide-in-from-bottom-4">
                         {role === Role.VENDOR ? (
                             // Seller's Action: Enter payout address + Shield password + Mark as Delivered
                             <div className="bg-white p-6 rounded-2xl shadow-xl max-w-md">
                                <h3 className="font-display font-bold text-sm mb-4 text-black">Ship & Pre-sign</h3>
                                <p className="text-xs text-black/60 mb-3">Enter your Monero payout address and Shield password to pre-authorize release:</p>
                                <input
                                   type="text"
                                   value={vendorPayoutAddress}
                                   onChange={(e) => setVendorPayoutAddress(e.target.value)}
                                   placeholder="4... (95 characters)"
                                   className="w-full px-4 py-3 border border-black/10 rounded-xl font-mono text-xs focus:outline-none focus:border-black/30 mb-3"
                                />
                                {vendorPayoutAddress && vendorPayoutAddress.length !== 95 && (
                                   <p className="text-xs text-red-500 mb-2">Address must be 95 characters ({vendorPayoutAddress.length}/95)</p>
                                )}
                                <input
                                   type="password"
                                   value={backupPassword}
                                   onChange={(e) => setBackupPassword(e.target.value)}
                                   placeholder="Shield password..."
                                   className="w-full px-4 py-3 border border-black/10 rounded-xl font-mono text-xs focus:outline-none focus:border-black/30 mb-4"
                                />
                                <p className="text-[10px] text-black/40 mb-3">Your key image will be pre-submitted so buyer can release instantly.</p>
                                <ActionButton
                                   onClick={handleSellerDelivery}
                                   isLoading={isLoading}
                                   className="w-full"
                                   disabled={!vendorPayoutAddress || vendorPayoutAddress.length !== 95 || !backupPassword}
                                >
                                   <Package size={18} />
                                   Ship & Pre-authorize Release
                                </ActionButton>
                                <button onClick={() => setStep(EscrowStep.DISPUTE)} className="mt-3 text-xs font-bold text-red-500 hover:text-red-700 text-center w-full">
                                    Raise a Dispute
                                </button>
                             </div>
                         ) : (
                             // Buyer's View: Waiting for delivery
                             <div className="bg-white px-8 py-4 rounded-full shadow-xl flex items-center gap-4">
                                <span className="text-xs font-bold text-black/60">Awaiting Vendor Delivery...</span>
                                <div className="w-px h-4 bg-black/10"></div>
                                <button onClick={() => setStep(EscrowStep.DISPUTE)} className="text-xs font-bold text-red-500 hover:text-red-700">
                                    Raise a Dispute
                                </button>
                             </div>
                         )}
                      </div>
                   )}

                   {/* STEP 5: DELIVERED / RELEASE_SIGNING (CONFIRMATION) */}
                   {(step === EscrowStep.DELIVERED || step === EscrowStep.RELEASE_SIGNING) && (
                      <div className="flex flex-col gap-4 animate-in slide-in-from-bottom-4">
                         {role === Role.BUYER ? (
                             // Buyer's Action: Enter Shield password + Confirm Receipt & Release
                             <div className="bg-white p-6 rounded-2xl shadow-xl max-w-md">
                                <h3 className="font-display font-bold text-sm mb-4 text-black flex items-center gap-2">
                                   <Shield size={16} />
                                   Confirm & Release
                                </h3>
                                <p className="text-xs text-black/60 mb-3">Enter your Shield password to sign the release transaction:</p>
                                <input
                                   type="password"
                                   value={backupPassword}
                                   onChange={(e) => setBackupPassword(e.target.value)}
                                   placeholder="Shield password..."
                                   className="w-full px-4 py-3 border border-black/10 rounded-xl font-mono text-xs focus:outline-none focus:border-black/30 mb-4"
                                />

                                {/* Signing Progress Indicators */}
                                {signingProgress.stage !== 'idle' && (
                                  <div className="mb-4 p-4 bg-art-bg rounded-xl border border-black/5">
                                    <div className="flex items-center gap-3 mb-2">
                                      {signingProgress.stage === 'loading_key' && (
                                        <>
                                          <FileKey size={16} className="animate-pulse" />
                                          <span className="text-xs font-mono">Loading key...</span>
                                        </>
                                      )}
                                      {signingProgress.stage === 'generating_nonce' && (
                                        <>
                                          <Activity size={16} className="animate-spin" />
                                          <span className="text-xs font-mono">Generating nonce...</span>
                                        </>
                                      )}
                                      {signingProgress.stage === 'waiting_vendor' && (
                                        <>
                                          <Clock size={16} className="animate-pulse" />
                                          <span className="text-xs font-mono">Waiting for vendor...</span>
                                        </>
                                      )}
                                      {signingProgress.stage === 'signing' && (
                                        <>
                                          <Lock size={16} className="animate-pulse" />
                                          <span className="text-xs font-mono">Signing...</span>
                                        </>
                                      )}
                                      {signingProgress.stage === 'waiting_arbiter' && (
                                        <>
                                          <Scale size={16} className="animate-pulse" />
                                          <span className="text-xs font-mono">Arbiter signing...</span>
                                        </>
                                      )}
                                      {signingProgress.stage === 'completed' && (
                                        <>
                                          <CheckCircle size={16} className="text-green-500" />
                                          <span className="text-xs font-mono text-green-600">Completed!</span>
                                        </>
                                      )}
                                      {signingProgress.stage === 'failed' && (
                                        <>
                                          <AlertTriangle size={16} className="text-red-500" />
                                          <span className="text-xs font-mono text-red-600">Failed</span>
                                        </>
                                      )}
                                    </div>
                                    <p className="text-[10px] text-black/60">{signingProgress.message}</p>
                                    {signingProgress.error && (
                                      <p className="text-[10px] text-red-500 mt-2">{signingProgress.error}</p>
                                    )}
                                    {signingProgress.stage === 'failed' && signingProgress.error?.includes('Key package not found') && (
                                      <button
                                        onClick={() => setShowShieldRecovery(true)}
                                        className="mt-3 w-full bg-amber-500 hover:bg-amber-400 text-black text-xs font-bold py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 transition-colors"
                                      >
                                        <Shield size={14} />
                                        Upload Shield Backup to Restore Key
                                      </button>
                                    )}
                                  </div>
                                )}

                                {/* Show restore button when key is missing, even before signing attempt */}
                                {hasLocalKey === false && signingProgress.stage === 'idle' && (
                                  <div className="mb-4 p-4 bg-amber-50 rounded-xl border border-amber-200">
                                    <p className="text-xs text-amber-800 font-semibold mb-2">Key package not found in this browser.</p>
                                    <p className="text-[10px] text-amber-700 mb-3">Upload your Shield backup file to restore signing capability.</p>
                                    <button
                                      onClick={() => setShowShieldRecovery(true)}
                                      className="w-full bg-amber-500 hover:bg-amber-400 text-black text-xs font-bold py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 transition-colors"
                                    >
                                      <Shield size={14} />
                                      Upload Shield Backup
                                    </button>
                                  </div>
                                )}

                                <ActionButton
                                   onClick={handleBuyerRelease}
                                   isLoading={isLoading}
                                   className="w-full"
                                   disabled={!backupPassword}
                                >
                                   <CheckCircle size={18} />
                                   Confirm Receipt & Release Funds
                                </ActionButton>
                                <p className="text-[10px] text-black/40 mt-3 text-center">
                                   TX outputs: Vendor wallet + Platform fee (5%)
                                </p>
                             </div>
                         ) : step === EscrowStep.RELEASE_SIGNING ? (
                             // Seller's Action: Co-sign release (buyer has confirmed receipt)
                             <div className="bg-white p-6 rounded-2xl shadow-xl max-w-md">
                                <h3 className="font-display font-bold text-sm mb-4 text-black flex items-center gap-2">
                                   <Shield size={16} />
                                   Co-sign Release
                                </h3>
                                <p className="text-xs text-black/60 mb-3">Buyer confirmed receipt. Enter Shield password to co-sign the release transaction:</p>
                                <input
                                   type="password"
                                   value={backupPassword}
                                   onChange={(e) => setBackupPassword(e.target.value)}
                                   placeholder="Shield password..."
                                   className="w-full px-4 py-3 border border-black/10 rounded-xl font-mono text-xs focus:outline-none focus:border-black/30 mb-4"
                                />

                                {/* Signing Progress Indicators (same as buyer) */}
                                {signingProgress.stage !== 'idle' && (
                                  <div className="mb-4 p-4 bg-art-bg rounded-xl border border-black/5">
                                    <div className="flex items-center gap-3 mb-2">
                                      {(signingProgress.stage === 'loading_key' || signingProgress.stage === 'generating_nonce') && (
                                        <><Activity size={16} className="animate-spin" /><span className="text-xs font-mono">{signingProgress.message}</span></>
                                      )}
                                      {signingProgress.stage === 'waiting_vendor' && (
                                        <><Clock size={16} className="animate-pulse" /><span className="text-xs font-mono">Waiting for buyer...</span></>
                                      )}
                                      {signingProgress.stage === 'signing' && (
                                        <><Lock size={16} className="animate-pulse" /><span className="text-xs font-mono">Signing...</span></>
                                      )}
                                      {signingProgress.stage === 'completed' && (
                                        <><CheckCircle size={16} className="text-green-500" /><span className="text-xs font-mono text-green-600">Completed!</span></>
                                      )}
                                      {signingProgress.stage === 'failed' && (
                                        <><AlertTriangle size={16} className="text-red-500" /><span className="text-xs font-mono text-red-600">Failed</span></>
                                      )}
                                    </div>
                                    <p className="text-[10px] text-black/60">{signingProgress.message}</p>
                                    {signingProgress.error && (
                                      <p className="text-[10px] text-red-500 mt-2">{signingProgress.error}</p>
                                    )}
                                  </div>
                                )}

                                {hasLocalKey === false && signingProgress.stage === 'idle' && (
                                  <div className="mb-4 p-4 bg-amber-50 rounded-xl border border-amber-200">
                                    <p className="text-xs text-amber-800 font-semibold mb-2">Key package not found in this browser.</p>
                                    <p className="text-[10px] text-amber-700 mb-3">Upload your Shield backup file to restore signing capability.</p>
                                    <button
                                      onClick={() => setShowShieldRecovery(true)}
                                      className="w-full bg-amber-500 hover:bg-amber-400 text-black text-xs font-bold py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 transition-colors"
                                    >
                                      <Shield size={14} />
                                      Upload Shield Backup
                                    </button>
                                  </div>
                                )}

                                <ActionButton
                                   onClick={handleBuyerRelease}
                                   isLoading={isLoading}
                                   className="w-full"
                                   disabled={!backupPassword}
                                >
                                   <CheckCircle size={18} />
                                   Co-sign & Release Funds
                                </ActionButton>
                                <p className="text-[10px] text-black/40 mt-3 text-center">
                                   TX outputs: Your wallet + Platform fee (5%)
                                </p>
                             </div>
                         ) : (
                             // Seller's View: Waiting for buyer confirmation (DELIVERED step)
                             <div className="bg-white px-8 py-4 rounded-full shadow-xl flex items-center gap-4">
                                <CheckCircle size={16} className="text-green-500" />
                                <span className="text-xs font-bold text-black">Delivery Broadcasted. Waiting for Buyer.</span>
                             </div>
                         )}
                      </div>
                   )}

              </div>
           </div>

           {/* Floating Element: Contract Info */}
           <div className="absolute top-10 left-4 md:left-20 w-72 glass-card p-6 rounded-2xl animate-float hidden md:block rotate-[-3deg]">
              <div className="flex justify-between items-start mb-4">
                 <div className="flex -space-x-2">
                    <div className="w-8 h-8 rounded-full bg-gray-200 border-2 border-white flex items-center justify-center text-black/60"><Shield size={14}/></div>
                    <div className="w-8 h-8 rounded-full bg-gray-300 border-2 border-white flex items-center justify-center text-black/60"><Network size={14}/></div>
                    <div className="w-8 h-8 rounded-full bg-black text-white border-2 border-white flex items-center justify-center text-xs"><Lock size={12}/></div>
                 </div>
                 <span className="text-[10px] font-bold uppercase text-black/40">FROST-RFC9591</span>
              </div>
              <h3 className="font-display font-bold text-xl mb-1">
                 {step === EscrowStep.IDLE ? "Non-Custodial" : step === EscrowStep.COMPLETED ? "Settled" : step === EscrowStep.DISPUTE_RESOLVED ? "Claiming" : "Enclave Active"}
              </h3>
              <p className="text-xs text-black/60 leading-relaxed mb-4">
                 {step === EscrowStep.IDLE 
                    ? "2-of-3 threshold logic. Arbiter cannot move funds alone. Buyer and Vendor hold keys."
                    : "Shamir's Secret Sharing prevents unilateral control. Collaboration required for signature."
                 }
              </p>
              {sessionId && (
                 <div className="space-y-2">
                   <div className="bg-black text-white text-[10px] font-mono p-2 rounded text-center flex items-center justify-center gap-2">
                      <FileKey size={10} />
                      SID: {displaySessionId || sessionId}
                   </div>
                   {hasLocalKey === false && (step === EscrowStep.ACTIVE || step === EscrowStep.DELIVERED || step === EscrowStep.RELEASE_SIGNING) && (
                     <button
                       onClick={() => setShowShieldRecovery(true)}
                       className="w-full bg-amber-500 text-black text-[10px] font-mono font-bold p-2 rounded text-center flex items-center justify-center gap-2 hover:bg-amber-400 transition-colors animate-pulse"
                     >
                       <Shield size={10} />
                       RESTORE SHIELD KEY
                     </button>
                   )}
                 </div>
              )}
           </div>

           {/* Floating Element: Terminal */}
           <div className="absolute bottom-0 right-4 md:right-8 w-80 animate-float-delayed hidden md:block z-20">
              <Terminal logs={logs} />
           </div>

           {/* --- STEP 4B: DISPUTE MODE --- */}
           {step === EscrowStep.DISPUTE && (
             <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg animate-in zoom-in-95 duration-500 z-50">
               <div className="bg-white p-8 md:p-10 rounded-[2.5rem] shadow-[0_30px_80px_rgba(200,50,50,0.15)] border border-red-500/10 overflow-hidden relative">
                  
                  {/* Decorative Background */}
                  <div className="absolute -top-10 -right-10 text-red-50 opacity-50 pointer-events-none">
                     <AlertTriangle size={200} strokeWidth={0.5} />
                  </div>

                  {/* Header */}
                  <div className="relative z-10 flex items-start justify-between mb-6">
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                           <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
                           <span className="font-mono text-[10px] text-red-500 font-bold uppercase tracking-widest">Dispute Protocol</span>
                        </div>
                        <h2 className="font-display font-bold text-4xl text-black tracking-tight">Arbitration<br/>Request</h2>
                      </div>
                      <div className="w-14 h-14 rounded-2xl bg-red-50 flex items-center justify-center text-red-600 border border-red-100 shadow-sm">
                         <Scale size={24} strokeWidth={1.5} />
                      </div>
                  </div>

                  {/* Data Grid */}
                  <div className="relative z-10 grid grid-cols-2 gap-4 mb-6">
                      <div className="p-4 rounded-2xl border border-black/5 bg-art-bg/50">
                          <label className="block font-mono text-[9px] uppercase tracking-widest text-black/40 mb-1">Session ID</label>
                          <div className="font-mono text-xs font-bold truncate">{sessionId}</div>
                      </div>
                       <div className="p-4 rounded-2xl border border-black/5 bg-art-bg/50">
                          <label className="block font-mono text-[9px] uppercase tracking-widest text-black/40 mb-1">Locked Value</label>
                          <div className="font-mono text-xs font-bold">{escrowStatus && escrowStatus.amount > 0 ? (escrowStatus.amount / 1e12).toFixed(4) : parseFloat(escrowAmount || '0').toFixed(4)} XMR</div>
                      </div>
                  </div>

                  {/* Logic Description */}
                  <p className="relative z-10 text-sm text-black/70 mb-6 leading-relaxed">
                     You have flagged this transaction. The Arbiter (Key 3) has been summoned to review evidence. 
                     <br/><br/>
                     To resolve, the Arbiter will combine their key with either the Buyer OR Vendor to reach the 2-of-3 threshold.
                  </p>

                  {/* Actions */}
                  <div className="relative z-10 space-y-3">
                     <textarea
                        value={disputeReason}
                        onChange={(e) => setDisputeReason(e.target.value)}
                        placeholder="Describe the issue (required)..."
                        rows={3}
                        className="w-full px-4 py-3 border border-black/10 rounded-xl font-mono text-xs focus:outline-none focus:border-red-300 resize-none"
                     />

                     <div className="flex flex-col gap-3 pt-2">
                        <ActionButton
                           onClick={async () => {
                              if (!disputeReason.trim()) {
                                 addLog(generateLog('ERROR', 'Please describe the issue before initiating arbitration.'));
                                 return;
                              }
                              if (!sessionId) return;
                              setDisputeLoading(true);
                              try {
                                 const resp = await initiateDispute(sessionId, disputeReason.trim());
                                 if (resp.data?.success) {
                                    addLog(generateLog('CRITICAL', 'Arbitration protocol initiated. Arbiter summoned.'));
                                    setDisputeReason('');
                                 } else {
                                    addLog(generateLog('ERROR', `Dispute failed: ${resp.error || 'Unknown error'}`));
                                 }
                              } catch (err) {
                                 addLog(generateLog('ERROR', `Dispute error: ${err}`));
                              } finally {
                                 setDisputeLoading(false);
                              }
                           }}
                           isLoading={disputeLoading}
                           disabled={!disputeReason.trim()}
                           variant="primary"
                           className="w-full bg-red-600 hover:bg-red-700 hover:shadow-red-500/20 border-transparent"
                        >
                           <AlertTriangle size={18} />
                           Initiate Arbitration
                        </ActionButton>

                        <ActionButton
                           onClick={() => { setStep(EscrowStep.ACTIVE); setDisputeReason(''); }}
                           variant="secondary"
                           className="w-full"
                        >
                           Withdraw Dispute
                        </ActionButton>
                     </div>

                     <p className="text-center text-[10px] text-red-400 mt-4 font-mono">
                        Platform fee: 3% on refund, 5% on release — deducted from settlement.
                     </p>
                  </div>

               </div>
             </div>
           )}
           
           {/* --- STEP 4C: DISPUTE RESOLVED — AUTO-CLAIM --- */}
           {step === EscrowStep.DISPUTE_RESOLVED && (
             <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg animate-in zoom-in-95 duration-500 z-50">
               <div className="bg-white p-8 md:p-10 rounded-[2.5rem] shadow-[0_30px_80px_rgba(16,185,129,0.15)] border border-green-500/10 overflow-hidden relative">

                  {/* Decorative Background */}
                  <div className="absolute -top-10 -right-10 text-green-50 opacity-50 pointer-events-none">
                     <CheckCircle size={200} strokeWidth={0.5} />
                  </div>

                  {/* Header */}
                  <div className="relative z-10 flex items-start justify-between mb-6">
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                           <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                           <span className="font-mono text-[10px] text-green-600 font-bold uppercase tracking-widest">Dispute Resolved</span>
                        </div>
                        <h2 className="font-display font-bold text-4xl text-black tracking-tight">Claiming<br/>Funds</h2>
                      </div>
                      <div className="w-14 h-14 rounded-2xl bg-green-50 flex items-center justify-center text-green-600 border border-green-100 shadow-sm">
                         <Scale size={24} strokeWidth={1.5} />
                      </div>
                  </div>

                  {/* Status Content */}
                  <div className="relative z-10 space-y-4">
                    {/* Progress steps */}
                    {(disputeClaimStatus === 'loading_key' || disputeClaimStatus === 'extracting' || disputeClaimStatus === 'submitting') && (
                      <div className="flex items-center gap-4 p-4 rounded-2xl border border-green-100 bg-green-50/50">
                        <div className="w-8 h-8 border-2 border-green-500 border-t-transparent rounded-full animate-spin"></div>
                        <div>
                          <div className="font-mono text-xs font-bold text-green-700 uppercase">
                            {disputeClaimStatus === 'loading_key' && 'Loading cryptographic keys...'}
                            {disputeClaimStatus === 'extracting' && 'Extracting FROST signing share...'}
                            {disputeClaimStatus === 'submitting' && 'Broadcasting to network...'}
                          </div>
                          <div className="font-mono text-[10px] text-green-600/70 mt-1">
                            Zero-friction auto-claim in progress
                          </div>
                        </div>
                      </div>
                    )}

                    {disputeClaimStatus === 'polling' && (
                      <div className="flex items-center gap-4 p-4 rounded-2xl border border-blue-100 bg-blue-50/50">
                        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                        <div>
                          <div className="font-mono text-xs font-bold text-blue-700 uppercase">
                            Waiting for blockchain broadcast...
                          </div>
                          <div className="font-mono text-[10px] text-blue-600/70 mt-1">
                            Arbiter watchdog processing co-signature
                          </div>
                        </div>
                      </div>
                    )}

                    {disputeClaimStatus === 'needs_restore' && (
                      <div className="space-y-3">
                        <div className="flex items-center gap-3 p-3 rounded-xl border border-amber-200 bg-amber-50">
                          <Shield size={16} className="text-amber-600" />
                          <span className="font-mono text-xs text-amber-700 font-bold">Key not found in this browser</span>
                        </div>
                        <p className="font-mono text-[10px] text-black/50 px-1">
                          Upload your Shield backup file (.nxshld) to restore signing capability and claim funds.
                        </p>
                        <button
                          onClick={() => setShowShieldRecovery(true)}
                          className="w-full px-4 py-3 bg-amber-500 hover:bg-amber-400 text-black rounded-xl font-mono text-xs font-bold uppercase flex items-center justify-center gap-2 transition-colors"
                        >
                          <Shield size={14} />
                          Upload Shield Backup
                        </button>
                      </div>
                    )}

                    {disputeClaimStatus === 'needs_password' && (
                      <div className="space-y-3">
                        <div className="flex items-center gap-3 p-3 rounded-xl border border-amber-200 bg-amber-50">
                          <Shield size={16} className="text-amber-600" />
                          <span className="font-mono text-xs text-amber-700">Shield password required to unlock signing key</span>
                        </div>
                        <div className="flex gap-2">
                          <input
                            type="password"
                            value={disputeShieldPassword}
                            onChange={(e) => setDisputeShieldPassword(e.target.value)}
                            placeholder="Shield password..."
                            className="flex-1 px-4 py-3 border border-black/10 rounded-xl font-mono text-xs focus:outline-none focus:border-green-300"
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' && disputeShieldPassword) {
                                setDisputeClaimStatus('idle');
                                disputeClaimRef.current = false;
                                executeDisputeClaim(disputeShieldPassword);
                              }
                            }}
                          />
                          <button
                            onClick={() => {
                              if (disputeShieldPassword) {
                                setDisputeClaimStatus('idle');
                                disputeClaimRef.current = false;
                                executeDisputeClaim(disputeShieldPassword);
                              }
                            }}
                            disabled={!disputeShieldPassword}
                            className="px-6 py-3 bg-green-600 text-white rounded-xl font-mono text-xs font-bold uppercase hover:bg-green-700 transition-colors disabled:opacity-40"
                          >
                            Unlock & Claim
                          </button>
                        </div>
                      </div>
                    )}

                    {disputeClaimStatus === 'completed' && (
                      <div className="space-y-3">
                        <div className="flex items-center gap-4 p-4 rounded-2xl border border-green-200 bg-green-50">
                          <CheckCircle size={24} className="text-green-600" />
                          <div>
                            <div className="font-mono text-xs font-bold text-green-700 uppercase">
                              Funds claimed successfully
                            </div>
                            <div className="font-mono text-[10px] text-green-600/70 mt-1">
                              Transaction broadcast to Monero network
                            </div>
                          </div>
                        </div>
                        {disputeClaimTxHash && (
                          <div className="p-3 rounded-xl bg-black/[0.03] border border-black/5">
                            <div className="font-mono text-[9px] text-black/40 uppercase mb-1">TX Hash</div>
                            <div className="font-mono text-[10px] text-black/70 break-all select-all cursor-text">
                              {disputeClaimTxHash}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {disputeClaimStatus === 'error' && (
                      <div className="space-y-3">
                        <div className="flex items-center gap-3 p-4 rounded-2xl border border-red-200 bg-red-50">
                          <AlertTriangle size={20} className="text-red-600" />
                          <div>
                            <div className="font-mono text-xs font-bold text-red-700 uppercase">Auto-claim failed</div>
                            <div className="font-mono text-[10px] text-red-600/70 mt-1">{disputeClaimError}</div>
                          </div>
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => {
                              setDisputeClaimStatus('idle');
                              setDisputeClaimError(null);
                              disputeClaimRef.current = false;
                              executeDisputeClaim();
                            }}
                            className="flex-1 px-4 py-3 bg-black text-white rounded-xl font-mono text-xs font-bold uppercase hover:bg-black/80 transition-colors"
                          >
                            Retry Claim
                          </button>
                          <button
                            onClick={() => setShowShieldRecovery(true)}
                            className="px-4 py-3 bg-amber-500 hover:bg-amber-400 text-black rounded-xl font-mono text-xs font-bold uppercase flex items-center gap-2 transition-colors"
                          >
                            <Shield size={12} />
                            Restore Key
                          </button>
                        </div>
                      </div>
                    )}

                    {disputeClaimStatus === 'idle' && (
                      <div className="flex items-center gap-4 p-4 rounded-2xl border border-black/5 bg-black/[0.02]">
                        <div className="w-8 h-8 border border-black/20 rounded-full flex items-center justify-center">
                          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                        </div>
                        <div className="font-mono text-xs text-black/60">
                          Preparing auto-claim...
                        </div>
                      </div>
                    )}
                  </div>

                  <p className="relative z-10 text-center text-[10px] text-green-500/60 mt-6 font-mono">
                    Settlement fee deducted automatically from claim amount.
                  </p>
               </div>
             </div>
           )}

           {/* --- STEP 5: COMPLETED — Full Ceremony Overlay --- */}
           {step === EscrowStep.COMPLETED && (
              <CompletionCeremony
                escrowId={sessionId || ''}
                amount={(escrowStatus?.amount && escrowStatus.amount > 0
                  ? (escrowStatus.amount / 1e12).toFixed(4)
                  : parseFloat(escrowAmount || '0').toFixed(4)
                )}
                txHash={signingState.txHash || disputeClaimTxHash || null}
                role={role || Role.BUYER}
                onClose={() => { setStep(EscrowStep.IDLE); setSessionId(''); }}
              />
           )}

        </div>

        {/* Floating Chat Button - Available whenever escrow is active */}
        {sessionId && role && !isChatOpen && step !== EscrowStep.IDLE && step !== EscrowStep.COMPLETED && (
          <button
            onClick={() => setIsChatOpen(true)}
            className="fixed bottom-8 left-8 z-40 group flex items-center gap-3 px-5 py-3 bg-black text-white rounded-full shadow-2xl hover:scale-105 transition-transform duration-300"
          >
            <MessageSquareLock size={20} />
            <span className="font-mono text-sm font-bold uppercase tracking-wide">Secure Chat</span>
            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
          </button>
        )}

        {/* Footer */}
        <div className="absolute bottom-0 w-full border-t border-black/5 py-4 sm:py-8 md:py-12 bg-white/50 backdrop-blur-sm animate-hero-enter" style={{ animationDelay: '400ms' }}>
           <div className="container mx-auto px-4 sm:px-8">
              <h2 className="font-display font-bold text-lg sm:text-3xl md:text-5xl uppercase tracking-tighter text-black flex items-center gap-2 sm:gap-4">
                 Round-Robin Threshold CLSAG <ArrowDown size={20} className="animate-bounce sm:w-6 sm:h-6" />
              </h2>
           </div>
        </div>

      {/* TX Ticker — auto-populated from successful broadcasts */}
      <div className="fixed bottom-0 left-0 right-0 z-30 bg-black/95 backdrop-blur-sm border-t border-white/5 overflow-hidden h-7 flex items-center">
        <div className="flex animate-ticker whitespace-nowrap">
          {tickerTxHashes.map((tx, i) => (
            <span key={i} className="inline-flex items-center gap-2 mx-8 text-[10px] font-mono">
              <span className={`w-1.5 h-1.5 rounded-full ${tx.label === 'DISPUTE' ? 'bg-amber-400' : 'bg-emerald-400'}`}></span>
              <span className="text-white/30">{tx.label}</span>
              <span className="text-white/50">{tx.hash}</span>
            </span>
          ))}
          {/* Duplicate for seamless scroll loop */}
          {tickerTxHashes.map((tx, i) => (
            <span key={`dup-${i}`} className="inline-flex items-center gap-2 mx-8 text-[10px] font-mono">
              <span className={`w-1.5 h-1.5 rounded-full ${tx.label === 'DISPUTE' ? 'bg-amber-400' : 'bg-emerald-400'}`}></span>
              <span className="text-white/30">{tx.label}</span>
              <span className="text-white/50">{tx.hash}</span>
            </span>
          ))}
        </div>
      </div>

      </main>
    </div>
  );
};

export default App;