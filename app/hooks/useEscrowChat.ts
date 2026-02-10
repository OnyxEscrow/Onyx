import { useState, useEffect, useCallback, useRef } from 'react';
import { getWasmModule } from '../services/wasmService';

export interface ChatMessage {
  id: string;
  senderId: string;
  senderRole: 'buyer' | 'vendor' | 'arbiter';
  senderUsername: string;
  encryptedContent: string;
  decryptedContent?: string;
  senderEphemeralPubkey: string;
  nonce: string;
  frostSignature?: string;
  createdAt: string;
  isRead: boolean;
  isOwnMessage: boolean;
}

export interface ChatParticipant {
  userId: string;
  username: string;
  role: 'buyer' | 'vendor' | 'arbiter';
  publicKey?: string;
}

export interface UseEscrowChatResult {
  messages: ChatMessage[];
  participants: ChatParticipant[];
  isLoading: boolean;
  isSending: boolean;
  error: Error | null;
  hasKeypair: boolean;
  allKeypairsRegistered: boolean;
  sendMessage: (plaintext: string) => Promise<void>;
  markAsRead: (messageId: string) => Promise<void>;
  registerKeypair: (publicKey: string) => Promise<void>;
  refetch: () => void;
}

const API_BASE = '/api/v2';

export function useEscrowChat(escrowId: string, userRole: string): UseEscrowChatResult {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [participants, setParticipants] = useState<ChatParticipant[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [hasKeypair, setHasKeypair] = useState(false);
  const [allKeypairsRegistered, setAllKeypairsRegistered] = useState(false);

  const privateKeyRef = useRef<string | null>(null);

  // Get or create keypair
  const getOrCreateKeypair = useCallback(async (): Promise<{ publicKey: string; privateKey: string }> => {
    const storageKey = `escrow_chat_keypair_${escrowId}`;
    const stored = localStorage.getItem(storageKey);

    if (stored) {
      const keypair = JSON.parse(stored);
      privateKeyRef.current = keypair.privateKey;
      return keypair;
    }

    const wasm = getWasmModule();
    if (!wasm || !wasm.generate_x25519_keypair) {
      throw new Error('WASM module not ready');
    }

    const keypair = wasm.generate_x25519_keypair();
    localStorage.setItem(storageKey, JSON.stringify(keypair));
    privateKeyRef.current = keypair.privateKey;

    return keypair;
  }, [escrowId]);

  // Fetch keypairs
  const fetchKeypairs = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/escrow/${escrowId}/chat/keypairs`, {
        credentials: 'include',
      });

      if (!response.ok) return;

      const json = await response.json();
      const data = json.data || json; // Unwrap ApiResponse wrapper
      const newParticipants: ChatParticipant[] = [];

      if (data.buyer_pubkey) {
        newParticipants.push({
          userId: data.buyer_id || '',
          username: data.buyer_username || 'Buyer',
          role: 'buyer',
          publicKey: data.buyer_pubkey,
        });
      }

      if (data.vendor_pubkey) {
        newParticipants.push({
          userId: data.vendor_id || '',
          username: data.vendor_username || 'Vendor',
          role: 'vendor',
          publicKey: data.vendor_pubkey,
        });
      }

      if (data.arbiter_pubkey) {
        newParticipants.push({
          userId: data.arbiter_id || '',
          username: data.arbiter_username || 'Arbiter',
          role: 'arbiter',
          publicKey: data.arbiter_pubkey,
        });
      }

      setParticipants(newParticipants);
      // Chat is ready when buyer + vendor both have keys (arbiter is automated)
      const buyerReady = !!data.buyer_pubkey;
      const vendorReady = !!data.vendor_pubkey;
      setAllKeypairsRegistered(buyerReady && vendorReady);

      const myKeypair = newParticipants.find(p => p.role === userRole);
      setHasKeypair(!!myKeypair?.publicKey);
    } catch (err) {
      console.error('Failed to fetch keypairs:', err);
    }
  }, [escrowId, userRole]);

  // Fetch messages
  const fetchMessages = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/escrow/${escrowId}/chat/messages?limit=100`, {
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch messages: ${response.statusText}`);
      }

      const json = await response.json();
      const data = json.data || json; // Unwrap ApiResponse wrapper
      const wasm = getWasmModule();
      const privateKey = privateKeyRef.current;

      const decryptedMessages: ChatMessage[] = (data.messages || []).map((msg: any) => {
        let decryptedContent: string | undefined;

        if (wasm && privateKey && msg.encrypted_content && wasm.decrypt_group_message) {
          try {
            decryptedContent = wasm.decrypt_group_message(
              msg.encrypted_content,
              msg.sender_ephemeral_pubkey,
              msg.nonce,
              privateKey
            );
          } catch (err) {
            decryptedContent = '[Decryption failed]';
          }
        }

        return {
          id: msg.id,
          senderId: msg.sender_id,
          senderRole: msg.sender_role,
          senderUsername: msg.sender_username || msg.sender_role,
          encryptedContent: msg.encrypted_content,
          decryptedContent,
          senderEphemeralPubkey: msg.sender_ephemeral_pubkey,
          nonce: msg.nonce,
          frostSignature: msg.frost_signature,
          createdAt: msg.created_at,
          isRead: msg.is_read,
          isOwnMessage: msg.is_own_message,
        };
      });

      setMessages(decryptedMessages);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [escrowId]);

  // Register keypair
  const registerKeypair = useCallback(async (publicKey: string) => {
    const response = await fetch(`${API_BASE}/escrow/${escrowId}/chat/keypair`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ public_key: publicKey }),
    });

    if (!response.ok) {
      throw new Error(`Failed to register keypair: ${response.statusText}`);
    }

    setHasKeypair(true);
    await fetchKeypairs();
  }, [escrowId, fetchKeypairs]);

  // Send message
  const sendMessage = useCallback(async (plaintext: string) => {
    if (!allKeypairsRegistered) {
      throw new Error('Not all participants have registered keypairs');
    }

    const wasm = getWasmModule();
    const privateKey = privateKeyRef.current;

    if (!wasm || !privateKey || !wasm.encrypt_for_group) {
      throw new Error('WASM module or private key not available');
    }

    setIsSending(true);
    setError(null);

    try {
      // Build participant list in fixed order: buyer, vendor, arbiter
      const roles: Array<'buyer' | 'vendor' | 'arbiter'> = ['buyer', 'vendor', 'arbiter'];
      const sortedParticipants = roles.map(r => participants.find(p => p.role === r));

      const recipientPubkeys = sortedParticipants
        .map(p => p?.publicKey)
        .filter(Boolean) as string[];

      if (recipientPubkeys.length < 2) {
        throw new Error('Need at least buyer + vendor public keys');
      }

      const encrypted = wasm.encrypt_for_group(plaintext, recipientPubkeys, privateKey);

      // Map ciphertexts to roles (only for participants with keys)
      let cipherIdx = 0;
      const ciphertexts: Record<string, string> = {};
      for (const role of roles) {
        const p = sortedParticipants[roles.indexOf(role)];
        if (p?.publicKey) {
          ciphertexts[`encrypted_content_${role}`] = encrypted.ciphertexts[cipherIdx++];
        } else {
          ciphertexts[`encrypted_content_${role}`] = '';
        }
      }

      const response = await fetch(`${API_BASE}/escrow/${escrowId}/chat/send`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...ciphertexts,
          sender_ephemeral_pubkey: encrypted.ephemeralPubkey,
          nonce: encrypted.nonce,
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to send message: ${response.statusText}`);
      }

      await fetchMessages();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
      throw err;
    } finally {
      setIsSending(false);
    }
  }, [escrowId, allKeypairsRegistered, participants, fetchMessages]);

  // Mark as read
  const markAsRead = useCallback(async (messageId: string) => {
    await fetch(`${API_BASE}/escrow/${escrowId}/chat/${messageId}/read`, {
      method: 'POST',
      credentials: 'include',
    });
  }, [escrowId]);

  // Initialize — auto-generate + auto-register keypair, then fetch
  useEffect(() => {
    const init = async () => {
      try {
        const keypair = await getOrCreateKeypair();
        await fetchKeypairs();

        // Auto-register if server doesn't have our key yet
        if (!hasKeypair) {
          try {
            await registerKeypair(keypair.publicKey);
          } catch {
            // May fail if already registered (race condition) — safe to ignore
          }
        }

        await fetchMessages();
      } catch (err) {
        setError(err instanceof Error ? err : new Error(String(err)));
        setIsLoading(false);
      }
    };

    if (escrowId) {
      init();
    }
  }, [escrowId, getOrCreateKeypair, fetchKeypairs, fetchMessages, hasKeypair, registerKeypair]);

  // Poll for peer keypairs every 5s until all registered
  useEffect(() => {
    if (allKeypairsRegistered || !hasKeypair) return;

    const interval = setInterval(() => {
      fetchKeypairs();
    }, 5000);

    return () => clearInterval(interval);
  }, [allKeypairsRegistered, hasKeypair, fetchKeypairs]);

  return {
    messages,
    participants,
    isLoading,
    isSending,
    error,
    hasKeypair,
    allKeypairsRegistered,
    sendMessage,
    markAsRead,
    registerKeypair,
    refetch: fetchMessages,
  };
}
