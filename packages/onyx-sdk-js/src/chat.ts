/**
 * Onyx SDK Escrow E2EE Chat Operations
 *
 * End-to-end encrypted group messaging within escrows.
 * Security: X25519 ECDH + ChaCha20Poly1305 AEAD with ephemeral keys per message.
 */

import type {
  RegisterChatKeypairParams,
  ChatKeypairsDto,
  SendChatMessageParams,
  ChatMessagesResponse,
} from './types.js';

type RequestFn = <T>(method: string, path: string, body?: unknown) => Promise<T>;

/**
 * Escrow E2EE Chat resource operations
 *
 * @example
 * ```typescript
 * // Register keypair for chat
 * await client.chat.registerKeypair('escrow-id', {
 *   public_key: 'hex-encoded-x25519-pubkey',
 * });
 *
 * // Get all participants' public keys
 * const keypairs = await client.chat.getKeypairs('escrow-id');
 *
 * // Send encrypted message (3 copies, one per participant)
 * await client.chat.sendMessage('escrow-id', {
 *   encrypted_content_buyer: '...',
 *   encrypted_content_vendor: '...',
 *   encrypted_content_arbiter: '...',
 *   sender_ephemeral_pubkey: '...',
 *   nonce: '...',
 * });
 *
 * // Get chat history
 * const { messages } = await client.chat.getMessages('escrow-id');
 * ```
 */
export class ChatResource {
  private readonly request: RequestFn;

  constructor(request: RequestFn) {
    this.request = request;
  }

  /**
   * Register a messaging keypair for the current user in an escrow
   *
   * POST /api/v2/escrow/{id}/chat/keypair
   */
  async registerKeypair(
    escrowId: string,
    params: RegisterChatKeypairParams
  ): Promise<unknown> {
    return this.request(
      'POST',
      `/v2/escrow/${escrowId}/chat/keypair`,
      params
    );
  }

  /**
   * Get all participants' public keys for an escrow chat
   *
   * GET /api/v2/escrow/{id}/chat/keypairs
   */
  async getKeypairs(escrowId: string): Promise<ChatKeypairsDto> {
    return this.request<ChatKeypairsDto>(
      'GET',
      `/v2/escrow/${escrowId}/chat/keypairs`
    );
  }

  /**
   * Send an encrypted message to the escrow group chat.
   * The message must be encrypted 3 times (once per participant).
   *
   * POST /api/v2/escrow/{id}/chat/send
   */
  async sendMessage(
    escrowId: string,
    params: SendChatMessageParams
  ): Promise<{ id: string; created_at: string }> {
    return this.request(
      'POST',
      `/v2/escrow/${escrowId}/chat/send`,
      params
    );
  }

  /**
   * Get chat message history for an escrow
   *
   * GET /api/v2/escrow/{id}/chat/messages
   *
   * @param limit - Max messages per page (default: 50)
   * @param offset - Pagination offset
   */
  async getMessages(
    escrowId: string,
    params?: { limit?: number; offset?: number }
  ): Promise<ChatMessagesResponse> {
    const searchParams = new URLSearchParams();
    if (params?.limit !== undefined) {
      searchParams.set('limit', String(params.limit));
    }
    if (params?.offset !== undefined) {
      searchParams.set('offset', String(params.offset));
    }
    const query = searchParams.toString();
    const path = query
      ? `/v2/escrow/${escrowId}/chat/messages?${query}`
      : `/v2/escrow/${escrowId}/chat/messages`;
    return this.request<ChatMessagesResponse>('GET', path);
  }

  /**
   * Mark a chat message as read
   *
   * POST /api/v2/escrow/{id}/chat/{messageId}/read
   */
  async markRead(escrowId: string, messageId: string): Promise<void> {
    await this.request(
      'POST',
      `/v2/escrow/${escrowId}/chat/${messageId}/read`
    );
  }

  /**
   * Export chat history as signed evidence (for disputes)
   *
   * GET /api/v2/escrow/{id}/chat/export
   */
  async exportForDispute(escrowId: string): Promise<unknown> {
    return this.request(
      'GET',
      `/v2/escrow/${escrowId}/chat/export`
    );
  }
}
