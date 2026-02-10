import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useEscrowChat, ChatMessage, ChatParticipant } from '../../hooks/useEscrowChat';
import { MessageBubble } from './MessageBubble';
import { ChatInput } from './ChatInput';
import {
  MessageSquare, Users, Shield, AlertTriangle, RefreshCw,
  Lock, CheckCircle, Loader2, User, Wallet, X, Terminal
} from 'lucide-react';

interface EscrowChatProps {
  escrowId: string;
  userRole: 'buyer' | 'vendor' | 'arbiter';
  onClose?: () => void;
}

export const EscrowChat: React.FC<EscrowChatProps> = ({
  escrowId,
  userRole,
  onClose,
}) => {
  const {
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
    refetch,
  } = useEscrowChat(escrowId, userRole);

  const [isRegistering, setIsRegistering] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const chatContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Mark messages as read when scrolled into view
  useEffect(() => {
    const unread = messages.filter((m) => !m.isRead && !m.isOwnMessage);
    unread.forEach((m) => markAsRead(m.id));
  }, [messages, markAsRead]);

  // Register keypair handler
  const handleRegisterKeypair = useCallback(async () => {
    setIsRegistering(true);
    try {
      const { getWasmModule } = await import('../../services/wasmService');
      const wasm = getWasmModule();
      if (!wasm?.generate_x25519_keypair) {
        throw new Error('WASM not ready');
      }
      const keypair = wasm.generate_x25519_keypair();
      localStorage.setItem(`escrow_chat_keypair_${escrowId}`, JSON.stringify(keypair));
      await registerKeypair(keypair.publicKey);
    } catch (err) {
      console.error('Failed to register keypair:', err);
    } finally {
      setIsRegistering(false);
    }
  }, [escrowId, registerKeypair]);

  // Get participant by role
  const getParticipant = (role: string): ChatParticipant | undefined => {
    return participants.find((p) => p.role === role);
  };

  const getRoleIcon = (role: string) => {
    switch (role) {
      case 'buyer': return <Wallet className="h-3 w-3 text-white/60" />;
      case 'vendor': return <User className="h-3 w-3 text-white/60" />;
      case 'arbiter': return <Shield className="h-3 w-3 text-white/60" />;
    }
  };

  // Group messages by date
  const groupMessagesByDate = (msgs: ChatMessage[]) => {
    const groups: { date: string; messages: ChatMessage[] }[] = [];
    let currentDate = '';
    msgs.forEach((msg) => {
      const msgDate = new Date(msg.createdAt).toLocaleDateString();
      if (msgDate !== currentDate) {
        currentDate = msgDate;
        groups.push({ date: msgDate, messages: [msg] });
      } else {
        groups[groups.length - 1].messages.push(msg);
      }
    });
    return groups;
  };

  const messageGroups = groupMessagesByDate(messages);

  return (
    <div className="flex flex-col h-full bg-[#0A0A0A] border border-white/10 rounded-xl overflow-hidden shadow-2xl">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-white/10 bg-white/[0.02]">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-white/5 rounded-md border border-white/10">
            <Terminal className="h-4 w-4 text-white/80" />
          </div>
          <div>
            <h3 className="text-white font-mono font-bold text-xs uppercase tracking-widest">Secure Uplink</h3>
            <div className="flex items-center gap-1 text-[10px] text-white/40 font-mono mt-0.5">
              <Lock className="h-2.5 w-2.5" />
              <span>E2EE :: ACTIVATED</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={refetch}
            disabled={isLoading}
            className="p-2 hover:bg-white/5 rounded transition-colors"
            title="Sync"
          >
            <RefreshCw className={`h-3.5 w-3.5 text-white/40 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
          {onClose && (
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/5 rounded transition-colors"
            >
              <X className="h-3.5 w-3.5 text-white/40" />
            </button>
          )}
        </div>
      </div>

      {/* Participants bar */}
      <div className="px-4 py-2 border-b border-white/5 bg-black">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            {['buyer', 'vendor', 'arbiter'].map((role) => {
              const participant = getParticipant(role);
              const isActive = !!participant?.publicKey;
              return (
                <div key={role} className={`flex items-center gap-1.5 transition-opacity ${isActive ? 'opacity-100' : 'opacity-30'}`}>
                  {getRoleIcon(role)}
                  <span className="text-[9px] font-mono uppercase tracking-wider text-white">
                    {participant?.username || role}
                  </span>
                  {isActive && <div className="w-1 h-1 bg-white rounded-full ml-1"></div>}
                </div>
              );
            })}
          </div>
          <div className="text-[9px] font-mono text-white/20 uppercase">Network Status: Online</div>
        </div>
      </div>

      {/* Keypair registration prompt */}
      {!hasKeypair && (
        <div className="p-4 bg-white/5 border-b border-white/10 flex items-center justify-between animate-in fade-in">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-4 w-4 text-white" />
              <span className="text-white/80 text-xs font-mono">ENCRYPTION KEYS MISSING</span>
            </div>
            <button
              onClick={handleRegisterKeypair}
              disabled={isRegistering}
              className="px-4 py-1.5 bg-white text-black text-[10px] font-bold font-mono uppercase tracking-widest hover:bg-gray-200 transition flex items-center gap-2 rounded-sm"
            >
              {isRegistering ? <Loader2 className="h-3 w-3 animate-spin" /> : <Lock className="h-3 w-3" />}
              Generate Keys
            </button>
        </div>
      )}

      {/* Waiting for all keypairs — show who's missing */}
      {hasKeypair && !allKeypairsRegistered && (
        <div className="p-3 bg-white/[0.02] border-b border-white/5">
           <div className="flex items-center justify-center gap-2 mb-1.5">
             <Loader2 className="h-3 w-3 text-white/40 animate-spin" />
             <span className="text-white/40 text-[10px] font-mono uppercase tracking-wide">
                Awaiting Peer Handshake...
             </span>
           </div>
           <div className="flex items-center justify-center gap-3">
             {['buyer', 'vendor', 'arbiter'].map((r) => {
               const p = participants.find((x) => x.role === r);
               const hasKey = !!p?.publicKey;
               return (
                 <span key={r} className={`text-[9px] font-mono uppercase tracking-wider ${hasKey ? 'text-green-400' : 'text-white/20'}`}>
                   {hasKey ? '\u2713' : '\u2717'} {r}
                 </span>
               );
             })}
           </div>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="p-3 bg-red-500/10 border-b border-red-500/20 text-red-400 text-xs font-mono flex items-center gap-2">
           <AlertTriangle className="h-3 w-3" />
           {error.message}
        </div>
      )}

      {/* Messages */}
      <div
        ref={chatContainerRef}
        className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent"
      >
        {/* Loading state */}
        {isLoading && messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full space-y-2">
            <div className="w-1 h-1 bg-white rounded-full animate-ping"></div>
            <p className="text-white/20 font-mono text-[10px] uppercase tracking-widest">Decrypting Stream...</p>
          </div>
        )}

        {/* Empty state */}
        {!isLoading && messages.length === 0 && allKeypairsRegistered && (
          <div className="flex flex-col items-center justify-center h-full text-center opacity-30">
            <MessageSquare className="h-8 w-8 text-white mb-2" />
            <p className="text-white text-xs font-mono uppercase tracking-widest">Channel Empty</p>
            <p className="text-[10px] text-white/60">Transmission secure. You may begin.</p>
          </div>
        )}

        {/* Message groups */}
        {messageGroups.map((group) => (
          <div key={group.date}>
            <div className="flex items-center justify-center my-6">
              <span className="text-[9px] text-white/20 font-mono uppercase tracking-widest border-b border-white/5 pb-1 px-2">{group.date}</span>
            </div>
            {group.messages.map((msg, index) => {
              const prevMsg = group.messages[index - 1];
              const showSender = !prevMsg || prevMsg.senderId !== msg.senderId;
              return (
                <MessageBubble
                  key={msg.id}
                  message={msg}
                  showSender={showSender}
                />
              );
            })}
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <ChatInput
        onSend={sendMessage}
        disabled={!hasKeypair || !allKeypairsRegistered || isSending}
        placeholder={
          !hasKeypair
            ? 'KEYS REQUIRED'
            : !allKeypairsRegistered
            ? 'WAITING FOR PEERS...'
            : 'ENTER MESSAGE...'
        }
      />
    </div>
  );
};

export default EscrowChat;
