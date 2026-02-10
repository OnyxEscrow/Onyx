import React from 'react';
import { ChatMessage } from '../../hooks/useEscrowChat';
import { Shield, AlertTriangle, Check, CheckCheck, User, Wallet } from 'lucide-react';

interface MessageBubbleProps {
  message: ChatMessage;
  showSender?: boolean;
}

export const MessageBubble: React.FC<MessageBubbleProps> = ({
  message,
  showSender = true,
}) => {
  const isOwn = message.isOwnMessage;
  const decryptionFailed = message.decryptedContent === '[Decryption failed]';

  const getRoleIcon = () => {
    switch (message.senderRole) {
      case 'buyer':
        return <Wallet className="h-3 w-3 text-blue-400" />;
      case 'vendor':
        return <User className="h-3 w-3 text-green-400" />;
      case 'arbiter':
        return <Shield className="h-3 w-3 text-purple-400" />;
    }
  };

  const getRoleColor = () => {
    switch (message.senderRole) {
      case 'buyer':
        return 'text-blue-400';
      case 'vendor':
        return 'text-green-400';
      case 'arbiter':
        return 'text-purple-400';
    }
  };

  const formatTime = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className={`flex ${isOwn ? 'justify-end' : 'justify-start'} mb-3`}>
      <div
        className={`max-w-[88%] sm:max-w-[75%] ${
          isOwn
            ? 'bg-green-500/20 border-green-500/30'
            : 'bg-gray-800/50 border-gray-700/50'
        } border rounded-lg overflow-hidden`}
      >
        {/* Sender header */}
        {showSender && !isOwn && (
          <div className="px-3 pt-2 flex items-center gap-2">
            {getRoleIcon()}
            <span className={`text-xs font-mono ${getRoleColor()}`}>
              {message.senderUsername}
            </span>
            <span className="text-xs text-gray-500 font-mono uppercase">
              ({message.senderRole})
            </span>
          </div>
        )}

        {/* Message content */}
        <div className="px-3 py-2">
          {decryptionFailed ? (
            <div className="flex items-center gap-2 text-yellow-400">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm italic">Unable to decrypt message</span>
            </div>
          ) : (
            <p className="text-white text-sm whitespace-pre-wrap break-words">
              {message.decryptedContent || message.encryptedContent}
            </p>
          )}
        </div>

        {/* Footer: time + status */}
        <div className="px-3 pb-2 flex items-center justify-between gap-3">
          <span className="text-xs text-gray-500">{formatTime(message.createdAt)}</span>
          <div className="flex items-center gap-2">
            {/* FROST signature indicator */}
            {message.frostSignature && (
              <div className="flex items-center gap-1" title="FROST signed">
                <Shield className="h-3 w-3 text-purple-400" />
              </div>
            )}
            {/* Read status (own messages only) */}
            {isOwn && (
              <div className="text-green-500/60">
                {message.isRead ? (
                  <CheckCheck className="h-3 w-3" />
                ) : (
                  <Check className="h-3 w-3" />
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default MessageBubble;
