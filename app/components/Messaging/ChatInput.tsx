import React, { useState, useRef, useCallback, KeyboardEvent } from 'react';
import { Send, Lock, Loader2, AlertCircle } from 'lucide-react';

interface ChatInputProps {
  onSend: (message: string) => Promise<void>;
  disabled?: boolean;
  placeholder?: string;
  maxLength?: number;
  isEncrypted?: boolean;
}

export const ChatInput: React.FC<ChatInputProps> = ({
  onSend,
  disabled = false,
  placeholder = 'Type a message...',
  maxLength = 2000,
  isEncrypted = true,
}) => {
  const [message, setMessage] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handleSend = useCallback(async () => {
    const trimmed = message.trim();
    if (!trimmed || isSending || disabled) return;

    setIsSending(true);
    setError(null);

    try {
      await onSend(trimmed);
      setMessage('');
      // Reset textarea height
      if (textareaRef.current) {
        textareaRef.current.style.height = 'auto';
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send message');
    } finally {
      setIsSending(false);
    }
  }, [message, isSending, disabled, onSend]);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent<HTMLTextAreaElement>) => {
      // Send on Enter (without Shift)
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSend();
      }
    },
    [handleSend]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLTextAreaElement>) => {
      const value = e.target.value;
      if (value.length <= maxLength) {
        setMessage(value);
        setError(null);

        // Auto-resize textarea
        if (textareaRef.current) {
          textareaRef.current.style.height = 'auto';
          textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 120)}px`;
        }
      }
    },
    [maxLength]
  );

  const charCount = message.length;
  const isNearLimit = charCount > maxLength * 0.9;

  return (
    <div className="border-t border-green-500/20 bg-black/50">
      {/* Error banner */}
      {error && (
        <div className="px-4 py-2 bg-red-500/10 border-b border-red-500/30 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 text-red-400" />
          <span className="text-red-400 text-sm">{error}</span>
        </div>
      )}

      <div className="p-4">
        <div className="flex items-end gap-3">
          {/* Textarea container */}
          <div className="flex-1 relative">
            <textarea
              ref={textareaRef}
              value={message}
              onChange={handleChange}
              onKeyDown={handleKeyDown}
              placeholder={placeholder}
              disabled={disabled || isSending}
              rows={1}
              className={`w-full px-4 py-3 bg-black/50 border rounded-lg resize-none font-mono text-sm text-white placeholder:text-green-500/30 focus:outline-none focus:ring-1 transition ${
                disabled
                  ? 'border-gray-700/50 cursor-not-allowed'
                  : 'border-green-500/30 focus:border-green-500/50 focus:ring-green-500/30'
              }`}
              style={{ minHeight: '44px', maxHeight: '120px' }}
            />

            {/* Encryption indicator */}
            {isEncrypted && (
              <div className="absolute right-3 bottom-3 flex items-center gap-1 text-green-500/40">
                <Lock className="h-3 w-3" />
              </div>
            )}
          </div>

          {/* Send button */}
          <button
            onClick={handleSend}
            disabled={!message.trim() || isSending || disabled}
            className={`p-3 rounded-lg transition flex items-center justify-center ${
              message.trim() && !isSending && !disabled
                ? 'bg-green-500/20 border border-green-500/50 text-green-400 hover:bg-green-500/30'
                : 'bg-gray-700/20 border border-gray-700/30 text-gray-500 cursor-not-allowed'
            }`}
          >
            {isSending ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Send className="h-5 w-5" />
            )}
          </button>
        </div>

        {/* Character count & hint */}
        <div className="flex items-center justify-between mt-2 px-1">
          <span className="text-xs text-green-500/40">
            Press Enter to send, Shift+Enter for new line
          </span>
          <span
            className={`text-xs font-mono ${
              isNearLimit ? 'text-yellow-400' : 'text-green-500/40'
            }`}
          >
            {charCount}/{maxLength}
          </span>
        </div>
      </div>
    </div>
  );
};

export default ChatInput;
