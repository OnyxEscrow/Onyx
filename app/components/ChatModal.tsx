import React, { useState, useEffect, useRef } from 'react';
import { Send, Lock, X, Check } from 'lucide-react';
import { LogEntry } from '../types';

interface ChatModalProps {
  sessionId: string;
  isOpen: boolean;
  onClose: () => void;
  onTransmit: () => void;
}

const ChatModal: React.FC<ChatModalProps> = ({ sessionId, isOpen, onClose, onTransmit }) => {
  const [messages, setMessages] = useState<{sender: 'me' | 'peer', text: string}[]>([]);
  const [input, setInput] = useState(`Onyx Uplink ID: ${sessionId}`);
  const [isTyping, setIsTyping] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) {
      setMessages([{sender: 'peer', text: 'Secure channel established. Waiting for Uplink...'}]);
    }
  }, [isOpen]);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    // Send User Message
    const userMsg = input;
    setMessages(prev => [...prev, { sender: 'me', text: userMsg }]);
    setInput('');
    onTransmit(); // Notify parent app that transmission happened

    // Simulate Peer Response
    setIsTyping(true);
    setTimeout(() => {
      setIsTyping(false);
      setMessages(prev => [...prev, { sender: 'peer', text: 'Received. Initiating handshake sequence.' }]);
    }, 2500);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed left-2 right-2 bottom-2 sm:left-4 sm:right-auto sm:bottom-4 md:left-8 md:bottom-8 z-50 w-auto sm:w-80 md:w-96 max-w-[calc(100vw-1rem)] flex flex-col animate-in slide-in-from-left-10 duration-500 font-sans">
      <div className="bg-black text-white rounded-t-2xl p-4 sm:p-5 flex justify-between items-center shadow-2xl">
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="p-1.5 sm:p-2 bg-white/10 rounded-full">
             <Lock size={14} />
          </div>
          <div>
            <h3 className="text-xs sm:text-sm font-bold font-display tracking-wide">Encrypted Channel</h3>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></span>
              <span className="text-[10px] text-white/60 uppercase tracking-wider font-mono">End-to-End</span>
            </div>
          </div>
        </div>
        <button onClick={onClose} className="text-white/40 hover:text-white transition-colors p-1 hover:bg-white/10 rounded-lg">
          <X size={18} />
        </button>
      </div>

      <div className="bg-white/95 backdrop-blur-md border-x border-b border-black/5 h-80 sm:h-96 flex flex-col shadow-2xl rounded-b-2xl overflow-hidden">
        {/* Chat Area */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4 sm:space-y-6">
          {messages.map((msg, idx) => (
            <div key={idx} className={`flex ${msg.sender === 'me' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[85%] p-4 rounded-2xl text-xs font-mono leading-relaxed shadow-sm ${
                msg.sender === 'me' 
                  ? 'bg-black text-white rounded-tr-none' 
                  : 'bg-art-bg text-black border border-black/5 rounded-tl-none'
              }`}>
                {msg.text}
              </div>
            </div>
          ))}
          {isTyping && (
            <div className="flex justify-start">
               <div className="bg-art-bg text-black border border-black/5 rounded-2xl rounded-tl-none px-5 py-4 flex gap-1.5 items-center">
                  <span className="w-1 h-1 bg-black/40 rounded-full animate-bounce"></span>
                  <span className="w-1 h-1 bg-black/40 rounded-full animate-bounce delay-100"></span>
                  <span className="w-1 h-1 bg-black/40 rounded-full animate-bounce delay-200"></span>
               </div>
            </div>
          )}
          <div ref={scrollRef} />
        </div>

        {/* Input Area */}
        <form onSubmit={handleSend} className="p-4 bg-white border-t border-black/5 flex gap-3">
          <input 
            type="text" 
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="flex-1 bg-art-bg rounded-xl px-4 py-3 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-black/10 transition-shadow"
            placeholder="Type message..."
          />
          <button type="submit" className="bg-black text-white p-3 rounded-xl hover:scale-105 transition-transform shadow-lg shadow-black/20">
             <Send size={16} />
          </button>
        </form>
      </div>
    </div>
  );
};

export default ChatModal;