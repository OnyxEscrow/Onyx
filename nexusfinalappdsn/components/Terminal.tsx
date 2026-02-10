import React, { useEffect, useRef } from 'react';
import { LogEntry } from '../types';
import TypewriterText from './TypewriterText';

interface TerminalProps {
  logs: LogEntry[];
}

const Terminal: React.FC<TerminalProps> = ({ logs }) => {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="h-full max-h-[50vh] sm:max-h-full flex flex-col bg-white rounded-lg shadow-[0_10px_40px_rgba(0,0,0,0.05)] overflow-hidden border border-black/5">
      <div className="bg-art-bg px-4 py-3 sm:px-6 sm:py-4 flex justify-between items-center border-b border-black/5">
        <span className="text-[10px] uppercase tracking-widest font-bold text-black">Live Feed</span>
        <div className="w-2 h-2 rounded-full bg-black animate-pulse"></div>
      </div>
      <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-3 sm:space-y-4 font-mono text-xs">
        {logs.map((log) => (
          <div key={log.id} className="flex gap-4 items-start animate-in fade-in slide-in-from-bottom-2 duration-500">
            <span className="text-black/30 w-12 shrink-0">{log.timestamp}</span>
            <div className="flex-1">
              <span className={`font-bold mr-2 uppercase text-[10px] tracking-wider ${
                log.level === 'SUCCESS' ? 'text-black' :
                log.level === 'CRITICAL' ? 'text-red-500' :
                log.level === 'WARN' ? 'text-orange-500' :
                'text-black/60'
              }`}>
                {log.level}
              </span>
              <p className="text-black/80 leading-relaxed mt-1">
                <TypewriterText text={log.message} speed={15} />
              </p>
              {log.hash && (
                <div className="mt-2 text-[10px] bg-art-bg inline-block px-2 py-1 rounded text-black/50">
                  {log.hash}
                </div>
              )}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
};

export default Terminal;