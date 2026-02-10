import React, { useState } from 'react';
import { useDashboard, DashboardEscrow, formatXmr, getStatusBadge } from '../../hooks/useDashboard';
import {
  RefreshCw, Plus, ChevronRight, Clock, User, Shield,
  MessageSquare, AlertTriangle, Wallet, CheckCircle, Activity, X,
  Copy, ExternalLink, Key, Hash, Terminal as TerminalIcon, Search
} from 'lucide-react';

interface EscrowDashboardProps {
  onSelectEscrow: (escrowId: string, role?: string, status?: string, amount?: number) => void;
  onCreateNew: () => void;
  onClose?: () => void;
  onBroadcastTxFound?: (hash: string, label: string) => void;
}

export const EscrowDashboard: React.FC<EscrowDashboardProps> = ({
  onSelectEscrow,
  onCreateNew,
  onClose,
  onBroadcastTxFound,
}) => {
  const [statusFilter, setStatusFilter] = useState<string[]>([]);
  const [page, setPage] = useState(1);

  const { escrows, stats, pagination, isLoading, error, refetch } = useDashboard({
    status: statusFilter,
    page,
    perPage: 10,
  });

  // Bubble up broadcast TX hashes to parent for ticker
  React.useEffect(() => {
    if (!onBroadcastTxFound || !escrows.length) return;
    for (const e of escrows) {
      if (e.broadcast_tx_hash) {
        const isDispute = e.status === 'resolved_buyer' || e.status === 'resolved_vendor';
        onBroadcastTxFound(e.broadcast_tx_hash, isDispute ? 'DISPUTE' : 'CLSAG');
      }
    }
  }, [escrows, onBroadcastTxFound]);

  return (
    <div className="fixed inset-0 z-40 bg-white/95 backdrop-blur-xl overflow-y-auto animate-in slide-in-from-bottom-10 duration-500 pt-20 sm:pt-24 md:pt-32">
      {/* Background Grid */}
      <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 pointer-events-none"></div>
      
      {/* Close button */}
      {onClose && (
        <button
          onClick={onClose}
          className="fixed top-4 right-4 sm:top-6 sm:right-6 md:top-8 md:right-8 z-50 group flex items-center gap-2 px-3 py-1.5 sm:px-4 sm:py-2 bg-black text-white rounded-full hover:bg-red-600 transition-colors duration-300 shadow-xl"
        >
          <span className="text-[9px] font-mono uppercase tracking-widest hidden group-hover:block animate-in fade-in slide-in-from-right-2">Close Lobby</span>
          <X className="h-4 w-4" />
        </button>
      )}

      <div className="max-w-7xl mx-auto p-4 sm:p-6 md:p-12 relative z-10">
        
        {/* Header Section */}
        <div className="flex flex-col md:flex-row items-center justify-between gap-6 mb-12 border-b border-black/5 pb-8">
          <div>
            <div className="flex items-center gap-2 mb-3">
               <div className="w-1.5 h-1.5 bg-black rounded-full"></div>
               <span className="font-mono text-[9px] uppercase tracking-[0.3em] text-black/40">Onyx / Terminal / Lobby</span>
            </div>
          </div>
          
          <div className="flex items-center gap-3 sm:gap-6">
             <div className="flex flex-col text-right">
                <span className="font-mono text-[9px] text-black/30 uppercase tracking-widest">Active</span>
                <span className="font-mono text-xs font-bold">{escrows.length}</span>
             </div>
             <button
              onClick={onCreateNew}
              className="group relative px-6 py-2.5 bg-black text-white font-mono text-[10px] font-bold tracking-[0.1em] overflow-hidden rounded-full flex items-center gap-2 transition-all duration-300 hover:bg-black/90 hover:shadow-xl hover:shadow-black/5"
            >
              <Plus className="h-3.5 w-3.5 transition-transform group-hover:rotate-90" />
              <span>NEW CONTRACT</span>
            </button>
          </div>
        </div>

        {/* Stats Rail - Technical Style */}
        {stats && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-px bg-black/5 border border-black/5 rounded-2xl overflow-hidden mb-8 sm:mb-12">
            <StatBlock label="Total Operations" value={stats.total || 0} icon={Hash} />
            <StatBlock label="Active Nodes" value={stats.active || 0} icon={Activity} highlight />
            <StatBlock label="Settled" value={stats.completed || 0} icon={CheckCircle} />
            <StatBlock label="Volume (XMR)" value={formatXmr(stats.total_volume || 0)} icon={Wallet} mono />
          </div>
        )}

        {/* Controls Bar */}
        <div className="flex flex-col md:flex-row justify-between items-center gap-3 sm:gap-6 mb-6 sm:mb-8 sticky top-0 bg-white/80 backdrop-blur-md p-3 sm:p-4 -mx-3 sm:-mx-4 rounded-xl z-20 border border-black/5">
          {/* Filters */}
          <div className="flex gap-1.5 sm:gap-2 overflow-x-auto w-full md:w-auto pb-2 md:pb-0 no-scrollbar">
            {['all', 'active', 'completed', 'disputed'].map((filter) => (
              <button
                key={filter}
                onClick={() => setStatusFilter(filter === 'all' ? [] : [filter])}
                className={`px-3 py-1.5 sm:px-6 sm:py-2 rounded-full text-[10px] font-bold uppercase tracking-widest transition-all border whitespace-nowrap ${
                  (filter === 'all' && statusFilter.length === 0) || statusFilter.includes(filter)
                    ? 'bg-black text-white border-black'
                    : 'bg-transparent text-black/40 border-transparent hover:border-black/10 hover:text-black'
                }`}
              >
                {filter}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 sm:gap-4 w-full md:w-auto">
             <div className="relative flex-1 md:w-64">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-black/30" />
                <input
                  type="text"
                  placeholder="SEARCH..."
                  className="w-full bg-black/5 border-none rounded-lg pl-10 pr-3 sm:pr-4 py-2 font-mono text-xs uppercase focus:ring-1 focus:ring-black outline-none placeholder:text-black/20"
                />
             </div>
             <button
              onClick={refetch}
              disabled={isLoading}
              className="p-2 hover:bg-black/5 rounded-lg transition-colors"
              title="Refresh Data"
            >
              <RefreshCw className={`h-4 w-4 text-black/60 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Error State */}
        {error && (
          <div className="p-4 bg-red-50 border-l-4 border-red-500 mb-8 font-mono text-xs text-red-600 flex items-center gap-3">
            <AlertTriangle className="w-4 h-4" />
            {error.message}
          </div>
        )}

        {/* Loading State */}
        {isLoading && !escrows.length && (
          <div className="flex flex-col items-center justify-center py-32 space-y-4">
             <div className="w-16 h-16 border border-black/10 rounded-full flex items-center justify-center relative">
                <div className="absolute inset-0 border-t border-black rounded-full animate-spin"></div>
                <div className="w-2 h-2 bg-black rounded-full"></div>
             </div>
             <div className="font-mono text-xs uppercase tracking-widest text-black/40 animate-pulse">Fetching Encrypted Data...</div>
          </div>
        )}

        {/* Empty State with Ghost Data */}
        {!isLoading && !error && escrows.length === 0 && (
          <div className="relative min-h-[400px]">
             
             {/* Contextual CTA Overlay */}
             <div className="absolute inset-0 z-10 flex flex-col items-center justify-center">
                <div className="bg-white/80 backdrop-blur-sm p-8 rounded-2xl border border-black/10 shadow-2xl text-center max-w-md w-full animate-in zoom-in-95 duration-500">
                   <div className="font-mono text-xs text-black/60 mb-6 space-y-2">
                      <p>&gt; SCANNING NETWORK...</p>
                      <p>&gt; STATUS: IDLE</p>
                      <p>&gt; NO ACTIVE CONTRACTS DETECTED.</p>
                   </div>
                   
                   <div className="flex flex-col gap-4">
                      <p className="font-display font-bold text-xl uppercase tracking-widest">Initiate New Protocol Link?</p>
                      <div className="flex justify-center gap-4">
                         <button 
                           onClick={onCreateNew}
                           className="bg-black text-white px-8 py-3 rounded-lg font-mono text-xs font-bold uppercase tracking-widest hover:bg-black/80 transition-all hover:scale-105"
                         >
                           [Y] Yes, Initialize
                         </button>
                      </div>
                   </div>
                </div>
             </div>

             {/* Ghost Rows (Visual Noise) */}
             <div className="opacity-[0.03] pointer-events-none select-none blur-[1px]">
                {[1, 2, 3].map((i) => (
                   <div key={i} className="border-b border-black/20 p-6 flex justify-between items-center grayscale">
                      <div className="flex gap-4">
                         <div className="w-10 h-10 bg-black rounded-lg"></div>
                         <div className="space-y-2">
                            <div className="w-32 h-4 bg-black rounded"></div>
                            <div className="w-20 h-3 bg-black rounded"></div>
                         </div>
                      </div>
                      <div className="w-24 h-4 bg-black rounded"></div>
                   </div>
                ))}
             </div>
          </div>
        )}

        {/* Escrow List Grid */}
        {escrows.length > 0 && (
          <div className="grid grid-cols-1 gap-4">
            {escrows.map((escrow, index) => (
              <div 
                key={escrow.id} 
                className="animate-in slide-in-from-bottom-4 fade-in duration-500 fill-mode-backwards"
                style={{ animationDelay: `${index * 50}ms` }}
              >
                <EscrowRow
                  escrow={escrow}
                  onClick={() => onSelectEscrow(escrow.id, escrow.role, escrow.status, escrow.amount)}
                />
              </div>
            ))}
          </div>
        )}

        {/* Pagination */}
        {pagination && pagination.total > pagination.per_page && (
          <div className="flex items-center justify-center gap-8 mt-16 font-mono text-xs">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="hover:underline disabled:opacity-30 disabled:no-underline"
            >
              PREVIOUS
            </button>
            <span className="text-black/40">
              PAGE {page} OF {Math.ceil(pagination.total / pagination.per_page)}
            </span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={page >= Math.ceil(pagination.total / pagination.per_page)}
              className="hover:underline disabled:opacity-30 disabled:no-underline"
            >
              NEXT
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

// --- SUBCOMPONENTS ---

const StatBlock: React.FC<{
  label: string;
  value: string | number;
  icon: React.ComponentType<{ size?: number }>;
  highlight?: boolean;
  mono?: boolean;
}> = ({ label, value, icon: Icon, highlight, mono }) => (
  <div className={`p-4 sm:p-6 bg-white flex flex-col justify-between h-24 sm:h-32 hover:bg-black/[0.02] transition-colors group relative overflow-hidden`}>
      {highlight && <div className="absolute top-0 right-0 w-2 h-2 bg-green-500 rounded-bl-lg"></div>}
      <div className="flex justify-between items-start">
         <span className="text-[10px] font-mono uppercase tracking-widest text-black/40">{label}</span>
         <Icon size={14} className="text-black/20 group-hover:text-black/60 transition-colors" />
      </div>
      <div className={`text-xl sm:text-3xl font-bold text-black ${mono ? 'font-mono' : 'font-display'}`}>
         {value}
      </div>
  </div>
);

const EscrowRow: React.FC<{
  escrow: DashboardEscrow;
  onClick: () => void;
}> = ({ escrow, onClick }) => {
  const [copiedId, setCopiedId] = useState(false);
  
  const status = getStatusBadge(escrow.status);
  
  const getRoleStyle = () => {
    switch (escrow.role) {
      case 'buyer': return { label: 'INITIATOR', bg: 'bg-blue-500' };
      case 'vendor': return { label: 'VENDOR', bg: 'bg-emerald-500' };
      case 'arbiter': return { label: 'ARBITER', bg: 'bg-purple-500' };
      default: return { label: escrow.role, bg: 'bg-gray-500' };
    }
  };

  const roleStyle = getRoleStyle();

  return (
    <div
      onClick={onClick}
      className="group relative bg-white border border-black/5 hover:border-black rounded-xl p-4 sm:p-6 cursor-pointer transition-all duration-300 hover:shadow-xl hover:-translate-y-1 overflow-hidden"
    >
      {/* Hover Beam */}
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-black to-transparent -translate-x-full group-hover:animate-shimmer opacity-0 group-hover:opacity-100 transition-opacity"></div>

      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 sm:gap-6">

        {/* Left: ID & Role */}
        <div className="flex items-center gap-3 sm:gap-6 min-w-0 sm:min-w-[200px]">
           <div className={`w-10 h-10 rounded-lg ${roleStyle.bg} flex items-center justify-center text-white shadow-lg shrink-0`}>
              {escrow.role === 'buyer' ? <User size={18} /> : escrow.role === 'vendor' ? <Wallet size={18} /> : <Shield size={18} />}
           </div>
           <div>
              <div className="flex items-center gap-2 mb-1">
                 <span className="font-mono text-xs font-bold uppercase tracking-widest text-black/40">{roleStyle.label}</span>
                 {escrow.unread_messages ? (
                    <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse" title="New messages"></span>
                 ) : null}
              </div>
              <div className="font-mono text-xl font-bold text-black tracking-tight">
                 {formatXmr(escrow.amount)} <span className="text-sm text-black/40">XMR</span>
              </div>
           </div>
        </div>

        {/* Middle: Status & Progress */}
        <div className="flex-1 w-full md:w-auto">
           <div className="flex items-center gap-3 mb-2">
              <span className={`w-2 h-2 rounded-full ${status.color.includes('green') ? 'bg-green-500' : status.color.includes('blue') ? 'bg-blue-500' : 'bg-gray-300'}`}></span>
              <span className="text-sm font-bold uppercase">{status.text}</span>
           </div>
           <div className="w-full h-1 bg-black/5 rounded-full overflow-hidden">
              <div
                className={`h-full ${status.color.includes('green') ? 'bg-green-500' : status.color.includes('purple') ? 'bg-purple-500' : status.color.includes('blue') ? 'bg-blue-500' : 'bg-black'} transition-all duration-1000`}
                style={{
                  width: escrow.status === 'completed' || escrow.status === 'released' ? '100%'
                       : escrow.status === 'releasing' ? '85%'
                       : escrow.status === 'shipped' ? '70%'
                       : escrow.status === 'funded' || escrow.status === 'active' ? '50%'
                       : escrow.status === 'payment_detected' ? '40%'
                       : escrow.status === 'dkg_complete' ? '30%'
                       : '15%'
                }}
              ></div>
           </div>
           <div className="flex justify-between mt-2 text-[10px] font-mono text-black/40 uppercase">
              <span>{timeAgo(escrow.created_at)}</span>
              <span>{escrow.counterparty?.username || 'WAITING FOR PEER...'}</span>
           </div>
           {/* TX Hash for completed escrows */}
           {escrow.broadcast_tx_hash && (
             <div className="mt-2 flex items-center gap-2">
               <span className={`w-1.5 h-1.5 rounded-full ${
                 escrow.status === 'resolved_buyer' || escrow.status === 'resolved_vendor' ? 'bg-amber-400' : 'bg-emerald-400'
               }`}></span>
               <span className="text-[9px] font-mono text-black/30 uppercase tracking-wider">TX</span>
               <span
                 className="text-[9px] font-mono text-black/50 hover:text-black cursor-copy transition-colors"
                 onClick={(e) => {
                   e.stopPropagation();
                   navigator.clipboard.writeText(escrow.broadcast_tx_hash!);
                 }}
                 title="Click to copy TX hash"
               >
                 {escrow.broadcast_tx_hash.slice(0, 16)}...{escrow.broadcast_tx_hash.slice(-8)}
               </span>
               <ExternalLink size={10} className="text-black/20" />
             </div>
           )}
        </div>

        {/* Right: Actions & ID */}
        <div className="flex items-center gap-3 sm:gap-4 shrink-0 md:border-l md:border-black/5 md:pl-6">
           <div className="text-right hidden md:block">
              <div className="text-[10px] font-mono uppercase text-black/30 mb-1">Session ID</div>
              <div 
                className="font-mono text-xs font-bold text-black hover:bg-black hover:text-white px-2 py-1 rounded transition-colors cursor-copy"
                onClick={(e) => {
                   e.stopPropagation();
                   navigator.clipboard.writeText(escrow.id);
                   setCopiedId(true);
                   setTimeout(() => setCopiedId(false), 2000);
                }}
              >
                 {escrow.id.replace('esc_', '').slice(0, 8).toUpperCase()}
                 {copiedId && <span className="ml-2 text-green-500">✓</span>}
              </div>
           </div>
           <div className="w-10 h-10 rounded-full border border-black/10 flex items-center justify-center group-hover:bg-black group-hover:text-white transition-colors">
              <ChevronRight size={18} />
           </div>
        </div>

      </div>
    </div>
  );
};

// Helper to format time ago (keep existing logic)
const timeAgo = (dateStr: string): string => {
  const now = new Date();
  const date = new Date(dateStr);
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);
  if (seconds < 60) return 'JUST NOW';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}M AGO`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}H AGO`;
  return date.toLocaleDateString().toUpperCase();
};

export default EscrowDashboard;
