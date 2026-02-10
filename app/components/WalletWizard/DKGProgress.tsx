/**
 * DKGProgress Component
 *
 * Visual progress indicator for FROST DKG rounds.
 * Shows which parties have completed each round.
 */

import React from 'react';
import { Check, Circle, Loader2 } from 'lucide-react';
import { DkgPhase } from '../../hooks/useFrostDkg';

interface DkgParticipants {
  buyer_round1_ready: boolean;
  vendor_round1_ready: boolean;
  arbiter_round1_ready: boolean;
  buyer_round2_ready: boolean;
  vendor_round2_ready: boolean;
  arbiter_round2_ready: boolean;
}

interface DKGProgressProps {
  phase: DkgPhase;
  participants?: DkgParticipants | null;
}

interface StepIndicatorProps {
  label: string;
  status: 'pending' | 'active' | 'complete';
  participants?: {
    buyer: boolean;
    vendor: boolean;
    arbiter: boolean;
  };
}

const StepIndicator: React.FC<StepIndicatorProps> = ({ label, status, participants }) => {
  return (
    <div className="flex items-start gap-4">
      {/* Status Icon */}
      <div
        className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${
          status === 'complete'
            ? 'bg-green-500/20 text-green-400'
            : status === 'active'
            ? 'bg-cyan-500/20 text-cyan-400'
            : 'bg-white/5 text-gray-500'
        }`}
      >
        {status === 'complete' ? (
          <Check className="w-4 h-4" />
        ) : status === 'active' ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <Circle className="w-4 h-4" />
        )}
      </div>

      {/* Content */}
      <div className="flex-1 pb-6 border-l border-white/10 pl-4 -ml-4 ml-4">
        <p
          className={`font-medium ${
            status === 'complete'
              ? 'text-green-400'
              : status === 'active'
              ? 'text-white'
              : 'text-gray-500'
          }`}
        >
          {label}
        </p>

        {/* Participant Status */}
        {participants && status !== 'pending' && (
          <div className="flex gap-2 mt-2">
            <PartyBadge role="Buyer" ready={participants.buyer} />
            <PartyBadge role="Vendor" ready={participants.vendor} />
            <PartyBadge role="Arbiter" ready={participants.arbiter} />
          </div>
        )}
      </div>
    </div>
  );
};

interface PartyBadgeProps {
  role: string;
  ready: boolean;
}

const PartyBadge: React.FC<PartyBadgeProps> = ({ role, ready }) => {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs ${
        ready
          ? 'bg-green-500/20 text-green-300'
          : 'bg-white/5 text-gray-500'
      }`}
    >
      {ready ? <Check className="w-3 h-3" /> : <Circle className="w-3 h-3" />}
      {role}
    </span>
  );
};

const DKGProgress: React.FC<DKGProgressProps> = ({ phase, participants }) => {
  // Determine round statuses based on phase
  const getRound1Status = (): 'pending' | 'active' | 'complete' => {
    if (
      phase === 'idle' ||
      phase === 'initializing' ||
      phase === 'round1_generating' ||
      phase === 'round1_submitting' ||
      phase === 'round1_waiting'
    ) {
      if (phase === 'idle') return 'pending';
      return 'active';
    }
    return 'complete';
  };

  const getRound2Status = (): 'pending' | 'active' | 'complete' => {
    if (getRound1Status() !== 'complete') return 'pending';
    if (
      phase === 'round2_generating' ||
      phase === 'round2_submitting' ||
      phase === 'round2_waiting'
    ) {
      return 'active';
    }
    if (
      phase === 'round3_finalizing' ||
      phase === 'storing_key' ||
      phase === 'complete'
    ) {
      return 'complete';
    }
    return 'pending';
  };

  const getRound3Status = (): 'pending' | 'active' | 'complete' => {
    if (getRound2Status() !== 'complete') return 'pending';
    if (phase === 'round3_finalizing' || phase === 'storing_key') {
      return 'active';
    }
    if (phase === 'complete') {
      return 'complete';
    }
    return 'pending';
  };

  // Build participant status for each round
  const round1Participants = participants
    ? {
        buyer: participants.buyer_round1_ready,
        vendor: participants.vendor_round1_ready,
        arbiter: participants.arbiter_round1_ready,
      }
    : undefined;

  const round2Participants = participants
    ? {
        buyer: participants.buyer_round2_ready,
        vendor: participants.vendor_round2_ready,
        arbiter: participants.arbiter_round2_ready,
      }
    : undefined;

  return (
    <div className="space-y-1">
      <h3 className="text-sm font-medium text-gray-400 mb-4">DKG Progress</h3>

      <StepIndicator
        label="Round 1: Commitments"
        status={getRound1Status()}
        participants={round1Participants}
      />

      <StepIndicator
        label="Round 2: Secret Shares"
        status={getRound2Status()}
        participants={round2Participants}
      />

      <StepIndicator
        label="Round 3: Key Finalization"
        status={getRound3Status()}
      />

      {/* Overall Progress Bar */}
      <div className="mt-6">
        <div className="flex justify-between text-xs text-gray-500 mb-1">
          <span>Progress</span>
          <span>
            {phase === 'complete'
              ? '100%'
              : getRound3Status() === 'active'
              ? '90%'
              : getRound2Status() === 'complete'
              ? '66%'
              : getRound2Status() === 'active'
              ? '50%'
              : getRound1Status() === 'complete'
              ? '33%'
              : getRound1Status() === 'active'
              ? '15%'
              : '0%'}
          </span>
        </div>
        <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              phase === 'error' ? 'bg-red-500' : 'bg-gradient-to-r from-cyan-500 to-purple-500'
            }`}
            style={{
              width:
                phase === 'complete'
                  ? '100%'
                  : phase === 'error'
                  ? '100%'
                  : getRound3Status() === 'active'
                  ? '90%'
                  : getRound2Status() === 'complete'
                  ? '66%'
                  : getRound2Status() === 'active'
                  ? '50%'
                  : getRound1Status() === 'complete'
                  ? '33%'
                  : getRound1Status() === 'active'
                  ? '15%'
                  : '0%',
            }}
          />
        </div>
      </div>
    </div>
  );
};

export default DKGProgress;
