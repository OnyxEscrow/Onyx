import React from 'react';
import { EscrowStep } from '../types';
import { Plus, Key, Shield, QrCode, Lock, Package, FileKey, CheckCircle } from 'lucide-react';

interface ProgressStepperProps {
  step: EscrowStep;
  shieldComplete: boolean;
}

const STEPS = [
  { key: 'create',  label: 'Create',  icon: Plus },
  { key: 'keygen',  label: 'Keygen',  icon: Key },
  { key: 'shield',  label: 'Shield',  icon: Shield },
  { key: 'fund',    label: 'Fund',    icon: QrCode },
  { key: 'active',  label: 'Active',  icon: Lock },
  { key: 'deliver', label: 'Deliver', icon: Package },
  { key: 'sign',    label: 'Sign',    icon: FileKey },
  { key: 'done',    label: 'Done',    icon: CheckCircle },
] as const;

function mapStepToIndex(step: EscrowStep, shieldComplete: boolean): number {
  switch (step) {
    case EscrowStep.IDLE:
    case EscrowStep.INITIATING:
      return 0;
    case EscrowStep.DKG_WAITING:
    case EscrowStep.DKG_RUNNING:
      return 1;
    case EscrowStep.FUNDING:
      return shieldComplete ? 3 : 2; // Shield step between DKG and Fund
    case EscrowStep.ACTIVE:
      return 4;
    case EscrowStep.DELIVERED:
      return 5;
    case EscrowStep.DISPUTE:
    case EscrowStep.DISPUTE_RESOLVED:
      return 5; // Dispute branches off from deliver/sign
    case EscrowStep.RELEASE_SIGNING:
      return 6;
    case EscrowStep.COMPLETED:
      return 7;
    default:
      return 0;
  }
}

const ProgressStepper: React.FC<ProgressStepperProps> = ({ step, shieldComplete }) => {
  const currentIndex = mapStepToIndex(step, shieldComplete);
  const isDispute = step === EscrowStep.DISPUTE || step === EscrowStep.DISPUTE_RESOLVED;

  return (
    <div className="sticky top-0 z-20 bg-white/80 backdrop-blur-sm border-b border-black/5 px-4 py-3">
      <div className="max-w-2xl mx-auto flex items-center justify-between">
        {STEPS.map((s, i) => {
          const Icon = s.icon;
          const isCompleted = i < currentIndex;
          const isActive = i === currentIndex;
          const isFuture = i > currentIndex;
          const isDisputeStep = isDispute && (i === 5 || i === 6);

          return (
            <React.Fragment key={s.key}>
              {/* Step circle */}
              <div className="flex flex-col items-center gap-1 relative">
                <div
                  className={`
                    w-7 h-7 sm:w-8 sm:h-8 rounded-full flex items-center justify-center transition-all duration-500
                    ${isCompleted
                      ? 'bg-black text-white'
                      : isActive
                        ? isDisputeStep
                          ? 'bg-red-500 text-white shadow-lg shadow-red-500/20'
                          : 'bg-black text-white shadow-lg shadow-black/20'
                        : 'bg-black/5 text-black/20'
                    }
                  `}
                >
                  {isCompleted ? (
                    <CheckCircle size={12} />
                  ) : (
                    <Icon size={12} />
                  )}
                  {/* Pulse ring on active step */}
                  {isActive && (
                    <div
                      className={`absolute inset-0 rounded-full border-2 ${
                        isDisputeStep ? 'border-red-500' : 'border-black'
                      } animate-ping opacity-20`}
                    />
                  )}
                </div>
                {/* Label — hidden on mobile */}
                <span
                  className={`
                    hidden sm:block text-[8px] font-mono uppercase tracking-widest transition-colors duration-300
                    ${isCompleted || isActive ? 'text-black/60' : 'text-black/20'}
                    ${isActive ? 'font-bold' : ''}
                  `}
                >
                  {isDisputeStep && isActive ? 'Dispute' : s.label}
                </span>
              </div>

              {/* Connecting line (not after last step) */}
              {i < STEPS.length - 1 && (
                <div className="flex-1 h-px mx-1 sm:mx-2 relative">
                  {/* Background line */}
                  <div className="absolute inset-0 bg-black/5" />
                  {/* Progress fill */}
                  <div
                    className={`absolute inset-y-0 left-0 transition-all duration-700 ease-out ${
                      isDisputeStep ? 'bg-red-500' : 'bg-black'
                    }`}
                    style={{
                      width: isCompleted ? '100%' : isActive ? '50%' : '0%',
                    }}
                  />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};

export default ProgressStepper;
