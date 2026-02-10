/**
 * DKG Phase Labels — human-readable mapping for FROST protocol phases
 */

export interface PhaseLabel {
  short: string;
  long: string;
  tooltip: string;
}

const PHASE_MAP: Record<string, PhaseLabel> = {
  idle: {
    short: 'Ready',
    long: 'Waiting to begin',
    tooltip: 'The key generation protocol has not started yet.',
  },
  initializing: {
    short: 'Starting',
    long: 'Initializing protocol',
    tooltip: 'Preparing cryptographic parameters for distributed key generation.',
  },
  round1_generating: {
    short: 'Round 1',
    long: 'Generating commitments',
    tooltip: 'Each party creates a secret commitment. These are shared publicly to ensure fairness.',
  },
  round1_submitting: {
    short: 'Round 1',
    long: 'Submitting commitments',
    tooltip: 'Sending your commitment to the server for distribution to all participants.',
  },
  round1_waiting: {
    short: 'Round 1',
    long: 'Waiting for parties',
    tooltip: 'Your commitment is ready. Waiting for all 3 participants to submit theirs.',
  },
  round2_generating: {
    short: 'Round 2',
    long: 'Computing key shares',
    tooltip: 'Using all commitments to derive encrypted secret shares for each participant.',
  },
  round2_submitting: {
    short: 'Round 2',
    long: 'Distributing shares',
    tooltip: 'Sending encrypted key shares to other parties. Only they can decrypt their share.',
  },
  round2_waiting: {
    short: 'Round 2',
    long: 'Waiting for shares',
    tooltip: 'Waiting for all participants to distribute their encrypted shares.',
  },
  round3_finalizing: {
    short: 'Finalizing',
    long: 'Assembling group key',
    tooltip: 'Combining all shares to derive the shared public key. No single party ever sees the full private key.',
  },
  storing_key: {
    short: 'Securing',
    long: 'Encrypting key package',
    tooltip: 'Encrypting and saving your key share locally in this browser.',
  },
  complete: {
    short: 'Complete',
    long: 'Keys generated',
    tooltip: 'All 3 parties now hold a unique key share. Any 2-of-3 can sign a transaction.',
  },
  error: {
    short: 'Error',
    long: 'Key generation failed',
    tooltip: 'Something went wrong during key generation. Check the terminal for details.',
  },
};

export function getPhaseLabel(phase: string | undefined): PhaseLabel {
  if (!phase) return PHASE_MAP.idle;
  return PHASE_MAP[phase] || { short: phase, long: phase, tooltip: '' };
}
