/**
 * Error Humanizer — maps cryptic FROST/WASM errors to plain English
 */

export interface HumanError {
  message: string;
  action: string;
}

const ERROR_PATTERNS: Array<{ pattern: RegExp; human: HumanError }> = [
  {
    pattern: /FROST share extraction failed/i,
    human: {
      message: 'Could not extract your signing key from the stored package.',
      action: 'Try restoring from your Shield backup file (.nxshld).',
    },
  },
  {
    pattern: /Key package not found/i,
    human: {
      message: 'No signing key found in this browser.',
      action: 'Upload your Shield backup file to restore access.',
    },
  },
  {
    pattern: /Shield password required|key not found in storage/i,
    human: {
      message: 'Your key is encrypted and needs a password to unlock.',
      action: 'Enter the password you chose when creating the Shield backup.',
    },
  },
  {
    pattern: /Wrong Shield password|corrupted backup/i,
    human: {
      message: 'Incorrect password or damaged backup file.',
      action: 'Double-check your password. If the file is damaged, use another copy of your .nxshld file.',
    },
  },
  {
    pattern: /Invalid secret share.*expected 64/i,
    human: {
      message: 'The key share is damaged or incompatible.',
      action: 'Restore from a fresh Shield backup. Do not modify .nxshld files manually.',
    },
  },
  {
    pattern: /Semaphore closed/i,
    human: {
      message: 'Server connection was interrupted during signing.',
      action: 'Check your internet connection and try again.',
    },
  },
  {
    pattern: /NetworkError|Failed to fetch|net::ERR/i,
    human: {
      message: 'Cannot reach the ONYX server.',
      action: 'Check your internet connection and refresh the page.',
    },
  },
  {
    pattern: /HTTP 4\d\d|Unauthorized|Forbidden/i,
    human: {
      message: 'Your session may have expired.',
      action: 'Try logging out and logging back in.',
    },
  },
  {
    pattern: /HTTP 5\d\d|Internal Server Error/i,
    human: {
      message: 'The server encountered an unexpected error.',
      action: 'Wait a moment and try again. If it persists, the team has been notified.',
    },
  },
  {
    pattern: /timeout|timed out/i,
    human: {
      message: 'The operation took too long to complete.',
      action: 'This can happen with slow connections. Try again.',
    },
  },
];

export function humanizeError(raw: string): HumanError {
  for (const { pattern, human } of ERROR_PATTERNS) {
    if (pattern.test(raw)) return human;
  }
  return {
    message: raw,
    action: 'If this persists, check your connection or contact support.',
  };
}
