export const PRESET_DEFAULTS = {
  relaxed: {
    auditLevel: "critical",
    ignoreScripts: false,
    minReleaseAgeDays: 0,
    requireLockfile: true,
    requirePmPin: false,
  },
  standard: {
    auditLevel: "high",
    ignoreScripts: true,
    minReleaseAgeDays: 1,
    requireLockfile: true,
    requirePmPin: true,
  },
  strict: {
    auditLevel: "moderate",
    ignoreScripts: true,
    minReleaseAgeDays: 14,
    requireLockfile: true,
    requirePmPin: true,
  },
} as const;
