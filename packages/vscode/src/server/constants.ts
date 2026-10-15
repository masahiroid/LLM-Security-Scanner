import type { LanguageId } from '@llmscan/core';

export const COMMAND_SCAN_WORKSPACE = 'llmscan.scanWorkspace';
export const COMMAND_CREATE_BASELINE = 'llmscan.createBaseline';

export const LANGUAGE_ID_MAP: Record<string, LanguageId> = {
  python: 'python',
  javascript: 'javascript',
  javascriptreact: 'javascript',
  typescript: 'typescript',
  typescriptreact: 'tsx',
  php: 'php',
};

