import type { LanguageId } from '@llmscan/core';

export const COMMAND_SCAN_WORKSPACE = 'llmscan.scanWorkspace';
export const COMMAND_CREATE_BASELINE = 'llmscan.createBaseline';
export const COMMAND_CLEAR_SCAN = 'llmscan.clearScan';
export const COMMAND_CLEAR_BASELINE = 'llmscan.clearBaseline';

export const LSP_DEBUG_PORT = 6019;

export const LANGUAGE_ID_MAP: Record<string, LanguageId> = {
  python: 'python',
  javascript: 'javascript',
  javascriptreact: 'javascript',
  typescript: 'typescript',
  typescriptreact: 'tsx',
  php: 'php',
};

export const SUPPORTED_VSCODE_LANGUAGES = Object.keys(LANGUAGE_ID_MAP);

