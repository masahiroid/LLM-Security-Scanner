import * as path from 'node:path';
import * as vscode from 'vscode';
import { LanguageClient, type LanguageClientOptions, type ServerOptions, TransportKind } from 'vscode-languageclient/node';

import { LSP_DEBUG_PORT, SUPPORTED_VSCODE_LANGUAGES } from './server/constants';
import { registerFindingsView } from './tree';

let client: LanguageClient | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const { provider } = registerFindingsView(context);

  const module = context.asAbsolutePath(path.join('dist', 'server.js'));
  const serverOptions: ServerOptions = {
    run: { module, transport: TransportKind.ipc },
    debug: { module, transport: TransportKind.ipc, options: { execArgv: ['--nolazy', `--inspect=${LSP_DEBUG_PORT}`] } },
  };
  const clientOptions: LanguageClientOptions = {
    documentSelector: SUPPORTED_VSCODE_LANGUAGES.flatMap((language) => [
      { scheme: 'file', language },
      { scheme: 'untitled', language },
    ]),
    synchronize: {
      configurationSection: 'llmscan',
      fileEvents: vscode.workspace.createFileSystemWatcher('**/{.llmscan.yml,.llmscan.yaml,.llmscan-baseline.json}'),
    },
    diagnosticCollectionName: 'llmscan',
  };
  client = new LanguageClient('llmscan', 'LLM Security Scanner', serverOptions, clientOptions);
  // llmscan.scanWorkspace / llmscan.createBaseline は Language Server の executeCommand として登録される
  await client.start();

  void vscode.commands.executeCommand('setContext', 'llmscan.scanned', false);

  client.onNotification('llmscan/scanCompleted', () => {
    void vscode.commands.executeCommand('setContext', 'llmscan.scanned', true);
    provider.refresh();
  });
  client.onNotification('llmscan/scanCleared', () => {
    void vscode.commands.executeCommand('setContext', 'llmscan.scanned', false);
    provider.refresh();
  });
}

export async function deactivate(): Promise<void> {
  await client?.stop();
}
