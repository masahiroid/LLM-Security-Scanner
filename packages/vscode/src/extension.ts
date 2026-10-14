import * as path from 'node:path';
import * as vscode from 'vscode';
import { LanguageClient, type LanguageClientOptions, type ServerOptions, TransportKind } from 'vscode-languageclient/node';

let client: LanguageClient | undefined;

const LANGUAGES = ['python', 'javascript', 'javascriptreact', 'typescript', 'typescriptreact', 'php'];

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const module = context.asAbsolutePath(path.join('dist', 'server.js'));
  const serverOptions: ServerOptions = {
    run: { module, transport: TransportKind.ipc },
    debug: { module, transport: TransportKind.ipc, options: { execArgv: ['--nolazy', '--inspect=6019'] } },
  };
  const clientOptions: LanguageClientOptions = {
    documentSelector: LANGUAGES.flatMap((language) => [
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
}

export async function deactivate(): Promise<void> {
  await client?.stop();
}
