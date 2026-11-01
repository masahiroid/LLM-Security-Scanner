import * as vscode from 'vscode';
import { DEFAULT_TRIAGE_ENDPOINTS, DEFAULT_TRIAGE_MODELS, SUPPORTED_TRIAGE_PROVIDERS, validateTriageEndpoint, type TriageProvider } from '@llmscan/core';
import { COMMAND_CONFIGURE_TRIAGE, TRIAGE_CONFIG_KEY, TRIAGE_SECRET_PREFIX } from './server/constants';

export function registerTriageConfiguration(context: vscode.ExtensionContext): void {
  const t = (jp: string, en: string) => vscode.env.language.startsWith('ja') ? jp : en;
  context.subscriptions.push(vscode.commands.registerCommand(COMMAND_CONFIGURE_TRIAGE, async () => {
    const action = await vscode.window.showQuickPick(['openai', 'anthropic', 'ollama', t('設定・キーを削除', 'Delete configuration and keys')], {
      title: t('AI トリアージ設定（任意）', 'Configure optional AI triage'),
    });
    if (!action) return;
    if (!SUPPORTED_TRIAGE_PROVIDERS.includes(action as TriageProvider)) {
      for (const provider of SUPPORTED_TRIAGE_PROVIDERS) await context.secrets.delete(TRIAGE_SECRET_PREFIX + provider);
      await context.globalState.update(TRIAGE_CONFIG_KEY, undefined);
      return;
    }
    const provider = action as TriageProvider;
    const model = await vscode.window.showInputBox({ title: t('モデル ID', 'Model ID'), value: DEFAULT_TRIAGE_MODELS[provider], ignoreFocusOut: true });
    if (!model?.trim()) return;
    const endpoint = await vscode.window.showInputBox({ title: t('送信先 API URL', 'Destination API URL'), value: DEFAULT_TRIAGE_ENDPOINTS[provider], ignoreFocusOut: true,
      validateInput: value => { try { validateTriageEndpoint(value, provider); return undefined; } catch { return t('HTTPS URL またはローカル Ollama の HTTP URL を指定してください', 'Use HTTPS or loopback HTTP for Ollama'); } },
    });
    if (!endpoint) return;
    if (provider !== 'ollama') {
      const key = await vscode.window.showInputBox({ title: t('API キー（SecretStorage に保存）', 'API key (saved in SecretStorage)'), password: true, ignoreFocusOut: true });
      if (!key?.trim()) return;
      await context.secrets.store(TRIAGE_SECRET_PREFIX + provider, key.trim());
    }
    await context.globalState.update(TRIAGE_CONFIG_KEY, { provider, model: model.trim(), endpoint });
    void vscode.window.showInformationMessage(t('AI トリアージを設定しました。送信は指摘ごとの手動操作時のみです。', 'AI triage configured. Requests are sent only when you manually review a finding.'));
  }));

}
