import { registerTriageConfiguration } from './triage-config';
import * as vscode from 'vscode';
import {
  initParsers, triageContextBounds, buildTriagePrompt, triageFindingWithLlm, maskTriageSecrets,
  languageForFile,
  TRIAGE_REDACTED, type TriageConfig,
} from '@llmscan/core';
import type { FindingsTreeItem } from './tree';
import { getDiagnosticRuleCode } from './report';
import { COMMAND_CONFIGURE_TRIAGE, COMMAND_TRIAGE_FINDING, TRIAGE_CONFIG_KEY, TRIAGE_SECRET_PREFIX } from './server/constants';

export function registerTriage(context: vscode.ExtensionContext): void {
  const ja = vscode.env.language.startsWith('ja');
  const t = (jp: string, en: string) => ja ? jp : en;
  registerTriageConfiguration(context);

  context.subscriptions.push(vscode.commands.registerCommand(COMMAND_TRIAGE_FINDING, async (item?: FindingsTreeItem) => {
    if (!vscode.workspace.isTrusted) {
      void vscode.window.showWarningMessage(t('AI トリアージには信頼済みワークスペースが必要です。', 'AI triage requires a trusted workspace.')); return;
    }
    if (!item?.uri || !item.diagnostic) {
      void vscode.window.showInformationMessage(t('サイドバーの指摘を右クリックして AI トリアージを選んでください。', 'Right-click a finding in the sidebar and select AI triage.')); return;
    }
    const config = context.globalState.get<TriageConfig>(TRIAGE_CONFIG_KEY);
    if (!config) { await vscode.commands.executeCommand(COMMAND_CONFIGURE_TRIAGE); return; }
    try {
      const document = await vscode.workspace.openTextDocument(item.uri);
      const language = languageForFile(item.uri.fsPath);
      if (!language) return;
      const snapshot = document.getText();
      const version = document.version;
      const diagnostic = item.diagnostic;
      if (!vscode.languages.getDiagnostics(item.uri).includes(diagnostic)) throw new Error(t('指摘が更新されています。再スキャンしてください。', 'Finding is stale. Rescan and try again.'));
      await initParsers({ wasmDir: context.asAbsolutePath('dist/wasm') });
      const input = {
        ruleId: getDiagnosticRuleCode(diagnostic), severity: vscode.DiagnosticSeverity[diagnostic.severity], message: diagnostic.message,
        ...await triageContextBounds(snapshot, language, diagnostic.range.start.line, diagnostic.range.start.character),
        filePath: '', language, startLine: diagnostic.range.start.line + 1, endLine: diagnostic.range.end.line + 1,
        trace: (diagnostic.relatedInformation ?? []).map(info => info.message), sourceText: snapshot, isJa: ja,
      };
      const prompt = buildTriagePrompt(input);
      const payloadPreview = await vscode.workspace.openTextDocument({ content: `${config.provider} / ${config.model}\n${config.endpoint}\n\n${prompt.systemPrompt}\n\n${prompt.userPrompt}`, language: 'plaintext' });
      await vscode.window.showTextDocument(payloadPreview, { preview: true });
      const send = t('この内容を送信', 'Send this content');
      if (await vscode.window.showWarningMessage(t(
        `表示中の内容を ${config.endpoint} に送信します。マスクは完全ではありません。秘密情報が残っていないことを確認してください。API 利用料金が発生する場合があります。プレビューの編集は送信内容に反映されません。`,
        `Send the displayed content to ${config.endpoint}? Redaction is best effort: inspect for remaining secrets. API charges may apply. Editing the preview does not change the payload.`), { modal: true }, send) !== send) return;
      if (!vscode.workspace.isTrusted) return;
      const apiKey = await context.secrets.get(TRIAGE_SECRET_PREFIX + config.provider);
      const result = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: t('AI が指摘を精査中…', 'Reviewing finding with AI…') }, () => triageFindingWithLlm(input, { ...config, apiKey }));
      const report = await vscode.workspace.openTextDocument({ content: `${result.verdict} (${result.confidence})\n\n${result.reasoning}\n\n${result.explanation}`, language: 'plaintext' });
      await vscode.window.showTextDocument(report, { preview: false });
      if (result.patchedCode === result.originalCode || !result.patchedCode.trim() || result.patchedCode.includes(TRIAGE_REDACTED) || maskTriageSecrets(result.originalCode) !== result.originalCode) return;
      const start = new vscode.Position(input.startLine - 1, 0);
      const end = document.lineAt(input.endLine - 1).range.end;
      const range = new vscode.Range(start, end);
      const patched = snapshot.slice(0, document.offsetAt(start)) + result.patchedCode.replace(/\n/g, document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n') + snapshot.slice(document.offsetAt(end));
      const before = await vscode.workspace.openTextDocument({ content: snapshot, language: document.languageId });
      const after = await vscode.workspace.openTextDocument({ content: patched, language: document.languageId });
      await vscode.commands.executeCommand('vscode.diff', before.uri, after.uri, t('AI 修正案（未適用・要確認）', 'AI patch proposal (unapplied; review required)'));
      const apply = t('修正案を適用', 'Apply proposed patch');
      if (await vscode.window.showWarningMessage(t('AI の修正案を確認してください。安全性・正しさは保証されません。', 'Review the AI proposal. Safety and correctness are not guaranteed.'), { modal: true }, apply) !== apply) return;
      if (!vscode.workspace.isTrusted || document.isClosed || document.version !== version || document.getText() !== snapshot) throw new Error(t('元ファイルが変更されています。再実行してください。', 'Source changed. Run triage again.'));
      const edit = new vscode.WorkspaceEdit(); edit.replace(item.uri, range, result.patchedCode.replace(/\n/g, document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n'));
      if (!await vscode.workspace.applyEdit(edit)) throw new Error(t('修正を適用できませんでした。', 'Could not apply patch.'));
    } catch (error) {
      // Never display provider response bodies or credentials.
      void vscode.window.showErrorMessage(t('AI トリアージに失敗しました: ', 'AI triage failed: ') + (error instanceof Error ? error.message : 'Unknown error'));
    }
  }));
}
