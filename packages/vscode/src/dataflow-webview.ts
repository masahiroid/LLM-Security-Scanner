import * as fs from 'node:fs';
import type * as vscode from 'vscode';
import {
  KIND_META,
  type LanguageId,
  findKindMetaForRuleId,
  getLanguageFamily,
  languageForFile,
  owaspForRuleId,
} from '@llmscan/core';
import { getDiagnosticRuleCode, isCriticalRuleCode } from './report';
import { WEBVIEW_TYPE_DATAFLOW_GRAPH } from './server/constants';

export interface DataflowNodeItem {
  stepIndex: number;
  totalSteps: number;
  role: 'source' | 'step' | 'sink';
  line: number;
  column: number;
  message: string;
  codeLine?: string;
}

export interface DataflowGraphModel {
  ruleCode: string;
  title: string;
  severity: string;
  cwe: string;
  owaspId: string;
  owaspTitle: string;
  owaspUrl: string;
  relativePath: string;
  message: string;
  why: string;
  recommendation: string;
  nodes: DataflowNodeItem[];
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * データフローグラフ Webview の HTML を生成する純粋関数（単体テスト可能）
 */
export function renderDataflowGraphHtml(model: DataflowGraphModel, isJa = true): string {
  const roleLabel = (role: DataflowNodeItem['role']) => {
    if (isJa) {
      return role === 'source' ? '汚染源 (Source)' : role === 'sink' ? '危険な処理 (Sink)' : '伝播経路 (Step)';
    }
    return role === 'source' ? 'Source' : role === 'sink' ? 'Dangerous Sink' : 'Propagation Step';
  };

  const nodesHtml = model.nodes
    .map((n, idx) => {
      const arrow =
        idx < model.nodes.length - 1
          ? `<div class="flow-arrow" aria-hidden="true">↓</div>`
          : '';
      const codeHtml = n.codeLine
        ? `<pre class="code-line"><code>${escapeHtml(n.codeLine.trim())}</code></pre>`
        : '';
      const clickHint = isJa ? 'クリックで該当行へ移動' : 'Click to jump to line';
      return `
        <div class="flow-node role-${n.role}" data-line="${n.line}" data-col="${n.column}" title="${clickHint}">
          <div class="node-header">
            <span class="role-badge role-${n.role}">${escapeHtml(roleLabel(n.role))}</span>
            <span class="step-num">${n.stepIndex}/${n.totalSteps}</span>
            <span class="line-badge">L${n.line}</span>
          </div>
          <div class="node-msg">${escapeHtml(n.message)}</div>
          ${codeHtml}
        </div>
        ${arrow}
      `;
    })
    .join('\n');

  const whyHeader = isJa ? '危険な理由' : 'Why This Is Dangerous';
  const fixHeader = isJa ? '推奨される安全な書き方' : 'Recommended Remediation';
  const flowHeader = isJa
    ? 'データフロー汚染経路（ノードをクリックすると該当コードへジャンプします）'
    : 'Dataflow Taint Path (Click any node to jump to source line)';

  return `<!DOCTYPE html>
<html lang="${isJa ? 'ja' : 'en'}">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>LLMScan Dataflow: ${escapeHtml(model.ruleCode)}</title>
  <style>
    body {
      font-family: var(--vscode-font-family, sans-serif);
      color: var(--vscode-foreground);
      background-color: var(--vscode-editor-background);
      padding: 20px;
      line-height: 1.5;
    }
    .header {
      border-bottom: 1px solid var(--vscode-panel-border, #444);
      padding-bottom: 14px;
      margin-bottom: 20px;
    }
    .badges {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 8px;
    }
    .badge {
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      background: var(--vscode-badge-background);
      color: var(--vscode-badge-foreground);
    }
    .badge.sev-critical, .badge.sev-high {
      background: #d32f2f;
      color: #fff;
    }
    .badge.sev-medium {
      background: #f57c00;
      color: #fff;
    }
    h1 {
      font-size: 18px;
      margin: 4px 0;
    }
    .file-path {
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 12px;
      opacity: 0.8;
    }
    .section-title {
      font-size: 14px;
      font-weight: 600;
      margin: 20px 0 10px;
    }
    .flow-container {
      display: flex;
      flex-direction: column;
      align-items: stretch;
      max-width: 720px;
    }
    .flow-node {
      border: 1px solid var(--vscode-panel-border, #555);
      border-left-width: 5px;
      border-radius: 6px;
      padding: 12px 14px;
      background: var(--vscode-editorWidget-background, rgba(128,128,128,0.08));
      cursor: pointer;
      transition: transform 0.1s ease, border-color 0.1s ease;
    }
    .flow-node:hover {
      transform: translateX(3px);
      border-color: var(--vscode-focusBorder, #007fd4);
    }
    .flow-node.role-source {
      border-left-color: #0288d1;
    }
    .flow-node.role-step {
      border-left-color: #fbc02d;
    }
    .flow-node.role-sink {
      border-left-color: #d32f2f;
    }
    .node-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
      font-size: 12px;
    }
    .role-badge {
      padding: 1px 6px;
      border-radius: 3px;
      font-weight: 600;
    }
    .role-badge.role-source { background: rgba(2, 136, 209, 0.2); color: #29b6f6; }
    .role-badge.role-step { background: rgba(251, 192, 45, 0.2); color: #ffd54f; }
    .role-badge.role-sink { background: rgba(211, 47, 47, 0.25); color: #ef5350; }
    .line-badge {
      margin-left: auto;
      font-family: var(--vscode-editor-font-family, monospace);
      font-weight: 600;
      text-decoration: underline;
    }
    .node-msg {
      font-size: 13px;
      margin-bottom: 6px;
    }
    .code-line {
      margin: 0;
      padding: 6px 10px;
      border-radius: 4px;
      background: var(--vscode-textCodeBlock-background, rgba(0,0,0,0.25));
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 12px;
      overflow-x: auto;
    }
    .flow-arrow {
      text-align: center;
      font-size: 18px;
      font-weight: bold;
      padding: 4px 0;
      opacity: 0.7;
    }
    .info-card {
      max-width: 720px;
      border: 1px solid var(--vscode-panel-border, #444);
      border-radius: 6px;
      padding: 12px 14px;
      margin-top: 14px;
      background: var(--vscode-editorWidget-background, rgba(128,128,128,0.05));
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="badges">
      <span class="badge sev-${escapeHtml(model.severity.toLowerCase())}">${escapeHtml(model.severity)}</span>
      <span class="badge">${escapeHtml(model.ruleCode)}</span>
      <span class="badge">${escapeHtml(model.owaspId)} ${escapeHtml(model.owaspTitle)}</span>
      <span class="badge">${escapeHtml(model.cwe)}</span>
    </div>
    <h1>${escapeHtml(model.title)}</h1>
    <div class="file-path">${escapeHtml(model.relativePath)}</div>
  </div>

  <div class="section-title">${escapeHtml(flowHeader)}</div>
  <div class="flow-container">
    ${nodesHtml}
  </div>

  <div class="info-card">
    <div class="section-title" style="margin-top:0">${escapeHtml(whyHeader)}</div>
    <div>${escapeHtml(model.why)}</div>
    <div class="section-title">${escapeHtml(fixHeader)}</div>
    <div>${escapeHtml(model.recommendation)}</div>
  </div>

  <script>
    const vscode = acquireVsCodeApi();
    document.querySelectorAll('.flow-node').forEach((el) => {
      el.addEventListener('click', () => {
        const line = Number(el.getAttribute('data-line') || '1');
        const col = Number(el.getAttribute('data-col') || '1');
        vscode.postMessage({ type: 'jumpToLine', line, column: col });
      });
    });
  </script>
</body>
</html>`;
}

/**
 * Diagnostic と対象ファイル URI から DataflowGraphModel を構築する
 */
export function buildDataflowGraphModel(
  uri: vscode.Uri,
  relativePath: string,
  diagnostic: vscode.Diagnostic,
  isJa = true,
): DataflowGraphModel {
  const ruleCode = getDiagnosticRuleCode(diagnostic);
  const owasp = owaspForRuleId(ruleCode);
  const langId: LanguageId = languageForFile(uri.fsPath) ?? 'javascript';
  const family = getLanguageFamily(langId);

  const meta = findKindMetaForRuleId(ruleCode) ?? KIND_META.sqli;

  let fileLines: string[] = [];
  try {
    if (fs.existsSync(uri.fsPath)) {
      fileLines = fs.readFileSync(uri.fsPath, 'utf8').split(/\r?\n/);
    }
  } catch {
    // 読み込み不可時はコード行スニペットを省略
  }

  const rels = diagnostic.relatedInformation ?? [];
  const totalSteps = Math.max(1, rels.length);
  const nodes: DataflowNodeItem[] =
    rels.length > 0
      ? rels.map((rel, idx) => {
          const line0 = rel.location.range.start.line;
          const col0 = rel.location.range.start.character;
          const role: DataflowNodeItem['role'] =
            idx === 0
              ? rels.length === 1
                ? 'sink'
                : 'source'
              : idx === rels.length - 1
                ? 'sink'
                : 'step';
          return {
            stepIndex: idx + 1,
            totalSteps,
            role,
            line: line0 + 1,
            column: col0 + 1,
            message: rel.message,
            codeLine: fileLines[line0],
          };
        })
      : [
          {
            stepIndex: 1,
            totalSteps: 1,
            role: 'sink',
            line: diagnostic.range.start.line + 1,
            column: diagnostic.range.start.character + 1,
            message: diagnostic.message,
            codeLine: fileLines[diagnostic.range.start.line],
          },
        ];

  const severity = isCriticalRuleCode(ruleCode) ? 'Critical' : 'High';

  return {
    ruleCode,
    title: isJa ? meta.title : meta.titleEn,
    severity,
    cwe: meta.cwe,
    owaspId: owasp.id,
    owaspTitle: isJa ? owasp.title : owasp.titleEn,
    owaspUrl: owasp.url,
    relativePath,
    message: diagnostic.message,
    why: isJa ? meta.why : meta.whyEn,
    recommendation: isJa ? meta.fix[family] : meta.fixEn[family],
    nodes,
  };
}

/**
 * VS Code エディタ横にデータフローグラフ Webview パネルを表示する
 */
export function showDataflowGraphPanel(
  vscodeApi: typeof vscode,
  uri: vscode.Uri,
  diagnostic: vscode.Diagnostic,
): void {
  const isJa = vscodeApi.env.language.startsWith('ja');
  const relativePath = vscodeApi.workspace.asRelativePath(uri);
  const model = buildDataflowGraphModel(uri, relativePath, diagnostic, isJa);

  const panel = vscodeApi.window.createWebviewPanel(
    WEBVIEW_TYPE_DATAFLOW_GRAPH,
    `LLMScan Flow: ${model.ruleCode}`,
    vscodeApi.ViewColumn.Beside,
    { enableScripts: true },
  );

  panel.webview.html = renderDataflowGraphHtml(model, isJa);

  panel.webview.onDidReceiveMessage(async (msg: { type?: string; line?: number; column?: number }) => {
    if (msg.type === 'jumpToLine' && typeof msg.line === 'number') {
      const line0 = Math.max(0, msg.line - 1);
      const col0 = Math.max(0, (msg.column ?? 1) - 1);
      const pos = new vscodeApi.Position(line0, col0);
      const range = new vscodeApi.Range(pos, pos);
      const doc = await vscodeApi.workspace.openTextDocument(uri);
      await vscodeApi.window.showTextDocument(doc, {
        viewColumn: vscodeApi.ViewColumn.One,
        selection: range,
        preserveFocus: false,
      });
    }
  });
}
