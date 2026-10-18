import * as path from 'node:path';
import * as vscode from 'vscode';
import {
  collectReportItems,
  generateAiRemediationPrompt,
  getDiagnosticRuleCode,
  isActiveLlmscanDiagnostic,
} from './report';

export class FindingsTreeItem extends vscode.TreeItem {
  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly uri?: vscode.Uri,
    public readonly diagnostic?: vscode.Diagnostic,
  ) {
    super(label, collapsibleState);
  }
}

export class FindingsTreeDataProvider implements vscode.TreeDataProvider<FindingsTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<FindingsTreeItem | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private highOnlyFilter = false;

  constructor() {
    vscode.languages.onDidChangeDiagnostics(() => {
      this._onDidChangeTreeData.fire();
    });
  }

  toggleFilter(): boolean {
    this.highOnlyFilter = !this.highOnlyFilter;
    this._onDidChangeTreeData.fire();
    return this.highOnlyFilter;
  }

  isHighOnly(): boolean {
    return this.highOnlyFilter;
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FindingsTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FindingsTreeItem): vscode.ProviderResult<FindingsTreeItem[]> {
    const errSev = vscode.DiagnosticSeverity.Error;

    if (!element) {
      // ルート階層: llmscan による診断を持つファイル一覧
      const isJa = vscode.env.language.startsWith('ja');
      const fileDiagnostics = vscode.languages
        .getDiagnostics()
        .filter(([, diags]) => diags.some((d) => isActiveLlmscanDiagnostic(d, this.highOnlyFilter, errSev)));

      if (fileDiagnostics.length === 0) {
        return [];
      }

      return fileDiagnostics.map(([uri, diags]) => {
        const activeDiags = diags.filter((d) => isActiveLlmscanDiagnostic(d, this.highOnlyFilter, errSev));
        const count = activeDiags.length;
        const relative = vscode.workspace.asRelativePath(uri);
        const fileName = path.basename(uri.fsPath);
        const dirName = path.dirname(relative);

        const item = new FindingsTreeItem(fileName, vscode.TreeItemCollapsibleState.Expanded, uri);
        const countText = isJa ? `(${count}件)` : `(${count} items)`;
        item.description = dirName === '.' ? countText : `${dirName} ${countText}`;
        item.iconPath = vscode.ThemeIcon.File;
        item.contextValue = 'file';
        return item;
      });
    }

    if (element.uri && !element.diagnostic) {
      // ファイル配下の指摘一覧
      const isJa = vscode.env.language.startsWith('ja');
      const diags = (vscode.languages.getDiagnostics(element.uri) || []).filter((d) =>
        isActiveLlmscanDiagnostic(d, this.highOnlyFilter, errSev),
      );

      return diags.map((d) => {
        const line = d.range.start.line + 1;
        const code = getDiagnosticRuleCode(d);
        const shortMsg = d.message.replace(/（確信度: .*?）/, '');
        const isLlm = code.startsWith('LLM0');
        const severityLabel =
          d.severity === vscode.DiagnosticSeverity.Error
            ? 'High'
            : d.severity === vscode.DiagnosticSeverity.Warning
              ? 'Med'
              : 'Low';

        const item = new FindingsTreeItem(
          `[${code}] ${shortMsg}`,
          vscode.TreeItemCollapsibleState.None,
          element.uri,
          d,
        );
        item.description = `L${line} • ${severityLabel}${isLlm ? ' • AI' : ''}`;
        const linePrefix = isJa ? '行' : 'Line';
        item.tooltip = new vscode.MarkdownString(`**${code}** (${linePrefix}: ${line})\n\n${d.message}`);

        if (d.severity === vscode.DiagnosticSeverity.Error) {
          item.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('problemsErrorIcon.foreground'));
        } else if (d.severity === vscode.DiagnosticSeverity.Warning) {
          item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
        } else {
          item.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('problemsInfoIcon.foreground'));
        }

        item.command = {
          command: 'vscode.open',
          title: isJa ? 'ファイルを開く' : 'Open File',
          arguments: [
            element.uri,
            {
              selection: d.range,
              preserveFocus: false,
            },
          ],
        };

        return item;
      });
    }

    return [];
  }
}

export function registerFindingsView(context: vscode.ExtensionContext): {
  treeView: vscode.TreeView<FindingsTreeItem>;
  provider: FindingsTreeDataProvider;
} {
  const provider = new FindingsTreeDataProvider();
  const treeView = vscode.window.createTreeView('llmscan.findings', {
    treeDataProvider: provider,
    showCollapseAll: true,
  });

  const updateBadge = () => {
    const isJa = vscode.env.language.startsWith('ja');
    const errSev = vscode.DiagnosticSeverity.Error;
    const total = vscode.languages.getDiagnostics().reduce((acc, [, diags]) => {
      return acc + diags.filter((d) => isActiveLlmscanDiagnostic(d, false, errSev)).length;
    }, 0);
    treeView.badge =
      total > 0
        ? {
            value: total,
            tooltip: isJa ? `${total} 件のセキュリティ指摘` : `${total} security findings`,
          }
        : undefined;
  };

  const toggleFilterCmd = vscode.commands.registerCommand('llmscan.toggleFilter', () => {
    const isJa = vscode.env.language.startsWith('ja');
    const highOnly = provider.toggleFilter();
    const msg = highOnly
      ? (isJa ? 'LLMScan: 高重大度（Critical / High）のみ表示中' : 'LLMScan: Showing High / Critical findings only')
      : (isJa ? 'LLMScan: すべての重大度を表示中' : 'LLMScan: Showing all severities');
    vscode.window.showInformationMessage(msg);
  });

  const copyFindingsCmd = vscode.commands.registerCommand('llmscan.copyFindings', async () => {
    const isJa = vscode.env.language.startsWith('ja');
    const items = collectReportItems(vscode, provider.isHighOnly());
    if (items.length === 0) {
      const msg = isJa ? 'LLMScan: コピー対象のセキュリティ指摘はありません' : 'LLMScan: No security findings to copy';
      vscode.window.showInformationMessage(msg);
      return;
    }
    const markdown = generateAiRemediationPrompt(items, isJa);
    await vscode.env.clipboard.writeText(markdown);
    const msg = isJa
      ? `LLMScan: ${items.length} 件の指摘を AI 修正用プロンプト（Markdown）としてクリップボードにコピーしました`
      : `LLMScan: Copied ${items.length} findings to clipboard as AI remediation prompt`;
    vscode.window.showInformationMessage(msg);
  });

  const exportReportCmd = vscode.commands.registerCommand('llmscan.exportReport', async () => {
    const isJa = vscode.env.language.startsWith('ja');
    const items = collectReportItems(vscode, provider.isHighOnly());
    const markdown = generateAiRemediationPrompt(items, isJa);
    const doc = await vscode.workspace.openTextDocument({
      content: markdown,
      language: 'markdown',
    });
    await vscode.window.showTextDocument(doc, { preview: false });
  });

  context.subscriptions.push(
    treeView,
    toggleFilterCmd,
    copyFindingsCmd,
    exportReportCmd,
    vscode.languages.onDidChangeDiagnostics(() => updateBadge()),
  );

  updateBadge();
  return { treeView, provider };
}
