import * as path from 'node:path';
import * as vscode from 'vscode';
import { SUPPRESSION_RULE_ID } from '@llmscan/core';

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
    if (!element) {
      // ルート階層: llmscan による診断を持つファイル一覧
      const isJa = vscode.env.language.startsWith('ja');
      const fileDiagnostics = vscode.languages
        .getDiagnostics()
        .filter(([, diags]) =>
          diags.some(
            (d) =>
              d.source === 'llmscan' &&
              d.code !== SUPPRESSION_RULE_ID &&
              (!this.highOnlyFilter || d.severity === vscode.DiagnosticSeverity.Error),
          ),
        );

      if (fileDiagnostics.length === 0) {
        return [];
      }

      return fileDiagnostics.map(([uri, diags]) => {
        const activeDiags = diags.filter(
          (d) =>
            d.source === 'llmscan' &&
            d.code !== SUPPRESSION_RULE_ID &&
            (!this.highOnlyFilter || d.severity === vscode.DiagnosticSeverity.Error),
        );
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
      const diags = (vscode.languages.getDiagnostics(element.uri) || []).filter(
        (d) =>
          d.source === 'llmscan' &&
          d.code !== SUPPRESSION_RULE_ID &&
          (!this.highOnlyFilter || d.severity === vscode.DiagnosticSeverity.Error),
      );

      return diags.map((d) => {
        const line = d.range.start.line + 1;
        const code =
          typeof d.code === 'string'
            ? d.code
            : typeof d.code === 'object' && d.code !== null
              ? String(d.code.value)
              : '';
        const shortMsg = d.message.replace(/（確信度: .*?）/, '');
        const isLlm = code.startsWith('LLM05');
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

export function registerFindingsView(context: vscode.ExtensionContext): vscode.TreeView<FindingsTreeItem> {
  const provider = new FindingsTreeDataProvider();
  const treeView = vscode.window.createTreeView('llmscan.findings', {
    treeDataProvider: provider,
    showCollapseAll: true,
  });

  const updateBadge = () => {
    const isJa = vscode.env.language.startsWith('ja');
    const total = vscode.languages.getDiagnostics().reduce((acc, [, diags]) => {
      return acc + diags.filter((d) => d.source === 'llmscan' && d.code !== SUPPRESSION_RULE_ID).length;
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

  context.subscriptions.push(
    treeView,
    toggleFilterCmd,
    vscode.languages.onDidChangeDiagnostics(() => updateBadge()),
  );

  updateBadge();
  return treeView;
}
