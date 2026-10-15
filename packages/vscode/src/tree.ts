import * as path from 'node:path';
import * as vscode from 'vscode';
import { SUPPRESSION_RULE_ID } from '@llmscan/core';
import { collectReportItems, generateAiRemediationPrompt } from './report';

export class FindingsTreeItem extends vscode.TreeItem {
  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly itemType: 'action' | 'status' | 'file' | 'finding' = 'file',
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
  private scanState: {
    status: 'idle' | 'scanning' | 'scanned';
    totalFiles: number;
    lastScanTime?: string;
  } = { status: 'idle', totalFiles: 0 };

  constructor() {
    vscode.languages.onDidChangeDiagnostics(() => {
      this._onDidChangeTreeData.fire();
    });
  }

  markScanning(): void {
    this.scanState = { ...this.scanState, status: 'scanning' };
    this._onDidChangeTreeData.fire();
  }

  markScanned(totalFiles: number): void {
    const now = new Date();
    const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
    this.scanState = { status: 'scanned', totalFiles, lastScanTime: timeStr };
    this._onDidChangeTreeData.fire();
  }

  resetScanned(): void {
    this.scanState = { status: 'idle', totalFiles: 0, lastScanTime: undefined };
    this._onDidChangeTreeData.fire();
  }

  isScanned(): boolean {
    return this.scanState.status === 'scanned';
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
    const isJa = vscode.env.language.startsWith('ja');

    if (!element) {
      const items: FindingsTreeItem[] = [];

      // 1. 最上部のアクションボタン
      if (this.scanState.status === 'scanning') {
        const scanningItem = new FindingsTreeItem(
          isJa ? 'スキャンを実行中...' : 'Scanning workspace...',
          vscode.TreeItemCollapsibleState.None,
          'status',
        );
        scanningItem.description = isJa ? 'ファイルを解析しています' : 'Analyzing files...';
        scanningItem.iconPath = new vscode.ThemeIcon('sync~spin');
        items.push(scanningItem);
      } else {
        const scanBtn = new FindingsTreeItem(
          this.scanState.status === 'scanned'
            ? (isJa ? 'ワークスペース全体を再スキャン' : 'Rescan Workspace')
            : (isJa ? 'ワークスペース全体をスキャン' : 'Scan Workspace'),
          vscode.TreeItemCollapsibleState.None,
          'action',
        );
        scanBtn.description = isJa ? 'クリックして検査実行' : 'Click to scan';
        scanBtn.iconPath = new vscode.ThemeIcon(
          this.scanState.status === 'scanned' ? 'refresh' : 'play',
          new vscode.ThemeColor('charts.green'),
        );
        scanBtn.command = {
          command: 'llmscan.scanWorkspace',
          title: isJa ? 'ワークスペース全体をスキャン' : 'Scan Workspace',
        };
        items.push(scanBtn);
      }

      // 診断を持つファイル一覧の取得
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

      const totalFindings = fileDiagnostics.reduce((acc, [, diags]) => {
        return (
          acc +
          diags.filter(
            (d) =>
              d.source === 'llmscan' &&
              d.code !== SUPPRESSION_RULE_ID &&
              (!this.highOnlyFilter || d.severity === vscode.DiagnosticSeverity.Error),
          ).length
        );
      }, 0);

      // 指摘が存在する場合: AI修正プロンプトコピー、レポート出力、クリアボタン
      if (totalFindings > 0) {
        const copyBtn = new FindingsTreeItem(
          isJa ? 'AI 修正用プロンプトをコピー' : 'Copy for AI Fix',
          vscode.TreeItemCollapsibleState.None,
          'action',
        );
        copyBtn.description = isJa ? `${totalFindings} 件の指摘を一括コピー` : `Copy ${totalFindings} findings`;
        copyBtn.iconPath = new vscode.ThemeIcon('copy', new vscode.ThemeColor('charts.blue'));
        copyBtn.command = {
          command: 'llmscan.copyFindings',
          title: isJa ? 'AI 修正用プロンプトをコピー' : 'Copy for AI Fix',
        };
        items.push(copyBtn);

        const exportBtn = new FindingsTreeItem(
          isJa ? 'レポートをタブで開く' : 'Open Report in Tab',
          vscode.TreeItemCollapsibleState.None,
          'action',
        );
        exportBtn.description = isJa ? 'Markdown 形式で表示' : 'View Markdown report';
        exportBtn.iconPath = new vscode.ThemeIcon('output');
        exportBtn.command = {
          command: 'llmscan.exportReport',
          title: isJa ? 'レポートをタブで開く' : 'Open Report in Tab',
        };
        items.push(exportBtn);

        const clearBtn = new FindingsTreeItem(
          isJa ? 'スキャン結果をクリア' : 'Clear Scan Results',
          vscode.TreeItemCollapsibleState.None,
          'action',
        );
        clearBtn.iconPath = new vscode.ThemeIcon('clear-all');
        clearBtn.command = {
          command: 'llmscan.clearScan',
          title: isJa ? 'スキャン結果をクリア' : 'Clear Scan Results',
        };
        items.push(clearBtn);

        // 指摘サマリーヘッダー
        const summaryItem = new FindingsTreeItem(
          isJa ? `検出されたセキュリティ指摘 (${totalFindings}件)` : `Security Findings (${totalFindings})`,
          vscode.TreeItemCollapsibleState.None,
          'status',
        );
        summaryItem.iconPath = new vscode.ThemeIcon('alert', new vscode.ThemeColor('problemsWarningIcon.foreground'));
        items.push(summaryItem);

        // 各ファイル項目（配下に指摘を展開）
        for (const [uri, diags] of fileDiagnostics) {
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

          const fileItem = new FindingsTreeItem(
            fileName,
            vscode.TreeItemCollapsibleState.Expanded,
            'file',
            uri,
          );
          const countText = isJa ? `(${count}件)` : `(${count} items)`;
          fileItem.description = dirName === '.' ? countText : `${dirName} ${countText}`;
          fileItem.iconPath = vscode.ThemeIcon.File;
          fileItem.contextValue = 'file';
          items.push(fileItem);
        }

        return items;
      }

      // 指摘が 0 件の場合（スキャン完了後）
      if (this.scanState.status === 'scanned') {
        const secureItem = new FindingsTreeItem(
          isJa ? '✓ 脆弱性は検出されませんでした' : '✓ No vulnerabilities detected',
          vscode.TreeItemCollapsibleState.None,
          'status',
        );
        secureItem.description = isJa ? '安全です' : 'Workspace is secure';
        secureItem.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));
        items.push(secureItem);

        const countItem = new FindingsTreeItem(
          isJa
            ? `${this.scanState.totalFiles} ファイルを検査完了`
            : `${this.scanState.totalFiles} files scanned`,
          vscode.TreeItemCollapsibleState.None,
          'status',
        );
        countItem.description = isJa ? '指摘 0 件' : '0 findings';
        countItem.iconPath = new vscode.ThemeIcon('folder');
        items.push(countItem);

        const excludeItem = new FindingsTreeItem(
          isJa ? '除外設定 (.llmscan.yml)' : 'Exclusions (.llmscan.yml)',
          vscode.TreeItemCollapsibleState.None,
          'status',
        );
        excludeItem.description = isJa ? 'テスト/フィクスチャ除外適用中' : 'Active';
        excludeItem.iconPath = new vscode.ThemeIcon('filter');
        items.push(excludeItem);

        if (this.scanState.lastScanTime) {
          const timeItem = new FindingsTreeItem(
            isJa ? `最終スキャン: ${this.scanState.lastScanTime}` : `Last scanned: ${this.scanState.lastScanTime}`,
            vscode.TreeItemCollapsibleState.None,
            'status',
          );
          timeItem.iconPath = new vscode.ThemeIcon('history');
          items.push(timeItem);
        }

        const clearBtn = new FindingsTreeItem(
          isJa ? 'スキャン結果をクリア' : 'Clear Scan Results',
          vscode.TreeItemCollapsibleState.None,
          'action',
        );
        clearBtn.iconPath = new vscode.ThemeIcon('clear-all');
        clearBtn.command = {
          command: 'llmscan.clearScan',
          title: isJa ? 'スキャン結果をクリア' : 'Clear Scan Results',
        };
        items.push(clearBtn);

        return items;
      }

      // 未スキャン（初期状態）
      const infoItem = new FindingsTreeItem(
        isJa ? 'リアルタイム静的解析' : 'Real-time Static Scanner',
        vscode.TreeItemCollapsibleState.None,
        'status',
      );
      infoItem.description = isJa ? '開いたファイルは自動解析されます' : 'Active files analyzed live';
      infoItem.iconPath = new vscode.ThemeIcon('info');
      items.push(infoItem);

      const confItem = new FindingsTreeItem(
        isJa ? '設定 (.llmscan.yml)' : 'Config (.llmscan.yml)',
        vscode.TreeItemCollapsibleState.None,
        'status',
      );
      confItem.description = isJa ? 'テスト/フィクスチャ除外設定中' : 'Excluding test fixtures';
      confItem.iconPath = new vscode.ThemeIcon('gear');
      items.push(confItem);

      return items;
    }

    // ファイル配下の指摘一覧を展開
    if (element.itemType === 'file' && element.uri && !element.diagnostic) {
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
          'finding',
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

    if (total > 0) {
      treeView.description = isJa ? `${total} 件の指摘` : `${total} findings`;
    } else if (provider.isScanned()) {
      treeView.description = isJa ? '安全 (0件)' : 'Secure (0)';
    } else {
      treeView.description = undefined;
    }
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
