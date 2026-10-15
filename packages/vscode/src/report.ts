import * as fs from 'node:fs';
import * as path from 'node:path';
import type * as vscode from 'vscode';
import { KIND_META, SUPPRESSION_RULE_ID, type SinkKind } from '@llmscan/core';

export interface FindingReportItem {
  uri: vscode.Uri;
  relativePath: string;
  line: number;
  column: number;
  ruleCode: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  message: string;
  trace: string[];
  codeSnippet?: string;
  language: string;
  recommendation?: string;
  cwe?: string;
}

/**
 * ワークスペース内のすべての llmscan 指摘を収集し、レポート項目を作成する
 */
export function collectReportItems(vscodeApi: typeof vscode, highOnly = false): FindingReportItem[] {
  const items: FindingReportItem[] = [];
  const isJa = vscodeApi.env.language.startsWith('ja');

  const fileDiagnostics = vscodeApi.languages.getDiagnostics().filter(([, diags]) =>
    diags.some((d) => d.source === 'llmscan' && d.code !== SUPPRESSION_RULE_ID),
  );

  for (const [uri, diags] of fileDiagnostics) {
    const activeDiags = diags.filter(
      (d) =>
        d.source === 'llmscan' &&
        d.code !== SUPPRESSION_RULE_ID &&
        (!highOnly || d.severity === 0),
    );

    if (activeDiags.length === 0) continue;

    const relativePath = vscodeApi.workspace.asRelativePath(uri);
    const ext = path.extname(uri.fsPath).replace('.', '');
    const lang = ext === 'ts' || ext === 'tsx' ? 'typescript' : ext === 'py' ? 'python' : ext === 'php' ? 'php' : 'javascript';

    let fileLines: string[] | undefined;
    try {
      if (fs.existsSync(uri.fsPath)) {
        fileLines = fs.readFileSync(uri.fsPath, 'utf8').split('\n');
      }
    } catch {
      // ファイル読み込みに失敗した場合はスニペット省略
    }

    for (const d of activeDiags) {
      const line = d.range.start.line + 1;
      const column = d.range.start.character + 1;
      const ruleCode =
        typeof d.code === 'string'
          ? d.code
          : typeof d.code === 'object' && d.code !== null
            ? String(d.code.value)
            : 'SECURITY-001';

      const isCritical = ruleCode.startsWith('LLM05-') || ruleCode.includes('CMDI') || ruleCode.includes('CODEI');
      const severity: 'Critical' | 'High' | 'Medium' | 'Low' =
        d.severity === vscodeApi.DiagnosticSeverity.Error
          ? (isCritical ? 'Critical' : 'High')
          : d.severity === vscodeApi.DiagnosticSeverity.Warning
            ? 'Medium'
            : 'Low';

      const trace: string[] = [];
      if (d.relatedInformation && d.relatedInformation.length > 0) {
        for (const rel of d.relatedInformation) {
          const relLine = rel.location.range.start.line + 1;
          const relFile = path.basename(rel.location.uri.fsPath);
          trace.push(`${rel.message} (${relFile}:${relLine})`);
        }
      }

      let codeSnippet: string | undefined;
      if (fileLines && d.range.start.line < fileLines.length) {
        const start = Math.max(0, d.range.start.line - 1);
        const end = Math.min(fileLines.length, d.range.end.line + 2);
        codeSnippet = fileLines
          .slice(start, end)
          .map((l, i) => `${start + i + 1 === line ? '> ' : '  '}${start + i + 1} | ${l}`)
          .join('\n');
      }

      // KIND_META から推奨修正と CWE を取得
      let recommendation: string | undefined;
      let cwe: string | undefined;
      const metaKey = Object.keys(KIND_META).find((k) =>
        ruleCode.toLowerCase().includes(KIND_META[k as SinkKind].code.toLowerCase()),
      ) as SinkKind | undefined;

      if (metaKey) {
        const meta = KIND_META[metaKey];
        cwe = meta.cwe;
        const family = lang === 'python' ? 'python' : lang === 'php' ? 'php' : 'javascript';
        recommendation = isJa ? meta.fix[family] : meta.fixEn[family];
      }

      items.push({
        uri,
        relativePath,
        line,
        column,
        ruleCode,
        severity,
        message: d.message,
        trace,
        codeSnippet,
        language: lang,
        recommendation,
        cwe,
      });
    }
  }

  // 重大度順（Critical -> High -> Medium -> Low）にソート
  const order: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  return items.sort((a, b) => order[a.severity] - order[b.severity]);
}

/**
 * AI コーディング（Claude, ChatGPT, Copilot, Cursor 等）に直接渡せるプロンプト形式の Markdown を生成
 */
export function generateAiRemediationPrompt(items: FindingReportItem[], isJa = true): string {
  const count = items.length;
  const criticalCount = items.filter((i) => i.severity === 'Critical').length;
  const highCount = items.filter((i) => i.severity === 'High').length;
  const medCount = items.filter((i) => i.severity === 'Medium').length;
  const lowCount = items.filter((i) => i.severity === 'Low').length;

  if (count === 0) {
    return isJa
      ? '# LLMScan セキュリティスキャン結果\n\n現在検出された脆弱性・セキュリティ上の問題はありません。'
      : '# LLMScan Security Scan Results\n\nNo security vulnerabilities are currently detected.';
  }

  const lines: string[] = [];

  if (isJa) {
    lines.push('# LLMScan セキュリティ脆弱性修正プロンプト');
    lines.push('');
    lines.push('あなたはシニアセキュリティエンジニアおよびフルスタック開発者です。');
    lines.push('LLMScan 静的解析ツールによって検出された以下のセキュリティ脆弱性を確認し、各コードを安全に修正してください。');
    lines.push('');
    lines.push('### AI修正指示:');
    lines.push('1. 各脆弱性に対して、プレースホルダや適切な無害化関数を用いた安全なコードにリファクタリングしてください。');
    lines.push('2. 単に指摘コメント（`# llmscan-ignore` 等）を追加して握りつぶすのではなく、根本原因を修正してください。');
    lines.push('3. 既存の機能、引数の型、ビジネスロジック、およびテスト互換性を保持してください。');
    lines.push('4. ファイルパスと、変更前・変更後の明確なコード差分を提示してください。');
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 検出サマリー');
    lines.push(`- **合計指摘数**: ${count} 件`);
    lines.push(`- **Critical**: ${criticalCount} 件 / **High**: ${highCount} 件 / **Medium**: ${medCount} 件 / **Low**: ${lowCount} 件`);
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 指摘一覧と詳細');
    lines.push('');

    items.forEach((item, index) => {
      lines.push(`### [${index + 1}/${count}] [${item.severity}] ${item.ruleCode}`);
      lines.push(`- **ファイル**: \`${item.relativePath}:${item.line}:${item.column}\``);
      if (item.cwe) lines.push(`- **CWE**: ${item.cwe}`);
      lines.push(`- **概要**: ${item.message}`);
      if (item.trace.length > 0) {
        lines.push('- **汚染経路 (Taint Trace)**:');
        item.trace.forEach((t) => lines.push(`  - ${t}`));
      }
      if (item.codeSnippet) {
        lines.push('');
        lines.push('**対象箇所のコード:**');
        lines.push(`\`\`\`${item.language}`);
        lines.push(item.codeSnippet);
        lines.push('\`\`\`');
      }
      if (item.recommendation) {
        lines.push(`- **推奨修正方法**: ${item.recommendation}`);
      }
      lines.push('');
      lines.push('---');
      lines.push('');
    });
  } else {
    lines.push('# LLMScan Security Remediation Prompt');
    lines.push('');
    lines.push('You are a senior security engineer and principal developer.');
    lines.push('Please analyze and remediate the following security vulnerabilities identified by the LLMScan static security analyzer.');
    lines.push('');
    lines.push('### Instructions:');
    lines.push('1. Remediate each vulnerability using secure coding practices (e.g. parameterized queries, safe execution APIs, strict validation/sanitization).');
    lines.push('2. Do not merely suppress or ignore the alert comments; fix the root cause.');
    lines.push('3. Preserve all existing business logic, types, and test compatibility.');
    lines.push('4. Provide the exact file path and code diff for each remediation.');
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## Summary');
    lines.push(`- **Total Findings**: ${count}`);
    lines.push(`- **Critical**: ${criticalCount} / **High**: ${highCount} / **Medium**: ${medCount} / **Low**: ${lowCount}`);
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## Findings Details');
    lines.push('');

    items.forEach((item, index) => {
      lines.push(`### [${index + 1}/${count}] [${item.severity}] ${item.ruleCode}`);
      lines.push(`- **File**: \`${item.relativePath}:${item.line}:${item.column}\``);
      if (item.cwe) lines.push(`- **CWE**: ${item.cwe}`);
      lines.push(`- **Message**: ${item.message}`);
      if (item.trace.length > 0) {
        lines.push('- **Taint Trace**:');
        item.trace.forEach((t) => lines.push(`  - ${t}`));
      }
      if (item.codeSnippet) {
        lines.push('');
        lines.push('**Code Context:**');
        lines.push(`\`\`\`${item.language}`);
        lines.push(item.codeSnippet);
        lines.push('\`\`\`');
      }
      if (item.recommendation) {
        lines.push(`- **Recommendation**: ${item.recommendation}`);
      }
      lines.push('');
      lines.push('---');
      lines.push('');
    });
  }

  return lines.join('\n');
}
