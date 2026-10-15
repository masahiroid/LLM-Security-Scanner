import type { Family } from './languages/spec';
import type { OriginKind, Severity, SinkKind } from './types';

export interface KindMeta {
  code: string;
  title: string;
  titleEn: string;
  cwe: string;
  baseSeverity: Severity;
  /** 危険な理由 (日本語) */
  why: string;
  /** 危険な理由 (英語) */
  whyEn: string;
  /** 言語別の安全な書き方 (日本語) */
  fix: Record<Family, string>;
  /** 言語別の安全な書き方 (英語) */
  fixEn: Record<Family, string>;
}

export const KIND_META: Record<SinkKind, KindMeta> = {
  sqli: {
    code: 'SQLI',
    title: 'SQL インジェクション',
    titleEn: 'SQL Injection',
    cwe: 'CWE-89',
    baseSeverity: 'high',
    why: '外部から来た値が SQL 文の一部として解釈され、条件の改ざん・データの窃取・削除が可能になります。',
    whyEn: 'Untrusted input is interpreted as part of a SQL query, allowing query alteration, authentication bypass, or unauthorized data access.',
    fix: {
      python: 'プレースホルダを使い、値は別引数で渡します: `cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))`',
      javascript: 'プレースホルダ付きのクエリにします: `db.query("SELECT * FROM users WHERE id = ?", [id])`。Prisma なら `$queryRaw` のタグ付きテンプレートを使います。',
      php: 'プリペアドステートメントを使います: `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);`',
    },
    fixEn: {
      python: 'Use placeholders and pass values separately: `cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))`',
      javascript: 'Use parameterized queries: `db.query("SELECT * FROM users WHERE id = ?", [id])`. In Prisma, use `$queryRaw` tagged templates.',
      php: 'Use prepared statements: `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);`',
    },
  },
  cmdi: {
    code: 'CMDI',
    title: 'OS コマンドインジェクション',
    titleEn: 'OS Command Injection',
    cwe: 'CWE-78',
    baseSeverity: 'critical',
    why: 'シェルを経由してコマンドを組み立てると、`;` や `$( )` で任意のコマンドを実行されます。',
    whyEn: 'Constructing shell commands with untrusted input permits arbitrary command execution via operators such as ; or $( ).',
    fix: {
      python: '`shell=True` をやめ、引数をリストで渡します: `subprocess.run(["convert", path], check=True)`',
      javascript: '`exec` をやめ、`execFile` / `spawn` に引数を配列で渡します（`shell: true` は指定しない）。',
      php: 'できるだけ PHP の関数で代替し、やむを得ない場合は各引数を `escapeshellarg()` で囲みます。',
    },
    fixEn: {
      python: 'Avoid `shell=True` and pass arguments as a list: `subprocess.run(["convert", path], check=True)`',
      javascript: 'Avoid `exec`. Use `execFile` or `spawn` with an argument array without `shell: true`.',
      php: 'Use native PHP functions when possible, or wrap each argument with `escapeshellarg()`.',
    },
  },
  codei: {
    code: 'CODEI',
    title: 'コードインジェクション',
    titleEn: 'Code Injection',
    cwe: 'CWE-94',
    baseSeverity: 'critical',
    why: '文字列をコードとして実行するため、外部の値が混ざると任意のコードを実行されます。',
    whyEn: 'Executing dynamic code containing external input permits execution of arbitrary instructions in application context.',
    fix: {
      python: '`eval` / `exec` を使わない設計にします。値の解析なら `ast.literal_eval` や `json.loads` を使います。',
      javascript: '`eval` / `new Function` / 文字列を渡す `setTimeout` を使わない設計にします。値の解析なら `JSON.parse` を使います。',
      php: '`eval` / `assert(文字列)` / `create_function` を使わない設計にします。',
    },
    fixEn: {
      python: 'Avoid `eval` and `exec`. For data parsing, use `ast.literal_eval` or `json.loads`.',
      javascript: 'Avoid `eval`, `new Function`, or string `setTimeout`. Use `JSON.parse` for data.',
      php: 'Avoid `eval`, string `assert()`, or `create_function()`.',
    },
  },
  deser: {
    code: 'DESER',
    title: '安全でないデシリアライズ',
    titleEn: 'Insecure Deserialization',
    cwe: 'CWE-502',
    baseSeverity: 'high',
    why: 'pickle / unserialize 等は復元時にオブジェクトのコードが動くため、外部データを渡すと任意コード実行につながります。',
    whyEn: 'Deserializers like pickle or unserialize execute object code during reconstruction, leading to arbitrary code execution if untrusted.',
    fix: {
      python: 'JSON 等のデータ専用形式に置き換えます。YAML は `yaml.safe_load`、PyTorch は `torch.load(..., weights_only=True)` を使います。',
      javascript: 'JSON.parse 等のデータ専用の形式に置き換えます。',
      php: '`json_decode` に置き換えます。やむを得ない場合は `unserialize($x, ["allowed_classes" => false])` とします。',
    },
    fixEn: {
      python: 'Use safe data formats such as JSON. For YAML use `yaml.safe_load`; for PyTorch use `torch.load(..., weights_only=True)`.',
      javascript: 'Use data-only formats such as `JSON.parse`.',
      php: 'Use `json_decode`. If `unserialize` is required, specify `["allowed_classes" => false]`.',
    },
  },
  xss: {
    code: 'XSS',
    title: 'クロスサイトスクリプティング（XSS）',
    titleEn: 'Cross-Site Scripting (XSS)',
    cwe: 'CWE-79',
    baseSeverity: 'medium',
    why: 'エスケープせずに HTML として出力すると、利用者のブラウザで任意のスクリプトが動きます。',
    whyEn: 'Emitting unescaped input to HTML allows arbitrary script execution in victim browsers.',
    fix: {
      python: 'テンプレートの自動エスケープに任せ、`Markup` / `mark_safe` / `|safe` で無効化しないでください。',
      javascript: '`textContent` を使うか、HTML が必要なら DOMPurify 等で無害化します。React では `dangerouslySetInnerHTML` を避けます。',
      php: '出力時に `htmlspecialchars($v, ENT_QUOTES, "UTF-8")` でエスケープします。',
    },
    fixEn: {
      python: 'Rely on template auto-escaping. Do not disable it with `Markup`, `mark_safe`, or `|safe`.',
      javascript: 'Use `textContent`, or sanitize with DOMPurify before inserting. In React, avoid `dangerouslySetInnerHTML`.',
      php: 'Escape output with `htmlspecialchars($v, ENT_QUOTES, "UTF-8")`.',
    },
  },
  ssti: {
    code: 'SSTI',
    title: 'サーバーサイドテンプレートインジェクション',
    titleEn: 'Server-Side Template Injection (SSTI)',
    cwe: 'CWE-1336',
    baseSeverity: 'high',
    why: 'テンプレートそのものを外部の値から作ると、テンプレート構文経由でサーバー上のコードを実行されます。',
    whyEn: 'Generating templates dynamically from external values enables attackers to run server-side code through template engine expressions.',
    fix: {
      python: 'テンプレートは固定のファイル（`render_template`）にし、外部の値は変数として渡します。',
      javascript: 'テンプレートは固定にし、外部の値はレンダリング時のデータとして渡します。',
      php: 'テンプレートは固定にし、外部の値は変数として渡します。',
    },
    fixEn: {
      python: 'Keep templates in static files (`render_template`) and pass external values as variables.',
      javascript: 'Use static template files and pass external values as render context data.',
      php: 'Use static template files and pass external values as view parameters.',
    },
  },
  fileinc: {
    code: 'FILEINC',
    title: 'ファイルインクルード',
    titleEn: 'File Inclusion',
    cwe: 'CWE-98',
    baseSeverity: 'high',
    why: '外部の値で読み込むファイルを決めると、任意のファイルの読み込みやコード実行につながります。',
    whyEn: 'Allowing external input to dictate file inclusion paths enables reading arbitrary sensitive files or executing unintended code.',
    fix: {
      python: '読み込むファイルは許可リストから選びます。',
      javascript: '読み込むファイルは許可リストから選びます。',
      php: '`include` するファイルは許可リスト（配列のキー照合など）から選び、外部の値を直接パスに使わないでください。',
    },
    fixEn: {
      python: 'Select files to include from a strict allowlist.',
      javascript: 'Select files to include from a strict allowlist.',
      php: 'Select included files from a hardcoded allowlist (array lookup) and never use raw input in file paths.',
    },
  },
};

export { SEVERITY_ORDER, SUPPRESSION_RULE_ID } from './constants';

export function severityFor(kind: SinkKind, origin: OriginKind): Severity {
  const base = KIND_META[kind].baseSeverity;
  if (origin !== 'llm') return base;
  // LLM05: LLM の出力を危険な処理に渡すのは、プロンプトインジェクション経由で外部から操作できるため一段重くする
  return kind === 'xss' ? 'high' : 'critical';
}

export function ruleIdFor(kind: SinkKind, origin: OriginKind, prefix: string): string {
  const code = KIND_META[kind].code;
  return origin === 'llm' ? `LLM05-${code}-001` : `${prefix}-${code}-001`;
}

export const OWASP_A05 = { id: 'A05:2025', title: 'インジェクション', url: 'https://owasp.org/Top10/' };
export const OWASP_LLM05 = {
  id: 'LLM05:2025',
  title: '不適切な出力処理（Improper Output Handling）',
  url: 'https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/',
};
