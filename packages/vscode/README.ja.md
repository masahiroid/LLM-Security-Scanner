# LLMScan - AI Security Scanner

[English](README.md) | 日本語

**AI & Web アプリケーション向け ローカル静的セキュリティ検査ツール**

LLMScan は、**Python**、**TypeScript**、**JavaScript**、**PHP** のコードを編集中にリアルタイム解析し、外部入力や LLM の応答が危険な処理へ到達する経路を波線で検出する VS Code 拡張機能です。

従来のインジェクション脆弱性（**OWASP Top 10**）に加え、LLM 固有のセキュリティ問題（**OWASP LLM Top 10 - LLM05: 不適切な出力処理**）を検出します。

解析はすべて手元のマシン上で完結（Tree-sitter WebAssembly 利用）し、**コードを外部サーバーへ一切送信しません**。信頼されていないワークスペースや社内閉域網でも安全に動作します。

---

## 🌟 主な機能

- **インジェクション脆弱性検出 (OWASP A05)**:
  SQL インジェクション（生クエリ・各種 ORM）、OS コマンドインジェクション（`exec`, `spawn`, `shell=True`）、コード実行（`eval`, `new Function`）、安全でないデシリアライズ（`pickle`, `unserialize`, `yaml.unsafe_load`）、XSS、テンプレートインジェクション（SSTI）、ファイルインクルード（パストラバーサル）。
- **OWASP LLM05（不適切な出力処理）& Agentic セキュリティの追跡**:
  OpenAI、Anthropic、Gemini、Ollama、LangChain、LlamaIndex、Vercel AI SDK 等の応答に加え、AI エージェントのツール呼び出し引数（`tool_call.function.arguments`, `tool_input`）や **Model Context Protocol (MCP)** のツール引数（`request.params.arguments`）を SQL・eval・シェル・innerHTML に渡している危険な箇所を特定。
- **サイドバー・アクティビティバー連携**:
  専用のアクティビティバーアイコン（`llm.svg`）、指摘件数バッジ、重要度別のアイコン表示、行単位のジャンプ、高重大度（High / Critical）のみを絞り込むフィルターボタンを搭載。
- **高精度な無害化判定**:
  Zod、Yup、Pydantic によるスキーマ検証、暗号学的ハッシュ（`hashlib`, `crypto.createHash`, `bin2hex`）、単項数値変換（`+x`, `Number()`, `int()`, `filter_var`）などを安全と自動判定。
- **充実したホバー解説 & クイックフィックス**:
  波線にカーソルを合わせると、危険な理由・安全な書き方・OWASP / CWE リンクを表示。電球メニューから 1 クリックで理由付きの抑制コメントを挿入可能。
- **ベースライン対応**:
  `.llmscan-baseline.json` を作成することで既存の指摘を除外し、今後新しく混入した指摘だけを通知。

---

## 📖 使い方

| 機能 | 操作 |
|---|---|
| **リアルタイム診断** | 対象言語のファイルを開くと自動で解析。問題パネルやエディタ内に波線表示されます。 |
| **経路の確認** | 指摘の「関連情報」に「入力の出どころ → 代入 → 危険な処理」の全ステップが表示されます。 |
| **詳細解説** | 波線にカーソルを合わせると、危険な理由・安全な書き方・CWE リンクを表示します。 |
| **抑制コメント** | 電球メニュー「この箇所で抑制する」をクリックし、挿入されたコメントに理由を記入します。 |
| **全体スキャン** | コマンドパレットまたはサイドバーから「LLMScan: ワークスペース全体をスキャン」を実行。 |
| **既存指摘の除外** | 「LLMScan: 現在の指摘でベースラインを作成・更新」で以後は新規指摘のみを表示。 |

---

## ⚙️ 設定

リポジトリ直下の `.llmscan.yml`（CLI と共通）または VS Code の設定（`settings.json`）で変更可能です：

```yaml
# .llmscan.yml
minConfidence: medium        # low | medium | high
failOn: high                 # CLI の失敗条件
baseline: .llmscan-baseline.json
exclude:
  - "**/tests/**"
  - "**/generated/**"
sanitizers:                  # 自作のエスケープ・検証関数（別ファイルで定義したもの）
  javascript: ["mySanitizer"]
  python: ["app.security.sanitize_query"]
  php: ["clean_input"]
```

### VS Code 設定項目
- `llmscan.enable`: LLMScan によるセキュリティ検査を有効にする（既定: `true`）
- `llmscan.minConfidence`: 表示する指摘の確信度の下限（`low`, `medium`, `high`）
- `llmscan.showBaselined`: ベースラインに登録済みの既存の指摘も表示する（既定: `false`）

---

## 🛡️ 検出ルール一覧

| ルール ID | カテゴリ | 重大度 |
|---|---|---|
| `{PY,JS,PHP}-SQLI-001` | SQL インジェクション | High |
| `{PY,JS,PHP}-CMDI-001` | OS コマンドインジェクション | Critical |
| `{PY,JS,PHP}-CODEI-001` | コード実行 (`eval` / `new Function`) | Critical |
| `{PY,JS,PHP}-DESER-001` | 安全でないデシリアライズ (`pickle`, `unserialize`) | High |
| `{PY,JS}-SSTI-001` | テンプレートインジェクション | High |
| `{PY,JS,PHP}-XSS-001` | クロスサイトスクリプティング (`innerHTML`, `echo`) | Medium |
| `PHP-FILEINC-001` | ファイルインクルード (`include`, `require`) | High |
| `LLM05-*-001` | **OWASP LLM05** 不適切な出力処理 | Critical / High |
| `LLMSCAN-SUPPRESS-001` | 理由のない抑制コメント | Low |

---

## 🔒 プライバシー保護

LLMScan は手元で Tree-sitter WebAssembly によりローカル完結でコードを解析します。**ソースコードやファイル名などの外部送信は一切行いません。**

