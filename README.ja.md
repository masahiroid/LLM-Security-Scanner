# LLMScan - AI Security Scanner

[![Visual Studio Marketplace](https://vsmarketplacebadges.dev/version/masahirocom.llm-security-scan.svg)](https://marketplace.visualstudio.com/items?itemName=masahirocom.llm-security-scan)
[![Downloads](https://vsmarketplacebadges.dev/downloads/masahirocom.llm-security-scan.svg)](https://marketplace.visualstudio.com/items?itemName=masahirocom.llm-security-scan)
[![Rating](https://vsmarketplacebadges.dev/rating-star/masahirocom.llm-security-scan.svg)](https://marketplace.visualstudio.com/items?itemName=masahirocom.llm-security-scan)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

[English](README.md) | 日本語

**AI & Web アプリケーション向け ローカル静的セキュリティ検査ツール**

LLMScan は、**Python** / **TypeScript** / **JavaScript** / **PHP** のソースコードをローカルで静的解析し、外部入力や LLM の応答が危険な処理へ到達する経路をリアルタイムに検出する VS Code 拡張機能および CI 用 CLI ツールです。

従来の Web 脆弱性（**OWASP Top 10**）に加え、LLM アプリ特有のセキュリティ脅威（**OWASP LLM Top 10 - LLM05: 不適切な出力処理**）を検出します。

通常の静的解析は手元のマシン上で完結（Tree-sitter WASM 利用）し、テレメトリを送信しません。任意の AI トリアージは、送信内容を確認・承認した場合だけマスク済みコード片を指定先へ送信します（下記参照）。


## 任意の AI トリアージ — v2.0.0

通常の静的解析はローカルで完結し、API キーは不要です。AI トリアージは設定するまで無効で、信頼済みワークスペースで指摘ごとに手動実行した場合だけ通信します。CLI は AI を使用しません。

1. **LLMScan: AI トリアージ設定（API キー / プロバイダ）** を実行します。OpenAI / Anthropic / Ollama を選び、契約・サーバーで利用できるモデル ID と完全な API URL を指定します。クラウドは HTTPS、ローカル Ollama は `http://127.0.0.1:11434/api/chat` が利用できます。OpenAI は Chat Completions JSON API、Anthropic は Messages、Ollama はネイティブ Chat に対応します。利用可能なモデルと料金はプロバイダに依存します。
2. API キーは VS Code の SecretStorage、プロバイダ・モデル・URL はリポジトリ設定から独立した拡張のグローバル状態に保存します。削除する場合は設定コマンドから **設定・キーを削除** を選びます。
3. サイドバーの指摘を右クリックし、**AI で指摘を精査・修正案をプレビュー** を選びます。送信先とマスク済み内容を確認して送信します。対象関数内の前後最大8行の短いコード片、指摘、経路メッセージのみを送信し、トップレベルでは対象行のみに制限します。ファイルパスのメタデータは含めません。既知のキー・認証情報代入・Bearer トークン・秘密鍵を可能な範囲でマスクしますが、完全ではありません。秘密情報が残っていないことを確認してください。プレビューの編集は送信内容に反映されないため、変更時はキャンセルして元コードを編集してください。
4. 判定（`true_positive`: 真の脆弱性、`false_positive`: 誤検知、`needs_review`: 要確認）と理由を確認します。修正案は Diff エディタで確認し、**修正案を適用** を選んだ場合だけ編集します。自動保存・実行はしません。元ファイルが変更されている場合は適用を拒否するため、再実行してください。対象行に秘密情報がマスクされた場合は、実際の認証情報をプレースホルダで上書きしないよう修正案の適用を提供しません。

AI の判定・修正は誤りやコード中の指示による影響を含む可能性があります。指摘・ベースラインは AI 判定によって自動変更・抑制しません。修正は必ずレビュー・再テストしてください。通信は30秒でタイムアウトします。認証・レート制限・API 障害時に元ファイルは変更しません。URL・モデル・キーを確認して再試行してください。ローカル運用ではローカル Ollama モデルとループバック URL を選択してください。外部エンドポイントへの送信データの扱いは各プロバイダの規約に従います。

---

## 🌟 主な特徴

- **インジェクション脆弱性検出 (OWASP A05)**:
  SQL インジェクション（生クエリおよび ORM）、OS コマンドインジェクション（`exec`, `spawn`, `shell=True`）、コードインジェクション（`eval`, `new Function`）、安全でないデシリアライズ（`pickle`, `yaml.unsafe_load`, `unserialize`）、クロスサイトスクリプティング（XSS）、サーバーサイドテンプレートインジェクション（SSTI）、ファイルインクルード（パストラバーサル）を検出。
- **OWASP LLM05（不適切な出力処理）& Agentic セキュリティの追跡**:
  OpenAI, Anthropic, Gemini, Ollama, LangChain, LlamaIndex, Vercel AI SDK などの LLM 応答に加え、AI エージェントのツール呼び出し引数（`tool_call.function.arguments`, `tool_input`）や **Model Context Protocol (MCP)** のツール引数（`request.params.arguments`）が出力シンク（SQL、eval、シェル、innerHTML 等）へ渡る危険な経路を自動検出。
- **高精度な無害化判定（誤検知防止）**:
  **Zod** スキーマ検証、**Yup**、**Pydantic**、暗号学的ハッシュ（`hashlib`, `crypto.createHash`, `bin2hex`）、単項数値変換（`+x`, `Number()`, `int()`, `filter_var`）などを安全と自動判定。
- **カスタムルール定義 (`.llmscan.yml`)**:
  プロジェクト固有の汚染源（`sources`）、危険なシンク（`sinks`）、無害化関数（`sanitizers`）を `.llmscan.yml` で言語別に自由に追加可能。
- **クロスファイル（複数ファイル間）汚染追跡 (`ProjectIndex`)**:
  ワークスペース内の各ファイルで定義された関数の要約（汚染源・無害化関数・危険なシンクラッパー）を自動インデックス化し、別ファイルのヘルパー関数を経由する `Source -> Cross-File Helper -> Sink` の経路も高精度に追跡。
- **インタラクティブな VS Code 拡張機能・データフローグラフ & 1クリック自動修正**:
  専用のアクティビティバーアイコン、重要度バッジ、視覚的なフローチャートで経路を確認しクリックで該当行へジャンプできる**データフローグラフパネル**、リアルタイム波線診断、1クリックでの安全なコードへの自動書き換え（`shell=False`、`ast.literal_eval`、`yaml.safe_load`、`textContent` 等）や抑制コメント挿入、AI修正プロンプト出力を完備。
- **CI/CD・差分スキャン & SARIF 連携**:
  Git の変更差分のみを高速検査する `--changed-only` / `--diff-base <ref>` オプションや、GitHub Code Scanning でそのまま可視化できる SARIF 出力に対応した CLI を同梱。
- **ベースライン機能**:
  既存コードの指摘を `.llmscan-baseline.json` に記録し、新規混入した脆弱性のみを通知・CI 失敗条件に設定可能。

---

## 📁 モノレポ構造

```
./
├── packages/core/     解析エンジン（Tree-sitter WASM + クロスファイル汚染追跡）。VS Code に依存しない
├── packages/cli/      CI 用 CLI（text / json / SARIF 出力、ベースライン、差分スキャン）
├── packages/vscode/   VS Code 拡張機能（Language Server + TreeView + データフローグラフ）
└── scripts/           ビルド共通処理（WASM の同梱など）
```

---

## 🚀 セットアップ

```bash
npm install          # 依存関係のインストール（WASM 版文法のみ使用、ignore-scripts=true）
npm test             # 単体テスト・フィクスチャ・CLI・Language Server のテスト実行
npm run typecheck    # 厳格な TypeScript 型チェック
npm run build        # 全パッケージのビルド
```

---

## 💻 VS Code 拡張機能

ローカルでのパッケージングとインストール：

```bash
npm run package:extension
code --install-extension packages/vscode/llm-security-scan-1.6.0.vsix
```

詳細な機能や画面操作については [packages/vscode/README.ja.md](packages/vscode/README.ja.md) をご覧ください。

---

## 🛠️ CLI の使い方（CI / GitHub Actions）

```bash
node packages/cli/dist/cli.js scan [パス...] [--format text|json|sarif] [--output ファイル]
                                   [--changed-only | --diff-base <ref>]
                                   [--baseline ファイル | --no-baseline | --update-baseline]
                                   [--min-confidence low|medium|high] [--fail-on low|medium|high|critical|none]
```

- **終了コード**：`0` 問題なし / `1` ベースライン外に `failOn` 以上の指摘あり / `2` 実行エラー
- **差分スキャン**：`--changed-only`（`HEAD` との差分）や `--diff-base origin/main` を指定すると、変更されたファイルのみを高速にスキャンできます。
- `dist/` は依存を同梱した単体ファイル＋WASM なので、Node.js 18 以上があればどこでも動作します。

### GitHub Actions ワークフロー設定例

```yaml
- run: npm ci && npm run build
- run: node packages/cli/dist/cli.js scan --diff-base origin/main --format sarif --output llmscan.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: llmscan.sarif
```

---

## 🛡️ 検出ルール一覧

| ルール ID | カテゴリ | 既定の重大度 | 内容 |
|---|---|---|---|
| `{PY,JS,PHP}-SQLI-001` | SQL インジェクション | High | SQL 文文字列への生連結・安全でない ORM 呼び出し |
| `{PY,JS,PHP}-CMDI-001` | OS コマンドインジェクション | Critical | シェル経由の外部コマンド実行（`exec`, `spawn`, `shell=True`） |
| `{PY,JS,PHP}-CODEI-001` | コードインジェクション | Critical | 動的コード実行（`eval`, `new Function`, `setTimeout`） |
| `{PY,JS,PHP}-DESER-001` | 安全でないデシリアライズ | High | 任意コード実行につながる復元（`pickle`, `unserialize`, `yaml.load`） |
| `{PY,JS}-SSTI-001` | テンプレートインジェクション | High | 外部値からの動的テンプレート生成 |
| `{PY,JS,PHP}-XSS-001` | クロスサイトスクリプティング | Medium | エスケープなしでの HTML 出力（`innerHTML`, `dangerouslySetInnerHTML`） |
| `PHP-FILEINC-001` | ファイルインクルード | High | 動的パスによる `include` / `require` |
| `{PY,JS,PHP}-SSRF-001` | SSRF（サーバーサイドリクエストフォージェリ） | High | 外部入力や LLM 出力による送信先 URL の制御 |
| `{PY,JS,PHP}-PATH-001` | パストラバーサル | High | 外部入力によるファイル読み書き・削除パスの制御 |
| `LLM01-PROMPTI-001` | **OWASP LLM01** | High | 信頼できない外部入力のシステムプロンプト（`system` / `developer`）への直接結合 |
| `LLM02-SECRET-001` | **OWASP LLM02** | High | ソースコード内にハードコードされた API キー・機密トークン |
| `LLM05-*-001` | **OWASP LLM05** | Critical / High | LLM の応答が危険な処理へ到達（不適切な出力処理） |
| `LLMSCAN-SUPPRESS-001` | 理由のない抑制 | Low | 理由の明記がない抑制コメント |

---

## 🔒 プライバシー保護

LLMScan は手元の環境内で Tree-sitter WebAssembly によりローカル完結でコードを解析します。**ソースコード、ファイル名、利用状況などの外部送信は一切行いません。**

---

## 📄 ライセンス

[Apache License 2.0](LICENSE)

