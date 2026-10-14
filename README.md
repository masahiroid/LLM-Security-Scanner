# LLM Security Scanner

インジェクションと、LLM を使うアプリ特有の危険なコードを検出する VS Code 拡張・CLI です。
Python / TypeScript / JavaScript / PHP のコードを静的解析し、外部入力や LLM の応答が危険な処理に届く経路を検出します。
解析はローカルで完結し、コードを外部に送信しません。

設計と今後の計画は [docs/design.md](docs/design.md) を参照してください（現在は段階 1（MVP）まで実装済み）。
コマンド名・設定ファイル・抑制コメントには短い名前 `llmscan` を使います（`llmscan scan`、`.llmscan.yml`、`llmscan-ignore`）。

```
./
├── packages/core/     解析エンジン（tree-sitter + 関数内の汚染追跡）。VS Code に依存しない
├── packages/cli/      CI 用 CLI（text / json / SARIF 出力、ベースライン）
├── packages/vscode/   VS Code 拡張（Language Server + 薄いクライアント）
└── scripts/           ビルド共通処理（WASM の同梱など）
```

## セットアップ

```bash
npm install          # .npmrc で ignore-scripts=true（文法は WASM 版のみ使うため、ネイティブビルドをしない）
npm test             # 単体テスト・フィクスチャ・CLI・Language Server の結合テスト
npm run typecheck
npm run build        # packages/cli/dist と packages/vscode/dist を生成
```

## VS Code 拡張

```bash
npm run package -w llm-security-scanner      # packages/vscode/llm-security-scanner-0.1.0.vsix を生成
code --install-extension packages/vscode/llm-security-scanner-0.1.0.vsix
```

開発中は VS Code で `packages/vscode` を開き、`npm run build` 後に F5（拡張機能の開発ホスト）で起動できます。
機能の詳細は [packages/vscode/README.md](packages/vscode/README.md) を参照してください。

## CLI

```bash
node packages/cli/dist/cli.js scan [パス...] [--format text|json|sarif] [--output file]
                                   [--baseline file | --no-baseline | --update-baseline]
                                   [--min-confidence low|medium|high] [--fail-on low|medium|high|critical|none]
```

- 終了コード：`0` 問題なし / `1` ベースライン外に `failOn` 以上の指摘あり / `2` 実行エラー
- `dist/` は依存を同梱した単体ファイル＋WASM なので、`dist` ごとコピーすれば Node.js 18 以上で動きます

例：別のプロジェクトを解析する

```bash
node packages/cli/dist/cli.js scan --root ~/src/my-app --no-baseline
```

### GitHub Actions（Code Scanning に表示する例）

```yaml
# スキャナーを llm-security-scanner/ に checkout した場合
- run: npm ci && npm run build
  working-directory: llm-security-scanner
- run: node llm-security-scanner/packages/cli/dist/cli.js scan --format sarif --output llmscan.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: llmscan.sarif
```

## 検出ルール

| ルール ID | 内容 | 重大度（既定） |
|---|---|---|
| `{PY,JS,PHP}-SQLI-001` | SQL インジェクション | high |
| `{PY,JS,PHP}-CMDI-001` | OS コマンドインジェクション | critical |
| `{PY,JS,PHP}-CODEI-001` | コード実行（eval / exec / new Function 等） | critical |
| `{PY,JS,PHP}-DESER-001` | 安全でないデシリアライズ（pickle / yaml.load / unserialize 等） | high |
| `{PY,JS}-SSTI-001` | テンプレートインジェクション（render_template_string 等） | high |
| `{PY,JS,PHP}-XSS-001` | XSS（innerHTML / dangerouslySetInnerHTML / Markup / echo 等） | medium |
| `PHP-FILEINC-001` | ファイルインクルード（include / require） | high |
| `LLM05-*-001` | **LLM の応答**が上記の危険な処理に届く（OWASP LLM05） | critical（XSS は high） |
| `LLMSCAN-SUPPRESS-001` | 理由のない抑制コメント | low |

### 確信度

| 確信度 | 条件 |
|---|---|
| high | 入力の出どころ（`request.args`、`$_GET`、`req.query`、LLM の応答など）から危険な処理まで経路が確定 |
| medium | 途中で無害化の有無が分からない関数を経由した／関数の引数を文字列連結して SQL・コマンド等を組み立てている |
| low | 関数の引数をそのまま渡しているだけ／引数から HTML を組み立てている |

既定では medium 以上を表示します（`.llmscan.yml` の `minConfidence`）。

### 誤検知を減らす仕組み

- **無害化関数**：`int()` / `intval()` / `(int)` / `htmlspecialchars` / `shlex.quote` / `escapeshellarg` / DOMPurify 等を通った値は、その種類の危険な処理に対して安全とみなします
- **同じファイル内の関数の要約**：自作のエスケープ関数（`function h($s) { return htmlspecialchars(...); }`）や、入力を取得して返す関数を自動で判定します
- **許可リストの判定**：`in_array($x, LIST, true) ? $x : 既定値` / `x if x in ALLOWED else ...` / `LIST.includes(x) ? x : ...`
- **安全な API**：プレースホルダ付きクエリ、タグ付きテンプレート（`sql\`...\``、Prisma の `$queryRaw\`...\``）、`subprocess.run([...])`（`shell=True` なし）、`yaml.safe_load` など
- **別ファイルの自作関数**：`.llmscan.yml` の `sanitizers` に登録します

### 制限（今後の段階で対応）

- 解析は**ファイル単位**です。別ファイルで定義した関数の中身は追跡しません（段階 4：ファイルをまたぐ解析）
- 分岐ごとの区別はせず、コードの上から順に追跡します（`if` の中で検証している場合などは誤検知になり得ます）
- LLM による誤検知判定・修正案（段階 2）、LLM01 / 06 / 07 / 10 等の LLM 固有ルール（段階 3）は未実装です

## ルールの追加

言語ごとの定義は `packages/core/src/languages/{python,javascript,php}.ts` にあります。

- `sourceForPath` / `sourceForCall`：入力の出どころ（ユーザー入力・LLM の応答）
- `sinkForCall`：危険な処理と検査する引数
- `sanitizerForCall`：無害化関数
- `propagator`：汚染をそのまま伝える関数（文字列操作など）

追加したら `packages/core/test/fixtures/` のフィクスチャに、検出すべき行（`expect: ルールID` コメント付き）と検出してはいけない安全な書き方の両方を加えてください。
# LLM-Security-Scanner
