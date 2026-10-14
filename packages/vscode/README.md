# LLM Security Scanner

Python / TypeScript / JavaScript / PHP のコードを編集中に解析し、次の問題を波線で示します。

- **インジェクション（OWASP A05）**：SQL インジェクション、OS コマンド、コード実行（eval 等）、安全でないデシリアライズ、XSS、テンプレートインジェクション、ファイルインクルード
- **LLM の応答を危険な処理に渡すコード（OWASP LLM05 不適切な出力処理）**：OpenAI / Anthropic / Vercel AI SDK / LangChain 等の応答を SQL・eval・シェル・innerHTML に渡している箇所

すべてローカルで解析し、コードを外部に送信しません（信頼されていないワークスペースでも動作します）。

## 使い方

| 機能 | 操作 |
|---|---|
| 指摘の表示 | 対象言語のファイルを開くと自動で解析。問題パネルにも表示されます |
| 経路の確認 | 指摘の「関連情報」に「入力の出どころ → 代入 → 危険な処理」が並びます |
| 説明 | 指摘にカーソルを合わせると、危険な理由・安全な書き方・OWASP / CWE へのリンクを表示 |
| 抑制 | 電球メニュー「この箇所で抑制する」→ 挿入されたコメントの `TODO 理由を記入` を理由に書き換えます（理由のない抑制は無効） |
| 全体スキャン | コマンドパレット「LLM Security Scanner: ワークスペース全体をスキャン」 |
| 既存の指摘を除外 | 「LLM Security Scanner: 現在の指摘でベースラインを作成・更新」。以後は新しく増えた指摘だけを表示します |

## 設定

リポジトリ直下の `.llmscan.yml`（CLI と共通）：

```yaml
minConfidence: medium        # low | medium | high
failOn: high                 # CLI の失敗条件
baseline: .llmscan-baseline.json
exclude: ["**/tests/**"]
sanitizers:                  # 自作のエスケープ・検証関数（別ファイルで定義したもの）
  php: ["h"]
  python: ["app.security.escape_sql_identifier"]
```

VS Code の設定：`llmscan.enable` / `llmscan.minConfidence` / `llmscan.showBaselined`
