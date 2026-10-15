# LLMScan - AI Security Scanner

English | [日本語 (Japanese)](README.ja.md)

**Local Static Application Security Testing (SAST) for AI & Web Applications**

LLMScan is a high-performance local static security scanner and VS Code extension for **Python**, **TypeScript**, **JavaScript**, and **PHP**. It detects both traditional injection vulnerabilities (**OWASP Top 10**) and LLM-specific application threats (**OWASP LLM Top 10 - LLM05: Insecure Output Handling**).

All scans run **100% locally** using Tree-sitter WebAssembly parsers. **No code or telemetry is ever transmitted over the network.**

---

## 🌟 Key Features

- **Injection Vulnerability Detection (OWASP A05)**:
  Detects SQL Injection (raw queries & ORMs), OS Command Injection (`exec`, `spawn`, `shell=True`), Code Injection (`eval`, `new Function`), Insecure Deserialization (`pickle`, `yaml.unsafe_load`, `unserialize`), Cross-Site Scripting (XSS), Server-Side Template Injection (SSTI), and File Inclusion / Path Traversal.
- **OWASP LLM05 (Insecure Output Handling) & Agentic Security**:
  Traces data flow from LLM model outputs (OpenAI, Anthropic, Gemini, Ollama, LangChain, LlamaIndex, Vercel AI SDK) as well as AI agent tool calls (`tool_call.function.arguments`, `tool_input`) and **Model Context Protocol (MCP)** tool handlers (`request.params.arguments`) directly to dangerous sinks (such as dynamic execution, database queries, and raw HTML rendering).
- **Intelligent Taint & Sanitizer Algebra**:
  Recognizes safe validation barriers including **Zod** schema parsing, **Yup**, **Pydantic** validation, cryptographic hash digests (`hashlib`, `crypto.createHash`, `bin2hex`), and type coercions (`+x`, `Number()`, `int()`, `filter_var`).
- **Interactive VS Code Extension**:
  Includes a dedicated Activity Bar sidebar with severity badges, real-time squiggly diagnostics, detailed hovers, one-click QuickFix suppressions, and severity filters.
- **CI/CD & SARIF Integration**:
  Provides a standalone CLI that generates SARIF reports for native GitHub Code Scanning integration.
- **Baseline Support**:
  Create `.llmscan-baseline.json` to suppress existing technical debt and alert only on newly introduced security issues.

---

## 📁 Monorepo Structure

```
./
├── packages/core/     Analysis engine (Tree-sitter WASM + taint tracking). Independent of VS Code.
├── packages/cli/      CI CLI tool (outputs Text, JSON, and SARIF for GitHub Code Scanning).
├── packages/vscode/   VS Code Extension (Language Server Protocol + TreeView + Activity Bar).
└── scripts/           Build scripts and WASM distribution assets.
```

---

## 🚀 Quick Start

```bash
npm install          # Install dependencies (WASM grammar only, ignore-scripts=true)
npm test             # Run test suite across Core, CLI, and Language Server
npm run typecheck    # Strict TypeScript verification
npm run build        # Build packages/cli/dist and packages/vscode/dist
```

---

## 💻 VS Code Extension

Package and install the extension locally:

```bash
npm run package:extension
code --install-extension packages/vscode/llm-security-scan-1.2.0.vsix
```

See [packages/vscode/README.md](packages/vscode/README.md) for full extension documentation.

---

## 🛠️ CLI Usage (CI / GitHub Actions)

```bash
node packages/cli/dist/cli.js scan [paths...] [--format text|json|sarif] [--output file]
                                   [--baseline file | --no-baseline | --update-baseline]
                                   [--min-confidence low|medium|high] [--fail-on low|medium|high|critical|none]
```

- **Exit Codes**: `0` Clean / `1` Vulnerabilities meeting or exceeding `failOn` found outside baseline / `2` Execution error
- The `dist/` bundle includes all dependencies and WebAssembly grammars, requiring only Node.js 18+.

### GitHub Actions Workflow Example

```yaml
- run: npm ci && npm run build
- run: node packages/cli/dist/cli.js scan --format sarif --output llmscan.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: llmscan.sarif
```

---

## 🛡️ Detection Rules

| Rule ID | Category | Default Severity | Description |
|---|---|---|---|
| `{PY,JS,PHP}-SQLI-001` | SQL Injection | High | Unsanitized input embedded in SQL query string or raw ORM call |
| `{PY,JS,PHP}-CMDI-001` | OS Command Injection | Critical | Command execution via shell (`exec`, `spawn`, `shell=True`) |
| `{PY,JS,PHP}-CODEI-001` | Code Injection | Critical | Dynamic code execution (`eval`, `new Function`, `setTimeout`) |
| `{PY,JS,PHP}-DESER-001` | Insecure Deserialization | High | Untrusted deserialization (`pickle`, `unserialize`, `yaml.load`) |
| `{PY,JS}-SSTI-001` | Template Injection | High | Dynamic template construction from external input |
| `{PY,JS,PHP}-XSS-001` | Cross-Site Scripting | Medium | Unescaped HTML rendering (`innerHTML`, `dangerouslySetInnerHTML`) |
| `PHP-FILEINC-001` | File Inclusion | High | Dynamic path used in `include` / `require` |
| `LLM05-*-001` | **OWASP LLM05** | Critical / High | LLM output flowing directly to dangerous sink |
| `LLMSCAN-SUPPRESS-001` | Invalid Suppression | Low | Suppression comment without reason |

---

## 🔒 Privacy & Security

LLMScan parses code strictly on your local machine using Tree-sitter WebAssembly. **No code, file names, or telemetry data are ever uploaded or transmitted.**

---

## 📄 License

UNLICENSED
