# LLMScan - AI Security Scanner

English | [日本語 (Japanese)](README.ja.md)

**Local Static Application Security Testing (SAST) for AI & Web Applications**

LLMScan analyzes **Python**, **TypeScript**, **JavaScript**, and **PHP** source code in real time as you edit. It traces data flow from untrusted sources to dangerous sinks, detecting both traditional web vulnerabilities (**OWASP Top 10**) and LLM-specific security threats (**OWASP LLM Top 10 - LLM05: Insecure Output Handling**).

All scans run **100% locally** inside your editor using Tree-sitter WebAssembly. **Zero code is sent to external servers**, making it fully safe for proprietary codebases and untrusted workspaces.

---

## 🌟 Key Features

- **Injection Vulnerability Detection (OWASP A05)**:
  SQL Injection (Raw ORM & parameterized queries), Command Injection (`exec`, `spawn`, `shell=True`), Code Injection (`eval`, `new Function`), Insecure Deserialization (`pickle`, `unserialize`, `yaml.unsafe_load`), Cross-Site Scripting (XSS), Server-Side Template Injection (SSTI), and Path Traversal / File Inclusion.
- **OWASP LLM05 (Insecure Output Handling) & Agentic Security**:
  Tracks responses from OpenAI, Anthropic, Gemini, Ollama, LangChain, LlamaIndex, and Vercel AI SDK, as well as AI Agent tool calls (`tool_call.function.arguments`, `tool_input`) and **Model Context Protocol (MCP)** tool handlers (`request.params.arguments`) directly to dangerous sinks (`innerHTML`, `sqlite3.execute`, `subprocess.run`, `eval`).
- **Interactive Tree View & Activity Bar**:
  Dedicated Activity Bar icon (`llm.svg`) and sidebar view with severity badges, line-by-line navigation, and a quick toggle filter for High/Critical issues.
- **Intelligent Taint Tracking & Sanitizers**:
  Built-in understanding of safe sanitizers: Zod schema validation, Yup, Pydantic, cryptographic hash digests (`hashlib`, `crypto.createHash`, `bin2hex`), and type coercion (`+x`, `Number()`, `int()`, `filter_var`).
- **Actionable Hovers & QuickFix**:
  Hover over any wavy line to see the vulnerability explanation, language-specific remediation examples, complete taint propagation trace, and OWASP/CWE references. Insert reason-enforced suppression comments with one click (`QuickFix`).
- **Baseline Support**:
  Create `.llmscan-baseline.json` to suppress legacy technical debt and only alert on newly introduced vulnerabilities.

---

## 📖 Usage

| Feature | Action |
|---|---|
| **Real-time Diagnostics** | Automatically scans active files and highlights vulnerabilities in the Problems panel and editor squiggly lines. |
| **Dataflow Trace** | Under "Related Information", view the complete path: `Source -> Assignment -> Sink`. |
| **Detailed Explanation** | Hover over findings to view why it is dangerous, safe remediation code, and CWE links. |
| **Copy for AI Fix** | Click the `$(copy)` button in the sidebar title to copy all findings formatted as an AI remediation prompt (Markdown) directly to clipboard. |
| **Open Report in Tab** | Click the `$(output)` button in the sidebar title to open the findings report in a new Markdown editor tab. |
| **Clear Scan Results** | Click the `$(clear-all)` button to clear whole-workspace scan results and reset the view back to only open files. |
| **Suppression** | Click the QuickFix lightbulb to insert `# llmscan-ignore[RULE]: TODO Reason`. |
| **Workspace Scan** | Click the `$(refresh)` button or run `LLMScan: Scan entire workspace` from the Command Palette. |
| **Baseline / Reset** | Run `Create baseline` to ignore existing alerts, or `Clear baseline` to restore and view all findings again. |

---

## ⚙️ Configuration

You can configure options in `.llmscan.yml` at the repository root (shared with the CI CLI) or via VS Code Settings:

```yaml
# .llmscan.yml
minConfidence: medium        # low | medium | high
failOn: high                 # Failure threshold for CI CLI
baseline: .llmscan-baseline.json
exclude:
  - "**/tests/**"
  - "**/generated/**"
sanitizers:                  # Custom sanitization functions defined in your project
  javascript: ["mySanitizer"]
  python: ["app.security.sanitize_query"]
  php: ["clean_input"]
```

### VS Code Settings (`settings.json`)
- `llmscan.enable`: Enable or disable LLMScan security analysis. (Default: `true`)
- `llmscan.minConfidence`: Filter findings by minimum confidence level (`low`, `medium`, `high`).
- `llmscan.showBaselined`: Whether to display existing findings recorded in the baseline file. (Default: `false`)

---

## 🛡️ Supported Rules

| Rule ID | Category | Severity |
|---|---|---|
| `{PY,JS,PHP}-SQLI-001` | SQL Injection | High |
| `{PY,JS,PHP}-CMDI-001` | OS Command Injection | Critical |
| `{PY,JS,PHP}-CODEI-001` | Code Injection (`eval` / `new Function`) | Critical |
| `{PY,JS,PHP}-DESER-001` | Insecure Deserialization (`pickle`, `unserialize`) | High |
| `{PY,JS}-SSTI-001` | Server-Side Template Injection | High |
| `{PY,JS,PHP}-XSS-001` | Cross-Site Scripting (`innerHTML`, `echo`) | Medium |
| `PHP-FILEINC-001` | File Inclusion (`include`, `require`) | High |
| `LLM05-*-001` | **OWASP LLM05** Insecure LLM Output Handling | Critical / High |
| `LLMSCAN-SUPPRESS-001` | Suppression comment without reason | Low |

---

## 🔒 Privacy & Local Processing

LLMScan is built on local Tree-sitter WebAssembly grammar parsers. **No source code, file paths, or telemetry are ever transmitted across the network.** It functions completely offline and in air-gapped environments.
