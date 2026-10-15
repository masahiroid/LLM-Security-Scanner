import {
  JS_CRYPTO_HASH_REGEX,
  JS_SAFE_PRIMITIVES_REGEX,
  JS_VALIDATOR_SAFE_REGEX,
  JS_YUP_SAFE_SCHEMA_REGEX,
  JS_ZOD_SAFE_SCHEMA_REGEX,
  JS_ZOD_SAFE_STRING_SCHEMA_REGEX,
  LLM_TOOL_PATH_PATTERN,
  MCP_TOOL_PARAM_PATTERN,
} from '../constants';
import { type CallInfo, type FileContext, type LanguageSpec, matchesCustom } from './spec';

const USER_PATH = [
  /^(?:req|request|ctx\.request|ctx|context\.req|c\.req|event)\.(query|params|body|headers|cookies|signedCookies|files|file|originalUrl|url|path|hostname|json|formData|text|param|queryStringParameters|pathParameters)\b/,
  /^(?:window\.|document\.)?location\.(search|hash|href|pathname)\b/,
  /^document\.(URL|documentURI|referrer|cookie|baseURI)\b/,
  /^window\.name$/,
  /^process\.argv\b/,
  /^(?:router|this\.\$route|route|\$route)\.(query|params)\b/,
  /(^|\.)searchParams\b/,
];
const USER_CALL = /^(useSearchParams|useParams)$/;

const LLM_CALL = [
  /(^|\.)(chat\.)?completions\.(create|parse|stream)$/,
  /(^|\.)messages\.(create|stream)$/,
  /(^|\.)responses\.(create|parse|stream)$/,
  /(^|\.)generateContent(Stream)?$/,
  /^(generateText|generateObject|streamText|streamObject)$/,
  /^ollama\.(chat|generate)$/,
];
const OLLAMA_METHOD = /^(chat|generate)$/;
const LLM_RECEIVER = /(llm|chain|agent|model|chatModel|chat|executor|graph|runnable|tool)$/i;
const LLM_METHOD = /^(invoke|call|predict|stream|batch|run|generate)$/;

const DB_RECEIVER =
  /(^|_)(db|conn|connection|client|pool|database|knex|sequelize|tx|trx|pg|mysql|sqlite|sql|stmt|statement|queryRunner|manager|em|prisma|repo|repository|cursor|session|dataSource|datasource|appDataSource|dbClient)$/i;
const SQL_GENERIC = /^(query|execute|exec|run|all|get|prepare|each)$/;
const SQL_UNSAFE = /^(\$queryRawUnsafe|\$executeRawUnsafe|raw|rawQuery|executeRaw|whereRaw|orWhereRaw|orderByRaw|havingRaw|selectRaw|joinRaw|groupByRaw|unsafe)$/;

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** `import { exec as run }` / `const { exec: run } = require(...)` で別名を付けた exec / execSync か */
function isExecAlias(name: string, ctx: FileContext): boolean {
  const n = escapeRegExp(name);
  return ctx.mentions(new RegExp(`\\b(?:exec|execSync)\\s*(?:\\bas\\s+|:\\s*)${n}(?![\\w$])`));
}

/** `const o = new Ollama(...)` で作ったクライアントか */
function isOllamaClient(receiver: string, ctx: FileContext): boolean {
  if (!/^[A-Za-z_$][\w$]*$/.test(receiver)) return false;
  return ctx.mentions(new RegExp(`(?<![\\w$])${escapeRegExp(receiver)}\\s*=\\s*new\\s+Ollama\\s*\\(`));
}

const PROPAGATE_KEEP = new Set([
  'toString', 'trim', 'trimStart', 'trimEnd', 'toLowerCase', 'toUpperCase', 'slice', 'substring',
  'substr', 'split', 'replace', 'replaceAll', 'padStart', 'padEnd', 'repeat', 'at', 'String',
  'parse', 'stringify', 'decodeURIComponent', 'decodeURI', 'values', 'entries', 'from', 'get',
  'getAll', 'json', 'text', 'formData', 'normalize', 'flat', 'toLocaleLowerCase', 'toLocaleUpperCase',
  'valueOf', 'atob', 'Buffer', 'URLSearchParams', 'URL',
]);
const PROPAGATE_BUILT = new Set(['join', 'concat', 'format']);

export const javascript: LanguageSpec = {
  family: 'javascript',
  rulePrefix: 'JS',
  commentPrefix: '//',

  sourceForPath(path) {
    if (LLM_TOOL_PATH_PATTERN.test(path) || MCP_TOOL_PARAM_PATTERN.test(path)) {
      return { kind: 'llm', label: path };
    }
    if (USER_PATH.some((re) => re.test(path))) return { kind: 'user', label: path };
    return null;
  },

  sourceForCall(call, ctx) {
    const { path, name, receiver } = call;
    if (USER_PATH.some((re) => re.test(path)) || USER_CALL.test(path)) return { kind: 'user', label: path };
    if (LLM_CALL.some((re) => re.test(path))) return { kind: 'llm', label: path };
    if (OLLAMA_METHOD.test(name) && isOllamaClient(receiver, ctx)) return { kind: 'llm', label: path };
    if (receiver && LLM_METHOD.test(name) && LLM_RECEIVER.test(receiver.split('.').pop() ?? '')) {
      return { kind: 'llm', label: path };
    }
    return null;
  },

  sinkForCall(call, ctx) {
    const { path, name, receiver, args, isNew } = call;
    const recvLast = receiver.split('.').pop() ?? '';
    const first = args.slice(0, 1);

    // --- SQL ---
    if (SQL_UNSAFE.test(name) && receiver !== '') return { kind: 'sqli', args: first };
    if (SQL_GENERIC.test(name) && DB_RECEIVER.test(recvLast)) return { kind: 'sqli', args: first };

    // --- OS コマンド ---
    const usesChildProcess = ctx.mentions(/child_process|shelljs|execa/);
    if (usesChildProcess) {
      if (/^(exec|execSync)$/.test(name) && (receiver === '' || /child|^cp$|proc|shell|^sh$/i.test(recvLast))) {
        return { kind: 'cmdi', args: first };
      }
      if (receiver === '' && isExecAlias(name, ctx)) return { kind: 'cmdi', args: first };
      if (/^(spawn|spawnSync|execFile|execFileSync)$/.test(name) && args.some((a) => /shell\s*:\s*true/.test(a.text))) {
        return { kind: 'cmdi', args: args.slice(0, 2) };
      }
      if (/^(execaCommand|execaCommandSync)$/.test(path) || /^execa\.command(Sync)?$/.test(path)) {
        return { kind: 'cmdi', args: first };
      }
    }

    // --- コード実行 ---
    if (/^(eval|window\.eval|globalThis\.eval)$/.test(path)) return { kind: 'codei', args: first };
    if (/^(Function|window\.Function)$/.test(path)) return { kind: 'codei', args };
    if (/^vm\.(runInThisContext|runInNewContext|runInContext|compileFunction)$/.test(path)) {
      return { kind: 'codei', args: first };
    }
    if (isNew && /^vm\.Script$/.test(path)) return { kind: 'codei', args: first };
    if (/^(window\.)?(setTimeout|setInterval)$/.test(path)) return { kind: 'codei', args: first };

    // --- 安全でないデシリアライズ ---
    if (name === 'unserialize') return { kind: 'deser', args: first };

    // --- テンプレートインジェクション ---
    if (/^(ejs|pug|jade|handlebars|Handlebars|nunjucks|mustache|Mustache)\.(render|compile|renderString)$/.test(path)) {
      return { kind: 'ssti', args: first };
    }
    if (/^(_|lodash)\.template$/.test(path)) return { kind: 'ssti', args: first };

    // --- XSS ---
    if (/^document\.(write|writeln)$/.test(path)) return { kind: 'xss', args };
    if (name === 'insertAdjacentHTML') return { kind: 'xss', args: args.slice(1, 2) };
    if (name === 'createContextualFragment') return { kind: 'xss', args: first };
    if (/^(html|append|prepend|after|before|replaceWith)$/.test(name) && /^(\$|jQuery)\b/.test(receiver)) {
      return { kind: 'xss', args: first };
    }
    return null;
  },

  sanitizerForCall(call, ctx) {
    const { path, name, receiver } = call;
    if (matchesCustom(path, ctx.customSanitizers)) return 'all';
    if (JS_SAFE_PRIMITIVES_REGEX.test(path)) return 'all';
    if (JS_VALIDATOR_SAFE_REGEX.test(path)) return 'all';
    if (JS_ZOD_SAFE_SCHEMA_REGEX.test(path) || JS_ZOD_SAFE_STRING_SCHEMA_REGEX.test(path)) return 'all';
    if (JS_YUP_SAFE_SCHEMA_REGEX.test(path)) return 'all';
    if (JS_CRYPTO_HASH_REGEX.test(path) || (name === 'digest' && /hash|sha|md5|crypto/i.test(receiver))) return 'all';
    if (/^(encodeURIComponent|encodeURI|escape|escapeHtml|escapeHTML|sanitizeHtml|xss|filterXSS)$/.test(path)) return ['xss'];
    if (name === 'sanitize' || /^(he|validator|_|lodash|entities)\.(encode|escape|encodeHTML)$/.test(path)) return ['xss'];
    if ((name === 'escape' || name === 'escapeId' || name === 'format') && /mysql|SqlString|conn|connection|pool|db/i.test(receiver)) {
      return ['sqli'];
    }
    if (/^(shellQuote\.quote|shellEscape|shellescape|quote)$/.test(path)) return ['cmdi'];
    return null;
  },

  propagator(call) {
    if (PROPAGATE_BUILT.has(call.name)) return 'built';
    if (PROPAGATE_KEEP.has(call.name)) return 'keep';
    return null;
  },
};
