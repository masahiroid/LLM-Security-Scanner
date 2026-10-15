import {
  LLM_TOOL_PATH_PATTERN,
  MCP_TOOL_PARAM_PATTERN,
  PY_SAFE_CRYPTO_REGEX,
  PY_SAFE_DATETIME_REGEX,
  PY_SAFE_IP_REGEX,
  PY_SAFE_MATH_REGEX,
  PY_SAFE_PRIMITIVES_REGEX,
  PY_SAFE_SCHEMA_REGEX,
} from '../constants';
import { type CallInfo, type LanguageSpec, matchesCustom } from './spec';

const USER_PATH =
  /^(?:self\.)?(?:flask\.)?request\.(args|form|values|json|data|files|cookies|headers|GET|POST|COOKIES|META|FILES|body|query_params|path_params|get_json|get_data|stream|environ)\b|^sys\.argv\b/;

const LLM_CALL = [
  /(^|\.)(chat\.)?completions\.(create|parse|stream)$/,
  /(^|\.)messages\.(create|stream)$/,
  /(^|\.)responses\.(create|parse|stream)$/,
  /(^|\.)(ChatCompletion|Completion)\.(create|acreate)$/,
  /^litellm\.(a?completion|text_completion)$/,
  /(^|\.)generate_content(_async)?$/,
  /^ollama\.(chat|generate|achat|agenerate)$/,
];

const LLM_RECEIVER = /(llm|chain|agent|chat_model|chat|executor|graph|runnable|crew|query_engine|chat_engine|tool)$/i;
const LLM_METHOD = /^(invoke|ainvoke|predict|apredict|run|arun|generate|agenerate|stream|astream|batch|abatch|kickoff|query|aquery|chat|achat)$/;

const DB_RECEIVER = /^(c|cur|con|tx|txn)$|cursor|conn|db|session|engine|database|transaction/i;
const SUBPROCESS = /^(call|run|Popen|check_call|check_output)$/;

const PROPAGATE_KEEP = new Set([
  'str', 'repr', 'strip', 'lstrip', 'rstrip', 'lower', 'upper', 'title', 'capitalize', 'casefold',
  'replace', 'split', 'rsplit', 'splitlines', 'encode', 'decode', 'get', 'getlist', 'pop', 'items',
  'values', 'keys', 'copy', 'removeprefix', 'removesuffix', 'ljust', 'rjust', 'zfill', 'center',
  'partition', 'rpartition', 'loads', 'dumps', 'unquote', 'unquote_plus', 'b64decode', 'list',
  'tuple', 'dict', 'set', 'sorted', 'reversed', 'read', 'readline', 'readlines', 'model_dump',
  'model_dump_json', 'dict', 'to_dict', 'text', 'content', 'normpath', 'expandtabs', 'translate',
]);
const PROPAGATE_BUILT = new Set(['format', 'format_map', 'join']);

function kwText(call: CallInfo, name: string): string | undefined {
  return call.kwargs.get(name)?.text;
}

export const python: LanguageSpec = {
  family: 'python',
  rulePrefix: 'PY',
  commentPrefix: '#',

  sourceForPath(path) {
    if (LLM_TOOL_PATH_PATTERN.test(path) || MCP_TOOL_PARAM_PATTERN.test(path)) {
      return { kind: 'llm', label: path };
    }
    if (USER_PATH.test(path)) return { kind: 'user', label: path };
    return null;
  },

  sourceForCall(call, ctx) {
    const { path, name, receiver } = call;
    if (USER_PATH.test(path)) return { kind: 'user', label: path };
    if (path === 'input' || path === 'raw_input') return { kind: 'user', label: path };
    if (LLM_CALL.some((re) => re.test(path))) return { kind: 'llm', label: path };
    if ((path === 'completion' || path === 'acompletion') && ctx.mentions(/from\s+litellm\s+import/)) {
      return { kind: 'llm', label: path };
    }
    if (receiver && LLM_METHOD.test(name) && LLM_RECEIVER.test(receiver.split('.').pop() ?? '')) {
      return { kind: 'llm', label: path };
    }
    return null;
  },

  sinkForCall(call, ctx) {
    const { path, name, receiver, args } = call;
    const recvLast = receiver.split('.').pop() ?? '';
    const first = args.slice(0, 1);

    // --- SQL ---
    if (/^(execute|executemany|executescript)$/.test(name) && DB_RECEIVER.test(recvLast)) {
      return { kind: 'sqli', args: first };
    }
    if (name === 'raw' && /objects$/.test(receiver)) return { kind: 'sqli', args: first };
    if (name === 'extra' && (/objects|filter|all|select_related/.test(receiver) || call.kwargs.has('where'))) {
      const whereArg = call.kwargs.get('where');
      return { kind: 'sqli', args: whereArg ? [whereArg] : first };
    }
    if (/(^|\.)(read_sql|read_sql_query)$/.test(path)) return { kind: 'sqli', args: first };
    if (/(^|\.)(RawSQL|SQL)$/.test(path)) return { kind: 'sqli', args: first };
    if (/^(sqlalchemy\.|sa\.)?text$/.test(path) && ctx.mentions(/sqlalchemy/)) {
      return { kind: 'sqli', args: first };
    }

    // --- OS コマンド ---
    if (/^os\.(system|popen|popen2|popen3|popen4)$/.test(path)) return { kind: 'cmdi', args: first };
    if (/^(commands|subprocess)\.(getoutput|getstatusoutput)$/.test(path)) return { kind: 'cmdi', args: first };
    if (/^asyncio\.create_subprocess_shell$/.test(path)) return { kind: 'cmdi', args: first };
    if ((receiver === 'subprocess' || receiver === '') && SUBPROCESS.test(name)) {
      if (kwText(call, 'shell') === 'True') return { kind: 'cmdi', args: first };
    }

    // --- コード実行 ---
    if (/^(builtins\.)?(eval|exec|compile)$/.test(path)) return { kind: 'codei', args: first };

    // --- 安全でないデシリアライズ ---
    if (/^(pickle|cPickle|_pickle|dill|marshal|joblib|shelve)\.(loads?|open)$/.test(path)) {
      return { kind: 'deser', args: first };
    }
    if (/^jsonpickle\.decode$/.test(path)) return { kind: 'deser', args: first };
    if (/^yaml\.(load|load_all)$/.test(path)) {
      const loader = kwText(call, 'Loader') ?? args[1]?.text ?? '';
      if (!/Safe|CSafe|BaseLoader/.test(loader)) return { kind: 'deser', args: first };
    }
    if (/^yaml\.unsafe_load(_all)?$/.test(path)) return { kind: 'deser', args: first };
    if (/^torch\.load$/.test(path) && kwText(call, 'weights_only') !== 'True') {
      return { kind: 'deser', args: first };
    }

    // --- テンプレートインジェクション ---
    if (/(^|\.)render_template_string$/.test(path)) return { kind: 'ssti', args: first };
    if (/^(jinja2\.)?Template$/.test(path) && ctx.mentions(/jinja2/)) return { kind: 'ssti', args: first };
    if (name === 'from_string' && receiver !== '') return { kind: 'ssti', args: first };

    // --- XSS（自動エスケープの無効化） ---
    if (/^(markupsafe\.|flask\.)?Markup$/.test(path) || /(^|\.)(mark_safe|SafeString)$/.test(path)) {
      return { kind: 'xss', args: first };
    }
    return null;
  },

  sanitizerForCall(call, ctx) {
    const { path } = call;
    if (matchesCustom(path, ctx.customSanitizers)) return 'all';
    if (PY_SAFE_PRIMITIVES_REGEX.test(path)) return 'all';
    if (PY_SAFE_MATH_REGEX.test(path)) return 'all';
    if (PY_SAFE_IP_REGEX.test(path)) return 'all';
    if (PY_SAFE_DATETIME_REGEX.test(path)) return 'all';
    if (PY_SAFE_CRYPTO_REGEX.test(path)) return 'all';
    if (PY_SAFE_SCHEMA_REGEX.test(path)) return 'all';
    if ((/(^|\.)(escape|conditional_escape|escape_html)$/.test(path) && !/^re\./.test(path)) || /^bleach\.clean$/.test(path)) {
      return ['xss'];
    }
    if (/^(shlex|pipes)\.quote$/.test(path) || (path === 'quote' && ctx.mentions(/shlex/))) return ['cmdi'];
    if (/^os\.path\.basename$/.test(path)) return ['fileinc'];
    return null;
  },

  propagator(call) {
    if (PROPAGATE_BUILT.has(call.name)) return 'built';
    if (PROPAGATE_KEEP.has(call.name)) return 'keep';
    if (/^(json|urllib\.parse|base64|os\.path)\./.test(call.path)) return 'keep';
    return null;
  },
};
