import { PHP_SAFE_FILTER_REGEX, PHP_SAFE_PRIMITIVES_REGEX } from '../constants';
import { type CallInfo, type LanguageSpec, matchesCustom } from './spec';

const SUPERGLOBALS = /^(_GET|_POST|_REQUEST|_COOKIE|_FILES|_SERVER|HTTP_RAW_POST_DATA)\b/;
const LARAVEL_REQUEST =
  /^(request|this\.request|Request)\.(input|query|get|post|all|cookie|header|route|string|json|only|except|validated|safe|getContent|getQueryString)$/;

const LLM_CALL = /(^|\.)(chat|completions|messages|responses)\.(create|createStreamed|stream)$/;

const SQL_FUNC_ARG0 = /^(mysql_query|sqlite_query|sqlite_exec)$/;
const SQL_FUNC_ARG1 = /^(mysqli_query|mysqli_multi_query|mysqli_real_query|mysqli_prepare|pg_send_query|pg_prepare)$/;
const SQL_METHOD =
  /^(query|exec|prepare|multi_query|real_query|unprepared|statement|whereRaw|orWhereRaw|selectRaw|orderByRaw|havingRaw|orHavingRaw|groupByRaw|joinRaw|leftJoinRaw|rightJoinRaw|raw|fromRaw)$/;

const PROPAGATE_KEEP = new Set([
  'trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper', 'mb_strtolower', 'mb_strtoupper', 'substr',
  'mb_substr', 'str_replace', 'str_ireplace', 'explode', 'json_decode', 'urldecode', 'rawurldecode',
  'base64_decode', 'ucfirst', 'lcfirst', 'ucwords', 'str_pad', 'stripslashes', 'addslashes',
  'strval', 'nl2br', 'array_values', 'reset', 'end', 'current', 'array_pop', 'array_shift',
  'file_get_contents',
]);
const PROPAGATE_BUILT = new Set(['sprintf', 'vsprintf', 'implode', 'join', 'str_repeat']);

export const php: LanguageSpec = {
  family: 'php',
  rulePrefix: 'PHP',
  commentPrefix: '//',

  sourceForPath(path) {
    return SUPERGLOBALS.test(path) ? { kind: 'user', label: '$' + path } : null;
  },

  sourceForCall(call) {
    const { path, args } = call;
    if (LARAVEL_REQUEST.test(path)) return { kind: 'user', label: path };
    if (path === 'request' && args.length > 0) return { kind: 'user', label: path };
    if (path === 'file_get_contents' && args[0]?.text.includes('php://input')) return { kind: 'user', label: 'php://input' };
    if (path === 'filter_input' && !/VALIDATE_(INT|FLOAT|BOOL)/.test(call.node.text)) {
      return { kind: 'user', label: path };
    }
    if (path === 'getallheaders') return { kind: 'user', label: path };
    if (LLM_CALL.test(path)) return { kind: 'llm', label: path };
    return null;
  },

  sinkForCall(call) {
    const { path, name, receiver, receiverNode, args } = call;
    const first = args.slice(0, 1);
    const isFunction = receiver === '' && receiverNode === null;

    if (isFunction) {
      if (SQL_FUNC_ARG0.test(name)) return { kind: 'sqli', args: first };
      if (SQL_FUNC_ARG1.test(name)) return { kind: 'sqli', args: args.slice(1, 2) };
      if (name === 'pg_query') return { kind: 'sqli', args: args.slice(-1) };
      if (/^(exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)$/.test(name)) return { kind: 'cmdi', args: first };
      if (/^(eval|assert)$/.test(name)) return { kind: 'codei', args: first };
      if (name === 'create_function') return { kind: 'codei', args };
      if (name === 'unserialize') return { kind: 'deser', args: first };
      return null;
    }
    if (SQL_METHOD.test(name)) {
      if (/^DB$/.test(receiver) && !/^(raw|select|statement|unprepared|insert|update|delete)$/.test(name)) return null;
      return { kind: 'sqli', args: first };
    }
    if (/^DB\.(select|insert|update|delete)$/.test(path)) return { kind: 'sqli', args: first };
    return null;
  },

  sanitizerForCall(call, ctx) {
    const { path, name } = call;
    if (matchesCustom(path, ctx.customSanitizers)) return 'all';
    if (PHP_SAFE_PRIMITIVES_REGEX.test(path)) return 'all';
    if (/^filter_var$/.test(path) && PHP_SAFE_FILTER_REGEX.test(call.node.text)) return 'all';
    if (/^(htmlspecialchars|htmlentities|e|esc_html|esc_attr|esc_url|urlencode|rawurlencode|strip_tags)$/.test(path)) return ['xss'];
    if (/^(escapeshellarg|escapeshellcmd)$/.test(path)) return ['cmdi'];
    if (/^(mysqli_real_escape_string|pg_escape_string|pg_escape_literal|sqlite_escape_string)$/.test(path)) return ['sqli'];
    if (name === 'real_escape_string' || name === 'quote' || name === 'escape_string') return ['sqli'];
    if (path === 'basename') return ['fileinc'];
    return null;
  },

  propagator(call) {
    if (PROPAGATE_BUILT.has(call.name)) return 'built';
    if (PROPAGATE_KEEP.has(call.name)) return 'keep';
    return null;
  },
};
