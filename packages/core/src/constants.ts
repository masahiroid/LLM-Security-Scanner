import type { Confidence, OriginKind, Severity } from './types';

/**
 * コアエンジンおよびスキャナー全体で利用する定数定義
 * マジックナンバーおよびハードコードを排除し、設定可能な値を一元管理する
 */

/** トレース経路に記録する最大ステップ数 */
export const MAX_TRACE_STEPS = 12;

/** ログやホバー等で表示するコード片の最大文字数 */
export const MAX_DISPLAY_TEXT_LENGTH = 60;

/** コード片を省略表記する際のプレフィックス文字数 */
export const TEXT_TRUNCATION_LIMIT = 57;

/** ワークスペーススキャン時にスキップする巨大ファイルの上限バイト数 (2MB) */
export const MAX_FILE_SIZE_BYTES = 2_000_000;

/** エディタ入力時のデバウンス待ち時間 (ミリ秒) */
export const DEFAULT_DEBOUNCE_MS = 300;

/** 指紋（フィンガープリント）生成時のハッシュ文字数 */
export const FINGERPRINT_HASH_LENGTH = 32;

/** 汚染源（Origin）の優先順位（数値が大きい方を優先して採用） */
export const ORIGIN_PRIORITY: Record<OriginKind, number> = {
  param: 0,
  user: 1,
  llm: 2,
};

/** 重大度（Severity）の順序スコア */
export const SEVERITY_ORDER: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/** 確信度（Confidence）の順序スコア */
export const CONFIDENCE_ORDER: Record<Confidence, number> = {
  low: 0,
  medium: 1,
  high: 2,
};

/** 確信度の日本語表示ラベル */
export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: '高',
  medium: '中',
  low: '低',
};

/** 確信度の英語表示ラベル */
export const CONFIDENCE_LABEL_EN: Record<Confidence, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

/** 抑制ルールの識別ID */
export const SUPPRESSION_RULE_ID = 'LLMSCAN-SUPPRESS-001';

/** 許可リスト検証関数・メソッドの照合正規表現 */
export const ALLOWLIST_CALL_PATTERN = /^(in_array|array_key_exists|isset)\s*\(|\.(includes|has|hasOwnProperty)\s*\(/;

/** 抑制コメントの検出正規表現 */
export const SUPPRESSION_COMMENT_PATTERN = /llmscan-ignore(?:\[([^\]]*)\])?(?:\s*:\s*(.*))?/;

/** LLM ツール呼び出し・関数引数アクセスのプロパティパス（JS/TS, Python） */
export const LLM_TOOL_PATH_PATTERN =
  /(^|\.)(?:tool_?calls?(\[\])?\.(?:function\.(?:arguments|parsed_arguments)|args|arguments)|tool_?calls?|tool_?input|action\.tool_?input)\b/i;

/** MCP (Model Context Protocol) ツールハンドラーの引数プロパティパス */
export const MCP_TOOL_PARAM_PATTERN =
  /(^|\.)(?:request\.params\.arguments|params\.arguments|callTool\.arguments)\b/i;

/** 単項演算子で結果が非汚染（真偽値・数値等）となる演算子セット */
export const CLEAN_UNARY_OPERATORS = new Set(['!', 'not', '+', '-', '~', 'typeof', 'void', 'delete']);

// --- JavaScript / TypeScript 無害化パターン ---
export const JS_SAFE_PRIMITIVES_REGEX =
  /^(Number|parseInt|parseFloat|BigInt|Boolean|isNaN|Number\.parseInt|Number\.parseFloat|Math\.\w+|crypto\.randomUUID)$/;

export const JS_VALIDATOR_SAFE_REGEX =
  /^validator\.(isNumeric|isInt|isFloat|isUUID|isAlphanumeric|isIP|isPort|isHexadecimal|isMD5|isISO8601|isJWT|isPostalCode|isMACAddress|isBoolean|isDataURI)$/;

export const JS_ZOD_SAFE_SCHEMA_REGEX =
  /^z\.(coerce\.)?(number|boolean|bigint|date)\.(parse|safeParse)$/;

export const JS_ZOD_SAFE_STRING_SCHEMA_REGEX =
  /^z\.(enum|literal)\.(parse|safeParse)$|^z\.string\.(uuid|ip|datetime|regex)\.(parse|safeParse)$/;

export const JS_YUP_SAFE_SCHEMA_REGEX =
  /^yup\.(number|boolean|date)\.(validate|validateSync|cast)$/;

export const JS_CRYPTO_HASH_REGEX =
  /(^|\.)createHash(\.\w+)*\.digest$|^(crypto\.)?(subtle\.digest|randomUUID|randomInt|randomBytes)$/;

// --- Python 無害化パターン ---
export const PY_SAFE_PRIMITIVES_REGEX =
  /^(int|float|bool|len|abs|round|uuid\.UUID|UUID|ord|hash|id|isinstance|callable)$/;

export const PY_SAFE_MATH_REGEX =
  /^math\.(floor|ceil|sqrt|trunc|abs|sin|cos|tan|log|exp|pow|factorial)$/;

export const PY_SAFE_IP_REGEX =
  /^ipaddress\.(ip_address|IPv4Address|IPv6Address|ip_network)$/;

export const PY_SAFE_DATETIME_REGEX =
  /^datetime\.(date|datetime|time)\.(fromisoformat|strptime)$/;

export const PY_SAFE_CRYPTO_REGEX =
  /^(hashlib\.\w+(\.\w+)*\.hexdigest|hmac\.\w+(\.\w+)*\.hexdigest|binascii\.(hexlify|b2a_hex|crc32)|zlib\.crc32|secrets\.(choice|randbelow|token_hex|token_urlsafe)|random\.(choice|randint|randrange|random))$/;

export const PY_SAFE_SCHEMA_REGEX =
  /^(TypeAdapter|pydantic\.TypeAdapter)\.validate_python$|^(pydantic\.)?(conint|PositiveInt|NonNegativeInt)$/;

// --- PHP 無害化パターン ---
export const PHP_SAFE_PRIMITIVES_REGEX =
  /^(intval|floatval|boolval|abs|count|ctype_digit|ctype_alnum|ctype_xdigit|is_numeric|strlen|uniqid|bin2hex|crc32|hexdec|random_int|random_bytes|md5|sha1|hash|hash_hmac)$/;

export const PHP_SAFE_FILTER_REGEX =
  /VALIDATE_(INT|FLOAT|BOOL|BOOLEAN|IP|MAC|DOMAIN)/;

// --- SSRF & パストラバーサル検出パターン (v1.5.0) ---
export const PY_SSRF_SINK_REGEX =
  /^(requests|httpx|aiohttp\.ClientSession)\.(get|post|put|delete|patch|head|options|request)$|^urllib\.request\.urlopen$/;

export const PY_PATH_SINK_REGEX =
  /^(builtins\.)?open$|^os\.(remove|unlink|rmdir|makedirs|listdir)$|^shutil\.(rmtree|copy|copy2|copyfile|move)$|^(flask\.)?send_file$/;

export const JS_SSRF_SINK_REGEX =
  /^(window\.|globalThis\.)?fetch$|^(axios|got|ky)\.(get|post|put|delete|patch|head|request)$|^axios$/;

export const JS_PATH_SINK_REGEX =
  /^(fs|fs\.promises| fsPromises)\.(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|createReadStream|createWriteStream)$|^(res|response)\.(sendFile|download)$/;

export const PHP_SSRF_SINK_REGEX = /^(curl_init|get_headers)$/;
export const PHP_PATH_SINK_REGEX =
  /^(file_get_contents|file_put_contents|fopen|readfile|unlink|rmdir|copy|rename)$/;

// --- OWASP LLM01: システムプロンプト汚染検出パターン ---
export const SYSTEM_ROLE_VALUE_REGEX = /^['"`]?(system|developer)['"`]?$/i;
export const SYSTEM_PROMPT_KEY_REGEX = /^['"`]?(system|system_instruction|systemInstruction|instructions)['"`]?$/;
export const SYSTEM_MESSAGE_CALL_REGEX = /(^|\.)(SystemMessage|ChatPromptTemplate\.from_messages)$/;
export const MESSAGES_KEY_REGEX = /^['"`]?messages['"`]?$/;
export const ROLE_KEY_REGEX = /^['"`]?role['"`]?$/;
export const CONTENT_KEY_REGEX = /^['"`]?(content|text)['"`]?$/;

// --- OWASP LLM02: ハードコードされた API キー・シークレット検出パターン ---
export const HARDCODED_API_KEY_REGEX =
  /\b(sk-(?:proj-|ant-api03-|live-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|hf_[A-Za-z0-9]{30,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{20,})\b/;

/** シークレット検出時にマスク表示する先頭文字数 */
export const MASKED_SECRET_PREFIX_LENGTH = 8;

/** クロスファイル関数要約でレシーバ付き呼び出し（obj.method）から除外する汎用メソッド名 */
export const AMBIGUOUS_SUMMARY_NAMES = new Set([
  'get',
  'set',
  'post',
  'put',
  'delete',
  'patch',
  'run',
  'exec',
  'execute',
  'query',
  'open',
  'close',
  'read',
  'write',
  'send',
  'render',
  'parse',
  'load',
  'loads',
  'dump',
  'dumps',
  'format',
  'create',
  'invoke',
  'call',
  'apply',
  'bind',
  'toString',
  'valueOf',
]);



