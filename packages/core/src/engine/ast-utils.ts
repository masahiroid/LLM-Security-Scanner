import type { Node } from 'web-tree-sitter';
import { ALLOWLIST_CALL_PATTERN, MAX_DISPLAY_TEXT_LENGTH, TEXT_TRUNCATION_LIMIT } from '../constants';
import type { Range, TraceStep } from '../types';

export const FUNCTION_TYPES = new Set([
  // Python
  'function_definition',
  'lambda',
  // JS / TS
  'function_declaration',
  'function_expression',
  'function',
  'arrow_function',
  'method_definition',
  'generator_function_declaration',
  'generator_function',
  // PHP
  'method_declaration',
  'anonymous_function',
  'anonymous_function_creation_expression',
]);

export const CALL_TYPES = new Set([
  'call',
  'call_expression',
  'new_expression',
  'function_call_expression',
  'member_call_expression',
  'nullsafe_member_call_expression',
  'scoped_call_expression',
  'object_creation_expression',
]);

export const MEMBER_TYPES = new Set([
  'attribute',
  'member_expression',
  'member_access_expression',
  'nullsafe_member_access_expression',
  'scoped_property_access_expression',
  'subscript',
  'subscript_expression',
]);

/** 汚染しない（真偽値・数値を返す）式 */
export const CLEAN_TYPES = new Set([
  'comparison_operator',
  'not_operator',
  'integer',
  'float',
  'number',
  'true',
  'false',
  'none',
  'null',
  'boolean',
  'type_annotation',
  'type',
  'comment',
  'decorator',
  'import_statement',
  'import_from_statement',
  'import_declaration',
  'namespace_use_declaration',
  'instanceof_expression',
  'type_alias_declaration',
  'interface_declaration',
  'enum_declaration',
]);

export const SUMMARY_FUNCTION_TYPES = new Set([
  'function_definition',
  'function_declaration',
  'generator_function_declaration',
  'method_definition',
  'method_declaration',
]);

/** ノードのテキストを一定長で切り詰めて取得 */
export function short(node: Node): string {
  const text = node.text.replace(/\s+/g, ' ');
  return text.length > MAX_DISPLAY_TEXT_LENGTH
    ? text.slice(0, TEXT_TRUNCATION_LIMIT) + '...'
    : text;
}

/** ASTノードの Range を取得 */
export function rangeOf(node: Node): Range {
  return {
    start: { line: node.startPosition.row, column: node.startPosition.column },
    end: { line: node.endPosition.row, column: node.endPosition.column },
  };
}

/** トレースステップを生成 */
export function step(node: Node, message: string): TraceStep {
  return { range: rangeOf(node), message };
}

/** コメント以外の名前付き子ノードを抽出 */
export function named(node: Node): Node[] {
  return node.namedChildren.filter((n): n is Node => n !== null && n.type !== 'comment');
}

/** 呼び出し先などを "a.b.c" 形式に正規化する */
export function calleePath(node: Node | null): string {
  if (!node) return '?';
  switch (node.type) {
    case 'identifier':
    case 'property_identifier':
    case 'private_property_identifier':
    case 'shorthand_property_identifier':
    case 'name':
    case 'this':
    case 'super':
    case 'type_identifier':
      return node.text;
    case 'variable_name':
      return node.text.replace(/^\$/, '');
    case 'qualified_name':
    case 'relative_name':
      return node.text.replace(/^\\/, '').replace(/\\/g, '.');
    case 'attribute':
      return `${calleePath(node.childForFieldName('object'))}.${node.childForFieldName('attribute')?.text ?? '?'}`;
    case 'member_expression':
      return `${calleePath(node.childForFieldName('object'))}.${node.childForFieldName('property')?.text ?? '?'}`;
    case 'member_access_expression':
    case 'nullsafe_member_access_expression':
    case 'member_call_expression':
    case 'nullsafe_member_call_expression':
      return `${calleePath(node.childForFieldName('object'))}.${calleePath(node.childForFieldName('name'))}`;
    case 'scoped_call_expression':
    case 'scoped_property_access_expression':
    case 'class_constant_access_expression': {
      const scope = node.childForFieldName('scope') ?? named(node)[0] ?? null;
      const name = node.childForFieldName('name') ?? named(node)[1] ?? null;
      return `${calleePath(scope)}.${calleePath(name)}`;
    }
    case 'subscript':
      return `${calleePath(node.childForFieldName('value'))}[]`;
    case 'subscript_expression':
      return `${calleePath(node.childForFieldName('object') ?? named(node)[0] ?? null)}[]`;
    case 'call':
    case 'call_expression':
    case 'function_call_expression':
      return calleePath(node.childForFieldName('function'));
    case 'new_expression':
      return calleePath(node.childForFieldName('constructor'));
    case 'parenthesized_expression':
    case 'await_expression':
    case 'non_null_expression':
    case 'as_expression':
    case 'satisfies_expression':
      return calleePath(named(node)[0] ?? null);
    default:
      return '?';
  }
}

/** 条件式が value を許可リストと照合しているかを判定 */
export function isAllowlistCheck(condition: Node, value: string): boolean {
  const text = condition.text.replace(/\s+/g, ' ');
  if (!value || !/^[$\w.]+$/.test(value)) return false;
  const escaped = value.replace(/[$.]/g, (c) => '\\' + c);
  // Python: x in ALLOWED
  if (new RegExp(`^${escaped} in \\w`).test(text)) return true;
  if (!ALLOWLIST_CALL_PATTERN.test(text)) return false;
  // in_array($x, ...) / array_key_exists($x, ...) / LIST.includes(x)
  return new RegExp(`(\\(|, ?)${escaped}\\s*[,)]`).test(text);
}

/** PHP の <?= ... ?> の式か */
export function isShortEcho(node: Node): boolean {
  let prev = node.previousSibling;
  if (prev?.type === 'text_interpolation') prev = prev.lastChild;
  return prev?.type === 'php_tag' && prev.text.startsWith('<?=');
}

