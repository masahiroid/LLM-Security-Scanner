import type { Node } from 'web-tree-sitter';
import {
  CONTENT_KEY_REGEX,
  HARDCODED_API_KEY_REGEX,
  MASKED_SECRET_PREFIX_LENGTH,
  MESSAGES_KEY_REGEX,
  ROLE_KEY_REGEX,
  SYSTEM_MESSAGE_CALL_REGEX,
  SYSTEM_PROMPT_KEY_REGEX,
  SYSTEM_ROLE_VALUE_REGEX,
} from '../constants';
import type { CallInfo, FileContext, LanguageSpec } from '../languages/spec';
import { named } from './ast-utils';

/**
 * LLM 呼び出しからシステムプロンプト（system / developer ロールや system 引数）として
 * 渡されている AST ノード群を抽出する（OWASP LLM01 検査用）
 */
export function extractSystemPromptTargets(
  call: CallInfo,
  spec: LanguageSpec,
  ctx: FileContext,
): Node[] {
  const isLlmSource = spec.sourceForCall(call, ctx)?.kind === 'llm';
  const isSystemMsgHelper = SYSTEM_MESSAGE_CALL_REGEX.test(call.path);
  if (!isLlmSource && !isSystemMsgHelper) return [];

  const targets: Node[] = [];

  if (/(^|\.)SystemMessage$/.test(call.path)) {
    const contentKw = call.kwargs.get('content');
    if (contentKw) targets.push(contentKw);
    else if (call.args[0]) targets.push(call.args[0]);
    return targets;
  }

  // 1. キーワード引数 (Python / PHP 名前付き引数): system=..., instructions=..., messages=...
  for (const [k, v] of call.kwargs.entries()) {
    if (SYSTEM_PROMPT_KEY_REGEX.test(k)) {
      targets.push(v);
    } else if (MESSAGES_KEY_REGEX.test(k)) {
      targets.push(...extractSystemNodesFromMessages(v));
    }
  }

  // 2. 位置引数（JS のオプションオブジェクト `{ system, messages }` やメッセージ配列）
  for (const arg of call.args) {
    if (isObjectOrDictNode(arg)) {
      for (const { keyText, valueNode } of iterateKeyValues(arg)) {
        if (SYSTEM_PROMPT_KEY_REGEX.test(keyText)) {
          targets.push(valueNode);
        } else if (MESSAGES_KEY_REGEX.test(keyText)) {
          targets.push(...extractSystemNodesFromMessages(valueNode));
        }
      }
    } else if (isListOrArrayNode(arg)) {
      targets.push(...extractSystemNodesFromMessages(arg));
    }
  }

  return targets;
}

/**
 * messages 配列・リストから role: "system" | "developer" の content ノード、
 * または ("system", content) タプルの content ノードを抽出する
 */
function extractSystemNodesFromMessages(messagesNode: Node): Node[] {
  const results: Node[] = [];
  if (!isListOrArrayNode(messagesNode)) return results;

  for (const item of named(messagesNode)) {
    const unwrapped = item.type === 'array_element_initializer' ? named(item)[0] ?? item : item;
    if (isObjectOrDictNode(unwrapped)) {
      let isSystemRole = false;
      let contentNode: Node | null = null;
      for (const { keyText, valueNode } of iterateKeyValues(unwrapped)) {
        if (ROLE_KEY_REGEX.test(keyText) && SYSTEM_ROLE_VALUE_REGEX.test(valueNode.text.trim())) {
          isSystemRole = true;
        } else if (CONTENT_KEY_REGEX.test(keyText)) {
          contentNode = valueNode;
        }
      }
      if (isSystemRole && contentNode) {
        results.push(contentNode);
      }
    } else if (unwrapped.type === 'tuple' || unwrapped.type === 'array' || unwrapped.type === 'list') {
      const elements = named(unwrapped);
      if (elements.length >= 2 && SYSTEM_ROLE_VALUE_REGEX.test(elements[0].text.trim())) {
        results.push(elements[1]);
      }
    }
  }
  return results;
}

function isObjectOrDictNode(node: Node): boolean {
  return (
    node.type === 'dictionary' ||
    node.type === 'object' ||
    node.type === 'array_creation_expression'
  );
}

function isListOrArrayNode(node: Node): boolean {
  return (
    node.type === 'list' ||
    node.type === 'array' ||
    node.type === 'array_creation_expression'
  );
}

function iterateKeyValues(node: Node): { keyText: string; valueNode: Node }[] {
  const entries: { keyText: string; valueNode: Node }[] = [];
  for (const child of named(node)) {
    if (child.type === 'pair') {
      const k = child.childForFieldName('key');
      const v = child.childForFieldName('value');
      if (k && v) entries.push({ keyText: k.text.trim(), valueNode: v });
    } else if (child.type === 'array_element_initializer') {
      const parts = named(child);
      if (parts.length === 2) {
        entries.push({ keyText: parts[0].text.trim(), valueNode: parts[1] });
      }
    }
  }
  return entries;
}

/**
 * 文字列リテラル AST ノードからハードコードされた API キーを検出する（OWASP LLM02 検査用）
 * 検出された場合はマスク済みのキー識別子（例: `sk-proj-...`）を返す
 */
export function detectHardcodedSecret(node: Node): string | null {
  const m = HARDCODED_API_KEY_REGEX.exec(node.text);
  if (!m) return null;
  const raw = m[1];
  return `${raw.slice(0, MASKED_SECRET_PREFIX_LENGTH)}...`;
}
