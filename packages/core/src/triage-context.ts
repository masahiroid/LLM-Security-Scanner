import { getParser } from './parser';
import { FUNCTION_TYPES } from './engine/ast-utils';
import type { LanguageId } from './types';

/** Bound optional AI context to the innermost function, without retaining AST nodes. */
export async function triageContextBounds(text: string, language: LanguageId, line: number, column: number): Promise<{ contextStartLine: number; contextEndLine: number }> {
  const parser = await getParser(language);
  const tree = parser.parse(text);
  try {
    let node = tree?.rootNode.descendantForPosition({ row: line, column });
    while (node && !FUNCTION_TYPES.has(node.type)) node = node.parent ?? undefined;
    return { contextStartLine: (node?.startPosition.row ?? line) + 1, contextEndLine: (node?.endPosition.row ?? line) + 1 };
  } finally { tree?.delete(); }
}
