import type { T } from './taint';

/**
 * レキシカルスコープの変数管理
 * 内側のスコープ（関数・ブロック）は外側を parent として参照し、不要なコピーを行わない
 */
export class Scope {
  private readonly vars = new Map<string, T>();

  constructor(
    readonly functionName: string,
    private readonly parent: Scope | null = null,
  ) {}

  has(name: string): boolean {
    return this.vars.has(name) || (this.parent?.has(name) ?? false);
  }

  get(name: string): T {
    if (this.vars.has(name)) return this.vars.get(name) ?? null;
    return this.parent ? this.parent.get(name) : null;
  }

  set(name: string, t: T): void {
    this.vars.set(name, t);
  }
}

