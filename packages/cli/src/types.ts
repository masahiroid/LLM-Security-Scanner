import type { Finding, TriageSummary } from '@llmscan/core';

export interface Item {
  finding: Finding;
  relativePath: string;
  triage?: TriageSummary;
}
