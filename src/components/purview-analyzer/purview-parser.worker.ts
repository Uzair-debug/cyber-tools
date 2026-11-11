// Web Worker: runs the Purview log parser off the main thread so large uploads don't freeze the UI.
import { parsePurviewLogs, CustomAuditRule, ParsedAuditRecord } from './purview-parser';

export interface PurviewParseRequest {
  id: number;
  content: string;
  rules: CustomAuditRule[];
  limit: number;
}

export type PurviewParseResponse =
  | { id: number; ok: true; records: ParsedAuditRecord[]; truncated: boolean }
  | { id: number; ok: false; error: string };

self.onmessage = (event: MessageEvent<PurviewParseRequest>) => {
  const { id, content, rules, limit } = event.data;
  let response: PurviewParseResponse;
  try {
    const { records, truncated } = parsePurviewLogs(content, rules, limit);
    response = { id, ok: true, records, truncated };
  } catch (e: any) {
    response = { id, ok: false, error: e?.message || 'Error parsing audit logs' };
  }
  (self as unknown as Worker).postMessage(response);
};
