import type { SeqoyaUsage } from '../host/seqoya-usage.js';

export const seqoyaDestinations = {
  'codex/chatgpt': 'https://chatgpt.com/settings/usage',
  'pi/chatgpt': 'https://chatgpt.com/settings/usage',
  'claude/anthropic': 'https://claude.ai/settings/usage',
  'pi/kimi-coding': 'https://www.kimi.ai/code/console',
  'pi/deepseek': 'https://platform.deepseek.com/usage',
  'mimo/xiaomi': 'https://platform.xiaomimimo.com/console/plan-manage',
  'pi/zai': 'https://z.ai/manage-apikey/coding-plan/personal/my-plan',
  'pi/minimax': 'https://platform.minimax.io/console/usage',
} as const;

export type SeqoyaProvider = keyof typeof seqoyaDestinations;
export const seqoyaClaimPattern = /^[A-Za-z0-9_-]{43}$/;
export const seqoyaProfilePattern = /^seqoya-[0-9a-f]{32}$/;
export const seqoyaUsageLimit = 32 * 1024;

export function isSeqoyaProvider(value: unknown): value is SeqoyaProvider {
  return typeof value === 'string' && Object.hasOwn(seqoyaDestinations, value);
}

export interface SeqoyaParameters { provider: SeqoyaProvider; claim: string }
export interface SeqoyaRequest { wire: 1; id: string; method: 'seqoya-usage'; params: SeqoyaParameters }
type SeqoyaRefusal = 'deferred' | 'dashboard_unavailable' | 'authentication_required';
export type SeqoyaResult = { status: 'read'; reading: SeqoyaUsage } | { status: SeqoyaRefusal };
export interface SeqoyaReply { wire: 1; id: string; method: 'seqoya-usage-result'; result: SeqoyaResult }

export function plain(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function isSeqoyaRequest(value: unknown): value is SeqoyaRequest {
  return plain(value) && Object.keys(value).length === 4 && value.wire === 1 && value.method === 'seqoya-usage' &&
    typeof value.id === 'string' && /^req_[A-Za-z0-9_-]{22}$/.test(value.id) && plain(value.params) &&
    Object.keys(value.params).length === 2 && isSeqoyaProvider(value.params.provider) &&
    typeof value.params.claim === 'string' && seqoyaClaimPattern.test(value.params.claim);
}

export function isSeqoyaResult(value: unknown): value is SeqoyaResult {
  if (!plain(value)) return false;
  if (value.status === 'read') {
    return Object.keys(value).length === 2 && plain(value.reading) && typeof value.reading.observedAt === 'string' &&
      value.reading.observedAt.length <= 32 && Array.isArray(value.reading.windows) && value.reading.windows.length <= 3 &&
      JSON.stringify(value).length < seqoyaUsageLimit - 1024;
  }
  return Object.keys(value).length === 1 &&
    (value.status === 'deferred' || value.status === 'dashboard_unavailable' || value.status === 'authentication_required');
}

export function isSeqoyaReply(value: unknown): value is SeqoyaReply {
  return plain(value) && Object.keys(value).length === 4 && value.wire === 1 && value.method === 'seqoya-usage-result' &&
    typeof value.id === 'string' && /^req_[A-Za-z0-9_-]{22}$/.test(value.id) && isSeqoyaResult(value.result);
}
