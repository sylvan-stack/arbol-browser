import type { WindowHost } from './windows.js';
import { SeqoyaPageRefusal, readSeqoyaPage, type SeqoyaProvider } from './seqoya-page.js';

export interface SeqoyaUsageWindow {
  minutes: 300 | 10080 | 43200;
  usedPercent: number;
  resetAt?: string;
  creditsTotal?: number;
}

export interface SeqoyaUsage {
  observedAt: string;
  windows: SeqoyaUsageWindow[];
  plan?: 'plus' | 'pro' | 'pro-200' | 'max' | 'team' | 'enterprise';
  piCapPercent?: number;
  resetCredits?: { available: number; expiries: string[] };
  deepseekBalance?: string;
  mimoCredits?: { total: string; remaining: string; resetAt: string };
  minimax?: {
    activePlan: boolean;
    credits: string;
    llmTokens: string;
    period: 'Today' | 'Last 7 days' | 'Last 30 days';
    cacheHitPercent?: number;
  };
}

/** The host evaluates this self-contained reader in an isolated world. Only
 * the fixed typed return value crosses from the operation-owned document. */
function extractUsage(provider: SeqoyaProvider, observedAt: string): SeqoyaUsage | null {
  const when = Date.parse(observedAt);
  const dialog = provider === 'claude/anthropic';
  const chatgpt = provider === 'codex/chatgpt' || provider === 'pi/chatgpt';
  const roots = [...document.querySelectorAll<HTMLElement>(dialog ? '[role="dialog"]' : 'main')];
  const shown = (node: HTMLElement) => {
    const style = getComputedStyle(node);
    return node.getClientRects().length > 0 && style.visibility === 'visible' && style.display !== 'none';
  };
  const text = (node: HTMLElement) => node.innerText.trim().replace(/\s+/g, ' ');
  const labels = 'h1,h2,h3,h4,h5,dt,label,span,p,div,strong,button';
  const visibleLeaves = (scope: HTMLElement) => [...scope.querySelectorAll<HTMLElement>(labels)]
    .slice(0, 12_000).filter(node => node.childElementCount === 0 && shown(node));
  const overview = () => {
    const headings = [...document.querySelectorAll<HTMLElement>('h1,h2,h3,h4,h5,h6,[role="heading"]')]
      .slice(0, 256).filter(node => shown(node) && text(node) === 'Usage');
    if (headings.length !== 1) return undefined;
    let scope = headings[0]?.parentElement;
    for (let depth = 0; scope && scope !== document.body && depth < 8; depth++, scope = scope.parentElement) {
      const names = new Set(visibleLeaves(scope).map(text));
      if (names.has('Plan limits') && (names.has('ChatGPT Plus') || names.has('ChatGPT Pro') || names.has('ChatGPT Pro 200')))
        return scope;
    }
    return undefined;
  };
  const scopes = roots.filter(shown);
  const root = (chatgpt ? overview() : undefined) ?? (scopes.length === 1 ? scopes[0] : undefined);
  if (!root) return null;
  if (root.querySelector('input[type="password"],input[autocomplete="one-time-code"]')) return null;
  const result: SeqoyaUsage = { observedAt, windows: [] };
  const leaves = visibleLeaves(root);
  const contains = (value: string) => leaves.some(node => text(node) === value);
  const around = <T>(label: string, parse: (lines: string[]) => T | undefined, region = root): T | undefined => {
    for (const anchor of leaves) {
      if (!region.contains(anchor) || text(anchor) !== label) continue;
      let block: HTMLElement | null = anchor.parentElement;
      for (let depth = 0; block && region.contains(block) && block !== root && depth < 5; depth++, block = block.parentElement) {
        const value = block.innerText;
        if (value.length > 4096) break;
        const lines = value.split('\n').map(line => line.trim().replace(/\s+/g, ' ')).filter(Boolean);
        const afterLabel = (items: string[]) => {
          const start = items.indexOf(label);
          return start >= 0 && items.lastIndexOf(label) === start ? parse(items.slice(start + 1)) : undefined;
        };
        // Inline quota labels may have separate visible elements without
        // line breaks in the surrounding card's innerText.
        const parsed = afterLabel(lines) ?? (chatgpt
          ? afterLabel(leaves.filter(node => block?.contains(node)).map(text)) : undefined);
        if (parsed !== undefined) return parsed;
      }
    }
    return undefined;
  };
  const percentage = (value: string | undefined, suffix = ''): number | undefined => {
    if (!value?.endsWith('%' + suffix)) return undefined;
    const raw = value.slice(0, value.length - suffix.length - 1);
    if (!/^\d{1,3}(?:\.\d{1,6})?$/.test(raw)) return undefined;
    const number = Number(raw);
    return number <= 100 ? number : undefined;
  };
  const iso = (stamp: number): string | undefined =>
    Number.isFinite(stamp) && stamp >= when - 1_000 && stamp - when <= 366 * 86_400_000
      ? new Date(stamp).toISOString() : undefined;
  const countdown = (line: string | undefined): string | undefined => {
    const match = line?.match(/^Resets in\s+(?:(\d{1,2})d\s*)?(?:(\d{1,3})\s*(?:hr|h)\s*)?(?:(\d{1,3})\s*(?:min|m))?$/);
    if (!match) return undefined;
    const minutes = Number(match[1] ?? 0) * 1440 + Number(match[2] ?? 0) * 60 + Number(match[3] ?? 0);
    return minutes > 0 && minutes <= 35 * 1440 ? iso(when + minutes * 60_000) : undefined;
  };
  const localClock = (line: string | undefined): string | undefined => {
    const match = line?.match(/^Resets (at|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday) (\d{1,2}):(\d{2}) ([AP]M)$/);
    if (!match || Number(match[2]) < 1 || Number(match[2]) > 12 || Number(match[3]) > 59) return undefined;
    const date = new Date(when);
    date.setHours(Number(match[2]) % 12 + (match[4] === 'PM' ? 12 : 0), Number(match[3]), 0, 0);
    const day = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'].indexOf(match[1] ?? '');
    const offset = day < 0 ? 0 : (day - date.getDay() + 7) % 7;
    date.setDate(date.getDate() + (offset || (date.getTime() <= when ? (day < 0 ? 1 : 7) : 0)));
    return iso(date.getTime());
  };
  const addWindow = (minutes: SeqoyaUsageWindow['minutes'], usedPercent: number, resetAt?: string) => {
    result.windows.push({ minutes, usedPercent, ...(resetAt ? { resetAt } : {}) });
  };
  const amount = (input: string | undefined): string | undefined => {
    const raw = input?.replaceAll(',', '');
    return raw && /^\d{1,18}(?:\.\d{1,8})?$/.test(raw) ? raw : undefined;
  };
  const expiry = (line: string): string | undefined => {
    const match = line.match(/^Expires ([A-Z][a-z]{2} \d{1,2}), (\d{1,2}:\d{2} [AP]M) GMT([+-])(\d{1,2})(?::(\d{2}))?$/);
    if (!match || Number(match[4]) > 14 || Number(match[5] ?? 0) > 59) return undefined;
    const zone = 'GMT' + match[3] + match[4]?.padStart(2, '0') + (match[5] ?? '00');
    const year = new Date(when).getUTCFullYear();
    const date = (value: number) => Date.parse(`${match[1]} ${value} ${match[2]} ${zone}`);
    const current = date(year);
    return iso(when - current > 180 * 86_400_000 ? date(year + 1) : current);
  };
  const creditInventory = (rows: string[], reported: boolean) => {
    const cutoff = rows.indexOf(reported ? 'Credits' : 'Usage credits');
    const section = cutoff < 0 ? rows : rows.slice(0, cutoff);
    const expiries = section.map(expiry).filter((value): value is string => value !== undefined);
    const index = section.indexOf('Available');
    if (reported ? index < 0 || !/^\d{1,3}$/.test(section[index + 1] ?? '') : expiries.length === 0) return undefined;
    const available = reported ? Number(section[index + 1]) : expiries.length;
    return Number.isInteger(available) && available >= expiries.length && available <= 100
      ? { available, expiries } : undefined;
  };

  switch (provider) {
    case 'codex/chatgpt':
    case 'pi/chatgpt': {
      const plus = contains('ChatGPT Plus');
      const pro200 = contains('ChatGPT Pro 200');
      const pro = pro200 || contains('ChatGPT Pro');
      if (plus === pro) return null;
      result.plan = plus ? 'plus' : pro200 && provider === 'codex/chatgpt' ? 'pro-200' : 'pro';
      for (const [minutes, label] of [[300, '5-hour limit'], [10080, 'Weekly limit']] as const) {
        const reading = around(label, rows => {
          const nextSection = rows.findIndex(row =>
            /^(?:5-hour limit|Weekly limit|Usage limit resets|Credits|Connected App Limits)(?:\s|$)/.test(row));
          const card = nextSection < 0 ? rows : rows.slice(0, nextSection);
          const resets = card.map(countdown).filter((value): value is string => value !== undefined);
          const remaining = card.map(line => percentage(line, ' left')).filter((value): value is number => value !== undefined);
          return resets.length === 1 && remaining.length === 1 ? { reset: resets[0], left: remaining[0]! } : undefined;
        });
        if (reading) addWindow(minutes, 100 - reading.left, reading.reset);
      }
      if (provider === 'pi/chatgpt') {
        const cap = around('Connected App Limits', rows => {
          const pi = rows.indexOf('Pi');
          return pi >= 0 ? percentage(rows[pi + 1]) : undefined;
        });
        if (cap === undefined) return null;
        result.piCapPercent = cap;
      } else {
        const resets = around('Usage limit resets', rows => creditInventory(rows, true));
        if (resets) result.resetCredits = resets;
      }
      break;
    }
    case 'claude/anthropic': {
      const plan = around('Your usage', rows => {
        const value = rows[0]?.toLowerCase();
        return value === 'pro' || value === 'max' || value === 'team' || value === 'enterprise' ? value : undefined;
      });
      if (!plan) return null;
      result.plan = plan;
      for (const [minutes, label] of [[300, 'Current session'], [10080, 'This week']] as const) {
        const reading = around(label, rows => {
          const reset = localClock(rows[0]);
          const used = percentage(rows[1], ' used');
          return reset && used !== undefined ? { reset, used } : undefined;
        });
        if (reading) addWindow(minutes, reading.used, reading.reset);
      }
      const resets = around('Limit resets', rows => creditInventory(rows, false));
      if (resets) result.resetCredits = resets;
      break;
    }
    case 'pi/kimi-coding': {
      for (const [minutes, label] of [[43200, 'Monthly usage'], [300, 'Rate limit details']] as const) {
        const reading = around(label, rows => {
          const used = rows.map(line => percentage(line)).find(value => value !== undefined);
          const reset = rows.map(countdown).find(Boolean);
          return used !== undefined && reset ? { used, reset } : undefined;
        });
        if (reading) addWindow(minutes, reading.used, reading.reset);
      }
      break;
    }
    case 'pi/deepseek': {
      const balance = around('Topped-up balance', rows => {
        const dollar = rows[rows.indexOf('USD') - 1];
        return dollar?.startsWith('$') ? amount(dollar.slice(1)) : undefined;
      });
      return balance === undefined ? null : { ...result, deepseekBalance: balance };
    }
    case 'mimo/xiaomi': {
      if (!contains('Pro Monthly Plan')) return null;
      const pair = around('Current plan usage', ([line]) => {
        const split = line?.match(/^([\d,]+) \/ ([\d,]+)$/);
        const used = amount(split?.[1]);
        const total = amount(split?.[2]);
        return used && total && Number(used) <= Number(total) && Number(total) > 0 && Number(total) <= 10 ** 15
          ? { total, remaining: String(Number(total) - Number(used)) } : undefined;
      });
      const until = leaves.map(text).find(line => /^Valid until \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \(UTC\)$/.test(line));
      const resetAt = until && iso(Date.parse(until.slice(12, -6).replace(' ', 'T') + 'Z'));
      return pair && resetAt ? { ...result, plan: 'pro', mimoCredits: { ...pair, resetAt } } : null;
    }
    case 'pi/zai': {
      if (!contains('Usage Statistics')) return null;
      for (const [minutes, label] of [[300, '5-hour limit'], [10080, 'Weekly limit']] as const) {
        const reading = around(label, rows => {
          const measured = percentage(rows[1] === '%' ? rows[0] + '%' : rows[0]);
          if (measured === undefined) return undefined;
          const date = rows.find(line => /^Reset Time: (?:\d{4}-\d{2}-\d{2} )?\d{2}:\d{2}$/.test(line))?.slice(12);
          const today = new Date(when + 8 * 3_600_000).toISOString().slice(0, 10);
          const clockOnly = date?.length === 5;
          let stamp = date ? Date.parse((clockOnly ? today + 'T' + date : date.replace(' ', 'T')) + ':00+08:00') : NaN;
          if (clockOnly && stamp <= when) stamp += 86_400_000;
          const resetAt = !clockOnly || stamp - when <= 301 * 60_000 ? iso(stamp) : undefined;
          if (minutes === 10080 && !resetAt) return undefined;
          const credit = (line: string | undefined) => {
            const match = line?.match(/^([\d,.]+)([KMB]?)$/);
            const number = amount(match?.[1]);
            const factor = { '': 1, K: 1000, M: 10 ** 6, B: 10 ** 9 }[match?.[2] ?? ''];
            return number && factor ? { scaled: factor !== 1, value: Number(number) * factor } : undefined;
          };
          const usedCredits = credit(rows[1] === '%' && rows[2] === 'Used' && rows[3] === 'Credits' ? rows[4] : undefined);
          const total = credit(rows[5] === '/' ? rows[6] : undefined);
          if (!usedCredits || !total || usedCredits.value > total.value || total.value <= 0 || total.value > 10 ** 12) return undefined;
          const used = measured === 0 || (!usedCredits.scaled && !total.scaled) ? usedCredits.value / total.value * 100 : measured;
          return { used, resetAt, creditsTotal: Number.isInteger(total.value) ? total.value : undefined };
        });
        if (reading) result.windows.push({ minutes, usedPercent: reading.used,
          ...(reading.resetAt ? { resetAt: reading.resetAt } : {}),
          ...(reading.creditsTotal === undefined ? {} : { creditsTotal: reading.creditsTotal }) });
      }
      break;
    }
    case 'pi/minimax': {
      const activePlan = contains('Plan Details');
      if (!activePlan && !contains('Not subscribed to M Plan')) return null;
      const credits = around('Credits', rows => amount(rows[rows.indexOf('credits') - 1]));
      const overview = root.querySelector<HTMLElement>('section[aria-labelledby="plan-usage-overview"]');
      const selected = overview?.querySelector<HTMLElement>('[aria-pressed="true"]');
      const period = selected && shown(selected) ? text(selected) : undefined;
      if (!overview) return null;
      const llmTokens = around('LLM usage', rows => rows[1] === 'Token' && /^\d[\d,.]{0,25}[KMBT]?$/.test(rows[0] ?? '') ? rows[0] : undefined, overview);
      if (!credits || !overview || !llmTokens || (period !== 'Today' && period !== 'Last 7 days' && period !== 'Last 30 days')) return null;
      const cacheHitPercent = around('Cache hit rate', ([value]) => percentage(value), overview);
      result.minimax = { activePlan, credits, llmTokens, period, ...(cacheHitPercent === undefined ? {} : { cacheHitPercent }) };
      if (activePlan) {
        for (const [minutes, label] of [[300, '5-hour limit'], [10080, 'Weekly limit']] as const) {
          const reading = around(label, rows => {
            const reset = countdown(rows[0]);
            const pair = (rows[reset ? 1 : 0] ?? '').match(/^Total quota (\d{1,3}%) · (\d{1,3}%) used$/);
            const total = percentage(pair?.[1]);
            const used = percentage(pair?.[2]);
            return total && used !== undefined && used <= total ? { reset, used: used / total * 100 } : undefined;
          });
          if (reading) addWindow(minutes, reading.used, reading.reset);
        }
      }
      break;
    }
  }
  return result.windows.length || result.minimax ? result : null;
}

export function captureSeqoyaUsage(host: WindowHost, provider: SeqoyaProvider, deadline: number,
  signal: AbortSignal, ownerBusy: () => boolean): Promise<SeqoyaUsage> {
  return readSeqoyaPage(host, provider, deadline, signal, ownerBusy, async (contents, check) => {
    for (let attempt = 0; attempt < 16; attempt++) {
      check();
      const stamp = new Date().toISOString();
      const code = `(${extractUsage.toString()})(${JSON.stringify(provider)},${JSON.stringify(stamp)})`;
      const result: SeqoyaUsage | null = await contents.executeJavaScriptInIsolatedWorld(998, [{ code }]);
      check();
      if (result && JSON.stringify(result).length <= 16_384) return result;
      await new Promise<void>(resolve => setTimeout(resolve, 500));
    }
    throw new SeqoyaPageRefusal('dashboard_unavailable');
  });
}
