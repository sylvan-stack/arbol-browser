/** Bounded management JSON. Detect duplicate decoded names before JSON.parse. */
export function parseStrictJson(bytes: Uint8Array, limit = 65536): unknown {
  if (!Number.isSafeInteger(limit) || limit < 1 || bytes.byteLength > limit) throw new Error('Invalid management JSON');
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  let at = 0;
  const fail = (): never => { throw new Error('Invalid management JSON'); };
  const space = (): void => { while (at < text.length && /[\x20\x09\x0a\x0d]/.test(text[at]!)) at++; };
  const string = (): string => {
    if (text[at] !== '"') return fail();
    const start = at++;
    while (at < text.length) {
      const char = text[at++]!;
      if (char === '"') {
        const result: unknown = JSON.parse(text.slice(start, at));
        return typeof result === 'string' ? result : fail();
      }
      if (char === '\\') { if (at >= text.length) return fail(); at++; }
      else if (char.charCodeAt(0) < 0x20) return fail();
    }
    return fail();
  };
  const value = (depth: number): void => {
    if (depth > 128) return fail();
    space();
    if (text[at] === '"') { string(); return; }
    if (text[at] === '{') {
      at++; space();
      const keys = new Set<string>();
      if (text[at] === '}') { at++; return; }
      for (;;) {
        space(); const key = string();
        if (keys.has(key)) return fail();
        keys.add(key); space();
        if (text[at++] !== ':') return fail();
        value(depth + 1); space();
        const delimiter = text[at++];
        if (delimiter === '}') return;
        if (delimiter !== ',') return fail();
      }
    }
    if (text[at] === '[') {
      at++; space();
      if (text[at] === ']') { at++; return; }
      for (;;) {
        value(depth + 1); space();
        const delimiter = text[at++];
        if (delimiter === ']') return;
        if (delimiter !== ',') return fail();
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));
    if (!token) return fail();
    at += token[0].length;
  };
  value(0); space();
  if (at !== text.length) return fail();
  return JSON.parse(text) as unknown;
}
