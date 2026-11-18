const { randomUUID } = require('node:crypto');

function pagePoint(token, step, selectors) {
  const key = Symbol.for('arbol-preview-drag');
  if (step === 'clear') {
    if (globalThis[key]?.token === token) delete globalThis[key];
    return;
  }
  if (step === 'prepare') {
    let endpoints;
    try { endpoints = selectors.map(selector => document.querySelectorAll(selector)); }
    catch { return { error: 'Use valid CSS selectors for the drag source and destination.' }; }
    if (endpoints.some(matches => matches.length !== 1))
      return { error: 'Each drag selector must match exactly one element.' };
    const [source, destination] = endpoints.map(matches => matches[0]);
    if (source === destination || [source, destination].some(element =>
      element.matches('iframe, frame, object, embed, input[type="file"]') ||
      !element.getClientRects().length)) {
      return { error: 'Choose two different rendered elements within this page.' };
    }
    globalThis[key] = { token, source, destination };
  }
  const drag = globalThis[key];
  if (drag?.token !== token || !drag.source.isConnected || !drag.destination.isConnected)
    return { error: 'The document or one of the drag endpoints changed.' };

  const element = step.startsWith('destination') ? drag.destination : drag.source;
  function hitPoint() {
    const width = document.documentElement.clientWidth;
    const height = document.documentElement.clientHeight;
    for (const rect of element.getClientRects()) {
      const left = Math.max(0, rect.left), right = Math.min(width, rect.right);
      const top = Math.max(0, rect.top), bottom = Math.min(height, rect.bottom);
      if (right <= left || bottom <= top) continue;
      const x = (left + right) / 2, y = (top + bottom) / 2;
      const hit = document.elementFromPoint(x, y);
      if (hit && element.contains(hit) && !hit.matches('iframe, frame, object, embed, input[type="file"]'))
        return { x, y, width };
    }
    return null;
  }
  let point = hitPoint();
  if (!point && (step === 'prepare' || step === 'destination')) {
    element.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
    point = hitPoint();
  }
  return point ?? { error: 'A drag endpoint is hidden, covered, or outside the page viewport.' };
}

async function dragInPage(contents, text, isCurrent, within) {
  const invalid = 'Use drag ["source CSS selector", "destination CSS selector"].';
  let selectors;
  try { selectors = JSON.parse(text); }
  catch { throw new Error(invalid); }
  if (!Array.isArray(selectors) || selectors.length !== 2 ||
      selectors.some(selector => typeof selector !== 'string' || !selector.trim() || selector.length > 512))
    throw new Error(invalid);

  const token = randomUUID();
  const client = contents.debugger;
  if (client.isAttached()) throw new Error('The page already has an input session.');
  let active = true, attached = false, pressed = false, releasing = false;
  const current = () => {
    if (!active || !isCurrent()) throw new Error('The active page changed during the drag.');
  };
  const evaluate = (step, args) => contents.executeJavaScriptInIsolatedWorld(1002,
    [{ code: `(${pagePoint.toString()})(...${JSON.stringify([token, step, args])})` }]);
  async function point(step, args) {
    current();
    const result = await evaluate(step, args);
    current();
    if (result.error) throw new Error(result.error);
    return result;
  }
  const mouse = (type, { x, y }, buttons, button = 'none') => {
    current();
    return client.sendCommand('Input.dispatchMouseEvent', {
      type, x, y, buttons, button, clickCount: button === 'left' ? 1 : 0,
    });
  };
  function stable(a, b) {
    if (a.x !== b.x || a.y !== b.y) throw new Error('A drag endpoint moved during the gesture.');
  }
  async function gesture() {
    const source = await point('prepare', selectors);
    client.attach();
    attached = true;
    await mouse('mouseMoved', source, 0);
    stable(source, await point('source'));
    pressed = true;
    await mouse('mousePressed', source, 1, 'left');
    const x = source.x + (source.x < source.width / 2 ? 16 : -16);
    // Chromium handles a drag that originates from its own injected mouse
    // sequence inside the page. No macOS pointer event is posted.
    await mouse('mouseMoved', { x, y: source.y }, 1, 'left');
    const destination = await point('destination');
    await mouse('mouseMoved', destination, 1, 'left');
    await mouse('mouseMoved', destination, 1, 'left');
    stable(destination, await point('destination-confirm'));
    releasing = true;
    await mouse('mouseReleased', destination, 0, 'left');
    pressed = false;
    return { dispatched: true };
  }

  try {
    return await within(gesture(), () => { active = false; });
  } catch (error) {
    if (releasing) throw new Error('The drop result is uncertain. Inspect the page before retrying.');
    throw error;
  } finally {
    active = false;
    if (attached && !contents.isDestroyed() && client.isAttached()) {
      try {
        if (pressed) await cancelDrag(client);
      } finally {
        if (!contents.isDestroyed() && client.isAttached()) client.detach();
      }
    }
    if (isCurrent()) void evaluate('clear').catch(() => {});
  }
}

async function cancelDrag(client) {
  let timer;
  try {
    await Promise.race([
      client.sendCommand('Input.cancelDragging'),
      new Promise(resolve => { timer = setTimeout(resolve, 500); }),
    ]);
  } catch {
    // A renderer or debugger that has already disconnected cannot be canceled.
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { dragInPage };
