const { randomUUID } = require('node:crypto');

function dragInDocument(token, selectors) {
  const key = Symbol.for('arbol-preview-drag');
  const unusable = 'A drag endpoint is hidden, covered, or outside the current document.';
  const nativeElement = 'iframe, frame, object, embed, input[type="file"]';

  if (selectors) {
    delete globalThis[key];
    let matches;
    try { matches = selectors.map(selector => document.querySelectorAll(selector)); }
    catch { return { error: 'Use valid CSS selectors for the drag source and destination.' }; }
    if (matches.some(elements => elements.length !== 1))
      return { error: 'Each drag selector must match exactly one element.' };
    const [source, destination] = matches.map(elements => elements[0]);
    if (source === destination || [source, destination].some(element =>
      element.matches(nativeElement) || !element.getClientRects().length)) {
      return { error: 'Choose two different rendered elements within this page.' };
    }
    globalThis[key] = { token, source, destination };
    return { prepared: true };
  }

  const drag = globalThis[key];
  if (drag?.token !== token) return { error: 'The document changed before the drag.' };
  delete globalThis[key];
  const { source, destination } = drag;

  const connected = element => element.isConnected && element.ownerDocument === document;
  function hitPoint(element) {
    if (!connected(element)) return null;
    const { clientWidth, clientHeight } = document.documentElement;
    for (const rect of element.getClientRects()) {
      const left = Math.max(0, rect.left), right = Math.min(clientWidth, rect.right);
      const top = Math.max(0, rect.top), bottom = Math.min(clientHeight, rect.bottom);
      if (right <= left || bottom <= top) continue;
      const clientX = (left + right) / 2, clientY = (top + bottom) / 2;
      const hit = document.elementFromPoint(clientX, clientY);
      if (hit && element.contains(hit) && !hit.matches(nativeElement)) return { clientX, clientY };
    }
    return null;
  }

  function point(element) {
    const hit = hitPoint(element);
    if (hit || !connected(element)) return hit;
    element.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
    return hitPoint(element);
  }

  // Check both endpoints before sending a down or dragstart event. A second
  // source check accounts for any scroll that exposed the destination.
  if (!point(destination)) return { error: unusable };
  const start = point(source);
  if (!start) return { error: unusable };

  const eventOptions = { bubbles: true, cancelable: true, composed: true };
  if (source.draggable) {
    const dataTransfer = new DataTransfer();
    const emit = (element, type, at) => element.dispatchEvent(
      new DragEvent(type, { ...eventOptions, ...at, dataTransfer }));
    if (!emit(source, 'dragstart', start)) return { error: 'The page canceled the drag.' };
    let end = start;
    try {
      emit(source, 'drag', start);
      end = point(destination);
      if (!connected(source) || !end) return { error: unusable };
      emit(destination, 'dragenter', end);
      if (emit(destination, 'dragover', end)) return { error: 'The page did not accept the drop.' };
      if (!connected(source) || !hitPoint(destination)) return { error: unusable };
      if (dataTransfer.files.length) return { error: 'File drops are unavailable in this command.' };
      emit(destination, 'drop', end);
    } finally {
      if (connected(source)) emit(source, 'dragend', end ?? start);
    }
    return { dispatched: true };
  }

  function pointer(element, type, at, buttons) {
    return element.dispatchEvent(new PointerEvent('pointer' + type, {
      ...eventOptions, ...at, buttons, button: type === 'move' ? -1 : 0,
      pointerId: 1, pointerType: 'mouse', isPrimary: true, pressure: buttons ? 0.5 : 0,
    }));
  }
  function mouse(element, type, at, buttons) {
    element.dispatchEvent(new MouseEvent('mouse' + type, { ...eventOptions, ...at, buttons, button: 0 }));
  }

  // Native pointer capture is not available to a page-local event sequence.
  const compatibility = pointer(source, 'down', start, 1);
  if (compatibility) mouse(source, 'down', start, 1);
  let released = false;
  try {
    const end = point(destination);
    if (!connected(source) || !end) return { error: unusable };
    for (const fraction of [0.35, 0.7, 1]) {
      const at = {
        clientX: start.clientX + (end.clientX - start.clientX) * fraction,
        clientY: start.clientY + (end.clientY - start.clientY) * fraction,
      };
      const hit = document.elementFromPoint(at.clientX, at.clientY);
      if (!hit || hit.matches(nativeElement)) continue;
      pointer(hit, 'move', at, 1);
      if (compatibility && connected(hit)) mouse(hit, 'move', at, 1);
    }
    const finish = hitPoint(destination);
    if (!connected(source) || !finish) return { error: unusable };
    pointer(destination, 'up', finish, 0);
    if (compatibility && connected(destination)) mouse(destination, 'up', finish, 0);
    released = true;
    return { dispatched: true };
  } finally {
    if (!released && connected(source)) {
      pointer(source, 'cancel', start, 0);
      if (compatibility && connected(source)) mouse(source, 'up', start, 0);
    }
  }
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
  const evaluate = args => contents.executeJavaScriptInIsolatedWorld(1002,
    [{ code: '(' + dragInDocument.toString() + ')(...' + JSON.stringify([token, args]) + ')' }]);
  let active = true, started = false;
  async function gesture() {
    if (!isCurrent()) throw new Error('The active page changed before the drag.');
    const prepared = await evaluate(selectors);
    if (prepared.error) throw new Error(prepared.error);
    if (!active || !isCurrent()) throw new Error('The active page changed before the drag.');
    started = true;
    return evaluate(null);
  }

  let result;
  try { result = await within(gesture(), () => { active = false; }); }
  catch (error) {
    if (started) throw new Error('The drop result is uncertain. Inspect the page before retrying.');
    throw error;
  }
  if (result.error) throw new Error(result.error);
  return result;
}

module.exports = { dragInPage };
