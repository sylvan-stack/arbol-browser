const { app, BaseWindow, WebContentsView, session } = require('electron');
const { createInterface } = require('node:readline');

const maximumTabs = 8;
const actionTimeout = 15000;
const preferences = Object.freeze({
  sandbox: true, contextIsolation: true, nodeIntegration: false,
  backgroundThrottling: false, devTools: false, webSecurity: true,
});
const localPaths = {
  userData: process.env.ARBOL_DEMO_USER_DATA, sessionData: process.env.ARBOL_DEMO_SESSION_DATA,
  clipboard: process.env.ARBOL_DEMO_CLIPBOARD, framework: process.env.ARBOL_DEMO_FRAMEWORK,
};

function write(result) {
  const json = JSON.stringify(result).replace(/[\x7f-\x9f\u2028-\u202e\u2066-\u2069]/g,
    character => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'));
  process.stdout.write(json + '\n');
}

function address(value) {
  if (!value || value.length > 8192 || /[\x00-\x20\x7f]/.test(value))
    throw new Error('Enter an HTTP or HTTPS address.');
  let parsed;
  try { parsed = new URL(value); }
  catch { throw new Error('Enter an HTTP or HTTPS address.'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password)
    throw new Error('Enter an HTTP or HTTPS address without embedded credentials.');
  return parsed.href;
}

function options(args) {
  const config = { fixture: false, visible: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--visible' && !config.visible) config.visible = true;
    else if (args[i] === '--fixture' && !config.fixture) config.fixture = true;
    else if (args[i] === '--url' && !config.url) config.url = address(args[++i]);
    else throw new Error('Use --fixture, --url URL, or --visible. Run npm run demo -- --help for usage.');
  }
  if (config.fixture && config.url) throw new Error('Choose --fixture or --url.');
  return config;
}

function sessionPolicy(website) {
  website.setPermissionRequestHandler((_contents, _permission, reply) => reply(false));
  website.setPermissionCheckHandler(() => false);
  website.setDevicePermissionHandler(() => false);
  website.setDisplayMediaRequestHandler((_request, reply) => reply({}));
  website.on('will-download', event => event.preventDefault());
}

function operate(operation, selector, value) {
  const target = document.querySelector(selector || 'body');
  if (!target) return { error: 'No element matches the selector.' };
  const textField = target instanceof HTMLTextAreaElement ||
    (target instanceof HTMLInputElement && ['text', 'search', 'email', 'tel', 'url', 'number'].includes(target.type));
  if (operation === 'inspect') {
    const text = typeof target.innerText === 'string' ? target.innerText : target.textContent;
    return { title: document.title.slice(0, 200), text: (text || '').slice(0, 1600),
      ...(textField ? { value: target.value.slice(0, 1600) } : {}) };
  }
  if (operation === 'fill') {
    if (!textField || target.disabled || target.readOnly) return { error: 'Choose an editable ordinary text field.' };
    const prototype = target instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(prototype, 'value').set.call(target, value);
    target.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    target.dispatchEvent(new Event('change', { bubbles: true }));
    return { value: target.value.slice(0, 1600) };
  }
  const clickable = target instanceof HTMLButtonElement || target instanceof HTMLAnchorElement ||
    (target instanceof HTMLInputElement && ['button', 'checkbox', 'radio', 'reset', 'submit'].includes(target.type));
  if (!clickable || target.disabled) return { error: 'Choose an enabled button, link, checkbox or radio button.' };
  target.click();
  return { clicked: true };
}

function within(work, onTimeout = () => {}) {
  let timer;
  return Promise.race([work, new Promise((_, reject) => {
    timer = setTimeout(() => {
      onTimeout();
      reject(new Error('The page operation timed out.'));
    }, actionTimeout);
  })]).finally(() => clearTimeout(timer));
}

async function main(config, clipboard) {
  await app.whenReady();
  clipboard.install(localPaths.framework);
  clipboard.check();
  const website = session.fromPartition('arbol-browser-preview');
  sessionPolicy(website);
  const window = new BaseWindow({ width: 1100, height: 780, minWidth: 360, minHeight: 260,
    title: 'Arbol Browser Preview', show: false });
  const tabs = new Map();
  let selected, nextTab = 0, closing = false;
  let pageWork = Promise.resolve(), presentationWork = Promise.resolve();
  let fixture, input;
  const cadence = setInterval(clipboard.check, 1000);
  cadence.unref();

  function layout() {
    const { width, height } = window.getContentBounds();
    for (const { view } of tabs.values()) view.setBounds({ x: 0, y: 0, width, height });
  }
  function select(tab) {
    if (!tab) throw new Error('That preview tab does not exist.');
    if (selected !== tab) {
      selected?.view.setVisible(false);
      selected = tab;
      tab.view.setVisible(true);
      if (window.isVisible()) tab.view.webContents.focus();
    }
  }
  function newTab() {
    clipboard.check();
    if (tabs.size >= maximumTabs) throw new Error('The preview allows eight open tabs.');
    const view = new WebContentsView({ webPreferences: { ...preferences, session: website } });
    const contents = view.webContents;
    const tab = { id: ++nextTab, view };
    const checkNavigation = event => {
      if (!event.isMainFrame && /^(about:|data:|blob:)/.test(event.url)) return;
      try { address(event.url); }
      catch { event.preventDefault(); }
    };
    contents.setWindowOpenHandler(() => ({ action: 'deny' }));
    contents.on('will-frame-navigate', checkNavigation);
    contents.on('will-redirect', checkNavigation);
    contents.on('will-attach-webview', event => event.preventDefault());
    contents.on('will-prevent-unload', event => event.preventDefault());
    window.contentView.addChildView(view);
    tabs.set(tab.id, tab);
    layout();
    select(tab);
    return tab;
  }
  function describe(tab) {
    const contents = tab.view.webContents;
    return { tab: tab.id, url: contents.getURL().slice(0, 8192), contents: contents.id,
      renderer: contents.getOSProcessId(), history: contents.navigationHistory.getAllEntries().length };
  }
  function status() {
    return { visible: window.isVisible(), dock: app.dock.isVisible(), current: describe(selected) };
  }
  async function show(visible) {
    if (visible) {
      app.setActivationPolicy('regular');
      await app.dock.show();
      if (closing) return;
      window.show();
      selected.view.webContents.focus();
    } else {
      window.hide();
      app.dock.hide();
      app.setActivationPolicy('accessory');
    }
    return status();
  }
  function quit() {
    if (closing) return;
    closing = true;
    clearInterval(cadence);
    input?.close();
    for (const { view } of tabs.values()) view.webContents.close();
    window.destroy();
    fixture?.close();
    write({ event: 'closed' });
    app.quit();
  }
  async function navigate(tab, url) {
    const contents = tab.view.webContents;
    try { await within(contents.loadURL(url), () => { if (!contents.isDestroyed()) contents.stop(); }); }
    catch { throw new Error('The page could not be loaded. Check the address, network and certificate.'); }
    return describe(tab);
  }
  async function action(command, argumentsText) {
    clipboard.check();
    switch (command) {
      case 'go': return navigate(selected, address(argumentsText));
      case 'open': {
        const url = address(argumentsText);
        return navigate(newTab(), url);
      }
      case 'tabs': return { selected: selected.id, tabs: [...tabs.values()].map(describe) };
      case 'tab': select(tabs.get(Number(argumentsText))); return status();
      case 'inspect':
      case 'fill':
      case 'click': {
        let selector = argumentsText;
        let value;
        if (command === 'fill') [selector, value] = /^([^ ]+) (.*)$/.exec(argumentsText)?.slice(1) ?? [];
        if ((command !== 'inspect' && !selector) || selector?.length > 512 || value?.length > 1600)
          throw new Error('Use inspect [selector], fill selector text, or click selector.');
        const contents = selected.view.webContents;
        if (contents.isLoadingMainFrame() || !contents.getURL()) throw new Error('Navigate to a loaded page first.');
        const args = JSON.stringify([command, selector, value]);
        let result;
        try {
          result = await within(contents.executeJavaScriptInIsolatedWorld(1001,
            [{ code: '(' + operate.toString() + ')(...' + args + ')' }]));
        } catch { throw new Error('The page could not complete the action.'); }
        if (result.error) throw new Error(result.error);
        return result;
      }
      default: throw new Error('Commands: status, show, hide, go URL, open URL, tabs, tab ID, inspect [selector], fill selector text, click selector, quit.');
    }
  }
  function line(text) {
    if (closing || !text.trim()) return;
    if (Buffer.byteLength(text) > 10000) { write({ ok: false, error: 'Command is too long.' }); return; }
    const [command] = text.trimStart().split(/ +/, 1);
    if (command === 'quit') { quit(); return; }
    const args = text.trimStart().slice(command.length).trimStart();
    const presentation = ['show', 'hide', 'status'].includes(command);
    const pending = presentation ? presentationWork : pageWork;
    const work = pending.then(async () => {
      if (closing) return;
      try {
        const result = presentation ? command === 'status' ? status() : await show(command === 'show') :
          await action(command, args);
        if (!closing) write({ command, ok: true, result });
      } catch (error) { if (!closing) write({ command, ok: false, error: String(error.message).slice(0, 290) }); }
    });
    if (presentation) presentationWork = work;
    else pageWork = work;
  }

  window.on('resize', layout);
  window.on('close', event => { event.preventDefault(); quit(); });
  newTab();
  app.dock.hide();
  if (config.visible) await show(true);
  if (config.fixture) {
    fixture = await require('./fixture.cjs').startFixture();
    config.url = fixture.url;
  }
  write({ event: 'ready', ...status(), ...(fixture ? { fixture: fixture.url } : {}) });
  if (config.url) pageWork = navigate(selected, config.url).then(result => write({ command: 'go', ok: true, result }),
    error => write({ command: 'go', ok: false, error: error.message }));
  input = createInterface({ input: process.stdin, terminal: false, crlfDelay: Infinity });
  input.on('line', line);
  input.once('close', () => { void Promise.allSettled([pageWork, presentationWork]).then(quit); });
}

try {
  if (process.type !== 'browser' || process.versions.electron !== '45.3.2' ||
      Object.values(localPaths).some(path => !path)) throw new Error('Launch the preview with npm run demo.');
  const config = options(process.argv.slice(2));
  app.setName('Arbol Browser Preview');
  app.setPath('userData', localPaths.userData);
  app.setPath('sessionData', localPaths.sessionData);
  app.setActivationPolicy('accessory');
  void main(config, require(localPaths.clipboard)).catch(error => {
    write({ event: 'failed', error: String(error.message).slice(0, 290) });
    app.exit(1);
  });
} catch (error) {
  write({ event: 'failed', error: String(error.message).slice(0, 290) });
  app.exit(1);
}
