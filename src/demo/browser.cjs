const { app, BaseWindow, WebContentsView, ipcMain, protocol, session } = require('electron');
const { createHash } = require('node:crypto');
const { readFile } = require('node:fs/promises');
const { join } = require('node:path');
const { createInterface } = require('node:readline');
const { privateDirectory, validAccount, profileId, readProfiles, writeProfiles } = require('./profile-storage.cjs');
const { dragInPage } = require('./drag.cjs');

const maximumTabs = 40;
const maximumProfileTabs = 8;
const actionTimeout = 15000;
const chromeOrigin = 'arbol-preview://chrome';
const chromeEntry = chromeOrigin + '/index.html';
const chromeFiles = new Map([
  ['/index.html', 'text/html; charset=utf-8'],
  ['/chrome.mjs', 'text/javascript; charset=utf-8'],
  ['/navigation.mjs', 'text/javascript; charset=utf-8'],
  ['/navigation.css', 'text/css; charset=utf-8'],
]);
const preferences = Object.freeze({
  sandbox: true, contextIsolation: true, nodeIntegration: false,
  backgroundThrottling: false, devTools: false, webSecurity: true,
});
const localPaths = {
  userData: process.env.ARBOL_DEMO_USER_DATA, sessionData: process.env.ARBOL_DEMO_SESSION_DATA,
  clipboard: process.env.ARBOL_DEMO_CLIPBOARD, framework: process.env.ARBOL_DEMO_FRAMEWORK,
  profiles: process.env.ARBOL_DEMO_PROFILES,
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
  const { browserProfileWidth, browserToolbarHeight } = await import('./chrome/navigation.mjs');
  const website = session.fromPartition('arbol-browser-preview');
  sessionPolicy(website);
  const profilesRoot = privateDirectory(localPaths.profiles);
  const defaultProfile = { id: 'default', name: 'Default', website, tabs: new Map(), selected: null };
  const loginProfiles = new Map(readProfiles(profilesRoot).map(record => {
    const id = profileId(record);
    return [id, { ...record, id, website: null, tabs: new Map(), selected: null }];
  }));
  const chromeSession = session.fromPartition('arbol-browser-preview-chrome', { cache: false });
  sessionPolicy(chromeSession);
  chromeSession.protocol.handle('arbol-preview', async request => {
    const url = new URL(request.url);
    const type = url.host === 'chrome' && !url.search && !url.hash && chromeFiles.get(url.pathname);
    if (!type || request.method !== 'GET') return new Response(null, { status: 404 });
    return new Response(await readFile(join(__dirname, 'chrome', url.pathname.slice(1))), {
      headers: { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff' },
    });
  });
  const window = new BaseWindow({ width: 1100, height: 780, minWidth: 360, minHeight: 260,
    title: 'Arbol Browser Preview', show: false });
  const chrome = new WebContentsView({ webPreferences: { ...preferences, session: chromeSession,
    preload: join(__dirname, 'chrome/preload.cjs') } });
  chrome.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  chrome.webContents.on('will-frame-navigate', event => event.preventDefault());
  chrome.webContents.on('will-attach-webview', event => event.preventDefault());
  window.contentView.addChildView(chrome);
  const tabs = new Map();
  let activeProfile = defaultProfile, selected = null, nextTab = 0, revision = 0;
  let closing = false, quitting = false;
  let pageWork = Promise.resolve(), presentationWork = Promise.resolve();
  let selectionRevision = 0;
  let fixture, input;
  const cadence = setInterval(clipboard.check, 1000);
  cadence.unref();

  function layout() {
    const { width, height } = window.getContentBounds();
    const x = browserProfileWidth(width), y = browserToolbarHeight;
    chrome.setBounds({ x: 0, y: 0, width, height });
    for (const { view } of tabs.values())
      view.setBounds({ x, y, width: Math.max(0, width - x), height: Math.max(0, height - y) });
  }
  function profileState() {
    return {
      revision, profile: activeProfile.id, tab: selected?.id ?? null,
      profiles: [defaultProfile, ...loginProfiles.values()].map(profile => ({
        id: profile.id, name: profile.name,
        tabs: [...profile.tabs.values()].map(tab => {
          const url = tab.view.webContents.getURL();
          return { id: tab.id, site: url.startsWith('http') ? new URL(url).hostname : tab.site };
        }),
      })),
    };
  }
  function publish() {
    revision++;
    if (!closing && !chrome.webContents.isDestroyed()) chrome.webContents.send('arbol-preview:changed', profileState());
  }
  function selectProfile(profile, tab = profile.selected) {
    activeProfile = profile;
    profile.selected = tab;
    if (selected !== tab) {
      selectionRevision++;
      selected?.view.setVisible(false);
      selected = tab;
      selected?.view.setVisible(true);
    }
    publish();
  }
  function select(tab) {
    if (!tab) throw new Error('That preview tab does not exist.');
    selectProfile(tab.profile, tab);
  }
  function findProfile(id) {
    const profile = id === defaultProfile.id ? defaultProfile : loginProfiles.get(id);
    if (!profile) throw new Error('That preview profile does not exist. Use profiles to find its ID.');
    return profile;
  }
  function registerProfile(url, account, name) {
    if (!validAccount(account))
      throw new Error('Choose an account label of 1–32 lowercase letters, digits or hyphens.');
    const site = new URL(url).hostname.replace(/\.$/, '');
    const id = profileId({ site, account });
    const current = loginProfiles.get(id);
    if (current && (!name || current.name === name)) return current;
    const record = { site, account, name: name ?? id };
    const records = new Map(loginProfiles);
    records.set(id, record);
    writeProfiles(privateDirectory(profilesRoot), [...records.values()]);
    if (current) current.name = record.name;
    else loginProfiles.set(id, { ...record, id, website: null, tabs: new Map(), selected: null });
    publish();
    return loginProfiles.get(id);
  }
  function websiteSession(profile) {
    if (!profile.website) {
      privateDirectory(profilesRoot);
      const key = createHash('sha256').update(profile.site).update('\0').update(profile.account).digest('hex');
      const path = privateDirectory(join(profilesRoot, 'site-' + key));
      const website = session.fromPath(path);
      if (website.getStoragePath() !== path) throw new Error('Could not open the selected site profile.');
      sessionPolicy(website);
      profile.website = website;
    }
    return profile.website;
  }
  function newTab(profile = defaultProfile) {
    clipboard.check();
    if (tabs.size >= maximumTabs || profile.tabs.size >= maximumProfileTabs)
      throw new Error('Close a tab before opening another.');
    const view = new WebContentsView({ webPreferences: { ...preferences, session: websiteSession(profile) } });
    view.setVisible(false);
    const contents = view.webContents;
    const tab = { id: ++nextTab, view, profile, site: '', documentRevision: 0 };
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
    contents.on('did-start-navigation', ({ isMainFrame, isSameDocument }) => {
      if (isMainFrame && !isSameDocument) tab.documentRevision++;
    });
    contents.on('did-navigate', publish);
    contents.on('did-navigate-in-page', publish);
    window.contentView.addChildView(view);
    tabs.set(tab.id, tab);
    profile.tabs.set(tab.id, tab);
    layout();
    select(tab);
    return tab;
  }
  function closeTab(tab) {
    const { profile, view, id } = tab;
    const next = profile.selected === tab ?
      [...profile.tabs.values()].find(candidate => candidate !== tab) ?? null : profile.selected;
    tabs.delete(id);
    profile.tabs.delete(id);
    selectProfile(profile, next);
    window.contentView.removeChildView(view);
    view.webContents.close();
  }
  function describe(tab) {
    const contents = tab.view.webContents;
    const url = contents.getURL();
    const reportedUrl = tab.profile === defaultProfile ? url : url.split(/[?#]/, 1)[0];
    return { tab: tab.id, profile: tab.profile.id, url: reportedUrl.slice(0, 8192), contents: contents.id,
      renderer: contents.getOSProcessId(), history: contents.navigationHistory.getAllEntries().length };
  }
  function status() {
    return { visible: window.isVisible(), dock: app.dock.isVisible(), focused: window.isFocused(), profile: activeProfile.id,
      current: selected ? describe(selected) : null };
  }
  function show(visible) {
    if (visible) {
      // Electron's Dock show can activate applications while changing policy.
      if (!app.dock.isVisible()) app.setActivationPolicy('regular');
      if (!window.isVisible()) window.showInactive();
    } else {
      if (window.isVisible()) window.hide();
      if (app.dock.isVisible()) app.setActivationPolicy('accessory');
    }
    return status();
  }
  async function quit() {
    if (closing) return;
    closing = true;
    clearInterval(cadence);
    input?.close();
    ipcMain.removeHandler('arbol-preview:state');
    ipcMain.removeHandler('arbol-preview:action');
    chrome.webContents.close();
    for (const { view } of tabs.values()) view.webContents.close();
    try {
      await within(Promise.all([...loginProfiles.values()].filter(profile => profile.website).map(({ website }) => {
        website.flushStorageData();
        return website.cookies.flushStore();
      })));
    } catch {
      write({ event: 'failed', error: 'The preview could not confirm that its login data was saved.' });
      app.exit(1);
      return;
    }
    quitting = true;
    window.destroy();
    fixture?.close();
    write({ event: 'closed' });
    app.quit();
  }
  async function navigate(tab, url) {
    const contents = tab.view.webContents;
    tab.site = new URL(url).hostname;
    publish();
    try { await within(contents.loadURL(url), () => { if (!contents.isDestroyed()) contents.stop(); }); }
    catch { throw new Error('The page could not be loaded. Check the address, network and certificate.'); }
    return describe(tab);
  }
  async function action(command, argumentsText) {
    clipboard.check();
    switch (command) {
      case 'go': {
        const url = address(argumentsText);
        return navigate(selected ?? newTab(activeProfile), url);
      }
      case 'open': {
        const url = address(argumentsText);
        return navigate(newTab(), url);
      }
      case 'profile-create': {
        const [match, target, account, name] = /^(\S+)\s+(\S+)\s+(.+)$/.exec(argumentsText.trim()) ?? [];
        if (!match) throw new Error('Use profile-create URL account Display name.');
        const profile = registerProfile(address(target), account, name);
        return { id: profile.id, name: profile.name };
      }
      case 'login': {
        const [target, account = 'primary', extra] = argumentsText.trim().split(/\s+/, 3);
        if (extra) throw new Error('Use login URL [account].');
        const url = address(target);
        if (tabs.size >= maximumTabs) throw new Error('Close a tab before opening another.');
        return navigate(newTab(registerProfile(url, account)), url);
      }
      case 'profiles': return profileState();
      case 'profile': selectProfile(findProfile(argumentsText.trim())); return status();
      case 'tabs': return { selected: selected?.id ?? null, tabs: [...tabs.values()].map(describe) };
      case 'tab': select(tabs.get(Number(argumentsText))); return status();
      case 'drag': {
        const tab = selected;
        const contents = tab?.view.webContents;
        if (!contents || contents.isLoadingMainFrame() || !contents.getURL()) throw new Error('Navigate to a loaded page first.');
        const revision = selectionRevision;
        const document = tab.documentRevision;
        const frame = contents.mainFrame;
        const isCurrent = () => !closing && selected === tab && selectionRevision === revision &&
          !contents.isDestroyed() && tab.documentRevision === document && contents.mainFrame === frame &&
          !contents.isLoadingMainFrame();
        return dragInPage(contents, argumentsText, isCurrent, within);
      }
      case 'inspect':
      case 'fill':
      case 'click': {
        let selector = argumentsText;
        let value;
        if (command === 'fill') [selector, value] = /^([^ ]+) (.*)$/.exec(argumentsText)?.slice(1) ?? [];
        if ((command !== 'inspect' && !selector) || selector?.length > 512 || value?.length > 1600)
          throw new Error('Use inspect [selector], fill selector text, or click selector.');
        const contents = selected?.view.webContents;
        if (!contents || contents.isLoadingMainFrame() || !contents.getURL()) throw new Error('Navigate to a loaded page first.');
        const args = JSON.stringify([command, selector, value]);
        let result;
        try {
          result = await within(contents.executeJavaScriptInIsolatedWorld(1001,
            [{ code: '(' + operate.toString() + ')(...' + args + ')' }]));
        } catch { throw new Error('The page could not complete the action.'); }
        if (result.error) throw new Error(result.error);
        return result;
      }
      default: throw new Error('Commands: status, show, hide, go URL, open URL, login URL [account], profiles, profile ID, profile-create URL account Display name, tabs, tab ID, inspect, fill, click, drag, quit.');
    }
  }
  function line(text) {
    if (closing || !text.trim()) return;
    if (Buffer.byteLength(text) > 10000) { write({ ok: false, error: 'Command is too long.' }); return; }
    const [command] = text.trimStart().split(/ +/, 1);
    if (command === 'quit') { void quit(); return; }
    const args = text.trimStart().slice(command.length).trimStart();
    const presentation = ['show', 'hide', 'status'].includes(command);
    const pending = presentation ? presentationWork : pageWork;
    const work = pending.then(async () => {
      if (closing) return;
      try {
        const result = presentation ? command === 'status' ? status() : show(command === 'show') :
          await action(command, args);
        if (!closing) write({ command, ok: true, result });
      } catch (error) { if (!closing) write({ command, ok: false, error: String(error.message).slice(0, 290) }); }
    });
    if (presentation) presentationWork = work;
    else pageWork = work;
  }

  let resolveChrome;
  const readyChrome = new Promise(resolve => { resolveChrome = resolve; });
  function requireChrome(event) {
    if (closing || event.sender !== chrome.webContents || !event.senderFrame ||
        event.senderFrame !== chrome.webContents.mainFrame || event.senderFrame.url !== chromeEntry)
      throw new Error('The Browser control request was refused.');
  }
  ipcMain.handle('arbol-preview:state', event => {
    requireChrome(event);
    resolveChrome();
    return profileState();
  });
  ipcMain.handle('arbol-preview:action', async (event, request) => {
    requireChrome(event);
    try {
      if (!request || request.profile !== activeProfile.id || request.tab !== (selected?.id ?? null))
        return { error: 'The active profile or tab changed. Try again.' };
      clipboard.check();
      switch (request.type) {
        case 'select-profile': selectProfile(findProfile(request.value)); break;
        case 'select-tab': select(activeProfile.tabs.get(request.value)); break;
        case 'new-tab': newTab(activeProfile); break;
        case 'close-tab': {
          const tab = activeProfile.tabs.get(request.value);
          if (!tab) throw new Error('That preview tab does not exist.');
          closeTab(tab);
          break;
        }
        case 'navigate': {
          const url = address(typeof request.value === 'string' ? request.value : '');
          await navigate(selected ?? newTab(activeProfile), url);
          break;
        }
        default: return { error: 'The Browser control request was refused.' };
      }
      return { ok: true };
    } catch (error) { return { error: String(error.message).slice(0, 290) }; }
  });
  window.on('resize', layout);
  window.on('close', event => { event.preventDefault(); void quit(); });
  app.on('before-quit', event => {
    if (quitting) return;
    event.preventDefault();
    void quit();
  });
  layout();
  await within(chrome.webContents.loadURL(chromeEntry));
  await within(readyChrome);
  if (closing) return;
  newTab();
  if (config.visible) show(true);
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
  if (!app.requestSingleInstanceLock()) throw new Error('The Browser preview is already running with this data store.');
  protocol.registerSchemesAsPrivileged([{ scheme: 'arbol-preview',
    privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true } }]);
  void main(config, require(localPaths.clipboard)).catch(error => {
    write({ event: 'failed', error: String(error.message).slice(0, 290) });
    app.exit(1);
  });
} catch (error) {
  write({ event: 'failed', error: String(error.message).slice(0, 290) });
  app.exit(1);
}
