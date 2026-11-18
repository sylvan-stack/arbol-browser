const { createServer } = require('node:http');
const { randomBytes } = require('node:crypto');

function content(nonce, second) {
  const title = second ? 'Second page' : 'Live page';
  return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · Arbol Browser demo</title>
<style nonce="${nonce}">
  * { box-sizing: border-box; }
  body { margin: 0; background: #f6f5f1; color: #202822; font: 16px/1.55 system-ui, sans-serif; }
  main { margin: max(24px, 6vh) auto; padding: 26px 34px; max-width: min(700px, 94vw); border: 1px solid #d9ded7; border-radius: 12px; background: #fff; }
  h1 { margin: 0 0 20px; font-size: 30px; line-height: 1.2; }
  dl { margin: 0 0 24px; }
  dt { color: #42564a; font-size: 14px; margin-top: 8px; }
  dd { margin: 0; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
  label { display: block; font-weight: 600; }
  textarea { display: block; width: 100%; margin: 5px 0 18px; padding: 10px; border: 1px solid #9baaa0; border-radius: 6px; font: inherit; }
  button { font: inherit; font-weight: 600; color: #fff; background: #204f37; border: 0; border-radius: 7px; padding: 8px 14px; cursor: pointer; }
  button:focus-visible, textarea:focus-visible, a:focus-visible { outline: 3px solid #427258; outline-offset: 3px; }
  output { margin-inline-start: 12px; font-weight: 600; font-variant-numeric: tabular-nums; }
  a { display: block; width: fit-content; margin-top: 22px; color: #204f37; }
</style>
<main>
  <h1>${title}</h1>
  <dl>
    <dt>Document ID</dt>
    <dd id="document"></dd>
    <dt>Running time</dt>
    <dd id="timer"></dd>
  </dl>
  <label for="message">Unsaved message</label>
  <textarea id="message" rows="3"></textarea>
  <button id="increment" type="button">Increase count</button>
  <output id="count" for="increment" aria-label="Count">0</output>
  <a id="other-page" href="${second ? '/' : '/second'}">${second ? 'Open live page' : 'Open second page'}</a>
</main>
<script nonce="${nonce}">
  const epoch = performance.now();
  const timer = document.querySelector('#timer');
  const update = () => { timer.textContent = ((performance.now() - epoch) / 1000).toFixed(1) + ' s'; };
  document.querySelector('#document').textContent = crypto.randomUUID();
  const count = document.querySelector('#count');
  document.querySelector('#increment').addEventListener('click', () => {
    count.textContent = String(Number(count.textContent) + 1);
  });
  update();
  setInterval(update, 100);
</script>
</html>`;
}

async function startFixture() {
  const server = createServer((request, response) => {
    const path = request.url;
    if (request.headers.host !== '127.0.0.1:' + server.address().port || request.method !== 'GET' ||
        !['/', '/second'].includes(path)) {
      response.writeHead(404).end();
      return;
    }
    const nonce = randomBytes(16).toString('base64');
    response.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; style-src 'nonce-" + nonce + "'; script-src 'nonce-" + nonce + "'",
    }).end(content(nonce, path === '/second'));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { url: 'http://127.0.0.1:' + server.address().port + '/',
    close() { server.close(); server.closeAllConnections(); } };
}

module.exports = { startFixture };
