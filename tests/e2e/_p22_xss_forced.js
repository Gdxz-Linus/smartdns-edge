// 问题 22 的**反向验证**：证明"错误详情走文本插入"这个契约**有判别力**。
//
// ## 为什么要单独写这个
//
// 主脚本 `_p22_xss.js` 的探针走的是 hash → url → err.message 这条外部路径，
// 而实测发现**那条路注入不进来**（hash 里的 `<>` 已被编码）——
// 于是把实现改回 `innerHTML` 时，主脚本**仍然全绿**。它的"通过"是假的。
//
// 本脚本换成**直接构造真实调用**：让 `loadMarkdown` 在 fetch 阶段拿到一个
// **含 HTML 标签的 url**（用 `Runtime.evaluate` 临时替换 `window.fetch` 抛错，
// 错误信息里带标签）。这才是"后端/URL 真的回显了危险内容"时的形态。
//
// 于是：
//   · 实现用 textContent → 标签以文本显示，**不生成元素** ⇒ 通过；
//   · 实现用 innerHTML  → 标签被解析，**生成元素** ⇒ 失败。
// 判别力由此成立（我用改回 innerHTML 的方式实测验证过，会 FAIL）。

const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const SITE = path.resolve(__dirname, '../../../smartdns-edge-docs/docs');
// ⚠️ 端口取 27030：原先用 26993，反复调试时被残留进程占用，
// 而 `Get-NetTCPConnection` 有时看不到它（进程已死、端口仍处于 TIME_WAIT/占用状态）。
// 换一个高位端口并与其它脚本错开，避免互相干扰。
const PORT = Number(process.env.P22F_PORT || 27030);
const EDGE = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const MIME = { '.html': 'text/html; charset=utf-8', '.md': 'text/markdown; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };

const results = [];
const check = (n, ok, d) => { results.push({ n, ok }); console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${n}${!ok && d ? ' -- ' + d : ''}`); };

const PROBE_ID = 'p22-force-probe';
const PAYLOAD = `<img id="${PROBE_ID}" src=x onerror="window.__p22_forced=true">`;

http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/') p = '/index.html';
  const f = path.join(SITE, p);
  if (!f.startsWith(SITE) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); res.end('nope'); return; }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream' });
  fs.createReadStream(f).pipe(res);
}).listen(PORT, '127.0.0.1', async () => {
  const dp = PORT + 1;
  const prof = fs.mkdtempSync(path.join(os.tmpdir(), 'p22f-'));
  const edge = spawn(EDGE, ['--headless=new', '--disable-gpu', '--no-sandbox', `--user-data-dir=${prof}`, `--remote-debugging-port=${dp}`, 'about:blank'], { stdio: 'ignore' });

  const ver = async () => {
    for (let i = 0; i < 40; i++) {
      try {
        const d = await new Promise((res, rej) => http.get({ host: '127.0.0.1', port: dp, path: '/json/version' }, (r) => { let b = ''; r.on('data', (x) => b += x); r.on('end', () => res(JSON.parse(b))); }).on('error', rej));
        if (d.webSocketDebuggerUrl) return d.webSocketDebuggerUrl;
      } catch (_) {}
      await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error('no edge');
  };

  try {
    console.log('===== 问题 22：反向验证（强行让 url 带 HTML 标签）=====');
    console.log('');

    const ws = new WebSocket(await ver());
    await new Promise((r) => ws.addEventListener('open', r, { once: true }));
    let id = 0; const pend = new Map();
    ws.addEventListener('message', (ev) => { const m = JSON.parse(ev.data); if (m.id && pend.has(m.id)) { pend.get(m.id)(m.result || {}); pend.delete(m.id); } });
    const send = (method, params = {}, sid) => new Promise((res) => { const i = ++id; pend.set(i, res); ws.send(JSON.stringify({ id: i, method, params, sessionId: sid })); });

    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    await send('Page.enable', {}, sessionId);
    await send('Runtime.enable', {}, sessionId);
    const ev = async (expr) => (await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true }, sessionId)).result?.value;

    const waitLoad = () => new Promise((resolve) => {
      const h = (m) => { const x = JSON.parse(m.data); if (x.method === 'Page.loadEventFired' && x.sessionId === sessionId) { ws.removeEventListener('message', h); resolve(); } };
      ws.addEventListener('message', h);
      setTimeout(resolve, 8000);
    });

    const loaded = waitLoad();
    await send('Page.navigate', { url: `http://127.0.0.1:${PORT}/index.html` }, sessionId);
    await loaded;
    await new Promise((r) => setTimeout(r, 2000));

    // 关键一步：把 window.fetch 换掉 —— 让**抓取文档**的那次请求抛出一个
    // 携带 HTML 标签的错误（模拟"url 里真的带了危险内容"）。
    // 这样就走的是与线上完全相同的错误处理分支，只是输入被强行污染。
    const patched = await ev(`(() => {
      const realFetch = window.fetch;
      window.fetch = function(u, o) {
        if (String(u).includes('.md') || String(u).includes('config')) {
          // 错误信息里带标签：这正是"外部数据进入 err.message"的形态
          return Promise.reject(new Error(${JSON.stringify(PAYLOAD)}));
        }
        return realFetch.apply(this, arguments);
      };
      return typeof window.fetch === 'function';
    })()`);
    check('已替换 fetch 以污染错误信息', patched === true);

    // 触发一次文档加载
    await ev(`(async () => { try { await loadMarkdown(); } catch (_) {} })()`);
    await new Promise((r) => setTimeout(r, 1500));

    const probeFound = await ev(`!!document.getElementById(${JSON.stringify(PROBE_ID)})`);
    check('带标签的错误信息未被解析成元素（textContent 生效）', probeFound === false,
      '出现了注入元素 —— 该处的实现已退回 innerHTML 拼接');

    const boxText = await ev(`(document.querySelector('#markdown-content .error-msg')||{}).textContent || ''`);
    check('错误详情仍然显示该内容（功能未被改坏）',
      typeof boxText === 'string' && boxText.includes(PROBE_ID),
      `错误框文本：${String(boxText).slice(0, 140)}`);

    const executed = await ev('window.__p22_forced === true');
    check('onerror 未被执行', executed !== true);
  } finally {
    edge.kill();
    try { fs.rmSync(prof, { recursive: true, force: true }); } catch (_) {}
    const failed = results.filter((r) => !r.ok);
    console.log('');
    console.log('='.repeat(56));
    console.log(`汇总: ${results.length - failed.length} 通过 / ${failed.length} 失败`);
    process.exit(failed.length ? 1 : 0);
  }
});
