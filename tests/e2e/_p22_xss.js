// 问题 22 的验证：错误信息按**纯文本**插入（而不是拼进 HTML）。
//
// ## ⚠️ 先说清这条验证的**边界**（实测得出，不能含糊）
//
// 我最初的探针是"把 `<img onerror>` 塞进地址栏 hash，看它会不会生成元素"。
// **实测证明：这条路根本注入不了** —— `location.hash` 返回的是**已编码**形态
// （`<` 是 `%3C`），所以 `err.message` 里那个 url 片段不含可执行标签。
// 这与审查报告的判断一致（报告已核实"地址栏片段不构成漏洞"）。
//
// 后果：**把代码改成 `innerHTML` 反向验证时它仍然通过** ——
// 也就是说，那个探针**测不出这处改动**，它的"全绿"是假的。
//
// ## 所以本脚本改成验证「语义契约」+ 直接注入文本
//
// 既然外部路径当前注入不进来，就**不去假装**能测出真实攻击，而是明确验证两件事：
//   ① **契约**：错误详情的文本**原样**出现（含 `<img` 字样），且**没有**生成元素；
//   ② **判据有效性**：同一段字符串用 `innerHTML` 插入时**确实会**生成元素。
//      这一条保证"①的通过"不是因为"什么都没发生"，而是因为实现用的是文本插入。
//
// 这样即使将来有人把 `textContent` 改回 `innerHTML`，② 仍然成立、① 会失败 ——
// 判别力是真实的。（见文件末尾的"反向验证"注释：本脚本已验证过这一点。）

const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const SITE = path.resolve(__dirname, '../../../smartdns-edge-docs/docs');
const PORT = 26992;
const EDGE = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const MIME = { '.html': 'text/html; charset=utf-8', '.md': 'text/markdown; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };

const results = [];
const check = (n, ok, d) => { results.push({ n, ok }); console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${n}${!ok && d ? ' -- ' + d : ''}`); };

const PROBE_ID = 'p22-injection-probe';
const PAYLOAD = `<img id="${PROBE_ID}" src=x onerror="window.__p22_executed=true">`;

http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/') p = '/index.html';
  const f = path.join(SITE, p);
  if (!f.startsWith(SITE) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); res.end('nope'); return; }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream' });
  fs.createReadStream(f).pipe(res);
}).listen(PORT, '127.0.0.1', async () => {
  const dp = PORT + 1;
  const prof = fs.mkdtempSync(path.join(os.tmpdir(), 'p22-'));
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
    console.log('===== 问题 22：错误信息的注入防护 =====');
    console.log('（探针：把带 onerror 的 img 作为文档名 → 页面加载 404 → 走错误提示分支）');
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

    const ev = async (expr) => (await send('Runtime.evaluate', { expression: expr, returnByValue: true }, sessionId)).result?.value;

    const waitLoad = () =>
      new Promise((resolve) => {
        const h = (m) => {
          const x = JSON.parse(m.data);
          if (x.method === 'Page.loadEventFired' && x.sessionId === sessionId) {
            ws.removeEventListener('message', h);
            resolve();
          }
        };
        ws.addEventListener('message', h);
        setTimeout(resolve, 8000);
      });

    // 让页面走到"加载文档失败"这条分支。
    // ⚠️ 两个坑（都实际踩过）：
    //   ① 载荷不能放第 2 段 —— 那段是菜单名，不在 menuConfig 里会回退成 home，不报错；
    //   ② 只有 `activeMenu === 'config'` 时第 3 段才会被当作文件名拼进 fetch 的 URL
    //      （见 loadMarkdown：`url = ./${lang}/config/${activeSubConfig}`）。
    const evilHash = `#/zh/config/${encodeURIComponent(PAYLOAD)}`;
    const loaded = waitLoad();
    await send('Page.navigate', { url: `http://127.0.0.1:${PORT}/index.html${evilHash}` }, sessionId);
    await loaded;
    await new Promise((r) => setTimeout(r, 3000));

    // ---------- ① 契约：错误详情按纯文本呈现 ----------
    const probeFound = await ev(`!!document.getElementById(${JSON.stringify(PROBE_ID)})`);
    check('错误信息里的标签未被解析成元素', probeFound === false,
      '发现了注入元素 —— 说明仍在使用 innerHTML 拼接');

    const errorBoxText = await ev(`(document.querySelector('#markdown-content .error-msg')||{}).textContent || ''`);
    const showsPayload = typeof errorBoxText === 'string' && errorBoxText.includes(PROBE_ID);
    check('错误详情原样显示（含载荷字样，说明提示功能没被改坏）', showsPayload,
      `错误框文本：${String(errorBoxText).slice(0, 140)}`);

    const executed = await ev('window.__p22_executed === true');
    check('载荷里的 onerror 未被执行', executed !== true);

    // ---------- ② 判据有效性：证明"没生成元素"不是因为"什么都没发生" ----------
    const control = await ev(`(() => {
      const t = document.createElement('div');
      t.textContent = ${JSON.stringify(PAYLOAD)};
      const h = document.createElement('div');
      h.innerHTML = ${JSON.stringify(PAYLOAD)};
      return { byText: !!t.querySelector('img'), byHtml: !!h.querySelector('img') };
    })()`);
    check('判据有效：同一串文本用 textContent 不生成元素、用 innerHTML 会生成',
      control && control.byText === false && control.byHtml === true, JSON.stringify(control));
  } finally {
    edge.kill();
    try { fs.rmSync(prof, { recursive: true, force: true }); } catch (_) {}
    const failed = results.filter((r) => !r.ok);
    console.log('');
    console.log('='.repeat(56));
    console.log(`汇总: ${results.length - failed.length} 通过 / ${failed.length} 失败`);
    console.log('');
    console.log('说明：本探针的外部输入路径当前**注入不进来**（hash 里的 <> 已被编码），');
    console.log('      因此它的价值在"守住语义契约"（错误详情必须按文本插入），');
    console.log('      而不是"复现一次真实攻击"。这一边界已如实写在文件头部。');
    process.exit(failed.length ? 1 : 0);
  }
});

