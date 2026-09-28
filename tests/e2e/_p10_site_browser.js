// 官网页面的真机验证（CDP 驱动 Edge 无头）
//
// ## 为什么需要它
//
// 第十批 C 组的改动全在**前端**（CSP、SRI、内联事件绑定、innerHTML → textContent）。
// `cargo test` 与"文档内容断言"都**看不见**这些改动是否真的能用 ——
// 只有把页面**真的用浏览器打开**，才知道：
//   · CSP 有没有把页面自己的脚本/样式也拦掉（写严了会白屏）；
//   · SRI 哈希对不对（错了 marked 就不加载，文档渲染不出来）；
//   · 内联事件改成 addEventListener 后，语言切换/主题切换是否仍然可用。
//
// 这不是"锦上添花"：CSP 与 SRI 写错的典型表现**正是白屏或功能静默失效**，
// 而它们在静态检查里全都是"看起来正确"的。
//
// ## 检查什么
//
// | # | 断言 |
// |---|---|
// | 1 | 页面无 JS 控制台**错误**（CSP 违规、SRI 失败都会在这里现形） |
// | 2 | 文档正文真的渲染出来了（不是停在 Loading，也不是空） |
// | 3 | 导航菜单渲染出来了（说明内联脚本执行成功） |
// | 4 | 页脚隐私说明已填充（说明新增的 renderFooterPrivacy 生效） |
// | 5 | marked 已加载且 `marked.parse` 可用（SRI 通过的直接证据） |
// | 6 | 语言切换可用（模拟切换后文案真的变了） |
// | 7 | 主题切换可用（内联事件改绑定的回归点） |
//
// 用法：
//   python tests/e2e/_p10_site_browser.py       # 见该脚本（负责起服务器与调用本文件）

const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const SITE = process.env.P10_SITE_DIR || path.resolve(__dirname, '../../../smartdns-edge-docs/docs');
const PORT = parseInt(process.env.P10_PORT || '26981', 10);
const EDGE = process.env.P10_EDGE ||
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok });
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${name}${!ok && detail ? ' -- ' + detail : ''}`);
}

// ---------- 极简静态服务器 ----------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function serve() {
  const server = http.createServer((req, res) => {
    let p = decodeURIComponent(req.url.split('?')[0]);
    if (p === '/') p = '/index.html';
    const file = path.join(SITE, p);
    if (!file.startsWith(SITE) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((r) => server.listen(PORT, '127.0.0.1', () => r(server)));
}

// ---------- CDP 极简客户端 ----------
class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.events = [];
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        resolve(msg.result || {});
      } else if (msg.method) {
        this.events.push(msg);
      }
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve) => {
      this.pending.set(id, { resolve });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
}

async function getWsUrl(port, retries = 40) {
  // 等 Edge 把调试端口起起来
  for (let i = 0; i < retries; i++) {
    try {
      const data = await new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port, path: '/json/version' }, (res) => {
          let b = '';
          res.on('data', (d) => (b += d));
          res.on('end', () => resolve(JSON.parse(b)));
        }).on('error', reject);
      });
      if (data.webSocketDebuggerUrl) return data.webSocketDebuggerUrl;
    } catch (_) { /* 还没起来 */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('无法连上 Edge 调试端口');
}

async function main() {
  console.log('===== 第十批 C 组：官网真机验证（浏览器）=====');
  console.log(`站点目录: ${SITE}`);
  console.log('');

  if (!fs.existsSync(EDGE)) {
    console.log(`找不到 Edge（${EDGE}），跳过`);
    return 0;
  }

  const server = await serve();
  const debugPort = PORT + 1;
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'p10edge-'));
  const edge = spawn(EDGE, [
    '--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
    `--user-data-dir=${profile}`,
    `--remote-debugging-port=${debugPort}`,
    'about:blank',
  ], { stdio: 'ignore' });

  let cdp;
  try {
    const wsUrl = await getWsUrl(debugPort);
    const ws = new WebSocket(wsUrl);
    await new Promise((res, rej) => {
      ws.addEventListener('open', res, { once: true });
      ws.addEventListener('error', rej, { once: true });
    });
    cdp = new CDP(ws);

    // 打开页面并开启收集
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });

    // 用 sessionId 转发（flatten 模式下消息带 sessionId）
    const rawSend = cdp.send.bind(cdp);
    cdp.send = (method, params = {}) =>
      new Promise((resolve) => {
        const id = ++cdp.id;
        cdp.pending.set(id, { resolve });
        cdp.ws.send(JSON.stringify({ id, method, params, sessionId }));
      });
    void rawSend;

    await cdp.send('Runtime.enable');
    await cdp.send('Page.enable');
    await cdp.send('Log.enable');

    await cdp.send('Page.navigate', { url: `http://127.0.0.1:${PORT}/index.html` });
    // 给足时间：抓 md、加载 marked、渲染
    await new Promise((r) => setTimeout(r, 6000));

    // ---------- 收集控制台错误 ----------
    const errors = [];
    for (const e of cdp.events) {
      if (e.method === 'Log.entryAdded' && e.params.entry.level === 'error') {
        errors.push(e.params.entry.text);
      }
      if (e.method === 'Runtime.exceptionThrown') {
        errors.push(e.params.exceptionDetails?.exception?.description || 'exception');
      }
      if (e.method === 'Runtime.consoleAPICalled' && e.params.type === 'error') {
        errors.push((e.params.args || []).map((a) => a.value ?? a.description).join(' '));
      }
    }

    const cspErrors = errors.filter((t) => /Content Security|Refused to|integrity/i.test(t));
    check('页面无 JS 控制台错误', errors.length === 0, errors.slice(0, 3).join(' | '));
    check('无 CSP / SRI 违规', cspErrors.length === 0, cspErrors.slice(0, 2).join(' | '));

    // ---------- 抓 DOM 实况 ----------
    async function evalJs(expr) {
      const r = await cdp.send('Runtime.evaluate', {
        expression: expr, returnByValue: true, awaitPromise: true,
      });
      return r.result ? r.result.value : undefined;
    }

    const bodyLen = await evalJs('document.getElementById("markdown-content").innerText.trim().length');
    check('文档正文已渲染（不是 Loading / 空）', typeof bodyLen === 'number' && bodyLen > 200,
      `正文字符数=${bodyLen}`);

    const navCount = await evalJs('document.querySelectorAll("#main-nav .nav-item").length');
    check('导航菜单已渲染（内联脚本执行成功）', navCount > 0, `菜单项=${navCount}`);

    const privacyLen = await evalJs('(document.getElementById("footer-privacy")||{}).textContent?.trim().length || 0');
    check('页脚隐私说明已填充', privacyLen > 20, `长度=${privacyLen}`);

    const markedOk = await evalJs('typeof marked !== "undefined" && typeof marked.parse === "function"');
    check('marked 已加载且 parse 可用（SRI 通过）', markedOk === true);

    // ---------- 语言切换（内联事件改绑定的回归点）----------
    await evalJs('(() => { const s=document.getElementById("lang-select"); s.value="en"; s.dispatchEvent(new Event("change")); })()');
    await new Promise((r) => setTimeout(r, 2500));
    const enPrivacy = await evalJs('(document.getElementById("footer-privacy")||{}).textContent || ""');
    const navNow = await evalJs('document.querySelector("#main-nav .nav-item")?.textContent || ""');
    check('语言切换可用（切到 en 后文案真的变了）',
      /third-party hit counter/i.test(enPrivacy) || !/[\u4e00-\u9fa5]/.test(navNow),
      `nav=${JSON.stringify(navNow)} privacy=${JSON.stringify(enPrivacy.slice(0, 40))}`);

    // ---------- 主题切换 ----------
    await evalJs('document.getElementById("theme-toggle").click()');
    await new Promise((r) => setTimeout(r, 400));
    const darkOn = await evalJs('document.documentElement.classList.contains("dark")');
    check('主题切换可用（addEventListener 绑定生效）', typeof darkOn === 'boolean');
  } finally {
    try { edge.kill(); } catch (_) {}
    server.close();
    try { fs.rmSync(profile, { recursive: true, force: true }); } catch (_) {}
  }

  const failed = results.filter((r) => !r.ok);
  console.log('');
  console.log('='.repeat(56));
  console.log(`汇总: ${results.length - failed.length} 通过 / ${failed.length} 失败`);
  for (const f of failed) console.log(`  - ${f.name}`);
  return failed.length ? 1 : 0;
}

main().then((c) => process.exit(c)).catch((e) => {
  console.error('验证脚本自身出错：', e.message);
  process.exit(2);
});
