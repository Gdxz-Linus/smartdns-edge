// 问题 4 / 7 的真机验证：直接调用 Cloudflare Pages Function 的 onRequest。
//
// ## 为什么必须真跑
//
// 改动全在"返回值与响应头"上（404 / CORS / 不回显内部错误）。
// **看代码看不出**"是不是真的返回了 404"、"CORS 头到底有没有去掉"。
// 而这个文件是 ES module、`onRequest` 就是个普通函数 ——
// 所以可以**直接 import 并构造 Request 调用它**，比"读代码"强得多。
//
// ## 检查什么
//
// | # | 场景 | 期望 |
// |---|---|---|
// | 1 | 6 个合法短别名 | 都能正常走到上游 fetch（不是 404/400） |
// | 2 | 未知 key（如 `smartdns-xxx.zip`） | **404**，且**不**去访问 GitHub（防探测） |
// | 3 | 路径穿越（`..%2F..%2Fetc%2Fpasswd`） | 404 / 400，绝不拼进 GitHub URL |
// | 4 | 上游 404 | 回 **404**，且**不**含 GitHub 的状态码 |
// | 5 | 上游 500 | 回 **404**（统一文案），不泄露上游状态 |
// | 6 | fetch 抛异常 | 回 **502**，且**不**含内部错误信息 |
// | 7 | 带自家 Referer | 放行（不是 403） |
// | 8 | 带第三方 Referer | **403** |
// | 9 | 自家 Origin | 回 `Access-Control-Allow-Origin: <该来源>` |
// | 10 | 第三方 Origin | **不回** `Access-Control-Allow-Origin`；也不回 `*` |
// | 11 | 任何情况下 | **绝不**出现 `Access-Control-Allow-Origin: *` |
//
// 用法：node tests/e2e/_p4_download.js

const path = require('path');
const { pathToFileURL } = require('url');

const FN = path.resolve(
  __dirname,
  '../../../smartdns-edge-docs/functions/download/[[file]].js'
);

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok });
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${name}` + (!ok && detail ? ' -- ' + detail : ''));
}

// 记录"是否真的去访问了 GitHub"（用于验证未命中时没有外发请求）
let fetched = [];
function installFetchMock(handler) {
  fetched = [];
  globalThis.fetch = async (url, opts) => {
    fetched.push(String(url));
    return handler(String(url), opts);
  };
}

function makeRequest(url, headers = {}) {
  return new Request(url, { headers });
}

async function call(fileKey, headers = {}) {
  const mod = await import(pathToFileURL(FN).href);
  const g = globalThis;
  void g;
  const request = makeRequest(`https://smartdns-edge.pages.dev/download/${fileKey}`, headers);
  const context = { request, params: { file: [fileKey] } };
  return mod.onRequest(context);
}

// 上游正常返回一个假文件流
function okUpstream() {
  return new Response('BINARY', {
    status: 200,
    headers: { 'Content-Type': 'application/octet-stream', 'Location': 'https://github.com/x' },
  });
}

(async () => {
  console.log('===== 问题 4/7：下载接口真机验证 =====');
  console.log('');

  const VALID = ['windows-x64', 'windows-arm64', 'linux-x64', 'linux-arm64', 'mac-intel', 'mac-arm64'];

  // ---------- 1. 6 个合法别名都能走通 ----------
  console.log('--- 合法别名（页面实际用到的 6 个）---');
  installFetchMock(okUpstream);
  for (const k of VALID) {
    const res = await call(k, { Referer: 'https://smartdns-edge.pages.dev/' });
    check(`别名 ${k} 正常放行`, res.status === 200, `status=${res.status}`);
  }
  check('合法别名都触发了上游请求（6 次）', fetched.length === 6, `实际 ${fetched.length} 次`);

  // ---------- 2. 未知 key 必须 404 且不外发 ----------
  console.log('');
  console.log('--- 未知 key：必须 404、且不得去探测 GitHub ---');
  installFetchMock(okUpstream);
  const unknown = await call('smartdns-secret-internal.zip', {});
  check('未知 key 返回 404', unknown.status === 404, `status=${unknown.status}`);
  check('未知 key **不**访问 GitHub（防仓库探测）', fetched.length === 0,
    `却外发到了：${fetched.join(', ')}`);
  const body = await unknown.text();
  check('404 文案给出了可用 key（可操作性）', body.includes('windows-x64'), body.slice(0, 80));

  // ---------- 3. 路径穿越 ----------
  console.log('');
  console.log('--- 路径穿越不得拼进 GitHub URL ---');
  installFetchMock(okUpstream);
  for (const evil of ['../../../etc/passwd', '..%2F..%2Fsecret', 'a/../../b']) {
    const r = await call(evil, {});
    check(`拒绝 ${JSON.stringify(evil)}`,
      (r.status === 404 || r.status === 400) && fetched.length === 0,
      `status=${r.status}, fetched=${fetched.length}`);
  }

  // ---------- 4. 上游 404 → 统一 404，不泄露上游状态 ----------
  console.log('');
  console.log('--- 上游失败时不得回显内部信息 ---');
  installFetchMock(() => new Response('nope', { status: 404 }));
  const up404 = await call('linux-x64', {});
  const b404 = await up404.text();
  check('上游 404 → 本接口回 404', up404.status === 404, `status=${up404.status}`);
  check('响应体不含上游状态码（防探测）', !/404/.test(b404) && !/File not found \(/.test(b404), b404.slice(0, 80));

  installFetchMock(() => new Response('boom', { status: 500 }));
  const up500 = await call('linux-x64', {});
  check('上游 500 → 本接口仍回 404（不泄露上游状态）', up500.status === 404, `status=${up500.status}`);

  installFetchMock(() => { throw new Error('internal dns resolution failed for secret-host'); });
  const thrown = await call('linux-x64', {});
  const bThrown = await thrown.text();
  check('fetch 抛异常 → 502', thrown.status === 502, `status=${thrown.status}`);
  check('响应体**不含**内部错误详情', !bThrown.includes('secret-host') && !bThrown.includes('internal dns'),
    bThrown.slice(0, 120));

  // ---------- 5. 防盗链（按用户定调：保持现状） ----------
  console.log('');
  console.log('--- 防盗链（保持现状：有 Referer 才校验）---');
  installFetchMock(okUpstream);
  const okRef = await call('linux-x64', { Referer: 'https://smartdns-edge.pages.dev/download' });
  check('自家 Referer 放行', okRef.status === 200, `status=${okRef.status}`);

  installFetchMock(okUpstream);
  const badRef = await call('linux-x64', { Referer: 'https://evil.example.com/' });
  check('第三方 Referer → 403', badRef.status === 403, `status=${badRef.status}`);

  installFetchMock(okUpstream);
  const noRef = await call('linux-x64', {});
  check('缺 Referer 仍放行（用户选定的方案 b）', noRef.status === 200, `status=${noRef.status}`);

  // ---------- 6. CORS（问题 7） ----------
  console.log('');
  console.log('--- CORS：不再无条件 `*`（问题 7）---');
  installFetchMock(okUpstream);
  const ownOrigin = await call('linux-x64', { Origin: 'https://smartdns-edge.pages.dev' });
  const ownAcao = ownOrigin.headers.get('Access-Control-Allow-Origin');
  check('自家 Origin → 回该来源', ownAcao === 'https://smartdns-edge.pages.dev', `实际 ${ownAcao}`);
  check('自家 Origin 回带 Vary: Origin', (ownOrigin.headers.get('Vary') || '').includes('Origin'));

  installFetchMock(okUpstream);
  const evilOrigin = await call('linux-x64', { Origin: 'https://evil.example.com' });
  const evilAcao = evilOrigin.headers.get('Access-Control-Allow-Origin');
  check('第三方 Origin → **不回** CORS 头', evilAcao === null, `实际 ${evilAcao}`);

  installFetchMock(okUpstream);
  const anyOrigin = await call('linux-x64', { Origin: 'https://evil.example.com' });
  check('任何情况下都不得出现 `*`',
    anyOrigin.headers.get('Access-Control-Allow-Origin') !== '*',
    '仍然回了通配符');

  // 同源跳转（页面真实用法）不带 Origin，因此不该回任何 CORS 头 —— 也不该因此被拒
  installFetchMock(okUpstream);
  const plainJump = await call('linux-x64', { Referer: 'https://smartdns-edge.pages.dev/download' });
  check('页面真实用法（同源跳转、无 Origin）正常放行且无 CORS 头',
    plainJump.status === 200 && plainJump.headers.get('Access-Control-Allow-Origin') === null,
    `status=${plainJump.status}, acao=${plainJump.headers.get('Access-Control-Allow-Origin')}`);

  // ---------- 汇总 ----------
  const failed = results.filter((r) => !r.ok);
  console.log('');
  console.log('='.repeat(56));
  console.log(`汇总: ${results.length - failed.length} 通过 / ${failed.length} 失败`);
  for (const f of failed) console.log(`  - ${f.name}`);
  process.exit(failed.length ? 1 : 0);
})().catch((e) => {
  console.error('验证脚本自身出错：', e && e.stack ? e.stack : e);
  process.exit(2);
});
