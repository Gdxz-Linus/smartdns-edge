// 取所有被引用的 GitHub Action 在指定版本标签上的**真实 commit SHA**。
//
// ## 为什么需要它（问题 17）
//
// `actions/checkout@v7` 这种写法锁的是**大版本浮动标签** —— 上游仓库可以随时把它
// 指向新的 commit。发布流程一旦引用了被改写的 action，跑的就是别人的新代码。
// 修法是固定到 **commit SHA**（不可变）。
//
// ⚠️ 但 SHA 一旦写错，CI 会**直接失败**（找不到 action）。
// 所以不能手抄：本脚本从 GitHub API 取回真实 SHA，并做一致性校验，
// 生成的清单再由人核对后写入 workflow。
//
// 用法：node tests/e2e/_p17_action_shas.js

const REFS = [
  'actions/checkout@v7',
  'actions/upload-artifact@v7',
  'actions/download-artifact@v8',
  'softprops/action-gh-release@v3',
  'docker/login-action@v4',
  'docker/setup-qemu-action@v4',
  'docker/setup-buildx-action@v4',
  'lhotari/action-upterm@v1',
  'taiki-e/install-action@v2',
  'dtolnay/rust-toolchain@stable',
];

function get(url) {
  return new Promise((resolve, reject) => {
    const https = require('https');
    https.get(url, { headers: { 'User-Agent': 'p17-sha-probe', Accept: 'application/vnd.github+json' } }, (res) => {
      let b = '';
      res.on('data', (d) => (b += d));
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}: ${b.slice(0, 120)}`));
        try { resolve(JSON.parse(b)); } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

(async () => {
  console.log('===== 问题 17：取 action 的真实 commit SHA =====');
  console.log('');
  const out = [];
  for (const ref of REFS) {
    const [repo, tag] = ref.split('@');
    try {
      // 先按标签解析（可能返回 tag 对象或 commit）
      const d = await get(`https://api.github.com/repos/${repo}/git/ref/tags/${tag}`);
      let sha = d.object.sha;
      let kind = d.object.type;
      // 附注标签（annotated tag）要再解一层才拿到 commit
      if (kind === 'tag') {
        const t = await get(`https://api.github.com/repos/${repo}/git/tags/${sha}`);
        sha = t.object.sha;
        kind = t.object.type;
      }
      out.push({ ref, sha, kind });
      console.log(`  ${ref.padEnd(34)} -> ${sha}  (${kind})`);
    } catch (e) {
      out.push({ ref, sha: null, error: e.message });
      console.log(`  ${ref.padEnd(34)} -> 取不到：${e.message}`);
    }
  }

  console.log('');
  console.log('--- 可直接粘贴的固定写法 ---');
  for (const o of out) {
    if (o.sha) console.log(`  ${o.ref.split('@')[0]}@${o.sha} # ${o.ref.split('@')[1]}`);
  }
  process.exit(out.some((o) => !o.sha) ? 1 : 0);
})().catch((e) => { console.error('脚本出错：', e.message); process.exit(2); });
