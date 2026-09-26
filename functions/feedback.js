// functions/feedback.js - 反馈中转函数
//
// 🔐 这个函数**不持有任何秘密**。它只做三件事：校验输入、限流、把反馈转给你的私有仓库。
//
// 为什么这么改（安全模型）：
//   * 之前它手里握着 GITHUB_TOKEN，任何能碰到这个函数的人都能借它建 Issue；
//     靠 Origin 请求头判断「是不是本站来的」是**挡不住的** ——
//     命令行工具、脚本、程序都**不需要**遵守 Origin，不发这个头就绕过了。
//   * 现在的防线换成「抬高门槛 + 限制影响面」：
//       1. 限流（进程内计数）——单 IP 高频提交会被拒；
//       2. 校验浏览器特征头——最粗糙的脚本会被挡下；
//       3. 提交耗时检查——机械式秒刷会被拒；
//       4. 字段长度上限 + 类型白名单——灌长文、乱塞标签会被拒；
//       5. 相同内容去重。
//     这些**都不是身份验证**，只是让灌水变麻烦（详见项目审查报告的方案五说明）。
//   * 影响面：反馈统一进**私有仓库**（GITHUB_REPO），公开页面不会直接出现任何内容；
//     另由「令牌权限收紧到只能建 Issue」兜底，最坏情况也只是往私有仓库塞垃圾。

// 🔐 反馈落地的仓库：私有仓库，只有维护者能看到，审阅后才由人工转公开。
// 想改回公开仓库：把 GITHUB_REPO 环境变量设为公开仓库名即可（形如 owner/repo）。
const DEFAULT_FEEDBACK_REPO = 'Gdxz-Linus/smartdns-edge-feedback';

// 允许的反馈类型白名单（不再把用户输入直接当 GitHub 标签用）
const ALLOWED_TYPES = {
  Bug: 'bug',
  Enhancement: 'enhancement',
  Question: 'question',
};

// 字段长度上限
const MAX_TITLE = 200;
const MAX_CONTACT = 200;
const MAX_DESCRIPTION = 20000;

// 提交耗时下限（毫秒）：人类不可能比这更快填完整个表单。
// 页面会在加载时埋一个时间戳随表单一起提交（见 docs/index.html）。
const MIN_ELAPSED_MS = 2000;
// 时间戳允许的最长有效期（毫秒）：超过视为重放，要求重新打开页面
const MAX_ELAPSED_MS = 6 * 60 * 60 * 1000;

// 🔐 进程内限流（没有配置 KV 时的降级方案）。
// 说明：Cloudflare 边缘函数是无状态的，同一个实例只服务一小段时间，
// 因此这个计数**不如 KV 可靠**（请求会被分散到多个实例）。它的作用是提高门槛，
// 不是精确限流。想要真正生效，请绑定一个 KV 到 LIMIT_DB 变量。
const RATE_WINDOW_MS = 60 * 1000;
const RATE_LIMIT = 3; // 窗口内最多提交几次
const seenByIp = new Map();

// 去重表：短时间内的相同内容直接拒掉
const DEDUP_WINDOW_MS = 10 * 60 * 1000;
const recentHashes = new Map();

function corsHeadersFor(request) {
  // 🔐 不信任 Origin 的**授权**含义，但 CORS 头仍需正确回显，
  // 否则正常用户的浏览器会拦下请求。这里只做「回显」、不做「放行判断」。
  const origin = request.headers.get('Origin');
  const headers = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    Vary: 'Origin',
  };
  if (origin) {
    headers['Access-Control-Allow-Origin'] = origin;
  }
  return headers;
}

function json(body, status, corsHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

/** 🔐 校验「像不像一个真实浏览器提交的表单」。
 *  这不是身份验证 —— 只是把最粗糙的脚本（一个裸 fetch / curl）挡在外面。
 *  带这些头是可伪造的，所以它只用于抬高门槛。 */
function looksLikeBrowser(request) {
  const h = request.headers;
  // 浏览器跨源 POST 一定会带 Origin
  if (!h.get('Origin')) return false;
  // Sec-Fetch-* 是现代浏览器发出的，裸脚本一般没有
  const site = h.get('Sec-Fetch-Site');
  const mode = h.get('Sec-Fetch-Mode');
  if (!site || !mode) return false;
  if (mode !== 'cors') return false;
  // 表单提交一定带 Content-Type: application/json（前端用 fetch 发的）
  const ct = h.get('Content-Type') || '';
  if (!ct.includes('application/json')) return false;
  return true;
}

/** 清理过期的限流/去重记录，避免内存无限增长。 */
function prune(now) {
  for (const [ip, entry] of seenByIp) {
    if (now - entry.first > RATE_WINDOW_MS) seenByIp.delete(ip);
  }
  for (const [hash, ts] of recentHashes) {
    if (now - ts > DEDUP_WINDOW_MS) recentHashes.delete(hash);
  }
}

/** 简单的字符串哈希（FNV-1a 变体），仅用于去重，不用于安全用途。 */
function hashString(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16);
}

async function isRateLimited(env, ip, now) {
  // 配了 KV 就用 KV（真正跨实例生效）
  if (env.LIMIT_DB) {
    const key = `fb-limit:${ip}`;
    try {
      const hit = await env.LIMIT_DB.get(key);
      const count = hit ? parseInt(hit, 10) : 0;
      if (count >= RATE_LIMIT) return true;
      await env.LIMIT_DB.put(key, String(count + 1), {
        expirationTtl: Math.ceil(RATE_WINDOW_MS / 1000),
      });
      return false;
    } catch (err) {
      // KV 出错时**不降级放行**，改用进程内计数继续挡（之前是出错就放行）
      console.error('LIMIT_DB error, falling back to in-process counter:', err);
    }
  }

  // 降级：进程内计数
  const entry = seenByIp.get(ip);
  if (!entry || now - entry.first > RATE_WINDOW_MS) {
    seenByIp.set(ip, { first: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT;
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const corsHeaders = corsHeadersFor(request);
  const now = Date.now();

  prune(now);

  // ── 1. 浏览器特征校验（抬高门槛，不是身份验证）──────────────────
  if (!looksLikeBrowser(request)) {
    return json(
      { error: '请求来源无法识别：请通过官网页面上的表单提交反馈。' },
      403,
      corsHeaders
    );
  }

  // ── 2. 限流 ──────────────────────────────────────────────────
  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await isRateLimited(env, clientIp, now)) {
    return json(
      { error: '提交过于频繁，请稍后再试（同一来源每分钟最多 3 次）。' },
      429,
      corsHeaders
    );
  }

  // ── 3. 请求体 ────────────────────────────────────────────────
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: '请求体格式不正确。' }, 400, corsHeaders);
  }

  const { type, title, description, contact, ts } = body || {};

  // 提交耗时检查：人类不会在 2 秒内填完整个表单
  const submittedAt = Number(ts);
  if (!Number.isFinite(submittedAt)) {
    return json(
      { error: '缺少表单时间戳，请刷新页面后重新提交。' },
      400,
      corsHeaders
    );
  }
  const elapsed = now - submittedAt;
  if (elapsed < MIN_ELAPSED_MS) {
    return json({ error: '提交速度异常，请确认是由本人手动填写后提交。' }, 400, corsHeaders);
  }
  if (elapsed > MAX_ELAPSED_MS || elapsed < 0) {
    return json({ error: '表单已过期，请刷新页面后重新提交。' }, 400, corsHeaders);
  }

  // ── 4. 字段校验 ──────────────────────────────────────────────
  const t = typeof title === 'string' ? title.trim() : '';
  const d = typeof description === 'string' ? description.trim() : '';
  const c = typeof contact === 'string' ? contact.trim() : '';

  if (!t || !d) {
    return json({ error: '标题与详细描述不能为空。' }, 400, corsHeaders);
  }
  if (t.length > MAX_TITLE) {
    return json({ error: `标题过长（上限 ${MAX_TITLE} 字）。` }, 400, corsHeaders);
  }
  if (c.length > MAX_CONTACT) {
    return json({ error: `联系方式过长（上限 ${MAX_CONTACT} 字）。` }, 400, corsHeaders);
  }
  if (d.length > MAX_DESCRIPTION) {
    return json({ error: `描述过长（上限 ${MAX_DESCRIPTION} 字）。` }, 400, corsHeaders);
  }

  // 🔐 类型白名单：不再把用户输入直接当标签用
  const githubLabel = ALLOWED_TYPES[type];
  if (!githubLabel) {
    return json({ error: '反馈类型不合法。' }, 400, corsHeaders);
  }

  // ── 5. 相同内容去重 ──────────────────────────────────────────
  const contentHash = hashString(`${clientIp}|${t}|${d}`);
  const lastSeen = recentHashes.get(contentHash);
  if (lastSeen && now - lastSeen < DEDUP_WINDOW_MS) {
    return json({ error: '相同内容刚刚已提交过，请勿重复提交。' }, 409, corsHeaders);
  }

  // ── 6. 转交私有仓库 ──────────────────────────────────────────
  // 这个函数本身不留存任何令牌之外的能力；令牌由 Cloudflare 环境变量提供，
  // 且应被收紧到「只能写 Issue」。
  const token = env.GITHUB_TOKEN;
  if (!token) {
    return json(
      { error: '服务端未正确配置，暂时无法接收反馈。' },
      500,
      corsHeaders
    );
  }

  const repo = env.GITHUB_REPO || DEFAULT_FEEDBACK_REPO;

  const issueTitle = `[${type}] ${t}`;
  const contactLine = c ? `**联系方式 (Contact)**: \`${c}\`\n\n` : '';
  const issueBody =
    `### 反馈类型\n${type}\n\n${contactLine}` +
    `### 详细描述\n${d}\n\n---\n` +
    `*来自 SmartDNS Edge 官网表单（待审阅：审阅通过后再转至公开仓库）*`;

  try {
    const response = await fetch(`https://api.github.com/repos/${repo}/issues`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'SmartDNS-Edge-Feedback-Gateway',
      },
      body: JSON.stringify({
        title: issueTitle,
        body: issueBody,
        labels: [githubLabel],
      }),
    });

    if (!response.ok) {
      // 🔐 不再把 GitHub 的原始错误文本回给客户端（可能含内部信息），只写日志
      const errText = await response.text();
      console.error('GitHub API error:', response.status, errText);
      return json(
        { error: '反馈暂时无法送达，请稍后再试。' },
        502,
        corsHeaders
      );
    }

    // 记录去重时间戳
    recentHashes.set(contentHash, now);

    // 🔐 返回「已收到」而不是 Issue 链接与编号：
    // 反馈进的是私有仓库，用户无法访问，给出编号只会造成误解。
    return json(
      {
        success: true,
        message: '反馈已收到，感谢你的提交！维护者会在审阅后处理。',
      },
      200,
      corsHeaders
    );
  } catch (err) {
    console.error('feedback forwarding failed:', err && err.message);
    return json({ error: '反馈暂时无法送达，请稍后再试。' }, 502, corsHeaders);
  }
}

export async function onRequestOptions(context) {
  return new Response(null, {
    status: 204,
    headers: corsHeadersFor(context.request),
  });
}
