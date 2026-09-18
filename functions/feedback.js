// functions/feedback.js - 搭载服务器端 IP 限流器的反馈处理函数
const GITHUB_REPO = 'Gdxz-Linus/smartdns-edge';

// 🔐 安全修复：只允许本站来源调用本接口。
// 原来响应头写死 `Access-Control-Allow-Origin: *` —— 于是**任意网站**都能借访客的浏览器
// 用本函数里的 GITHUB_TOKEN 往仓库建 issue（同仓库的下载接口早就做了来源校验）。
// 白名单与下载接口保持一致；要加自定义域名，改这里或用环境变量 ALLOWED_ORIGINS（逗号分隔）。
const DEFAULT_ALLOWED_HOSTS = [
  'smartdns-edge.pages.dev',
  'downloads-21j.pages.dev',
  'localhost',
  '127.0.0.1',
];

function allowedHosts(env) {
  const extra = (env && env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS : '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return [...DEFAULT_ALLOWED_HOSTS, ...extra];
}

/** 来源允许吗？没有 Origin 头（同源请求/服务端调用）时不拦。 */
function isOriginAllowed(request, env) {
  const origin = request.headers.get('Origin');
  if (!origin) return { allowed: true, origin: '' };
  try {
    const host = new URL(origin).hostname;
    const ok = allowedHosts(env).some(
      (h) => host === h || host.endsWith('.' + h)
    );
    return { allowed: ok, origin };
  } catch (e) {
    return { allowed: false, origin };
  }
}

/** 只有允许的来源才回显 Access-Control-Allow-Origin；其余不发该头，浏览器会直接拦下。 */
function corsHeadersFor(request, env) {
  const { allowed, origin } = isOriginAllowed(request, env);
  const headers = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    Vary: 'Origin',
  };
  if (allowed && origin) {
    headers['Access-Control-Allow-Origin'] = origin;
  }
  return headers;
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // 1. CORS 响应头：只对白名单来源回显
  const corsHeaders = corsHeadersFor(request, env);

  // 1b. 🔐 来源校验：不是本站的直接拒绝 —— 否则等于把仓库 token 借给别人用
  if (!isOriginAllowed(request, env).allowed) {
    return new Response(
      JSON.stringify({ error: '403 Forbidden: 本接口仅允许来自本站页面的请求。' }),
      {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  }

  // 2. 🌟 提取来访用户的真实公网 IP 地址（通过 Cloudflare 边缘服务器请求头提取）
  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  const limitKey = `fb-limit:${clientIp}`;

  // 3. 🌟 【核心防灌水防线】：如果配置了 LIMIT_DB，在边缘服务器上直接拦截 60 秒内的重复发帖 [1]
  if (env.LIMIT_DB) {
    try {
      const isLocked = await env.LIMIT_DB.get(limitKey);
      if (isLocked) {
        return new Response(JSON.stringify({ 
          error: '您提交反馈的频率过快。为了防止恶意泛洪，系统限制同一个 IP 每分钟仅能提交 1 次反馈。' 
        }), {
          status: 429, // 429 Too Many Requests (超载/限流标准状态码)
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    } catch (dbErr) {
      // 数据库读取异常时记录日志并降级放行，保证高可用性
      console.error('LIMIT_DB read error:', dbErr);
    }
  }

  // 4. 解析前端传过来的 JSON 表单数据
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({ error: '无效的 JSON 请求体' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const { type, title, description, contact } = body;

  if (!title || !description) {
    return new Response(JSON.stringify({ error: '标题与详细描述不能为空' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // 5. 读取在 Cloudflare Pages 变量设置中安全保存的 GITHUB_TOKEN
  const token = env.GITHUB_TOKEN;
  if (!token) {
    return new Response(JSON.stringify({ error: '系统配置错误：未在 Cloudflare 环境变量中检测到 GITHUB_TOKEN' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // 6. 自动格式化排版 GitHub Issue 的内容
  const issueTitle = `[${type}] ${title}`;
  const contactLine = contact ? `**联系方式 (Contact)**: \`${contact}\`\n\n` : '';
  const issueBody = `### 反馈类型\n${type}\n\n${contactLine}### 详细描述\n${description}\n\n---\n*来自 SmartDNS Edge 网页控制台用户的实时反馈*`;

  // 7. 🌟 精准匹配映射：将前端提交的类型名称转换为 GitHub 官方默认对应的合规标签 [2]
  const labelMap = {
    'Bug': 'bug',
    'Enhancement': 'enhancement',
    'Question': 'question'
  };
  const githubLabel = labelMap[type] || type.toLowerCase();

  const githubApiUrl = `https://api.github.com/repos/${GITHUB_REPO}/issues`;

  try {
    // 8. 安全向 GitHub 发起创建 Issue 的请求（完全隐藏 Token 密钥）
    const response = await fetch(githubApiUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'SmartDNS-Edge-Feedback-Gateway'
      },
      body: JSON.stringify({
        title: issueTitle,
        body: issueBody,
        labels: [githubLabel] // 使用映射好、完全对齐的官方标签 [2]
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      return new Response(JSON.stringify({ error: `GitHub API 响应错误: ${errText}` }), {
        status: response.status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const data = await response.json();

    // 🌟 9. 【核心安全锁入】：发帖成功后，立刻将该 IP 锁入 KV 数据库并设置生存周期为 60 秒 [1]
    if (env.LIMIT_DB) {
      try {
        await env.LIMIT_DB.put(limitKey, 'locked', { expirationTtl: 60 });
      } catch (dbErr) {
        console.error('LIMIT_DB write error:', dbErr);
      }
    }

    // 10. 返回成功，将 Issue 的网页链接与编号回传给前端网页，让用户知晓
    return new Response(JSON.stringify({
      success: true,
      issue_url: data.html_url,
      issue_number: data.number
    }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (err) {
    return new Response(JSON.stringify({ error: `服务器网络异常: ${err.message}` }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}

// 11. 处理浏览器的 Preflight (OPTIONS) 预检请求，防止跨域拦截
//     🔐 同样只对白名单来源回显 CORS 头（不允的来源拿不到头，浏览器就会拦下真正的请求）
export async function onRequestOptions(context) {
  const corsHeaders = corsHeadersFor(context.request, context.env);

  return new Response(null, {
    status: 204,
    headers: corsHeaders,
  });
}