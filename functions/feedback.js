// functions/feedback.js - 搭载服务器端 IP 限流器的反馈处理函数
const GITHUB_REPO = 'Gdxz-Linus/smartdns-edge';

export async function onRequestPost(context) {
  const { request, env } = context;

  // 1. 允许跨域（CORS）响应头，让前端网页可以无障碍发起请求
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

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
export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}