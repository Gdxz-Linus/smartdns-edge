// functions/feedback.js - Cloudflare Pages 专用问题反馈后端处理程序
const GITHUB_REPO = 'Gdxz-Linus/smartdns-edge';

export async function onRequestPost(context) {
  const { request, env } = context;

  // 1. 允许跨域（CORS）响应头，让前端网页可以无障碍发起请求
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  // 2. 解析前端传过来的 JSON 表单数据
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

  // 3. 读取在 Cloudflare Pages 变量设置中安全保存的 GITHUB_TOKEN
  const token = env.GITHUB_TOKEN;
  if (!token) {
    return new Response(JSON.stringify({ error: '系统配置错误：未在 Cloudflare 环境变量中检测到 GITHUB_TOKEN' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // 4. 自动格式化排版 GitHub Issue 的内容
  const issueTitle = `[${type}] ${title}`;
  const contactLine = contact ? `**联系方式 (Contact)**: \`${contact}\`\n\n` : '';
  const issueBody = `### 反馈类型\n${type}\n\n${contactLine}### 详细描述\n${description}\n\n---\n*来自 SmartDNS Edge 网页控制台用户的实时反馈*`;

  const githubApiUrl = `https://api.github.com/repos/${GITHUB_REPO}/issues`;

  try {
    // 5. 在服务器后台安全向 GitHub 发起创建 Issue 的请求（完全隐藏 Token 密钥）
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
        labels: [type.toLowerCase()] // 自动打上 bug 或 suggestion 标签
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

    // 6. 返回成功，将 Issue 的网页链接与编号回传给前端网页，让用户知晓
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

// 7. 处理浏览器的 Preflight (OPTIONS) 预检请求，防止跨域拦截
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