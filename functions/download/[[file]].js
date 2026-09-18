// functions/download/[[file]].js - Cloudflare Pages 专用隐藏源站极速下载函数
const GITHUB_REPO = 'Gdxz-Linus/smartdns-edge';

// 漂亮的短链接别名映射表（自动匹配并翻译为 GitHub 上的最新文件名）
const FILE_MAP = {
  // Windows
  'windows-x64': 'smartdns-x86_64-pc-windows-msvc.zip',
  'windows-arm64': 'smartdns-aarch64-pc-windows-msvc.zip',

  // Linux
  'linux-x64': 'smartdns-x86_64-generic-linux-gnu.tar.gz',
  'linux-arm64': 'smartdns-aarch64-generic-linux-gnu.tar.gz',

  // macOS
  'mac-intel': 'smartdns-x86_64-apple-darwin.zip',
  'mac-arm64': 'smartdns-aarch64-apple-darwin.zip',
};

export async function onRequest(context) {
  const { request, params } = context;

  // 🌟 核心安全新增：宽松防盗链校验 (允许直接复制下载，封杀第三方网站盗用) [1.2.2]
  const referer = request.headers.get('Referer');
  if (referer) {
    try {
      const refUrl = new URL(referer);
      // 允许的白名单域名（只允许您自己的官网、本地调试环境）
      const allowedHosts = [
        'smartdns-edge.pages.dev',
        'downloads-21j.pages.dev',
        'localhost',
        '127.0.0.1'
      ];

      // 判断来源网站域名是否在白名单中
      const isAllowed = allowedHosts.some(host => 
        refUrl.hostname === host || refUrl.hostname.endsWith('.' + host)
      );

      // 🚨 拦截：发现是第三方网站在恶意盗用下载链接，直接返回 403 拒绝访问 [1.2.2]
      if (!isAllowed) {
        return new Response('403 Forbidden: Hotlinking is not allowed from this website.', {
          status: 403,
          headers: { 'Content-Type': 'text/plain' }
        });
      }
    } catch (e) {
      // 解析异常时放行，确保可用性
    }
  }
  
  // 自动从路径参数中提取文件名标识
  const fileKey = params.file ? params.file[0] : '';
  
  if (!fileKey) {
    return new Response('No file specified', { status: 400 });
  }

  // 匹配映射表拿到真实文件名，若未匹配到（如用户请求校验文件），则直接作为原名向下传递
  const targetFile = FILE_MAP[fileKey] || fileKey;
  
  // 在服务器后台悄悄拼接 GitHub 最新 Release 的底端下载 URL
  const githubUrl = `https://github.com/${GITHUB_REPO}/releases/latest/download/${targetFile}`;

  try {
    // 🌟 在 CF 内部服务器上发起 fetch 并自动跟随 302 重定向 (redirect: 'follow')
    // 重定向全在 Cloudflare 的服务器间完成，100% 隐藏 github.com 域名
    const response = await fetch(githubUrl, {
      method: request.method,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      },
      redirect: 'follow'
    });

    if (!response.ok) {
      return new Response(`File not found (${response.status})`, { status: response.status });
    }

    const headers = new Headers(response.headers);
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Content-Disposition', `attachment; filename="${targetFile}"`);
    headers.delete('Location'); // 彻底删除可能泄露源站的重定向相应头

    // 以 200 OK 直接把文件数据流推送给用户
    return new Response(response.body, {
      status: 200,
      headers: headers
    });
  } catch (e) {
    return new Response('Proxy Error: ' + e.message, { status: 500 });
  }
}