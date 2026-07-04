// Cloudflare Worker: SmartDNS Edge 隐藏源站的流式下载代理
const GITHUB_REPO = 'Gdxz-Linus/smartdns-edge';

// 短链接别名映射表（自动匹配 GitHub 上的最新文件名）
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

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/+|\/+$/g, ''); // 提取清理路径

  // 1. 如果直接访问根目录，返回可视化下载导航页面
  if (!path) {
    return new Response(
      `<!DOCTYPE html>
       <html>
       <head><title>SmartDNS Edge Direct Downloads</title></head>
       <body style="font-family:sans-serif; padding:2rem; line-height:1.6;">
         <h2>🐋 SmartDNS Edge 直接下载点</h2>
         <p>点击下方链接直接下载最新版（全全程隐蔽源站）：</p>
         <ul>
           <li><a href="/download/windows-x64">Windows (x64)</a></li>
           <li><a href="/download/windows-arm64">Windows (ARM64)</a></li>
           <li><a href="/download/linux-x64">Linux (x64)</a></li>
           <li><a href="/download/linux-arm64">Linux (ARM64)</a></li>
           <li><a href="/download/mac-intel">macOS (Intel)</a></li>
           <li><a href="/download/mac-arm64">macOS (Apple Silicon)</a></li>
         </ul>
       </body>
       </html>`,
      { headers: { 'content-type': 'text/html;charset=UTF-8' } }
    );
  }

  // 2. 匹配短链接，例如 /download/windows-arm64 或 /download/smartdns-aarch64-pc-windows-msvc.zip
  let key = path;
  if (path.startsWith('download/')) {
    key = path.replace('download/', '');
  }
  
  // 匹配映射表，如果未命中别名，则直接作为原生文件名使用
  const targetFile = FILE_MAP[key] || key;

  // 3. 在服务器端静默构造 GitHub 最新版的真实下载 URL
  const githubUrl = `https://github.com/${GITHUB_REPO}/releases/latest/download/${targetFile}`;

  try {
    // 4. 【核心】：在 CF 内部服务器上发起 fetch 并自动跟随重定向 (redirect: 'follow')
    // 这样 302 重定向过程全在 Cloudflare 内部完成，绝不向客户端暴露真正的 githubusercontent 链接！
    const response = await fetch(githubUrl, {
      method: request.method,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      },
      redirect: 'follow'
    });

    if (!response.ok) {
      return new Response(`File not found or upstream error (${response.status})`, { status: response.status });
    }

    // 5. 构造纯净响应，强制触发文件下载并隐蔽真实 Location
    const headers = new Headers(response.headers);
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Content-Disposition', `attachment; filename="${targetFile}"`);
    headers.delete('Location'); // 彻底删除可能泄露源站的重定向响应头

    // 以 200 OK 直接把文件数据流推给用户
    return new Response(response.body, {
      status: 200,
      headers: headers
    });
  } catch (e) {
    return new Response('Proxy Stream Error: ' + e.message, { status: 500 });
  }
}