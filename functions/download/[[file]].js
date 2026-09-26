// functions/download/[[file]].js - Cloudflare Pages 专用隐藏源站极速下载函数
const GITHUB_REPO = 'Gdxz-Linus/smartdns-edge';

// 漂亮的短链接别名映射表（自动匹配并翻译为 GitHub 上的最新文件名）
//
// 🔐 问题 4：这张表同时是**唯一允许的入口名单**。
// 以前未命中映射时会"直接把用户输入当文件名"拼进 GitHub 地址，
// 那等于让调用者**自由探测仓库里的其它发布资源**，并把 GitHub 的状态码回显出去当探测信号。
// 现在未命中就 404（见下），所以**新增平台必须在这里登记**。
//
// 取值依据：`docs/zh|en/download.md` 里的 `data-file` 属性是**唯一**的调用方，
// 它只用到下面这 6 个别名（已全仓库检索确认，没有别处再用"原名"直连）。
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

// 🔐 问题 4：映射表里的目标文件名仍要过一遍**白名单**（纵深防御）。
//
// 理由：`FILE_MAP` 是常量、当前都安全，但它是**会被人改的**（新增平台时就要加一行）。
// 万一将来有人不小心写进 `../` 或奇怪字符，这里能挡住，不必依赖"下次还记得检查"。
// 允许的字符集就是 GitHub Release 资产名的实际范围：字母、数字、点、下划线、连字符。
const SAFE_ASSET_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

// 🔐 问题 7：CORS 收紧。
//
// 原来是无条件 `Access-Control-Allow-Origin: *` —— 意思是**任意网站都能用脚本读取本接口的
// 响应内容**（不只是触发一次下载）。这与本接口自身"防盗链"的意图直接矛盾。
// 下载本身**不需要 CORS**：`<a>`/`window.location` 跳转或直接让浏览器下载都不受同源策略限制。
// 所以这里改为**只对自己站点回允许头**（不带 `*`）——
// 既不影响正常下载，也不再让第三方页面把本接口当"可读的 API"。
const ALLOWED_ORIGIN_SUFFIXES = ['smartdns-edge.pages.dev', 'downloads-21j.pages.dev'];

function corsOriginFor(request) {
  const origin = request.headers.get('Origin');
  if (!origin) return null; // 非跨域请求，无需该头
  try {
    const host = new URL(origin).hostname;
    const ok = ALLOWED_ORIGIN_SUFFIXES.some(
      (h) => host === h || host.endsWith('.' + h)
    );
    return ok ? origin : null; // 不在名单里就**不回** CORS 头（浏览器自然拦住读取）
  } catch {
    return null;
  }
}

export async function onRequest(context) {
  const { request, params } = context;

  // 🌟 宽松防盗链校验 (允许直接复制下载，封杀第三方网站盗用) [1.2.2]
  //
  // 🔐 问题 4（按用户定调保留现状）：**仍然只在"带了 Referer"时才校验**。
  // 为什么不改成"缺 Referer 也拒绝"：安装包本身是公开资源，防盗链的价值有限；
  // 而从严会让"在地址栏粘贴链接""用下载工具"这类**正常用法**失败，代价大于收益。
  // 因此这里不动，真正修的是另外三处（未命中→404 / 文件名白名单 / 不回显内部错误）。
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

  // 🔐 问题 4（核心修复）：**未命中映射表就 404，不再把用户输入当文件名往下传**。
  //
  // 原来的 `FILE_MAP[fileKey] || fileKey` 有两个问题：
  //   ① 调用者可以拿它**探测仓库里有哪些发布资源**（任意猜一个名字，
  //      由返回的状态码判断存在与否）；
  //   ② 备注里写的"如用户请求校验文件"其实**已经不成立** ——
  //      已全仓库检索确认：官网没有任何地方链接 `*-sha256sum.txt`。
  // 所以这里直接拒绝，并把"该请求什么"说清楚（可操作性）。
  const targetFile = FILE_MAP[fileKey];
  if (!targetFile) {
    return new Response(
      `404 Not Found: unknown download key '${fileKey}'.\n` +
      `Available keys: ${Object.keys(FILE_MAP).join(', ')}\n`,
      { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
    );
  }

  // 🔐 问题 4：映射结果本身也要过白名单（纵深防御，防将来改表时写错）
  if (!SAFE_ASSET_NAME.test(targetFile) || targetFile.includes('..')) {
    // 这是**我们自己的配置错误**，不是调用方的问题 —— 不能把它当成 404 糊过去，
    // 否则将来加错一行、用户只会看到"文件不存在"，排查方向全错。
    console.error('download map produced an unsafe asset name', { fileKey, targetFile });
    return new Response('500 Internal Server Error', { status: 500 });
  }

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
      // 🔐 问题 4：**不再把 GitHub 的状态码原样回显**。
      // 原来 `File not found (${response.status})` 会让调用者拿到上游状态当探针信号。
      // 上游 5xx 是"我们这边取不到"，对本接口的调用者来说仍是"暂时没有这个文件" ——
      // 统一成 404 + 稳定文案，既不泄露上游，也不给探测留下差异化响应。
      return new Response('File not found', {
        status: 404,
        headers: { 'Content-Type': 'text/plain' }
      });
    }

    const headers = new Headers(response.headers);
    // 🔐 问题 7：只在来源确实是自家站点时才回 CORS 头（不再无条件 `*`）
    const allowOrigin = corsOriginFor(request);
    if (allowOrigin) {
      headers.set('Access-Control-Allow-Origin', allowOrigin);
      // 回具体来源时要带上 Vary，避免中间缓存把某个来源的响应当成通用响应
      headers.append('Vary', 'Origin');
    } else {
      headers.delete('Access-Control-Allow-Origin');
    }
    headers.set('Content-Disposition', `attachment; filename="${targetFile}"`);
    headers.delete('Location'); // 彻底删除可能泄露源站的重定向相应头

    // 以 200 OK 直接把文件数据流推送给用户
    return new Response(response.body, {
      status: 200,
      headers: headers
    });
  } catch (e) {
    // 🔐 问题 4：**错误详情只写服务端日志，不回给调用方**。
    // 原来 `'Proxy Error: ' + e.message` 会把内部信息（例如 fetch 的失败细节）暴露出去。
    console.error('download proxy failed', { fileKey, targetFile, error: e && e.message });
    return new Response('Bad Gateway', { status: 502 });
  }
}