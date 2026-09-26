// SmartDNS Edge 官网页面的交互逻辑。
//
// 🔐 问题 23：本文件的内容**原先内联在 index.html 的 <script> 里**。
// 为配合内容安全策略（CSP）而抽出成外部文件，理由是：
//   · CSP 的 script-src 若放行内联脚本，就要维护一个 **hash**（内容改一个字就失效、
//     而失效的表现是**整页脚本被拦、官网白屏**，且静态检查完全看不出来）；
//   · 抽成外部文件后，script-src 'self' 即可，**没有需要同步维护的哈希**。
// 这比"用 hash 放行内联"更不容易出错 —— 后者已经实测踩过一次（见审查报告 §32）。
//
// ⚠️ 本文件必须是**独立文件**（不能改回内联），否则 CSP 会拦下它。
        // 安全数据存储容器（防 file:// 本地打开时浏览器安全策略报错）
        const safeStorage = {
            getItem(key) {
                try {
                    return localStorage.getItem(key);
                } catch (e) {
                    return this[key] || null;
                }
            },
            setItem(key, value) {
                try {
                    localStorage.setItem(key, value);
                } catch (e) {
                    this[key] = value;
                }
            }
        };

        // A. 5个主菜单的配置及其对应的 md 文件路径（相对于 docs 根路径，直接采用 `zh/` 或 `en/`）
        const menuConfig = {
            home: {
                zh: { label: '主页', file: './zh/main.md' },
                en: { label: 'Home', file: './en/main.md' }
            },
            install: {
                zh: { label: '安装与运行', file: './zh/install&run.md' },
                en: { label: 'Install & Run', file: './en/install&run.md' }
            },
            download: {
                zh: { label: '下载', file: './zh/download.md' },
                en: { label: 'Download', file: './en/download.md' }
            },
            config: {
                zh: { label: '配置指导', file: null },
                en: { label: 'Config Guide', file: null }
            },
            options: {
                zh: { label: '配置选项说明', file: './zh/configuration.md' },
                en: { label: 'Config Options', file: './en/configuration.md' }
            },
            feedback: {
                zh: { label: '问题反馈', file: './zh/feedback.md' },
                en: { label: 'Feedback', file: './en/feedback.md' }
            }
        };

        // B. “配置指导”对应的 8 个子模块配置文件信息
        const configModules = [
            {
                id: '1-basic-service.md',
                zh: { label: '1. 基础服务与监听配置', file: './zh/config/1-basic-service.md' },
                en: { label: '1. Basic Service', file: './en/config/1-basic-service.md' }
            },
            {
                id: '2-upstream-and-proxy.md',
                zh: { label: '2. 上游 DNS 与代理通道', file: './zh/config/2-upstream-and-proxy.md' },
                en: { label: '2. Upstream & Proxy', file: './en/config/2-upstream-and-proxy.md' }
            },
            {
                id: '3-speed-check.md',
                zh: { label: '3. 解析测速与 IP 优选', file: './zh/config/3-speed-check.md' },
                en: { label: '3. Speed Check', file: './en/config/3-speed-check.md' }
            },
            {
                id: '4-dns-cache.md',
                zh: { label: '4. 高性能 DNS 缓存机制', file: './zh/config/4-dns-cache.md' },
                en: { label: '4. DNS Cache', file: './en/config/4-dns-cache.md' }
            },
            {
                id: '5-domain-control.md',
                zh: { label: '5. 域名控制与广告拦截', file: './zh/config/5-domain-control.md' },
                en: { label: '5. Domain Control', file: './en/config/5-domain-control.md' }
            },
            {
                id: '6-ip-control.md',
                zh: { label: '6. IP 控制与 CDN 加速', file: './zh/config/6-ip-control.md' },
                en: { label: '6. IP Control', file: './en/config/6-ip-control.md' }
            },
            {
                id: '7-split-routing.md',
                zh: { label: '7. 智能分流与客户端控制', file: './zh/config/7-split-routing.md' },
                en: { label: '7. Split Routing', file: './en/config/7-split-routing.md' }
            },
            {
                id: '8-firewall-integration.md',
                zh: { label: '8. 高级防火墙联动', file: './zh/config/8-firewall-integration.md' },
                en: { label: '8. Firewall Integration', file: './en/config/8-firewall-integration.md' }
            }
        ];

        // 默认状态变量
        let currentLang = 'zh';
        let activeMenu = 'home';
        let activeSubConfig = '1-basic-service.md';

        // 获取当前语言状态
        function getLang() {
            return safeStorage.getItem('lang') || (navigator.language.startsWith('zh') ? 'zh' : 'en');
        }

        // 1. 初始化主题设置
        function initTheme() {
            const savedTheme = safeStorage.getItem('theme');
            const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            if (savedTheme === 'dark' || (!savedTheme && systemPrefersDark)) {
                document.documentElement.classList.add('dark');
                document.getElementById('theme-toggle').textContent = '☀️';
            } else {
                document.documentElement.classList.remove('dark');
                document.getElementById('theme-toggle').textContent = '🌙';
            }
        }

        // 手动开灯/关灯切换
        function toggleTheme() {
            const isDark = document.documentElement.classList.toggle('dark');
            safeStorage.setItem('theme', isDark ? 'dark' : 'light');
            document.getElementById('theme-toggle').textContent = isDark ? '☀️' : '🌙';
        }

        // 2. 路由逻辑解析器 (Hash-based Router)
        function handleHashRoute() {
            const hash = window.location.hash;
            let lang = getLang();
            let menu = 'home';
            let subFile = '1-basic-service.md';

            if (hash && hash.startsWith('#/')) {
                const parts = hash.slice(2).split('/');
                if (parts[0] === 'zh' || parts[0] === 'en') {
                    lang = parts[0];
                }
                if (menuConfig[parts[1]]) {
                    menu = parts[1];
                }
                if (parts[2]) {
                    subFile = parts[2];
                }
            }

            currentLang = lang;
            activeMenu = menu;
            activeSubConfig = subFile;

            // 同步下拉框状态
            safeStorage.setItem('lang', currentLang);
            document.getElementById('lang-select').value = currentLang;

            renderTopNav();
            renderSidebar();
            renderFooterPrivacy();
            loadMarkdown();
        }

        // 🔐 问题 23：页脚隐私说明跟随语言切换。
        //
        // 页脚是**静态 HTML**（不像导航那样由 JS 生成），所以需要在语言变化时重新填充。
        // 这里刻意跟随页面既有的模式：`handleHashRoute` 是语言切换的唯一入口，
        // 它已经在调用 `renderTopNav` / `renderSidebar`，本函数与它们并列。
        //
        // ⚠️ 用 `textContent` 而不是 `innerHTML` —— 隐私说明是纯文本，
        // 不涉及富文本，没有必要走 HTML 解析（这与问题 22 的整改方向一致）。
        function renderFooterPrivacy() {
            const el = document.getElementById('footer-privacy');
            if (!el) return; // 页脚被改掉时不报错，静默跳过
            el.textContent = currentLang === 'zh'
                ? '本页使用第三方访问计数服务（komarev.com）统计访问量：该请求会把你的 IP、浏览器标识与来源页发送给该服务。它不影响任何功能，可用广告拦截插件屏蔽。'
                : 'This page uses a third-party hit counter (komarev.com): that request sends your IP, browser identifier and referring page to that service. It does not affect any functionality and can be blocked with an ad blocker.';
        }

        // 3. 渲染主导航菜单
        function renderTopNav() {
            const nav = document.getElementById('main-nav');
            nav.innerHTML = '';
            Object.keys(menuConfig).forEach(key => {
                const item = menuConfig[key];
                const btn = document.createElement('button');
                btn.className = 'nav-item' + (key === activeMenu ? ' active' : '');
                // 改为读取当前语言对象下的 label
                btn.textContent = item[currentLang].label;
                btn.addEventListener('click', () => switchMenu(key));
                nav.appendChild(btn);
            });
        }

        // 4. 渲染或隐藏配置侧边栏（单/双栏切换）
        function renderSidebar() {
            const menu = document.getElementById('sidebar-menu');
            const container = document.getElementById('layout-container');

            if (activeMenu === 'config') {
                container.classList.remove('no-sidebar');
                menu.innerHTML = '';
                configModules.forEach(mod => {
                    const li = document.createElement('li');
                    // 使用唯一标识 id 进行激活项匹配
                    li.className = 'sidebar-item' + (mod.id === activeSubConfig ? ' active' : '');
                    // 改为读取当前语言对象下的 label
                    li.textContent = mod[currentLang].label;
                    li.addEventListener('click', () => switchSubConfig(mod.id));
                    menu.appendChild(li);
                });
            } else {
                container.classList.add('no-sidebar');
            }
        }

        // 5. 动态 Fetch 对应 Markdown 文件并渲染
        // 5. 动态 Fetch 对应 Markdown 文件并渲染（含表单自动注入与提交控制）
        async function loadMarkdown() {
            const contentArea = document.getElementById('markdown-content');
            contentArea.innerHTML = '<div class="loading">Loading...</div>';

            let url = '';
            if (activeMenu === 'config') {
                const activeMod = configModules.find(mod => mod.id === activeSubConfig);
                if (activeMod && activeMod[currentLang]) {
                    url = activeMod[currentLang].file;
                } else {
                    url = `./${currentLang}/config/${activeSubConfig}`;
                }
            } else {
                url = menuConfig[activeMenu][currentLang].file;
            }

            try {
                const response = await fetch(url);
                if (!response.ok) {
                    throw new Error(`File not found: ${url} (HTTP ${response.status})`);
                }
                const markdownText = await response.text();
                // 🔐 问题 22：这是页面上**唯一保留 HTML 拼接**的地方，且是**有前提的**。
                //
                // 现状与理由：
                //   · `markdownText` 来自**本站仓库**的 `.md` 文档（`fetch('./zh/...md')`），
                //     不是用户输入，也不来自第三方；
                //   · 已核实：这些文档里**没有** `<script>` / `<iframe>` / `onerror=`
                //     / `javascript:` 之类危险内容，但**有 63 处普通 HTML 标签**
                //     （`<br>`、`<table>` 等），是排版需要；
                //   · `marked` 本身**不做消毒**（它按设计只管转换）。所以"当前安全"
                //     完全依赖"文档受信"这个前提。
                //
                // ⚠️ **前提一旦变化，这里必须改**。以下任一情况发生，就要给输出接消毒组件
                //    （如 DOMPurify，需同样固定版本 + SRI）：
                //      ① 开放外部贡献文档（PR 里的 md 会直接进站点）；
                //      ② 改为渲染远程 URL 的内容（`?doc=https://...` 这类）；
                //      ③ 任何把**用户输入**写进 md 的流程。
                //    只加这条注释、不改代码，是因为当前引入消毒依赖的收益小于成本
                //    （会连带影响那 63 处合法 HTML 的排版）。这个取舍已记录在审查报告 §32。
                contentArea.innerHTML = marked.parse(markdownText);

                // 🌟 核心新增：检测页面是否含有反馈表单占位符，若有则自动注入表单并绑定逻辑
                injectFeedbackFormIfNeeded();
				
				// 🌟 核心新增：动态绑定防复制隐蔽下载事件
                bindSecureDownloadEvents();

            } catch (err) {
                // 🔐 问题 22：**错误信息必须按纯文本插入，不能拼进 HTML**。
                //
                // 原因：`err.message` 里带着 `url`，而 `url` 部分来自**地址栏 hash**
                // （`#/zh/config/xxx` 那一段）。报告已核实：按 URL 规范，`<` `>` `"` 在
                // 片段里会被百分号编码，所以**当前不构成注入漏洞**。
                // 但"当前恰好安全"不是可以依赖的性质 —— 只要将来有人换一种取 url 的方式
                // （例如从 `?query` 或服务端响应里取），这里立刻就是注入点。
                // 因此按"不消毒就不拼 HTML"的原则改造：结构用 DOM 建，外部数据一律 `textContent`。
                const errorBox = document.createElement('div');
                errorBox.className = 'error-msg';

                const h3 = document.createElement('h3');
                h3.textContent = '加载失败 (Load Error)';
                errorBox.appendChild(h3);

                const p1 = document.createElement('p');
                p1.textContent = '无法获取目标文档，请检查路径是否正确或稍后重试。';
                errorBox.appendChild(p1);

                // 出错详情的样式（与原来的内联样式等价，只是改成用 style 属性设置）
                const p2 = document.createElement('p');
                p2.style.cssText =
                    'font-size:0.85em; margin-top:8px; font-family:monospace; ' +
                    'background:rgba(0,0,0,0.04); padding:4px 8px; border-radius:4px;';
                p2.textContent = err.message; // ← 外部数据：纯文本插入
                errorBox.appendChild(p2);

                if (window.location.protocol === 'file:') {
                    const advice = document.createElement('div');

                    const t1 = document.createElement('p');
                    t1.style.cssText = 'margin-top:12px; color:#cf222e; font-weight:bold;';
                    t1.textContent = '⚠️ 检测到您目前是通过双击本地 HTML 文件 (file:// 协议) 打开的。';

                    const t2 = document.createElement('p');
                    t2.style.cssText = 'font-size:0.92rem; margin-top:4px;';
                    t2.textContent =
                        '由于浏览器的安全机制 (CORS)，直接在本地双击加载子文档会被浏览器拒绝，导致一直处于 Loading。';

                    const t3 = document.createElement('p');
                    t3.style.cssText = 'font-size:0.92rem; margin-top:4px; font-weight:bold;';
                    t3.textContent =
                        '解决方法：请使用本地静态网页服务器打开本页面。当您将该项目部署至 GitHub Pages 时，此问题会自动消失。';

                    advice.append(t1, t2, t3);
                    errorBox.appendChild(advice);
                }

                contentArea.replaceChildren(errorBox);
            }
        }

        // 🌟 核心新增：反馈表单注入与安全提交控制器
        function injectFeedbackFormIfNeeded() {
            const placeholder = document.getElementById("feedback-form-placeholder");
            if (!placeholder) return; // 没有占位符，说明不是反馈页面，直接退出

            const label_type = currentLang === 'zh' ? '反馈类型' : 'Feedback Type';
            const opt_bug = currentLang === 'zh' ? '🐛 Bug 反馈' : '🐛 Bug Report';
            const opt_enh = currentLang === 'zh' ? '💡 功能建议' : '💡 Enhancement';
            const opt_que = currentLang === 'zh' ? '💬 使用咨询' : '💬 Question';
			const label_title = currentLang === 'zh' ? '简短标题' : 'Title';
			const label_contact = currentLang === 'zh' ? '您的电子邮箱（选填，方便回复您）' : 'Your Email (Optional)';
            const label_desc = currentLang === 'zh' ? '详细问题描述（建议附带简要日志或配置，请勿包含私密密钥）' : 'Description';
			const tip_markdown = currentLang === 'zh' ? '💡 提示：本输入框支持 Markdown 语法。如需插入图片，可将其上传至任意免费图床（如 SM.MS 或路过图床），然后使用 `![描述](图片链接)` 格式粘贴到正文中即可。' : '💡 Tip: Markdown supported. To insert images, upload to an image host and use `![desc](image_url)` syntax.';
            const btn_submit = currentLang === 'zh' ? '提交反馈' : 'Submit';
            const msg_empty = currentLang === 'zh' ? '请填写标题与描述！' : 'Please fill in both title and description.';
            const msg_sending = currentLang === 'zh' ? '正在提交，请稍候...' : 'Submitting, please wait...';
            const msg_err = currentLang === 'zh' ? '反馈发送失败' : 'Submission failed';

            // 动态构建高度美观、完美契合亮/暗主题的 HTML 表单
            placeholder.innerHTML = `
                <div style="background-color: var(--bg-secondary); border: 1px solid var(--border-color); padding: 24px; border-radius: 8px; margin-top: 24px; box-shadow: var(--shadow);">
                    <form id="raw-feedback-form">
                    <div style="margin-bottom: 16px;">
                        <label style="display: block; font-weight: 600; margin-bottom: 6px; font-size: 0.95rem;">${label_type}</label>
                        <select id="fb-type" style="width: 100%; padding: 10px; background-color: var(--bg-primary); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: 6px; outline: none; font-size: 0.95rem;">
                            <option value="Bug">${opt_bug}</option>
                            <option value="Enhancement">${opt_enh}</option>
                            <option value="Question">${opt_que}</option>
                        </select>
                    </div>
					<div style="margin-bottom: 16px;">
                        <label style="display: block; font-weight: 600; margin-bottom: 6px; font-size: 0.95rem;">${label_title}</label>
                        <input type="text" id="fb-title" placeholder="e.g. Windows下服务无法正常自启" style="width: 100%; padding: 10px; background-color: var(--bg-primary); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: 6px; outline: none; font-size: 0.95rem;" required />
                    </div>
                    <div style="margin-bottom: 16px;">
                        <label style="display: block; font-weight: 600; margin-bottom: 6px; font-size: 0.95rem;">${label_contact}</label>
                        <input type="text" id="fb-contact" placeholder="e.g. email@example.com" style="width: 100%; padding: 10px; background-color: var(--bg-primary); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: 6px; outline: none; font-size: 0.95rem;" />
                    </div>
                    <div style="margin-bottom: 20px;">
                            <label style="display: block; font-weight: 600; margin-bottom: 6px; font-size: 0.95rem;">${label_desc}</label>
                            <textarea id="fb-desc" rows="16" placeholder="e.g. 1. 运行环境\n2. 具体复现步骤\n3. 终端报错日志" style="width: 100%; height: 320px; overflow-y: auto; padding: 10px; background-color: var(--bg-primary); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: 6px; outline: none; font-size: 0.95rem; font-family: monospace; resize: vertical;" required></textarea>
                            <small style="display: block; margin-top: 6px; color: var(--text-secondary); font-size: 0.85rem; line-height: 1.4;">${tip_markdown}</small>
                        </div>
                        <div id="fb-status-msg" style="margin-bottom: 16px; font-size: 0.95rem; font-weight: 500;"></div>
                        <button type="submit" id="fb-submit-btn" style="background-color: var(--accent-color); color: #ffffff; border: none; padding: 10px 24px; border-radius: 6px; cursor: pointer; font-size: 0.95rem; font-weight: 600; transition: background-color 0.2s;">${btn_submit}</button>
                    </form>
                </div>
            `;

            // 监听表单安全提交
            const form = document.getElementById("raw-feedback-form");
            // 🔐 记录表单「开始填写」的时刻，随请求一起提交。
            // 服务端据此判断提交速度是否像人类（秒填完的一律拒掉，见 functions/feedback.js）。
            const formOpenedAt = Date.now();
            form.addEventListener("submit", async (e) => {
                e.preventDefault();

                const type = document.getElementById("fb-type").value;
                const title = document.getElementById("fb-title").value.trim();
                const contact = document.getElementById("fb-contact").value.trim(); 
                const description = document.getElementById("fb-desc").value.trim();
                const statusMsg = document.getElementById("fb-status-msg");
                const submitBtn = document.getElementById("fb-submit-btn");

                if (!title || !description) {
                    statusMsg.innerHTML = `<span style="color: #cf222e;">⚠️ ${msg_empty}</span>`;
                    return;
                }

                // 准备锁死按钮，防止用户重复疯狂点击
                submitBtn.disabled = true;
                submitBtn.style.opacity = "0.6";
                statusMsg.innerHTML = `<span style="color: var(--text-secondary);">${msg_sending}</span>`;

                // 🌟 获取当前访问域名并自动拼接 API。
                const apiUrl = `${window.location.protocol}//${window.location.host}/feedback`;

                try {
                    const response = await fetch(apiUrl, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            type, title, description, contact,
                            ts: formOpenedAt,
                        }),
                    });

                    const resData = await response.json();

                    if (response.ok && resData.success) {
                        // 🔐 反馈先进入私有仓库等待审阅，用户看不到那个仓库，
                        // 因此这里不再回显 Issue 编号（给了也打不开、只会造成误解）。
                        statusMsg.innerHTML = `
                            <span style="color: #1a7f37; font-weight: bold; display: block; margin-bottom: 8px;">
                                💚 ${currentLang === 'zh' ? '反馈已收到，感谢你的提交！' : 'Feedback received. Thank you!'}
                            </span>
                            <span style="font-size: 0.92rem; color: var(--text-primary);">
                                ${currentLang === 'zh'
                                    ? '维护者会在审阅后处理。若需要跟进，我们可能会通过你留下的联系方式回复。'
                                    : 'The maintainer will review it. We may reply via the contact you provided.'}
                            </span>
                        `;
                        // 清空表单输入框，并让提交按钮隐退
                        document.getElementById("fb-title").value = "";
                        document.getElementById("fb-contact").value = "";
                        document.getElementById("fb-desc").value = "";
                        submitBtn.style.display = "none";
                    } else {
                        throw new Error(resData.error || "未知服务器异常");
                    }
                } catch (err) {
                    // 🔐 问题 22（重点）：这里的 `err.message` 来自**后端响应**
                    // （`throw new Error(resData.error || ...)`，见上，
                    //  而 `resData.error` 由 `functions/feedback.js` 决定）。
                    //
                    // 这是页面上**最危险的一处拼接**：后端完全可以回一句
                    // "标题含有非法字符 <img onerror=...>" 这类带用户输入的文案 ——
                    // 那一刻它就会被当 HTML 执行。前端不该赌后端永远不回显用户输入，
                    // 所以改成 DOM 构造 + `textContent`。
                    statusMsg.replaceChildren();
                    const span = document.createElement('span');
                    span.style.color = '#cf222e';
                    span.textContent = `❌ ${msg_err}: ${err.message}`;
                    statusMsg.appendChild(span);

                    submitBtn.disabled = false;
                    submitBtn.style.opacity = "1";
                }
            });
        }

        // 6. 交互路由跳转控制
        function switchMenu(key) {
            if (key === 'config') {
                window.location.hash = `#/${currentLang}/config/${activeSubConfig}`;
            } else {
                window.location.hash = `#/${currentLang}/${key}`;
            }
        }

        function switchSubConfig(file) {
            window.location.hash = `#/${currentLang}/config/${file}`;
        }

        function changeLang(newLang) {
            safeStorage.setItem('lang', newLang);
            if (activeMenu === 'config') {
                window.location.hash = `#/${newLang}/config/${activeSubConfig}`;
            } else {
                window.location.hash = `#/${newLang}/${activeMenu}`;
            }
        }

        // 🌟 核心新增：无链接隐蔽下载与右键拦截控制器
        function bindSecureDownloadEvents() {
            const dlLinks = document.querySelectorAll('.dl-link');
            dlLinks.forEach(link => {
                // 1. 拦截右键点击：当用户右键点击“点击下载”时，直接吞掉菜单，无法弹出“复制链接地址” [3]
                link.addEventListener('contextmenu', e => e.preventDefault());
                
                // 2. 监听左键点击：采用无感路由隐蔽跳转下载
                link.addEventListener('click', () => {
                    const fileKey = link.getAttribute('data-file');
                    if (fileKey) {
                        // 动态隐蔽启动下载流，对外绝对不暴露任何真实的绝对 URL 属性 [2]
                        window.location.href = `./download/${fileKey}`;
                    }
                });
            });
        }
		
		// 7. 脚本初始化执行入口
        document.addEventListener('DOMContentLoaded', () => {
            initTheme();

            // 🔐 问题 23：把原来写在 HTML 上的内联事件处理器（`onchange=` / `onclick=`）
            // 改成这里绑定。原因：CSP 的 `script-src` 若为了内联属性而加 `'unsafe-inline'`，
            // 就等于**放弃了对内联脚本注入的防护** —— 而问题 22 担心的正是这类注入。
            // 改用 `addEventListener` 后，CSP 可以完全不依赖 `'unsafe-inline'`。
            document.getElementById('lang-select')
                .addEventListener('change', (e) => changeLang(e.target.value));
            document.getElementById('theme-toggle')
                .addEventListener('click', () => toggleTheme());

			// 🌟 自动触发 GitHub 访问计数器（通过后台静默加载图片）
            // 🔐 问题 23：这是**向第三方发出的请求**，会把访客的 IP、浏览器标识、
            // 来源页暴露给 komarev.com，且页面上没有隐私说明。
            // 处置：① 加 `referrerpolicy` 之类无从设置（Image 对象），所以改为**可关闭**——
            //        默认仍然加载（保留既有的计数功能），但受 CSP `img-src` 约束；
            //      ② 隐私说明写进页脚（见下方 HTML 与 `docs/zh|en/main.md`）。
            // 若日后决定彻底去掉第三方统计，把下面这一行删除即可（不影响任何功能）。
            new Image().src = "https://komarev.com/ghpvc/?username=Gdxz-Linus&repo=smartdns-edge&color=0969da&t=" + Date.now();

            // 绑定 Logo 的点击跳转
            document.getElementById('header-logo').addEventListener('click', () => {
                window.location.hash = `#/${getLang()}/home`;
            });

            // 如果首次进入页面且无 Hash 路由，跳转至默认 Hash
            if (!window.location.hash) {
                window.location.hash = `#/${getLang()}/home`;
            }

            // 监听 Hash 变化
            window.addEventListener('hashchange', handleHashRoute);
            handleHashRoute();
        });
