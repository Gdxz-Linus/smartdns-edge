# -*- coding: utf-8 -*-
"""官网死链与悬空引用检查（第十批 C 组配套）。

## 为什么查这个

问题 20 的原文是：「`SECURITY.md` 里告诉报告者……见仓库里的审计报告与处置状态文档，
但**仓库和官网里都没有这份文件**」。D 组已修掉 `SECURITY.md` 那一处，
但报告特意点了"**官网**"，所以要确认官网侧是否存在**同类悬空引用**。

顺带把官网所有**内部链接**（文档互链、锚点）都过一遍：
官网是用户下载安装包、提交反馈的入口，死链会直接影响可用性。

## 检查什么

| # | 断言 |
|---|---|
| 1 | 官网里不得引用「审计报告 / 处置状态」这类不存在的文档 |
| 2 | `index.html` / `functions/` 里引用的**仓库内文件**都必须真实存在 |
| 3 | Markdown 文档里的**站内相对链接**（`xxx.md` / `./xxx.md`）必须存在 |
| 4 | `menuConfig` / `configModules` 里登记的**每个文档路径**都必须真实存在 |
| 5 | 引用的第三方资源必须带**版本号**（问题 23 的前半） |

用法：
    python tests/e2e/_p10_docs_links.py
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # D:\smartdns-edge
DOCS = ROOT.parent / "smartdns-edge-docs"
DOCS_DIR = DOCS / "docs"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if not ok and detail else ""), flush=True)


def main():
    if not DOCS_DIR.is_dir():
        print(f"找不到文档站仓库：{DOCS_DIR}")
        return 1

    index = (DOCS_DIR / "index.html").read_text(encoding="utf-8")
    print("===== 第十批 C 组：官网死链与悬空引用检查 =====")
    print("")

    # ---------- 1. 悬空引用（问题 20 的官网侧） ----------
    print("--- 悬空引用（问题 20 官网侧）---")
    dangling = re.search(r"(见|参见|详见)[^。\n<]{0,20}(审计报告|处置状态)", index)
    check(
        "官网不指向不存在的「审计报告/处置状态」",
        dangling is None,
        f"仍在指向：{dangling.group(0).strip() if dangling else ''}",
    )
    # 也不该出现"点击查看报告"这类按钮
    check(
        "官网没有「审计报告/处置状态」的下载或跳转入口",
        not re.search(r"(href|src)\s*=\s*[\"'][^\"']*(audit|处置)[^\"']*[\"']", index, re.I),
        "发现了可疑的跳转入口",
    )

    # ---------- 2. menuConfig / configModules 登记的路径 ----------
    print("")
    print("--- 菜单登记的文档路径必须存在 ---")
    # ⚠️ 菜单配置在 `app.js` 里（问题 23 的整改把那段内联脚本抽成了外部文件）。
    #    第一版只在 index.html 里找，抽取之后就"一个都解析不到"了 ——
    #    这类"检查脚本自身过时"要当场修脚本（判据跟着实现走）。
    app_js = DOCS_DIR / "app.js"
    menu_src = app_js.read_text(encoding="utf-8") if app_js.is_file() else index
    # 形如：file: './zh/config/6-ip-control.md'
    files = re.findall(r"file:\s*['\"]([^'\"]+\.md)['\"]", menu_src)
    check("菜单里登记了文档路径", bool(files), "一个都没解析到，检查解析规则是否过时")
    missing = []
    for f in sorted(set(files)):
        # './zh/x.md' 相对 docs/ 根
        p = (DOCS_DIR / f.lstrip("./")).resolve()
        if not p.is_file():
            missing.append(f)
    check(
        f"菜单登记的 {len(set(files))} 个文档路径都存在",
        not missing,
        f"缺失：{missing}",
    )

    # ---------- 3. Markdown 站内相对链接 ----------
    print("")
    print("--- Markdown 站内相对链接必须存在 ---")
    md_files = list(DOCS_DIR.rglob("*.md"))
    broken = []
    for md in md_files:
        text = md.read_text(encoding="utf-8", errors="ignore")
        for target in re.findall(r"\]\((\.{0,2}/?[^)#:]+\.md)(?:#[^)]*)?\)", text):
            p = (md.parent / target).resolve()
            if not p.is_file():
                broken.append(f"{md.relative_to(DOCS_DIR)} -> {target}")
    check(
        f"{len(md_files)} 个 Markdown 文档的站内链接都有效",
        not broken,
        f"死链 {len(broken)} 处：{broken[:5]}",
    )

    # ---------- 4. index.html 里的本地资源 ----------
    print("")
    print("--- index.html 引用的本地资源必须存在 ---")
    local_refs = re.findall(r"(?:href|src)\s*=\s*[\"']([^\"'>]+)[\"']", index)
    bad_local = []
    for ref in local_refs:
        if ref.startswith(("http://", "https://", "//", "#", "data:", "mailto:")):
            continue
        p = (DOCS_DIR / ref.lstrip("./")).resolve()
        if not p.exists():
            bad_local.append(ref)
    check(
        "index.html 的本地 href/src 都存在",
        not bad_local,
        f"缺失：{bad_local}",
    )

    # ---------- 5. 第三方资源必须固定版本（问题 23） ----------
    print("")
    print("--- 第三方资源必须固定版本（问题 23）---")
    ext_scripts = re.findall(r"<script[^>]+src=[\"'](https?://[^\"']+)[\"']", index)
    unpinned = []
    for url in ext_scripts:
        # 固定版本的判据：路径里出现 @x.y.z（语义化版本），而不是光秃秃的包名
        if not re.search(r"@\d+\.\d+\.\d+", url):
            unpinned.append(url)
    check(
        f"{len(ext_scripts)} 个第三方脚本都固定了版本",
        not unpinned,
        f"未固定版本：{unpinned}",
    )

    has_integrity = bool(re.search(r"<script[^>]+integrity=[\"']sha(256|384|512)-", index))
    check("第三方脚本带完整性校验（SRI）", has_integrity, "缺少 integrity 属性")

    # ---------- 6. CSP（问题 23） ----------
    print("")
    print("--- 内容安全策略（问题 23）---")
    has_csp_meta = bool(re.search(r"http-equiv=[\"']Content-Security-Policy[\"']", index, re.I))
    check("页面设置了 CSP（meta 或响应头）", has_csp_meta, "未发现 CSP（meta 形式）")

    # ---------- 汇总 ----------
    print("")
    print("=" * 56)
    print(f"汇总: {len(PASS)} 通过 / {len(FAIL)} 失败")
    for f in FAIL:
        print(f"  - {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
