# -*- coding: utf-8 -*-
"""第十批 B 组的验证：发布流程的结构断言（问题 18、17）。

## 为什么是"结构断言"而不是端到端

B 组改的是**发版流程**。它的端到端验证意味着**真的发一次版** ——
那会 `git push --follow-tags` 到远端、创建标签、发布 Release。
这是不可接受的副作用（一次错误发版会占用版本号、污染历史）。

所以本脚本验证的是**流程结构**：顺序对不对、该固定的固定了没有、
会不会在测试之前写远端。它**不能**证明"整条流水线真能跑通"（那只能在
下一次真实发版时才知道），但能挡住"顺序写反""忘了固定版本"这类**结构性错误**。

## 检查什么

| # | 对应 | 断言 |
|---|---|---|
| 1 | **18** | `bump` 任务依赖 `test`（即测试先跑） |
| 2 | **18** | `bump` 里**唯一**会写远端的那一步，其前置是测试通过 |
| 3 | **18** | 全仓库**只有一处** `git push`（避免别处偷偷推送） |
| 4 | **18** | `build` 依赖 `bump`（保证顺序：测试 → 升版本 → 打包发布） |
| 5 | **17** | 所有外部 action 都固定到 **40 位 commit SHA** |
| 6 | **17** | 保留可读性：每个 SHA 后带 `# 版本号` 注释 |
| 7 | **17** | 发布前存在"独立复核校验值"的步骤，且位于 publish 之前 |
| 8 | — | workflow 里引用的本地 action 路径都真实存在 |

用法：
    python tests/e2e/_p10_release_flow.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github" / "workflows"
ACTIONS = ROOT / ".github" / "actions"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if not ok and detail else ""), flush=True)


def main():
    version = (WF / "version.yml").read_text(encoding="utf-8")
    build = (WF / "build.yml").read_text(encoding="utf-8")
    test = (WF / "test.yml").read_text(encoding="utf-8")

    print("===== 第十批 B 组：发布流程结构断言 =====")
    print("")

    # ---------- 问题 18：测试必须先于"写远端" ----------
    print("--- 问题 18：测试必须跑在写远端之前 ---")

    # 取出各 job 的块（粗略按顶层 job 名切分即可）
    def job_block(text, job):
        m = re.search(rf"^  {job}:\n(.*?)(?=^  [A-Za-z_-]+:\n|\Z)", text, re.M | re.S)
        return m.group(1) if m else ""

    bump = job_block(version, "bump")
    check("解析到了 bump 任务", bool(bump), "job 结构变了，检查解析规则")

    needs = re.search(r"needs:\s*\[([^\]]*)\]", bump)
    needs_list = [s.strip().strip('"\'') for s in needs.group(1).split(",")] if needs else []
    check("bump 依赖 test（测试先跑）", "test" in needs_list, f"bump.needs={needs_list}")

    test_block = job_block(version, "test")
    check("test 任务不再依赖 bump（否则成环）",
          "bump" not in (re.search(r"needs:\s*\[([^\]]*)\]", test_block) or type("", (), {"group": lambda *_: ""})()).group(1),
          "test 与 bump 互相依赖会形成环")

    # 全仓库只有一处 git push（只数**真正的命令行**，不数注释里提到的）
    all_wf = list(WF.glob("*.yml"))
    pushes = []
    for f in all_wf:
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            # ⚠️ 必须排除注释行：说明文字里会提到 `git push`（描述旧行为），
            #    第一版没排除，于是把注释也数进来、报了个假失败。
            if stripped.startswith("#"):
                continue
            if re.search(r"\bgit\s+push\b", line):
                pushes.append(f"{f.name}:{i}")
    check("全仓库只有一处 git push（写远端）", len(pushes) == 1, f"发现 {len(pushes)} 处：{pushes}")

    # 那处 push 必须落在 bump 任务里（也就是已被 needs: test 门禁保护）
    check("唯一的 git push 位于 bump 任务内（受测试门禁保护）",
          any(p.startswith("version.yml") for p in pushes),
          f"push 出现在：{pushes}")

    build_needs = re.search(r"^  build:\n(.*?)needs:\s*\[([^\]]*)\]", version, re.M | re.S)
    check("build 依赖 bump（顺序：测试→升版本→打包）",
          bool(build_needs) and "bump" in build_needs.group(2),
          f"build.needs={build_needs.group(2) if build_needs else '解析失败'}")

    # ---------- 问题 17：action 必须固定到 SHA ----------
    print("")
    print("--- 问题 17：外部 action 必须固定到 commit SHA ---")

    sources = {
        "build.yml": build,
        "test.yml": test,
        "setup/action.yml": (ACTIONS / "setup" / "action.yml").read_text(encoding="utf-8"),
    }

    sha_re = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)(?:\s*#\s*(.*))?$", re.M)
    floating, pinned, local = [], [], []
    for fname, text in sources.items():
        for m in sha_re.finditer(text):
            ref = m.group(1)
            if ref.startswith("./"):
                local.append(ref)
                continue
            if "@" not in ref:
                floating.append(f"{fname}:{ref}")
                continue
            _repo, _, ver = ref.rpartition("@")
            if re.fullmatch(r"[0-9a-f]{40}", ver):
                pinned.append((ref, (m.group(2) or "").strip()))
            else:
                floating.append(f"{fname}:{ref}")

    check(f"所有外部 action 都已固定到 40 位 SHA（共 {len(pinned)} 处）",
          not floating, f"仍浮动：{floating}")
    check("固定的 action 都带了版本注释（便于日后升级）",
          all(cmt for _, cmt in pinned),
          f"缺注释：{[r for r, c in pinned if not c]}")

    # 本地 action 路径必须存在
    # ⚠️ 拼接时不能用 `ROOT / ref.lstrip("./")` —— `lstrip` 会按**字符集**剥离，
    #    `"./.github/actions/setup".lstrip("./")` 会把开头的 `.` `/` 全啃掉，
    #    得到 `.github/actions/setup` 尚可，但对别的路径（如 `./a/../b`）语义就错了。
    #    这里显式去掉前缀更稳。
    missing_local = []
    for ref in set(local):
        rel = ref[2:] if ref.startswith("./") else ref
        p = ROOT / rel
        if not (p.is_dir() or p.is_file()):
            missing_local.append(ref)
    check("引用的本地 action 路径都存在", not missing_local, f"缺失：{missing_local}")

    # ---------- 问题 17：发布前独立复核 ----------
    print("")
    print("--- 问题 17：发布前的独立复核步骤 ---")

    verify_idx = build.find("Verify artifact checksums before publishing")
    publish_idx = build.find("- name: Publish release")
    check("存在发布前的校验复核步骤", verify_idx >= 0, "没找到该步骤")
    check("复核步骤位于 Publish release **之前**",
          verify_idx >= 0 and publish_idx >= 0 and verify_idx < publish_idx,
          f"verify@{verify_idx} publish@{publish_idx}")
    # 复核必须真的重算（而不是只读自带的文件）
    verify_block = build[verify_idx:publish_idx] if verify_idx >= 0 and publish_idx > verify_idx else ""
    check("复核确实**重新计算**了哈希（而非只回显校验文件）",
          "sha256sum " in verify_block and "actual" in verify_block,
          "没看到独立重算的痕迹")

    # ---------- 问题 18 延伸：重复测试的削减（paths-ignore / concurrency） ----------
    print("")
    print("--- 问题 18 延伸：削减「版本号提交」带来的重复测试 ---")

    # ① paths-ignore 只能忽略"版本号文件"，不能忽略可能含实质内容的文件
    check("test.yml 的 push 忽略 Cargo.toml / Cargo.lock（版本号提交）",
          "'Cargo.toml'" in test and "'Cargo.lock'" in test and "paths-ignore" in test,
          "没找到 paths-ignore 或缺少这两个文件")
    check("paths-ignore **不含** RELEASE_NOTES.md（它可能含实质内容，必须测）",
          "RELEASE_NOTES.md" not in test.split("paths-ignore")[1][:400] if "paths-ignore" in test else False,
          "把 RELEASE_NOTES.md 也忽略了 —— 发版说明里的实质改动会漏测")

    # ② concurrency：必须存在，且**不能影响发布门禁**
    check("test.yml 配置了 concurrency（取消过时的自动运行）",
          "concurrency:" in test and "cancel-in-progress:" in test,
          "没找到 concurrency 配置")

    conc = re.search(r"^concurrency:\n((?:[ \t]+.*\n?)+)", test, re.M)
    conc_block = conc.group(1) if conc else ""
    # ⚠️ 只取 **group 那一行**再判 —— 第一版是在整个 concurrency 块里找 `event_name`，
    #    而 `cancel-in-progress` 那行**也含** `event_name`，于是
    #    「把 group 里的 event_name 去掉」这个反向验证**没能被抓住**（假通过）。
    #    判据范围过宽必须当场收紧。
    group_line = ""
    for _line in conc_block.splitlines():
        if _line.strip().startswith("group:"):
            group_line = _line.strip()
            break

    # ⚠️ 最关键的一条：group 必须带 event_name，否则 push 会取消正在跑的发布门禁
    check("concurrency.group 含 github.event_name（门禁与普通推送不同组）",
          "event_name" in group_line,
          f"group 行为 {group_line!r} —— 不含 event_name，普通 push 可能取消正在跑的发布门禁，"
          "而门禁被取消后 bump 仍会推送远端，问题 18 的修复会静默失效")
    check("concurrency 的取消仅在 push / pull_request 时生效",
          "cancel-in-progress" in conc_block and "push" in conc_block and "pull_request" in conc_block,
          "取消条件未限定事件类型")

    # ③ 门禁本身必须仍然存在（不能在削减重复时把它一起砍掉）
    # ⚠️ 必须排除**注释行**：注释里也提到 `workflow_call`
    #    （"发布流程会调用本工作流…因此必须声明 workflow_call"），
    #    第一版直接 `"workflow_call" in test`，于是"把真实的键删掉"这个反向验证**假通过**。
    on_block = test[:test.find("jobs:")] if "jobs:" in test else test
    real_keys = [
        line.strip()
        for line in on_block.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    check("test.yml 仍保留 workflow_call（发布门禁要用）",
          any(k.startswith("workflow_call") for k in real_keys),
          "砍掉了 workflow_call（或它只出现在注释里）—— "
          "version.yml 的 `uses: ./.github/workflows/test.yml` 会报错")

    print("")
    print("=" * 56)
    print(f"汇总: {len(PASS)} 通过 / {len(FAIL)} 失败")
    for f in FAIL:
        print(f"  - {f}")
    print("")
    print("⚠️ 本脚本只做**结构断言**：它能挡住「顺序写反 / 忘了固定版本」这类结构性错误，")
    print("   但**不能**证明整条流水线真能跑通（那需要一次真实发版，代价不可接受）。")
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
