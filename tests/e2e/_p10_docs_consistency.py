# -*- coding: utf-8 -*-
"""第十批 D 组的验收检查：发布说明 / 安全策略与仓库实际状态的一致性。

## 为什么需要它

第十批**不碰主程序**，`cargo test` 在这里没有判别力：
它既不会读 `RELEASE_NOTES.md`，也不会检查 `SECURITY.md` 的引用是否悬空。
所以这一批的"回归保障"必须换成**对文档内容的断言**。

## 检查什么（每条都对应一个已修问题）

| # | 对应问题 | 断言 |
|---|---|---|
| 1 | **21** | 验证表里出现**版本绑定**说明（"本版本/发版提交实测"），否则数字无法溯源 |
| 2 | **21** | 验证表明确写出这些数字是**完整套件的总量**，不是本版新增数 |
| 3 | **43** | **编译器告警检查**与**风格/静态提示检查**被**分开列明**（不许再混成一句"0 错误 0 告警"） |
| 4 | **43** | 明确说明提示检查**是否阻断发布**（读者要知道它的门槛语义） |
| 5 | **20** | `SECURITY.md` 不再引用仓库里**不存在**的文档 |
| 6 | — | 中英文的验证数字**互相一致**（曾出现中文 27 项 / 英文 19 checks） |

用法：
    python tests/e2e/_p10_docs_consistency.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RELEASE_NOTES = ROOT / "RELEASE_NOTES.md"
SECURITY = ROOT / "SECURITY.md"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    mark = "PASS" if ok else "FAIL"
    line = f"  [{mark}] {name}"
    if not ok and detail:
        line += f" -- {detail}"
    print(line, flush=True)


def main():
    notes = RELEASE_NOTES.read_text(encoding="utf-8")
    security = SECURITY.read_text(encoding="utf-8")

    print("===== 第十批 D 组：文档一致性检查 =====")
    print("")

    # ---------- 问题 21：数字必须可溯源 ----------
    print("--- 问题 21：发布说明的数字要能溯源 ---")

    check(
        "验证表绑定了版本（写明是本版本/发版提交的实测值）",
        ("发版提交实测" in notes) or ("release commit" in notes),
        "没写清这些数字对应哪个提交，读者无法复核",
    )

    check(
        "说明了数字是「完整套件的总量」而非本版新增条数",
        ("完整套件的总量" in notes) or ("whole suite" in notes),
        "总量与增量的含义不同，必须写明是哪一个",
    )

    # ---------- 问题 43：两项检查必须分开 ----------
    print("")
    print("--- 问题 43：两项静态检查必须分开列明 ---")

    # 旧表述：把两项混成一句「静态检查 | 0 错误 0 告警」
    mixed = re.search(r"\|\s*静态检查\s*\|[^|]*0\s*错误\s*0\s*告警", notes)
    check(
        "不再把两项检查混成一句「静态检查 0 错误 0 告警」",
        mixed is None,
        f"仍在混用：{mixed.group(0).strip() if mixed else ''}",
    )

    check(
        "分列了「编译器告警检查」（-D warnings）",
        ("编译器告警检查" in notes) and ("-D warnings" in notes),
        "未单独说明编译器告警这道硬门槛",
    )

    check(
        "分列了「风格/静态提示检查」",
        ("风格与静态提示检查" in notes) or ("cargo clippy" in notes),
        "未单独说明 clippy/fmt 这类提示检查",
    )

    check(
        "说明了提示检查是否阻断发布",
        ("不阻断发布" in notes) or ("不会让 CI 失败" in notes) or ("without failing CI" in notes),
        "读者需要知道这道检查的门槛语义",
    )

    # ---------- 问题 20：不许引用不存在的文档 ----------
    print("")
    print("--- 问题 20：SECURITY.md 不得引用悬空文档 ---")

    # 扫描仓库里实际存在的文档名，确认被引用的文件确实在
    repo_docs = {
        p.name
        for p in ROOT.rglob("*.md")
        if ".git" not in p.parts and "target" not in p.parts
    }

    # 旧行为：声称"见仓库里的审计报告与处置状态文档"（**肯定语态**的引用）。
    # ⚠️ 不能只搜关键词 —— 修正后的文案会在**否定语态**下提到这个词
    # （"本仓库当前**不发布**审计报告…"），那是正确的表述。
    # 因此判据是：有没有"见/参见/详见 <这类文档>"这种**指向性的肯定引用**。
    pointing = re.search(
        r"(见|参见|详见|参考)[^。\n]{0,20}(审计报告|处置状态)",
        security,
    )
    check(
        "不再以肯定语态指向仓库里不存在的「审计报告/处置状态文档」",
        pointing is None,
        f"仍在指向：{pointing.group(0).strip() if pointing else ''}",
    )

    check(
        "明确说明这类清单当前不发布、以及理由",
        ("不发布" in security) and ("私密报告" in security),
        "删掉引用还不够，要告诉报告者结论从哪来",
    )

    # 兜底：SECURITY.md 里凡以「见仓库...」形式提到的 .md 都必须真实存在
    referenced = re.findall(r"`([A-Za-z0-9_.\-]+\.md)`", security)
    missing = [r for r in referenced if r not in repo_docs]
    check(
        "SECURITY.md 里提到的文件名都真实存在",
        not missing,
        f"引用了不存在的文件：{missing}",
    )

    # ---------- 中英文一致性 ----------
    print("")
    print("--- 中英文验证数字必须一致 ---")

    zh_unit = re.search(r"\|\s*单元测试\s*\|\s*(\d+)\s*通过", notes)
    en_unit = re.search(r"(\d+)\s*unit tests passing", notes)
    check(
        "中英文的单元测试数一致",
        bool(zh_unit) and bool(en_unit) and zh_unit.group(1) == en_unit.group(1),
        f"中文 {zh_unit.group(1) if zh_unit else '?'} vs 英文 {en_unit.group(1) if en_unit else '?'}",
    )

    # Linux 真机项数：中文写「共 N 项」，英文写「N checks」——曾经 27 vs 19
    zh_linux = re.search(r"共\s*(\d+)\s*项", notes)
    en_linux = re.search(r"(\d+)\s*checks on a real Linux", notes)
    check(
        "中英文的 Linux 真机项数一致",
        bool(zh_linux) and bool(en_linux) and zh_linux.group(1) == en_linux.group(1),
        f"中文 {zh_linux.group(1) if zh_linux else '?'} vs 英文 {en_linux.group(1) if en_linux else '?'}",
    )

    # ---------- 汇总 ----------
    print("")
    print("=" * 56)
    print(f"汇总: {len(PASS)} 通过 / {len(FAIL)} 失败")
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print(f"  - {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
