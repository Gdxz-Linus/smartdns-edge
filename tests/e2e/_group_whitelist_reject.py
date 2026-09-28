#!/usr/bin/env python3
"""真机验证：没有组级写法的参数写进 `group-begin`，必须被拒绝且不污染全局。

## 为什么必须真机验

单元测试证明的是"配置解析后全局没被改"；真机要证明的是
**"从一份真实配置文件启动 → 日志里真的给出了提示"** ——
用户是靠日志知道"这一行被忽略了"的，提示不出现等于静默失效。

## 判据（成对）

  · 组里写了 `cache-size` → 日志必须出现该行被忽略的提示，
    且**启动出来的全局缓存容量仍是顶层的值**；
  · 组里只写合法参数     → **不得**出现该提示（防"无脑打印"）。
"""
import os
import subprocess
import sys
import tempfile
import time

REPO = "/mnt/d/smartdns-edge"
BIN = os.path.join(REPO, "target/debug/smartdns")

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  [PASS] {msg}")


def bad(msg):
    global FAIL
    FAIL += 1
    print(f"  [FAIL] {msg}")


def run_case(label, group_lines, port):
    tmp = tempfile.mkdtemp()
    os.chmod(tmp, 0o777)
    conf = os.path.join(tmp, "c.conf")
    with open(conf, "w") as f:
        f.write(
            "server 127.0.0.1:19999\n"
            f"bind 127.0.0.1:{port}\n"
            "cache-size 512\n"
            "group-begin office\n"
            f"{group_lines}"
            "group-end\n"
            f"log-file {tmp}/l.log\n"
            "log-level info\n"
        )
    os.chmod(conf, 0o644)

    proc = subprocess.Popen([BIN, "run", "-c", conf],
                            stdout=open(os.path.join(tmp, "out.txt"), "w"),
                            stderr=subprocess.STDOUT)
    time.sleep(3)
    try:
        logs = ""
        for f in (os.path.join(tmp, "l.log"), os.path.join(tmp, "out.txt")):
            if os.path.exists(f):
                with open(f, errors="replace") as fh:
                    logs += fh.read()
        rejected = "has no per-rule-group form" in logs
        # 全局缓存容量：摘要里的 `cache: size(N)`
        import re
        m = re.search(r"cache: size\((\d+)\)", logs)
        size = int(m.group(1)) if m else None
        print(f"  {label}: 出现拒绝提示={rejected}  全局 cache-size={size}")
        return rejected, size
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(0.3)
        subprocess.run(["rm", "-rf", tmp])


def main():
    print("===== 真机验证：规则组写入白名单 =====")
    print()

    rejected, size = run_case("组里写 cache-size 1024", "cache-size 1024\n", 26981)
    ok_rej, ok_size = run_case("组里只写 rr-ttl（合法）", "rr-ttl 111\n", 26983)
    print()

    if rejected:
        ok("组里写 `cache-size` → 日志给出了「无组级写法、该行被忽略」的提示")
    else:
        bad("组里写 `cache-size` 没有任何提示 ⇒ 用户会以为它生效了")

    if size == 512:
        ok("全局 cache-size 仍是顶层的 512（**未被组里那行污染**）")
    elif size is None:
        bad("没能从摘要里读到全局 cache-size，判据无从判断")
    else:
        bad(f"全局 cache-size 变成了 {size} ⇒ 组里那行污染了全局（修复前正是如此）")

    if not ok_rej:
        ok("组里只写合法参数 → **不**出现该提示（未无脑打印）")
    else:
        bad("合法参数也被报「无组级写法」⇒ 判据过宽，会误伤正常配置")

    if ok_size == 512:
        ok("对照组：全局 cache-size 仍是 512")
    else:
        bad(f"对照组全局 cache-size 异常：{ok_size}")

    print()
    print("=" * 56)
    print(f"汇总: {PASS} 通过 / {FAIL} 失败")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
