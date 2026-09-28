#!/usr/bin/env python3
"""临时探针：确认组级 `serve-expired` 现在会在启动摘要里被点出来。

背景：配置摘要里**没有** `serve-expired` 那一行，所以"某个组写了 serve-expired"
此前完全不可见 —— 用户看不出它是否按组生效。本次补了提示，这里做真机确认。

判据成对：
  · 组里写了 `serve-expired no` → 摘要必须出现该组的提示；
  · 组里没写               → **不得**出现该提示（防"无脑打印"）。
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


def run_case(label, group_extra, port):
    tmp = tempfile.mkdtemp()
    os.chmod(tmp, 0o777)
    conf = os.path.join(tmp, "c.conf")
    with open(conf, "w") as f:
        f.write(
            f"server 127.0.0.1:19999\n"
            f"bind 127.0.0.1:{port}\n"
            "group-begin office\n"
            f"{group_extra}"
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
        hit = "set `serve-expired` themselves" in logs
        print(f"  {label}: 摘要含 serve-expired 组级提示 = {hit}")
        return hit
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(0.3)
        subprocess.run(["rm", "-rf", tmp])


def main():
    print("===== 探针：组级 serve-expired 的启动提示 =====")
    print()
    with_hit = run_case("组里写了 serve-expired no", "serve-expired no\n", 26996)
    without_hit = run_case("组里没写", "", 26997)
    print()

    if with_hit:
        ok("组里写了 → 摘要点出该组（此前完全不可见）")
    else:
        bad("组里写了却没有提示 ⇒ 该组级配置对用户仍然不可见")

    if not without_hit:
        ok("组里没写 → 摘要**不**提（未无脑打印）")
    else:
        bad("组里没写也打印 ⇒ 提示范围过宽，会刷无关信息")

    print()
    print("=" * 56)
    print(f"汇总: {PASS} 通过 / {FAIL} 失败")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
