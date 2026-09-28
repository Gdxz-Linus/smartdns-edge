#!/usr/bin/env python3
"""丙-2c 的真机验证：组级 `dualstack-ip-selection` 是否按组生效。

## 为什么必须真机验（而不是只靠单元测试）

单元测试证明的是"配置解析出来后取值正确、纯函数优先级正确"。
真机要证明的是**中间件真的按那个值决定做不做双栈族对决** ——
取值对了但没接到调用点上，单测全绿而功能不生效，正是本项目反复抓到的形态。

## 判据（成对）

`dualstack-ip-selection` 只决定"要不要做 A/AAAA 族对决"。族对决**只要运行**，
**必然**在 debug 日志里留下一条 `dual stack IP selection: <域名> , ...`
（三个分支——A 赢 / AAAA 赢 / 平手——**每个都打日志**）。
所以：

  · 组级 `no` 的组 → 该组的查询**不该有**这条日志（优选被关掉）；
  · 组级没写 / 组级 `yes` 的组 → 该组查询**必须有**这条日志。

两侧必须**同时**成立：
  · 只看"关掉的组没有日志" → 漏掉"全都没做族对决"（等于把功能整体关死）；
  · 只看"开着的组有日志" → 漏掉"组级根本没生效"（那正是本次要修的东西）。

## 怎么在**同一个进程**里造出两个组（比前任脚本更强）

规则组没有 bind 级写法，只能靠 `client-rules` 按**来源**分。
前任脚本（`_bing1` / `_bing2_dns64_group`）受限于"只有一个回环来源"，
只能起两份配置各跑一次，并如实标注了"没有覆盖两个来源同时存在"这一层。

本脚本用 **127.0.0.0/8 里两个不同的回环地址**（127.0.0.1 / 127.0.0.2）当两个客户端来源 ——
Linux 上整个 127/8 都是本机，可以随便 `bind` 源地址。
于是**一个进程、两个组、两条查询**同时发生，真正验到"同一域名、不同组各走各的"。

两条查询用**不同的域名**（`on.test` / `off.test`），日志里带着域名，
因此"哪条查询做了族对决"可以精确判定，不会互相串。
"""
import os
import socket
import struct
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


def build_query(name, qtype=1, txid=0x2C2C):
    q = bytearray()
    q += struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        if label:
            q += bytes([len(label)]) + label.encode()
    q += b"\0" + struct.pack("!HH", qtype, 1)
    return bytes(q)


def query_a_count(port, name, src, timeout=6.0):
    """从指定**源地址**发一次 A 查询；返回应答里的 A 记录条数（失败返回 None）。

    ⚠️ 超时给足 6 秒：族对决里每种测速模式各有 600ms 死线，
    默认两种模式最坏要 1.2 秒以上 —— 超时太短会把"功能正常"误判成失败。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((src, 0))  # ← 关键：让服务端看到的来源就是这一组的归属地址
    except Exception as e:
        s.close()
        print(f"  （无法绑定源地址 {src}: {e}）")
        return None
    s.settimeout(timeout)
    try:
        s.sendto(build_query(name), ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
    except Exception:
        return None
    finally:
        s.close()

    i = 12
    while i < len(data) and data[i] != 0:
        i += 1 + data[i]
    i += 1 + 4
    ancount = struct.unpack("!H", data[6:8])[0]
    count = 0
    for _ in range(ancount):
        if i + 10 > len(data):
            break
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while i < len(data) and data[i] != 0:
                i += 1 + data[i]
            i += 1
        rtype, _c, _ttl, rdlen = struct.unpack("!HHIH", data[i:i + 10])
        i += 10 + rdlen
        if rtype == 1:
            count += 1
    return count


# 上游：对 A 与 AAAA **都**给出地址（两族都有记录，族对决才有对象）
UPSTREAM = """import socket,struct,sys
port=int(sys.argv[1])
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',port))
while True:
    try: d,a=s.recvfrom(4096)
    except OSError: break
    if len(d)<12: continue
    tx=d[0:2]; i=12
    while d[i]!=0: i+=1+d[i]
    i+=1
    qt,_=struct.unpack('!HH',d[i:i+4]); qn=d[12:i+4]
    if qt==1:
        h=tx+struct.pack('!HHHHH',0x8180,1,1,0,0)
        ans=b'\\xc0\\x0c'+struct.pack('!HHIH',1,1,300,4)+socket.inet_aton('10.20.20.20')
        s.sendto(h+qn+ans,a)
    elif qt==28:
        h=tx+struct.pack('!HHHHH',0x8180,1,1,0,0)
        ans=b'\\xc0\\x0c'+struct.pack('!HHIH',28,1,300,16)+socket.inet_pton(socket.AF_INET6,'2001:db8::20')
        s.sendto(h+qn+ans,a)
    else:
        s.sendto(tx+struct.pack('!HHHHH',0x8180,1,0,0,0)+qn,a)
"""


def run_case(label, global_line, group_line, port, upstream_port):
    """起上游 + 一个进程，从两个源地址各查一次，回收日志。

    返回 (日志文本, 第一次查询的 A 记录数, 第二次查询的 A 记录数)。
    第一次来自 src_group（归属规则组），第二次来自 127.0.0.1（归属默认组）。
    """
    tmp = tempfile.mkdtemp()
    os.chmod(tmp, 0o777)

    up_py = os.path.join(tmp, "up.py")
    with open(up_py, "w") as f:
        f.write(UPSTREAM)

    up = subprocess.Popen(["python3", up_py, str(upstream_port)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    conf = os.path.join(tmp, "c.conf")
    with open(conf, "w") as f:
        f.write(
            f"server 127.0.0.1:{upstream_port}\n"
            f"bind 127.0.0.1:{port}\n"
            f"{global_line}"
            # 用一个**只有本脚本会用**的回环地址当"命中组的客户端"
            "client-rules 127.0.0.2 -g race\n"
            "group-begin race\n"
            f"{group_line}"
            "group-end\n"
            f"log-file {tmp}/l.log\n"
            "log-level debug\n"
        )
    os.chmod(conf, 0o644)

    log_path = os.path.join(tmp, "l.log")
    proc = subprocess.Popen([BIN, "run", "-c", conf],
                            stdout=open(os.path.join(tmp, "out.txt"), "w"),
                            stderr=subprocess.STDOUT)
    time.sleep(3)

    try:
        # ① 来自 127.0.0.2 ⇒ 命中 race 组（组级说话）
        n_group = query_a_count(port, "on.test", "127.0.0.2")
        # ② 来自 127.0.0.1 ⇒ 默认组（组级不参与，全局说话）
        n_default = query_a_count(port, "off.test", "127.0.0.1")
        time.sleep(0.5)

        logs = ""
        for f in (log_path, os.path.join(tmp, "out.txt")):
            if os.path.exists(f):
                with open(f, errors="replace") as fh:
                    logs += fh.read()

        print(f"  {label}: 组内查询 A 条数={n_group}  默认组查询 A 条数={n_default}")
        return logs, n_group, n_default
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        up.terminate()
        try:
            up.wait(timeout=3)
        except Exception:
            up.kill()
        time.sleep(0.3)
        subprocess.run(["rm", "-rf", tmp])


def race_lines(logs, name):
    """族对决日志里与某个域名相关的那几条。

    判据用**源码里的实际字样** `dual stack IP selection: <域名>` ——
    注意 `dual stack` 中间是**空格**（`dual-stack` 那个写法只出现在另一条
    "partial failure tolerated" 日志里，不能拿来当判据）。
    """
    return [ln for ln in logs.splitlines()
            if "dual stack IP selection:" in ln and name in ln]


def main():
    print("===== 丙-2c 真机验证：组级 dualstack-ip-selection =====")
    print()

    # ── 用例一：全局开、组里关 → 组内不该族对决，默认组照旧族对决 ──
    logs1, n1g, n1d = run_case(
        "用例一 全局 yes / race 组 no",
        "dualstack-ip-selection yes\n",
        "dualstack-ip-selection no\n",
        26991, 26992,
    )
    print()

    # 前置：两条查询都得有答案，否则后面的判据无意义
    if n1g and n1d:
        ok("前置：两条查询都拿到了 A 记录（上游可达）")
    else:
        bad(f"前置失败：A 记录拿不到（组内={n1g} 默认组={n1d}）—— 后面的判据无意义")

    if not race_lines(logs1, "on.test"):
        ok("组级 no 生效：race 组（127.0.0.2）的查询**没有**发生双栈族对决")
    else:
        bad(f"组级 no 未生效：race 组的查询竟然做了族对决：{race_lines(logs1, 'on.test')[:2]}")

    if race_lines(logs1, "off.test"):
        ok("对照组：默认组（127.0.0.1）的查询**照旧**发生族对决（全局 yes 未被组级带偏）")
    else:
        bad("对照组失败：默认组也没做族对决 ⇒ 可能是功能被整体关死，而不是按组分流")

    # 关键：两条路径**必须不同**
    if bool(race_lines(logs1, "on.test")) != bool(race_lines(logs1, "off.test")):
        ok("同一进程内两个组表现**不同**（组级确实按组分流）")
    else:
        bad("两个组表现相同 ⇒ 组级参数没有真正按组生效")

    # ── 用例二（反向）：全局关、组里开 → 组内该族对决，默认组不该 ──
    #
    # 这一条钉的是"**组级既能关、也能开**"。只做用例一的话，
    # 一个"把组级当成额外单向闸"的错误实现也会全绿。
    logs2, n2g, n2d = run_case(
        "用例二 全局 no / race 组 yes",
        "dualstack-ip-selection no\n",
        "dualstack-ip-selection yes\n",
        26993, 26994,
    )
    print()

    if n2g and n2d:
        ok("前置：两条查询都拿到了 A 记录（上游可达）")
    else:
        bad(f"前置失败：A 记录拿不到（组内={n2g} 默认组={n2d}）—— 后面的判据无意义")

    if race_lines(logs2, "on.test"):
        ok("组级 yes 生效：race 组的查询**发生了**双栈族对决（组级能开，不只是能关）")
    else:
        bad("组级 yes 未生效：race 组没有族对决 ⇒ 组级只能关不能开，与取值链语义不符")

    if not race_lines(logs2, "off.test"):
        ok("对照组：默认组（127.0.0.1）的查询**没有**族对决（全局 no 生效）")
    else:
        bad("对照组失败：默认组做了族对决 ⇒ 组级把全局也带开了")

    if bool(race_lines(logs2, "on.test")) != bool(race_lines(logs2, "off.test")):
        ok("同一进程内两个组表现**不同**（反向用例同样成立）")
    else:
        bad("两个组表现相同 ⇒ 反向用例下组级没有真正按组生效")

    print()
    print("=" * 56)
    print(f"汇总: {PASS} 通过 / {FAIL} 失败")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
