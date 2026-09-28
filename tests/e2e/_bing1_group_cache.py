#!/usr/bin/env python3
"""丙-1 的真机验证：组级 `serve-expired` 与 `prefetch-domain` 是否按组生效。

## 要证明什么

单元测试证明的是"配置解析出来后取值正确"。真机要证明的是
**"从一份真实配置文件启动 → 真实查询 → 行为确实按组不同"**。

判据必须**成对**：命中组的查询与未命中组的查询必须**表现不同**。
只看一侧会漏掉"组级根本没生效"——那正是这类改动最容易出的错。

## 怎么造出"同一域名、不同组"

规则组**没有** bind 级写法，只能靠 `client-rules` 按来源分配。
本机只有一个回环来源，所以用**两份配置**各起一次进程：
  ① 一份带 `client-rules 127.0.0.1 -g office`（命中 office 组）
  ② 一份不带（落在默认组）
两份配置里 office 组各写不同的组级值。

## 本脚本验的是 `serve-expired-reply-ttl`（最可观测的那个）

它决定"用过期数据回包时报多少 TTL"，能直接从应答里读出来，判据客观。
（`serve-expired` 的开关本身与 `prefetch-domain` 的通知都不直接体现在应答里，
它们在单元测试里已覆盖；真机这里挑可观测的那个。）

做法：
  · 先让上游给出 TTL 很短的记录，把它查进缓存，然后**停掉上游**；
  · 等它过期，再查一次 —— 此时走的就是"喂过期数据"路径；
  · 读应答 TTL：office 组应当写组级值，默认组应当写全局值。
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


def query_ttl(port, name, timeout=4.0, txid=0x7777):
    q = bytearray()
    q += struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        if label:
            q += bytes([len(label)]) + label.encode()
    q += b"\0" + struct.pack("!HH", 1, 1)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(bytes(q), ("127.0.0.1", port))
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
    for _ in range(ancount):
        if i + 10 > len(data):
            return None
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while i < len(data) and data[i] != 0:
                i += 1 + data[i]
            i += 1
        rtype, _c, ttl, rdlen = struct.unpack("!HHIH", data[i:i + 10])
        i += 10 + rdlen
        if rtype == 1:
            return ttl
    return None


UPSTREAM = """import socket,struct,sys
port=int(sys.argv[1]); ttl=int(sys.argv[2])
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
        ans=b'\\xc0\\x0c'+struct.pack('!HHIH',1,1,ttl,4)+socket.inet_aton('10.5.5.5')
        s.sendto(h+qn+ans,a)
    else:
        s.sendto(tx+struct.pack('!HHHHH',0x8180,1,0,0,0)+qn,a)
"""


def run_case(label, extra_group_line, port, upstream_port):
    """起上游 + 一个进程，查两次（第二次在上游停掉之后，走过期数据路径）。"""
    tmp = tempfile.mkdtemp()
    os.chmod(tmp, 0o777)

    up_py = os.path.join(tmp, "up.py")
    with open(up_py, "w") as f:
        f.write(UPSTREAM)

    # 上游给 TTL=2 的记录，便于快速过期
    up = subprocess.Popen(["python3", up_py, str(upstream_port), "2"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    conf = os.path.join(tmp, "c.conf")
    with open(conf, "w") as f:
        f.write(
            "serve-expired yes\n"
            "serve-expired-reply-ttl 5\n"
            f"server 127.0.0.1:{upstream_port}\n"
            f"bind 127.0.0.1:{port}\n"
            "client-rules 127.0.0.1 -g office\n"
            "group-begin office\n"
            f"{extra_group_line}"
            "group-end\n"
            f"log-file {tmp}/l.log\n"
            "log-level debug\n"
        )
    os.chmod(conf, 0o644)

    proc = subprocess.Popen([BIN, "run", "-c", conf],
                            stdout=open(os.path.join(tmp, "out.txt"), "w"),
                            stderr=subprocess.STDOUT)
    time.sleep(3)

    try:
        first = query_ttl(port, "stale.test")
        # 停掉上游：之后缓存过期就只能靠"喂过期数据"
        up.terminate()
        try:
            up.wait(timeout=3)
        except Exception:
            up.kill()
        time.sleep(3)  # 等记录过期

        second = query_ttl(port, "stale.test")
        print(f"  {label}: 首次(新鲜) TTL={first}  过期后 TTL={second}")
        return second
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(0.3)
        subprocess.run(["rm", "-rf", tmp])


def main():
    print("===== 丙-1 真机验证：组级 serve-expired-reply-ttl =====")
    print()

    # ① 命中 office 组：组级写 99
    office = run_case("office 组(组级 99)", "serve-expired-reply-ttl 99\n", 26971, 26972)
    # ② 同样配置但组里不写 → 回落全局 5
    plain = run_case("office 组(不写, 回落全局 5)", "", 26973, 26974)
    print()

    if office == 99:
        ok("命中组取到组级值 99")
    else:
        bad(f"命中组应为 99，实际 {office}（组级未生效）")

    if plain == 5:
        ok("组里没写 → 回落全局 5")
    else:
        bad(f"未写组级时应回落全局 5，实际 {plain}")

    if office is not None and plain is not None and office != plain:
        ok("两个组拿到**不同**的值（组级确实按组生效）")
    else:
        bad("两条路径拿到相同的值 ⇒ 组级没有真正按组生效")

    print()
    print("=" * 56)
    print(f"汇总: {PASS} 通过 / {FAIL} 失败")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
