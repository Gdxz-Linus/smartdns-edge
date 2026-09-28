#!/usr/bin/env python3
"""丙-2a 的真机验证：组级 `dns64` 是否按组生效。

## 为什么必须真机验（而不是只靠单元测试）

本次唯一有**行为变化**的改动就在这里：DNS64 中间件原先"配了才挂"，
现在**无条件挂**、由逐查询取值决定要不要合成。单元测试只能证明"取值对了"，
证明不了"中间件真的按那个值去合成 / 不合成"。

## 判据（成对）

上游对一个域名**只回 A、不回 AAAA**（诚实的 IPv4-only 站点）。此时：

  · 配了 `dns64` 的组 → 应答里应当出现 **AAAA 记录**（由 A 合成）；
  · 没配 `dns64` 的组 → 应答里**不应有** AAAA 记录（NODATA）。

两侧必须**同时**成立：
  · 只看"配了的组合成了" → 漏掉"没配的组合成坏了"（等于给所有人开了 DNS64）；
  · 只看"没配的组没有 AAAA" → 漏掉"配了也不生效"（那正是旧实现的失效场景）。

## 怎么造出两种组

规则组没有 bind 级写法，只能靠 `client-rules` 按来源分。本机只有一个回环来源，
所以用**两份配置**各起一次进程：一份带 `client-rules 127.0.0.1 -g v6only`，一份不带。
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


def query(port, name, qtype, timeout=4.0, txid=0x5151):
    """返回应答里该类型的记录数据（列表）。"""
    q = bytearray()
    q += struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        if label:
            q += bytes([len(label)]) + label.encode()
    q += b"\0" + struct.pack("!HH", qtype, 1)

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
    out = []
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
        rdata = data[i + 10:i + 10 + rdlen]
        i += 10 + rdlen
        if rtype == qtype:
            out.append(rdata)
    return out


# 上游：v4only.test 只回 A；v6.test 回 AAAA —— 用来验证 DNS64 只在该合成时合成
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
        ans=b'\\xc0\\x0c'+struct.pack('!HHIH',1,1,300,4)+socket.inet_aton('10.8.8.8')
        s.sendto(h+qn+ans,a)
    elif qt==28:
        # 故意**不回** AAAA（模拟 IPv4-only 站点）→ NODATA，触发 DNS64 候选路径
        s.sendto(tx+struct.pack('!HHHHH',0x8180,1,0,0,0)+qn,a)
    else:
        s.sendto(tx+struct.pack('!HHHHH',0x8180,1,0,0,0)+qn,a)
"""


def run_case(label, group_line, port, upstream_port):
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
            "client-rules 127.0.0.1 -g v6only\n"
            "group-begin v6only\n"
            f"{group_line}"
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
        aaaa = query(port, "v4only.test", 28)  # AAAA
        a = query(port, "v4only.test", 1)      # A（确认上游确实可达）
        print(f"  {label}: AAAA 记录数={len(aaaa) if aaaa is not None else 'None'}  "
              f"A 记录数={len(a) if a is not None else 'None'}")
        return aaaa, a
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


def main():
    print("===== 丙-2a 真机验证：组级 dns64 =====")
    print()

    # ① 组里配了 dns64 ⇒ AAAA 应被合成出来
    aaaa_on, a_on = run_case("v6only 组配了 dns64", "dns64 64:ff9b::/96\n", 26981, 26982)
    # ② 组里没配 ⇒ 不该有 AAAA（NODATA 原样返回）
    aaaa_off, a_off = run_case("v6only 组没配 dns64", "", 26983, 26984)
    print()

    # 前置：上游必须确实可达（否则后面两个判据都无意义）
    if a_on and a_off:
        ok("前置：上游 A 记录可达（两次都拿到了 A）")
    else:
        bad(f"前置失败：A 记录拿不到（on={a_on} off={a_off}）—— 后面的判据无意义")

    if aaaa_on:
        ok("配了 dns64 的组 → AAAA 已由 A 合成")
    else:
        bad("配了 dns64 的组 → 没有 AAAA ⇒ DNS64 没生效")

    if not aaaa_off:
        ok("没配 dns64 的组 → 没有 AAAA（NODATA 原样返回，未被误开）")
    else:
        bad(f"没配 dns64 的组 → 居然有 AAAA {aaaa_off} ⇒ DNS64 被误开给所有人")

    print()
    print("=" * 56)
    print(f"汇总: {PASS} 通过 / {FAIL} 失败")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
