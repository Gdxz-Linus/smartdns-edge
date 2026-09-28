#!/usr/bin/env python3
"""
可控上游（双栈 TTL 实验专用）：为同一域名返回**不同 TTL** 的 A 与 AAAA。

用途：真机验证「问题 5：双栈优选必须取较短 TTL，不能把短 TTL 拉长」。

场景设计（对应报告第十八节的例子）：
  A    记录：TTL 60 与 TTL 3600 两条   → 该族 min_ttl = 60
  AAAA 记录：TTL 3600                  → 该族 min_ttl = 3600
  期望：双栈对齐后 **两族的 TTL 都变成 60**（而不是被拉长到 3600）

用法：python3 ttl_upstream.py <port>
"""

import socket
import struct
import sys


def parse_question(query):
    i = 12
    labels = []
    while i < len(query) and query[i] != 0:
        ln = query[i]
        labels.append(query[i + 1 : i + 1 + ln].decode("ascii", "ignore"))
        i += 1 + ln
    i += 1
    qtype, qclass = struct.unpack("!HH", query[i : i + 4])
    return ".".join(labels), qtype, query[12 : i + 4]


def rr_a(ttl, ip):
    return b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)


def rr_aaaa(ttl, ip6):
    return (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 28, 1, ttl, 16)
        + socket.inet_pton(socket.AF_INET6, ip6)
    )


def build(query):
    txid = query[0:2]
    qname, qtype, question = parse_question(query)

    if qtype == 1:  # A：两条，TTL 分别 60 与 3600
        header = txid + struct.pack("!HHHHH", 0x8180, 1, 2, 0, 0)
        body = rr_a(60, "10.1.1.1") + rr_a(3600, "10.1.1.2")
        return header + question + body

    if qtype == 28:  # AAAA：一条，TTL 3600
        header = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        body = rr_aaaa(3600, "2001:db8::1")
        return header + question + body

    # 其它类型：空应答
    header = txid + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0)
    return header + question


def main():
    port = int(sys.argv[1])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    print(f"ttl upstream on 127.0.0.1:{port}", flush=True)
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except OSError:
            break
        if len(data) < 12:
            continue
        try:
            s.sendto(build(data), addr)
        except OSError:
            pass


if __name__ == "__main__":
    main()
