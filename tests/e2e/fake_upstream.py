#!/usr/bin/env python3
"""
一个可控的 DNS 上游，用于真机验证解析行为。

提供两种模式（按查询的域名区分）：
  * `nxdomain.test`  → 返回 **不带 SOA 的 NXDOMAIN**（模拟被污染/伪造的上游）
  * 其它域名          → 返回一个 A 记录（模拟正常上游）

这样可以在真机上验证「问题 6：假 NXDOMAIN 不能抢先赢下并发查询」。

用法：python3 fake_upstream.py <port> <mode>
  mode = fake-nx : nxdomain.test 回假否定
  mode = real    : 一律回真答案
"""

import socket
import struct
import sys
import time


def build_response(query: bytes, fake_nx: bool) -> bytes:
    """把一个 DNS 查询变成应答。"""
    txid = query[0:2]
    # 解析问题段（域名 + QTYPE + QCLASS）
    i = 12
    labels = []
    while i < len(query) and query[i] != 0:
        ln = query[i]
        labels.append(query[i + 1 : i + 1 + ln].decode("ascii", "ignore"))
        i += 1 + ln
    i += 1
    qname = ".".join(labels)
    qtype, qclass = struct.unpack("!HH", query[i : i + 4])
    question = query[12 : i + 4]

    if fake_nx and qname == "nxdomain.test":
        # QR=1, RCODE=3 (NXDOMAIN)，ANC NT=0 —— 刻意**不带 SOA**
        header = txid + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0)
        return header + question

    # 正常应答：QR=1, RCODE=0, ANCOUNT=1
    header = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("10.9.9.9")
    return header + question + answer


def main():
    port = int(sys.argv[1])
    mode = sys.argv[2] if len(sys.argv) > 2 else "fake-nx"
    # 可选：人工延迟（毫秒），用于制造"谁先应答"的确定性时序
    delay_ms = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    fake_nx = mode == "fake-nx"

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    print(f"fake upstream on 127.0.0.1:{port} mode={mode} delay={delay_ms}ms", flush=True)

    while True:
        try:
            data, addr = s.recvfrom(4096)
        except OSError:
            break
        if len(data) < 12:
            continue
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        try:
            s.sendto(build_response(data, fake_nx), addr)
        except OSError:
            pass


if __name__ == "__main__":
    main()
