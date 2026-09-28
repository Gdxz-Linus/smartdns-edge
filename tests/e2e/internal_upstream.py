#!/usr/bin/env python3
"""
"内网权威 DNS"模拟上游 —— 专用于验证**问题 46**。

## 它模拟什么

真实的**内网权威 DNS 服务器**通常只服务自己的内网域名，
对外部域名（`example.com` 是典型代表）一律拒绝或不答。

## 为什么必须用它

问题 46 的原缺陷是：程序与上游建立连接后会先发一条固定的
`example.com` A 查询，并**要求必须收到应答**才算这个上游可用。

后果：上面这类内网上游**明明能正常解析用户真正要查的内网域名**，
却因为"答不出 example.com"被**永久判定为不可用** ——
即使用户只想查内网域名也不行。

## 它怎么答

* **内网域名**（默认 `intranet.test`）：正常返回 A 记录（默认 `10.1.2.3`）。
* **其它一切域名（含 `example.com`）**：回 **REFUSED**（rcode=5）。
  REFUSED 是"我拒绝为你解析"的明确表态，比 NXDOMAIN 更能体现"不服务外部域名"。

## 用法

    python3 unreachable_upstream.py <port> [--allow 内网域名] [--ip 记录值]

脚本会把自己收到的每个查询名打到 stdout（便于确认真发了什么），
并统计 `example.com` 的查询次数 —— 修复后这个计数应当为 **0**。
"""

import argparse
import socket
import struct
import sys
import threading


def parse_question(query):
    """返回 (域名, qtype, question_bytes)。"""
    i = 12
    labels = []
    while i < len(query) and query[i] != 0:
        ln = query[i]
        labels.append(query[i + 1 : i + 1 + ln].decode("ascii", "ignore"))
        i += 1 + ln
    i += 1
    qtype, _qclass = struct.unpack("!HH", query[i : i + 4])
    return ".".join(labels), qtype, query[12 : i + 4]


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        # **关键指标**：`example.com` 被问了几次。修复后应为 0。
        self.example_com = 0
        self.queries = []

    def record(self, name):
        with self.lock:
            self.total += 1
            self.queries.append(name)
            if name.rstrip(".").lower() == "example.com":
                self.example_com += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int)
    ap.add_argument(
        "--allow",
        default="intranet.test",
        help="要正常解析的内网域名（默认 intranet.test）",
    )
    ap.add_argument("--ip", default="10.1.2.3", help="内网域名返回的 A 记录")
    ap.add_argument(
        "--alias",
        default=None,
        help=(
            "额外用两条相同的 A 记录应答这个域名（模拟「解析出多个 IP 的上游」）。"
            "这是复现问题 46 原缺陷的关键：程序只在「多地址竞速」路径上做 example.com 试探，"
            "单地址上游走的是不试探的快捷路径。"
        ),
    )
    args = ap.parse_args()

    allowed = args.allow.rstrip(".").lower()
    alias = args.alias.rstrip(".").lower() if args.alias else None
    stats = Stats()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", args.port))
    print(f"[内网上游] 监听 127.0.0.1:{args.port}", flush=True)
    print(f"[内网上游] 只解析 {allowed} -> {args.ip}；其它一律 REFUSED", flush=True)
    if alias:
        print(f"[内网上游] {alias} 会返回**两条**A 记录（内容相同）", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            break
        if len(data) < 12:
            continue

        txid = data[0:2]
        name, qtype, question = parse_question(data)
        stats.record(name)

        # 把收到的查询名打出来（真机脚本靠它确认"到底发了什么"）
        print(f"[内网上游] 收到查询: {name or '<空>'} type={qtype}", flush=True)

        lname = name.rstrip(".").lower()
        if lname == allowed and qtype == 1:
            # 正常应答：AA=1, rcode=0
            hdr = txid + struct.pack("!HHHHH", 0x8580, 1, 1, 0, 0)
            ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(
                args.ip
            )
            sock.sendto(hdr + question + ans, addr)
        elif alias and lname == alias and qtype == 1:
            # 🔑 两条相同 A 记录 —— 迫使程序走"多地址竞速"路径
            #    （单地址上游走的是不试探 example.com 的快捷路径）
            hdr = txid + struct.pack("!HHHHH", 0x8580, 1, 2, 0, 0)
            one = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(
                "127.0.0.1"
            )
            sock.sendto(hdr + question + one + one, addr)
        else:
            # 拒绝服务外部域名：QR=1, rcode=REFUSED(5)
            # flags: 0x8185 = QR(1) + RD(1) + RA(1) + rcode 5
            sock.sendto(txid + struct.pack("!HHHHH", 0x8185, 1, 0, 0, 0) + question, addr)

    print(
        f"[内网上游] 结束：共 {stats.total} 次查询，其中 example.com {stats.example_com} 次",
        flush=True,
    )
    # 修复后这里应当是 0 —— 脚本把它作为机器可读的结论输出
    print(f"EXAMPLE_COM_QUERIES={stats.example_com}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
