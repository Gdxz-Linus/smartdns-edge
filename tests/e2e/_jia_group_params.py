#!/usr/bin/env python3
"""甲类组级参数的真机验证（**不是单元测试的替代，而是补它抓不到的那一层**）。

## 为什么必须有这一条

单元测试证明的是"配置解析出来后取值正确"；真机要证明的是
**"从一份真实配置文件启动 → 真实查询 → 客户端看到的应答确实按组不同"**。
两者抓的不是同一件事（本项目第一批写 e2e 时就抓到过两个"单测全绿、实际有缺陷"的问题）。

## 组的分配方式（第一版脚本在这里写错过，记录一笔）

规则组**没有 bind 级写法** —— 只有两条路进组：
  ① `client-rules <来源> -g <组名>`（按客户端来源分）；
  ② `group-match`。

第一版我按 `bind -group office` 写，**那是服务器组（上游分组），不是规则组** ——
于是三个端口都落在默认组、全拿到全局值，看起来像"组级没生效"，其实是脚本用错了选项。
现在改用 ①：让**不同的客户端来源**匹配到不同的组。

## 验什么（判据**成对**，防判据过宽）

同一个域名 `local.test`（由 address 规则静态应答），在不同组里拿到**不同的 `local-ttl`**：

  · office 组 → `local-ttl 999`
  · guest 组  → 不写 → 回落全局的 `local-ttl 300`

判据：
  · 命中 office 的来源 → 应答 TTL = 999
  · 未命中的来源      → 应答 TTL = 300
  · **两者必须不同**（只看一侧会漏掉"组级没生效"，那正是本次要修的东西）

## 一个绕不开的限制（如实说明）

本机只有一个回环来源地址，无法真的用两个源 IP 发查询。因此这里用
**`client-rules` 匹配 `127.0.0.1`** 制造"命中 office 组"，再**用另一份配置**
（不写 client-rules）制造"不命中"。两份配置各起一次进程、各查一次，
判据仍是"同一域名在两种配置下 TTL 不同"。这能证明组级确实生效，
但**没有**覆盖"两个来源同时存在、各走各的"这一层 —— 那一层由单元测试
（`group_level_params_reach_the_context_accessor`）覆盖。
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


def build_query(name, qtype=1, txid=0x1234):
    q = bytearray()
    q += struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        if label:
            q += bytes([len(label)]) + label.encode()
    q += b"\0"
    q += struct.pack("!HH", qtype, 1)
    return bytes(q)


def query_ttl(port, name, timeout=3.0):
    """返回应答里第一条 A 记录的 TTL；失败返回 None。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_query(name), ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
    except Exception:
        return None
    finally:
        s.close()

    # 跳过 header(12) + question
    i = 12
    while i < len(data) and data[i] != 0:
        i += 1 + data[i]
    i += 1 + 4  # 结尾 0 + qtype/qclass

    ancount = struct.unpack("!H", data[6:8])[0]
    for _ in range(ancount):
        if i + 10 > len(data):
            return None
        # name（可能带压缩指针）
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while i < len(data) and data[i] != 0:
                i += 1 + data[i]
            i += 1
        rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", data[i:i + 10])
        i += 10 + rdlen
        if rtype == 1:
            return ttl
    return None


def main():
    print("===== 甲类组级参数真机验证 =====")
    print()

    tmp = tempfile.mkdtemp()
    os.chmod(tmp, 0o777)

    # 同一个域名由 address 规则静态应答，于是 TTL 完全由 local-ttl 决定，
    # 不受上游影响。组由 `client-rules`（按来源）分配 —— 规则组**没有** bind 级写法。
    def write_conf(path, port, extra):
        with open(path, "w") as f:
            f.write(
                f"local-ttl 300\n"
                f"server 127.0.0.1:19999\n"
                f"bind 127.0.0.1:{port}\n"
                f"{extra}"
                "group-begin office\n"
                "local-ttl 999\n"
                "address /local.test/10.1.1.1\n"
                "group-end\n"
                "address /local.test/10.3.3.3\n"
                f"log-file {tmp}/smartdns-{port}.log\n"
                "log-level debug\n"
            )
        os.chmod(path, 0o644)

    # ① 命中 office 组：来源 127.0.0.1 被 client-rules 分到 office
    conf_office = os.path.join(tmp, "office.conf")
    write_conf(conf_office, 26952, "client-rules 127.0.0.1 -g office\n")

    # ② 不命中任何组：同一份配置但不写 client-rules → 落默认组
    conf_plain = os.path.join(tmp, "plain.conf")
    write_conf(conf_plain, 26951, "")

    def run_and_query(conf, port):
        proc = subprocess.Popen(
            [BIN, "run", "-c", conf],
            stdout=open(os.path.join(tmp, f"out-{port}.txt"), "w"),
            stderr=subprocess.STDOUT,
        )
        time.sleep(3)
        try:
            return query_ttl(port, "local.test")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            time.sleep(0.5)

    try:
        ttl_office = run_and_query(conf_office, 26952)
        ttl_default = run_and_query(conf_plain, 26951)

        print(f"  office 组（client-rules 命中）→ TTL={ttl_office}")
        print(f"  默认组（未命中任何组）       → TTL={ttl_default}")
        print()

        # ① office 组写了 local-ttl 999 ⇒ 必须看到 999
        if ttl_office == 999:
            ok("命中 office 组的查询 → 应答 TTL = 999（组级生效）")
        else:
            bad(f"office 组应为 999，实际 {ttl_office}（组级未生效）")

        # ② 对照组：未命中任何组 ⇒ 回落全局 300
        if ttl_default == 300:
            ok("未命中组的查询 → 回落全局 300")
        else:
            bad(f"默认组应为 300（回落全局），实际 {ttl_default}")

        # ③ 关键：两条路径**必须不同** —— 只看单侧会漏掉"组级没生效"
        if ttl_office is not None and ttl_default is not None and ttl_office != ttl_default:
            ok("命中组与未命中组拿到**不同**的 TTL（组级确实按组分流）")
        else:
            bad("两条路径拿到相同的 TTL ⇒ 组级参数没有真正按组分流")

    finally:
        pass

    print()
    print("=" * 56)
    print(f"汇总: {PASS} 通过 / {FAIL} 失败")

    if FAIL:
        for port in (26951, 26952):
            log = os.path.join(tmp, f"out-{port}.txt")
            if os.path.exists(log):
                print(f"--- 进程输出（port {port}）---")
                with open(log) as f:
                    print(f.read()[-1200:])

    subprocess.run(["rm", "-rf", tmp])
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
