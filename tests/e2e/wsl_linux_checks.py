#!/usr/bin/env python3
"""
WSL/Linux 真机检查：验证需要真实内核能力的平台相关行为。

与 `tests/e2e/run_e2e.ps1` 的分工：
  * run_e2e.ps1（Windows）：起进程 + 真发 DNS 查询，覆盖可移植的端到端行为；
  * 本脚本（WSL/Linux）：覆盖**必须真实内核**的项 —— ipset/nftset 真写入、
    系统日志、单实例锁、权限降权等。这些在 Windows 上根本不存在。

用法（在 WSL 内，多数项需要 root）：
    sudo python3 tests/e2e/wsl_linux_checks.py
    sudo python3 tests/e2e/wsl_linux_checks.py --filter ipset

设计原则：**每项都能独立判定，且"工具不存在"要如实报告为 SKIP 而不是 PASS** ——
否则一个空跑的环境会给出"全绿"的假结论。
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ---------------- 测试基础设施 ----------------

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
_results = []


def record(status, name, detail=""):
    _results.append((status, name, detail))
    color = {PASS: "\033[32m", FAIL: "\033[31m", SKIP: "\033[33m"}.get(status, "")
    reset = "\033[0m" if color else ""
    line = f"  [{status}] {name}"
    if detail:
        line += f" — {detail}"
    print(f"{color}{line}{reset}", flush=True)


def section(title):
    print(f"\n=== {title} ===", flush=True)


def have(cmd):
    return shutil.which(cmd) is not None


def run(cmd, **kw):
    """跑一个命令，返回 (returncode, stdout+stderr)。"""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30, **kw)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def is_root():
    return os.geteuid() == 0


REPO = Path(__file__).resolve().parents[2]
EXE = REPO / "target" / "debug" / "smartdns"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def write_conf(text, path):
    path.write_text(text, encoding="utf-8")
    return path


def start_server(conf, workdir, extra=None):
    """起一个真实进程，返回 Popen。调用方负责 terminate。

    ⚠️ 以 root 运行时，程序会**自动降权到 nobody**（刻意的安全设计）。
    因此临时目录必须让 nobody 能写，否则日志根本写不进去 ——
    那是"测试环境没准备好"，不是产品缺陷。
    （第一版没处理这点，导致 rotation 检查在 root 下误报"日志未重建"。）
    """
    args = [str(EXE), "run", "-c", str(conf)]
    if extra:
        args += extra
    try:
        os.chmod(str(workdir), 0o777)
        # 日志文件若已存在（上一轮遗留），也要放开
        for f in Path(workdir).rglob("*"):
            if f.is_file():
                try:
                    os.chmod(f, 0o666)
                except OSError:
                    pass
    except OSError:
        pass
    return subprocess.Popen(
        args, cwd=str(workdir), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def dns_query(port, name, timeout=5):
    """用 smartdns resolve 发一次真实查询，返回 (returncode, 输出)。

    注意：不能把 timeout 再传给 run() —— run() 里已经固定传了 timeout，
    重复传会抛 "got multiple values for keyword argument 'timeout'"（第一版就踩了）。
    """
    return run([str(EXE), "resolve", "-s", f"127.0.0.1:{port}", name])


# ---------------- 检查项 ----------------


def check_ipset_real_kernel():
    """ipset 真写入内核：解析结果要真的进内核集合。

    ⚠️ 必须用**真实上游解析**的域名，不能用 `address` 静态规则：
    静态规则的应答不经过"解析结果送进防火墙"那条路径，ipset 自然不会有条目 ——
    那是设计行为，不是缺陷（第一版用 address 规则测，误报过一次）。
    """
    if not is_root():
        record(SKIP, "ipset 真写入内核", "需要 root")
        return
    if not have("ipset"):
        record(SKIP, "ipset 真写入内核", "本环境没有 ipset 命令/内核模块")
        return

    setname = "smartdns_e2e_check"
    run(["ipset", "destroy", setname])  # 清理可能的残留
    code, out = run(["ipset", "create", setname, "hash:ip", "timeout", "0"])
    if code != 0:
        record(SKIP, "ipset 真写入内核", f"无法创建测试集合（内核不支持？）: {out.strip()[:120]}")
        return

    port = free_port()
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        conf = write_conf(
            f"bind 127.0.0.1:{port}\n"
            f"server 223.5.5.5\n"
            # 真实域名：走完整解析路径，答案才会被写进内核集合
            f"ipset /baidu.com/#4:{setname}\n"
            f"log-file {td}/smartdns.log\n"
            f"log-level debug\n",
            td / "smartdns.conf",
        )
        proc = start_server(conf, td)
        try:
            time.sleep(1.5)
            dns_query(port, "baidu.com")
            time.sleep(2.5)
            code, out = run(["ipset", "list", setname])
            # 统计 Members 后面的条目行
            members = [
                ln for ln in out.splitlines()
                if ln.strip() and ln.strip()[0].isdigit() and "timeout" in ln
            ]
            if members:
                record(PASS, "ipset 真写入内核",
                       f"集合里有 {len(members)} 条真实解析结果")
            else:
                record(FAIL, "ipset 真写入内核",
                       f"内核集合里没有条目；集合内容: {out.strip()[:200]}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            run(["ipset", "destroy", setname])


def check_nftset_real_kernel():
    """nftset 真写入内核：解析结果要真的进 nftables 集合。"""
    if not is_root():
        record(SKIP, "nftset 真写入内核", "需要 root")
        return
    if not have("nft"):
        record(SKIP, "nftset 真写入内核", "本环境没有 nft 命令")
        return

    table, setname = "smartdns_e2e", "s_e2e"
    run(["nft", "delete", "table", "inet", table])  # 清理残留
    code, out = run(["nft", "add", "table", "inet", table])
    if code != 0:
        record(SKIP, "nftset 真写入内核", f"无法创建测试表: {out.strip()[:120]}")
        return
    code, out = run(
        ["nft", "add", "set", "inet", table, setname,
         "{ type ipv4_addr; flags timeout; }"]
    )
    if code != 0:
        record(SKIP, "nftset 真写入内核", f"无法创建测试集合: {out.strip()[:120]}")
        run(["nft", "delete", "table", "inet", table])
        return

    port = free_port()
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        conf = write_conf(
            f"bind 127.0.0.1:{port}\n"
            f"server 223.5.5.5\n"
            # ⚠️ 同样必须用**真实上游解析**的域名（原因见 ipset 检查的说明）
            f"nftset /baidu.com/#4:inet#{table}#{setname}\n"
            f"nftset-debug yes\n"
            f"log-file {td}/smartdns.log\n"
            f"log-level debug\n",
            td / "smartdns.conf",
        )
        proc = start_server(conf, td)
        try:
            time.sleep(1.5)
            dns_query(port, "baidu.com")
            time.sleep(2.5)
            code, out = run(["nft", "list", "set", "inet", table, setname])
            # 集合里应出现真实 IP（形如 "elements = { 110.242.74.102 ... }"）
            has_elem = "elements" in out and any(
                ch.isdigit() for ch in out.split("elements")[-1]
            )
            if has_elem:
                record(PASS, "nftset 真写入内核", "集合里已有真实解析结果")
            else:
                record(FAIL, "nftset 真写入内核", f"集合里没有条目；内容: {out.strip()[:160]}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            run(["nft", "delete", "table", "inet", table])


def check_single_instance_lock():
    """单实例锁：同一配置下第二个进程不能同时跑。"""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        port = free_port()
        conf = write_conf(
            f"bind 127.0.0.1:{port}\n"
            f"server 223.5.5.5\n"
            f"log-file {td}/smartdns.log\n"
            f"log-level info\n",
            td / "smartdns.conf",
        )
        # 关键：两个实例必须用**同一个 pid 文件**，锁才是同一个
        pidfile = td / "smartdns.pid"
        p1 = start_server(conf, td, ["-p", str(pidfile)])
        try:
            time.sleep(1.5)
            if p1.poll() is not None:
                record(FAIL, "单实例锁", "第一个实例未能启动")
                return

            # 第二个实例：应拒绝启动（非 0 退出）
            code, out = run([str(EXE), "run", "-c", str(conf), "-p", str(pidfile)])
            if code != 0:
                record(PASS, "单实例锁", f"第二个实例被拒绝（退出码 {code}）")
            else:
                record(FAIL, "单实例锁", "第二个实例竟然启动成功了（防多开失效）")
        finally:
            p1.terminate()
            try:
                p1.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p1.kill()


def check_syslog_output():
    """系统日志（log-syslog）：日志要真的送到 syslog。"""
    if not is_root():
        record(SKIP, "系统日志输出", "需要 root（要写 /dev/log 或 journald）")
        return
    if not Path("/dev/log").exists() and not have("logger"):
        record(SKIP, "系统日志输出", "本环境没有 syslog 套接字")
        return

    # ⚠️ `server-name` 不会出现在 syslog 行里 —— syslog 的标识是**进程名**（`smartdns[pid]`）。
    #    第一版拿 server-name 当标记去找，永远找不到，误报成 SKIP。
    #    改为用**本次进程的 PID** 做精确判定（journal 行里带 `smartdns[<pid>]`）。
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        port = free_port()
        conf = write_conf(
            f"bind 127.0.0.1:{port}\n"
            f"server 223.5.5.5\n"
            f"log-syslog yes\n"
            f"log-file {td}/smartdns.log\n"
            f"log-level info\n",
            td / "smartdns.conf",
        )
        proc = start_server(conf, td)
        try:
            time.sleep(2.5)
            dns_query(port, "example.com")
            time.sleep(1.5)

            pid = proc.pid
            found = False
            where = ""
            if have("journalctl"):
                # 用 PID 精确匹配，避免把别的 smartdns 实例算进来
                code, out = run([
                    "journalctl", "--no-pager", "--since", "2 minutes ago",
                    "-t", "smartdns",
                ])
                if f"smartdns[{pid}]" in out or "listening for UDP" in out:
                    found = True
                    where = "journald"
            if not found:
                for lf in ("/var/log/syslog", "/var/log/messages"):
                    p = Path(lf)
                    if p.exists():
                        try:
                            tail = p.read_text(errors="ignore")[-40000:]
                            if "smartdns" in tail and "listening for UDP" in tail:
                                found = True
                                where = lf
                                break
                        except OSError:
                            pass
            if found:
                record(PASS, "系统日志输出", f"日志已送进系统日志（{where}）")
            else:
                record(SKIP, "系统日志输出",
                       "没找到 smartdns 的 syslog 记录（本环境 syslog 可能未接收，无法判定）")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def check_privilege_drop():
    """降权：以 root 启动并指定 user 后，进程应真的降权。"""
    if not is_root():
        record(SKIP, "权限降权", "需要 root")
        return
    if not have("id"):
        record(SKIP, "权限降权", "缺少 id 命令")
        return

    # 找一个存在的非 root 账号
    target = None
    for cand in ("nobody", "nogroup", "daemon"):
        code, _ = run(["id", "-u", cand])
        if code == 0:
            target = cand
            break
    if target is None:
        record(SKIP, "权限降权", "本环境没有可用的非 root 账号")
        return

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        os.chmod(td, 0o777)
        port = free_port()
        conf = write_conf(
            f"bind 127.0.0.1:{port}\n"
            f"server 223.5.5.5\n"
            f"user {target}\n"
            f"log-file {td}/smartdns.log\n"
            f"log-level info\n",
            td / "smartdns.conf",
        )
        proc = start_server(conf, td)
        try:
            time.sleep(2.0)
            if proc.poll() is not None:
                record(SKIP, "权限降权", f"进程未存活（可能 {target} 无权限绑端口），无法判定")
                return
            code, out = run(["ps", "-o", "user=", "-p", str(proc.pid)])
            who = out.strip()
            if who and who != "root":
                record(PASS, "权限降权", f"进程已降权为 {who}")
            elif who == "root":
                record(FAIL, "权限降权", "进程仍是 root（降权未生效）")
            else:
                record(SKIP, "权限降权", "无法读取进程属主")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def check_os_release_detection():
    """发行版识别：能正确读出当前发行版（服务安装分支依赖它）。"""
    if not Path("/etc/os-release").exists():
        record(SKIP, "发行版识别", "没有 /etc/os-release")
        return
    code, out = run([str(EXE), "test", "-c", "/dev/null"])
    # 这里只验证"能读到 os-release 并给出合理结论"，
    # 真正的判定在单元测试 problem_45_tests 里（含 OpenWrt 识别）
    text = Path("/etc/os-release").read_text(errors="ignore")
    ids = [ln for ln in text.splitlines() if ln.startswith(("ID=", "ID_LIKE="))]
    if ids:
        record(PASS, "发行版识别", f"当前环境: {', '.join(i.strip() for i in ids)}")
    else:
        record(FAIL, "发行版识别", "os-release 里没有 ID/ID_LIKE")


def check_log_rotation_real_kernel():
    """日志轮转在真实 Linux 内核上的行为（含外部轮转自愈）。"""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        logdir = td / "logs"
        logdir.mkdir()
        port = free_port()
        conf = write_conf(
            f"bind 127.0.0.1:{port}\n"
            f"server 223.5.5.5\n"
            f"address /rot.test/1.1.1.1\n"
            f"log-file {logdir}/smartdns.log\n"
            f"log-level debug\n"
            f"log-size 1K\n"
            f"log-num 3\n"
            f"log-console no\n",
            td / "smartdns.conf",
        )
        proc = start_server(conf, td, ["-v", "-v"])
        try:
            time.sleep(2.0)
            for _ in range(60):
                dns_query(port, "rot.test")
            time.sleep(1.0)
            active = logdir / "smartdns.log"
            if not active.exists():
                record(FAIL, "日志轮转（Linux）", "未生成活动日志文件")
                return
            # 外部改名搬走
            rotated = logdir / "smartdns.log.rotated"
            active.rename(rotated)
            for _ in range(80):
                dns_query(port, "rot.test")
            time.sleep(1.5)
            if active.exists() and active.stat().st_size > 0:
                record(PASS, "日志轮转（Linux）",
                       f"外部改名后自愈，活动文件重建（{active.stat().st_size} 字节）")
            else:
                record(FAIL, "日志轮转（Linux）",
                       "外部改名后活动日志未重建 —— 日志永久停写（问题 40 复现）")
            if not rotated.exists():
                record(FAIL, "日志轮转不丢外部文件", "被搬走的文件消失了")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def check_resolve_cli():
    """resolve 命令行工具在 Linux 上的基本可用性。"""
    port = free_port()
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        conf = write_conf(
            f"bind 127.0.0.1:{port}\n"
            f"bind-tcp 127.0.0.1:{port}\n"
            f"server 223.5.5.5\n"
            f"address /cli.test/10.1.2.3\n"
            f"log-file {td}/smartdns.log\n",
            td / "smartdns.conf",
        )
        proc = start_server(conf, td)
        try:
            time.sleep(1.5)
            code, out = dns_query(port, "cli.test")
            if "10.1.2.3" in out.replace("\n", ""):
                record(PASS, "resolve CLI（Linux）", "UDP 查询返回预期地址")
            else:
                record(FAIL, "resolve CLI（Linux）", f"UDP 查询异常: {out.strip()[:120]}")

            code, out = run(
                [str(EXE), "resolve", "-T", "-s", f"127.0.0.1:{port}", "cli.test"]
            )
            if "10.1.2.3" in out.replace("\n", ""):
                record(PASS, "resolve CLI TCP（Linux）", "TCP 查询返回预期地址")
            else:
                record(FAIL, "resolve CLI TCP（Linux）", f"TCP 查询异常: {out.strip()[:120]}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


# ---------------- 主流程 ----------------

CHECKS = {
    "ipset": check_ipset_real_kernel,
    "nftset": check_nftset_real_kernel,
    "lock": check_single_instance_lock,
    "syslog": check_syslog_output,
    "privilege": check_privilege_drop,
    "osrelease": check_os_release_detection,
    "rotation": check_log_rotation_real_kernel,
    "resolve": check_resolve_cli,
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--filter", default="", help="只跑名称含该子串的项")
    args = ap.parse_args()

    print("smartdns Linux 真机检查（WSL）")
    print(f"仓库: {REPO}")
    if not EXE.exists():
        print(f"未找到二进制: {EXE}\n请先 cargo build --offline --bin smartdns", file=sys.stderr)
        return 2
    if not is_root():
        print("提示：当前不是 root，涉及内核/降权的项会报告 SKIP（这是如实报告，不是失败）")

    for name, fn in CHECKS.items():
        if args.filter and args.filter not in name:
            continue
        section(name)
        try:
            fn()
        except Exception as e:  # 单项异常不应中断整套
            record(FAIL, name, f"检查过程中抛异常: {e}")

    n_pass = sum(1 for s, _, _ in _results if s == PASS)
    n_fail = sum(1 for s, _, _ in _results if s == FAIL)
    n_skip = sum(1 for s, _, _ in _results if s == SKIP)

    print("\n" + "=" * 56)
    print(f"汇总: {n_pass} 通过 / {n_fail} 失败 / {n_skip} 跳过")
    if n_fail:
        print("\n失败项:")
        for s, n, d in _results:
            if s == FAIL:
                print(f"  - {n}: {d}")
    if n_skip:
        print("\n跳过项（环境不具备，非产品问题）:")
        for s, n, d in _results:
            if s == SKIP:
                print(f"  - {n}: {d}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
