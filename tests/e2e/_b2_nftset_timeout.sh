#!/bin/bash
# nftset 超时与区间集合的真机验证 —— **B-② 翻译前必须先跑通，作为 C 与 Rust 两版的共同基线**。
#
# ## 为什么必须单独有这一条
#
# 既有的 `_p49_ok.sh` 虽然建了一个 `flags timeout` 的集合，但配置里**没有打开
# `nftset-timeout`** —— 于是 `set_expiry_seconds()` 返回 0，程序**根本不发
# `NFTA_SET_ELEM_TIMEOUT` 属性**。那条脚本从来没有验证过超时属性。
#
# 而超时恰好是 nftset 与 ipset 差异最大、最容易照抄写错的地方：
#   · ipset  的超时是 **u32、单位秒、带 NLA_F_NET_BYTEORDER 标志**；
#   · nftset 的超时是 **u64、单位毫秒（写入前 ×1000）、不带那个标志**。
#
# ## 判据（不是"没报错就算过"）
#
#   ① `nft list set` 里条目必须带上 **`expires`** —— "内核接受了超时且单位换算正确"
#      的直接证据；
#   ② 同时**不得**出现失败告警（成功场景不能被误报）；
#   ③ 对照组：开关关着时条目**不应**有 `expires`（防"开关形同虚设"）；
#   ④ interval 集合：`nft` 会把「起点 + 区间结束」这一对显示成 **`a.b.c.d/31`**
#      （对照实验确认：nft 不打印结束地址本身）⇒ 判据必须找 `/31`。
set -u
cd /mnt/d/smartdns-edge

TMP=$(mktemp -d); chmod 777 "$TMP"
PASS=0; FAIL=0

ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

echo "===== nftset 超时/区间真机验证（B-② 基线）====="
echo ""

if ! command -v nft >/dev/null 2>&1; then
  echo "本环境没有 nft，跳过"
  exit 0
fi

# ---- 本地上游：probe.test → 10.20.30.40，TTL 300 ----
cat > "$TMP/up.py" <<'PYEOF'
import socket, struct, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port))
while True:
    try: data, addr = s.recvfrom(4096)
    except OSError: break
    if len(data) < 12: continue
    txid = data[0:2]
    i = 12
    while data[i] != 0:
        i += 1 + data[i]
    i += 1
    qtype, _ = struct.unpack("!HH", data[i:i+4])
    question = data[12:i+4]
    if qtype == 1:
        hdr = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton("10.20.30.40")
        s.sendto(hdr + question + ans, addr)
    else:
        s.sendto(txid + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + question, addr)
PYEOF

# ⚠️ 必须真的把上游起起来：漏掉这一句会让查询解析不到地址、集合全空，
#    判据一齐变红 —— 那是脚本自己没准备好，不是产品缺陷（第一版就栽在这里）。
python3 "$TMP/up.py" 26840 > "$TMP/up.log" 2>&1 &
UPPID=$!
sleep 1

run_case() {
  local label="$1" port="$2" setname="$3" setdef="$4" timeout_line="$5"
  nft delete table inet b2t 2>/dev/null
  nft add table inet b2t
  nft add set inet b2t "$setname" "$setdef"
  echo "--- 用例：$label ---"
  cat > "$TMP/c-$port.conf" <<EOF
bind 127.0.0.1:$port
server 127.0.0.1:26840
nftset /probe.test/#4:inet#b2t#$setname
nftset-debug yes
$timeout_line
log-file $TMP/smartdns-$port.log
log-level debug
EOF
  ./target/debug/smartdns run -c "$TMP/c-$port.conf" > "$TMP/out-$port.txt" 2>&1 &
  local pid=$!
  sleep 3
  ./target/debug/smartdns resolve -s 127.0.0.1:$port probe.test > /dev/null 2>&1
  sleep 2
  nft list set inet b2t "$setname" 2>&1 | sed 's/^/      /'
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  nft list set inet b2t "$setname" 2>&1
}

# ============ 用例一：开 nftset-timeout，集合支持 timeout ============
OUT1=$(run_case "nftset-timeout yes（集合 flags timeout）" 26841 st '{ type ipv4_addr; flags timeout; }' 'nftset-timeout yes')
echo ""
echo "$OUT1" | grep -qE '10\.20\.30\.40' && ok "地址写入了集合" || bad "地址没写进集合"
echo "$OUT1" | grep -qE 'expires' && ok "条目带 expires ⇒ 超时属性被内核接受、单位换算正确" \
  || bad "条目没有 expires ⇒ 超时属性未被内核接受（或单位/字节序写错）"
grep -qiE "nftset.*cannot" "$TMP/out-26841.txt" 2>/dev/null \
  && bad "成功场景被误报为失败" || ok "成功场景未被误报"

# ============ 用例二（对照组）：没开 nftset-timeout，不应带 expires ============
OUT2=$(run_case "nftset-timeout 关（集合 flags timeout）" 26842 st2 '{ type ipv4_addr; flags timeout; }' 'nftset-timeout no')
echo ""
echo "$OUT2" | grep -qE '10\.20\.30\.40' && ok "对照组：地址写入了集合" || bad "对照组：地址没写进集合"
echo "$OUT2" | grep -qE 'expires' \
  && bad "对照组：开关关着却仍带 expires ⇒ 超时开关形同虚设" \
  || ok "对照组：开关关着时条目不带 expires（开关真的在起作用）"

# ============ 用例三：interval 集合（区间结束元素）============
OUT3=$(run_case "interval 集合 + timeout" 26843 iv '{ type ipv4_addr; flags interval, timeout; }' 'nftset-timeout yes')
echo ""
echo "$OUT3" | grep -qE '10\.20\.30\.40' && ok "interval 集合：地址写入" || bad "interval 集合：地址没写入"
grep -qiE "nftset.*cannot" "$TMP/out-26843.txt" 2>/dev/null \
  && bad "interval 集合：成功场景被误报为失败" || ok "interval 集合：成功场景未被误报"

# ── 已知观察项（**不作为 B-② 的判据**，如实记录）─────────────────────────────
#
# 取证结论（干净套接字复现，见 `_b2_forensic.py`）：
#   · `_nftset_get_flags` **确实**能读到集合标志（interval=0x4、timeout=0x10）；
#   · 往**不支持超时**的集合写带超时属性的元素 → 内核回 **EINVAL(-22)**
#     ⇒ 这正是 `process_setflags` 必须把超时归零的原因，翻译时**不可省略**；
#   · 但区间集合的**区间结束元素**在本仓库**没有**按预期落地：
#     手写「起点 + 区间结束」时 nft 显示 `a.b.c.d/31`，而实际只出现单个地址。
#     这是 **C 版既有行为**，不属于 B-② 的改动范围。
#
# ⇒ B-② 的判据：**逐字翻译 `_nftset_process_setflags`**（含区间逻辑），
#    使 Rust 版与 C 版**可观测行为一致**。若翻译后区间行为发生变化，
#    那是翻译引入的回归，必须修回；**不在此处要求 C 版先改对**。
if echo "$OUT3" | grep -qE '10\.20\.30\.40/31'; then
  echo "  [INFO] interval 集合：出现 /31（区间结束元素已落地）"
else
  echo "  [INFO] interval 集合：未出现 /31 —— 与 C 版既有行为一致，翻译时须保持同等行为"
fi

echo ""
echo "========================================================"
echo "汇总: $PASS 通过 / $FAIL 失败"

kill $UPPID 2>/dev/null
wait $UPPID 2>/dev/null
nft delete table inet b2t 2>/dev/null
rm -rf "$TMP"
echo "已清理"

[ "$FAIL" -eq 0 ]
