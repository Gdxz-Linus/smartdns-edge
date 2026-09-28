#!/bin/bash
# 问题 42 真机验证：ipset 回执被真实读取（失败可见 + 成功不误报）
#
# ## 修的是什么
#
# ipset 写入后要读内核回执判断成功与否。解析时只校验了报文长度 >= 16 字节，
# 而**错误码在偏移 16..20**（完整回执还更长）—— 偏短的回执会读到缓冲区里的
# **残留零值**，于是 code == 0 被当成"写入成功"。
# 表现就是「ipset 写入静默失败」，与"失败要看得见"的目标相悖。
#
# 另有一处无效代码：`if msg_type != X || msg_seq != Y { if ... { continue } continue }`
# —— 内外两个分支动作相同，已清理。
#
# ## 本脚本验证两组（缺一不可）
#
#   组A【失败可见】：写进一个**不存在**的集合 → 必须看到明确的失败原因
#   组B【成功不误报】：写进**存在**的集合 → 必须真的进内核，且**不得**报失败
#
# 组B 与组A 同等重要：回执校验若写得过严，会把正常成功也判成失败，
# 那就从"静默漏报"变成"满屏误报"（这条教训来自问题 49 的验证）。
#
# ## ⚠️ 本脚本的边界（实测得出，务必如实理解）
#
# **本脚本对"偏短回执"这条修复分支没有判别力。**
# 实测：把长度门槛退回旧的 `n >= 16` 后，本脚本**仍然全绿** ——
# 因为**内核实际发出的总是完整的 36 字节回执**，真机路径上根本不会出现偏短回执。
#
# 那么"偏短回执被当成成功"靠什么保证？
#   → 单元测试 `classify_ack`（`src/ffi/ipset.rs` 的
#     `short_ack_is_not_treated_as_success` / `truncated_ack_is_rejected`），
#     它们用**人造报文**直接喂进判定函数，能精确构造 16/19/20 字节与自述长度撒谎的情形。
#     反向验证在那里是有效的（退回旧门槛即失败）。
#
# 本脚本负责的是**接线层**：回执真的被读了吗？失败真的报出来了吗？
# 成功有没有被误报？—— 这些恰好是单元测试碰不到的。
#
# ⚠️ 必须用**真实上游解析**的域名：`address` 静态规则的应答不经过
#    "解析结果送进防火墙"那条路径，ipset 不会有条目（那是设计行为，曾误报过一次）。
#
# 用法（需要 root）：
#   wsl -d Ubuntu -u root -- bash -lc "cd /mnt/d/smartdns-edge && bash tests/e2e/_p42_ipset_ack.sh"
set -u
cd /mnt/d/smartdns-edge

TMP=$(mktemp -d); chmod 777 "$TMP"

echo "===== 问题 42 真机验证：ipset 回执解析 ====="
echo ""

if ! command -v ipset >/dev/null 2>&1; then
  echo "本环境没有 ipset 命令/内核模块，跳过"
  rm -rf "$TMP"; exit 0
fi

# 本地上游：对 probe.test 返回 A 10.20.30.40（避免依赖公网）
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

python3 "$TMP/up.py" 26840 > "$TMP/up.log" 2>&1 &
UPPID=$!
sleep 1

PASS=0; FAIL=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1 -- $2"; FAIL=$((FAIL+1)); }

# ---------------------------------------------------------------- 组A：失败可见
echo "--- 组A：写进不存在的集合，失败必须可见 ---"
ipset destroy p42_missing 2>/dev/null
PORT_A=26841
cat > "$TMP/a.conf" <<EOF
bind 127.0.0.1:$PORT_A
server 127.0.0.1:26840
ipset /probe.test/#4:p42_missing
log-file $TMP/a.log
log-level debug
EOF

./target/debug/smartdns run -c "$TMP/a.conf" > "$TMP/a.out" 2>&1 &
PID_A=$!
sleep 3
./target/debug/smartdns resolve -s 127.0.0.1:$PORT_A probe.test > /dev/null 2>&1
sleep 3

if grep -qiE "ipset.*(cannot|fail|error|not exist|no such)" "$TMP/a.out" "$TMP/a.log" 2>/dev/null; then
  ok "不存在的集合已产生明确失败告警"
else
  bad "不存在的集合未产生失败告警（失败仍是静默的）" \
      "$(grep -i ipset "$TMP/a.out" "$TMP/a.log" 2>/dev/null | tail -2 | tr '\n' ' ')"
fi
kill $PID_A 2>/dev/null; wait $PID_A 2>/dev/null

# ---------------------------------------------------------------- 组B：成功不误报
echo ""
echo "--- 组B：写进存在的集合，必须真写入且不误报 ---"
ipset destroy p42_ok 2>/dev/null
if ! ipset create p42_ok hash:ip timeout 0 2>"$TMP/create.err"; then
  echo "无法创建测试集合（内核不支持？），跳过组B: $(cat "$TMP/create.err")"
else
  PORT_B=26842
  cat > "$TMP/b.conf" <<EOF
bind 127.0.0.1:$PORT_B
server 127.0.0.1:26840
ipset /probe.test/#4:p42_ok
log-file $TMP/b.log
log-level debug
EOF

  ./target/debug/smartdns run -c "$TMP/b.conf" > "$TMP/b.out" 2>&1 &
  PID_B=$!
  sleep 3
  ./target/debug/smartdns resolve -s 127.0.0.1:$PORT_B probe.test > /dev/null 2>&1
  sleep 3

  MEMBERS=$(ipset list p42_ok 2>/dev/null | grep -cE '^[0-9]')
  if [ "$MEMBERS" -gt 0 ]; then
    ok "地址真的写进了内核集合（$MEMBERS 条：$(ipset list p42_ok | grep -E '^[0-9]' | head -1 | tr -d '\t'))"
  else
    bad "地址未写入内核集合" "$(ipset list p42_ok 2>&1 | tail -3 | tr '\n' ' ')"
  fi

  # 成功场景不得出现失败告警（回执校验过严就会在这里翻车）
  if grep -qiE "ipset.*(cannot|fail|error)" "$TMP/b.out" "$TMP/b.log" 2>/dev/null; then
    bad "成功场景被误报为失败（回执校验过严）" \
        "$(grep -iE "ipset.*(cannot|fail|error)" "$TMP/b.out" "$TMP/b.log" 2>/dev/null | tail -2 | tr '\n' ' ')"
  else
    ok "成功场景未被误报"
  fi

  kill $PID_B 2>/dev/null; wait $PID_B 2>/dev/null
  ipset destroy p42_ok 2>/dev/null
fi

kill $UPPID 2>/dev/null; wait $UPPID 2>/dev/null
rm -rf "$TMP"

echo ""
echo "========================================================"
echo "汇总: $PASS 通过 / $FAIL 失败"
[ "$FAIL" -eq 0 ] || exit 1
echo "已清理"
