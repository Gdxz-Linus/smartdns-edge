#!/bin/bash
# 问题 49 真机验证（自建上游版）：
#   WSL 里访问不了公网 DNS，所以用 tests/e2e/ttl_upstream.py 之类的本地上游提供确定的 A 记录，
#   这样才真正走到 nftset 的内核写入路径。
#
# 验证目标：配置一个【不存在】的 nftables 集合 ——
#   修复前：写入静默"成功"，日志里没有任何失败原因
#   修复后：内核回执被读出，失败可见
set -u
cd /mnt/d/smartdns-edge

TMP=$(mktemp -d); chmod 777 "$TMP"

echo "===== 问题 49 真机验证（本地上游）====="
echo ""

if ! command -v nft >/dev/null 2>&1; then
  echo "本环境没有 nft，跳过"
  exit 0
fi

# 起一个本地上游，对 probe.test 返回 A 10.20.30.40
cat > "$TMP/up.py" <<'PYEOF'
import socket, struct, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port))
print("upstream on", port, flush=True)
while True:
    try: data, addr = s.recvfrom(4096)
    except OSError: break
    if len(data) < 12: continue
    txid = data[0:2]
    i = 12
    labels = []
    while data[i] != 0:
        ln = data[i]; labels.append(data[i+1:i+1+ln].decode("ascii","ignore")); i += 1+ln
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

python3 "$TMP/up.py" 26820 > "$TMP/up.log" 2>&1 &
UPPID=$!
sleep 1

# 建表、故意不建集合
nft delete table inet p49probe 2>/dev/null
nft add table inet p49probe
echo "已建表 inet p49probe（不建集合）"

PORT=26821
cat > "$TMP/c.conf" <<EOF
bind 127.0.0.1:$PORT
server 127.0.0.1:26820
nftset /probe.test/#4:inet#p49probe#nonexistent_set
nftset-debug yes
log-file $TMP/smartdns.log
log-level debug
EOF

./target/debug/smartdns run -c "$TMP/c.conf" > "$TMP/out.txt" 2>&1 &
PID=$!
sleep 3

echo ""
echo "--- 查询 probe.test（应返回 10.20.30.40）---"
./target/debug/smartdns resolve -s 127.0.0.1:$PORT probe.test 2>&1 | head -6 | sed 's/^/  /'
sleep 3

echo ""
echo "--- nftset 相关日志 ---"
grep -iE "nftset" "$TMP/out.txt" "$TMP/smartdns.log" 2>/dev/null | tail -10 | sed 's/^/  /'
echo ""

if grep -qiE "nftset.*(cannot|fail|error)" "$TMP/out.txt" "$TMP/smartdns.log" 2>/dev/null; then
  echo "判定: ✅ 写入失败已被感知（日志中出现明确的失败告警）"
else
  echo "判定: ❌ 未见到失败告警 —— 失败仍是静默的"
fi

kill $PID 2>/dev/null; kill $UPPID 2>/dev/null
wait $PID 2>/dev/null; wait $UPPID 2>/dev/null
nft delete table inet p49probe 2>/dev/null
rm -rf "$TMP"
echo "已清理"
