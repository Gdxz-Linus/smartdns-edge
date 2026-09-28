#!/bin/bash
# 问题 49 的反向保护：**集合存在时，写入必须照常成功、不得误报失败**。
#
# 这一条与"失败可见"同等重要：读回执的逻辑若写得太严，
# 会把正常成功也判成失败，那就从"静默漏报"变成"满屏误报"。
set -u
cd /mnt/d/smartdns-edge

TMP=$(mktemp -d); chmod 777 "$TMP"

echo "===== 问题 49 反向保护：正常写入不得误报 ====="
echo ""

if ! command -v nft >/dev/null 2>&1; then
  echo "本环境没有 nft，跳过"
  exit 0
fi

# 本地上游
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
python3 "$TMP/up.py" 26830 > /dev/null 2>&1 &
UPPID=$!
sleep 1

# 建表【并建集合】
nft delete table inet p49ok 2>/dev/null
nft add table inet p49ok
nft add set inet p49ok good_set '{ type ipv4_addr; flags timeout; }'
echo "已建表 inet p49ok 与集合 good_set"
nft list set inet p49ok good_set | sed 's/^/  /'
echo ""

PORT=26831
cat > "$TMP/c.conf" <<EOF
bind 127.0.0.1:$PORT
server 127.0.0.1:26830
nftset /probe.test/#4:inet#p49ok#good_set
nftset-debug yes
log-file $TMP/smartdns.log
log-level debug
EOF

./target/debug/smartdns run -c "$TMP/c.conf" > "$TMP/out.txt" 2>&1 &
PID=$!
sleep 3
./target/debug/smartdns resolve -s 127.0.0.1:$PORT probe.test > /dev/null 2>&1
sleep 3

echo "--- 内核集合内容（应有 10.20.30.40）---"
nft list set inet p49ok good_set | sed 's/^/  /'
echo ""
echo "--- 日志（不应出现失败告警）---"
grep -iE "nftset" "$TMP/out.txt" 2>/dev/null | tail -5 | sed 's/^/  /'
echo ""

if grep -qE '10\.20\.30\.40' <(nft list set inet p49ok good_set); then
  echo "判定: ✅ 地址真的写进了内核集合"
else
  echo "判定: ❌ 地址未写入内核集合"
fi

if grep -qiE "nftset.*cannot" "$TMP/out.txt" 2>/dev/null; then
  echo "判定: ❌ 成功场景被误报为失败（读回执逻辑过严）"
else
  echo "判定: ✅ 成功场景未被误报"
fi

kill $PID 2>/dev/null; kill $UPPID 2>/dev/null
wait $PID 2>/dev/null; wait $UPPID 2>/dev/null
nft delete table inet p49ok 2>/dev/null
rm -rf "$TMP"
echo "已清理"
