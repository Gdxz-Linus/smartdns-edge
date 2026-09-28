#!/bin/bash
# 问题 44 真机复现：用两种启动方式（带/不带 -p）起两个实例，看防多开是否失效。
# 两个实例用不同端口，避免端口冲突掩盖结论。
set -u
cd /mnt/d/smartdns-edge

TMP=$(mktemp -d); chmod 777 "$TMP"
echo "===== 问题 44 真机复现 ====="
echo "工作目录: $TMP"
echo ""

cat > "$TMP/a.conf" <<EOF
bind 127.0.0.1:26701
server 223.5.5.5
log-file $TMP/a.log
log-level info
EOF

cat > "$TMP/b.conf" <<EOF
bind 127.0.0.1:26702
server 223.5.5.5
log-file $TMP/b.log
log-level info
EOF

echo "--- 实例①：带 -p $TMP/run1.pid ---"
./target/debug/smartdns run -c "$TMP/a.conf" -p "$TMP/run1.pid" > "$TMP/o1.txt" 2>&1 &
P1=$!
sleep 3
if kill -0 $P1 2>/dev/null; then
  echo "  PID $P1 存活 ✅"
else
  echo "  PID $P1 已退出 ❌"; cat "$TMP/o1.txt" | head -5
fi

echo ""
echo "--- 实例②：不带 -p（pid 默认落到 <exe目录>/managed/）---"
./target/debug/smartdns run -c "$TMP/b.conf" > "$TMP/o2.txt" 2>&1 &
P2=$!
sleep 3
if kill -0 $P2 2>/dev/null; then
  echo "  PID $P2 存活 ← 若两个都存活，说明防多开失效"
else
  echo "  PID $P2 已退出（被防多开拦住）✅"
  head -5 "$TMP/o2.txt" | sed 's/^/    /'
fi

echo ""
echo "--- 两个实例的锁文件路径 ---"
find "$TMP" -name '*.lock' 2>/dev/null | sed 's/^/  /'
find /mnt/d/smartdns-edge/target/debug/managed -name '*.lock' 2>/dev/null | sed 's/^/  /'

echo ""
echo "--- 端口监听情况（两个端口都在 = 两个实例都活着）---"
ss -lun 2>/dev/null | grep -E '26701|26702' | sed 's/^/  /'

echo ""
kill $P1 2>/dev/null; kill $P2 2>/dev/null
wait $P1 2>/dev/null; wait $P2 2>/dev/null
rm -rf "$TMP"
rm -rf /mnt/d/smartdns-edge/target/debug/managed
echo "已清理"
