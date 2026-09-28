#!/bin/bash
# 验证问题 44 修复后，锁文件的【实际落点】与【跨 -p 复用】
set -u
cd /mnt/d/smartdns-edge

TMP=$(mktemp -d); chmod 777 "$TMP"
cat > "$TMP/a.conf" <<EOF
bind 127.0.0.1:26711
server 223.5.5.5
log-file $TMP/a.log
log-level info
EOF

echo "===== 锁文件实际落点 ====="
echo "（清理旧锁，确保是新生成的）"
rm -f /run/smartdns.lock /var/run/smartdns.lock /tmp/smartdns.lock

echo ""
echo "--- 以 root 起实例（带 -p 到临时目录）---"
./target/debug/smartdns run -c "$TMP/a.conf" -p "$TMP/r1.pid" > "$TMP/o.txt" 2>&1 &
P=$!
sleep 3

echo "  进程存活: $(kill -0 $P 2>/dev/null && echo yes || echo no)"
echo ""
echo "--- 各候选位置的锁文件 ---"
for f in /run/smartdns.lock /var/run/smartdns.lock /tmp/smartdns.lock; do
  if [ -e "$f" ]; then
    echo "  ✅ $f （存在）"
  else
    echo "  ·  $f （无）"
  fi
done
echo ""
echo "--- 临时目录里是否被动生成锁？---"
ls -la "$TMP" | grep -E '\.lock|\.pid' | sed 's/^/  /' || echo "  （无 .lock，符合预期）"

echo ""
echo "--- 关键：再从【另一个 -p 路径】起第二个实例，应被拒绝 ---"
cat > "$TMP/b.conf" <<EOF
bind 127.0.0.1:26712
server 223.5.5.5
log-file $TMP/b.log
log-level info
EOF
./target/debug/smartdns run -c "$TMP/b.conf" -p "$TMP/completely-different.pid" > "$TMP/o2.txt" 2>&1
CODE=$?
echo "  第二个实例退出码: $CODE"
grep -o 'already running.*' "$TMP/o2.txt" | head -1 | sed 's/^/  报错: /'

kill $P 2>/dev/null; wait $P 2>/dev/null
rm -f /run/smartdns.lock /var/run/smartdns.lock /tmp/smartdns.lock
rm -rf "$TMP"
echo ""
echo "已清理"
