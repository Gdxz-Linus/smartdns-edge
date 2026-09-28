#!/bin/bash
# 问题 17 的复核逻辑真跑验证：把 build.yml 里那段 bash **原样抽出来**跑一遍。
#
# ## 为什么必须真跑
#
# 这段逻辑在 CI 里才有机会执行；而它一旦写错，后果是**发布被卡住**
# （或更糟：该拦的没拦住）。而且我已经在格式上踩过一次坑 ——
# `just` 的 `sha256_file()` 返回**纯哈希**，不含文件名，`sha256sum -c` 解析不了。
# 所以这里造出与真实产物同构的目录，把逻辑跑通：
#   ① 正常情形（哈希对得上）→ 必须通过
#   ② 产物被篡改           → 必须失败
#   ③ 缺少校验文件         → 必须失败
#
# 用法（无需 root）：
#   wsl -d Ubuntu -- bash -lc "cd /mnt/d/smartdns-edge && bash tests/e2e/_p17_verify_release.sh"

set -uo pipefail

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1 -- $2"; FAIL=$((FAIL+1)); }

# ---- 与 build.yml 中一致的复核逻辑（保持同步！改了那边要同步这里）----
verify() {
  local dir="$1"
  local fail=0 found=0
  cd "$dir" || return 1

  for sumfile in *-sha256sum.txt; do
    [ -e "$sumfile" ] || continue
    found=1

    local artifact="${sumfile%-sha256sum.txt}"
    local expected
    expected="$(tr -d '[:space:]' < "$sumfile")"

    if [ ! -e "$artifact" ]; then
      echo "    -> $artifact listed but missing"
      fail=1
      continue
    fi

    local actual
    actual="$(sha256sum "$artifact" | awk '{print $1}')"

    if [ "$expected" != "$actual" ]; then
      echo "    -> $artifact checksum mismatch"
      fail=1
    fi
  done

  if [ "$found" -eq 0 ]; then
    echo "    -> no *-sha256sum.txt produced"
    fail=1
  fi

  for art in *.zip *.tar.gz *.tar.xz *.tar.zst *.msi *.exe; do
    [ -e "$art" ] || continue
    if [ ! -e "$art-sha256sum.txt" ]; then
      echo "    -> $art has no matching $art-sha256sum.txt"
      fail=1
    fi
  done

  return $fail
}

# ---- 造一个与真实产物同构的 dist/ ----
# 校验文件按 justfile 的真实写法生成：**纯哈希、无文件名**
make_dist() {
  local d="$1"
  rm -rf "$d"; mkdir -p "$d"
  # 两个归档（模拟 tar.gz 与 zip），加一个校验文件
  head -c 2048 /dev/urandom > "$d/smartdns-x86_64-generic-linux-gnu-v1.0.2.tar.gz"
  head -c 1024 /dev/urandom > "$d/smartdns-x86_64-pc-windows-msvc-v1.0.2.zip"
  for a in "$d"/*.tar.gz "$d"/*.zip; do
    sha256sum "$a" | awk '{print $1}' > "$a-sha256sum.txt"
  done
  # 让 bash 的 glob 在所有情形下行为一致
  :
}

echo "===== 问题 17：发布前复核逻辑的真跑验证 ====="
echo ""

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# ---------- ① 正常：哈希一致 ----------
echo "--- ① 正常情形（校验文件与实际产物一致）---"
make_dist "$TMP/ok"
if ( verify "$TMP/ok" ); then ok "正常情形通过"; else bad "正常情形应通过却失败" "见上"; fi

# 对照：确认生成的是"纯哈希、无文件名"（与 just 一致）
first="$(cat "$TMP/ok"/*-sha256sum.txt | head -1)"
if [ "${#first}" -eq 64 ]; then
  ok "校验文件格式与 justfile 一致（纯 64 位哈希、无文件名）"
else
  bad "校验文件格式不符" "长度=${#first}，内容=${first:0:40}"
fi

# ---------- ② 产物被篡改 ----------
echo ""
echo "--- ② 产物在打包后被改动（模拟链路替换）---"
make_dist "$TMP/tamper"
printf 'x' >> "$TMP/tamper/smartdns-x86_64-generic-linux-gnu-v1.0.2.tar.gz"
if ( verify "$TMP/tamper" ); then
  bad "篡改后应当失败却通过了" "复核没有起作用"
else
  ok "产物被篡改时复核失败（拦住了）"
fi

# ---------- ③ 缺校验文件 ----------
echo ""
echo "--- ③ 产物没有对应校验文件（漏算）---"
make_dist "$TMP/missing"
rm -f "$TMP/missing/smartdns-x86_64-pc-windows-msvc-v1.0.2.zip-sha256sum.txt"
if ( verify "$TMP/missing" ); then
  bad "缺校验文件应当失败却通过了" "漏算没有被发现"
else
  ok "产物缺校验文件时复核失败"
fi

# ---------- ④ 完全没有校验文件 ----------
echo ""
echo "--- ④ 一个校验文件都没有 ---"
make_dist "$TMP/none"
rm -f "$TMP/none"/*-sha256sum.txt
if ( verify "$TMP/none" ); then
  bad "无校验文件应当失败却通过了" "复核成了空转"
else
  ok "完全没有校验文件时复核失败"
fi

echo ""
echo "========================================================"
echo "汇总: $PASS 通过 / $FAIL 失败"
[ "$FAIL" -eq 0 ] || exit 1
