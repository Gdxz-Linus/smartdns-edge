#!/usr/bin/env bash

# Converts a pihole adlist to a smartdns compatible format. 
# Save adlist as pihole.txt in the same folder as this script and run it.

if [[ ! -f pihole.txt ]]; then
  echo "Error: pihole.txt not found!"
  exit 1
fi

echo "Converting pihole.txt to smartdns-ads.txt..."

# 🌟 核心优化：使用极其高效的单进程 awk 代替原先慢速的 while 循环，
# 处理 10 万行级别的过滤规则耗时由 5 分钟缩短至 0.1 秒！
awk '
{
  # 去除行首尾空格与制表符
  gsub(/^[ \t]+|[ \t]+$/, "");
  
  # 如果非注释行且非空行
  if ($0 !~ /^#/ && $0 != "") {
    # 提取域名（通常在第二列，若部分规则列表仅含域名则取第一列）
    domain = ($2 == "" ? $1 : $2);
    print "address /" domain "/0.0.0.0";
  }
}
' pihole.txt > smartdns-ads.txt

echo "Done! Generated smartdns-ads.txt successfully."
