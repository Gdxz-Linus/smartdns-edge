#!/usr/bin/env bash

# 🌟 核心优化 1：智能路径自适应，完美同时兼容 /etc/smartdns/smartdns.conf 和 /app/smartdns.conf
CONF_PATH="/etc/smartdns/smartdns.conf"

if [[ ! -f "${CONF_PATH}" ]]; then
  if [[ -f "/app/smartdns.conf" ]]; then
    CONF_PATH="/app/smartdns.conf"
  else
    echo "Error: Configuration file not found!"
    echo "Please mount your config to ${CONF_PATH} or /app/smartdns.conf"
    echo "Additional details: https://pymumu.github.io/smartdns/en/config/basic-config/"
    exit 1
  fi
fi

# 初始化参数（如果用户未指定额外的 PARAMS 环境变量）
if [[ -z "${PARAMS}" ]]; then
  PARAMS="run -c ${CONF_PATH}"
fi

# 🌟 核心优化 2：使用 exec 启动程序！
# 这会让 smartdns 进程彻底替代当前 shell 成为 PID 1 进程，
# 从而使容器能够完美响应系统的优雅退群信号 (SIGTERM)，实现秒级安全优雅关机，避免文件锁损坏。
exec /app/smartdns $PARAMS