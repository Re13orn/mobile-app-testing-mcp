#!/usr/bin/env bash
# 兼容入口：统一转发到跨平台 Node 安装脚本

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
node "$SCRIPT_DIR/setup.js" "$@"
