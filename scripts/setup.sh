#!/bin/bash
# 移动端App测试MCP 自动安装脚本

set -e

echo "🚀 开始安装移动端App测试MCP..."

# 检查Node.js版本
if ! command -v node &> /dev/null; then
    echo "❌ 未找到 Node.js，请先安装 Node.js 18.0+"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js 版本过低，需要 18.0+，当前版本: $(node -v)"
    exit 1
fi

echo "✅ Node.js 版本检查通过: $(node -v)"

# 安装npm依赖
echo "📦 安装项目依赖..."
npm install

# 构建项目
echo "🔨 构建项目..."
npm run build

# 检查和下载JADX
if [ ! -f "jadx/bin/jadx" ]; then
    echo "📥 下载 JADX 反编译工具..."
    mkdir -p jadx
    
    # 检测架构
    OS=$(uname -s)
    case $OS in
        Darwin)
            echo "检测到 macOS 系统"
            if command -v brew &> /dev/null; then
                echo "使用 Homebrew 安装 JADX..."
                brew install jadx
            else
                echo "下载 JADX 到项目目录..."
                curl -L https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip -o jadx.zip
                unzip -q jadx.zip -d jadx/
                rm jadx.zip
            fi
            ;;
        Linux)
            echo "检测到 Linux 系统，下载 JADX..."
            curl -L https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip -o jadx.zip
            unzip -q jadx.zip -d jadx/
            rm jadx.zip
            ;;
        *)
            echo "⚠️  未识别的系统，请手动下载 JADX: https://github.com/skylot/jadx/releases"
            ;;
    esac
else
    echo "✅ JADX 已安装"
fi

# 检查ADB
if ! command -v adb &> /dev/null; then
    echo "⚠️  未找到 ADB，请安装 Android SDK Platform Tools"
    echo "   下载地址: https://developer.android.com/studio/releases/platform-tools"
else
    echo "✅ ADB 已安装: $(adb version | head -n1)"
fi

# 检查Android SDK
if [ -z "$ANDROID_HOME" ] && [ -z "$ANDROID_SDK_ROOT" ]; then
    echo "⚠️  未设置 ANDROID_HOME 或 ANDROID_SDK_ROOT 环境变量"
    echo "   请设置环境变量指向 Android SDK 目录"
    
    # 尝试检测常见路径
    POSSIBLE_PATHS=(
        "$HOME/Library/Android/sdk"
        "$HOME/Android/Sdk"
        "/usr/local/android-sdk"
        "/opt/android-sdk"
    )
    
    for path in "${POSSIBLE_PATHS[@]}"; do
        if [ -d "$path" ]; then
            echo "   建议设置: export ANDROID_HOME=\"$path\""
            break
        fi
    done
else
    echo "✅ Android SDK 路径已配置"
fi

echo ""
echo "🎉 安装完成！"
echo ""
echo "📋 下一步操作："
echo "1. 配置 Claude Desktop MCP (参考 README.md)"
echo "2. 确保 Android SDK 环境变量已设置"
echo "3. 连接 Android 设备并启用 USB 调试"
echo "4. 运行: npm start"