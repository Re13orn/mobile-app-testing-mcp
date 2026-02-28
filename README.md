# 📱 移动端App测试MCP

一个基于 Model Context Protocol (MCP) 的移动应用测试工具，聚焦 ADB 自动化、AAPT APK信息分析、JADX 反编译与静态安全检测，为移动应用安全测试提供完整解决方案。

## 🚀 快速安装

### 前置要求

- **Node.js** 18.0+
- **Android SDK** (包含 ADB 和 AAPT)
- **JADX** 反编译工具 (可选)

### 安装步骤

```bash
# 1. 克隆项目
git clone https://github.com/your-username/mobile-app-testing-mcp.git
cd mobile-app-testing-mcp

# 2. 初始化环境配置（推荐）
cp .env.example .env
# 按需修改 .env（ANDROID_HOME / ADB_PATH / JADX_PATH 等）
# Windows PowerShell 可使用: copy .env.example .env

# 3. 运行跨平台安装脚本
npm run setup

# 或手动安装：
# npm install
# npm run build

# 4. 检查环境依赖
npm run check

# 5. 执行 MCP 自检
npm run smoke

# 6. 启动 MCP 服务器
npm start
```

## ⚙️ MCP 客户端配置

本项目是标准 `stdio` MCP Server，可接入 Claude Desktop、Codex、以及其他支持 MCP 的客户端。

### 通用配置模板 (推荐)

```json
{
  "mcpServers": {
    "mobile-app-testing": {
      "command": "node",
      "args": ["/path/to/your/project/dist/index.js"],
      "cwd": "/path/to/your/project",
      "env": {}
    }
  }
}
```

可直接使用仓库中的示例文件：`mcp-config.example.json`

### 完整配置 (可选)

```json
{
  "mcpServers": {
    "mobile-app-testing": {
      "command": "node", 
      "args": ["/path/to/your/project/dist/index.js"],
      "cwd": "/path/to/your/project",
      "env": {
        "ANDROID_HOME": "/path/to/android/sdk"
      }
    }
  }
}
```

### 客户端接入说明
- Claude Desktop: 将上面的 `mcpServers.mobile-app-testing` 配置合并到 `claude_desktop_config.json`
- Codex/其他客户端: 在对应客户端的 MCP Server 配置中添加同样的 `command/args/cwd/env`
- 核心原则:
  - `args` 必须指向本项目的绝对路径 `dist/index.js`
  - `cwd` 建议设为项目根目录
  - 若客户端未继承系统环境变量，请在 `env` 中显式传入 `ANDROID_HOME` / `PATH`

## ✅ 使用前必须配置

### 1. Android SDK (必需)
```bash
# 下载并安装 Android SDK 或 Android Studio
# https://developer.android.com/studio

# macOS / Linux 设置示例
export ANDROID_HOME=/path/to/android/sdk
export PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/build-tools/latest

# 验证安装
adb version
```

Windows PowerShell 示例：
```powershell
$env:ANDROID_HOME="C:\Users\<you>\AppData\Local\Android\Sdk"
$env:Path += ";$env:ANDROID_HOME\platform-tools;$env:ANDROID_HOME\build-tools\latest"
adb version
```

### 2. Android 设备连接 (必需) 
```bash
# 1. 开启开发者选项和USB调试
# 2. 连接设备后验证
adb devices
# 应该显示: device (而不是 unauthorized)
```

### 3. Node.js (必需)
```bash
# 确保版本 >= 18.0
node --version
```

## 🔧 可选组件配置

**自动安装** (推荐):
```bash
npm run check  # 检查环境
npm run setup  # 安装依赖并构建项目
```

**手动安装**:
- **JADX** (反编译): `brew install jadx`

**可配置路径（.env）**：
- `ADB_PATH`, `AAPT_PATH`, `JADX_PATH`
- `SCREENSHOTS_DIR`, `RECORDINGS_DIR`, `DECOMPILED_DIR`, `LOGS_DIR`

## 📋 可用工具

MCP 服务器提供以下工具类别：

### 📱 ADB 工具 (22个)
- 设备管理、应用操作、文件传输、UI自动化

### 📦 AAPT 工具 (4个)
- APK信息分析、权限检查、资源分析

### 🔍 JADX 工具 (3个)
- APK反编译、源码分析、项目统计

### 🔒 静态安全分析工具 (4个) ⭐ **新增**
- 硬编码敏感信息扫描、调试信息泄露检测
- 弱加密算法识别、综合安全分析

### 🤖 工作流工具 (6个)
- 智能建议、进度分析、模板管理

### 🔐 文件工具 (1个)
- SHA256哈希计算、文件完整性验证

## ⚡ 四步启动

```bash
# 1. 检查环境
npm run check

# 2. 配置Android SDK路径 (如果检查失败)
export ANDROID_HOME=/path/to/android/sdk

# 3. 执行 MCP 自检
npm run smoke

# 4. 启动服务
npm start
```

## 🧪 一键验证（推荐）

```bash
npm run verify
```

该命令会依次执行：
- 构建 (`npm run build`)
- 环境检查 (`npm run check`)
- MCP 协议自检 (`npm run smoke`)

## 🧭 启动缺依赖指引

`npm start` 启动时会自动输出 `adb / aapt / jadx` 运行环境检查结果。  
若发现缺失，会直接打印安装与 `.env` 配置步骤（包括 `ADB_PATH / AAPT_PATH / JADX_PATH / ANDROID_HOME`）。

## 💡 基本使用

配置完成后，在任意 MCP 客户端中即可使用：

```
分析这个APK文件的基本信息：/path/to/app.apk

请帮我反编译这个APK：com.example.app

对连接的Android设备进行截图
```

## 📋 高级用法示例

查看 **[prompt-examples](./prompt-examples/)** 目录，包含详细的使用示例：

- 🔍 **[静态代码安全分析](./prompt-examples/静态代码安全分析.md)** - 全面代码安全扫描 ⭐ **新增**
- 🔓 **[Root检测分析](./prompt-examples/Root检测绕过分析.md)** - Root检测机制识别与鲁棒性评估
- 🔑 **[密码验证逻辑分析](./prompt-examples/密码验证Hook分析.md)** - 静态审计 + ADB流程验证
- 🌐 **[网络加密分析](./prompt-examples/网络通信加密分析.md)** - 分析通信加密机制
- 🔒 **[SSL证书固定评估](./prompt-examples/SSL证书固定绕过.md)** - 识别证书固定实现与风险点
- 📦 **[应用结构分析](./prompt-examples/应用加壳脱壳分析.md)** - 加壳迹象识别与反编译可行性评估
- 🛡️ **[恶意软件分析](./prompt-examples/恶意软件行为分析.md)** - 全面恶意行为分析

每个示例都包含完整的分析流程、工具调用清单和代码示例。



## 🔐 安全注意事项

- 仅用于合法的安全测试和研究
- 确保拥有目标应用的测试授权
- 遵守当地法律法规
- 不用于恶意目的

## 🆘 常见问题解决

```bash
# 环境检查不通过？
npm run check

# MCP 无法连接？
# 1. 检查路径是否正确
# 2. 确保 npm run build 成功
# 3. 重启 Claude Desktop

# 设备检测不到？
adb devices  # 确保显示 'device' 状态
```
