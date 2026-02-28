# 📱 Mobile App Testing MCP

一个面向 Android 安全测试场景的 MCP Server，聚焦以下能力：
- ADB 设备与应用操作自动化
- AAPT APK 信息分析
- JADX 反编译与代码审计支撑
- 静态安全扫描（密钥泄露、弱加密、调试泄露）

项目遵循标准 `stdio` MCP 协议，可接入 Claude、Codex 及其他 MCP 客户端。

## ✨ 核心特性

- 开箱即用启动脚本：`npm start` 会先做依赖探测再启动服务
- 首次运行可自动下载 JADX（默认 `v1.5.5`）
- 支持 `.env`、Android SDK 路径、系统 PATH 多层回退
- 内置健康检查链路：`check` + `smoke` + `verify`

## 📌 能力边界

- 当前定位为 **Android App 测试 MCP**
- 已移除 Frida / Gadget 动态注入能力
- 动态 Hook 类测试不在当前工具范围内

## 🚀 启动流程（最简）

```bash
# 1) 克隆并进入目录
git clone https://github.com/your-username/mobile-app-testing-mcp.git
cd mobile-app-testing-mcp

# 2) 安装并构建
npm run setup

# 3) 启动 MCP
npm start
```

就这三步，其他配置都可以后补。

## 🧭 `npm start` 会自动做什么

`npm start` 实际执行 `node scripts/start.js`，启动前会自动：
1. 探测 `adb` / `aapt` / `jadx` 本地路径（`.env`、Android SDK、PATH）
2. 若缺少 `jadx` 且 `AUTO_DOWNLOAD_JADX=true`，自动下载并解压
3. 打印缺失依赖修复建议后，再启动服务

默认 JADX 下载地址：
`https://github.com/skylot/jadx/releases/download/v1.5.5/jadx-1.5.5.zip`

## 🛠 环境要求

- Node.js `>= 18`
- Android SDK（至少包含 `platform-tools`，推荐包含 `build-tools`）
- JADX（可选，可由启动脚本自动下载）

## ⚙️ 常用命令

```bash
npm run setup    # 安装依赖 + 构建
npm start        # 启动（含依赖探测与JADX自动下载）
npm run verify   # 完整验证（build + check + smoke）
npm run check    # 仅检查本机依赖
npm run smoke    # 仅做 MCP 冒烟测试
npm run build    # 清理 dist 后重新编译
npm run dev      # 构建后启动（同 start）
```

## 🔧 `.env` 配置

复制 `.env.example` 为 `.env` 后，常用配置如下：

- `ANDROID_HOME` / `ANDROID_SDK_ROOT`：Android SDK 路径（推荐设置）
- `ADB_PATH`：adb 可执行文件绝对路径（可选）
- `AAPT_PATH`：aapt 可执行文件绝对路径（可选）
- `JADX_PATH`：jadx 可执行文件绝对路径（可选）
- `AUTO_DOWNLOAD_JADX`：是否自动下载 JADX（默认 `true`）
- `JADX_VERSION`：自动下载版本（默认 `1.5.5`）
- `JADX_DOWNLOAD_URL`：JADX 下载 URL（可覆盖默认地址）
- `SCREENSHOTS_DIR` / `RECORDINGS_DIR` / `DECOMPILED_DIR` / `LOGS_DIR`：工作目录

## 🔌 MCP 客户端接入

项目是标准 `stdio` MCP Server，通用配置如下：

```json
{
  "mcpServers": {
    "mobile-app-testing": {
      "command": "node",
      "args": ["/path/to/your/project/scripts/start.js"],
      "cwd": "/path/to/your/project",
      "env": {}
    }
  }
}
```

说明：
- `args` 推荐指向 `scripts/start.js`（而不是 `dist/index.js`），才能保留自动依赖检查与 JADX 首启下载
- `cwd` 建议为项目根目录
- 客户端不继承系统环境时，请在 `env` 明确传入 `ANDROID_HOME`、`PATH`

示例文件：[`mcp-config.example.json`](./mcp-config.example.json)

## 🧰 工具能力清单

当前总计 `40` 个工具：

- ADB 工具 `22`：设备、应用、文件、输入模拟、截屏录屏
- AAPT 工具 `4`：badging、permissions、xmltree、完整分析
- JADX 工具 `3`：反编译、输出信息、APK 验证
- 静态分析工具 `4`：secrets/debug/weak-crypto/comprehensive
- 工作流工具 `6`：模板、上下文、智能建议、执行记录
- 文件工具 `1`：`sha256` 指纹

## 💡 使用示例

在任意 MCP 客户端可直接提出：

```text
分析这个 APK 的基础信息：/path/to/app.apk
反编译这个 APK 并输出关键目录：/path/to/app.apk
对当前连接设备截图并保存到默认目录
```

## 📚 Prompt 示例

参考 [`prompt-examples`](./prompt-examples/)：

- [SECURITY_TESTING_PROMPT](./prompt-examples/SECURITY_TESTING_PROMPT.md)
- [静态代码安全分析](./prompt-examples/静态代码安全分析.md)
- [网络通信加密分析](./prompt-examples/网络通信加密分析.md)
- [Root检测绕过分析](./prompt-examples/Root检测绕过分析.md)
- [SSL证书固定绕过](./prompt-examples/SSL证书固定绕过.md)
- [应用加壳脱壳分析](./prompt-examples/应用加壳脱壳分析.md)
- [恶意软件行为分析](./prompt-examples/恶意软件行为分析.md)

## 🆘 常见问题

### 1) 想要最省事启动

```bash
npm run setup
npm start
```

如果能启动，就不需要先跑 `check/smoke/verify`。

### 2) `npm start` 提示缺少 `adb` / `aapt`

先执行：
```bash
npm run check
```
然后按输出提示设置 `ANDROID_HOME` 或 `ADB_PATH` / `AAPT_PATH`。

### 3) `jadx` 缺失

- 保持 `AUTO_DOWNLOAD_JADX=true`，首次启动会自动下载
- 或手动安装后设置 `JADX_PATH`
- 如需固定下载源，设置 `JADX_DOWNLOAD_URL`

### 4) 客户端连不上 MCP

- 确认 `args` 是绝对路径且指向 `scripts/start.js`
- 确认 `cwd` 指向项目根目录
- 先运行 `npm run verify` 排除服务端问题

### 5) 设备显示 `unauthorized`

```bash
adb devices
```
在手机上确认 USB 调试授权后重试。

## 🔐 合规说明

- 仅用于合法授权的安全测试与研究
- 请遵守所在地法律法规与组织合规要求
- 禁止用于未授权目标或恶意用途
