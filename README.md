# 📱 移动端App测试MCP

一个基于 Model Context Protocol (MCP) 的移动应用测试工具，集成了 Frida、ADB、AAPT、JADX 等工具，为移动应用安全测试提供完整解决方案。

## 🚀 快速安装

### 前置要求

- **Node.js** 18.0+
- **Android SDK** (包含 ADB 和 AAPT)
- **Frida** 服务器 (可选)
- **JADX** 反编译工具 (可选)

### 安装步骤

```bash
# 1. 克隆项目
git clone https://github.com/your-username/mobile-app-testing-mcp.git
cd mobile-app-testing-mcp

# 2. 运行自动安装脚本
npm run setup

# 或手动安装:
# npm install
# npm run build

# 3. 检查环境依赖
npm run check

# 4. 启动 MCP 服务器
npm start
```

## ⚙️ MCP 配置

### Claude Desktop 配置

在 Claude Desktop 的 MCP 配置文件中添加：

**配置文件位置：**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/claude/claude_desktop_config.json`

### 基本配置 (推荐)

```json
{
  "mcpServers": {
    "mobile-app-testing": {
      "command": "node",
      "args": ["/path/to/your/project/dist/index.js"],
      "env": {}
    }
  }
}
```

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

## ✅ 使用前必须配置

### 1. Android SDK (必需)
```bash
# 下载并安装 Android SDK 或 Android Studio
# https://developer.android.com/studio

# 设置环境变量 (添加到 ~/.bashrc 或 ~/.zshrc)
export ANDROID_HOME=/path/to/android/sdk
export PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/build-tools/latest

# 验证安装
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
npm run setup  # 自动安装缺失组件
```

**手动安装**:
- **JADX** (反编译): `brew install jadx`
- **Frida** (动态分析): `pip install frida-tools`

## 📋 可用工具

MCP 服务器提供以下工具类别：

### 📱 ADB 工具 (12个)
- 设备管理、应用操作、文件传输、UI自动化

### 🔗 Frida 工具 (24个)
- 动态分析、进程附加、Hook注入、内存操作

### 📦 AAPT 工具 (4个)
- APK信息分析、权限检查、资源分析

### 🔍 JADX 工具 (3个)
- APK反编译、源码分析、项目统计

### 🔒 静态安全分析工具 (4个) ⭐ **新增**
- 硬编码敏感信息扫描、调试信息泄露检测
- 弱加密算法识别、综合安全分析

### 🤖 工作流工具 (4个)
- 智能建议、进度分析、模板管理

### 🛠️ Gadget 工具 (3个)
- 自动部署、状态检查、非Root环境支持

### 🔐 文件工具 (1个)
- SHA256哈希计算、文件完整性验证

## ⚡ 三步启动

```bash
# 1. 检查环境
npm run check

# 2. 配置Android SDK路径 (如果检查失败)
export ANDROID_HOME=/path/to/android/sdk

# 3. 启动服务
npm start
```

## 💡 基本使用

配置完成后，在 Claude Desktop 中即可使用：

```
分析这个APK文件的基本信息：/path/to/app.apk

请帮我反编译这个APK：com.example.app

对连接的Android设备进行截图
```

## 📋 高级用法示例

查看 **[prompt-examples](./prompt-examples/)** 目录，包含详细的使用示例：

- 🔍 **[静态代码安全分析](./prompt-examples/静态代码安全分析.md)** - 全面代码安全扫描 ⭐ **新增**
- 🔓 **[Root检测绕过](./prompt-examples/Root检测绕过分析.md)** - 自动分析并绕过Root检测
- 🔑 **[密码验证Hook](./prompt-examples/密码验证Hook分析.md)** - Hook登录验证逻辑  
- 🌐 **[网络加密分析](./prompt-examples/网络通信加密分析.md)** - 分析通信加密机制
- 🔒 **[SSL证书绕过](./prompt-examples/SSL证书固定绕过.md)** - 绕过证书固定抓包
- 📦 **[应用脱壳](./prompt-examples/应用加壳脱壳分析.md)** - 加壳应用动态脱壳
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