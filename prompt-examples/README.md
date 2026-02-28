# 📋 Prompt 示例库

本目录提供基于当前 MCP 能力（ADB / AAPT / JADX / 静态扫描）的可执行模板。

## 📁 可用示例

### 🔍 综合测试
- **[SECURITY_TESTING_PROMPT](./SECURITY_TESTING_PROMPT.md)** - 端到端安全测试通用模板

### 📦 APK静态与逆向
- **[网络通信加密分析](./网络通信加密分析.md)** - 网络与加密实现风险识别
- **[应用加壳脱壳分析](./应用加壳脱壳分析.md)** - 加壳识别与反编译可行性评估
- **[静态代码安全分析](./静态代码安全分析.md)** - 源码安全扫描模板

### 🧪 运行行为与专项评估
- **[恶意软件行为分析](./恶意软件行为分析.md)** - 可疑行为与证据留存分析
- **[SSL证书固定绕过](./SSL证书固定绕过.md)** - 证书固定安全评估模板
- **[Root检测绕过分析](./Root检测绕过分析.md)** - Root检测机制识别与鲁棒性评估
- **[密码验证Hook分析](./密码验证Hook分析.md)** - 密码验证逻辑分析（静态+ADB流程）

## 🚀 使用方法
1. 选择模板并替换目标参数（APK路径、包名等）。
2. 将模板内容发给已接入本 MCP 的助手执行。
3. 按输出报告中的高风险项逐条复核与修复。

## 🧩 建议工作顺序
1. `adb_list_devices` / `adb_list_packages`
2. `aapt_*` 系列（badging/permissions/xml）
3. `jadx_*` 系列（validate/decompile/info）
4. `static_*` 系列（secrets/debug/crypto/comprehensive）
5. `file_sha256` 与必要的 `adb_pull_file_advanced` 做证据固化

## ⚠️ 免责声明
模板仅用于合法授权的安全测试与研究。请遵守法律法规与组织合规要求。
