# 🛡️ 移动App安全测试 Prompt

## 🎯 使用方法
将以下prompt直接提供给Claude使用：

---

```
请使用移动端App测试MCP工具对目标应用进行全面安全测试。

**测试目标**: [包名: com.example.app 或 APK路径: /path/to/app.apk]

## 执行流程

### 阶段一：环境准备
1. `workflow_analyze_context` - 分析测试上下文
2. `adb_list_devices` - 检查设备连接
3. `frida_list_devices` + `frida_diagnose_environment` - 检查Frida环境
4. `adb_list_packages` - 检查App安装状态
5. 如需要：`adb_install_app` 安装APK

### 阶段二：静态分析
6. `jadx_validate_apk` - 验证APK完整性
7. `aapt_analyze_apk` - APK信息分析
8. `jadx_decompile_apk` - 反编译源代码
9. 重点检查：debuggable、allowBackup、exported组件、敏感权限

### 阶段三：动态测试
10. `adb_start_app` + `adb_screenshot` - 启动App并截图
11. 测试导出组件：
    - Activity: `adb_shell_command "am start -n ..."`
    - Service: `adb_shell_command "am startservice ..."`
    - Provider: `adb_shell_command "content query ..."`
12. 每次测试后截图验证

### 阶段四：运行时分析
13. `frida_attach` - 附加进程（失败则用`frida_deploy_gadget`）
14. `frida_batch_hook` - Hook敏感API（网络、加密、文件IO）
15. `frida_memory_search` - 搜索内存敏感数据
16. `frida_realtime_logs` - 监控实时日志

### 阶段五：数据收集
17. `adb_pull_file_advanced` - 提取App数据
18. `frida_save_logs` - 保存Hook日志
19. 生成安全测试报告

## 报告格式
```
# 安全测试报告
## 基本信息
- 应用: [名称] ([包名])  
- 版本: [版本号]
- sha256: [SHA256]
- 测试时间: [时间]

## 发现问题
### 🔴 高风险
[问题列表 + 截图]

### 🟡 中风险  
[问题列表]

### 🟢 低风险
[问题列表]

## 修复建议
[具体建议]
```

**要求**: 每步骤要有执行结果，遇错误提供解决方案，重要发现要截图证明。
```

---

## 💡 常见错误处理

- **设备未连接** → 检查USB调试和ADB权限
- **Frida未运行** → 启动frida-server并检查权限  
- **Hook失败** → 尝试Gadget模式或反调试绕过
- **组件测试失败** → 记录错误继续其他测试