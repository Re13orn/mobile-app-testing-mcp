# 密码验证逻辑分析（静态 + ADB流程）

## 说明
当前工具集不提供Hook注入。本模板通过源码审计与界面流程验证分析密码校验实现。

## 输入
- APK路径：`/path/to/app.apk`
- 目标包名：`com.example.app`

## 执行步骤
1. `jadx_decompile_apk`：获取源码。
2. `jadx_get_info`：定位登录模块与认证相关包。
3. `static_scan_secrets`：检查硬编码测试账号、后门口令、固定Token。
4. `static_scan_weak_crypto`：检查密码处理中的弱哈希/不安全加密。
5. `static_scan_debug_leaks`：检查密码/Token日志泄露。
6. `adb_start_app`：启动应用到登录页。
7. `adb_screenshot`：记录登录前后页面状态。
8. `adb_input_text` + `adb_tap`：执行错误凭据/边界输入测试。
9. `adb_shell_command`：采集异常输出和系统反馈。

## 检查清单
- [ ] 是否存在客户端本地明文/弱哈希校验
- [ ] 是否存在可被重放的静态凭据
- [ ] 是否存在敏感日志泄露
- [ ] 异常处理是否泄露内部实现细节

## 输出
- 认证链路结构（输入→处理→校验→反馈）
- 高风险问题及证据
- 修复建议（服务端校验、强哈希、日志脱敏、错误处理收敛）
