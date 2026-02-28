# SSL证书固定安全评估（静态+运行验证）

## 说明
当前工具集不提供运行时注入绕过能力。本模板用于识别证书固定实现与潜在错误配置，并给出测试与修复建议。

## 输入
- APK路径：`/path/to/app.apk`

## 执行步骤
1. `aapt_dump_badging`：确认应用与SDK信息。
2. `aapt_dump_xmltree`：检查 `networkSecurityConfig` 与证书相关配置。
3. `jadx_decompile_apk` + `jadx_get_info`：定位网络库与证书校验逻辑。
4. `static_scan_secrets`：识别内置证书、公钥、指纹常量。
5. `static_scan_weak_crypto`：检查不安全TLS/加密实现。
6. `adb_start_app` + `adb_screenshot`：记录可见错误提示和连接行为。

## 检查清单
- [ ] 是否存在硬编码证书指纹/公钥
- [ ] 是否存在自定义 TrustManager/HostnameVerifier
- [ ] 是否存在信任所有证书或关闭校验的实现
- [ ] 是否存在明文HTTP回退逻辑

## 输出
- 证书固定实现位置与证据
- 风险评级与影响评估
- 面向研发的修复建议（证书轮换、校验策略、异常处理）
