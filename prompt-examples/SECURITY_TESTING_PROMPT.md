# 移动应用安全测试通用 Prompt（ADB + AAPT + JADX）

请使用 `mobile-app-testing-mcp` 对目标应用执行一次完整安全测试，严格按步骤输出过程与结论。

## 目标信息
- APK路径：`/path/to/target.apk`
- 设备目标包名（如已安装）：`com.example.app`
- 测试重点：权限配置、组件暴露、敏感信息、弱加密、运行行为留证

## 执行流程
1. `adb_list_devices`：确认设备连接。
2. `adb_list_packages`：确认目标包是否已安装。
3. `aapt_dump_badging`：提取包名、版本、SDK、debuggable状态。
4. `aapt_dump_permissions`：分析权限申请与风险。
5. `aapt_dump_xmltree`（`AndroidManifest.xml`）：检查组件导出与清单配置。
6. `jadx_validate_apk`：验证APK完整性。
7. `jadx_decompile_apk`：反编译APK。
8. `jadx_get_info`：获取反编译目录结构与统计。
9. `static_scan_secrets`：扫描硬编码敏感信息。
10. `static_scan_debug_leaks`：扫描调试日志泄露。
11. `static_scan_weak_crypto`：扫描弱加密用法。
12. `static_comprehensive_analysis`：输出综合静态风险视图。
13. `adb_start_app` + `adb_screenshot`：记录应用运行态证据。
14. 如需文件证据，使用 `adb_pull_file_advanced` 拉取后调用 `file_sha256` 固化哈希。
15. 使用 `workflow_analyze_context` 与 `workflow_get_smart_suggestions` 检查遗漏项。

## 输出要求
- 先给“高风险问题 Top 5”（按严重度排序）。
- 每条问题包含：风险描述、证据（工具与关键输出）、影响范围、修复建议。
- 附“测试覆盖摘要”：
  - 已执行工具列表
  - 已覆盖安全域（权限/组件/密钥/加密/运行态）
  - 未覆盖项与原因

## 质量要求
- 所有结论必须可追溯到工具输出。
- 不要编造动态Hook结果。
- 对不确定结论，明确标注“待人工复核”。
