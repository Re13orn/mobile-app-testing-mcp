# Root检测机制识别与安全评估

## 说明
当前工具集不提供运行时绕过注入能力。本模板用于定位Root检测逻辑并评估其鲁棒性与误报风险。

## 输入
- APK路径：`/path/to/app.apk`

## 执行步骤
1. `aapt_dump_badging`：确认应用基础属性。
2. `jadx_decompile_apk`：反编译源码。
3. `jadx_get_info`：定位安全/检测相关包与类。
4. `static_scan_secrets`：查找 root/su/magisk/zygisk 等关键字线索。
5. `static_scan_debug_leaks`：查找检测结果日志输出。
6. `static_comprehensive_analysis`：汇总风险。
7. `adb_start_app` + `adb_screenshot`：记录检测触发界面。

## 检查清单
- [ ] 是否只做简单路径检测（`/system/xbin/su` 等）
- [ ] 是否存在单点判断导致易绕过
- [ ] 是否在客户端本地直接阻断关键流程
- [ ] 是否将检测结果安全上报并做服务端校验

## 输出
- Root检测点清单（类/方法/证据）
- 误报风险与绕过面评估
- 强化建议（多维检测、完整性校验、服务端联防）
