# Root检测绕过分析

请帮我分析并绕过目标APP的Root检测机制：

## 目标信息
- **APP包名**：`com.example.secure`
- **APK路径**：`/path/to/secure.apk`（二选一）

## 分析要求

### 1. 静态分析阶段
- 反编译APK，搜索常见Root检测关键词
- 定位Root检测相关类和方法
- 分析检测逻辑（su文件、Superuser包、busybox等）

### 2. 动态分析阶段
- Hook常见Root检测API（Runtime.exec、File.exists等）
- 监控系统属性读取（ro.build.tags、ro.debuggable等）
- 拦截native层检测函数

### 3. 绕过脚本生成
- 提供完整的Frida脚本
- 包含所有发现的检测点
- 添加详细注释说明

### 4. 验证测试
- 在Root设备上测试绕过效果
- 截图证明绕过成功

## 预期输出
- Root检测点清单
- 完整Frida绕过脚本
- 测试验证截图
- 绕过成功确认

## 执行检查清单
- [ ] 使用 `adb_devices` 确认设备连接
- [ ] 使用 `aapt_analyze_apk` 获取基本信息  
- [ ] 使用 `jadx_decompile_apk` 反编译源码
- [ ] 搜索Root检测关键词：`su`, `busybox`, `superuser`, `magisk`
- [ ] 使用 `frida_attach_process` 连接目标进程
- [ ] 使用 `frida_hook_class` Hook关键检测类
- [ ] 使用 `adb_screenshot` 记录测试过程
- [ ] 使用 `frida_save_logs` 保存分析结果

## 常见Root检测点
- 文件系统检查：`/system/bin/su`, `/system/xbin/su`
- 包名检查：`com.noshufou.android.su`, `eu.chainfire.supersu`
- 系统属性检查：`ro.build.tags`, `ro.debuggable`
- Native层检查：通过JNI调用检测
- 动态加载检测：检查Xposed、Substrate等框架