# 登录验证逻辑Hook分析

目标：Hook并分析APP的密码验证机制

## 目标APP
- **包名**：`com.banking.app`
- **APK文件**：`/path/to/banking.apk`（二选一）

## Hook任务

### 1. 定位验证逻辑
- 搜索登录相关Activity/Fragment
- 找到密码验证方法（login、authenticate、verify等）
- 分析验证参数和返回值

### 2. Hook关键函数
- Hook密码输入处理函数
- Hook网络请求发送函数
- Hook验证结果处理函数
- Hook加密/哈希算法函数

### 3. 数据提取
- 捕获用户输入的明文密码
- 拦截加密后的密码数据
- 记录验证请求和响应
- 分析验证失败的返回码

### 4. 绕过尝试
- 修改验证结果为成功
- 跳过验证逻辑直接进入主界面
- 测试万能密码或默认凭据

## 脚本要求
- 包含完整Frida JavaScript代码
- 添加详细日志输出
- 支持动态开关Hook功能
- 包含错误处理机制

## 验证步骤
- 正常登录流程测试
- 错误密码Hook测试  
- 绕过验证成功确认

## 执行检查清单
- [ ] 使用 `adb_devices` 确认设备连接
- [ ] 使用 `aapt_analyze_apk` 获取基本信息
- [ ] 使用 `jadx_decompile_apk` 反编译源码
- [ ] 搜索登录相关类：`Login`, `Auth`, `Verify`, `SignIn`
- [ ] 使用 `frida_list_processes` 找到目标进程
- [ ] 使用 `frida_attach_process` 连接进程
- [ ] 使用 `frida_hook_method` Hook关键方法
- [ ] 使用 `adb_screenshot` 记录登录界面
- [ ] 使用 `frida_save_logs` 保存Hook日志

## 常见Hook目标
- **Android系统类**：
  - `android.widget.EditText.getText()`
  - `java.net.HttpURLConnection`
  - `javax.crypto.Cipher`
  
- **常见验证方法**：
  - `*.login()`, `*.authenticate()`, `*.verify()`
  - `*.checkPassword()`, `*.validateUser()`
  - `*.doLogin()`, `*.performLogin()`

## 示例Hook代码结构
```javascript
Java.perform(function() {
    // Hook密码输入
    var EditText = Java.use("android.widget.EditText");
    EditText.getText.implementation = function() {
        var result = this.getText();
        console.log("[+] 密码输入: " + result);
        return result;
    };
    
    // Hook验证方法
    var LoginClass = Java.use("com.app.LoginActivity");
    LoginClass.authenticate.implementation = function(username, password) {
        console.log("[+] 验证尝试: " + username + " / " + password);
        var result = this.authenticate(username, password);
        console.log("[+] 验证结果: " + result);
        return true; // 强制返回成功
    };
});
```