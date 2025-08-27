# SSL证书固定绕过分析

协助分析APP的SSL证书固定机制并实现绕过：

## 目标应用
- **包名**：`com.bank.mobile`
- **场景**：需要抓包分析HTTPS流量

## 绕过策略

### 1. 证书固定检测
- 搜索证书固定相关代码
- 定位TrustManager实现
- 检查证书验证逻辑

### 2. Hook点识别
- `javax.net.ssl.TrustManager`
- `okhttp3.CertificatePinner`
- 自定义证书验证函数

### 3. 绕过脚本编写
- 禁用证书固定检查
- 信任所有证书
- Hook SSL握手过程

### 4. 抓包配置
- 配合Charles/Burp使用
- 验证HTTPS流量解密
- 测试API接口访问

## 脚本功能
- 通用SSL Pinning绕过
- 支持多种实现方式
- 动态开关控制
- 详细日志记录

## 执行检查清单
- [ ] 使用 `adb_devices` 确认设备连接
- [ ] 使用 `jadx_decompile_apk` 反编译源码
- [ ] 搜索证书相关类：`TrustManager`, `CertificatePinner`, `X509Certificate`
- [ ] 配置代理工具（Charles/Burp Suite）
- [ ] 使用 `frida_attach_process` 连接进程
- [ ] 使用 `frida_hook_class` Hook SSL相关类
- [ ] 测试HTTPS请求是否能正常抓包
- [ ] 使用 `frida_save_logs` 保存绕过日志

## 常见证书固定实现

### 1. 系统默认TrustManager
```java
TrustManagerFactory.getInstance("X509").getTrustManagers()
```

### 2. OkHttp证书固定
```java
CertificatePinner certificatePinner = new CertificatePinner.Builder()
    .add("example.com", "sha256/...")
    .build();
```

### 3. 自定义TrustManager
```java
public void checkServerTrusted(X509Certificate[] chain, String authType)
```

## 绕过脚本示例

### 通用SSL Pinning绕过
```javascript
Java.perform(function() {
    console.log("[+] 开始SSL证书固定绕过...");
    
    // Hook TrustManager
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    
    TrustManager.checkServerTrusted.implementation = function(chain, authType) {
        console.log("[+] 绕过TrustManager证书检查");
    };
    
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log("[+] 绕过TrustManagerImpl证书链验证");
        return untrustedChain;
    };
    
    // Hook OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] 绕过OkHttp证书固定: " + hostname);
        };
    } catch (e) {
        console.log("[-] OkHttp CertificatePinner未找到");
    }
    
    // Hook HostnameVerifier
    var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    HostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
        console.log("[+] 绕过主机名验证: " + hostname);
        return true;
    };
    
    console.log("[+] SSL证书固定绕过已激活");
});
```

## 验证步骤
1. **启动代理工具**（Charles/Burp Suite）
2. **配置设备代理**设置
3. **安装代理证书**到设备
4. **运行Frida脚本**
5. **启动目标APP**
6. **验证HTTPS流量**是否能正常抓取

## 注意事项
- 确保代理工具证书已正确安装
- 某些APP可能有多层证书验证
- 注意检查native层的证书固定
- 测试时注意保护敏感数据