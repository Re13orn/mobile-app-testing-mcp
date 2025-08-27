import * as frida from 'frida';
import { randomUUID } from 'crypto';
import { globalLogger, LogEntry } from './logger.js';
import { globalConnectionManager } from './connection-manager.js';

export interface FridaSession {
  id: string;
  session: frida.Session;
  process: frida.Process;
  scripts: Map<string, frida.Script>;
  logs: any[]; // 会话日志
  autoRecovery: boolean; // 自动恢复标志
}

export interface AttachResult {
  sessionId: string;
  process: {
    pid: number;
    name: string;
  };
}

export interface InjectResult {
  scriptId: string;
  sessionId: string;
}

export interface MemorySearchResult {
  addresses: string[];
  count: number;
}

export interface MemoryWriteResult {
  success: boolean;
  address: string;
  bytesWritten: number;
}

export interface ClassInfo {
  name: string;
  methods: number;
  fields?: number;
}

export interface MethodInfo {
  name: string;
  signature: string;
  address?: string;
}

export interface FunctionInfo {
  name: string;
  address: string;
  module: string;
}

// 扩展会话以包含日志管理
export interface FridaSession {
  id: string;
  session: frida.Session;
  process: frida.Process;
  scripts: Map<string, frida.Script>;
  logs: any[]; // Hook日志存储
  autoRecovery: boolean; // 自动恢复开关
}

export class FridaManager {
  private sessions: Map<string, FridaSession> = new Map();
  private currentSessionId: string | null = null;
  
  // 智能应用包名建议
  private async suggestPackageNames(target: string, device: frida.Device): Promise<string[]> {
    try {
      const processes = await device.enumerateProcesses();
      const suggestions: string[] = [];
      
      // 模糊匹配策略
      const targetLower = target.toLowerCase();
      
      for (const process of processes) {
        const processName = process.name.toLowerCase();
        
        // 1. 包含目标字符串
        if (processName.includes(targetLower)) {
          suggestions.push(process.name);
        }
        
        // 2. 反向包含（target包含进程名的部分）
        if (targetLower.includes(processName.split('.').pop() || '')) {
          suggestions.push(process.name);
        }
        
        // 3. 常见应用名模糊匹配
        if (targetLower.includes('test') && processName.includes('test')) {
          suggestions.push(process.name);
        }
      }
      
      // 去重并限制数量
      return [...new Set(suggestions)].slice(0, 5);
    } catch (error) {
      return [];
    }
  }

  async listProcesses(filter?: string, deviceId?: string): Promise<frida.Process[]> {
    try {
      let device: frida.Device;
      
      if (deviceId) {
        // 连接指定设备
        device = await frida.getDevice(deviceId);
      } else {
        // 默认获取USB设备，如果没有则使用本地设备
        const devices = await frida.enumerateDevices();
        const usbDevice = devices.find(d => d.type === 'usb');
        device = usbDevice || await frida.getLocalDevice();
      }
      
      const processes = await device.enumerateProcesses();
      
      if (!filter) {
        return processes;
      }
      
      return processes.filter((p: frida.Process) => 
        p.name.toLowerCase().includes(filter.toLowerCase())
      );
    } catch (error) {
      throw new Error(`无法列出进程: ${error}`);
    }
  }

  async attach(target: string, spawn: boolean = false, deviceId?: string): Promise<AttachResult> {
    try {
      console.log(`[Frida Attach] 开始附加到目标: ${target}, spawn: ${spawn}, deviceId: ${deviceId}`);
      
      // 第一步：获取设备
      let device: frida.Device;
      
      if (deviceId) {
        console.log(`[Frida Attach] 使用指定设备: ${deviceId}`);
        try {
          device = await frida.getDevice(deviceId);
        } catch (error) {
          throw new Error(`无法连接到设备 ${deviceId}: ${error}`);
        }
      } else {
        // 优先选择USB设备（手机），适用于移动应用测试
        console.log(`[Frida Attach] 枚举可用设备...`);
        const devices = await frida.enumerateDevices();
        console.log(`[Frida Attach] 找到 ${devices.length} 个设备:`, devices.map(d => `${d.name}(${d.type})`).join(', '));
        
        const usbDevice = devices.find(d => d.type === 'usb');
        device = usbDevice || await frida.getLocalDevice();
        
        console.log(`[Frida Attach] 使用设备: ${device.name} (${device.type})`);
      }
      
      // 第二步：验证设备连接
      try {
        console.log(`[Frida Attach] 测试设备连接...`);
        const testProcesses = await device.enumerateProcesses();
        console.log(`[Frida Attach] 设备连接正常，检测到 ${testProcesses.length} 个进程`);
      } catch (error) {
        throw new Error(`设备连接失败，可能需要启动 frida-server: ${error}`);
      }
      
      // 第三步：处理附加逻辑
      let session: frida.Session;
      let process: frida.Process;

      if (spawn) {
        // 启动新应用进程（适用于移动应用测试）
        console.log(`[Frida Attach] spawn 模式: 启动新进程 ${target}`);
        try {
          const pid = await device.spawn([target]);
          console.log(`[Frida Attach] 成功 spawn PID: ${pid}`);
          
          session = await device.attach(pid);
          console.log(`[Frida Attach] 成功附加到 PID: ${pid}`);
          
          await device.resume(pid);
          console.log(`[Frida Attach] 成功恢复进程: ${pid}`);
          
          // 获取进程信息
          const processes = await device.enumerateProcesses();
          process = processes.find((p: frida.Process) => p.pid === pid) || { pid, name: target } as frida.Process;
          console.log(`[Frida Attach] spawn 成功: ${target} (PID: ${pid})`);
        } catch (error) {
          throw new Error(`spawn 失败: ${error}. 请确认应用包名正确且应用已安装`);
        }
      } else {
        // 附加到现有进程
        const isNumeric = /^\d+$/.test(target);
        console.log(`[Frida Attach] attach 模式: 目标 ${target} (是否为PID: ${isNumeric})`);
        
        if (isNumeric) {
          // 按PID附加
          const pid = parseInt(target, 10);
          console.log(`[Frida Attach] 尝试附加到 PID: ${pid}`);
          
          try {
            session = await device.attach(pid);
            console.log(`[Frida Attach] 成功附加到 PID: ${pid}`);
            
            // 查找进程信息
            const processes = await device.enumerateProcesses();
            process = processes.find((p: frida.Process) => p.pid === pid) || { pid, name: 'unknown' } as frida.Process;
          } catch (error) {
            throw new Error(`附加到 PID ${pid} 失败: ${error}. 请确认进程存在且有足够权限`);
          }
        } else {
          // 按应用名附加（移动应用通常按包名）
          console.log(`[Frida Attach] 尝试查找应用进程: ${target}`);
          
          try {
            // 智能重试机制：应用可能正在启动中
            let processes = await this.listProcesses(target, deviceId);
            console.log(`[Frida Attach] 首次搜索找到 ${processes.length} 个匹配的进程`);
            
            // 如果没找到进程，等待并重试（应用启动延迟）
            if (processes.length === 0) {
              console.log(`[Frida Attach] 进程未找到，等待应用启动完成...`);
              for (let retry = 0; retry < 3; retry++) {
                await new Promise(resolve => setTimeout(resolve, 2000)); // 等待2秒
                processes = await this.listProcesses(target, deviceId);
                console.log(`[Frida Attach] 重试 ${retry + 1}/3: 找到 ${processes.length} 个匹配进程`);
                if (processes.length > 0) break;
              }
            }
            
            if (processes.length === 0) {
              // 智能建议：尝试spawn模式
              console.log(`[Frida Attach] 尝试智能spawn模式启动应用: ${target}`);
              try {
                const pid = await device.spawn([target]);
                console.log(`[Frida Attach] 智能spawn成功，PID: ${pid}`);
                
                session = await device.attach(pid);
                await device.resume(pid);
                
                // 获取进程信息
                const spawnedProcesses = await device.enumerateProcesses();
                process = spawnedProcesses.find((p: frida.Process) => p.pid === pid) || { pid, name: target } as frida.Process;
                
                console.log(`[Frida Attach] 智能spawn+attach成功: ${target} (PID: ${pid})`);
              } catch (spawnError) {
                // 智能包名建议
                const suggestions = await this.suggestPackageNames(target, device);
                const allProcesses = await device.enumerateProcesses();
                const mobileApps = allProcesses.filter(p => 
                  p.name.includes('.') && 
                  !p.name.startsWith('com.android.') && 
                  !p.name.startsWith('system')
                ).slice(0, 10);
                
                let errorMessage = `未找到应用进程: ${target}\n\n` +
                  `已尝试以下方法:\n` +
                  `1. ✗ 附加到现有进程 - 进程不存在\n` +
                  `2. ✗ 智能spawn启动 - ${spawnError}\n\n` +
                  `建议解决方案:\n` +
                  `• 使用 adb_start_app 手动启动应用后再尝试\n` +
                  `• 检查包名是否正确: ${target}\n` +
                  `• 确认应用已安装且frida-server运行正常\n\n`;
                
                if (suggestions.length > 0) {
                  errorMessage += `🤖 智能建议的相似包名:\n` +
                    suggestions.map(name => `• ${name}`).join('\n') + '\n\n';
                }
                
                errorMessage += `当前可用的移动应用进程:\n` +
                  mobileApps.map(p => `• ${p.name} (PID: ${p.pid})`).join('\n') +
                  (mobileApps.length === 0 ? '无可用移动应用进程' : '');
                
                throw new Error(errorMessage);
              }
            } else {
              // 选择第一个匹配的进程
              process = processes[0];
              console.log(`[Frida Attach] 尝试附加到: ${process.name} (PID: ${process.pid})`);
              
              session = await device.attach(process.pid);
              console.log(`[Frida Attach] 成功附加到: ${process.name} (PID: ${process.pid})`);
            }
          } catch (error: any) {
            if (error instanceof Error && error.message.includes('未找到应用进程')) {
              throw error; // 重新抛出详细错误信息
            }
            throw new Error(`附加到应用 ${target} 失败: ${error}`);
          }
        }
      }

      const sessionId = randomUUID();
      const fridaSession: FridaSession = {
        id: sessionId,
        session,
        process,
        scripts: new Map(),
        logs: [], // 初始化日志数组
        autoRecovery: false, // 默认不开启自动恢复
      };

      // 设置会话事件监听
      session.detached.connect((reason: string) => {
        console.warn(`会话 ${sessionId} 已断开: ${reason}`);
        
        // 通知连接管理器
        globalConnectionManager.handleDisconnection(sessionId, reason);
        
        this.sessions.delete(sessionId);
        if (this.currentSessionId === sessionId) {
          this.currentSessionId = null;
        }
      });

      // 注册到连接管理器
      globalConnectionManager.registerConnection(sessionId, process.name, process.pid);

      this.sessions.set(sessionId, fridaSession);
      this.currentSessionId = sessionId;

      return {
        sessionId,
        process: {
          pid: process.pid,
          name: process.name,
        },
      };
    } catch (error) {
      console.error(`[Frida Attach] 附加失败:`, error);
      
      // 提供更友好的错误信息
      if (error instanceof Error) {
        throw error; // 保持原始错误信息
      }
      
      throw new Error(`附加进程失败: ${error}`);
    }
  }

  async injectScript(scriptCode: string, sessionId?: string): Promise<InjectResult> {
    const targetSessionId = sessionId || this.currentSessionId;
    
    if (!targetSessionId) {
      throw new Error('没有活动的会话，请先附加到进程');
    }

    const fridaSession = this.sessions.get(targetSessionId);
    if (!fridaSession) {
      throw new Error(`会话不存在: ${targetSessionId}`);
    }

    try {
      const script = await fridaSession.session.createScript(scriptCode);
      const scriptId = randomUUID();

      // 设置脚本消息处理
      script.message.connect((message: any) => {
        console.log(`[脚本 ${scriptId}] 消息:`, JSON.stringify(message, null, 2));
      });

      await script.load();
      fridaSession.scripts.set(scriptId, script);

      return {
        scriptId,
        sessionId: targetSessionId,
      };
    } catch (error) {
      throw new Error(`脚本注入失败: ${error}`);
    }
  }

  async detach(sessionId?: string): Promise<void> {
    if (sessionId) {
      // 分离指定会话
      const fridaSession = this.sessions.get(sessionId);
      if (!fridaSession) {
        throw new Error(`会话不存在: ${sessionId}`);
      }

      try {
        // 卸载所有脚本
        for (const script of fridaSession.scripts.values()) {
          await script.unload();
        }
        
        await fridaSession.session.detach();
        this.sessions.delete(sessionId);
        
        if (this.currentSessionId === sessionId) {
          this.currentSessionId = null;
        }
      } catch (error) {
        throw new Error(`分离会话失败: ${error}`);
      }
    } else {
      // 分离所有会话
      const detachPromises = Array.from(this.sessions.values()).map(async (fridaSession) => {
        try {
          for (const script of fridaSession.scripts.values()) {
            await script.unload();
          }
          await fridaSession.session.detach();
        } catch (error) {
          console.warn(`分离会话 ${fridaSession.id} 时出错:`, error);
        }
      });

      await Promise.allSettled(detachPromises);
      this.sessions.clear();
      this.currentSessionId = null;
    }
  }


  // 获取会话信息
  getSessionInfo(sessionId?: string): FridaSession | null {
    const targetSessionId = sessionId || this.currentSessionId;
    if (!targetSessionId) return null;
    
    return this.sessions.get(targetSessionId) || null;
  }

  // 获取所有会话
  getAllSessions(): FridaSession[] {
    return Array.from(this.sessions.values());
  }

  // 获取当前活动会话ID
  getCurrentSessionId(): string | null {
    return this.currentSessionId;
  }

  // 枚举可用设备（移动设备）
  async enumerateDevices(): Promise<frida.Device[]> {
    try {
      const devices = await frida.enumerateDevices();
      console.log(`[设备发现] 找到 ${devices.length} 个设备`);
      
      devices.forEach(device => {
        console.log(`[设备] ${device.name} (${device.type}) - ID: ${device.id}`);
      });
      
      return devices;
    } catch (error) {
      throw new Error(`枚举设备失败: ${error}`);
    }
  }

  // 获取设备应用列表
  async enumerateApplications(deviceId?: string): Promise<frida.Application[]> {
    try {
      let device: frida.Device;
      
      if (deviceId) {
        device = await frida.getDevice(deviceId);
      } else {
        const devices = await frida.enumerateDevices();
        const usbDevice = devices.find(d => d.type === 'usb');
        device = usbDevice || await frida.getLocalDevice();
      }
      
      const applications = await device.enumerateApplications();
      console.log(`[应用发现] 在设备 ${device.name} 上找到 ${applications.length} 个应用`);
      
      return applications;
    } catch (error) {
      throw new Error(`枚举应用失败: ${error}`);
    }
  }

  // ===== 高级内存操作 =====
  
  async memorySearch(pattern: string, type: 'hex' | 'string' | 'utf8' | 'utf16' = 'string', sessionId?: string): Promise<MemorySearchResult> {
    const targetSessionId = sessionId || this.currentSessionId;
    if (!targetSessionId) {
      throw new Error('没有活动的会话，请先附加到进程');
    }

    const fridaSession = this.sessions.get(targetSessionId);
    if (!fridaSession) {
      throw new Error(`会话不存在: ${targetSessionId}`);
    }

    try {
      const searchScript = `
        function memorySearch(pattern, type) {
          var results = [];
          
          // 获取不同类型的内存区域进行搜索
          var searchRanges = [];
          
          // 策略1: 搜索可读写内存区域（数据段）
          var rwRanges = Process.enumerateRanges('rw-');
          searchRanges = searchRanges.concat(rwRanges.slice(0, 50)); // 限制数量避免性能问题
          
          // 策略2: 搜索只读内存区域（代码段、常量）
          var roRanges = Process.enumerateRanges('r--');
          searchRanges = searchRanges.concat(roRanges.slice(0, 30));
          
          // 策略3: 搜索可执行内存区域（某些数据可能在代码段）
          var rxRanges = Process.enumerateRanges('r-x');
          searchRanges = searchRanges.concat(rxRanges.slice(0, 20));
          
          console.log('[内存搜索] 总共搜索 ' + searchRanges.length + ' 个内存区域');
          
          for (var i = 0; i < searchRanges.length; i++) {
            try {
              var range = searchRanges[i];
              
              // 跳过过小或过大的内存区域
              if (range.size < 4 || range.size > 1024 * 1024 * 100) continue;
              
              var scanResult = null;
              
              if (type === 'hex') {
                // 十六进制搜索
                try {
                  var cleanHex = pattern.replace(/[\\s-]/g, '').toUpperCase();
                  if (cleanHex.length % 2 !== 0) cleanHex = '0' + cleanHex;
                  
                  var hexBytes = [];
                  for (var h = 0; h < cleanHex.length; h += 2) {
                    hexBytes.push(cleanHex.substr(h, 2));
                  }
                  var hexPattern = hexBytes.join(' ');
                  scanResult = Memory.scanSync(range.base, range.size, hexPattern);
                } catch (hexError) {
                  continue;
                }
              } else if (type === 'string') {
                // ASCII字符串搜索 - 转换为字节数组
                try {
                  var stringBytes = [];
                  for (var s = 0; s < pattern.length; s++) {
                    var byte = pattern.charCodeAt(s);
                    if (byte > 255) byte = 63; // 替换为'?'
                    stringBytes.push(('0' + byte.toString(16)).slice(-2));
                  }
                  var stringPattern = stringBytes.join(' ');
                  scanResult = Memory.scanSync(range.base, range.size, stringPattern);
                } catch (stringError) {
                  // 备用方案：直接搜索字符串
                  try {
                    scanResult = Memory.scanSync(range.base, range.size, pattern);
                  } catch (e2) {
                    continue;
                  }
                }
              } else if (type === 'utf8') {
                // UTF-8搜索 - 完整实现
                try {
                  var utf8Bytes = [];
                  for (var j = 0; j < pattern.length; j++) {
                    var code = pattern.charCodeAt(j);
                    if (code < 0x80) {
                      utf8Bytes.push(code);
                    } else if (code < 0x800) {
                      utf8Bytes.push(0xC0 | (code >> 6));
                      utf8Bytes.push(0x80 | (code & 0x3F));
                    } else if (code < 0x10000) {
                      utf8Bytes.push(0xE0 | (code >> 12));
                      utf8Bytes.push(0x80 | ((code >> 6) & 0x3F));
                      utf8Bytes.push(0x80 | (code & 0x3F));
                    }
                  }
                  var utf8Pattern = utf8Bytes.map(function(b) { 
                    return ('0' + b.toString(16)).slice(-2); 
                  }).join(' ');
                  scanResult = Memory.scanSync(range.base, range.size, utf8Pattern);
                } catch (utf8Error) {
                  continue;
                }
              } else if (type === 'utf16') {
                // UTF-16搜索（小端序）
                try {
                  var utf16Bytes = [];
                  for (var k = 0; k < pattern.length; k++) {
                    var code = pattern.charCodeAt(k);
                    // 小端序UTF-16
                    utf16Bytes.push(code & 0xFF);
                    utf16Bytes.push((code >> 8) & 0xFF);
                  }
                  var utf16Pattern = utf16Bytes.map(function(b) { 
                    return ('0' + b.toString(16)).slice(-2); 
                  }).join(' ');
                  scanResult = Memory.scanSync(range.base, range.size, utf16Pattern);
                  
                  // 同时尝试大端序
                  if (!scanResult || scanResult.length === 0) {
                    var utf16BeBytes = [];
                    for (var l = 0; l < pattern.length; l++) {
                      var code2 = pattern.charCodeAt(l);
                      // 大端序UTF-16
                      utf16BeBytes.push((code2 >> 8) & 0xFF);
                      utf16BeBytes.push(code2 & 0xFF);
                    }
                    var utf16BePattern = utf16BeBytes.map(function(b) { 
                      return ('0' + b.toString(16)).slice(-2); 
                    }).join(' ');
                    var scanResult2 = Memory.scanSync(range.base, range.size, utf16BePattern);
                    if (scanResult2 && scanResult2.length > 0) {
                      scanResult = scanResult2;
                    }
                  }
                } catch (utf16Error) {
                  continue;
                }
              }
              
              if (scanResult && scanResult.length > 0) {
                scanResult.forEach(function(match) {
                  results.push({
                    address: match.address.toString(),
                    range: {
                      base: range.base.toString(),
                      size: range.size,
                      protection: range.protection,
                      file: range.file ? range.file.path : null
                    }
                  });
                });
                
                console.log('[内存搜索] 在 ' + range.base + ' 找到 ' + scanResult.length + ' 个结果');
              }
            } catch (e) {
              // 忽略无法读取的内存区域，继续搜索其他区域
              continue;
            }
            
            // 限制总结果数量
            if (results.length > 200) {
              console.log('[内存搜索] 达到结果上限，停止搜索');
              break;
            }
          }
          
          console.log('[内存搜索] 搜索完成，共找到 ' + results.length + ' 个结果');
          
          return {
            addresses: results.map(function(r) { return r.address; }),
            details: results,
            count: results.length,
            searchType: type,
            pattern: pattern
          };
        }
        
        var result = memorySearch('${pattern.replace(/'/g, "\\'")}', '${type}');
        send(result);
      `;

      const script = await fridaSession.session.createScript(searchScript);
      
      return new Promise((resolve, reject) => {
        script.message.connect((message: any) => {
          if (message.type === 'send') {
            resolve(message.payload);
          } else if (message.type === 'error') {
            reject(new Error(message.description));
          }
        });

        script.load().catch(reject);
      });
    } catch (error) {
      throw new Error(`内存搜索失败: ${error}`);
    }
  }

  async memoryWrite(address: string, data: string, sessionId?: string): Promise<MemoryWriteResult> {
    const targetSessionId = sessionId || this.currentSessionId;
    if (!targetSessionId) {
      throw new Error('没有活动的会话，请先附加到进程');
    }

    const fridaSession = this.sessions.get(targetSessionId);
    if (!fridaSession) {
      throw new Error(`会话不存在: ${targetSessionId}`);
    }

    try {
      const writeScript = `
        function memoryWrite(address, hexData) {
          try {
            var addr = ptr('${address}');
            var bytes = hexData.replace(/\\s+/g, '').match(/.{2}/g).map(h => parseInt(h, 16));
            Memory.writeByteArray(addr, bytes);
            return {
              success: true,
              address: address,
              bytesWritten: bytes.length
            };
          } catch (e) {
            return {
              success: false,
              address: address,
              bytesWritten: 0,
              error: e.message
            };
          }
        }
        
        var result = memoryWrite('${address}', '${data}');
        send(result);
      `;

      const script = await fridaSession.session.createScript(writeScript);
      
      return new Promise((resolve, reject) => {
        script.message.connect((message: any) => {
          if (message.type === 'send') {
            resolve(message.payload);
          } else if (message.type === 'error') {
            reject(new Error(message.description));
          }
        });

        script.load().catch(reject);
      });
    } catch (error) {
      throw new Error(`内存写入失败: ${error}`);
    }
  }

  // ===== 类和方法枚举 =====

  async enumerateClasses(filter?: string, sessionId?: string): Promise<ClassInfo[]> {
    const targetSessionId = sessionId || this.currentSessionId;
    if (!targetSessionId) {
      throw new Error('没有活动的会话，请先附加到进程');
    }

    const fridaSession = this.sessions.get(targetSessionId);
    if (!fridaSession) {
      throw new Error(`会话不存在: ${targetSessionId}`);
    }

    try {
      const enumScript = `
        function enumerateClasses(filter) {
          var classes = [];
          
          if (Java.available) {
            // Android Java类枚举
            Java.perform(function() {
              Java.enumerateLoadedClasses({
                onMatch: function(className) {
                  if (!filter || className.toLowerCase().includes(filter.toLowerCase())) {
                    try {
                      var clazz = Java.use(className);
                      var methods = clazz.class.getDeclaredMethods();
                      classes.push({
                        name: className,
                        methods: methods.length,
                        type: 'Java'
                      });
                    } catch (e) {
                      // 忽略无法访问的类
                    }
                  }
                },
                onComplete: function() {}
              });
            });
          }
          
          if (ObjC.available) {
            // iOS Objective-C类枚举
            var objcClasses = Object.keys(ObjC.classes);
            objcClasses.forEach(function(className) {
              if (!filter || className.toLowerCase().includes(filter.toLowerCase())) {
                try {
                  var clazz = ObjC.classes[className];
                  var methods = clazz.$methods;
                  classes.push({
                    name: className,
                    methods: methods.length,
                    type: 'ObjC'
                  });
                } catch (e) {
                  // 忽略错误
                }
              }
            });
          }
          
          return classes.slice(0, 50); // 限制返回数量
        }
        
        var result = enumerateClasses('${filter || ''}');
        send(result);
      `;

      const script = await fridaSession.session.createScript(enumScript);
      
      return new Promise((resolve, reject) => {
        script.message.connect((message: any) => {
          if (message.type === 'send') {
            resolve(message.payload);
          } else if (message.type === 'error') {
            reject(new Error(message.description));
          }
        });

        script.load().catch(reject);
      });
    } catch (error) {
      throw new Error(`类枚举失败: ${error}`);
    }
  }

  async enumerateMethods(className: string, sessionId?: string): Promise<MethodInfo[]> {
    const targetSessionId = sessionId || this.currentSessionId;
    if (!targetSessionId) {
      throw new Error('没有活动的会话，请先附加到进程');
    }

    const fridaSession = this.sessions.get(targetSessionId);
    if (!fridaSession) {
      throw new Error(`会话不存在: ${targetSessionId}`);
    }

    try {
      const enumScript = `
        function enumerateMethods(className) {
          var methods = [];
          
          if (Java.available) {
            // Java方法枚举
            Java.perform(function() {
              try {
                var clazz = Java.use(className);
                var javaMethods = clazz.class.getDeclaredMethods();
                
                for (var i = 0; i < javaMethods.length; i++) {
                  var method = javaMethods[i];
                  methods.push({
                    name: method.getName(),
                    signature: method.toString(),
                    type: 'Java'
                  });
                }
              } catch (e) {
                // 可能不是Java类，尝试ObjC
              }
            });
          }
          
          if (ObjC.available && methods.length === 0) {
            // Objective-C方法枚举
            try {
              var clazz = ObjC.classes[className];
              if (clazz) {
                var objcMethods = clazz.$methods;
                objcMethods.forEach(function(methodName) {
                  methods.push({
                    name: methodName,
                    signature: methodName,
                    type: 'ObjC'
                  });
                });
              }
            } catch (e) {
              // 忽略错误
            }
          }
          
          return methods;
        }
        
        var result = enumerateMethods('${className}');
        send(result);
      `;

      const script = await fridaSession.session.createScript(enumScript);
      
      return new Promise((resolve, reject) => {
        script.message.connect((message: any) => {
          if (message.type === 'send') {
            resolve(message.payload);
          } else if (message.type === 'error') {
            reject(new Error(message.description));
          }
        });

        script.load().catch(reject);
      });
    } catch (error) {
      throw new Error(`方法枚举失败: ${error}`);
    }
  }

  // ===== 函数地址查找 =====

  async findFunction(functionName: string, moduleName?: string, sessionId?: string): Promise<FunctionInfo[]> {
    const targetSessionId = sessionId || this.currentSessionId;
    if (!targetSessionId) {
      throw new Error('没有活动的会话，请先附加到进程');
    }

    const fridaSession = this.sessions.get(targetSessionId);
    if (!fridaSession) {
      throw new Error(`会话不存在: ${targetSessionId}`);
    }

    try {
      const findScript = `
        function findFunction(funcName, modName) {
          var results = [];
          
          // 策略1: 搜索导出函数
          function searchExports(module) {
            try {
              var addr = Module.findExportByName(module.name, funcName);
              if (addr) {
                results.push({
                  name: funcName,
                  address: addr.toString(),
                  module: module.name,
                  type: 'export'
                });
              }
            } catch (e) {}
          }
          
          // 策略2: 符号表搜索（包括调试符号）
          function searchSymbols(module) {
            try {
              var symbols = module.enumerateSymbols();
              symbols.forEach(function(symbol) {
                if (symbol.name && (symbol.name === funcName || symbol.name.indexOf(funcName) !== -1)) {
                  results.push({
                    name: symbol.name,
                    address: symbol.address.toString(),
                    module: module.name,
                    type: 'symbol',
                    symbolType: symbol.type
                  });
                }
              });
            } catch (e) {}
          }
          
          // 策略3: 导入表搜索
          function searchImports(module) {
            try {
              var imports = module.enumerateImports();
              imports.forEach(function(imp) {
                if (imp.name === funcName) {
                  results.push({
                    name: imp.name,
                    address: imp.address ? imp.address.toString() : 'unknown',
                    module: module.name,
                    type: 'import',
                    importModule: imp.module
                  });
                }
              });
            } catch (e) {}
          }
          
          // 策略4: 内存模式匹配（适用于常见函数如malloc, free等）
          function searchMemoryPattern(module) {
            try {
              // 仅对主要系统库进行模式搜索，避免性能问题
              var systemLibs = ['libc', 'libsystem', 'libobjc', 'libdyld', 'CoreFoundation', 'Foundation'];
              var isSystemLib = systemLibs.some(function(lib) {
                return module.name.toLowerCase().indexOf(lib.toLowerCase()) !== -1;
              });
              
              if (!isSystemLib) return;
              
              // 常见函数的特征模式
              var patterns = {
                'malloc': 'FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??',
                'free': 'FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??',
                'printf': '48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??',
                'strlen': '48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??'
              };
              
              if (patterns[funcName]) {
                var matches = Memory.scanSync(module.base, module.size, patterns[funcName]);
                matches.slice(0, 3).forEach(function(match, idx) { // 限制结果数量
                  results.push({
                    name: funcName + '_pattern_' + idx,
                    address: match.address.toString(),
                    module: module.name,
                    type: 'pattern'
                  });
                });
              }
            } catch (e) {}
          }
          
          if (modName) {
            // 在指定模块中查找
            var modules = Process.enumerateModules();
            var targetModule = modules.find(function(m) { 
              return m.name === modName || m.name.toLowerCase().indexOf(modName.toLowerCase()) !== -1;
            });
            
            if (targetModule) {
              searchExports(targetModule);
              searchSymbols(targetModule);
              searchImports(targetModule);
              searchMemoryPattern(targetModule);
            }
          } else {
            // 在所有模块中查找，优先搜索主要模块
            var modules = Process.enumerateModules();
            
            // 首先搜索主执行文件和主要系统库
            var priorityModules = modules.filter(function(m) {
              return m.name === Process.getCurrentDir() || 
                     m.name.indexOf('libc') !== -1 || 
                     m.name.indexOf('libsystem') !== -1 ||
                     m.name.indexOf('libobjc') !== -1 ||
                     m.name.indexOf('Foundation') !== -1 ||
                     m.name.indexOf('CoreFoundation') !== -1;
            });
            
            // 然后搜索其他模块
            var otherModules = modules.filter(function(m) {
              return !priorityModules.includes(m);
            });
            
            var allModules = priorityModules.concat(otherModules.slice(0, 20)); // 限制搜索的模块数量
            
            allModules.forEach(function(module) {
              searchExports(module);
              searchSymbols(module);
              searchImports(module);
              if (priorityModules.includes(module)) {
                searchMemoryPattern(module);
              }
            });
          }
          
          // 去重并排序
          var uniqueResults = [];
          var seen = new Set();
          
          results.forEach(function(result) {
            var key = result.address + '_' + result.name;
            if (!seen.has(key)) {
              seen.add(key);
              uniqueResults.push(result);
            }
          });
          
          return uniqueResults;
        }
        
        var result = findFunction('${functionName}', '${moduleName || ''}');
        send(result);
      `;

      const script = await fridaSession.session.createScript(findScript);
      
      return new Promise((resolve, reject) => {
        script.message.connect((message: any) => {
          if (message.type === 'send') {
            resolve(message.payload);
          } else if (message.type === 'error') {
            reject(new Error(message.description));
          }
        });

        script.load().catch(reject);
      });
    } catch (error) {
      throw new Error(`函数查找失败: ${error}`);
    }
  }

  // ===== 批量Hook =====

  async batchHook(targets: Array<{class_name: string, method_name: string, hook_type: 'log' | 'block' | 'modify'}>, sessionId?: string): Promise<{success: number, failed: number, details: any[]}> {
    const targetSessionId = sessionId || this.currentSessionId;
    if (!targetSessionId) {
      throw new Error('没有活动的会话，请先附加到进程');
    }

    const fridaSession = this.sessions.get(targetSessionId);
    if (!fridaSession) {
      throw new Error(`会话不存在: ${targetSessionId}`);
    }

    try {
      const batchScript = `
        function batchHook(targets) {
          var results = {
            success: 0,
            failed: 0,
            details: []
          };
          
          if (Java.available) {
            Java.perform(function() {
              targets.forEach(function(target) {
                try {
                  var clazz = Java.use(target.class_name);
                  var targetMethod = target.method_name;
                  var hooked = false;
                  
                  // 尝试多种方法Hook策略
                  
                  // 策略1: 直接Hook（适用于无重载方法）
                  try {
                    if (clazz[targetMethod] && typeof clazz[targetMethod].implementation !== 'undefined') {
                      clazz[targetMethod].implementation = function() {
                        var args = Array.prototype.slice.call(arguments);
                        console.log("[批量Hook] " + target.class_name + "." + targetMethod + " 被调用");
                        console.log("[参数] " + JSON.stringify(args));
                        
                        if (target.hook_type === 'block') {
                          console.log("[阻止] 方法调用被阻止");
                          return null;
                        } else if (target.hook_type === 'modify') {
                          console.log("[修改] 方法被修改");
                        }
                        
                        var result = this[targetMethod].apply(this, arguments);
                        console.log("[返回值] " + JSON.stringify(result));
                        return result;
                      };
                      hooked = true;
                    }
                  } catch (directError) {
                    console.log("[Hook策略1失败] " + directError.message);
                  }
                  
                  // 策略2: Hook所有重载版本
                  if (!hooked) {
                    try {
                      var methods = clazz.class.getDeclaredMethods();
                      var targetMethods = [];
                      
                      for (var i = 0; i < methods.length; i++) {
                        if (methods[i].getName() === targetMethod) {
                          targetMethods.push(methods[i]);
                        }
                      }
                      
                      if (targetMethods.length > 0) {
                        console.log("[Hook策略2] 找到 " + targetMethods.length + " 个重载方法: " + targetMethod);
                        
                        // Hook每个重载版本
                        targetMethods.forEach(function(method, index) {
                          try {
                            var paramTypes = method.getParameterTypes();
                            var paramTypeNames = [];
                            for (var j = 0; j < paramTypes.length; j++) {
                              paramTypeNames.push(paramTypes[j].getName());
                            }
                            
                            console.log("[Hook重载] " + targetMethod + "(" + paramTypeNames.join(", ") + ")");
                            
                            // 使用overload Hook特定版本
                            var overloadMethod = clazz[targetMethod].overload.apply(clazz[targetMethod], paramTypeNames);
                            overloadMethod.implementation = function() {
                              var args = Array.prototype.slice.call(arguments);
                              console.log("[批量Hook-重载" + index + "] " + target.class_name + "." + targetMethod + " 被调用");
                              console.log("[参数] " + JSON.stringify(args));
                              
                              if (target.hook_type === 'block') {
                                console.log("[阻止] 方法调用被阻止");
                                return null;
                              }
                              
                              var result = this[targetMethod].apply(this, arguments);
                              console.log("[返回值] " + JSON.stringify(result));
                              return result;
                            };
                            
                            hooked = true;
                            
                          } catch (overloadError) {
                            console.log("[Hook重载失败] " + overloadError.message);
                          }
                        });
                      }
                    } catch (overloadScanError) {
                      console.log("[Hook策略2失败] " + overloadScanError.message);
                    }
                  }
                  
                  // 策略3: 通用Hook（最后尝试）
                  if (!hooked) {
                    try {
                      // 尝试Hook所有可能的方法签名
                      var commonSignatures = [
                        [],
                        ['java.lang.String'],
                        ['java.lang.Object'],
                        ['byte[]'],
                        ['int'],
                        ['boolean'],
                        ['java.lang.String', 'java.lang.String'],
                        ['byte[]', 'int', 'int']
                      ];
                      
                      for (var k = 0; k < commonSignatures.length; k++) {
                        try {
                          var overloadMethod = clazz[targetMethod].overload.apply(clazz[targetMethod], commonSignatures[k]);
                          overloadMethod.implementation = function() {
                            var args = Array.prototype.slice.call(arguments);
                            console.log("[批量Hook-通用] " + target.class_name + "." + targetMethod + " 被调用");
                            console.log("[参数] " + JSON.stringify(args));
                            
                            if (target.hook_type === 'block') {
                              console.log("[阻止] 方法调用被阻止");
                              return null;
                            }
                            
                            var result = this[targetMethod].apply(this, arguments);
                            console.log("[返回值] " + JSON.stringify(result));
                            return result;
                          };
                          
                          hooked = true;
                          console.log("[Hook策略3成功] " + targetMethod + "(" + commonSignatures[k].join(", ") + ")");
                          break;
                        } catch (e) {
                          // 继续尝试下一个签名
                        }
                      }
                    } catch (genericError) {
                      console.log("[Hook策略3失败] " + genericError.message);
                    }
                  }
                  
                  if (hooked) {
                    results.success++;
                    results.details.push({
                      target: target.class_name + "." + target.method_name,
                      status: "success"
                    });
                  } else {
                    throw new Error("所有Hook策略均失败");
                  }
                  
                } catch (e) {
                  results.failed++;
                  results.details.push({
                    target: target.class_name + "." + target.method_name,
                    status: "failed",
                    error: e.message
                  });
                }
              });
            });
          }
          
          return results;
        }
        
        var targets = ${JSON.stringify(targets)};
        var result = batchHook(targets);
        send(result);
      `;

      const script = await fridaSession.session.createScript(batchScript);
      
      return new Promise((resolve, reject) => {
        script.message.connect((message: any) => {
          if (message.type === 'send') {
            resolve(message.payload);
          } else if (message.type === 'error') {
            reject(new Error(message.description));
          }
        });

        script.load().catch(reject);
      });
    } catch (error) {
      throw new Error(`批量Hook失败: ${error}`);
    }
  }

  // ===== 日志管理 =====

  saveLogs(sessionId: string, format: 'json' | 'txt' | 'csv' = 'json', filename?: string, outputDir?: string): string {
    const targetSessionId = sessionId || this.currentSessionId;
    if (!targetSessionId) {
      throw new Error('没有活动的会话');
    }

    try {
      return globalLogger.saveLogs(targetSessionId, format, filename, outputDir);
    } catch (error) {
      // 如果日志系统没有正确初始化，尝试手动初始化
      console.warn('[日志保存] 尝试手动初始化日志系统');
      
      // 手动创建临时日志文件
      const fs = require('fs');
      const path = require('path');
      const projectRoot = process.cwd();
      const logsDir = path.join(projectRoot, 'logs');
      
      try {
        if (!fs.existsSync(logsDir)) {
          fs.mkdirSync(logsDir, { recursive: true });
        }
        
        const logs = this.getSessionLogs(targetSessionId);
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const fileName = filename || `frida-logs-${targetSessionId.substring(0, 8)}-${timestamp}`;
        
        let content: string;
        let ext: string;
        
        switch (format) {
          case 'json':
            content = JSON.stringify(logs, null, 2);
            ext = '.json';
            break;
          case 'txt':
            content = logs.map(log => {
              const date = new Date(log.timestamp).toISOString();
              return `[${date}] [${log.type.toUpperCase()}] ${log.source || ''}: ${JSON.stringify(log.data)}`;
            }).join('\n');
            ext = '.txt';
            break;
          case 'csv':
            const headers = 'Timestamp,Type,SessionId,Source,Data\n';
            const rows = logs.map(log => {
              const date = new Date(log.timestamp).toISOString();
              const data = JSON.stringify(log.data).replace(/"/g, '""');
              return `"${date}","${log.type}","${log.sessionId}","${log.source || ''}","${data}"`;
            }).join('\n');
            content = headers + rows;
            ext = '.csv';
            break;
          default:
            throw new Error(`不支持的格式: ${format}`);
        }
        
        const filePath = path.join(logsDir, fileName + ext);
        fs.writeFileSync(filePath, content, 'utf-8');
        
        console.log(`[日志保存] 已保存到: ${filePath}`);
        return filePath;
        
      } catch (fallbackError) {
        throw new Error(`日志保存失败: ${fallbackError}`);
      }
    }
  }

  getSessionLogs(sessionId?: string): LogEntry[] {
    const targetSessionId = sessionId || this.currentSessionId;
    if (!targetSessionId) {
      return [];
    }

    return globalLogger.getLogsForSession(targetSessionId);
  }

  // ===== 应用详细信息 =====

  async getApplicationInfo(packageName: string, deviceId?: string): Promise<any> {
    try {
      let device: frida.Device;
      
      if (deviceId) {
        device = await frida.getDevice(deviceId);
      } else {
        const devices = await frida.enumerateDevices();
        const usbDevice = devices.find(d => d.type === 'usb');
        device = usbDevice || await frida.getLocalDevice();
      }

      const applications = await device.enumerateApplications();
      const targetApp = applications.find(app => app.identifier === packageName);
      
      if (!targetApp) {
        throw new Error(`未找到应用: ${packageName}`);
      }

      // 获取更详细的应用信息
      const appInfoScript = `
        // 这里可以注入脚本获取更多应用信息
        // 比如权限、版本、签名等
        {
          "identifier": "${targetApp.identifier}",
          "name": "${targetApp.name}",
          "pid": ${targetApp.pid || 0}
        }
      `;

      return {
        basic: targetApp,
        device: device.name,
        // 可以扩展更多信息
      };
    } catch (error) {
      throw new Error(`获取应用信息失败: ${error}`);
    }
  }

  // ===== 自动崩溃恢复 =====

  enableAutoRecovery(sessionId?: string): void {
    const targetSessionId = sessionId || this.currentSessionId;
    if (!targetSessionId) {
      throw new Error('没有活动的会话');
    }

    const fridaSession = this.sessions.get(targetSessionId);
    if (!fridaSession) {
      throw new Error(`会话不存在: ${targetSessionId}`);
    }

    fridaSession.autoRecovery = true;
    console.log(`[自动恢复] 已为会话 ${targetSessionId} 启用自动崩溃恢复`);

    // 监听崩溃事件并尝试恢复
    fridaSession.session.detached.connect(async (reason: string) => {
      if (fridaSession.autoRecovery && reason.includes('crashed')) {
        console.log(`[自动恢复] 检测到应用崩溃，尝试重新附加...`);
        
        try {
          // 等待一段时间后重新附加
          setTimeout(async () => {
            try {
              await this.attach(fridaSession.process.name, false);
              console.log(`[自动恢复] 成功重新附加到 ${fridaSession.process.name}`);
            } catch (error) {
              console.error(`[自动恢复] 重新附加失败: ${error}`);
            }
          }, 3000);
        } catch (error) {
          console.error(`[自动恢复] 恢复过程出错: ${error}`);
        }
      }
    });
  }

  disableAutoRecovery(sessionId?: string): void {
    const targetSessionId = sessionId || this.currentSessionId;
    if (!targetSessionId) {
      throw new Error('没有活动的会话');
    }

    const fridaSession = this.sessions.get(targetSessionId);
    if (!fridaSession) {
      throw new Error(`会话不存在: ${targetSessionId}`);
    }

    fridaSession.autoRecovery = false;
    console.log(`[自动恢复] 已为会话 ${targetSessionId} 禁用自动崩溃恢复`);
  }

  // ===== 连接状态和实时日志功能 =====

  // 获取所有连接状态
  getConnectionStatuses() {
    return globalConnectionManager.getAllConnections();
  }

  // 手动触发重连
  forceReconnection(sessionId?: string): void {
    const targetSessionId = sessionId || this.currentSessionId;
    if (targetSessionId) {
      globalConnectionManager.forceReconnection(targetSessionId);
    }
  }

  // 启用实时日志监听
  startRealtimeLogs(sessionId?: string): void {
    const targetSessionId = sessionId || this.currentSessionId;
    if (targetSessionId) {
      globalLogger.startRealtimeWatch(targetSessionId);
    }
  }

  // 停止实时日志监听
  stopRealtimeLogs(sessionId?: string): void {
    const targetSessionId = sessionId || this.currentSessionId;
    if (targetSessionId) {
      globalLogger.stopRealtimeWatch(targetSessionId);
    }
  }

  // 获取实时日志统计
  getLogStats(sessionId?: string) {
    const targetSessionId = sessionId || this.currentSessionId;
    if (targetSessionId) {
      return globalLogger.getRealtimeStats(targetSessionId);
    }
    return null;
  }

  // 获取尾部日志 (类似tail)
  getTailLogs(sessionId?: string, lines: number = 50) {
    const targetSessionId = sessionId || this.currentSessionId;
    if (targetSessionId) {
      return globalLogger.getTailLogs(targetSessionId, lines);
    }
    return [];
  }

  // 流式日志 - 返回停止函数
  streamLogs(sessionId: string, callback: (log: LogEntry) => void): () => void {
    return globalLogger.streamLogs(sessionId, callback);
  }

  // 更新心跳 (用于健康检查)
  updateHeartbeat(sessionId?: string): void {
    const targetSessionId = sessionId || this.currentSessionId;
    if (targetSessionId) {
      globalConnectionManager.updateHeartbeat(targetSessionId);
    }
  }

  // 清理连接管理器资源
  async cleanup(): Promise<void> {
    await this.detach();
    globalConnectionManager.cleanup();
  }

  // ===== 环境检测和诊断 =====

  async diagnoseEnvironment(): Promise<{
    fridaServerStatus: { [deviceId: string]: string };
    recommendations: string[];
    deviceCapabilities: { [deviceId: string]: any };
  }> {
    const diagnosis = {
      fridaServerStatus: {} as { [deviceId: string]: string },
      recommendations: [] as string[],
      deviceCapabilities: {} as { [deviceId: string]: any }
    };

    try {
      const devices = await frida.enumerateDevices();
      
      for (const device of devices) {
        const deviceId = device.id;
        diagnosis.deviceCapabilities[deviceId] = {
          name: device.name,
          type: device.type,
          id: device.id
        };

        try {
          // 测试是否可以列出进程
          const processes = await device.enumerateProcesses();
          diagnosis.fridaServerStatus[deviceId] = `✅ 连接正常 (${processes.length} 个进程)`;
          
          // 检查是否有Gadget相关进程
          const gadgetProcess = processes.find(p => p.name.toLowerCase().includes('gadget'));
          if (gadgetProcess) {
            diagnosis.fridaServerStatus[deviceId] += ` 🎯 检测到Gadget`;
          }
          
        } catch (error: any) {
          diagnosis.fridaServerStatus[deviceId] = `❌ 连接失败: ${error.message}`;
          
          // 根据设备类型提供建议
          if (device.type === 'usb') {
            if (error.message.includes('Unable to connect') || error.message.includes('protocol error')) {
              diagnosis.recommendations.push(
                `📱 ${device.name}: 需要安装 frida-server。\n` +
                `   1. 下载 frida-server: https://github.com/frida/frida/releases\n` +
                `   2. 推送到设备: adb push frida-server /data/local/tmp/\n` +
                `   3. 设置权限: adb shell chmod 755 /data/local/tmp/frida-server\n` +
                `   4. 启动服务: adb shell /data/local/tmp/frida-server &`
              );
            } else if (error.message.includes('needs Gadget')) {
              diagnosis.recommendations.push(
                `📱 ${device.name}: 应用需要集成 Frida Gadget。请使用 APK 重打包工具集成 Gadget。`
              );
            }
          } else if (device.type === 'remote') {
            diagnosis.recommendations.push(
              `🌐 ${device.name}: 远程设备连接问题。\n` +
              `   1. 检查网络连接\n` +
              `   2. 确认 frida-server 运行状态\n` +
              `   3. 检查防火墙设置`
            );
          } else if (device.type === 'local') {
            if (device.name.toLowerCase().includes('iphone')) {
              diagnosis.recommendations.push(
                `📱 ${device.name}: iOS设备需要开发者镜像。\n` +
                `   1. 安装 pymobiledevice3: pip3 install pymobiledevice3\n` +
                `   2. 挂载开发者镜像: pymobiledevice3 mounter auto-mount\n` +
                `   3. 或使用 iOS App Store 版本的支持工具`
              );
            }
          }
        }
      }

      if (devices.length === 0) {
        diagnosis.recommendations.push(
          '⚠️ 未检测到任何设备。请尝试:\n' +
          '   1. 检查USB连接\n' +
          '   2. 启动Android模拟器\n' +
          '   3. 确认设备已开启USB调试\n' +
          '   4. 运行 adb devices 检查ADB连接'
        );
      }

    } catch (error: any) {
      diagnosis.recommendations.push(`❌ Frida 环境检测失败: ${error.message}`);
      diagnosis.recommendations.push(
        '请检查 Frida 安装:\n' +
        '   1. 更新 Frida: pip3 install frida-tools --upgrade\n' +
        '   2. 检查版本: frida --version\n' +
        '   3. 重启服务: adb shell pkill frida-server'
      );
    }

    return diagnosis;
  }
}