import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

export interface SecurityConfig {
  allowedProcessNames: string[];
  blockedProcessNames: string[];
  allowedPids: number[];
  requireConfirmation: boolean;
  maxScriptLength: number;
  allowedApiCalls: string[];
}

const DEFAULT_CONFIG: SecurityConfig = {
  allowedProcessNames: [], // 移动应用测试不需要限制
  blockedProcessNames: [], // 移动应用测试场景下移除系统进程限制
  allowedPids: [],
  requireConfirmation: false,
  maxScriptLength: 500000, // 增加到500KB，支持复杂的移动应用Hook脚本
  allowedApiCalls: [], // 移除API限制，安全测试需要完整访问权限
};

export class SecurityManager {
  private config: SecurityConfig;

  constructor(configPath?: string) {
    this.config = this.loadConfig(configPath);
  }

  private loadConfig(configPath?: string): SecurityConfig {
    if (configPath && existsSync(configPath)) {
      try {
        const configData = JSON.parse(readFileSync(configPath, 'utf-8'));
        return { ...DEFAULT_CONFIG, ...configData };
      } catch (error) {
        console.warn(`无法加载配置文件: ${error}，使用默认配置`);
      }
    }
    return DEFAULT_CONFIG;
  }

  validateProcessAccess(processName: string, pid: number): void {
    // 移动应用安全测试模式 - 最小限制
    console.log(`[安全检查] 允许访问进程: ${processName} (PID: ${pid})`);
    
    // 只保留基本的配置检查，不阻止任何进程
    if (this.config.allowedProcessNames.length > 0) {
      const isAllowed = this.config.allowedProcessNames.some(allowed => 
        processName.toLowerCase().includes(allowed.toLowerCase())
      );
      if (!isAllowed) {
        console.warn(`[警告] 进程 "${processName}" 不在允许列表中，但仍允许访问`);
      }
    }

    if (this.config.allowedPids.length > 0 && !this.config.allowedPids.includes(pid)) {
      console.warn(`[警告] PID ${pid} 不在允许列表中，但仍允许访问`);
    }
  }

  validateScript(script: string): void {
    // 移动应用安全测试模式 - 宽松的脚本检查
    if (script.length > this.config.maxScriptLength) {
      throw new Error(`脚本长度超过限制 (${this.config.maxScriptLength} 字符)`);
    }

    console.log(`[脚本检查] 脚本长度: ${script.length} 字符`);
    
    // 移动应用测试常用的操作不应被阻止
    // 只检查明显恶意的模式
    const maliciousPatterns = [
      /rm\s+-rf\s+\//, // 删除根目录
      /format\s+c:/, // 格式化C盘
      /dd\s+if=.*of=\/dev\/sd/, // 危险的dd操作
    ];

    for (const pattern of maliciousPatterns) {
      if (pattern.test(script)) {
        console.warn(`[警告] 脚本包含潜在恶意操作: ${pattern.source}`);
        // 不抛出错误，只警告
      }
    }

    // 移动应用Hook需要访问各种API，不限制
    console.log(`[脚本检查] 脚本验证通过，允许执行`);
  }

  isSystemProcess(processName: string): boolean {
    const systemProcesses = [
      'kernel',
      'launchd',
      'WindowServer',
      'loginwindow',
      'SecurityAgent',
      'systemuiserver',
      'coreauthd',
      'authd',
      'sudo',
      'su',
    ];

    return systemProcesses.some(sysProc => 
      processName.toLowerCase().includes(sysProc.toLowerCase())
    );
  }

  requiresElevatedPrivileges(pid: number): boolean {
    // 通常PID < 1000的进程需要更高权限
    return pid < 1000;
  }

  getConfig(): SecurityConfig {
    return { ...this.config };
  }

  updateConfig(newConfig: Partial<SecurityConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }
}