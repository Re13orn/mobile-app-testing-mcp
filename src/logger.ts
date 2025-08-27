import { writeFileSync, appendFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { EventEmitter } from 'events';

export interface LogEntry {
  timestamp: number;
  type: 'hook' | 'memory' | 'network' | 'error' | 'info';
  sessionId: string;
  data: any;
  source?: string; // 来源（脚本ID、类名等）
}

export class Logger extends EventEmitter {
  private logs: LogEntry[] = [];
  private logDir: string;
  private initialized: boolean = false;
  private realtimeWatchers: Set<string> = new Set(); // 实时监听的会话ID

  constructor() {
    super();
    // 延迟初始化，避免在模块加载时创建目录
    this.logDir = '';
    this.initialized = false;
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      try {
        // 使用项目根目录而不是当前工作目录
        const projectRoot = process.cwd();
        this.logDir = join(projectRoot, 'logs');
        
        console.log(`[Logger] 初始化日志目录: ${this.logDir}`);
        
        if (!existsSync(this.logDir)) {
          mkdirSync(this.logDir, { recursive: true });
        }
        
        this.initialized = true;
        console.log(`[Logger] 日志系统初始化完成`);
      } catch (error) {
        console.warn(`[Logger] 无法创建日志目录，将禁用文件日志: ${error}`);
        this.logDir = '';
        this.initialized = true; // 标记为已初始化，避免重复尝试
      }
    }
  }

  addLog(entry: Omit<LogEntry, 'timestamp'>): void {
    const logEntry: LogEntry = {
      ...entry,
      timestamp: Date.now(),
    };
    
    this.logs.push(logEntry);
    console.log(`[${entry.type.toUpperCase()}] ${JSON.stringify(entry.data)}`);
    
    // 触发实时日志事件
    this.emit('newLog', logEntry);
    
    // 如果有会话在监听，发送实时更新
    if (this.realtimeWatchers.has(entry.sessionId)) {
      this.emit('realtimeLog', entry.sessionId, logEntry);
    }
  }

  getLogsForSession(sessionId: string): LogEntry[] {
    return this.logs.filter(log => log.sessionId === sessionId);
  }

  getAllLogs(): LogEntry[] {
    return [...this.logs];
  }

  clearLogsForSession(sessionId: string): void {
    this.logs = this.logs.filter(log => log.sessionId !== sessionId);
  }

  saveLogs(sessionId: string, format: 'json' | 'txt' | 'csv' = 'json', filename?: string, outputDir?: string): string {
    this.ensureInitialized(); // 确保日志系统已初始化
    
    // 确定最终输出目录
    let finalDir: string;
    if (outputDir) {
      // 使用用户指定的绝对路径
      finalDir = outputDir;
      // 确保目录存在
      if (!existsSync(finalDir)) {
        mkdirSync(finalDir, { recursive: true });
      }
      console.log(`[Logger] 使用自定义输出目录: ${finalDir}`);
    } else {
      // 使用默认日志目录
      if (!this.logDir) {
        throw new Error('日志系统未正确初始化，无法保存日志文件');
      }
      finalDir = this.logDir;
    }
    
    const sessionLogs = this.getLogsForSession(sessionId);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const defaultFilename = `mobile-app-testing-logs-${sessionId.substring(0, 8)}-${timestamp}`;
    const finalFilename = filename || defaultFilename;

    let content: string;
    let extension: string;

    switch (format) {
      case 'json':
        content = JSON.stringify(sessionLogs, null, 2);
        extension = '.json';
        break;
      
      case 'txt':
        content = sessionLogs.map(log => {
          const date = new Date(log.timestamp).toISOString();
          return `[${date}] [${log.type.toUpperCase()}] ${log.source || ''}: ${JSON.stringify(log.data)}`;
        }).join('\n');
        extension = '.txt';
        break;
      
      case 'csv':
        const headers = 'Timestamp,Type,SessionId,Source,Data\n';
        const rows = sessionLogs.map(log => {
          const date = new Date(log.timestamp).toISOString();
          const data = JSON.stringify(log.data).replace(/"/g, '""'); // CSV转义
          return `"${date}","${log.type}","${log.sessionId}","${log.source || ''}","${data}"`;
        }).join('\n');
        content = headers + rows;
        extension = '.csv';
        break;
      
      default:
        throw new Error(`不支持的格式: ${format}`);
    }

    const filePath = join(finalDir, finalFilename + extension);
    writeFileSync(filePath, content, 'utf-8');
    
    return filePath;
  }

  // 实时日志过滤
  filterLogs(sessionId: string, filters: {
    type?: string[];
    source?: string;
    timeRange?: [number, number];
    keyword?: string;
  }): LogEntry[] {
    let filtered = this.getLogsForSession(sessionId);

    if (filters.type) {
      filtered = filtered.filter(log => filters.type!.includes(log.type));
    }

    if (filters.source) {
      filtered = filtered.filter(log => 
        log.source && log.source.toLowerCase().includes(filters.source!.toLowerCase())
      );
    }

    if (filters.timeRange) {
      const [start, end] = filters.timeRange;
      filtered = filtered.filter(log => log.timestamp >= start && log.timestamp <= end);
    }

    if (filters.keyword) {
      filtered = filtered.filter(log => {
        const searchText = JSON.stringify(log.data).toLowerCase();
        return searchText.includes(filters.keyword!.toLowerCase());
      });
    }

    return filtered;
  }

  // ===== 实时日志功能 =====

  // 启用实时日志监听
  startRealtimeWatch(sessionId: string): void {
    this.realtimeWatchers.add(sessionId);
    console.log(`[Logger] 启用实时日志监听: ${sessionId}`);
  }

  // 停止实时日志监听  
  stopRealtimeWatch(sessionId: string): void {
    this.realtimeWatchers.delete(sessionId);
    console.log(`[Logger] 停止实时日志监听: ${sessionId}`);
  }

  // 获取最近的日志 (类似tail功能)
  getTailLogs(sessionId: string, lines: number = 50): LogEntry[] {
    const sessionLogs = this.getLogsForSession(sessionId);
    return sessionLogs.slice(-lines); // 获取最后N条记录
  }

  // 流式日志输出 (类似tail -f)
  streamLogs(sessionId: string, callback: (log: LogEntry) => void): () => void {
    // 先发送最近的日志
    const recentLogs = this.getTailLogs(sessionId, 20);
    recentLogs.forEach(callback);

    // 启用实时监听
    this.startRealtimeWatch(sessionId);

    // 设置实时监听器
    const realtimeHandler = (sid: string, log: LogEntry) => {
      if (sid === sessionId) {
        callback(log);
      }
    };

    this.on('realtimeLog', realtimeHandler);

    // 返回停止函数
    return () => {
      this.stopRealtimeWatch(sessionId);
      this.off('realtimeLog', realtimeHandler);
    };
  }

  // 格式化日志输出
  formatLogEntry(log: LogEntry): string {
    const timestamp = new Date(log.timestamp).toISOString();
    const typeColor = this.getTypeColor(log.type);
    const source = log.source ? `[${log.source}]` : '';
    
    return `${timestamp} ${typeColor}[${log.type.toUpperCase()}]${source} ${JSON.stringify(log.data)}`;
  }

  private getTypeColor(type: string): string {
    const colors = {
      'error': '\x1b[31m',   // 红色
      'hook': '\x1b[33m',    // 黄色  
      'network': '\x1b[36m', // 青色
      'memory': '\x1b[35m',  // 紫色
      'info': '\x1b[32m',    // 绿色
    };
    return colors[type as keyof typeof colors] || '\x1b[0m';
  }

  // 实时日志统计
  getRealtimeStats(sessionId: string): {
    totalLogs: number;
    errorCount: number;
    hookCount: number;
    networkCount: number;
    lastLogTime: number;
  } {
    const sessionLogs = this.getLogsForSession(sessionId);
    
    return {
      totalLogs: sessionLogs.length,
      errorCount: sessionLogs.filter(l => l.type === 'error').length,
      hookCount: sessionLogs.filter(l => l.type === 'hook').length,
      networkCount: sessionLogs.filter(l => l.type === 'network').length,
      lastLogTime: sessionLogs.length > 0 ? Math.max(...sessionLogs.map(l => l.timestamp)) : 0,
    };
  }
}

// 全局日志管理器
export const globalLogger = new Logger();