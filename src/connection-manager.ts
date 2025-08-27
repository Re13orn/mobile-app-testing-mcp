import * as frida from 'frida';
import { EventEmitter } from 'events';
import { globalLogger } from './logger.js';

export interface ConnectionConfig {
  maxRetries: number;
  retryDelay: number;
  healthCheckInterval: number;
  appRestartDetection: boolean;
  autoReattach: boolean;
}

export interface ConnectionStatus {
  sessionId: string;
  status: 'connected' | 'disconnected' | 'reconnecting' | 'failed';
  processName: string;
  pid?: number;
  lastError?: string;
  retryCount: number;
  lastHeartbeat: number;
}

export class ConnectionManager extends EventEmitter {
  private connections: Map<string, ConnectionStatus> = new Map();
  private reconnectTimers: Map<string, NodeJS.Timeout> = new Map();
  private healthCheckTimer?: NodeJS.Timeout;
  
  private config: ConnectionConfig = {
    maxRetries: 5,
    retryDelay: 3000, // 3秒
    healthCheckInterval: 10000, // 10秒健康检查
    appRestartDetection: true,
    autoReattach: true,
  };

  constructor(config?: Partial<ConnectionConfig>) {
    super();
    if (config) {
      this.config = { ...this.config, ...config };
    }
    
    this.startHealthCheck();
    this.setupGlobalErrorHandling();
  }

  // 注册连接
  registerConnection(sessionId: string, processName: string, pid?: number): void {
    const status: ConnectionStatus = {
      sessionId,
      status: 'connected',
      processName,
      pid,
      retryCount: 0,
      lastHeartbeat: Date.now(),
    };

    this.connections.set(sessionId, status);
    
    globalLogger.addLog({
      type: 'info',
      sessionId,
      data: { 
        action: 'connection_registered',
        processName,
        pid 
      }
    });

    this.emit('connectionRegistered', status);
  }

  // 连接断开处理
  handleDisconnection(sessionId: string, reason: string): void {
    const connection = this.connections.get(sessionId);
    if (!connection) return;

    connection.status = 'disconnected';
    connection.lastError = reason;
    
    globalLogger.addLog({
      type: 'error',
      sessionId,
      data: {
        action: 'connection_lost',
        reason,
        processName: connection.processName
      }
    });

    this.emit('connectionLost', connection);

    // 启动自动重连（如果启用）
    if (this.config.autoReattach && connection.retryCount < this.config.maxRetries) {
      this.startReconnection(sessionId);
    } else {
      connection.status = 'failed';
      this.emit('connectionFailed', connection);
    }
  }

  // 启动重连流程
  private startReconnection(sessionId: string): void {
    const connection = this.connections.get(sessionId);
    if (!connection) return;

    connection.status = 'reconnecting';
    connection.retryCount++;

    globalLogger.addLog({
      type: 'info',
      sessionId,
      data: {
        action: 'reconnection_attempt',
        attempt: connection.retryCount,
        maxRetries: this.config.maxRetries
      }
    });

    const delay = this.config.retryDelay * connection.retryCount; // 递增延迟
    
    const timer = setTimeout(async () => {
      try {
        await this.attemptReconnection(sessionId);
      } catch (error) {
        globalLogger.addLog({
          type: 'error',
          sessionId,
          data: {
            action: 'reconnection_failed',
            error: error instanceof Error ? error.message : String(error)
          }
        });

        // 继续重试或标记为失败
        if (connection.retryCount < this.config.maxRetries) {
          this.startReconnection(sessionId);
        } else {
          connection.status = 'failed';
          this.emit('connectionFailed', connection);
        }
      }
    }, delay);

    this.reconnectTimers.set(sessionId, timer);
  }

  // 尝试重新连接
  private async attemptReconnection(sessionId: string): Promise<void> {
    const connection = this.connections.get(sessionId);
    if (!connection) return;

    // 检查应用是否重启（PID变化）
    if (this.config.appRestartDetection) {
      const currentPid = await this.detectProcessRestart(connection.processName);
      if (currentPid && currentPid !== connection.pid) {
        connection.pid = currentPid;
        globalLogger.addLog({
          type: 'info',
          sessionId,
          data: {
            action: 'process_restart_detected',
            oldPid: connection.pid,
            newPid: currentPid
          }
        });
      }
    }

    // 触发重新附加事件
    this.emit('reconnectionAttempt', connection);
  }

  // 检测进程重启
  private async detectProcessRestart(processName: string): Promise<number | null> {
    try {
      const device = await frida.getLocalDevice();
      const processes = await device.enumerateProcesses();
      
      // 优先选择USB设备
      const devices = await frida.enumerateDevices();
      const usbDevice = devices.find(d => d.type === 'usb');
      const targetDevice = usbDevice || device;
      
      const targetProcesses = await targetDevice.enumerateProcesses();
      const process = targetProcesses.find(p => p.name === processName);
      
      return process ? process.pid : null;
    } catch (error) {
      return null;
    }
  }

  // 连接成功
  handleReconnectionSuccess(sessionId: string): void {
    const connection = this.connections.get(sessionId);
    if (!connection) return;

    connection.status = 'connected';
    connection.retryCount = 0;
    connection.lastHeartbeat = Date.now();
    connection.lastError = undefined;

    // 清理重连定时器
    const timer = this.reconnectTimers.get(sessionId);
    if (timer) {
      clearTimeout(timer);
      this.reconnectTimers.delete(sessionId);
    }

    globalLogger.addLog({
      type: 'info',
      sessionId,
      data: {
        action: 'reconnection_success',
        processName: connection.processName
      }
    });

    this.emit('reconnectionSuccess', connection);
  }

  // 更新心跳
  updateHeartbeat(sessionId: string): void {
    const connection = this.connections.get(sessionId);
    if (connection) {
      connection.lastHeartbeat = Date.now();
    }
  }

  // 健康检查
  private startHealthCheck(): void {
    this.healthCheckTimer = setInterval(() => {
      const now = Date.now();
      
      for (const [sessionId, connection] of this.connections) {
        if (connection.status === 'connected') {
          const timeSinceHeartbeat = now - connection.lastHeartbeat;
          
          if (timeSinceHeartbeat > this.config.healthCheckInterval * 2) {
            globalLogger.addLog({
              type: 'error',
              sessionId,
              data: {
                action: 'health_check_failed',
                timeSinceHeartbeat,
                processName: connection.processName
              }
            });

            this.handleDisconnection(sessionId, 'Health check timeout');
          }
        }
      }
    }, this.config.healthCheckInterval);
  }

  // 全局错误处理
  private setupGlobalErrorHandling(): void {
    process.on('uncaughtException', (error) => {
      globalLogger.addLog({
        type: 'error',
        sessionId: 'global',
        data: {
          action: 'uncaught_exception',
          error: error.message,
          stack: error.stack
        }
      });
    });

    process.on('unhandledRejection', (reason) => {
      globalLogger.addLog({
        type: 'error',
        sessionId: 'global',
        data: {
          action: 'unhandled_rejection',
          reason: String(reason)
        }
      });
    });
  }

  // 获取所有连接状态
  getAllConnections(): ConnectionStatus[] {
    return Array.from(this.connections.values());
  }

  // 获取特定连接状态
  getConnectionStatus(sessionId: string): ConnectionStatus | undefined {
    return this.connections.get(sessionId);
  }

  // 手动触发重连
  forceReconnection(sessionId: string): void {
    const connection = this.connections.get(sessionId);
    if (connection && connection.status !== 'reconnecting') {
      connection.retryCount = 0; // 重置重试计数
      this.startReconnection(sessionId);
    }
  }

  // 移除连接
  removeConnection(sessionId: string): void {
    const timer = this.reconnectTimers.get(sessionId);
    if (timer) {
      clearTimeout(timer);
      this.reconnectTimers.delete(sessionId);
    }

    this.connections.delete(sessionId);
    
    globalLogger.addLog({
      type: 'info',
      sessionId,
      data: { action: 'connection_removed' }
    });
  }

  // 清理资源
  cleanup(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
    }

    for (const timer of this.reconnectTimers.values()) {
      clearTimeout(timer);
    }
    
    this.reconnectTimers.clear();
    this.connections.clear();
    this.removeAllListeners();
  }
}

// 全局连接管理器
export const globalConnectionManager = new ConnectionManager();