import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import { writeFileSync, existsSync, mkdirSync, unlinkSync, statSync, readFileSync } from 'fs';
import { join, dirname, basename } from 'path';
import { homedir, tmpdir } from 'os';
import { globalLogger } from './logger.js';
import { getProjectRoot, getEnvValue, loadProjectEnv } from './env-utils.js';

const execAsync = promisify(exec);

export interface ADBDevice {
  id: string;
  state: 'device' | 'offline' | 'unauthorized';
  product?: string;
  model?: string;
  device?: string;
  transport_id?: string;
}

export interface AppInfo {
  packageName: string;
  versionName?: string;
  versionCode?: string;
  targetSdk?: string;
  installLocation?: string;
  permissions?: string[];
}

export interface ProcessInfo {
  pid: string;
  ppid: string;
  name: string;
  user: string;
}

export interface ScreenshotResult {
  success: boolean;
  localPath?: string;
  devicePath?: string;
  error?: string;
}

export interface ScreenRecordResult {
  success: boolean;
  localPath?: string;
  devicePath?: string;
  error?: string;
  duration?: number;
}

export interface FileTransferResult {
  success: boolean;
  localPath?: string;
  remotePath?: string;
  size?: number;
  error?: string;
}

export interface ShellCommandResult {
  success: boolean;
  stdout: string | Buffer | any;
  stderr: string | Buffer | any;
  exitCode: number;
}

export interface InputResult {
  success: boolean;
  command: string;
  error?: string;
}

export class ADBManager {
  private adbPath: string;
  private currentDeviceId?: string;
  private screenshotDir: string;
  private recordingDir: string;

  constructor(adbPath?: string) {
    loadProjectEnv();
    const projectRoot = getProjectRoot();

    this.adbPath = adbPath || getEnvValue('ADB_PATH') || 'adb';
    this.screenshotDir = getEnvValue('SCREENSHOTS_DIR') || join(projectRoot, 'screenshots');
    this.recordingDir = getEnvValue('RECORDINGS_DIR') || join(projectRoot, 'recordings');
    
    // 确保目录存在
    this.ensureDirectories();
  }

  private ensureDirectories(): string {
    const fallbackDirs = [
      { screenshotDir: this.screenshotDir, recordingDir: this.recordingDir },
      {
        screenshotDir: join(homedir(), 'mobile-app-testing-screenshots'),
        recordingDir: join(homedir(), 'mobile-app-testing-recordings')
      },
      {
        screenshotDir: join(tmpdir(), 'mobile-app-testing-screenshots'),
        recordingDir: join(tmpdir(), 'mobile-app-testing-recordings')
      }
    ];

    for (let i = 0; i < fallbackDirs.length; i++) {
      const { screenshotDir, recordingDir } = fallbackDirs[i];
      try {
        console.log(`[ADB] 尝试目录 ${i + 1}/${fallbackDirs.length}: ${screenshotDir}`);
        
        if (!existsSync(screenshotDir)) {
          mkdirSync(screenshotDir, { recursive: true });
          console.log(`[ADB] 成功创建目录: ${screenshotDir}`);
        }
        if (!existsSync(recordingDir)) {
          mkdirSync(recordingDir, { recursive: true });
        }
        
        // 验证目录可写性
        const testFile = join(screenshotDir, `.test_write_${Date.now()}`);
        writeFileSync(testFile, 'test screenshot permission');
        
        if (existsSync(testFile)) {
          unlinkSync(testFile);
          console.log(`[ADB] ✅ 目录验证成功: ${screenshotDir}`);
          
          // 更新实例属性
          this.screenshotDir = screenshotDir;
          this.recordingDir = recordingDir;
          
          return screenshotDir;  // 返回成功的路径
        }
      } catch (error) {
        console.warn(`[ADB] ❌ 目录 ${screenshotDir} 不可用: ${error}`);
        continue;  // 尝试下一个路径
      }
    }
    
    throw new Error('所有备用目录都无法使用，截屏功能不可用');
  }

  private async runADBCommand(command: string, deviceId?: string, options: { encoding?: string | null } = {}): Promise<ShellCommandResult> {
    try {
      const targetDevice = deviceId || this.currentDeviceId;
      const deviceArg = targetDevice ? `-s ${targetDevice}` : '';
      const fullCommand = `${this.adbPath} ${deviceArg} ${command}`.trim();
      
      console.log(`[ADB] 执行命令: ${fullCommand}`);
      
      const execOptions = options.encoding !== undefined ? { encoding: options.encoding } : {};
      const { stdout, stderr } = await execAsync(fullCommand, execOptions);
      
      // 对于二进制数据，不要记录到日志中
      const isLogSafe = !command.includes('screencap') && !command.includes('exec-out');
      if (isLogSafe) {
        globalLogger.addLog({
          type: 'info',
          sessionId: 'adb',
          data: {
            command: fullCommand,
            stdout: typeof stdout === 'string' ? stdout.trim() : '[Binary Data]',
            stderr: typeof stderr === 'string' ? stderr.trim() : '[Binary Data]'
          }
        });
      }

      return {
        success: stderr === '' || !stderr.includes('error'),
        stdout: typeof stdout === 'string' ? stdout.trim() : stdout,
        stderr: typeof stderr === 'string' ? stderr.trim() : stderr,
        exitCode: 0
      };
    } catch (error: any) {
      console.error(`[ADB] 命令执行失败: ${error.message}`);
      
      globalLogger.addLog({
        type: 'error',
        sessionId: 'adb',
        data: {
          command,
          error: error.message
        }
      });

      return {
        success: false,
        stdout: '',
        stderr: error.message,
        exitCode: error.code || 1
      };
    }
  }

  // ===== 设备管理 =====

  async listDevices(): Promise<ADBDevice[]> {
    try {
      // 先尝试启动ADB服务器
      const serverResult = await this.runADBCommand('start-server');
      if (!serverResult.success) {
        console.warn(`[ADB] 启动服务器警告: ${serverResult.stderr}`);
      }

      const result = await this.runADBCommand('devices -l');
    
      if (!result.success) {
        console.error(`[ADB] 获取设备列表失败: ${result.stderr}`);
        // 尝试重启ADB服务器
        await this.runADBCommand('kill-server');
        await new Promise(resolve => setTimeout(resolve, 2000));
        await this.runADBCommand('start-server');
        
        // 再次尝试
        const retryResult = await this.runADBCommand('devices -l');
        if (!retryResult.success) {
          throw new Error(`获取设备列表失败: ${retryResult.stderr}`);
        }
        result.stdout = retryResult.stdout;
      }

      const devices: ADBDevice[] = [];
      const lines = result.stdout.split('\n').slice(1); // 跳过标题行

      for (const line of lines) {
        if (!line.trim()) continue;
        
        const parts = line.trim().split(/\s+/);
        if (parts.length < 2) continue;

        const device: ADBDevice = {
          id: parts[0],
          state: parts[1] as ADBDevice['state']
        };

        // 解析额外属性
        for (let i = 2; i < parts.length; i++) {
          const part = parts[i];
          if (part.includes(':')) {
            const [key, value] = part.split(':');
            switch (key) {
              case 'product': device.product = value; break;
              case 'model': device.model = value; break;
              case 'device': device.device = value; break;
              case 'transport_id': device.transport_id = value; break;
            }
          }
        }

        // 对于连接的设备，尝试获取更多信息
        if (device.state === 'device') {
          try {
            const propResult = await this.runADBCommand('shell getprop ro.product.model', device.id);
            if (propResult.success && propResult.stdout.trim()) {
              device.model = device.model || propResult.stdout.trim();
            }
          } catch (error) {
            // 忽略属性获取失败
          }
        }

        devices.push(device);
      }

      console.log(`[ADB] 发现 ${devices.length} 个设备`);
      return devices;
    } catch (error: any) {
      console.error(`[ADB] 列出设备异常: ${error.message}`);
      // 返回空列表而不是抛出异常，让用户知道没有设备但不中断流程
      return [];
    }
  }

  async connectDevice(host: string, port: number = 5555): Promise<boolean> {
    const result = await this.runADBCommand(`connect ${host}:${port}`);
    return result.success && result.stdout.includes('connected');
  }

  async disconnectDevice(host: string, port: number = 5555): Promise<boolean> {
    const result = await this.runADBCommand(`disconnect ${host}:${port}`);
    return result.success;
  }

  async getDeviceState(deviceId?: string): Promise<string> {
    const result = await this.runADBCommand('get-state', deviceId);
    return result.success ? result.stdout : 'unknown';
  }

  async waitForDevice(deviceId?: string, timeout: number = 30000): Promise<boolean> {
    const result = await this.runADBCommand('wait-for-device', deviceId);
    return result.success;
  }

  setCurrentDevice(deviceId: string): void {
    this.currentDeviceId = deviceId;
    console.log(`[ADB] 切换到设备: ${deviceId}`);
  }

  // ===== 应用管理 =====

  async installApp(apkPath: string, options: {
    replace?: boolean;
    test?: boolean;
    downgrade?: boolean;
    deviceId?: string;
  } = {}): Promise<boolean> {
    const flags: string[] = [];
    if (options.replace) flags.push('-r');
    if (options.test) flags.push('-t');
    if (options.downgrade) flags.push('-d');

    const flagStr = flags.length > 0 ? flags.join(' ') + ' ' : '';
    const result = await this.runADBCommand(`install ${flagStr}"${apkPath}"`, options.deviceId);
    
    return result.success && result.stdout.includes('Success');
  }

  async uninstallApp(packageName: string, keepData: boolean = false, deviceId?: string): Promise<boolean> {
    const keepFlag = keepData ? '-k' : '';
    const result = await this.runADBCommand(`uninstall ${keepFlag} ${packageName}`, deviceId);
    
    return result.success && result.stdout.includes('Success');
  }

  async listPackages(options: {
    thirdPartyOnly?: boolean;
    systemOnly?: boolean;
    enabledOnly?: boolean;
    disabledOnly?: boolean;
    deviceId?: string;
  } = {}): Promise<string[]> {
    const flags: string[] = [];
    if (options.thirdPartyOnly) flags.push('-3');
    if (options.systemOnly) flags.push('-s');
    if (options.enabledOnly) flags.push('-e');
    if (options.disabledOnly) flags.push('-d');

    const flagStr = flags.length > 0 ? flags.join(' ') + ' ' : '';
    const result = await this.runADBCommand(`shell pm list packages ${flagStr}`, options.deviceId);
    
    if (!result.success) {
      return [];
    }

    return (result.stdout as string)
      .split('\n')
      .filter((line: string) => line.startsWith('package:'))
      .map((line: string) => line.replace('package:', ''))
      .filter((pkg: string) => pkg.trim());
  }

  async getAppInfo(packageName: string, deviceId?: string): Promise<AppInfo | null> {
    const result = await this.runADBCommand(`shell pm dump ${packageName}`, deviceId);
    
    if (!result.success) {
      return null;
    }

    const appInfo: AppInfo = { packageName };
    const lines = result.stdout.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      
      if (trimmed.includes('versionName=')) {
        appInfo.versionName = trimmed.split('versionName=')[1]?.split(' ')[0];
      }
      if (trimmed.includes('versionCode=')) {
        appInfo.versionCode = trimmed.split('versionCode=')[1]?.split(' ')[0];
      }
      if (trimmed.includes('targetSdk=')) {
        appInfo.targetSdk = trimmed.split('targetSdk=')[1]?.split(' ')[0];
      }
      if (trimmed.includes('installLocation=')) {
        appInfo.installLocation = trimmed.split('installLocation=')[1]?.split(' ')[0];
      }
    }

    return appInfo;
  }

  async grantPermission(packageName: string, permission: string, deviceId?: string): Promise<boolean> {
    const result = await this.runADBCommand(`shell pm grant ${packageName} ${permission}`, deviceId);
    return result.success;
  }

  async revokePermission(packageName: string, permission: string, deviceId?: string): Promise<boolean> {
    const result = await this.runADBCommand(`shell pm revoke ${packageName} ${permission}`, deviceId);
    return result.success;
  }

  async grantMultiplePermissions(packageName: string, permissions: string[], deviceId?: string): Promise<{granted: string[], failed: string[]}> {
    const granted: string[] = [];
    const failed: string[] = [];

    for (const permission of permissions) {
      const success = await this.grantPermission(packageName, permission, deviceId);
      if (success) {
        granted.push(permission);
      } else {
        failed.push(permission);
      }
    }

    return { granted, failed };
  }

  // ===== 进程管理 =====

  async findProcess(packageName: string, deviceId?: string): Promise<ProcessInfo[]> {
    const result = await this.runADBCommand('shell ps', deviceId);
    
    if (!result.success || !result.stdout) {
      return [];
    }

    const processes: ProcessInfo[] = [];
    const lines = (result.stdout as string)
      .split('\n')
      .filter((line: string) => line.trim() && line.includes(packageName));

    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 9) {
        processes.push({
          user: parts[0],
          pid: parts[1],
          ppid: parts[2],
          name: parts[8] || packageName
        });
      }
    }

    return processes;
  }

  async killProcess(pid: string, deviceId?: string): Promise<boolean> {
    const result = await this.runADBCommand(`shell kill ${pid}`, deviceId);
    return result.success;
  }

  async forceStopApp(packageName: string, deviceId?: string): Promise<boolean> {
    const result = await this.runADBCommand(`shell am force-stop ${packageName}`, deviceId);
    return result.success;
  }

  async findMainActivity(packageName: string, deviceId?: string): Promise<string | null> {
    try {
      // 方法1: 通过dumpsys获取主Activity
      const dumpsysResult = await this.runADBCommand(`shell dumpsys package ${packageName}`, deviceId);
      if (dumpsysResult.success) {
        const lines = dumpsysResult.stdout.split('\n');
        for (const line of lines) {
          if (line.includes('android.intent.action.MAIN') && line.includes('.')) {
            const activityMatch = line.match(/([a-zA-Z0-9_.]+Activity[a-zA-Z0-9_]*)/);
            if (activityMatch) {
              console.log(`[ADB] 通过dumpsys找到主Activity: ${activityMatch[1]}`);
              return activityMatch[1];
            }
          }
        }
      }

      // 方法2: 通过pm dump获取Activity信息
      const pmResult = await this.runADBCommand(`shell pm dump ${packageName}`, deviceId);
      if (pmResult.success && pmResult.stdout) {
        const lines = pmResult.stdout.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!lines[i].includes('android.intent.action.MAIN')) {
            continue;
          }
          const nearby = lines.slice(i, i + 8).join('\n');
          const activityMatch = nearby.match(/([a-zA-Z0-9_.]+Activity[a-zA-Z0-9_]*)/);
          if (activityMatch) {
            console.log(`[ADB] 通过pm dump找到主Activity: ${activityMatch[1]}`);
            return activityMatch[1];
          }
        }
      }

      // 方法3: 常见Activity命名模式
      const commonActivities = [
        'MainActivity',
        'LauncherActivity',
        'WelcomeActivity',
        'SplashActivity',
        'LoginActivity',
        '.MainActivity',
        '.ui.MainActivity',
        '.activities.MainActivity',
        '.activity.MainActivity'
      ];

      for (const activity of commonActivities) {
        const testActivity = activity.startsWith('.') ? activity : `.${activity}`;
        const testResult = await this.runADBCommand(`shell am start -n ${packageName}/${testActivity}`, deviceId);
        if (testResult.success && !testResult.stderr.includes('Error')) {
          console.log(`[ADB] 通过尝试找到可用Activity: ${testActivity}`);
          // 立即停止，避免启动应用
          await this.runADBCommand(`shell am force-stop ${packageName}`, deviceId);
          return testActivity;
        }
      }

      console.log(`[ADB] 无法找到${packageName}的主Activity`);
      return null;
    } catch (error: any) {
      console.error(`[ADB] 查找主Activity失败: ${error.message}`);
      return null;
    }
  }

  async startApp(packageName: string, activity?: string, deviceId?: string): Promise<boolean> {
    try {
      let targetActivity: string | undefined = activity;
      
      // 如果没有指定Activity，尝试自动查找
      if (!targetActivity) {
        console.log(`[ADB] 自动查找${packageName}的主Activity`);
        targetActivity = await this.findMainActivity(packageName, deviceId) || undefined;
        
        if (!targetActivity) {
          // 尝试简单的包名启动
          console.log(`[ADB] 尝试使用包名直接启动: ${packageName}`);
          const packageResult = await this.runADBCommand(`shell monkey -p ${packageName} -c android.intent.category.LAUNCHER 1`, deviceId);
          if (packageResult.success) {
            return true;
          }
          
          // 最后尝试使用am start启动
          const amResult = await this.runADBCommand(`shell am start ${packageName}`, deviceId);
          return amResult.success && !amResult.stderr.includes('Error');
        }
      }
      
      const activityStr = targetActivity.startsWith('.') 
        ? `${packageName}/${targetActivity}` 
        : targetActivity.includes('/') 
          ? targetActivity 
          : `${packageName}/${targetActivity}`;
      
      console.log(`[ADB] 启动应用: ${activityStr}`);
      const result = await this.runADBCommand(`shell am start -n ${activityStr}`, deviceId);
      
      if (result.success && !result.stderr.includes('Error')) {
        return true;
      } else {
        console.log(`[ADB] Activity启动失败，尝试备用方法: ${result.stderr}`);
        // 备用方法：使用Intent启动
        const intentResult = await this.runADBCommand(`shell am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER ${packageName}`, deviceId);
        return intentResult.success && !intentResult.stderr.includes('Error');
      }
    } catch (error: any) {
      console.error(`[ADB] 启动应用异常: ${error.message}`);
      return false;
    }
  }

  async startAppWithClear(packageName: string, activity?: string, deviceId?: string): Promise<boolean> {
    try {
      let targetActivity: string | undefined = activity;
      
      // 如果没有指定Activity，尝试自动查找
      if (!targetActivity) {
        targetActivity = await this.findMainActivity(packageName, deviceId) || undefined;
        
        if (!targetActivity) {
          // 先强制停止，再尝试启动
          await this.forceStopApp(packageName, deviceId);
          const packageResult = await this.runADBCommand(`shell monkey -p ${packageName} -c android.intent.category.LAUNCHER 1`, deviceId);
          if (packageResult.success) {
            return true;
          }
          
          const amResult = await this.runADBCommand(`shell am start -S ${packageName}`, deviceId);
          return amResult.success && !amResult.stderr.includes('Error');
        }
      }
      
      const activityStr = targetActivity.startsWith('.') 
        ? `${packageName}/${targetActivity}` 
        : targetActivity.includes('/') 
          ? targetActivity 
          : `${packageName}/${targetActivity}`;
      
      console.log(`[ADB] 清除启动应用: ${activityStr}`);
      const result = await this.runADBCommand(`shell am start -S -n ${activityStr}`, deviceId);
      
      if (result.success && !result.stderr.includes('Error')) {
        return true;
      } else {
        // 备用方法：先停止再启动
        await this.forceStopApp(packageName, deviceId);
        await new Promise(resolve => setTimeout(resolve, 1000)); // 等待1秒
        return this.startApp(packageName, targetActivity || undefined, deviceId);
      }
    } catch (error: any) {
      console.error(`[ADB] 清除启动应用异常: ${error.message}`);
      return false;
    }
  }

  // ===== 截屏和录屏 =====

  async takeScreenshot(filename?: string, deviceId?: string, outputDir?: string): Promise<ScreenshotResult> {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const deviceStr = deviceId || this.currentDeviceId || 'unknown';
      const finalFilename = filename || `screenshot-${deviceStr}-${timestamp}.png`;
      
      // 确定最终输出目录
      let validDir: string;
      if (outputDir) {
        // 使用用户指定的绝对路径
        validDir = outputDir;
        // 确保目录存在
        if (!existsSync(validDir)) {
          mkdirSync(validDir, { recursive: true });
        }
        console.log(`[ADB] 使用自定义输出目录: ${validDir}`);
      } else {
        // 使用默认目录选择机制
        try {
          validDir = this.ensureDirectories();
        } catch (dirError) {
          return {
            success: false,
            error: `无法创建截屏目录: ${dirError}`
          };
        }
      }
      
      const devicePaths = [`/sdcard/Download/${finalFilename}`, `/sdcard/${finalFilename}`, `/data/local/tmp/${finalFilename}`];
      const localPath = join(validDir, finalFilename);

      let lastError = '';
      
      // 尝试多个设备路径
      for (const devicePath of devicePaths) {
        try {
          console.log(`[ADB] 尝试截屏路径: ${devicePath}`);
          
          // 在设备上截屏
          const screenshotResult = await this.runADBCommand(`shell screencap -p ${devicePath}`, deviceId);
          if (!screenshotResult.success) {
            lastError = `设备截屏失败 (${devicePath}): ${screenshotResult.stderr}`;
            continue;
          }

          // 检查文件是否创建成功
          const checkResult = await this.runADBCommand(`shell ls -l ${devicePath}`, deviceId);
          if (!checkResult.success || !checkResult.stdout.includes(finalFilename)) {
            lastError = `截屏文件未创建 (${devicePath})`;
            continue;
          }

          // 拉取到本地
          const pullResult = await this.runADBCommand(`pull ${devicePath} "${localPath}"`, deviceId);
          if (!pullResult.success) {
            lastError = `拉取截屏文件失败 (${devicePath}): ${pullResult.stderr}`;
            // 清理失败的文件
            await this.runADBCommand(`shell rm ${devicePath}`, deviceId);
            continue;
          }

          // 验证本地文件
          if (!existsSync(localPath)) {
            lastError = `本地文件创建失败: ${localPath}`;
            await this.runADBCommand(`shell rm ${devicePath}`, deviceId);
            continue;
          }

          // 清理设备上的临时文件
          await this.runADBCommand(`shell rm ${devicePath}`, deviceId);

          console.log(`[ADB] 截屏成功: ${localPath}`);
          return {
            success: true,
            localPath,
            devicePath
          };
        } catch (pathError: any) {
          lastError = `路径异常 (${devicePath}): ${pathError.message}`;
          continue;
        }
      }

      // 所有路径都失败了，尝试直接输出到标准输出的方法
      try {
        console.log(`[ADB] 尝试直接截屏方法 (stdout)`);
        const directResult = await this.runADBCommand(`shell screencap -p`, deviceId, { encoding: null });
        if (directResult.success && directResult.stdout) {
          // 处理PNG数据 - screencap -p 输出原始PNG数据
          const pngData = Buffer.isBuffer(directResult.stdout) ? 
                         directResult.stdout : 
                         Buffer.from(directResult.stdout as string, 'binary');
          writeFileSync(localPath, pngData);
          
          // 验证文件大小和PNG魔数
          if (existsSync(localPath)) {
            const stats = statSync(localPath);
            const fileData = readFileSync(localPath);
            const isPNG = fileData.length > 8 && 
                         fileData[0] === 0x89 && 
                         fileData[1] === 0x50 && 
                         fileData[2] === 0x4E && 
                         fileData[3] === 0x47;
            
            if (stats.size > 1000 && isPNG) {
              console.log(`[ADB] ✅ 直接截屏成功: ${localPath} (${stats.size} bytes)`);
              return {
                success: true,
                localPath,
                devicePath: 'stdout'
              };
            } else {
              console.warn(`[ADB] 截屏文件无效: size=${stats.size}, isPNG=${isPNG}`);
              // 尝试删除无效文件
              try { unlinkSync(localPath); } catch {}
            }
          }
        }
      } catch (directError: any) {
        lastError = `直接截屏失败: ${directError.message}`;
      }
      
      // 最后尝试：使用exec重定向方式
      try {
        console.log(`[ADB] 尝试exec重定向截屏方法`);
        const targetDevice = deviceId || this.currentDeviceId;
        const deviceArg = targetDevice ? `-s ${targetDevice}` : '';
        const redirectCommand = `${this.adbPath} ${deviceArg} exec-out screencap -p > "${localPath}"`;
        
        console.log(`[ADB] 执行重定向命令: ${redirectCommand}`);
        const { stdout, stderr } = await execAsync(redirectCommand, { encoding: null });
        
        if (existsSync(localPath)) {
          const stats = statSync(localPath);
          if (stats.size > 1000) {
            console.log(`[ADB] ✅ 重定向截屏成功: ${localPath} (${stats.size} bytes)`);
            return {
              success: true,
              localPath,
              devicePath: 'exec-out'
            };
          }
        }
      } catch (execError: any) {
        lastError = `exec重定向截屏失败: ${execError.message}`;
      }

      return {
        success: false,
        error: `所有截屏方法都失败了。最后错误: ${lastError}`
      };
    } catch (error: any) {
      return {
        success: false,
        error: `截屏异常: ${error.message}`
      };
    }
  }

  async startScreenRecord(filename?: string, options: {
    duration?: number;
    bitRate?: number;
    size?: string;
    deviceId?: string;
  } = {}): Promise<ScreenRecordResult> {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const deviceStr = options.deviceId || this.currentDeviceId || 'unknown';
      const finalFilename = filename || `recording-${deviceStr}-${timestamp}.mp4`;
      
      const devicePath = `/sdcard/${finalFilename}`;
      const localPath = join(this.recordingDir, finalFilename);

      const recordOptions: string[] = [];
      if (options.duration) recordOptions.push(`--time-limit ${options.duration}`);
      if (options.bitRate) recordOptions.push(`--bit-rate ${options.bitRate}`);
      if (options.size) recordOptions.push(`--size ${options.size}`);

      const optionStr = recordOptions.length > 0 ? recordOptions.join(' ') + ' ' : '';
      
      // 开始录屏（异步执行）
      const recordResult = await this.runADBCommand(`shell screenrecord ${optionStr}${devicePath}`, options.deviceId);
      
      return {
        success: true,
        localPath,
        devicePath,
        duration: options.duration
      };
    } catch (error: any) {
      return {
        success: false,
        error: `开始录屏异常: ${error.message}`
      };
    }
  }

  async stopScreenRecord(devicePath: string, localPath: string, deviceId?: string): Promise<ScreenRecordResult> {
    try {
      // 通过杀死screenrecord进程来停止录屏
      const stopResult = await this.runADBCommand('shell pkill screenrecord', deviceId);
      if (!stopResult.success) {
        await this.runADBCommand('shell killall screenrecord', deviceId);
      }
      
      // 等待一点时间让文件写入完成
      await new Promise(resolve => setTimeout(resolve, 2000));

      // 拉取录屏文件到本地
      const pullResult = await this.runADBCommand(`pull ${devicePath} "${localPath}"`, deviceId);
      if (!pullResult.success) {
        return {
          success: false,
          error: `拉取录屏文件失败: ${pullResult.stderr}`
        };
      }

      // 清理设备上的文件
      await this.runADBCommand(`shell rm ${devicePath}`, deviceId);

      return {
        success: true,
        localPath,
        devicePath
      };
    } catch (error: any) {
      return {
        success: false,
        error: `停止录屏异常: ${error.message}`
      };
    }
  }

  // ===== 文件传输 =====

  async pushFile(localPath: string, remotePath: string, deviceId?: string): Promise<FileTransferResult> {
    try {
      const result = await this.runADBCommand(`push "${localPath}" ${remotePath}`, deviceId);
      
      if (!result.success) {
        return {
          success: false,
          error: result.stderr
        };
      }

      return {
        success: true,
        localPath,
        remotePath
      };
    } catch (error: any) {
      return {
        success: false,
        localPath,
        remotePath,
        error: error.message
      };
    }
  }

  async pullFile(remotePath: string, localPath: string, deviceId?: string): Promise<FileTransferResult> {
    try {
      // 首先检查远程文件是否存在
      const checkResult = await this.runADBCommand(`shell ls -la "${remotePath}"`, deviceId);
      if (!checkResult.success || checkResult.stdout.includes('No such file')) {
        return {
          success: false,
          localPath,
          remotePath,
          error: `远程文件不存在: ${remotePath}`
        };
      }

      // 检查权限，如果是系统目录，尝试使用不同路径
      let actualRemotePath = remotePath;
      let tempRequired = false;

      if (remotePath.startsWith('/data/data/') || remotePath.startsWith('/system/')) {
        // 对于受保护的目录，先复制到临时目录
        const tempPath = `/data/local/tmp/temp_${Date.now()}_${remotePath.split('/').pop()}`;
        console.log(`[ADB] 受保护文件，使用临时路径: ${tempPath}`);
        
        const cpResult = await this.runADBCommand(`shell cp "${remotePath}" "${tempPath}"`, deviceId);
        if (cpResult.success) {
          actualRemotePath = tempPath;
          tempRequired = true;
        } else {
          console.warn(`[ADB] 无法访问受保护文件: ${remotePath}`);
        }
      }

      const result = await this.runADBCommand(`pull "${actualRemotePath}" "${localPath}"`, deviceId);
      
      // 清理临时文件
      if (tempRequired) {
        await this.runADBCommand(`shell rm "${actualRemotePath}"`, deviceId);
      }
      
      if (!result.success) {
        return {
          success: false,
          localPath,
          remotePath,
          error: `文件传输失败: ${result.stderr}`
        };
      }

      // 检查本地文件是否创建成功
      if (!existsSync(localPath)) {
        return {
          success: false,
          localPath,
          remotePath,
          error: `本地文件创建失败: ${localPath}`
        };
      }

      return {
        success: true,
        localPath,
        remotePath,
        size: result.stdout.match(/(\d+) bytes/) ? parseInt(result.stdout.match(/(\d+) bytes/)![1]) : undefined
      };
    } catch (error: any) {
      return {
        success: false,
        localPath,
        remotePath,
        error: `文件拉取异常: ${error.message}`
      };
    }
  }

  // ===== 高级文件操作 =====

  async pullFileAdvanced(remotePath: string, localPath: string, deviceId?: string): Promise<FileTransferResult> {
    try {
      console.log(`[ADB] 高级文件拉取: ${remotePath} -> ${localPath}`);
      
      // 确保本地目录存在
      const localDir = dirname(localPath);
      if (!existsSync(localDir)) {
        mkdirSync(localDir, { recursive: true });
      }

      // 策略1: 直接拉取
      const directResult = await this.pullFile(remotePath, localPath, deviceId);
      if (directResult.success) {
        return directResult;
      }
      
      console.log(`[ADB] 直接拉取失败，尝试高级方法: ${directResult.error}`);
      
      // 策略2: 使用su权限复制到可访问位置
      const timestamp = Date.now();
      const fileName = basename(remotePath);
      const tempPath = `/data/local/tmp/adb_pull_${timestamp}_${fileName}`;
      
      // 尝试使用su复制
      const suCopyResult = await this.runADBCommand(`shell su -c "cp '${remotePath}' '${tempPath}'"`, deviceId);
      if (suCopyResult.success) {
        // 修改权限使其可读
        await this.runADBCommand(`shell su -c "chmod 644 '${tempPath}'"`, deviceId);
        
        const pullResult = await this.runADBCommand(`pull "${tempPath}" "${localPath}"`, deviceId);
        await this.runADBCommand(`shell rm "${tempPath}"`, deviceId); // 清理
        
        if (pullResult.success && existsSync(localPath)) {
          return {
            success: true,
            localPath,
            remotePath,
            size: statSync(localPath).size
          };
        }
      }
      
      // 策略3: 使用cat输出内容
      console.log(`[ADB] 尝试cat方法读取文件内容`);
      const catResult = await this.runADBCommand(`shell cat "${remotePath}"`, deviceId);
      if (catResult.success && catResult.stdout) {
        writeFileSync(localPath, catResult.stdout, 'utf8');
        if (existsSync(localPath)) {
          return {
            success: true,
            localPath,
            remotePath,
            size: statSync(localPath).size
          };
        }
      }
      
      // 策略4: 使用base64编码传输（适用于二进制文件）
      console.log(`[ADB] 尝试base64编码传输`);
      const base64Result = await this.runADBCommand(`shell base64 "${remotePath}"`, deviceId);
      if (base64Result.success && base64Result.stdout) {
        try {
          const binaryData = Buffer.from(base64Result.stdout.replace(/\s+/g, ''), 'base64');
          writeFileSync(localPath, binaryData);
          if (existsSync(localPath)) {
            return {
              success: true,
              localPath,
              remotePath,
              size: binaryData.length
            };
          }
        } catch (decodeError) {
          console.warn(`[ADB] Base64解码失败: ${decodeError}`);
        }
      }
      
      return {
        success: false,
        localPath,
        remotePath,
        error: `所有传输方法都失败了。原始错误: ${directResult.error}`
      };
      
    } catch (error: any) {
      return {
        success: false,
        localPath,
        remotePath,
        error: `高级文件传输异常: ${error.message}`
      };
    }
  }

  // ===== Shell 命令 =====

  async runShellCommand(command: string, deviceId?: string): Promise<ShellCommandResult> {
    const targetDevice = deviceId || this.currentDeviceId;
    const deviceArgs = targetDevice ? ['-s', targetDevice] : [];
    const marker = `__MCP_EXIT_CODE_${Date.now()}_${Math.random().toString(36).slice(2, 8)}__`;
    const wrappedCommand = `${command}\n__mcp_ec=$?\nprintf "\\n${marker}:%s\\n" "$__mcp_ec"\nexit "$__mcp_ec"`;
    const adbArgs = [...deviceArgs, 'shell', 'sh', '-c', wrappedCommand];
    const displayCommand = `${this.adbPath} ${deviceArgs.join(' ')} shell sh -c "<user_command>"`.trim();

    console.log(`[ADB] Shell执行: ${displayCommand}`);

    const execution = await new Promise<{ stdout: string; stderr: string; exitCode: number }>((resolve) => {
      const child = spawn(this.adbPath, adbArgs, { shell: false });
      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (chunk: Buffer) => {
        stdout += chunk.toString('utf8');
      });
      child.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf8');
      });
      child.on('error', (error: Error) => {
        stderr += `${stderr ? '\n' : ''}${error.message}`;
      });
      child.on('close', (code) => {
        resolve({
          stdout,
          stderr,
          exitCode: typeof code === 'number' ? code : 1
        });
      });
    });

    let parsedExitCode = execution.exitCode;
    let cleanedStdout = execution.stdout;
    const markerRegex = new RegExp(`${this.escapeRegExp(marker)}:(-?\\d+)\\s*$`);
    const markerMatch = cleanedStdout.match(markerRegex);
    if (markerMatch) {
      const markerCode = parseInt(markerMatch[1], 10);
      if (!Number.isNaN(markerCode)) {
        parsedExitCode = markerCode;
      }
      cleanedStdout = cleanedStdout.replace(markerRegex, '').replace(/\n+$/, '');
    }

    const normalizedStdout = cleanedStdout.trim();
    const normalizedStderr = execution.stderr.trim();

    globalLogger.addLog({
      type: parsedExitCode === 0 ? 'info' : 'error',
      sessionId: 'adb',
      data: {
        command: displayCommand,
        userCommand: command,
        deviceId: targetDevice,
        exitCode: parsedExitCode,
        stdout: normalizedStdout,
        stderr: normalizedStderr
      }
    });

    return {
      success: parsedExitCode === 0,
      stdout: normalizedStdout,
      stderr: normalizedStderr,
      exitCode: parsedExitCode
    };
  }

  private escapeRegExp(value: string): string {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // ===== 输入模拟 =====

  async tap(x: number, y: number, deviceId?: string): Promise<InputResult> {
    const result = await this.runADBCommand(`shell input tap ${x} ${y}`, deviceId);
    return {
      success: result.success,
      command: `tap ${x} ${y}`,
      error: result.success ? undefined : result.stderr
    };
  }

  async swipe(x1: number, y1: number, x2: number, y2: number, duration: number = 300, deviceId?: string): Promise<InputResult> {
    const result = await this.runADBCommand(`shell input swipe ${x1} ${y1} ${x2} ${y2} ${duration}`, deviceId);
    return {
      success: result.success,
      command: `swipe ${x1} ${y1} ${x2} ${y2} ${duration}`,
      error: result.success ? undefined : result.stderr
    };
  }

  async inputText(text: string, deviceId?: string): Promise<InputResult> {
    // 转义特殊字符
    const escapedText = text.replace(/[ &;|<>()$`\\'"]/g, '\\$&');
    const result = await this.runADBCommand(`shell input text "${escapedText}"`, deviceId);
    return {
      success: result.success,
      command: `input text "${text}"`,
      error: result.success ? undefined : result.stderr
    };
  }

  async keyEvent(keyCode: number | string, deviceId?: string): Promise<InputResult> {
    const result = await this.runADBCommand(`shell input keyevent ${keyCode}`, deviceId);
    return {
      success: result.success,
      command: `keyevent ${keyCode}`,
      error: result.success ? undefined : result.stderr
    };
  }

  async longPress(x: number, y: number, duration: number = 1000, deviceId?: string): Promise<InputResult> {
    const result = await this.runADBCommand(`shell input swipe ${x} ${y} ${x} ${y} ${duration}`, deviceId);
    return {
      success: result.success,
      command: `longpress ${x} ${y} ${duration}`,
      error: result.success ? undefined : result.stderr
    };
  }
}

// 全局 ADB 管理器实例
export const globalADBManager = new ADBManager();
