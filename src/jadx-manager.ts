// JADX (Java反编译器) 管理器
// 用于APK反编译和源码分析

import { execSync, exec } from 'child_process';
import { promisify } from 'util';
import { existsSync, statSync, mkdirSync, readdirSync, rmSync } from 'fs';
import { join, dirname, basename, extname } from 'path';
import { globalLogger } from './logger.js';
import { getEnvValue, getProjectRoot, loadProjectEnv } from './env-utils.js';

const execAsync = promisify(exec);

export interface JADXDecompileOptions {
  outputDir?: string;
  showBadCode?: boolean;
  noReplace?: boolean;
  escapeUnicode?: boolean;
  respectBytecodeAccess?: boolean;
  deobfuscation?: boolean;
  useKotlinMetadata?: boolean;
  threadsCount?: number;
  verbose?: boolean;
}

export interface JADXDecompileResult {
  success: boolean;
  outputPath?: string;
  apkPath: string;
  filesGenerated?: number;
  classesCount?: number;
  resourcesCount?: number;
  duration?: number;
  error?: string;
  summary?: {
    javaFiles: number;
    resourceFiles: number;
    manifestFound: boolean;
    totalSize: string;
  };
}

export interface JADXStats {
  javaFiles: number;
  smaliFiles: number;
  resourceFiles: number;
  totalFiles: number;
  directories: number;
  manifestExists: boolean;
}

export class JADXManager {
  private jadxPath: string | null = null;
  private defaultOutputDir: string;
  
  constructor() {
    loadProjectEnv();
    this.defaultOutputDir = getEnvValue('DECOMPILED_DIR') || join(getProjectRoot(), 'decompiled');
    this.detectJADXPath();
  }

  private detectJADXPath(): void {
    const possiblePaths = [
      // 显式配置优先
      getEnvValue('JADX_PATH'),
      // 项目本地JADX
      join(getProjectRoot(), 'jadx', 'bin', 'jadx'),
      join(getProjectRoot(), 'jadx', 'bin', 'jadx.bat'),
      // 系统PATH中的jadx
      'jadx',
      // 常见安装路径
      '/usr/local/bin/jadx',
      '/opt/jadx/bin/jadx',
      // Homebrew安装路径 (macOS)
      '/opt/homebrew/bin/jadx',
      // 用户本地安装
      join(process.env.HOME || '', 'jadx', 'bin', 'jadx'),
      // Windows 常见路径
      process.env.LOCALAPPDATA ? join(process.env.LOCALAPPDATA, 'Programs', 'jadx', 'bin', 'jadx.bat') : '',
      process.env.ProgramFiles ? join(process.env.ProgramFiles, 'jadx', 'bin', 'jadx.bat') : ''
    ];

    for (const path of possiblePaths) {
      if (!path) {
        continue;
      }
      try {
        if (existsSync(path) && statSync(path).isFile()) {
          // 测试jadx命令是否可执行
          execSync(`"${path}" --help`, { stdio: 'ignore' });
          this.jadxPath = path;
          console.log(`[JADX] 找到JADX: ${path}`);
          return;
        } else if (path === 'jadx') {
          // 测试系统PATH中的jadx
          execSync('jadx --help', { stdio: 'ignore' });
          this.jadxPath = 'jadx';
          console.log(`[JADX] 找到JADX: ${path} (系统PATH)`);
          return;
        }
      } catch (error) {
        // 忽略错误，继续尝试下一个路径
      }
    }

    console.warn('[JADX] 未找到JADX工具，APK反编译功能将不可用');
    console.warn('[JADX] 请安装JADX工具或检查路径配置');
    console.warn('[JADX] 下载地址: https://github.com/skylot/jadx/releases');
  }

  async isAvailable(): Promise<boolean> {
    return this.jadxPath !== null;
  }

  async getVersion(): Promise<string | null> {
    if (!this.jadxPath) {
      return null;
    }

    try {
      const output = await execAsync(`"${this.jadxPath}" --version`);
      return output.stdout.trim() || output.stderr.trim();
    } catch (error) {
      console.error(`[JADX] 获取版本失败: ${error}`);
      return null;
    }
  }

  async decompileAPK(
    apkPath: string, 
    options: JADXDecompileOptions = {}
  ): Promise<JADXDecompileResult> {
    if (!this.jadxPath) {
      throw new Error('JADX工具不可用，请安装JADX');
    }

    if (!existsSync(apkPath)) {
      throw new Error(`APK文件不存在: ${apkPath}`);
    }

    const startTime = Date.now();
    const apkBaseName = basename(apkPath, '.apk');
    const outputDir = options.outputDir || join(this.defaultOutputDir, `${apkBaseName}_decompiled`);

    try {
      console.log(`[JADX] 开始反编译APK: ${apkPath}`);
      console.log(`[JADX] 输出目录: ${outputDir}`);

      // 创建输出目录
      if (!existsSync(outputDir)) {
        mkdirSync(outputDir, { recursive: true });
      }

      // 构建JADX命令
      const jadxCommand = this.buildJADXCommand(apkPath, outputDir, options);
      console.log(`[JADX] 执行命令: ${jadxCommand}`);

      // 执行反编译 (设置较长的超时时间，因为反编译可能很耗时)
      const output = await execAsync(jadxCommand, { 
        timeout: 300000, // 5分钟超时
        maxBuffer: 1024 * 1024 * 10 // 10MB buffer
      });

      const duration = Date.now() - startTime;
      console.log(`[JADX] 反编译完成，耗时: ${duration}ms`);

      // 分析输出结果
      const stats = await this.analyzeOutput(outputDir);
      const summary = this.generateSummary(stats, outputDir);

      return {
        success: true,
        outputPath: outputDir,
        apkPath,
        duration,
        filesGenerated: stats.totalFiles,
        classesCount: stats.javaFiles,
        resourcesCount: stats.resourceFiles,
        summary
      };

    } catch (error: any) {
      console.error(`[JADX] 反编译失败:`, error);
      
      // 尝试解析错误信息
      let errorMsg = error.message;
      if (error.stdout) {
        errorMsg += `\nSTDOUT: ${error.stdout}`;
      }
      if (error.stderr) {
        errorMsg += `\nSTDERR: ${error.stderr}`;
      }

      return {
        success: false,
        apkPath,
        duration: Date.now() - startTime,
        error: `JADX反编译失败: ${errorMsg}`
      };
    }
  }

  private buildJADXCommand(apkPath: string, outputDir: string, options: JADXDecompileOptions): string {
    const args: string[] = [];
    
    // 基本参数
    args.push('-d', `"${outputDir}"`);
    
    // 可选参数
    if (options.showBadCode) {
      args.push('--show-bad-code');
    }
    
    if (options.noReplace) {
      args.push('--no-replace');
    }
    
    if (options.escapeUnicode) {
      args.push('--escape-unicode');
    }
    
    if (options.respectBytecodeAccess) {
      args.push('--respect-bytecode-access-modifiers');
    }
    
    if (options.deobfuscation) {
      args.push('--deobf');
    }
    
    if (options.useKotlinMetadata) {
      args.push('--use-kotlin-metadata');
    }
    
    if (options.threadsCount && options.threadsCount > 0) {
      args.push('-j', options.threadsCount.toString());
    }
    
    if (options.verbose) {
      args.push('-v');
    }

    // APK文件路径
    args.push(`"${apkPath}"`);

    return `"${this.jadxPath}" ${args.join(' ')}`;
  }

  private async analyzeOutput(outputDir: string): Promise<JADXStats> {
    const stats: JADXStats = {
      javaFiles: 0,
      smaliFiles: 0,
      resourceFiles: 0,
      totalFiles: 0,
      directories: 0,
      manifestExists: false
    };

    if (!existsSync(outputDir)) {
      return stats;
    }

    try {
      // 检查AndroidManifest.xml
      const manifestPath = join(outputDir, 'AndroidManifest.xml');
      stats.manifestExists = existsSync(manifestPath);

      // 递归统计文件
      this.countFilesRecursive(outputDir, stats);
      
    } catch (error) {
      console.warn(`[JADX] 分析输出目录失败: ${error}`);
    }

    return stats;
  }

  private countFilesRecursive(dir: string, stats: JADXStats): void {
    try {
      const items = readdirSync(dir, { withFileTypes: true });
      
      for (const item of items) {
        const fullPath = join(dir, item.name);
        
        if (item.isDirectory()) {
          stats.directories++;
          this.countFilesRecursive(fullPath, stats);
        } else if (item.isFile()) {
          stats.totalFiles++;
          
          const ext = extname(item.name).toLowerCase();
          if (ext === '.java') {
            stats.javaFiles++;
          } else if (ext === '.smali') {
            stats.smaliFiles++;
          } else if (['.xml', '.png', '.jpg', '.jpeg', '.json', '.txt', '.properties'].includes(ext)) {
            stats.resourceFiles++;
          }
        }
      }
    } catch (error) {
      console.warn(`[JADX] 无法读取目录 ${dir}: ${error}`);
    }
  }

  private generateSummary(stats: JADXStats, outputDir: string): any {
    try {
      // 计算目录大小 (简单估算)
      const sizeBytes = this.calculateDirectorySize(outputDir);
      const sizeStr = this.formatBytes(sizeBytes);

      return {
        javaFiles: stats.javaFiles,
        resourceFiles: stats.resourceFiles,
        manifestFound: stats.manifestExists,
        totalSize: sizeStr
      };
    } catch (error) {
      return {
        javaFiles: stats.javaFiles,
        resourceFiles: stats.resourceFiles,
        manifestFound: stats.manifestExists,
        totalSize: '未知'
      };
    }
  }

  private calculateDirectorySize(dirPath: string): number {
    let totalSize = 0;
    
    try {
      const items = readdirSync(dirPath, { withFileTypes: true });
      
      for (const item of items) {
        const fullPath = join(dirPath, item.name);
        
        if (item.isFile()) {
          totalSize += statSync(fullPath).size;
        } else if (item.isDirectory()) {
          totalSize += this.calculateDirectorySize(fullPath);
        }
      }
    } catch (error) {
      // 忽略错误
    }
    
    return totalSize;
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // 获取反编译结果的关键信息
  async getDecompiledInfo(outputDir: string): Promise<any> {
    if (!existsSync(outputDir)) {
      throw new Error(`反编译输出目录不存在: ${outputDir}`);
    }

    const stats = await this.analyzeOutput(outputDir);
    const manifestPath = join(outputDir, 'AndroidManifest.xml');
    
    // 查找主要的Java包
    const sourcesDir = join(outputDir, 'sources');
    let mainPackages: string[] = [];
    
    if (existsSync(sourcesDir)) {
      try {
        mainPackages = readdirSync(sourcesDir, { withFileTypes: true })
          .filter(item => item.isDirectory())
          .map(item => item.name)
          .slice(0, 10); // 最多显示10个主要包
      } catch (error) {
        console.warn(`[JADX] 无法读取源码目录: ${error}`);
      }
    }

    return {
      stats,
      outputPath: outputDir,
      manifestExists: existsSync(manifestPath),
      mainPackages,
      sourcesPath: sourcesDir,
      resourcesPath: join(outputDir, 'resources')
    };
  }

  // 清理反编译输出
  async cleanOutput(outputDir: string): Promise<void> {
    if (!existsSync(outputDir)) {
      return;
    }

    try {
      rmSync(outputDir, { recursive: true, force: true });
      console.log(`[JADX] 已清理输出目录: ${outputDir}`);
    } catch (error) {
      console.warn(`[JADX] 清理输出目录失败: ${error}`);
    }
  }

  // 验证APK文件
  async validateAPK(apkPath: string): Promise<{ valid: boolean; error?: string }> {
    if (!existsSync(apkPath)) {
      return { valid: false, error: 'APK文件不存在' };
    }

    try {
      const stats = statSync(apkPath);
      if (!stats.isFile()) {
        return { valid: false, error: '路径不是文件' };
      }

      if (extname(apkPath).toLowerCase() !== '.apk') {
        return { valid: false, error: '文件扩展名不是.apk' };
      }

      // 简单的APK头验证 (检查是否是ZIP格式)
      const fs = await import('fs');
      const buffer = Buffer.alloc(4);
      const fd = fs.openSync(apkPath, 'r');
      fs.readSync(fd, buffer, 0, 4, 0);
      fs.closeSync(fd);
      
      // ZIP文件魔数: 50 4B 03 04
      const zipSignature = Buffer.from([0x50, 0x4B, 0x03, 0x04]);
      if (!buffer.equals(zipSignature)) {
        return { valid: false, error: 'APK文件格式无效（不是有效的ZIP文件）' };
      }

      return { valid: true };
    } catch (error: any) {
      return { valid: false, error: `APK验证失败: ${error.message}` };
    }
  }
}

// 全局JADX管理器
export const globalJADXManager = new JADXManager();
