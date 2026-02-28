// AAPT (Android Asset Packaging Tool) 管理器
// 用于APK分析和元数据提取

import { execSync, exec } from 'child_process';
import { promisify } from 'util';
import { existsSync, statSync, readFileSync, readdirSync } from 'fs';
import { join, dirname, basename, extname } from 'path';
import { globalLogger } from './logger.js';
import { getEnvValue, loadProjectEnv } from './env-utils.js';

const execAsync = promisify(exec);

export interface APKBadging {
  packageName?: string;
  versionCode?: string;
  versionName?: string;
  compileSdkVersion?: string;
  compileSdkVersionCodename?: string;
  platformBuildVersionName?: string;
  platformBuildVersionCode?: string;
  minSdkVersion?: string;
  targetSdkVersion?: string;
  maxSdkVersion?: string;
  installLocation?: string;
  applicationLabel?: string;
  applicationIcon?: string;
  applicationDebugable?: boolean;
  permissions?: string[];
  usesPermissions?: string[];
  usesFeatures?: string[];
  usesLibrary?: string[];
  supportScreens?: {
    small?: boolean;
    normal?: boolean;
    large?: boolean;
    xlarge?: boolean;
    anyDensity?: boolean;
    requiresSmallestWidthDp?: number;
    compatibleWidthLimitDp?: number;
    largestWidthLimitDp?: number;
  };
  densities?: string[];
  nativeCode?: string[];
  alternativeNativeCode?: string[];
}

export interface APKPermissions {
  name: string;
  protectionLevel?: string;
  label?: string;
  description?: string;
}

export interface APKResources {
  resources: Array<{
    type: string;
    name: string;
    value?: string;
    config?: string;
  }>;
  configurations?: string[];
}

export interface APKAnalysisResult {
  success: boolean;
  apkPath: string;
  badging?: APKBadging;
  permissions?: APKPermissions[];
  resources?: APKResources;
  xmlTrees?: { [filename: string]: string };
  error?: string;
}

export class AAPTManager {
  private aaptPath: string | null = null;
  
  constructor() {
    loadProjectEnv();
    this.detectAAPTPath();
  }

  private detectAAPTPath(): void {
    const possiblePaths: string[] = [
      // 显式配置优先
      getEnvValue('AAPT_PATH'),
      // Android SDK 标准路径
      process.env.ANDROID_HOME ? join(process.env.ANDROID_HOME, 'build-tools') : null,
      process.env.ANDROID_SDK_ROOT ? join(process.env.ANDROID_SDK_ROOT, 'build-tools') : null,
      // Homebrew 安装路径 (macOS)
      '/opt/homebrew/bin/aapt',
      '/usr/local/bin/aapt',
      // Windows 常见路径
      process.env.LOCALAPPDATA ? join(process.env.LOCALAPPDATA, 'Android', 'Sdk', 'build-tools') : null,
      process.env.ANDROID_HOME ? join(process.env.ANDROID_HOME, 'build-tools', 'aapt.exe') : null,
      process.env.ANDROID_SDK_ROOT ? join(process.env.ANDROID_SDK_ROOT, 'build-tools', 'aapt.exe') : null,
      // 系统PATH中的aapt
      'aapt'
    ].filter((value): value is string => Boolean(value));

    for (const path of possiblePaths) {
      try {
        if (path && path.includes('build-tools') && !path.endsWith('.exe')) {
          // 在build-tools目录中查找最新版本的aapt
          const buildToolsPath = this.findLatestBuildTools(path);
          if (buildToolsPath) {
            const candidates = [join(buildToolsPath, 'aapt'), join(buildToolsPath, 'aapt.exe')];
            for (const aaptBinary of candidates) {
              if (existsSync(aaptBinary)) {
                execSync(`"${aaptBinary}" version`, { stdio: 'ignore' });
                this.aaptPath = aaptBinary;
                console.log(`[AAPT] 找到AAPT: ${aaptBinary}`);
                return;
              }
            }
          }
        } else {
          // 直接测试aapt命令
          const cmd = path === 'aapt' ? 'aapt version' : `"${path}" version`;
          execSync(cmd, { stdio: 'ignore' });
          this.aaptPath = path;
          console.log(`[AAPT] 找到AAPT: ${path}`);
          return;
        }
      } catch (error) {
        // 忽略错误，继续尝试下一个路径
      }
    }

    console.warn('[AAPT] 未找到AAPT工具，APK分析功能将不可用');
    console.warn('[AAPT] 请安装Android SDK或单独安装aapt工具');
  }

  private findLatestBuildTools(buildToolsDir: string): string | null {
    try {
      if (!existsSync(buildToolsDir)) {
        return null;
      }

      const versions = readdirSync(buildToolsDir, { withFileTypes: true })
        .filter(item => item.isDirectory())
        .map(item => item.name)
        .filter(version => version.match(/^\d+\.\d+/))
        .sort((a, b) => {
          const parseVersion = (v: string) => v.split('.').map(n => parseInt(n, 10));
          const versionA = parseVersion(a);
          const versionB = parseVersion(b);
          
          for (let i = 0; i < Math.max(versionA.length, versionB.length); i++) {
            const numA = versionA[i] || 0;
            const numB = versionB[i] || 0;
            if (numA !== numB) return numB - numA; // 降序排列
          }
          return 0;
        });

      if (versions.length > 0) {
        return join(buildToolsDir, versions[0]);
      }
    } catch (error) {
      console.warn(`[AAPT] 无法枚举build-tools目录: ${error}`);
    }

    return null;
  }

  async isAvailable(): Promise<boolean> {
    return this.aaptPath !== null;
  }

  async getVersion(): Promise<string | null> {
    if (!this.aaptPath) {
      return null;
    }

    try {
      const output = await execAsync(`"${this.aaptPath}" version`);
      return output.stdout.trim();
    } catch (error) {
      console.error(`[AAPT] 获取版本失败: ${error}`);
      return null;
    }
  }

  async dumpBadging(apkPath: string): Promise<APKBadging> {
    if (!this.aaptPath) {
      throw new Error('AAPT工具不可用，请安装Android SDK');
    }

    if (!existsSync(apkPath)) {
      throw new Error(`APK文件不存在: ${apkPath}`);
    }

    try {
      console.log(`[AAPT] 分析APK badging: ${apkPath}`);
      const output = await execAsync(`"${this.aaptPath}" dump badging "${apkPath}"`);
      
      return this.parseBadgingOutput(output.stdout);
    } catch (error: any) {
      throw new Error(`AAPT badging 分析失败: ${error.message}`);
    }
  }

  async dumpPermissions(apkPath: string): Promise<APKPermissions[]> {
    if (!this.aaptPath) {
      throw new Error('AAPT工具不可用，请安装Android SDK');
    }

    if (!existsSync(apkPath)) {
      throw new Error(`APK文件不存在: ${apkPath}`);
    }

    try {
      console.log(`[AAPT] 分析APK permissions: ${apkPath}`);
      const output = await execAsync(`"${this.aaptPath}" dump permissions "${apkPath}"`);
      
      return this.parsePermissionsOutput(output.stdout);
    } catch (error: any) {
      throw new Error(`AAPT permissions 分析失败: ${error.message}`);
    }
  }

  async dumpResources(apkPath: string): Promise<APKResources> {
    if (!this.aaptPath) {
      throw new Error('AAPT工具不可用，请安装Android SDK');
    }

    if (!existsSync(apkPath)) {
      throw new Error(`APK文件不存在: ${apkPath}`);
    }

    try {
      console.log(`[AAPT] 分析APK resources: ${apkPath}`);
      const output = await execAsync(`"${this.aaptPath}" dump resources "${apkPath}"`);
      
      return this.parseResourcesOutput(output.stdout);
    } catch (error: any) {
      throw new Error(`AAPT resources 分析失败: ${error.message}`);
    }
  }

  async dumpXmlTree(apkPath: string, xmlFile: string): Promise<string> {
    if (!this.aaptPath) {
      throw new Error('AAPT工具不可用，请安装Android SDK');
    }

    if (!existsSync(apkPath)) {
      throw new Error(`APK文件不存在: ${apkPath}`);
    }

    try {
      console.log(`[AAPT] 分析XML树结构: ${xmlFile}`);
      const output = await execAsync(`"${this.aaptPath}" dump xmltree "${apkPath}" "${xmlFile}"`);
      
      return output.stdout;
    } catch (error: any) {
      throw new Error(`AAPT xmltree 分析失败: ${error.message}`);
    }
  }

  async analyzeAPK(apkPath: string, options: {
    includeBadging?: boolean;
    includePermissions?: boolean;
    includeResources?: boolean;
    includeXmlTrees?: string[];
  } = {}): Promise<APKAnalysisResult> {
    const {
      includeBadging = true,
      includePermissions = true,
      includeResources = false,
      includeXmlTrees = ['AndroidManifest.xml']
    } = options;

    try {
      const result: APKAnalysisResult = {
        success: true,
        apkPath
      };

      // 1. Badging 信息 (基本APK信息)
      if (includeBadging) {
        result.badging = await this.dumpBadging(apkPath);
      }

      // 2. 权限信息
      if (includePermissions) {
        result.permissions = await this.dumpPermissions(apkPath);
      }

      // 3. 资源信息 (可选，通常很大)
      if (includeResources) {
        result.resources = await this.dumpResources(apkPath);
      }

      // 4. XML树结构
      if (includeXmlTrees && includeXmlTrees.length > 0) {
        result.xmlTrees = {};
        for (const xmlFile of includeXmlTrees) {
          try {
            result.xmlTrees[xmlFile] = await this.dumpXmlTree(apkPath, xmlFile);
          } catch (error) {
            console.warn(`[AAPT] 无法分析XML文件 ${xmlFile}: ${error}`);
          }
        }
      }

      console.log(`[AAPT] APK分析完成: ${apkPath}`);
      return result;

    } catch (error: any) {
      return {
        success: false,
        apkPath,
        error: error.message
      };
    }
  }

  private parseBadgingOutput(output: string): APKBadging {
    const badging: APKBadging = {
      permissions: [],
      usesPermissions: [],
      usesFeatures: [],
      usesLibrary: [],
      densities: [],
      nativeCode: [],
      alternativeNativeCode: []
    };

    const lines = output.split('\n');
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      if (trimmed.startsWith('package:')) {
        const match = trimmed.match(/name='([^']+)'/);
        if (match) badging.packageName = match[1];
        
        const versionCode = trimmed.match(/versionCode='([^']+)'/);
        if (versionCode) badging.versionCode = versionCode[1];
        
        const versionName = trimmed.match(/versionName='([^']+)'/);
        if (versionName) badging.versionName = versionName[1];
        
        const compileSdkVersion = trimmed.match(/compileSdkVersion='([^']+)'/);
        if (compileSdkVersion) badging.compileSdkVersion = compileSdkVersion[1];
        
        const platformBuildVersionName = trimmed.match(/platformBuildVersionName='([^']+)'/);
        if (platformBuildVersionName) badging.platformBuildVersionName = platformBuildVersionName[1];
      }
      
      else if (trimmed.startsWith('sdkVersion:')) {
        const match = trimmed.match(/sdkVersion:'([^']+)'/);
        if (match) badging.minSdkVersion = match[1];
      }
      
      else if (trimmed.startsWith('targetSdkVersion:')) {
        const match = trimmed.match(/targetSdkVersion:'([^']+)'/);
        if (match) badging.targetSdkVersion = match[1];
      }
      
      else if (trimmed.startsWith('maxSdkVersion:')) {
        const match = trimmed.match(/maxSdkVersion:'([^']+)'/);
        if (match) badging.maxSdkVersion = match[1];
      }
      
      else if (trimmed.startsWith('install-location:')) {
        const match = trimmed.match(/install-location:'([^']+)'/);
        if (match) badging.installLocation = match[1];
      }
      
      else if (trimmed.startsWith('application-label:')) {
        const match = trimmed.match(/application-label:'([^']+)'/);
        if (match) badging.applicationLabel = match[1];
      }
      
      else if (trimmed.startsWith('application-icon-')) {
        const match = trimmed.match(/application-icon-\d+:'([^']+)'/);
        if (match && !badging.applicationIcon) {
          badging.applicationIcon = match[1];
        }
      }
      
      else if (trimmed.startsWith('application-debuggable')) {
        badging.applicationDebugable = true;
      }
      
      else if (trimmed.startsWith('uses-permission:')) {
        const match = trimmed.match(/uses-permission: name='([^']+)'/);
        if (match) badging.usesPermissions?.push(match[1]);
      }
      
      else if (trimmed.startsWith('uses-feature:')) {
        const match = trimmed.match(/uses-feature: name='([^']+)'/);
        if (match) badging.usesFeatures?.push(match[1]);
      }
      
      else if (trimmed.startsWith('uses-library:')) {
        const match = trimmed.match(/uses-library:'([^']+)'/);
        if (match) badging.usesLibrary?.push(match[1]);
      }
      
      else if (trimmed.startsWith('densities:')) {
        const match = trimmed.match(/densities: '([^']+)'/);
        if (match) {
          badging.densities = match[1].split(' ').filter(d => d.trim());
        }
      }
      
      else if (trimmed.startsWith('native-code:')) {
        const match = trimmed.match(/native-code: '([^']+)'/);
        if (match) {
          badging.nativeCode = match[1].split(' ').filter(c => c.trim());
        }
      }
      
      else if (trimmed.startsWith('alt-native-code:')) {
        const match = trimmed.match(/alt-native-code: '([^']+)'/);
        if (match) {
          badging.alternativeNativeCode = match[1].split(' ').filter(c => c.trim());
        }
      }
    }

    return badging;
  }

  private parsePermissionsOutput(output: string): APKPermissions[] {
    const permissions: APKPermissions[] = [];
    const lines = output.split('\n');
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      if (trimmed.startsWith('permission:')) {
        const match = trimmed.match(/permission: ([^\s]+)/);
        if (match) {
          const permission: APKPermissions = {
            name: match[1]
          };
          
          const protectionLevel = trimmed.match(/protectionLevel=([^\s]+)/);
          if (protectionLevel) {
            permission.protectionLevel = protectionLevel[1];
          }
          
          permissions.push(permission);
        }
      }
    }

    return permissions;
  }

  private parseResourcesOutput(output: string): APKResources {
    const resources: APKResources = {
      resources: [],
      configurations: []
    };

    const lines = output.split('\n');
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      // 这里可以添加更详细的资源解析逻辑
      // AAPT resources输出格式比较复杂，根据需要解析
      
      if (trimmed.startsWith('config ')) {
        const config = trimmed.replace('config ', '').replace(':', '');
        if (!resources.configurations?.includes(config)) {
          resources.configurations?.push(config);
        }
      }
    }

    return resources;
  }

  // 验证APK文件是否有效
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

      // 尝试读取APK的基本信息来验证
      await this.dumpBadging(apkPath);
      
      return { valid: true };
    } catch (error: any) {
      return { valid: false, error: `APK验证失败: ${error.message}` };
    }
  }
}

// 全局AAPT管理器
export const globalAAPTManager = new AAPTManager();
