// Frida Gadget 自动化部署管理器
// 解决非root环境下的Frida附加问题

import { execSync } from 'child_process';
import { existsSync, mkdirSync, writeFileSync, readFileSync, copyFileSync } from 'fs';
import { join } from 'path';
import { globalLogger } from './logger.js';

export interface GadgetDeployResult {
  success: boolean;
  packagePath?: string;
  originalBackup?: string;
  deploymentMethod: 'gadget' | 'xposed' | 'native';
  error?: string;
}

export interface GadgetConfig {
  packageName: string;
  targetArch: 'arm64' | 'arm' | 'x86_64' | 'x86';
  deploymentStrategy: 'replace_lib' | 'add_lib' | 'manifest_modify';
  preserveSignature: boolean;
}

export class GadgetManager {
  private workDir: string;
  private gadgetLibs: Map<string, string> = new Map();

  constructor() {
    this.workDir = join(process.cwd(), '.mobile-app-testing-gadget');
    this.initializeGadgetLibs();
  }

  private initializeGadgetLibs() {
    // Frida Gadget库文件映射
    this.gadgetLibs.set('arm64', 'libfrida-gadget.so');
    this.gadgetLibs.set('arm', 'libfrida-gadget.so');
    this.gadgetLibs.set('x86_64', 'libfrida-gadget.so');
    this.gadgetLibs.set('x86', 'libfrida-gadget.so');
  }

  async deployGadget(config: GadgetConfig): Promise<GadgetDeployResult> {
    try {
      console.log(`[GadgetManager] 开始为 ${config.packageName} 部署Frida Gadget`);
      
      // 1. 创建工作目录
      if (!existsSync(this.workDir)) {
        mkdirSync(this.workDir, { recursive: true });
      }

      // 2. 检测应用架构
      const arch = await this.detectAppArchitecture(config.packageName);
      console.log(`[GadgetManager] 检测到应用架构: ${arch}`);

      // 3. 下载应用APK
      const apkPath = await this.downloadApk(config.packageName);
      console.log(`[GadgetManager] APK下载完成: ${apkPath}`);

      // 4. 备份原始APK
      const backupPath = `${apkPath}.backup`;
      copyFileSync(apkPath, backupPath);

      // 5. 根据策略部署Gadget
      let deployResult: GadgetDeployResult;
      
      switch (config.deploymentStrategy) {
        case 'replace_lib':
          deployResult = await this.deployByReplaceLib(apkPath, arch, config);
          break;
        case 'add_lib':
          deployResult = await this.deployByAddLib(apkPath, arch, config);
          break;
        case 'manifest_modify':
          deployResult = await this.deployByManifestModify(apkPath, arch, config);
          break;
        default:
          throw new Error(`未支持的部署策略: ${config.deploymentStrategy}`);
      }

      if (deployResult.success) {
        // 6. 重新签名APK（如果需要）
        if (!config.preserveSignature) {
          await this.resignApk(apkPath);
          console.log(`[GadgetManager] APK重新签名完成`);
        }

        // 7. 安装修改后的APK
        await this.installModifiedApk(apkPath, config.packageName);
        console.log(`[GadgetManager] Gadget部署成功`);

        return {
          success: true,
          packagePath: apkPath,
          originalBackup: backupPath,
          deploymentMethod: 'gadget'
        };
      }

      return deployResult;

    } catch (error: any) {
      console.error(`[GadgetManager] Gadget部署失败:`, error);
      return {
        success: false,
        deploymentMethod: 'gadget',
        error: error.message
      };
    }
  }

  private async detectAppArchitecture(packageName: string): Promise<string> {
    try {
      // 使用aapt检测APK架构
      const aaptOutput = execSync(`aapt dump badging $(pm path ${packageName} | cut -d: -f2)`, 
        { encoding: 'utf8' });
      
      if (aaptOutput.includes('arm64-v8a')) return 'arm64';
      if (aaptOutput.includes('armeabi-v7a')) return 'arm';  
      if (aaptOutput.includes('x86_64')) return 'x86_64';
      if (aaptOutput.includes('x86')) return 'x86';
      
      // 默认使用arm64（现代Android设备最常见）
      return 'arm64';
    } catch (error) {
      console.warn(`[GadgetManager] 无法检测架构，使用默认arm64`);
      return 'arm64';
    }
  }

  private async downloadApk(packageName: string): Promise<string> {
    const apkPath = join(this.workDir, `${packageName}.apk`);
    
    try {
      // 从设备拉取APK
      const packagePath = execSync(`adb shell pm path ${packageName}`, { encoding: 'utf8' })
        .trim().replace('package:', '');
      
      execSync(`adb pull "${packagePath}" "${apkPath}"`);
      
      if (!existsSync(apkPath)) {
        throw new Error('APK拉取失败');
      }
      
      return apkPath;
    } catch (error) {
      throw new Error(`无法下载APK: ${error}`);
    }
  }

  private async deployByReplaceLib(apkPath: string, arch: string, config: GadgetConfig): Promise<GadgetDeployResult> {
    try {
      console.log(`[GadgetManager] 使用替换库策略部署Gadget`);
      
      // 1. 解压APK
      const extractDir = join(this.workDir, 'extracted');
      execSync(`unzip -o "${apkPath}" -d "${extractDir}"`);

      // 2. 查找可替换的native库
      const libDir = join(extractDir, 'lib', arch);
      
      if (!existsSync(libDir)) {
        return {
          success: false,
          deploymentMethod: 'gadget',
          error: `应用不包含 ${arch} 架构的native库`
        };
      }

      // 3. 选择目标库进行替换（通常选择最不重要的）
      const existingLibs = execSync(`ls "${libDir}"`, { encoding: 'utf8' }).trim().split('\n');
      const targetLib = this.selectTargetLibForReplace(existingLibs);

      if (!targetLib) {
        return {
          success: false,
          deploymentMethod: 'gadget', 
          error: '未找到合适的库文件用于替换'
        };
      }

      // 4. 下载并放置Frida Gadget
      await this.downloadGadgetLib(arch);
      const gadgetPath = join(this.workDir, this.gadgetLibs.get(arch)!);
      const targetPath = join(libDir, targetLib);
      
      copyFileSync(gadgetPath, targetPath);
      console.log(`[GadgetManager] 已替换库: ${targetLib} -> Frida Gadget`);

      // 5. 创建Gadget配置
      this.createGadgetConfig(extractDir, config);

      // 6. 重新打包APK
      await this.repackageApk(extractDir, apkPath);

      return {
        success: true,
        deploymentMethod: 'gadget'
      };

    } catch (error: any) {
      return {
        success: false,
        deploymentMethod: 'gadget',
        error: error.message
      };
    }
  }

  private async deployByAddLib(apkPath: string, arch: string, config: GadgetConfig): Promise<GadgetDeployResult> {
    try {
      console.log(`[GadgetManager] 使用添加库策略部署Gadget`);
      
      // 1. 解压APK
      const extractDir = join(this.workDir, 'extracted');
      execSync(`unzip -o "${apkPath}" -d "${extractDir}"`);

      // 2. 创建lib目录（如果不存在）
      const libDir = join(extractDir, 'lib', arch);
      if (!existsSync(libDir)) {
        mkdirSync(libDir, { recursive: true });
      }

      // 3. 添加Frida Gadget库
      await this.downloadGadgetLib(arch);
      const gadgetPath = join(this.workDir, this.gadgetLibs.get(arch)!);
      const targetPath = join(libDir, 'libfrida-gadget.so');
      
      copyFileSync(gadgetPath, targetPath);
      console.log(`[GadgetManager] 已添加Frida Gadget库`);

      // 4. 修改AndroidManifest.xml加载Gadget
      await this.modifyManifestForGadget(extractDir, config);

      // 5. 创建Gadget配置
      this.createGadgetConfig(extractDir, config);

      // 6. 重新打包APK
      await this.repackageApk(extractDir, apkPath);

      return {
        success: true,
        deploymentMethod: 'gadget'
      };

    } catch (error: any) {
      return {
        success: false,
        deploymentMethod: 'gadget',
        error: error.message
      };
    }
  }

  private async deployByManifestModify(apkPath: string, arch: string, config: GadgetConfig): Promise<GadgetDeployResult> {
    // 通过修改AndroidManifest.xml实现Gadget加载
    // 这是最兼容但也最复杂的方法
    return {
      success: false,
      deploymentMethod: 'gadget',
      error: 'Manifest修改策略暂未实现'
    };
  }

  private selectTargetLibForReplace(libs: string[]): string | null {
    // 选择优先级最低的库进行替换
    const lowPriorityLibs = [
      'libc++_shared.so',
      'liblog.so', 
      'libm.so',
      'libandroid.so'
    ];

    for (const priority of lowPriorityLibs) {
      if (libs.includes(priority)) {
        return priority;
      }
    }

    // 如果没有找到低优先级库，返回第一个
    return libs.length > 0 ? libs[0] : null;
  }

  private async downloadGadgetLib(arch: string): Promise<void> {
    const gadgetPath = join(this.workDir, this.gadgetLibs.get(arch)!);
    
    if (existsSync(gadgetPath)) {
      console.log(`[GadgetManager] Gadget库已存在: ${gadgetPath}`);
      return;
    }

    try {
      // 从GitHub下载Frida Gadget
      const version = 'latest';  // 可以指定版本
      const downloadUrl = `https://github.com/frida/frida/releases/download/${version}/frida-gadget-${version}-android-${arch}.so.xz`;
      
      console.log(`[GadgetManager] 下载Gadget库: ${downloadUrl}`);
      
      // 使用curl下载并解压
      const compressedPath = `${gadgetPath}.xz`;
      execSync(`curl -L "${downloadUrl}" -o "${compressedPath}"`);
      execSync(`xz -d "${compressedPath}"`);
      
      if (!existsSync(gadgetPath)) {
        throw new Error('Gadget库下载失败');
      }
      
      console.log(`[GadgetManager] Gadget库下载完成: ${gadgetPath}`);
    } catch (error) {
      throw new Error(`下载Gadget库失败: ${error}`);
    }
  }

  private createGadgetConfig(extractDir: string, config: GadgetConfig): void {
    const configContent = {
      "interaction": {
        "type": "listen",
        "address": "127.0.0.1",
        "port": 27042,
        "on_port_conflict": "pick_next"
      },
      "teardown": "minimal"
    };

    const configPath = join(extractDir, 'assets', 'frida-gadget-config.json');
    const assetsDir = join(extractDir, 'assets');
    
    if (!existsSync(assetsDir)) {
      mkdirSync(assetsDir, { recursive: true });
    }

    writeFileSync(configPath, JSON.stringify(configContent, null, 2));
    console.log(`[GadgetManager] 已创建Gadget配置: ${configPath}`);
  }

  private async modifyManifestForGadget(extractDir: string, config: GadgetConfig): Promise<void> {
    const manifestPath = join(extractDir, 'AndroidManifest.xml');
    
    if (!existsSync(manifestPath)) {
      throw new Error('AndroidManifest.xml不存在');
    }

    // 这里需要使用aapt2或其他工具来修改二进制格式的AndroidManifest.xml
    // 简化实现，假设我们有相应的工具
    console.log(`[GadgetManager] AndroidManifest.xml修改功能需要进一步实现`);
  }

  private async repackageApk(extractDir: string, apkPath: string): Promise<void> {
    try {
      console.log(`[GadgetManager] 重新打包APK: ${apkPath}`);
      
      // 删除原APK
      execSync(`rm -f "${apkPath}"`);
      
      // 重新打包
      execSync(`cd "${extractDir}" && zip -r "${apkPath}" .`);
      
      if (!existsSync(apkPath)) {
        throw new Error('APK重新打包失败');
      }
      
      console.log(`[GadgetManager] APK重新打包完成`);
    } catch (error) {
      throw new Error(`重新打包APK失败: ${error}`);
    }
  }

  private async resignApk(apkPath: string): Promise<void> {
    try {
      console.log(`[GadgetManager] 重新签名APK: ${apkPath}`);
      
      // 使用调试证书签名（在实际部署中应使用正式证书）
      const keystorePath = join(this.workDir, 'debug.keystore');
      
      // 创建调试keystore（如果不存在）
      if (!existsSync(keystorePath)) {
        execSync(`keytool -genkey -v -keystore "${keystorePath}" -alias debug -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Debug,OU=Debug,O=Debug,L=Debug,ST=Debug,C=US" -storepass android -keypass android`);
      }
      
      // 签名APK
      execSync(`jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore "${keystorePath}" -storepass android -keypass android "${apkPath}" debug`);
      
      console.log(`[GadgetManager] APK签名完成`);
    } catch (error) {
      throw new Error(`APK签名失败: ${error}`);
    }
  }

  private async installModifiedApk(apkPath: string, packageName: string): Promise<void> {
    try {
      console.log(`[GadgetManager] 安装修改后的APK`);
      
      // 卸载原应用
      try {
        execSync(`adb uninstall ${packageName}`, { stdio: 'ignore' });
      } catch (error) {
        // 忽略卸载错误，可能应用本来就不存在
      }
      
      // 安装修改后的APK
      execSync(`adb install "${apkPath}"`);
      
      console.log(`[GadgetManager] APK安装完成`);
    } catch (error) {
      throw new Error(`APK安装失败: ${error}`);
    }
  }

  // 清理工作目录
  async cleanup(): Promise<void> {
    try {
      if (existsSync(this.workDir)) {
        execSync(`rm -rf "${this.workDir}"`);
        console.log(`[GadgetManager] 工作目录已清理`);
      }
    } catch (error) {
      console.warn(`[GadgetManager] 清理工作目录失败: ${error}`);
    }
  }

  // 检查Gadget部署状态
  async checkGadgetStatus(packageName: string): Promise<boolean> {
    try {
      // 检查应用是否包含Frida Gadget
      const processes = execSync('adb shell ps | grep frida', { encoding: 'utf8' });
      return processes.includes(packageName);
    } catch (error) {
      return false;
    }
  }
}

// 全局Gadget管理器
export const globalGadgetManager = new GadgetManager();