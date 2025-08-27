#!/usr/bin/env node
// 环境依赖检查脚本

import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { join } from 'path';

const execAsync = promisify(exec);

console.log('🔍 检查移动端App测试MCP环境依赖...\n');

const checks = [];

// 检查Node.js版本
async function checkNodeVersion() {
  try {
    const version = process.version.slice(1); // 移除'v'
    const major = parseInt(version.split('.')[0]);
    
    if (major >= 18) {
      console.log(`✅ Node.js: ${process.version}`);
      return true;
    } else {
      console.log(`❌ Node.js: ${process.version} (需要 18.0+)`);
      return false;
    }
  } catch (error) {
    console.log(`❌ Node.js: 检查失败`);
    return false;
  }
}

// 检查ADB
async function checkADB() {
  try {
    const { stdout } = await execAsync('adb version');
    console.log(`✅ ADB: ${stdout.split('\n')[0]}`);
    return true;
  } catch (error) {
    console.log(`❌ ADB: 未找到或无法执行`);
    console.log(`   安装方法: 下载 Android SDK Platform Tools`);
    return false;
  }
}

// 检查AAPT
async function checkAAPT() {
  try {
    // 先检查环境变量中的路径
    if (process.env.ANDROID_HOME) {
      const aaptPath = join(process.env.ANDROID_HOME, 'build-tools');
      if (existsSync(aaptPath)) {
        console.log(`✅ AAPT: 在 Android SDK 中找到`);
        return true;
      }
    }
    
    // 检查系统PATH
    const { stdout } = await execAsync('aapt version');
    console.log(`✅ AAPT: ${stdout.split('\n')[0]}`);
    return true;
  } catch (error) {
    console.log(`❌ AAPT: 未找到`);
    console.log(`   需要: Android SDK Build Tools`);
    return false;
  }
}

// 检查JADX
async function checkJADX() {
  // 检查项目本地JADX
  const localJadx = join(process.cwd(), 'jadx', 'bin', 'jadx');
  if (existsSync(localJadx)) {
    console.log(`✅ JADX: 项目本地版本`);
    return true;
  }
  
  // 检查系统JADX
  try {
    const { stdout } = await execAsync('jadx --version');
    console.log(`✅ JADX: 系统版本`);
    return true;
  } catch (error) {
    console.log(`⚠️  JADX: 未找到 (可选)`);
    console.log(`   安装: 运行 scripts/setup.sh 或手动下载`);
    return null; // null表示可选依赖
  }
}

// 检查Frida
async function checkFrida() {
  try {
    const { stdout } = await execAsync('frida --version');
    console.log(`✅ Frida: ${stdout.trim()}`);
    return true;
  } catch (error) {
    console.log(`⚠️  Frida: 未找到 (可选)`);
    console.log(`   安装: pip install frida-tools`);
    return null; // null表示可选依赖
  }
}

// 检查Android SDK环境变量
function checkAndroidSDK() {
  if (process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT) {
    const sdkPath = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT;
    console.log(`✅ Android SDK: ${sdkPath}`);
    return true;
  } else {
    console.log(`⚠️  Android SDK: 环境变量未设置`);
    console.log(`   建议设置 ANDROID_HOME 或 ANDROID_SDK_ROOT`);
    return false;
  }
}

// 运行所有检查
async function runAllChecks() {
  const results = {
    node: await checkNodeVersion(),
    adb: await checkADB(),
    aapt: await checkAAPT(),
    jadx: await checkJADX(),
    frida: await checkFrida(),
    androidSDK: checkAndroidSDK()
  };
  
  console.log('\n📊 检查结果汇总:');
  
  const required = ['node', 'adb'];
  const optional = ['jadx', 'frida'];
  const recommended = ['aapt', 'androidSDK'];
  
  let allRequiredOk = true;
  
  console.log('\n🔴 必需依赖:');
  for (const key of required) {
    const status = results[key] ? '✅' : '❌';
    console.log(`  ${status} ${key}`);
    if (!results[key]) allRequiredOk = false;
  }
  
  console.log('\n🟡 推荐依赖:');
  for (const key of recommended) {
    const status = results[key] ? '✅' : '⚠️ ';
    console.log(`  ${status} ${key}`);
  }
  
  console.log('\n🟢 可选依赖:');
  for (const key of optional) {
    const status = results[key] === true ? '✅' : 
                   results[key] === null ? '⚠️ ' : '❌';
    console.log(`  ${status} ${key}`);
  }
  
  if (allRequiredOk) {
    console.log('\n🎉 环境检查通过！可以启动 MCP 服务器。');
    console.log('运行命令: npm start');
  } else {
    console.log('\n❌ 存在必需依赖缺失，请先安装。');
    console.log('运行命令: scripts/setup.sh');
  }
  
  return allRequiredOk;
}

// 运行检查
runAllChecks().catch(console.error);