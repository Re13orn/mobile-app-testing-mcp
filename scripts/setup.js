#!/usr/bin/env node

import { spawnSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';
import { getEnvValue, getProjectRoot, loadProjectEnv } from './env-utils.js';

loadProjectEnv();
const projectRoot = getProjectRoot();
process.chdir(projectRoot);

const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    stdio: 'inherit',
    shell: false,
    ...options
  });

  if (typeof result.status === 'number' && result.status !== 0) {
    throw new Error(`命令执行失败: ${command} ${args.join(' ')}`);
  }
}

function detectCommand(command, args = ['--version']) {
  const result = spawnSync(command, args, { stdio: 'pipe', encoding: 'utf8', shell: false });
  return result.status === 0;
}

function printSection(title) {
  console.log(`\n${title}`);
}

function checkNodeVersion() {
  const raw = process.version;
  const major = parseInt(raw.replace(/^v/, '').split('.')[0], 10);
  if (Number.isNaN(major) || major < 18) {
    throw new Error(`Node.js 版本过低: ${raw}，需要 >= 18`);
  }
  console.log(`✅ Node.js: ${raw}`);
}

function checkAndroidSdk() {
  const sdkPath = getEnvValue('ANDROID_HOME', 'ANDROID_SDK_ROOT');
  if (!sdkPath) {
    console.log('⚠️  未设置 ANDROID_HOME / ANDROID_SDK_ROOT');
    console.log('   请在 .env 或系统环境变量中配置 Android SDK 路径');
    return;
  }

  const platformTools = join(sdkPath, 'platform-tools');
  const buildTools = join(sdkPath, 'build-tools');
  const platformToolsOk = existsSync(platformTools);
  const buildToolsOk = existsSync(buildTools);

  console.log(`✅ Android SDK: ${sdkPath}`);
  if (!platformToolsOk) {
    console.log(`⚠️  未找到 platform-tools: ${platformTools}`);
  }
  if (!buildToolsOk) {
    console.log(`⚠️  未找到 build-tools: ${buildTools}`);
  }
}

function main() {
  console.log('🚀 开始初始化移动端App测试MCP...');
  checkNodeVersion();

  printSection('📦 安装依赖');
  runCommand(npmCmd, ['install']);

  printSection('🔨 构建项目');
  runCommand(npmCmd, ['run', 'build']);

  printSection('🔍 环境检测');
  const adbPath = getEnvValue('ADB_PATH') || 'adb';
  const aaptPath = getEnvValue('AAPT_PATH') || 'aapt';
  const jadxPath = getEnvValue('JADX_PATH') || 'jadx';

  console.log(detectCommand(adbPath, ['version']) ? `✅ ADB: ${adbPath}` : `⚠️  ADB 未找到: ${adbPath}`);
  console.log(detectCommand(aaptPath, ['version']) ? `✅ AAPT: ${aaptPath}` : `⚠️  AAPT 未找到: ${aaptPath} (可选)`);
  console.log(detectCommand(jadxPath, ['--version']) ? `✅ JADX: ${jadxPath}` : `⚠️  JADX 未找到: ${jadxPath} (可选)`);

  checkAndroidSdk();

  printSection('🎉 初始化完成');
  console.log('下一步:');
  console.log('1. npm run check');
  console.log('2. 配置 Claude Desktop MCP（README 有完整示例）');
  console.log('3. npm start');
}

try {
  main();
} catch (error) {
  console.error(`\n❌ 初始化失败: ${error.message}`);
  process.exit(1);
}
