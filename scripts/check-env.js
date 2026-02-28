#!/usr/bin/env node

import { existsSync, readdirSync } from 'fs';
import { join } from 'path';
import { spawnSync } from 'child_process';
import { getEnvValue, getProjectRoot, loadProjectEnv } from './env-utils.js';

loadProjectEnv();
process.chdir(getProjectRoot());

console.log('🔍 检查移动端App测试MCP环境依赖...\n');

function runVersionCommand(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', stdio: 'pipe', shell: false });
  return {
    ok: result.status === 0,
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim()
  };
}

function findLatestBuildTools(sdkPath) {
  const buildToolsDir = join(sdkPath, 'build-tools');
  if (!existsSync(buildToolsDir)) {
    return null;
  }

  const versions = readdirSync(buildToolsDir, { withFileTypes: true })
    .filter(item => item.isDirectory() && /^\d+\.\d+/.test(item.name))
    .map(item => item.name)
    .sort((a, b) => {
      const parse = value => value.split('.').map(num => parseInt(num, 10));
      const left = parse(a);
      const right = parse(b);
      const maxLen = Math.max(left.length, right.length);
      for (let i = 0; i < maxLen; i++) {
        const l = left[i] || 0;
        const r = right[i] || 0;
        if (l !== r) {
          return r - l;
        }
      }
      return 0;
    });

  return versions.length > 0 ? join(buildToolsDir, versions[0]) : null;
}

function checkNodeVersion() {
  const version = process.version.slice(1);
  const major = parseInt(version.split('.')[0], 10);
  if (major >= 18) {
    console.log(`✅ Node.js: ${process.version}`);
    return true;
  }
  console.log(`❌ Node.js: ${process.version} (需要 18.0+)`);
  return false;
}

function checkADB() {
  const adbPath = getEnvValue('ADB_PATH') || 'adb';
  const result = runVersionCommand(adbPath, ['version']);
  if (result.ok) {
    const firstLine = result.stdout.split('\n')[0];
    console.log(`✅ ADB: ${firstLine || adbPath}`);
    return true;
  }
  console.log(`❌ ADB: 未找到或无法执行 (${adbPath})`);
  console.log('   安装方法: Android SDK Platform Tools');
  return false;
}

function checkAAPT() {
  const configuredPath = getEnvValue('AAPT_PATH');
  if (configuredPath) {
    const result = runVersionCommand(configuredPath, ['version']);
    if (result.ok) {
      console.log(`✅ AAPT: ${result.stdout.split('\n')[0] || configuredPath}`);
      return true;
    }
  }

  const sdkPath = getEnvValue('ANDROID_HOME', 'ANDROID_SDK_ROOT');
  if (sdkPath) {
    const latestBuildTools = findLatestBuildTools(sdkPath);
    if (latestBuildTools) {
      const aaptCandidates = [join(latestBuildTools, 'aapt'), join(latestBuildTools, 'aapt.exe')];
      for (const candidate of aaptCandidates) {
        if (!existsSync(candidate)) {
          continue;
        }
        const result = runVersionCommand(candidate, ['version']);
        if (result.ok) {
          console.log(`✅ AAPT: ${candidate}`);
          return true;
        }
      }
    }
  }

  const result = runVersionCommand('aapt', ['version']);
  if (result.ok) {
    console.log(`✅ AAPT: ${result.stdout.split('\n')[0] || 'aapt'}`);
    return true;
  }

  console.log('⚠️  AAPT: 未找到 (推荐)');
  console.log('   需要 Android SDK Build Tools，或在 .env 中设置 AAPT_PATH');
  return false;
}

function checkJADX() {
  const configuredPath = getEnvValue('JADX_PATH');
  if (configuredPath) {
    const configured = runVersionCommand(configuredPath, ['--version']);
    if (configured.ok) {
      console.log(`✅ JADX: ${configuredPath}`);
      return true;
    }
  }

  const localCandidates = [
    join(process.cwd(), 'jadx', 'bin', 'jadx'),
    join(process.cwd(), 'jadx', 'bin', 'jadx.bat')
  ];
  for (const candidate of localCandidates) {
    if (!existsSync(candidate)) {
      continue;
    }
    const result = runVersionCommand(candidate, ['--version']);
    if (result.ok) {
      console.log(`✅ JADX: ${candidate}`);
      return true;
    }
  }

  const result = runVersionCommand('jadx', ['--version']);
  if (result.ok) {
    console.log('✅ JADX: 系统版本');
    return true;
  }

  console.log('⚠️  JADX: 未找到 (可选)');
  console.log('   安装后可启用 APK 反编译能力');
  return null;
}

function checkAndroidSDK() {
  const sdkPath = getEnvValue('ANDROID_HOME', 'ANDROID_SDK_ROOT');
  if (sdkPath) {
    console.log(`✅ Android SDK: ${sdkPath}`);
    return true;
  }
  console.log('⚠️  Android SDK: 环境变量未设置');
  console.log('   建议设置 ANDROID_HOME 或 ANDROID_SDK_ROOT（可写入 .env）');
  return false;
}

function summarize(results) {
  const required = ['node', 'adb'];
  const recommended = ['aapt', 'androidSDK'];
  const optional = ['jadx'];

  console.log('\n📊 检查结果汇总:');

  let requiredOk = true;
  console.log('\n🔴 必需依赖:');
  for (const key of required) {
    const ok = results[key] === true;
    console.log(`  ${ok ? '✅' : '❌'} ${key}`);
    if (!ok) {
      requiredOk = false;
    }
  }

  console.log('\n🟡 推荐依赖:');
  for (const key of recommended) {
    const ok = results[key] === true;
    console.log(`  ${ok ? '✅' : '⚠️ '} ${key}`);
  }

  console.log('\n🟢 可选依赖:');
  for (const key of optional) {
    const value = results[key];
    const icon = value === true ? '✅' : value === null ? '⚠️ ' : '❌';
    console.log(`  ${icon} ${key}`);
  }

  if (requiredOk) {
    console.log('\n🎉 环境检查通过！可以启动 MCP 服务器。');
    console.log('运行命令: npm start');
  } else {
    console.log('\n❌ 存在必需依赖缺失，请先安装。');
    console.log('运行命令: npm run setup');
  }

  return requiredOk;
}

const results = {
  node: checkNodeVersion(),
  adb: checkADB(),
  aapt: checkAAPT(),
  jadx: checkJADX(),
  androidSDK: checkAndroidSDK()
};

const ready = summarize(results);
process.exit(ready ? 0 : 1);
