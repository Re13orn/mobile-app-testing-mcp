#!/usr/bin/env node

import { createWriteStream, existsSync, mkdirSync, rmSync } from 'fs';
import { join, resolve } from 'path';
import { spawn, spawnSync } from 'child_process';
import { pipeline } from 'stream/promises';
import { get as httpsGet } from 'https';
import { format } from 'util';
import { getEnvValue, getProjectRoot, loadProjectEnv } from './env-utils.js';

loadProjectEnv();
const projectRoot = getProjectRoot();
process.chdir(projectRoot);

const IS_WINDOWS = process.platform === 'win32';
const ADB_BIN = IS_WINDOWS ? 'adb.exe' : 'adb';
const AAPT_BIN = IS_WINDOWS ? 'aapt.exe' : 'aapt';
const JADX_BIN = IS_WINDOWS ? 'jadx.bat' : 'jadx';

function log(...args) {
  process.stderr.write(`${format(...args)}\n`);
}

function toBool(value, defaultValue) {
  if (value === undefined) {
    return defaultValue;
  }
  const normalized = String(value).trim().toLowerCase();
  return !['0', 'false', 'no', 'off'].includes(normalized);
}

function runCommand(command, args, options = {}) {
  return spawnSync(command, args, {
    stdio: 'pipe',
    encoding: 'utf8',
    shell: false,
    ...options
  });
}

function commandOk(command, args) {
  const result = runCommand(command, args);
  return result.status === 0;
}

function findLatestBuildTools(sdkPath) {
  const baseDir = join(sdkPath, 'build-tools');
  if (!existsSync(baseDir)) {
    return null;
  }

  const lsResult = runCommand(IS_WINDOWS ? 'cmd' : 'ls', IS_WINDOWS ? ['/c', 'dir', '/b', baseDir] : [baseDir]);
  if (lsResult.status !== 0) {
    return null;
  }

  const versions = (lsResult.stdout || '')
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => /^\d+\.\d+/.test(line))
    .sort((a, b) => {
      const left = a.split('.').map(n => parseInt(n, 10));
      const right = b.split('.').map(n => parseInt(n, 10));
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

  if (versions.length === 0) {
    return null;
  }
  return join(baseDir, versions[0]);
}

function detectAdbPath() {
  const configured = getEnvValue('ADB_PATH');
  if (configured && commandOk(configured, ['version'])) {
    return configured;
  }

  const sdkPath = getEnvValue('ANDROID_HOME', 'ANDROID_SDK_ROOT');
  if (sdkPath) {
    const sdkAdb = join(sdkPath, 'platform-tools', ADB_BIN);
    if (existsSync(sdkAdb) && commandOk(sdkAdb, ['version'])) {
      return sdkAdb;
    }
  }

  if (commandOk('adb', ['version'])) {
    return 'adb';
  }
  return null;
}

function detectAaptPath() {
  const configured = getEnvValue('AAPT_PATH');
  if (configured && commandOk(configured, ['version'])) {
    return configured;
  }

  const sdkPath = getEnvValue('ANDROID_HOME', 'ANDROID_SDK_ROOT');
  if (sdkPath) {
    const latestBuildTools = findLatestBuildTools(sdkPath);
    if (latestBuildTools) {
      const sdkAapt = join(latestBuildTools, AAPT_BIN);
      if (existsSync(sdkAapt) && commandOk(sdkAapt, ['version'])) {
        return sdkAapt;
      }
    }
  }

  if (commandOk('aapt', ['version'])) {
    return 'aapt';
  }
  return null;
}

function detectJadxPath(version) {
  const configured = getEnvValue('JADX_PATH');
  if (configured && commandOk(configured, ['--version'])) {
    return configured;
  }

  const localCandidates = [
    join(projectRoot, 'tools', `jadx-${version}`, 'bin', JADX_BIN),
    join(projectRoot, 'jadx', 'bin', JADX_BIN)
  ];
  for (const candidate of localCandidates) {
    if (existsSync(candidate) && commandOk(candidate, ['--version'])) {
      return candidate;
    }
  }

  if (commandOk('jadx', ['--version'])) {
    return 'jadx';
  }
  return null;
}

async function downloadFile(url, destination, redirectCount = 0) {
  if (redirectCount > 5) {
    throw new Error('下载重定向次数过多');
  }

  await new Promise((resolvePromise, rejectPromise) => {
    const request = httpsGet(url, async response => {
      if (
        response.statusCode &&
        response.statusCode >= 300 &&
        response.statusCode < 400 &&
        response.headers.location
      ) {
        response.resume();
        try {
          await downloadFile(response.headers.location, destination, redirectCount + 1);
          resolvePromise();
        } catch (error) {
          rejectPromise(error);
        }
        return;
      }

      if (response.statusCode !== 200) {
        response.resume();
        rejectPromise(new Error(`下载失败，HTTP ${response.statusCode}`));
        return;
      }

      const writer = createWriteStream(destination);
      pipeline(response, writer)
        .then(resolvePromise)
        .catch(rejectPromise);
    });

    request.on('error', rejectPromise);
  });
}

function extractZip(zipFile, outputDir) {
  if (IS_WINDOWS) {
    const ps = runCommand('powershell', [
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-Command',
      `Expand-Archive -Path '${zipFile}' -DestinationPath '${outputDir}' -Force`
    ]);
    if (ps.status !== 0) {
      throw new Error(`解压失败: ${ps.stderr || ps.stdout || 'unknown error'}`);
    }
    return;
  }

  if (commandOk('unzip', ['-v'])) {
    const unzipResult = runCommand('unzip', ['-oq', zipFile, '-d', outputDir]);
    if (unzipResult.status !== 0) {
      throw new Error(`解压失败: ${unzipResult.stderr || unzipResult.stdout || 'unknown error'}`);
    }
    return;
  }

  if (commandOk('python3', ['--version'])) {
    const pyResult = runCommand('python3', ['-m', 'zipfile', '-e', zipFile, outputDir]);
    if (pyResult.status !== 0) {
      throw new Error(`解压失败: ${pyResult.stderr || pyResult.stdout || 'unknown error'}`);
    }
    return;
  }

  if (commandOk('python', ['--version'])) {
    const pyResult = runCommand('python', ['-m', 'zipfile', '-e', zipFile, outputDir]);
    if (pyResult.status !== 0) {
      throw new Error(`解压失败: ${pyResult.stderr || pyResult.stdout || 'unknown error'}`);
    }
    return;
  }

  throw new Error('未找到可用解压工具，请安装 unzip 或 python3');
}

async function ensureJadx(version, downloadUrl, autoDownload) {
  let jadxPath = detectJadxPath(version);
  if (jadxPath) {
    return { path: jadxPath, installedNow: false };
  }

  if (!autoDownload) {
    return { path: null, installedNow: false };
  }

  log(`[Start] 未检测到 JADX，尝试自动下载 v${version}...`);

  const toolsDir = join(projectRoot, 'tools');
  const archivePath = join(toolsDir, `jadx-${version}.zip`);
  const extractRoot = toolsDir;

  mkdirSync(toolsDir, { recursive: true });

  try {
    await downloadFile(downloadUrl, archivePath);
    extractZip(archivePath, extractRoot);
  } catch (error) {
    rmSync(archivePath, { force: true });
    throw error;
  }

  rmSync(archivePath, { force: true });
  jadxPath = detectJadxPath(version);

  if (!jadxPath) {
    throw new Error(`JADX 下载或解压后仍不可用，请手动检查: ${join(toolsDir, `jadx-${version}`)}`);
  }

  return { path: jadxPath, installedNow: true };
}

function printSummary(summary) {
  log('\n[Start] 依赖检查结果:');
  for (const item of summary) {
    const icon = item.ok ? '✅' : item.level === 'required' ? '❌' : '⚠️';
    log(`  ${icon} ${item.name} (${item.level}) - ${item.detail}`);
  }
}

function printGuidance(summary) {
  const missing = summary.filter(item => !item.ok);
  if (missing.length === 0) {
    log('[Start] 环境检查通过，启动 MCP 服务...');
    return;
  }

  log('\n[Start] 配置建议:');
  if (missing.some(item => item.name === 'adb')) {
    log('  1. 安装 Android SDK Platform Tools（提供 adb）');
    log('  2. 设置 ADB_PATH，或将 platform-tools 加入 PATH');
  }
  if (missing.some(item => item.name === 'aapt')) {
    log('  3. 安装 Android SDK Build Tools（提供 aapt）');
    log('  4. 设置 AAPT_PATH，或设置 ANDROID_HOME / ANDROID_SDK_ROOT');
  }
  if (missing.some(item => item.name === 'jadx')) {
    log('  5. 手动安装 JADX，或保持 AUTO_DOWNLOAD_JADX=true 自动下载');
    log('  6. 设置 JADX_PATH，或将 jadx 加入 PATH');
  }
  log('  7. 执行 npm run check 查看详细状态');
}

function runServer() {
  const serverEntry = resolve(projectRoot, 'dist', 'stdio-entry.js');
  if (!existsSync(serverEntry)) {
    log('[Start] 未找到 dist/stdio-entry.js，尝试自动构建...');
    const buildScript = resolve(projectRoot, 'scripts', 'build.js');
    const buildResult = runCommand(process.execPath, [buildScript], { stdio: 'pipe' });
    if (buildResult.stdout) {
      process.stderr.write(buildResult.stdout);
    }
    if (buildResult.stderr) {
      process.stderr.write(buildResult.stderr);
    }
    if (buildResult.status !== 0 || !existsSync(serverEntry)) {
      console.error('[Start] 构建失败，无法启动 MCP。请手动执行: npm run build');
      process.exit(1);
    }
  }

  const child = spawn(process.execPath, [serverEntry], {
    cwd: projectRoot,
    env: process.env,
    stdio: 'inherit',
    shell: false
  });

  const forwardSignal = signal => {
    if (!child.killed) {
      child.kill(signal);
    }
  };

  process.on('SIGINT', () => forwardSignal('SIGINT'));
  process.on('SIGTERM', () => forwardSignal('SIGTERM'));

  child.on('exit', code => {
    process.exit(code ?? 0);
  });
}

async function main() {
  const jadxVersion = getEnvValue('JADX_VERSION') || '1.5.5';
  const jadxDownloadUrl =
    getEnvValue('JADX_DOWNLOAD_URL') ||
    `https://github.com/skylot/jadx/releases/download/v${jadxVersion}/jadx-${jadxVersion}.zip`;
  const autoDownloadJadx = toBool(getEnvValue('AUTO_DOWNLOAD_JADX'), true);

  log('[Start] 准备启动移动端App测试MCP...');

  const adbPath = detectAdbPath();
  const aaptPath = detectAaptPath();

  let jadxPath = null;
  let jadxInstalledNow = false;
  try {
    const result = await ensureJadx(jadxVersion, jadxDownloadUrl, autoDownloadJadx);
    jadxPath = result.path;
    jadxInstalledNow = result.installedNow;
  } catch (error) {
    console.warn(`[Start] JADX 自动下载失败: ${error.message}`);
  }

  if (adbPath) {
    process.env.ADB_PATH = adbPath;
  }
  if (aaptPath) {
    process.env.AAPT_PATH = aaptPath;
  }
  if (jadxPath) {
    process.env.JADX_PATH = jadxPath;
  }

  if (jadxInstalledNow) {
    log(`[Start] JADX 首次下载完成: ${jadxPath}`);
  }

  const summary = [
    {
      name: 'adb',
      level: 'required',
      ok: Boolean(adbPath),
      detail: adbPath || '未找到（ADB 相关工具会失败）'
    },
    {
      name: 'aapt',
      level: 'recommended',
      ok: Boolean(aaptPath),
      detail: aaptPath || '未找到（AAPT 分析工具不可用）'
    },
    {
      name: 'jadx',
      level: 'optional',
      ok: Boolean(jadxPath),
      detail: jadxPath || '未找到（反编译工具不可用）'
    }
  ];

  printSummary(summary);
  printGuidance(summary);
  runServer();
}

main().catch(error => {
  console.error(`[Start] 启动失败: ${error.message}`);
  process.exit(1);
});
