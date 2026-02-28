#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, chmodSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { homedir } from 'os';
import { getProjectRoot, loadProjectEnv } from './env-utils.js';

loadProjectEnv();

const projectRoot = getProjectRoot();
const startScriptPath = resolve(projectRoot, 'scripts', 'start.js');

if (!existsSync(startScriptPath)) {
  console.error(`[install-mcp] 启动脚本不存在: ${startScriptPath}`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = {
    target: 'all',
    name: 'mobile-app-testing',
    codexConfig: process.env.CODEX_CONFIG_PATH || '',
    claudeConfig: process.env.CLAUDE_CONFIG_PATH || '',
    dryRun: false
  };

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === '--target' && argv[i + 1]) {
      args.target = argv[++i];
      continue;
    }
    if (token === '--name' && argv[i + 1]) {
      args.name = argv[++i];
      continue;
    }
    if (token === '--codex-config' && argv[i + 1]) {
      args.codexConfig = argv[++i];
      continue;
    }
    if (token === '--claude-config' && argv[i + 1]) {
      args.claudeConfig = argv[++i];
      continue;
    }
    if (token === '--dry-run') {
      args.dryRun = true;
      continue;
    }
  }

  if (!['all', 'codex', 'claude'].includes(args.target)) {
    throw new Error(`不支持的 --target: ${args.target}（可选: all/codex/claude）`);
  }

  return args;
}

function ensureDir(path) {
  mkdirSync(dirname(path), { recursive: true });
}

function backupIfExists(path, dryRun) {
  if (!existsSync(path)) {
    return null;
  }
  const backupPath = `${path}.bak.${Date.now()}`;
  if (!dryRun) {
    copyFileSync(path, backupPath);
  }
  return backupPath;
}

function defaultClaudeConfigPath() {
  if (process.platform === 'darwin') {
    return join(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  }
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA || join(homedir(), 'AppData', 'Roaming');
    return join(appData, 'Claude', 'claude_desktop_config.json');
  }
  return join(homedir(), '.config', 'Claude', 'claude_desktop_config.json');
}

function defaultCodexConfigPath() {
  return join(homedir(), '.codex', 'config.toml');
}

function safeRead(path, fallback = '') {
  if (!existsSync(path)) {
    return fallback;
  }
  return readFileSync(path, 'utf8');
}

function escapeTomlString(value) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function upsertCodexMcpServer(content, name, command, args, cwd) {
  const header = `[mcp_servers.${name}]`;
  const block = [
    header,
    `command = "${escapeTomlString(command)}"`,
    `args = [${args.map(arg => `"${escapeTomlString(arg)}"`).join(', ')}]`,
    `cwd = "${escapeTomlString(cwd)}"`,
    ''
  ];

  const lines = content.split(/\r?\n/);
  const start = lines.findIndex(line => line.trim() === header);

  if (start === -1) {
    const normalized = content.trimEnd();
    const prefix = normalized ? `${normalized}\n\n` : '';
    return `${prefix}${block.join('\n')}`.trimEnd() + '\n';
  }

  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (lines[i].trim().startsWith('[')) {
      end = i;
      break;
    }
  }

  const merged = [...lines.slice(0, start), ...block, ...lines.slice(end)];
  return merged.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n';
}

function installClaude(configPath, serverName, dryRun) {
  const raw = safeRead(configPath, '{}');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Claude 配置不是合法 JSON: ${configPath}`);
  }

  if (!parsed || typeof parsed !== 'object') {
    parsed = {};
  }
  if (!parsed.mcpServers || typeof parsed.mcpServers !== 'object') {
    parsed.mcpServers = {};
  }

  parsed.mcpServers[serverName] = {
    command: 'node',
    args: [startScriptPath],
    cwd: projectRoot,
    env: {}
  };

  const backup = backupIfExists(configPath, dryRun);
  ensureDir(configPath);
  if (!dryRun) {
    writeFileSync(configPath, `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');
  }

  return { configPath, backup };
}

function installCodex(configPath, serverName, dryRun) {
  const raw = safeRead(configPath, '');
  const merged = upsertCodexMcpServer(raw, serverName, 'node', [startScriptPath], projectRoot);

  const backup = backupIfExists(configPath, dryRun);
  ensureDir(configPath);
  if (!dryRun) {
    writeFileSync(configPath, merged, 'utf8');
    try {
      chmodSync(configPath, 0o600);
    } catch {
      // 非关键错误，忽略权限设置失败
    }
  }

  return { configPath, backup };
}

function printResult(title, result, dryRun) {
  console.log(`\n[install-mcp] ${title}`);
  console.log(`  配置文件: ${result.configPath}`);
  if (result.backup) {
    console.log(`  备份文件: ${result.backup}`);
  } else {
    console.log('  备份文件: (首次创建，无备份)');
  }
  console.log(`  状态: ${dryRun ? 'dry-run（未写入）' : '已写入'}`);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const codexPath = resolve(args.codexConfig || defaultCodexConfigPath());
  const claudePath = resolve(args.claudeConfig || defaultClaudeConfigPath());

  console.log('[install-mcp] 准备安装 MCP 客户端配置...');
  console.log(`[install-mcp] serverName=${args.name}, target=${args.target}, dryRun=${args.dryRun}`);

  if (args.target === 'all' || args.target === 'codex') {
    const result = installCodex(codexPath, args.name, args.dryRun);
    printResult('Codex 配置完成', result, args.dryRun);
  }

  if (args.target === 'all' || args.target === 'claude') {
    const result = installClaude(claudePath, args.name, args.dryRun);
    printResult('Claude 配置完成', result, args.dryRun);
  }

  console.log('\n[install-mcp] 下一步:');
  console.log('  1) 重启你的 MCP 客户端');
  console.log('  2) 如需校验服务端，执行: npm run verify');
}

try {
  main();
} catch (error) {
  console.error(`[install-mcp] 失败: ${error.message}`);
  process.exit(1);
}
