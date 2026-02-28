#!/usr/bin/env node

import { existsSync } from 'fs';
import { resolve } from 'path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { getProjectRoot, loadProjectEnv } from './env-utils.js';

const FORBIDDEN_PATTERNS = [/frida/i, /gadget/i];
const KNOWN_PREFIXES = ['adb_', 'aapt_', 'jadx_', 'static_', 'workflow_', 'file_'];

loadProjectEnv();
const projectRoot = getProjectRoot();
process.chdir(projectRoot);

function withTimeout(promise, timeoutMs, stepName) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`${stepName} 超时（>${timeoutMs}ms）`)), timeoutMs)
    )
  ]);
}

function buildChildEnv() {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value === 'string') {
      env[key] = value;
    }
  }
  return env;
}

function countToolsByPrefix(toolNames) {
  const counts = Object.fromEntries(KNOWN_PREFIXES.map(prefix => [prefix, 0]));
  const unknown = [];

  for (const name of toolNames) {
    const matchedPrefix = KNOWN_PREFIXES.find(prefix => name.startsWith(prefix));
    if (matchedPrefix) {
      counts[matchedPrefix] += 1;
    } else {
      unknown.push(name);
    }
  }

  return { counts, unknown };
}

function ensure(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function main() {
  console.log('🧪 开始 MCP smoke 测试...');

  const distEntry = resolve(projectRoot, 'dist/stdio-entry.js');
  ensure(
    existsSync(distEntry),
    '未找到 dist/stdio-entry.js，请先执行: npm run build'
  );

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [distEntry],
    cwd: projectRoot,
    env: buildChildEnv(),
    stderr: 'pipe'
  });
  let serverStderr = '';
  if (transport.stderr) {
    transport.stderr.on('data', chunk => {
      serverStderr += chunk.toString();
    });
  }

  const client = new Client({
    name: 'mobile-app-testing-mcp-smoke',
    version: '1.0.0'
  });

  try {
    await withTimeout(client.connect(transport), 10000, 'MCP connect');
    console.log('✅ MCP 连接成功');

    const listResult = await withTimeout(client.listTools(), 15000, 'tools/list');
    const toolNames = (listResult.tools || []).map(tool => tool.name);
    ensure(toolNames.length > 0, 'tools/list 返回为空');
    console.log(`✅ tools/list 成功: ${toolNames.length} 个工具`);

    const sortedNames = [...toolNames].sort();
    const duplicates = sortedNames.filter((name, index) => index > 0 && name === sortedNames[index - 1]);
    ensure(duplicates.length === 0, `检测到重复工具名: ${duplicates.join(', ')}`);

    const forbidden = toolNames.filter(name => FORBIDDEN_PATTERNS.some(pattern => pattern.test(name)));
    ensure(forbidden.length === 0, `检测到已移除能力残留: ${forbidden.join(', ')}`);

    const { counts, unknown } = countToolsByPrefix(toolNames);
    ensure(unknown.length === 0, `检测到未知工具前缀: ${unknown.join(', ')}`);

    console.log('📊 工具分类统计:');
    for (const prefix of KNOWN_PREFIXES) {
      console.log(`  • ${prefix}: ${counts[prefix]}`);
    }

    const workflowResult = await withTimeout(
      client.callTool({
        name: 'workflow_get_templates',
        arguments: {}
      }),
      15000,
      'tools/call workflow_get_templates'
    );

    ensure(!workflowResult.isError, 'workflow_get_templates 返回错误');
    ensure(
      Array.isArray(workflowResult.content) && workflowResult.content.length > 0,
      'workflow_get_templates 返回内容为空'
    );

    console.log('✅ workflow_get_templates 调用成功');
    console.log('🎉 Smoke 测试通过');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`❌ Smoke 测试失败: ${message}`);
    if (serverStderr.trim()) {
      console.error('\n--- server stderr ---');
      console.error(serverStderr.trim());
      console.error('---------------------');
    }
    process.exitCode = 1;
  } finally {
    try {
      await client.close();
    } catch {
      // 忽略清理阶段异常
    }
    try {
      await transport.close();
    } catch {
      // 忽略清理阶段异常
    }
  }
}

main().catch(error => {
  console.error(`❌ Smoke 测试异常: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
