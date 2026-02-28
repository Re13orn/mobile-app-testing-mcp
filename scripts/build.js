#!/usr/bin/env node

import { existsSync, rmSync } from 'fs';
import { resolve } from 'path';
import { spawnSync } from 'child_process';
import { getProjectRoot, loadProjectEnv } from './env-utils.js';

loadProjectEnv();
const projectRoot = getProjectRoot();
process.chdir(projectRoot);

const distDir = resolve(projectRoot, 'dist');
if (existsSync(distDir)) {
  rmSync(distDir, { recursive: true, force: true });
  console.log('🧹 已清理 dist 目录');
}

const tscBinary = process.platform === 'win32'
  ? resolve(projectRoot, 'node_modules', '.bin', 'tsc.cmd')
  : resolve(projectRoot, 'node_modules', '.bin', 'tsc');

const result = spawnSync(tscBinary, [], {
  stdio: 'inherit',
  shell: false
});

if (typeof result.status === 'number' && result.status !== 0) {
  process.exit(result.status);
}
