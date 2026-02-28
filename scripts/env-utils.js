import { existsSync, readFileSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

let cachedRoot = null;
let envLoaded = false;

function stripQuotes(value) {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function parseEnv(content) {
  const result = {};
  const lines = content.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    const normalized = line.startsWith('export ') ? line.slice(7).trim() : line;
    const eqIdx = normalized.indexOf('=');
    if (eqIdx <= 0) {
      continue;
    }

    const key = normalized.slice(0, eqIdx).trim();
    const value = stripQuotes(normalized.slice(eqIdx + 1).trim());
    if (key) {
      result[key] = value;
    }
  }

  return result;
}

export function getProjectRoot() {
  if (cachedRoot) {
    return cachedRoot;
  }

  const cwd = process.cwd();
  if (existsSync(resolve(cwd, 'package.json'))) {
    cachedRoot = cwd;
    return cachedRoot;
  }

  const moduleDir = dirname(fileURLToPath(import.meta.url));
  const candidate = resolve(moduleDir, '..');
  if (existsSync(resolve(candidate, 'package.json'))) {
    cachedRoot = candidate;
    return cachedRoot;
  }

  cachedRoot = cwd;
  return cachedRoot;
}

export function loadProjectEnv() {
  if (envLoaded) {
    return;
  }
  envLoaded = true;

  const envPath = resolve(getProjectRoot(), '.env');
  if (!existsSync(envPath)) {
    return;
  }

  try {
    const parsed = parseEnv(readFileSync(envPath, 'utf8'));
    for (const [key, value] of Object.entries(parsed)) {
      if (process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch (error) {
    console.warn(`[Env] 加载 .env 失败: ${error.message}`);
  }
}

export function getEnvValue(...keys) {
  for (const key of keys) {
    const value = process.env[key];
    if (value && value.trim()) {
      return value.trim();
    }
  }
  return undefined;
}

