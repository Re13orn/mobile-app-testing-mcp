import { existsSync, readFileSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

let cachedProjectRoot: string | null = null;
let envLoaded = false;

function stripQuotes(value: string): string {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function parseEnvFile(content: string): Record<string, string> {
  const parsed: Record<string, string> = {};
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
      parsed[key] = value;
    }
  }

  return parsed;
}

export function getProjectRoot(): string {
  if (cachedProjectRoot) {
    return cachedProjectRoot;
  }

  const envRoot = process.env.MCP_PROJECT_ROOT;
  if (envRoot && existsSync(resolve(envRoot, 'package.json'))) {
    cachedProjectRoot = envRoot;
    return cachedProjectRoot;
  }

  const cwd = process.cwd();
  if (existsSync(resolve(cwd, 'package.json'))) {
    cachedProjectRoot = cwd;
    return cachedProjectRoot;
  }

  const moduleDir = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(moduleDir, '..'),
    resolve(moduleDir, '..', '..')
  ];

  for (const candidate of candidates) {
    if (existsSync(resolve(candidate, 'package.json'))) {
      cachedProjectRoot = candidate;
      return cachedProjectRoot;
    }
  }

  cachedProjectRoot = cwd;
  return cachedProjectRoot;
}

export function loadProjectEnv(): void {
  if (envLoaded) {
    return;
  }
  envLoaded = true;

  const envPath = resolve(getProjectRoot(), '.env');
  if (!existsSync(envPath)) {
    return;
  }

  try {
    const parsed = parseEnvFile(readFileSync(envPath, 'utf8'));
    for (const [key, value] of Object.entries(parsed)) {
      if (process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch (error) {
    console.warn(`[Env] 读取 .env 失败: ${error}`);
  }
}

export function getEnvValue(...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = process.env[key];
    if (value && value.trim()) {
      return value.trim();
    }
  }
  return undefined;
}

