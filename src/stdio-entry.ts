#!/usr/bin/env node

import { format } from 'util';

function logToStderr(...args: unknown[]): void {
  process.stderr.write(`${format(...args)}\n`);
}

// MCP stdio 场景下，stdout 仅用于协议消息。
// 将 console.log/info/debug 重定向到 stderr，避免污染协议流。
console.log = logToStderr;
console.info = logToStderr;
console.debug = logToStderr;

await import('./index.js');
