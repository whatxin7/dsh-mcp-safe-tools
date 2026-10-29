import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** 起一个 stdio MCP server，握手后要工具清单，然后关掉。 */
function listTools(script, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(ROOT, script)], {
      cwd: ROOT,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, DSH_HOME: path.join(ROOT, '.dsh-none') }
    });
    const tools = [];
    let buffer = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`MCP 握手超时：${script}\n${stderr.slice(0, 500)}`));
    }, timeoutMs);

    const send = (obj) => child.stdin.write(`${JSON.stringify(obj)}\n`);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);
        if (!line) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        if (msg.id === 2) {
          clearTimeout(timer);
          for (const tool of msg.result?.tools ?? []) tools.push(tool.name);
          child.kill();
          resolve(tools);
        }
      }
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (c) => {
      stderr += c;
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });

    send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'ci', version: '1.0.0' } }
    });
    send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  });
}

test('mcp-web-search-safe：只暴露 web_search / web_fetch 两个只读工具', async () => {
  const tools = await listTools('src/mcp-web-search-safe.js');
  assert.deepEqual(tools.sort(), ['web_fetch', 'web_search']);
});

test('mcp-host-server：暴露 snowluma_status，且没有任何启停进程的工具', async () => {
  const tools = await listTools('src/mcp-host-server.js');
  assert.ok(tools.includes('snowluma_status'));
  assert.equal(tools.some((t) => /start|stop|kill|restart/i.test(t)), false, '不得提供启停网关的能力');
});
