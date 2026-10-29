import test from 'node:test';
import assert from 'node:assert/strict';
import { isPrivateIp, validateFetchUrl, safeFetch } from '../src/safe-fetch.js';
import { checkOutMedia, isDangerousName, mimeByExt, resolveOutMedia } from '../src/media-out.js';
import { SENSITIVE_RE } from '../src/sensitive.js';

test('isPrivateIp：内网/环回/链路本地/CGNAT/保留段全部识别为私有', () => {
  const priv = [
    '127.0.0.1', '10.0.0.5', '172.16.0.1', '172.31.255.255', '192.168.1.10',
    '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '198.18.0.1',
    '::1', '::', 'fc00::1', 'fd12::1', 'fe80::1', 'ff02::1', '2001:db8::1',
    '::ffff:127.0.0.1', '::ffff:192.168.1.1', '64:ff9b::c0a8:101',
    'not-an-ip', ''
  ];
  for (const ip of priv) assert.equal(isPrivateIp(ip), true, `${ip} 应判为私有`);
});

test('isPrivateIp：公网地址放行（含 IPv4-mapped 公网写法）', () => {
  for (const ip of ['1.1.1.1', '8.8.8.8', '223.5.5.5', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
    assert.equal(isPrivateIp(ip), false, `${ip} 应判为公网`);
  }
});

test('validateFetchUrl：非 http(s)、带凭据的 URL 直接拒绝', async () => {
  await assert.rejects(() => validateFetchUrl('file:///etc/passwd'), /仅允许 http\/https/);
  await assert.rejects(() => validateFetchUrl('gopher://127.0.0.1:6379/'), /仅允许 http\/https/);
  await assert.rejects(() => validateFetchUrl('http://user:pass@example.com/'), /不能包含凭据/);
  await assert.rejects(() => validateFetchUrl('not a url'), /URL 无效/);
});

test('validateFetchUrl：解析到内网地址的域名被拦（防 DNS rebinding）', async () => {
  await assert.rejects(() => validateFetchUrl('http://localhost:3000/'), /内网|解析失败|没有解析结果/);
});

test('safeFetch：内网目标在发请求前就被拒，不会真的连上去', async () => {
  await assert.rejects(() => safeFetch('http://127.0.0.1:3000/'), /内网|解析失败|没有解析结果/);
});

test('media-out：危险扩展名与路径逃逸都拦，图片 MIME 正确', () => {
  assert.equal(isDangerousName('payload.exe'), true);
  assert.equal(isDangerousName('run.bat'), true);
  assert.equal(isDangerousName('a.jpg'), false);
  assert.equal(mimeByExt('x.PNG'), 'image/png');

  // 越界路径直接抛错（错误信息是给模型看的，所以必须是能读懂的话）
  assert.throws(() => resolveOutMedia('C:/root', '../../secret.txt'), /不能包含 \.\./);
  assert.throws(() => resolveOutMedia('C:/root', 'audio/../secret.txt'), /不能包含 \.\./);
  assert.throws(() => resolveOutMedia('C:/root', 'state/x.png'), /必须在这些目录内/);
  assert.throws(() => resolveOutMedia('C:/root', 'https://evil/x.png'), /不接受 URL/);
  assert.equal(resolveOutMedia('C:/root', 'out/a.png').rel, 'out/a.png');

  assert.throws(() => checkOutMedia({ name: 'a.exe', size: 10 }), /可执行/);
  assert.throws(() => checkOutMedia({ name: 'big.png', size: 30 * 1024 * 1024, maxBytes: 1e6, maxImageBytes: 1e6 }), /超过上限/);
  assert.deepEqual(checkOutMedia({ name: 'a.png', size: 1024 }), { name: 'a.png', bytes: 1024, mime: 'image/png', image: true });
});

test('sensitive：本地路径与凭据形态会被识别（用于出站脱敏）', () => {
  assert.ok(SENSITIVE_RE.test('C:\\Users\\me\\.dsh\\config.json'));
  assert.ok(SENSITIVE_RE.test('token=abc123def'));
  assert.ok(SENSITIVE_RE.test('/home/me/.ssh/id_rsa'));
  assert.equal(SENSITIVE_RE.test('今天天气不错'), false);
});
