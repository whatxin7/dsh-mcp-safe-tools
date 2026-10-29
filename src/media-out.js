// 出站媒体的纯逻辑（不做 I/O、不碰网关）：路径白名单、扩展名黑名单、体积上限、合并转发节点整形。
//
// 为什么单独成文件：
//   1. 桥接 api 与 MCP 工具两边都要用同一套判定，写两份必然漂移；
//   2. 这些判定是「不能让模型外发本机任意文件」的硬边界，必须能被离线回归直接覆盖
//      （scripts/test-send-media.mjs），而不是只能靠起一个真网关手测。
//
// 边界约定（与语音、换头像保持同一套思路）：
//   · 只认**白名单目录内的相对路径**，绝对路径、盘符、`..`、UNC、URL 一律拒绝；
//   · 扩展名黑名单挡住可执行/脚本类（发出去就是投毒工具，没理由让聊天机器人干这个）；
//   · 体积、数量、字数都有上限，超了就报清楚原因，别让模型猜。

import path from 'node:path';

/** 默认允许发文件的目录（相对 qq-bridge 根）。 */
export const DEFAULT_OUT_DIRS = ['out', 'assets', 'audio', 'exports', 'state/media'];

/** 绝不外发的扩展名：可执行、脚本、快捷方式、安装包。 */
export const DANGEROUS_EXTS = [
  '.exe', '.com', '.scr', '.pif', '.msi', '.msix', '.msp', '.bat', '.cmd', '.ps1', '.psm1',
  '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.lnk', '.reg', '.dll', '.sys',
  '.jar', '.apk', '.app', '.dmg', '.sh', '.command', '.service', '.desktop'
];

/** 图片扩展名：走 base64:// 直接当图片发（不是当文件）。 */
export const IMAGE_EXTS = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'];

const MIME_BY_EXT = {
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.bmp': 'image/bmp',
  '.pdf': 'application/pdf',
  '.zip': 'application/zip',
  '.7z': 'application/x-7z-compressed',
  '.txt': 'text/plain',
  '.md': 'text/markdown',
  '.csv': 'text/csv',
  '.json': 'application/json',
  '.mp4': 'video/mp4',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
};

export function mimeByExt(name) {
  return MIME_BY_EXT[path.extname(String(name ?? '')).toLowerCase()] ?? 'application/octet-stream';
}

export function extOf(name) {
  return path.extname(String(name ?? '')).toLowerCase();
}

export function isImageName(name) {
  return IMAGE_EXTS.includes(extOf(name));
}

export function isDangerousName(name) {
  return DANGEROUS_EXTS.includes(extOf(name));
}

/**
 * 校验并规范化一个「允许外发的相对路径」。
 * 返回 { rel, abs }；不合法直接抛错（错误信息给模型看，所以要说人话）。
 */
export function resolveOutMedia(root, relPath, { dirs = DEFAULT_OUT_DIRS } = {}) {
  const raw = String(relPath ?? '').trim();
  if (!raw) throw new Error('path 不能为空');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) throw new Error('path 只接受白名单目录里的相对路径，不接受 URL；要发表情或头像请用 stickerId/url 参数');
  if (/^[a-z]:[\\/]/i.test(raw)) throw new Error('path 只接受相对路径（不要带盘符）');
  if (/^\\\\|^\/\//.test(raw)) throw new Error('path 不接受 UNC / 网络路径');
  const norm = raw.replace(/\\/g, '/');
  if (norm.split('/').includes('..')) throw new Error('path 不能包含 ..');

  const rootAbs = path.resolve(root);
  const abs = path.resolve(rootAbs, norm);
  const allowed = (dirs.length ? dirs : DEFAULT_OUT_DIRS).map((d) => path.resolve(rootAbs, d));
  const inside = allowed.some((d) => abs === d || abs.startsWith(d + path.sep));
  if (!inside) {
    throw new Error(`path 必须在这些目录内：${(dirs.length ? dirs : DEFAULT_OUT_DIRS).join(' / ')}（当前 ${norm}）`);
  }
  return { rel: path.relative(rootAbs, abs).split(path.sep).join('/'), abs };
}

/** 出站前的最终检查：扩展名 + 体积。返回 { name, bytes, mime, image }。 */
export function checkOutMedia({ name, size, maxBytes, maxImageBytes, allowImage = true }) {
  const displayName = path.basename(String(name ?? 'file')).slice(0, 120) || 'file';
  if (isDangerousName(displayName)) {
    throw new Error(`不发送可执行/脚本类文件（${extOf(displayName)}）：这条渠道只发文档、图片、压缩包、音视频`);
  }
  const image = isImageName(displayName);
  if (image && !allowImage) throw new Error('这个渠道不发表图片，请改用 qq_send_image');
  const cap = image ? Math.min(Number(maxImageBytes ?? 5 * 1024 * 1024), Number(maxBytes ?? Infinity)) : Number(maxBytes ?? 20 * 1024 * 1024);
  const bytes = Number(size ?? 0);
  if (!Number.isFinite(bytes) || bytes <= 0) throw new Error('文件是空的或读不到大小');
  if (bytes > cap) {
    throw new Error(`文件 ${(bytes / 1024 / 1024).toFixed(1)}MB 超过上限 ${(cap / 1024 / 1024).toFixed(1)}MB`);
  }
  return { name: displayName, bytes, mime: mimeByExt(displayName), image };
}

/**
 * 把「合并转发」的入参整形为 OneBot 的 nodes 数组。
 * items: [{ name, uin?, text, time? }]
 * 规则：节点数、单节点字数都有上限；空文本节点丢弃；一条都不剩就抛错。
 */
export function buildForwardNodes(items, { maxNodes = 10, maxChars = 300 } = {}) {
  const list = Array.isArray(items) ? items : [];
  const nodes = [];
  for (const item of list) {
    if (nodes.length >= maxNodes) break;
    const text = String(item?.text ?? '').trim();
    if (!text) continue;
    const node = {
      type: 'node',
      data: {
        name: String(item?.name ?? '聊天记录').slice(0, 32) || '聊天记录',
        uin: String(item?.uin ?? '0'),
        content: [{ type: 'text', data: { text: text.slice(0, maxChars) } }]
      }
    };
    nodes.push(node);
  }
  if (!nodes.length) throw new Error('合并转发的节点全是空的：至少要有一条带文字的 messageIds 或 text 节点');
  return nodes;
}

/** 给返回文案用的体积描述。 */
export function describeBytes(bytes) {
  const n = Number(bytes ?? 0);
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)}KB`;
  return `${(n / 1024 / 1024).toFixed(1)}MB`;
}
