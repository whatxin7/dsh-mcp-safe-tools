// 工具分片（tool groups）：把 59 个 qq_* 工具切成「常驻核心 + 按需扩展组」。
//
// 为什么要有这个文件：
//   每个工具的描述 + 参数 schema 都随 system prompt **每一次请求**重发。
//   实测一份 reserved2 会话的请求头是「58 个工具 / 45.5 KB schema（≈14k token/次）」，
//   而 5 天 4356 个回合里只碰过 28 个工具名、Top8 占 90%（state/tool-calls.jsonl）。
//   也就是说一半以上的 schema 是纯噪声：既摊薄注意力，又让长名字互相干扰
//   （日志里真出现过 `mcp__snowluma_qq_send_message` 这种少写一个下划线的拼错）。
//
// 设计约束：
//   1. **分组表是唯一事实源**：新增工具必须归组，否则 scripts/test-tool-groups.mjs 会红。
//   2. **core 必须自洽**：只看消息、说话、睡觉、记忆这几件事不能依赖任何扩展组，
//      否则模型会在一个说不成话的回合里先去开组。
//   3. **状态落盘**：桥接控制台/MCP 都能改，改完写 state/tool-groups.json；
//      新进程（新会话）启动时按落盘值挂载，MCP 侧再叠加运行期 enable（tools/list_changed）。
//   4. **closed-agent 例外**：管理员私聊操控整机时全开，不然远程操作 DSH 会用不了扩展工具。

import fs from 'node:fs';
import path from 'node:path';

/** 组顺序：core 在最前，其余按「越少用越靠后」排。 */
export const GROUP_ORDER = [
  'core',
  'memory',
  'media',
  'sticker',
  'voice',
  'people',
  'qzone',
  'identity',
  'slang',
  'douyin',
  'legacy'
];

export const GROUP_LABELS = {
  core: '基础通讯（常驻）',
  memory: '轻量记忆',
  media: '图片 / 文件 / 合并转发',
  sticker: '表情库维护',
  voice: '语音与唱歌',
  people: '成员与活跃查询',
  qzone: 'QQ 空间',
  identity: '身份（昵称/头像/名片/语气附录）',
  slang: '黑话词库',
  douyin: '抖音素材',
  legacy: '旧只读工具（仅封闭模式）'
};

/** 每组的工具清单；core 之外的组名也是 qq_tools 的入参。 */
export const GROUP_TOOLS = {
  core: [
    'qq_tools',
    'qq_status',
    'qq_get_prompt',
    'qq_social_state',
    'qq_get_unread_messages',
    'qq_get_recent_messages',
    'qq_get_my_recent_messages',
    'qq_get_message_detail',
    'qq_get_message_images',
    'qq_get_forward_msg',
    'qq_send_message',
    'qq_send_burst',
    'qq_send_group_message',
    'qq_send_private_message',
    'qq_reply',
    'qq_send_poke',
    'qq_send_sticker',
    'qq_get_sticker_image',
    'qq_send_image',
    'qq_speak',
    'qq_recall_message',
    'qq_identify_image',
    'qq_wait_for_messages',
    'qq_mark_read',
    'qq_set_wake_config',
    'qq_report_feedback'
  ],
  memory: [
    'qq_memory_append',
    'qq_memory_query',
    'qq_memory_update',
    'qq_memory_remove',
    'qq_memory_clear'
  ],
  media: ['qq_send_file', 'qq_send_forward'],
  sticker: [
    'qq_list_stickers',
    'qq_collect_sticker',
    'qq_sticker_note',
    'qq_set_sticker_remark',
    'qq_import_sticker'
  ],
  voice: ['qq_send_voice', 'qq_sing', 'qq_list_voices'],
  people: ['qq_get_group_members', 'qq_get_active_members'],
  qzone: [
    'qq_qzone_post',
    'qq_qzone_delete',
    'qq_qzone_list',
    'qq_qzone_feeds',
    'qq_qzone_comment',
    'qq_qzone_like',
    'qq_qzone_unlike'
  ],
  identity: ['qq_get_self_profile', 'qq_get_self_image', 'qq_set_nickname', 'qq_set_avatar', 'qq_set_group_card', 'qq_style_append'],
  slang: ['qq_slang_query', 'qq_slang_submit'],
  douyin: ['qq_douyin_comments', 'qq_douyin_grab_sticker', 'qq_douyin_learn'],
  legacy: ['qq_list_groups', 'qq_get_group_history']
};

/** 默认常驻：core + memory（记忆是常用能力，别让模型先去开组）。 */
export const DEFAULT_ACTIVE_GROUPS = ['core', 'memory'];

const TOOL_TO_GROUP = new Map();
for (const g of GROUP_ORDER) {
  for (const t of GROUP_TOOLS[g] ?? []) TOOL_TO_GROUP.set(t, g);
}

/** 查某个工具属于哪一组；未归组返回 null（测试会因此失败）。 */
export function groupOf(toolName) {
  return TOOL_TO_GROUP.get(String(toolName ?? '')) ?? null;
}

/** 所有已登记的工具名 → 组名映射（调试用）。 */
export function toolGroupMap() {
  return Object.fromEntries(TOOL_TO_GROUP);
}

/**
 * 校验：给定实际注册的工具名集合，返回 { unclassified, ghost }。
 * - unclassified：注册了但没归组（新增工具忘了写分组表）
 * - ghost：分组表里写了但没注册（改名/删除后的残留）
 */
export function auditGroups(registeredNames) {
  const reg = new Set([...registeredNames].map(String));
  const unclassified = [...reg].filter((n) => !TOOL_TO_GROUP.has(n)).sort();
  const ghost = [...TOOL_TO_GROUP.keys()].filter((n) => !reg.has(n)).sort();
  return { unclassified, ghost };
}

function sanitizeGroups(list) {
  const out = [];
  for (const raw of Array.isArray(list) ? list : []) {
    const g = String(raw ?? '').trim();
    if (g && GROUP_TOOLS[g] && !out.includes(g)) out.push(g);
  }
  // core 永远在，且排最前
  return ['core', ...out.filter((g) => g !== 'core')];
}

/**
 * 解析本次进程要挂载的组。
 * 优先级：closed-agent 全开 > 落盘状态 > config.socialV2.toolGroups.default > 内置默认。
 * @param {object} opts
 * @param {object} opts.cfg          桥接 config
 * @param {Set<string>|string[]} opts.registered 实际注册的工具名
 * @param {string} opts.stateFile    状态文件绝对路径
 * @param {string} opts.mode         当前桥接模式（bridge.mode）
 */
export function resolveActiveGroups({ cfg, registered, stateFile, mode }) {
  const reg = new Set([...registered].map(String));
  const known = new Set([...reg].map((n) => TOOL_TO_GROUP.get(n)).filter(Boolean));
  const tg = cfg?.socialV2?.toolGroups ?? {};

  if (mode === 'closed-agent') {
    // 远程操控整机：全开（含未来新增组）
    return { groups: new Set([...known]), source: 'closed-agent', all: true };
  }
  if (tg.enabled === false) {
    return { groups: known, source: 'disabled', all: true };
  }

  const saved = readGroupsState(stateFile);
  const base = saved?.active?.length ? saved.active : (Array.isArray(tg.default) ? tg.default : DEFAULT_ACTIVE_GROUPS);
  let groups = sanitizeGroups(base).filter((g) => known.has(g) || g === 'core');
  const maxActive = Number.isFinite(Number(tg.maxActive)) ? Math.max(1, Math.round(Number(tg.maxActive))) : 4;
  if (groups.length > maxActive) groups = groups.slice(0, maxActive);
  return { groups: new Set(groups.length ? groups : ['core']), source: saved?.active?.length ? 'state' : 'config', all: false };
}

function readGroupsState(stateFile) {
  try {
    const raw = fs.readFileSync(stateFile, 'utf8');
    const obj = JSON.parse(raw);
    const active = sanitizeGroups(obj?.active ?? []);
    return active.length ? { active, updatedAt: obj?.updatedAt ?? null } : null;
  } catch {
    return null;
  }
}

export function loadGroupsState(stateFile) {
  return readGroupsState(stateFile);
}

/** 落盘（原子写：先写 .tmp 再 rename，避免半截 JSON）。 */
export function saveGroupsState(stateFile, activeGroups, extra = {}) {
  const active = sanitizeGroups(activeGroups);
  const payload = { active, updatedAt: new Date().toISOString(), ...extra };
  try {
    fs.mkdirSync(path.dirname(stateFile), { recursive: true });
    const tmp = `${stateFile}.tmp`;
    fs.writeFileSync(tmp, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    fs.renameSync(tmp, stateFile);
    return payload;
  } catch {
    return null;
  }
}

/** 给 qq_tools 的 list 结果做文案：哪些开着、每组几个工具、组开关的用途。 */
export function describeGroups(activeGroups) {
  const active = new Set(sanitizeGroups([...activeGroups]));
  return GROUP_ORDER.filter((g) => GROUP_TOOLS[g]?.length).map((g) => ({
    group: g,
    label: GROUP_LABELS[g] ?? g,
    enabled: active.has(g),
    tools: GROUP_TOOLS[g]
  }));
}
