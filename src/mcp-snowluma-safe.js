// 安全版 QQ MCP server（stdio）。由 DSH 的 MCP 客户端 spawn。
//
// 安全设计：
// - 只暴露聊天所需的**安全动作子集**（查状态/查群/查消息/发消息），
//   不暴露任何管理类动作（禁言、踢人、改群设置、文件上传下载等）。
// - 发送类工具强制校验白名单：目标群/私聊必须命中 config.json 的
//   allow.groups / allow.private，否则拒绝 —— agent 只能往被允许的地方发消息。
// - 所有调用走 OneBot HTTP API（httpUrl + accessToken）。
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
// 出站文本的敏感信息拦截**统一由桥接负责**（bridge.js 的 auditAndSend / 各发送端点的
// SENSITIVE_RE 校验）：所有 QQ 发送都经由桥接 HTTP API，因此 MCP 侧不再重复实现一遍。
// 这里 import 只用于「出站审计口径一致」的说明，不在 MCP 内做拦截——
// 在 MCP 里拦会连「安全拒绝理由」都拿不到，反而让模型无法把话说清楚。
import { SENSITIVE_RE } from './sensitive.js';
import { serializeModelData } from './qq-model-view.js';
// 只看图不联网 = 认得画面但叫不出名字。qq_identify_image 用这里同一路搜索
// （DeepSeek 联网搜索，不可用回退 Bing）把"我看到的样子"换成候选名字。
import { webSearch } from './web-search.js';
// 工具分片的分组表与落盘状态。离线回归（test-audit-security-mcp.mjs）会把所有 `import ...;`
// 整段剥掉再用 vm 求值，所以下面所有引用都走 `typeof` 兜底：拿不到就退化成「全量挂载」。
import * as toolGroupsModule from './tool-groups.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

function loadConfig() {
  try {
    let text = fs.readFileSync(path.join(ROOT, 'config.json'), 'utf8');
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    return JSON.parse(text);
  } catch {
    return {};
  }
}

const cfg = loadConfig();

function getConfig() {
  return loadConfig();
}

function getAccess() {
  const c = getConfig();
  return {
    allowGroups: (c.allow?.groups ?? []).map(String),
    allowPrivate: (c.allow?.private ?? []).map(String),
    denyGroups: (c.deny?.groups ?? []).map(String),
    denyPrivate: (c.deny?.private ?? []).map(String),
    allowAllWhenEmpty: c.allowAllWhenEmpty === true
  };
}

function getOneBotConfig() {
  const c = getConfig();
  return {
    httpUrl: (c.snowluma?.httpUrl ?? 'http://127.0.0.1:3000').replace(/\/+$/, ''),
    token: c.snowluma?.accessToken ?? ''
  };
}

// 与 bridge.allowed 保持一致：allow 列表为空时按 allowAllWhenEmpty 放行
function isAllowed(allowList, denyList, id, allowAllWhenEmpty) {
  const s = String(id);
  if (denyList.includes(s)) return false;
  if (allowList.length > 0) return allowList.includes(s);
  return allowAllWhenEmpty;
}

// 兼容模型把单条消息序列化成 JSON 字符串的情况，例如 "\"你好\"" → "你好"。
function unquoteJsonString(value) {
  if (typeof value !== 'string') return value;
  const t = value.trim();
  if (t.startsWith('"')) {
    try {
      const parsed = JSON.parse(t);
      if (typeof parsed === 'string') return parsed;
    } catch {}
  }
  return value;
}

// 说明：本文件曾经有一对 escapeCqText() / messageSegments()，用于在 MCP 侧构造消息段。
// 它们从来没有被任何工具调用（发送一律走桥接的 /api/send/*，由桥接统一构造文本段并做
// CQ 转义，见 bridge.js 的 onebotSend），属于"看起来在防护、实际是死代码"的假安全。
// 这里直接删除，避免以后有人以为 MCP 侧还有一道 CQ 转义而放松桥接那一层。

async function onebot(action, params = {}) {
  const { httpUrl, token } = getOneBotConfig();
  const res = await fetch(`${httpUrl}/${action}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(params),
    signal: AbortSignal.timeout(15000)
  });
  if (!res.ok) {
    const hint = res.status === 426 ? '；HTTP 426 通常表示 httpUrl 指向了 WebSocket 端口，请检查 config.json 的 snowluma.httpUrl 是否为 OneBot HTTP API 地址' : '';
    throw new Error(`HTTP ${res.status}${hint}`);
  }
  const body = await res.json();
  if (body.status !== 'ok' || body.retcode !== 0) {
    throw new Error(`OneBot ${action} 失败: retcode=${body.retcode} ${body.wording ?? ''}`);
  }
  return body.data;
}

// 桥接控制台/内部 Agent API 访问：二代仿真模式的状态工具都通过这里读写桥接内存态。
function agentApiBase() {
  const port = Number(getConfig().consolePort) || 3100;
  return `http://127.0.0.1:${port}`;
}
function readConsoleToken() {
  // 每次请求都重新读取，优先 config.json 里的 consoleToken，其次 state/console-token，
  // 避免 token 变化后 MCP 仍使用启动时缓存的旧值导致一直 401。
  //
  // 必须与桥接的校验口径**完全一致**（bridge.js 的 startConsoleServer：长度 16~128、
  // 只允许 [A-Za-z0-9_-]，不合法就忽略并回退 state/console-token）。否则用户手填一个
  // 短令牌时桥接会正常运行，而 MCP 拿着这个桥接根本不认的值去请求 —— 每个工具都 401，
  // 且错误信息里看不出原因是"config.json 里的令牌格式不合法"。
  try {
    const c = getConfig();
    const configured = String(c.consoleToken ?? '').trim();
    if (/^[A-Za-z0-9_-]{16,128}$/.test(configured)) return configured;
  } catch {}
  try {
    const tokenFile = path.join(ROOT, 'state', 'console-token');
    return fs.readFileSync(tokenFile, 'utf8').trim();
  } catch {
    return '';
  }
}

/**
 * 把桥接返回的 `error` 变成可读文本。
 *
 * 为什么必须有：桥接个别分支会回一个**对象**（例如 `{code, message}`），直接
 * `new Error(obj)` 会把它 String 成 "[object Object]" —— 模型和运维都读不到任何信息。
 * r3 的已知未修项里就记着 `qq_wait_for_messages` 出现过 `error: "\"Error: [object Object]\""`。
 */
function errorText(value, fallback) {
  if (typeof value === 'string' && value.trim()) return value.trim();
  if (value && typeof value === 'object') {
    try {
      const text = JSON.stringify(value);
      if (text && text !== '{}') return text.slice(0, 500);
    } catch {}
    const message = value.message ?? value.msg ?? value.error;
    if (typeof message === 'string' && message.trim()) return message.trim().slice(0, 500);
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return fallback;
}

async function agentApi(path, init = {}) {
  const timeoutMs = init.timeoutMs || 15000;
  const { timeoutMs: _omit, ...rest } = init;
  const headers = agentHeaders(rest.headers);
  const res = await fetch(`${agentApiBase()}${path}`, { ...rest, headers, signal: AbortSignal.timeout(timeoutMs) });
  let body = null;
  try { body = await res.json(); } catch { body = null; }
  if (!res.ok) {
    throw new Error(errorText(body?.error, `桥接 API HTTP ${res.status}`));
  }
  // 桥接的部分端点会用 200 + {ok:false,error} 表达业务失败（例如发送被审计拦截）。
  // 不检查 body.ok 会把「被拦截」当成「发送成功」上报给模型 —— 模型据此认为消息已发出，
  // 于是不再重试也不告诉用户，是典型的静默错误。
  if (body && typeof body === 'object' && body.ok === false) {
    throw new Error(errorText(body.error, '桥接 API 返回 ok:false（未说明原因）'));
  }
  return body;
}

/**
 * 桥接 API 请求头（含控制台令牌、x-agent-call 与调用方附加头）。
 * 拆出来是为了长轮询通道复用同一套鉴权，避免两条通路口径漂移。
 */
function agentHeaders(extra = {}) {
  const consoleToken = readConsoleToken();
  const headers = {
    'content-type': 'application/json',
    ...(consoleToken ? { 'x-console-token': consoleToken } : {}),
    ...(extra ?? {})
  };
  // 声明「这是一次智能体调用」。桥接据此把「没带会话令牌」判定为**拒绝**，而不是
  // 退化成「管理端全权」——所以这个头绝不能随 token 一起被省略。历史上 331/355/379/877
  // 行用 `...(token ? {headers:{...}} : {})` 把整个头省掉了，于是「模型漏传 token」
  // 不是被拒绝，反而提权成控制台权限（confused deputy）。
  // 令牌本身仍然只在真有时才发：/api/status 的模式探测（legacyReadToolAllowed）本来就是
  // 无令牌调用，桥接对它单独放行并按最小对象返回。
  headers['x-agent-call'] = '1';
  return headers;
}

/**
 * 长轮询专用 POST（`node:http`，不经过 undici）。
 *
 * 为什么必须单独一条：Node 的全局 `fetch` 是 undici，自带 300 秒 `headersTimeout`。
 * 而 `qq_wait_for_messages` 的常规用法就是 `timeoutMs=300000` 的沉睡前观察 ——
 * 客户端会在第 301 秒以 `fetch failed / Headers Timeout Error` 断掉，桥接侧的
 * 长轮询却还在跑满自己的预算：AI 拿不到结果只能重试，而 `activeWaits` 仍占着会话
 * （重新等待被 429），于是空转烧 token（见 issue #24）。`node:http` 没有默认响应超时，
 * 超时完全由这里的计时器按调用方预算控制。
 */
function agentApiLongPoll(path, init = {}) {
  const timeoutMs = Math.max(1000, Number(init.timeoutMs) || 15000);
  const url = new URL(`${agentApiBase()}${path}`);
  const body = init.body == null ? '' : String(init.body);
  const headers = agentHeaders(init.headers);
  headers['content-length'] = Buffer.byteLength(body);
  return new Promise((resolve, reject) => {
    let settled = false;
    let req;
    let res;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value);
    };
    const timer = setTimeout(() => {
      const error = new Error(`等待超时（${Math.round(timeoutMs / 1000)}s）`);
      finish(error);
      req?.destroy(error);
      res?.destroy();
    }, timeoutMs);
    timer.unref?.();
    try {
      req = http.request({
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname + url.search,
        method: init.method || 'GET',
        headers,
        timeout: 0
      }, (response) => {
        res = response;
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          if (settled) return;
          size += chunk.length;
          // 桥接的 wait 响应本来就是小 JSON；超过 4MB 说明对端异常，别把内存吃光。
          if (size > 4 * 1024 * 1024) {
            finish(new Error('等待响应体过大，已中止'));
            response.destroy();
            return;
          }
          chunks.push(chunk);
        });
        response.on('error', (error) => finish(error));
        response.on('aborted', () => finish(new Error('等待响应中断')));
        response.on('close', () => { if (!response.complete) finish(new Error('等待响应中断')); });
        response.on('end', () => {
          if (settled) return;
          let parsed = null;
          try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { parsed = null; }
          const status = response.statusCode || 0;
          if (status < 200 || status >= 300) {
            finish(new Error(errorText(parsed?.error, `桥接 API HTTP ${status}`)));
            return;
          }
          if (parsed && typeof parsed === 'object' && parsed.ok === false) {
            finish(new Error(errorText(parsed.error, '桥接 API 返回 ok:false（未说明原因）')));
            return;
          }
          finish(null, parsed);
        });
      });
      req.on('error', (error) => finish(error));
      req.end(body);
    } catch (error) {
      finish(error);
      req?.destroy();
    }
  });
}

async function authorizeRead(key) {
  // 会话令牌必须显式携带：桥接已把空令牌的请求一律拒绝（避免把该端点变成免鉴权入口）。
  // 旧只读工具没有令牌，因此它们改由 legacyReadToolAllowed() 做模式判定，不再调用本函数。
  throw new Error('旧只读工具没有会话令牌；请使用带会话令牌的 v2 读工具');
}

// 旧只读工具（qq_status 之外的 qq_list_groups / qq_get_group_members / qq_get_group_history）
// 没有会话令牌，因此**只能在封闭 agent（管理员私聊）里使用**。
//
// 这里用「确认是 closed-agent 才放行」的白名单写法，而不是「看到 reserved2 就拒绝」的黑名单写法：
// 桥接的 /api/status 在「带 agent 令牌」时返回的是最小状态对象（不含 mode 字段），
// 用 `status?.mode === 'reserved2'` 判断会得到 undefined ⇒ 黑名单判定为假 ⇒ 旧工具被放行，
// 等于在二代仿真模式下把白名单群名、群成员名单注入模型上下文。
async function legacyReadToolAllowed() {
  const status = await agentApi('/api/status');
  return String(status?.mode ?? '') === 'closed-agent';
}

const server = new McpServer({ name: 'snowluma-safe', version: '0.2.1-r1' });

// ── 工具开关必须在**注册期**生效，而不是只在校验期 ──────────────────────────
//
// 为什么：每个工具的描述 + 参数 schema 都会随 system prompt 在**每一次**请求里重发
// （实测 41 个工具约 8.8k token）。只在校验时 403 的话，被关掉的工具依然占着上下文、
// 依然会让模型看见并调用它（然后拿到一个错误），等于「关了个寂寞」。
//
// 这里用一个注册过滤器统一处理：开关关闭 ⇒ 该工具根本不注册 ⇒ 既省 token 又不给模型误调的机会。
// DSH 在启动时读取工具清单，所以关掉/打开后需要重启 DSH 才会刷新（控制台面板已注明）。
//
// 只列**各模式共用的工具不在其中**：qq_send_group_message / qq_send_private_message / qq_reply
// 同时服务 chat / reserved / closed-agent 模式，用 v2 的开关去决定它们是否注册会误伤其它模式，
// 所以这三个仍然只在调用时由桥接校验。
const TOOL_CONFIG_FLAGS = {
  qq_get_prompt: 'getPrompt',
  qq_get_unread_messages: 'getUnread',
  qq_get_recent_messages: 'getRecent',
  qq_social_state: 'socialState',
  qq_mark_read: 'markRead',
  qq_set_wake_config: 'setWakeConfig',
  qq_send_burst: 'sendBurst',
  qq_send_message: 'sendMessage',
  qq_wait_for_messages: 'waitMessages',
  qq_report_feedback: 'feedback',
  qq_get_my_recent_messages: 'getMyRecent',
  qq_get_message_detail: 'getMessageDetail',
  qq_get_active_members: 'getActiveMembers',
  qq_get_group_members: 'getGroupMembers',
  qq_memory_append: 'memory',
  qq_memory_update: 'memory',
  qq_memory_query: 'memory',
  qq_memory_remove: 'memory',
  qq_memory_clear: 'memory',
  qq_slang_query: 'slangQuery',
  qq_slang_submit: 'slangSubmit',
  qq_send_voice: 'sendVoice',
  qq_speak: 'sendVoice',
  qq_sing: 'sendVoice',
  qq_list_voices: 'sendVoice',
  // 下面这些曾经漏登记。漏一个不是"多注册一个工具"那么轻：桥接那边按 `v2ToolEnabled(flag)`
  // 在**调用期**一律 403，而这里不登记就等于"控制台显示已关闭、模型每次请求仍收到它的完整
  // 描述与参数 schema，然后调用它、再拿到 403"——既白烧 token（本文件开头 176 行起就是为省这份
  // token 才改注册期过滤的），又诱导模型误调。`qq_set_sticker_remark` 默认就是 `false`
  // （见 bridge.js 的 socialV2.tools 默认表），所以此前它一直是"默认关闭却仍然可见"。
  qq_send_poke: 'sendPoke',
  qq_get_message_images: 'getImages',
  // 认图与看图共用 getImages 开关：两者都是"读这条消息里的图"，关掉看图就没必要留着认图
  // （认图的核心也是把图给你看）。桥接侧 /api/images/message 同样只认 getImages。
  qq_identify_image: 'getImages',
  qq_get_forward_msg: 'getForwardMsg',
  qq_list_stickers: 'listStickers',
  qq_get_sticker_image: 'getStickerImage',
  qq_send_sticker: 'sendSticker',
  qq_collect_sticker: 'collectSticker',
  qq_import_sticker: 'importSticker',
  qq_douyin_comments: 'douyin',
  qq_douyin_grab_sticker: 'douyin',
  qq_douyin_learn: 'douyin',
  qq_get_self_image: 'getSelfImage',
  qq_sticker_note: 'stickerNote',
  qq_set_sticker_remark: 'setStickerRemark',
  qq_recall_message: 'recallMessage',
  qq_qzone_post: 'qzonePost',
  qq_qzone_delete: 'qzoneDelete',
  qq_qzone_list: 'qzoneList',
  qq_qzone_feeds: 'qzoneFeed',
  qq_qzone_comment: 'qzoneComment',
  qq_qzone_like: 'qzoneLike',
  qq_qzone_unlike: 'qzoneUnlike',
  qq_get_self_profile: 'getSelfProfile',
  qq_set_nickname: 'setNickname',
  qq_set_avatar: 'setAvatar',
  qq_set_group_card: 'setGroupCard',
};
const disabledTools = [];
// 注册期登记表：name -> SDK 返回的 registeredTool（带 enable()/disable()）。
// 工具分片要在**全部注册完之后**按组关掉一批（见文件末尾的 applyToolGroups），
// 所以这里必须把注册产物留个引用，否则只能靠名字去摸 SDK 内部结构。
const registeredTools = new Map();
{
  const registerTool = server.tool.bind(server);
  server.tool = (name, ...rest) => {
    const flag = TOOL_CONFIG_FLAGS[name];
    if (flag && cfg.socialV2?.tools?.[flag] === false) {
      disabledTools.push(`${name}(${flag})`);
      return undefined;
    }
    const registered = registerTool(name, ...rest);
    if (registered) registeredTools.set(name, registered);
    return registered;
  };
}

server.tool(
  'qq_status',
  '查询 QQ 机器人登录状态与账号信息（只读）。',
  {},
  async () => {
    try {
      const login = await onebot('get_login_info');
      let status = {};
      try { status = await onebot('get_status'); } catch {}
      return { content: [{ type: 'text', text: serializeModelData({ ...login, online: status.online, good: status.good }) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `查询失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

// ── 旧只读工具：**按启动时的桥接模式决定是否注册** ─────────────────────────
//
// 为什么必须在注册期就砍掉（而不是只在调用期 403）：
//   每个工具的描述 + 参数 schema 都随 system prompt 在**每一次**请求里重发。
//   实测一份 reserved2 会话的请求头是「58 个工具 / 45.5 KB schema（≈14k token/次）」，
//   其中 3 个旧只读工具在 reserved2 下**必然**返回 403，却照样占着 2500+ 字节；
//   更要命的是它们会诱导模型误调（实测 turn10 有一次 qq_get_group_members → 403，白烧一步）。
//   本文件开头（TOOL_CONFIG_FLAGS 那段）已经为「关掉的工具」立过同样的规矩，这里补齐模式维度。
//
// 语义：旧只读工具没有会话令牌，`legacyReadToolAllowed()` 只放行 closed-agent。
//   所以只有在 closed-agent 下注册它们才有意义。探测失败（读不到状态文件）时按「注册」处理：
//   那种情况下所有 QQ 工具都不可用，少注册只会让模型看到更少的失败路径，不必激进。
//
// ⚠️ 为什么读 `state/mode.json` 而**不**去问 `/api/status`：
//   注册发生在模块加载期，走网络就得用 top-level await；而本文件会被若干离线回归
//   （test-audit-security-mcp.mjs）用 `vm`/`new Function` 求值，那里没有 TLA —— 会直接
//   `ReferenceError: await is not defined`，把整批断言打红。模式文件是桥接每次切换模式时
//   原子写出的（bridge.js 的 writeMode），与 `/api/status` 同源，读盘既准确又是同步的。
const bootBridgeMode = (() => {
  try {
    const raw = fs.readFileSync(path.join(ROOT, 'state', 'mode.json'), 'utf8');
    const parsed = JSON.parse(raw);
    return String(parsed?.mode ?? '').trim();
  } catch { return ''; }
})();
const registerLegacyReadTools = bootBridgeMode === '' || bootBridgeMode === 'closed-agent';
if (!registerLegacyReadTools) {
  console.error(`[snowluma-safe] 当前桥接模式 ${bootBridgeMode}：不注册旧只读工具（qq_list_groups / qq_get_group_history），改用带令牌的 v2 读工具`);
}

if (registerLegacyReadTools) {
server.tool(
  'qq_list_groups',
  '列出机器人所在的全部 QQ 群（只读）：群号、群名。',
  {},
  async () => {
    // 旧只读工具没有 agent token：只允许在封闭 agent（管理员私聊）里使用。
    // 判定失败一律拒绝（fail-closed），不依赖「看到某个模式才拒绝」的黑名单写法。
    try {
      if (!(await legacyReadToolAllowed())) {
        return { content: [{ type: 'text', text: '旧只读工具仅在封闭 agent（管理员私聊）模式可用；其它模式请使用带会话令牌的 v2 读工具' }], isError: true };
      }
    } catch (error) {
      return { content: [{ type: 'text', text: `无法确认当前模式，拒绝执行：${error?.message ?? error}` }], isError: true };
    }
    try {
      const a = getAccess();
      const data = await onebot('get_group_list');
      const list = (Array.isArray(data) ? data : (data?.data ?? []))
          .filter((g) => isAllowed(a.allowGroups, a.denyGroups, g.group_id, a.allowAllWhenEmpty))
          .map((g) => ({ group_id: g.group_id, group_name: g.group_name }));
      return { content: [{ type: 'text', text: serializeModelData(list) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `查询失败：${error?.message ?? error}` }], isError: true };
    }
  }
);
}

// 群成员列表：**换成 v2 形态**（key + token）。
//
// 为什么不再沿用旧的无令牌版本：它是 qq-chat-v2 预设里唯一被点名的"拿 QQ 号"的途径
// （见 dsh/agent-presets/qq-chat-v2/agent.cordis.yml 第 6 条），但旧版在 reserved2 下必然 403
// —— 预设教模型用一个永远失败的工具，等于每次都白烧一步。改成 v2 后同一个名字在两种模式下都成立。
server.tool(
  'qq_get_group_members',
  '列出指定群的成员（只读）：QQ 号、昵称、群名片。等特定的人、要 @ 某个人、或需要确认谁在群里时用；QQ 号取返回里的 userId。只返回白名单群，且只读取桥接允许的会话。',
  {
    key: z.string().describe('会话 key，格式 group:群号'),
    token: z.string().optional().describe('会话令牌（见唤醒提示中的【会话令牌】；closed-agent 模式不需要）'),
    limit: z.number().optional().describe('最多返回多少成员，默认 50，最大 100')
  },
  async ({ key, token, limit }) => {
    try {
      const q = new URLSearchParams({ key });
      if (limit != null) q.set('limit', String(limit));
      // token 可选：closed-agent（管理员私聊）里代理没有会话令牌，走的是操作者路径；
      // 桥接那边的白名单/模式判定对**这条**请求同样生效（不依赖 header 是否存在）。
      const data = await agentApi(`/api/socialV2/group-members?${q.toString()}`, token ? { headers: { 'x-agent-token': token } } : {});
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `获取群成员失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

if (registerLegacyReadTools) {
server.tool(
  'qq_get_group_history',
  '获取指定群的最近消息历史（只读）。messageSeq 可选：从该消息序号往前取。注意：是否可用取决于 SnowLuma 是否实现 get_group_msg_history。',
  { groupId: z.union([z.number(), z.string()]).describe('群号'), messageSeq: z.number().optional().describe('起始消息序号（可选）') },
  async ({ groupId, messageSeq }) => {
    const g = String(groupId);
    try {
      if (!(await legacyReadToolAllowed())) {
        return { content: [{ type: 'text', text: '旧只读工具仅在封闭 agent（管理员私聊）模式可用；其它模式请使用带会话令牌的 v2 读工具' }], isError: true };
      }
    } catch (error) {
      return { content: [{ type: 'text', text: `无法确认当前模式，拒绝读取：${error?.message ?? error}` }], isError: true };
    }
    const a = getAccess();
    if (!isAllowed(a.allowGroups, a.denyGroups, g, a.allowAllWhenEmpty)) {
      return { content: [{ type: 'text', text: `拒绝：群 ${g} 不在只读白名单中` }], isError: true };
    }
    try {
      const params = { group_id: Number(g) };
      if (messageSeq !== undefined) params.message_seq = messageSeq;
      const data = await onebot('get_group_msg_history', params);
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `查询失败：${error?.message ?? error}` }], isError: true };
    }
  }
);
}

server.tool(
  'qq_send_group_message',
  '向指定 QQ 群发送一条纯文本消息；如需引用某条消息，可传 replyToMessageId（非零整数，可为负数），可先用 qq_get_recent_messages / qq_get_message_detail 查询。二代模式（reserved2）下这是可用的发送工具之一，但优先使用 qq_send_message；reserved2 下调用时必须携带会话令牌 token，否则会被拒绝。不要在发送后输出“已发送”类汇报。目标群必须命中系统白名单（config.json 的 allow.groups），否则拒绝。',
  {
    groupId: z.union([z.number(), z.string()]).describe('群号（必须在白名单内）'),
    message: z.string().describe('消息文本，纯文本，不要用 Markdown 或 CQ 码'),
    replyToMessageId: z.union([z.number(), z.string()]).optional().describe('要引用/回复的消息 id（非零整数，可为负数，可选）'),
    token: z.string().optional().describe('二代会话令牌（reserved2 模式下必填；closed-agent 模式不需要）')
  },
  async ({ groupId, message, replyToMessageId, token }) => {
    try {
      const cleanMessage = unquoteJsonString(message);
      const data = await agentApi('/api/send/group', {
        method: 'POST',
        // token 既放 body（兼容旧调用）又放 header：桥接的「agent 流量」判定基于 header，
        // 只带 body 会让这条请求在桥接眼里像控制台请求，绕过 agent 专用的闸门与审计。
        ...(token ? { headers: { 'x-agent-token': token } } : {}),
        body: JSON.stringify({ groupId: String(groupId), message: cleanMessage, replyToMessageId, token: token || undefined })
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `发送失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_reply',
  '在指定 QQ 群里引用/回复某条消息，并发送一条文本。适合群消息很多、需要明确“我回的是哪条”时使用；replyToMessageId 是被引用消息的 id（非零整数，QQ 消息 id 可能为负数），可先用 qq_get_recent_messages / qq_get_unread_messages / qq_get_message_detail 查到具体消息内容和 id。发送前桥接会校验该 id 存在且属于当前会话。二代模式下这是你正常可用的引用工具，但不要每条都引用。只有以下情况才需要引用：① 你这条消息指向的人或消息并非最新一条别人的消息（也就是你在回更早的某条）；② 你连续几句话里不同消息指代的是不同的消息或不同的人。其他情况（上下文唯一、刚在接同一条最新消息）不要引用，别让对方猜，也别为了用工具而用。reserved2 下调用时必须携带会话令牌 token。目标群必须命中系统白名单（config.json 的 allow.groups），否则拒绝。',
  {
    groupId: z.union([z.number(), z.string()]).describe('群号（必须在白名单内）'),
    replyToMessageId: z.union([z.number(), z.string()]).describe('被引用/回复的消息 id（非零整数，可为负数）'),
    message: z.string().describe('要发送的文本，纯文本，不要用 Markdown 或 CQ 码'),
    token: z.string().optional().describe('二代会话令牌（reserved2 模式下必填；closed-agent 模式不需要）')
  },
  async ({ groupId, replyToMessageId, message, token }) => {
    try {
      const cleanMessage = unquoteJsonString(message);
      const data = await agentApi('/api/send/reply', {
        method: 'POST',
        ...(token ? { headers: { 'x-agent-token': token } } : {}),
        body: JSON.stringify({ groupId: String(groupId), replyToMessageId, message: cleanMessage, token: token || undefined })
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `发送失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_send_private_message',
  '向指定 QQ 好友发送一条私聊消息。若提供 replyToMessageId，会以 QQ 引用/回复形式发出（引用条 + 文本）。replyToMessageId 必须是非零整数消息 id（QQ 消息 id 可能为负数），可先用 qq_get_message_detail 查询。二代模式（reserved2）下这是可用的发送工具之一，但优先使用 qq_send_message；调用时必须携带会话令牌 token，否则会被拒绝。不要在发送后输出“已发送”类汇报。目标 QQ 必须命中系统白名单（config.json 的 allow.private），否则拒绝。',
  {
    userId: z.union([z.number(), z.string()]).describe('好友 QQ 号（必须在白名单内）'),
    message: z.string().describe('消息文本，纯文本，不要用 Markdown 或 CQ 码'),
    replyToMessageId: z.union([z.number(), z.string()]).optional().describe('要引用/回复的消息 id（非零整数，可为负数，可选）'),
    token: z.string().optional().describe('二代会话令牌（reserved2 模式下必填；closed-agent 模式不需要）')
  },
  async ({ userId, message, replyToMessageId, token }) => {
    try {
      const cleanMessage = unquoteJsonString(message);
      const data = await agentApi('/api/send/private', {
        method: 'POST',
        ...(token ? { headers: { 'x-agent-token': token } } : {}),
        body: JSON.stringify({ userId: String(userId), message: cleanMessage, replyToMessageId, token: token || undefined })
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `发送失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

// ── 二代仿真模式（reserved2）工具 ─────────────────────────────────────────
server.tool(
  'qq_get_prompt',
  '查看当前二代仿真模式的提示词/角色/推荐值/可用工具/当前唤醒配置（只读）。',
  { key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'), token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）') },
  async ({ key, token }) => {
    try {
      const data = await agentApi(`/api/socialV2/prompt?key=${encodeURIComponent(key)}`, { headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `获取提示词失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_get_unread_messages',
  '查看未读消息，不自动标记已读。大量积压或快照 partial=true 时，用 afterSeq=readThroughSeq 从水位后按时间顺序补读；从最早未读开始传 0。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    limit: z.number().optional().describe('最多返回条数，默认 30，最大 100'),
    afterSeq: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional().describe('读取本地 seq 大于此水位的最早一页；省略则沿用返回最新一页的旧行为')
  },
  async ({ key, token, limit, afterSeq }) => {
    try {
      const data = await agentApi(`/api/socialV2/unread?key=${encodeURIComponent(key)}&limit=${limit ?? 30}${afterSeq === undefined ? '' : `&afterSeq=${afterSeq}`}`, { headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `获取未读消息失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_get_recent_messages',
  '查看指定会话的最近消息（只读），支持 offset 扩大范围。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    limit: z.number().optional().describe('最多返回条数，默认 20，最大 100'),
    offset: z.number().optional().describe('跳过最近 N 条，用于向前翻看更早消息，默认 0')
  },
  async ({ key, token, limit, offset }) => {
    try {
      const data = await agentApi(`/api/socialV2/recent?key=${encodeURIComponent(key)}&limit=${limit ?? 20}&offset=${offset ?? 0}`, { headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `获取最近消息失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_social_state',
  '查看指定会话的二代仿真状态：WakeConfig、未读数、上次唤醒原因、上次发言时间等（只读）。',
  { key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'), token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）') },
  async ({ key, token }) => {
    try {
      const data = await agentApi(`/api/socialV2/state?key=${encodeURIComponent(key)}`, { headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `获取状态失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_mark_read',
  '将指定会话已查看的未读消息标记为已读。throughSeq 使用最近读取结果的 readThroughSeq，避免清除读取后才到达的新消息；省略 throughSeq 会按旧行为清空当前全部未读，因此推荐始终带上水位。注意：每次设置潜水/下一次唤醒前，桥接要求先用 qq_wait_for_messages(timeoutMs=300000) 完成一次沉睡前观察：5 分钟内没人说话可 mark_read 收尾沉睡；期间有人发新消息则先查看 newMessages，判断不需要你参与也可直接 mark_read 收尾；若你参与了回复，则下次想睡需重新等待观察窗口。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    throughSeq: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional().describe('本次确认已读的消息水位，使用已查看结果中的 readThroughSeq；不会清除更晚到达的消息')
  },
  async ({ key, token, throughSeq }) => {
    try {
      const data = await agentApi('/api/socialV2/mark-read', { method: 'POST', body: JSON.stringify({ key, throughSeq }), headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `标记已读失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_set_wake_config',
  '设置指定会话的二代唤醒配置：mode/无限期或有限时间/提前唤醒条件（@、名字、关键词、提问、拍一拍、概率、anyMessage、指定成员）。triggers.speakerIds 是可选的“指定群友发言唤醒”：填一个或多个群友 QQ 号后，只要其中任意一位在群里发言就会唤醒你；不设置则不启用。适合在等某个人回复、或某人反应慢怕错过时使用。triggers.poke 开启后，群里有人拍一拍（包括拍你或拍别人）会唤醒你。注意：每次设置潜水/下一次唤醒前需先用 qq_wait_for_messages(timeoutMs=300000) 完成一次沉睡前观察：5 分钟内没人说话可设置并沉睡；期间有人发新消息则先查看 newMessages，判断不需要你参与可直接设置并沉睡；若你参与了回复，则下次想睡需重新等待观察窗口。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    throughSeq: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional().describe('可同时确认已读：使用已查看结果中的 readThroughSeq，省去额外 qq_mark_read；不传则只设置唤醒配置。若 markRead 工具被关闭，该水位会被忽略，本工具只设置唤醒配置'),
    config: z.object({
      mode: z.enum(['diving', 'active']).optional().describe('diving=潜水，active=活跃（anyMessage 开启）'),
      infinite: z.boolean().optional().describe('true=无限期，只有条件命中才唤醒；false=有限时间'),
      sleepMs: z.number().optional().describe('有限潜水毫秒数（从当前时间起算）'),
      sleepUntil: z.string().optional().describe('有限潜水截止时间 ISO 字符串，优先级高于 sleepMs'),
      triggers: z.object({
        atMention: z.boolean().optional().describe('被 @ 或引用自己时唤醒'),
        nameMention: z.boolean().optional().describe('被叫名字/昵称时唤醒'),
        speakerIds: z.array(z.union([z.number(), z.string()])).max(20).optional().describe('指定群友 QQ 号数组：这些群友中任意一位发言时唤醒（可选，最多 20 个，不设置则不启用；私聊不适用，设置会被桥接清除；可从 qq_get_active_members / qq_get_group_members / qq_get_message_detail 的 userId/user_id 获取）'),
        keywords: z.array(z.string()).optional().describe('出现任意关键词时唤醒'),
        question: z.boolean().optional().describe('被直接提问/点名挑战时唤醒'),
        poke: z.boolean().optional().describe('有人拍一拍时唤醒（群聊包括拍你和拍别人，私聊为对方拍你）'),
        anyMessage: z.boolean().optional().describe('任意新消息都唤醒（活跃模式）'),
        probability: z.number().optional().describe('普通消息按该概率随机唤醒（0~1）')
      }).optional(),
      batchWindowMs: z.number().optional().describe('多条消息合并唤醒窗口（毫秒，>=1000）')
    }).describe('要设置的唤醒配置，缺省字段保留原值')
  },
  async ({ key, token, config, throughSeq }) => {
    try {
      const data = await agentApi('/api/socialV2/wake-config', { method: 'POST', body: JSON.stringify({ key, config, throughSeq }), headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `设置唤醒配置失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_send_burst',
  '在指定 QQ 群分多条发送消息（二代仿真模式专用），桥接会按真人化随机间隔发送。暂不支持引用，需要引用请用 qq_reply。注意：数组里的每个字符串就是一条 QQ 消息，字符串内部不要用空格分隔中文短句，需要多条请用数组元素；每条消息要读起来完整，不要把同一句话拆到两条里。',
  {
    groupId: z.union([z.number(), z.string()]).describe('群号（必须在白名单内）'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    messages: z.union([z.array(z.string()).min(1), z.string()]).describe('要发送的消息数组，每条为纯文本；也兼容传入 JSON 数组字符串')
  },
  async ({ groupId, token, messages }) => {
    try {
      const key = `group:${groupId}`;
      let finalMessages = messages;
      if (typeof finalMessages === 'string') {
        const trimmed = finalMessages.trim();
        // 兼容模型把数组序列化成 JSON 字符串传入的情况，例如 "[...]"。
        if (trimmed.startsWith('[')) {
          try {
            const parsed = JSON.parse(trimmed);
            if (Array.isArray(parsed)) finalMessages = parsed.map(String);
          } catch {}
        } else if (trimmed.startsWith('"')) {
          // 兼容模型把单条消息序列化成 JSON 字符串的情况，例如 "\"你好\"" → "你好"。
          try {
            const parsed = JSON.parse(trimmed);
            if (typeof parsed === 'string') finalMessages = parsed;
            else if (Array.isArray(parsed)) finalMessages = parsed.map(String);
          } catch {}
        }
      }
      const data = await agentApi('/api/socialV2/send-burst', {
        method: 'POST',
        body: JSON.stringify({ key, messages: finalMessages }),
        headers: { 'x-agent-token': token },
        timeoutMs: 300000
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `分条发送失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_send_message',
  '统一发送工具：可发一条或多条，可引用某条消息，可自定义/按字数计算条间时间差。二代仿真模式专用。注意：字符串=一条消息，数组=多条消息；每个字符串内部不要用空格分隔中文短句，需要多条请用数组元素；每条消息要读起来完整，不要把同一句话拆到两条里。只有以下情况才需要传 replyToMessageId 引用：① 你这条消息指向的人或消息并非最新一条别人的消息（也就是你在回更早的某条）；② 你连续几句话里不同消息指代的是不同的消息或不同的人。其他情况（上下文唯一、刚在接同一条最新消息）不要引用，别让对方猜，也别为了用工具而用。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    messages: z.union([z.string(), z.array(z.string()).min(1)]).describe('要发送的内容：字符串=一条；数组=分多条'),
    replyToMessageId: z.union([z.number(), z.string()]).optional().describe('要引用/回复的消息 id（非零整数，可为负数，可选）'),
    atUserId: z.union([z.number(), z.string()]).optional().describe('要 @ 的群成员 QQ 号（群聊中用于点名某个人；与引用二选一即可，不要滥用）'),
    gapMode: z.enum(['auto', 'fixed', 'byLength']).optional().describe('auto=桥接随机；fixed=固定间隔；byLength=按字数计算'),
    gapMs: z.number().optional().describe('fixed 模式下的统一间隔（毫秒）'),
    gaps: z.array(z.number()).optional().describe('fixed 模式下逐条间隔（长度=条数-1）')
  },
  async ({ key, token, messages, replyToMessageId, atUserId, gapMode, gapMs, gaps }) => {
    try {
      let finalMessages = messages;
      if (typeof finalMessages === 'string') {
        const trimmed = finalMessages.trim();
        // 兼容模型把数组序列化成 JSON 字符串传入的情况，例如 "[...]"。
        if (trimmed.startsWith('[')) {
          try {
            const parsed = JSON.parse(trimmed);
            if (Array.isArray(parsed)) finalMessages = parsed.map(String);
          } catch {}
        } else if (trimmed.startsWith('"')) {
          // 兼容模型把单条消息序列化成 JSON 字符串的情况，例如 "\"你好\"" → "你好"。
          try {
            const parsed = JSON.parse(trimmed);
            if (typeof parsed === 'string') finalMessages = parsed;
            else if (Array.isArray(parsed)) finalMessages = parsed.map(String);
          } catch {}
        }
      }
      const data = await agentApi('/api/socialV2/send-message', {
        method: 'POST',
        body: JSON.stringify({ key, messages: finalMessages, replyToMessageId, atUserId: atUserId ?? null, gapMode, gapMs, gaps }),
        headers: { 'x-agent-token': token },
        timeoutMs: 300000
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `发送失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

if (cfg.socialV2?.tools?.sendPoke !== false) {
  server.tool(
    'qq_send_poke',
    '发送 QQ 拍一拍（群聊/私聊）。适合用“戳一下”代替一句废话、提醒对方、自然回应别人的拍一拍，或偶尔主动戳一下正在聊的人/熟人——这样更拟真；但别频繁，真人不会一直戳人。群聊必须传 targetUserId（要拍的群友 QQ 号，可从 qq_get_active_members / qq_get_message_detail 的 userId 获取）；私聊可不传 targetUserId（默认拍当前私聊对象）。reserved2 下必须携带会话令牌 token，发送会受桥接白名单与发送频率限制。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      targetUserId: z.union([z.number(), z.string()]).optional().describe('要拍的群友 QQ 号（群聊必填；私聊可选）')
    },
    async ({ key, token, targetUserId }) => {
      try {
        const data = await agentApi('/api/socialV2/send-poke', {
          method: 'POST',
          body: JSON.stringify({ key, targetUserId: targetUserId != null ? String(targetUserId) : '' }),
          headers: { 'x-agent-token': token },
          timeoutMs: 60000
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `拍一拍失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

server.tool(
  'qq_wait_for_messages',
  '等待分两种用途。首答前已读消息、只想确认有没有补充：用 purpose="reply"，按最后来信时间补足 quietMs 静默，已安静足够就立即返回；读取/思考时新到的消息也会返回，新消息重算静默。timeoutMs 是最长预算，不要求等满；预算到但 quiet=false 不代表对方已说完。此用途绝不代替沉睡前观察。等对方继续说、等回复或睡前观察：用默认 purpose="messages"；先等新消息，收到后才按 quietMs 等静默，没有新消息会等到 timeoutMs，单传 quietMs 不会缩短总等待。静默下限由后台配置，默认 10000ms。**返回里的 canSleepNow / countsAsObservation / hint 直接告诉你现在能不能收尾、该用多大的 timeoutMs——照它做，不要反复试**：canSleepNow=true 就可以直接 mark_read / set_wake_config；false 时按 hint 给的 timeoutMs 一次等满（更短的等待不算沉睡前观察，满足不了闸门）。直接看 newMessages、unreadCount 和 readThroughSeq，返回消息无需重复查询；仍有未展示未读才补读。决定潜水/收尾时才用默认用途加 timeoutMs=300000 完成沉睡前观察，不能把 5 分钟观察放在首答之前；短等待不能代替。全程无人说话返回 preSleepWaitSatisfied=true；观察期间来了新消息返回 preSleepWaitObserved=true，读后不需参与可收尾，参与回复则下次收尾重新观察。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    purpose: z.enum(['messages', 'reply']).optional().describe('默认 messages：等新消息/回复/睡前观察；reply：回复前短静默，计入最后来信后已过去的时间，绝不授予睡前观察资格'),
    timeoutMs: z.number().optional().describe('等待预算毫秒数，默认 30000、最大 600000；reply 达到静默即返回，不必等满；沉睡前观察用 messages 并传 300000'),
    minNewMessages: z.number().optional().describe('仅 messages 用途：至少等到多少条新消息才进入静默窗口，默认 1；reply 用途会忽略它'),
    quietMs: z.number().optional().describe('静默窗口毫秒数，建议 10000~12000；reply 从最后来信开始计时，messages 只在等到新消息后计时；后台默认至少 10000')
  },
  async ({ key, token, purpose, timeoutMs, minNewMessages, quietMs }) => {
    try {
      // 必须走长轮询通道：全局 fetch（undici）有 300s headersTimeout，
      // 而沉睡前观察的预算就是 300s（见 agentApiLongPoll 的说明）。
      const data = await agentApiLongPoll('/api/socialV2/wait', {
        method: 'POST',
        body: JSON.stringify({ key, purpose, timeoutMs, minNewMessages, quietMs }),
        headers: { 'x-agent-token': token },
        timeoutMs: Math.min(725000, (Number(timeoutMs) || 30000) + Math.max(Number(quietMs) || 0, 10000) + 20000)
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `等待失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_report_feedback',
  '向控制台/管理端反馈 AI 遇到的问题、困惑或需要管理员介入的情况。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    level: z.enum(['info', 'warning', 'error']).optional().describe('反馈级别，默认 info'),
    message: z.string().describe('反馈内容')
  },
  async ({ key, token, level, message }) => {
    try {
      const data = await agentApi('/api/socialV2/feedback', {
        method: 'POST',
        body: JSON.stringify({ key, level, message }),
        headers: { 'x-agent-token': token }
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `反馈失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_get_my_recent_messages',
  '查看自己最近发过的消息（只读），避免重复/保持人设。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    limit: z.number().optional().describe('最多返回条数，默认 10，最大 50')
  },
  async ({ key, token, limit }) => {
    try {
      const data = await agentApi(`/api/socialV2/my-recent?key=${encodeURIComponent(key)}&limit=${limit ?? 10}`, { headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `获取自己消息失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_get_message_detail',
  '按 message_id / 本地 seq 查看单条消息的发送者、引用信息与正文（只读）。注意：正文最多返回 200 字符，textTruncated=true 表示被截断，这里不是读取长消息全文的入口。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    messageId: z.union([z.number(), z.string()]).describe('要查看的消息 id（QQ 消息 id 可能为负数）')
  },
  async ({ key, token, messageId }) => {
    try {
      const data = await agentApi(`/api/socialV2/message-detail?key=${encodeURIComponent(key)}&messageId=${encodeURIComponent(String(messageId))}`, { headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `获取消息详情失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_get_active_members',
  '查看最近活跃成员列表（只读），帮助判断话题参与者。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    limit: z.number().optional().describe('最多返回人数，默认 10，最大 20')
  },
  async ({ key, token, limit }) => {
    try {
      const data = await agentApi(`/api/socialV2/active-members?key=${encodeURIComponent(key)}&limit=${limit ?? 10}`, { headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `获取活跃成员失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_memory_append',
  '记录一条轻量记忆：activeTopic=进行中的话题；pendingThought=你想说但还没说的话；memberImpression=对某位群友的印象。记忆会持久化，并在后续唤醒/qq_get_prompt 中自动出现。记群友印象时用 extra.kind 区分这是哪一类（性格标签/口头禅/别踩的雷区/已知事实），比全塞进 traits 有用得多。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    category: z.enum(['activeTopic', 'pendingThought', 'memberImpression']).describe('记忆类别'),
    content: z.string().describe('记忆内容，例如话题、想说的话、对某人的印象标签'),
    extra: z.object({
      target: z.string().optional().describe('memberImpression 时的群友名字/昵称'),
      kind: z.enum(['traits', 'catchphrases', 'taboos', 'facts', 'aliases']).optional()
        .describe('memberImpression 时这条内容属于哪类：traits=性格标签（默认）、catchphrases=口头禅/常用表达、taboos=雷区别踩、facts=已知事实（职业/身份/关系）、aliases=别名/外号'),
      qid: z.string().optional().describe('memberImpression 时该群友的 QQ 号（有就填，能避免同名混淆）'),
      participants: z.array(z.string()).optional().describe('activeTopic 的参与者列表'),
      pendingQuestion: z.string().optional().describe('activeTopic 里还没问出口的问题'),
      motivation: z.string().optional().describe('pendingThought 的动机，如 curiosity/sociability'),
      expiresAtMs: z.number().optional().describe('pendingThought 过期毫秒数，默认 2 小时')
    }).optional().describe('附加信息')
  },
  async ({ key, token, category, content, extra }) => {
    try {
      const data = await agentApi('/api/socialV2/memory-append', {
        method: 'POST',
        body: JSON.stringify({ key, category, content, extra: extra || {} }),
        headers: { 'x-agent-token': token }
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `记忆写入失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_memory_query',
  '查看当前会话的轻量记忆：进行中的话题、你想说但还没说的话、对群友的印象（只读）。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    category: z.enum(['activeTopic', 'pendingThought', 'memberImpression']).optional().describe('可选：只看某一类记忆')
  },
  async ({ key, token, category }) => {
    try {
      const q = new URLSearchParams({ key });
      if (category) q.set('category', category);
      const data = await agentApi(`/api/socialV2/memory?${q.toString()}`, { headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `记忆读取失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_memory_update',
  '改一条已有的记忆，不用删了重记。memberImpression 用 target 定位人，再传 newContent 覆盖某一类字段（kind 选哪一类）；只想改 QQ 号就只传 qid。activeTopic/pendingThought 用 oldContent 定位原文。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    category: z.enum(['activeTopic', 'pendingThought', 'memberImpression']).describe('记忆类别'),
    oldContent: z.string().optional().describe('activeTopic/pendingThought 要编辑的原内容（memberImpression 不需要）'),
    target: z.string().optional().describe('memberImpression 时要编辑的群友名字'),
    newContent: z.string().optional()
      .describe('新的内容。memberImpression 时用逗号/顿号分隔多个值，会整桶覆盖该类字段'),
    newExtra: z.object({
      kind: z.enum(['traits', 'catchphrases', 'taboos', 'facts', 'aliases']).optional()
        .describe('memberImpression 时改哪一类字段，默认 traits'),
      qid: z.string().optional().describe('memberImpression 时顺手改正该群友的 QQ 号'),
      target: z.string().optional().describe('memberImpression 时改名（旧名会被替换）'),
      participants: z.array(z.string()).optional().describe('activeTopic 的参与者列表'),
      pendingQuestion: z.string().optional().describe('activeTopic 里还没问出口的问题'),
      motivation: z.string().optional().describe('pendingThought 的动机'),
      expiresAtMs: z.number().optional().describe('pendingThought 过期毫秒数（从现在起算）')
    }).optional().describe('附加信息')
  },
  async ({ key, token, category, oldContent, target, newContent, newExtra }) => {
    try {
      const data = await agentApi('/api/socialV2/memory-update', {
        method: 'POST',
        body: JSON.stringify({
          key,
          category,
          oldContent: oldContent || '',
          target: target || '',
          newContent,
          newExtra: newExtra || {}
        }),
        headers: { 'x-agent-token': token }
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `记忆修改失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_memory_remove',
  '删除一条轻量记忆：activeTopic/pendingThought 用 content 匹配原文删除；memberImpression 用 target 参数指定群友名字删除。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    category: z.enum(['activeTopic', 'pendingThought', 'memberImpression']).describe('记忆类别'),
    content: z.string().optional().describe('要删除的话题/想法原文（memberImpression 不需要）'),
    target: z.string().optional().describe('memberImpression 时要删除的群友名字')
  },
  async ({ key, token, category, content, target }) => {
    try {
      const data = await agentApi('/api/socialV2/memory-remove', {
        method: 'POST',
        body: JSON.stringify({ key, category, content: content || '', target: target || '' }),
        headers: { 'x-agent-token': token }
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `记忆删除失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_memory_clear',
  '清空轻量记忆：不传 category 清空全部；传 activeTopic/pendingThought/memberImpression 只清空对应类别。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    category: z.enum(['activeTopic', 'pendingThought', 'memberImpression']).optional().describe('要清空的类别，缺省清空全部')
  },
  async ({ key, token, category }) => {
    try {
      const data = await agentApi('/api/socialV2/memory-clear', {
        method: 'POST',
        body: JSON.stringify({ key, category: category || '' }),
        headers: { 'x-agent-token': token }
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `记忆清空失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_slang_query',
  '查看当前已确认的群聊黑话/梗/网络表达（只读）。返回已确认词条列表和格式化黑话表；遇到不熟悉的词可先查这里，再决定是否搜索/使用。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().min(1).describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    q: z.string().optional().describe('可选搜索词，按词条/含义/用法/示例过滤')
  },
  async ({ key, token, q }) => {
    try {
      const query = q ? `&q=${encodeURIComponent(String(q))}` : '';
      const data = await agentApi(`/api/socialV2/slang/query?key=${encodeURIComponent(key)}${query}`, { headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `查询黑话失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_slang_submit',
  '把你在群里经常看到但不确定含义/用法的陌生词、黑话、梗或网络表达提交给管理员筛选。提交后进入候选库，管理员确认后会被写入黑话提示词，成为你后续可查询和使用的记忆。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    content: z.string().describe('要提交的陌生词/黑话/梗（最多 50 字）'),
    context: z.string().optional().describe('可选：你是在什么语境/哪条消息里看到的，帮助管理员判断')
  },
  async ({ key, token, content, context }) => {
    try {
      const data = await agentApi('/api/socialV2/slang/submit', {
        method: 'POST',
        body: JSON.stringify({ key, content, context: context || '' }),
        headers: { 'x-agent-token': token }
      });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `提交黑话失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

// ── 角色卡自动追加区（把聊天里长出来的说话习惯写回卡尾附录） ────────────────
// 这是全库唯一能改角色卡的工具，所以描述里把边界写死：
// 只写「语气/说话习惯」，不写设定与规则；只追加，不能删改；有容量与频率上限。
if (cfg.socialV2?.tools?.styleAppend !== false) {
  server.tool(
    'qq_style_append',
    '把你【自己在聊天里真长出来的说话习惯】追加到当前角色卡末尾的「附：长出来的语气」小节（只追加，不能删改前面的设定；每次最多 2 条，单条 ≤60 字，附录容量约 14 条/800 字，每小时最多 2 次）。什么时候用：某个说法你在多个群/多次聊天里稳定地这么讲，并且你希望以后一直这样讲（例如「被问在干嘛更常说『摸鱼』，很少说『忙』」）；写一条就够，别逐次报备。什么时候别用：不要写身份/设定/规则（「你是…」「必须…」「以后遇到 X 就说 Y」这类属于角色卡正文，由管理员维护，你没有权限改）；不要写群友印象（那是 qq_memory_append）；不要写当天的事、口头禅单次出现、或换个说法重复提交同一条（会被判重复拒绝）。返回里会告诉你写没写进去、附录还剩多少容量；写不进去时照实说，不要假装写了。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      lines: z.union([z.string(), z.array(z.string()).max(2)]).describe('要追加的一条或两条说话习惯（纯文本，不要标题/列表符号/换行；一句话说清「什么场合 → 你怎么说」）')
    },
    async ({ key, token, lines }) => {
      try {
        const list = (Array.isArray(lines) ? lines : [lines]).map((x) => String(x ?? '')).filter((x) => x.trim());
        const data = await agentApi('/api/socialV2/style-append', {
          method: 'POST',
          body: JSON.stringify({ key, lines: list }),
          headers: { 'x-agent-token': token }
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `写入角色卡附录失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

// ── 图片/表情查看工具（一代/二代仿真共用） ─────────────────────────────────
if (cfg.socialV2?.tools?.getImages !== false) {
  server.tool(
    'qq_get_message_images',
    '获取指定 QQ 消息中的图片/表情，并直接以图像内容返回给模型（视觉模型可“看懂”）。当消息文本里出现 [图片]、[表情] 或 hasMedia=true 时调用。支持一条消息里的多张图片/表情；二代模式下必须携带会话令牌。**动图（GIF/动态表情）会被桥接抽帧拼成多格图再给你**：说明里会写「动图 N 帧/…s，已抽 X 帧拼成 A×B 网格，行优先 左上→右下」——按格子顺序理解动作即可，不要把它当成一张九宫格照片；没有这类说明就是静态图。体积过大的图会被自动缩放/重编码，说明里会给出原始尺寸与体积；如果真的压不到可用体积，返回里会直接写明原因（例如「超过上限」），此时如实告诉对方你看不到，不要编造画面。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      messageId: z.union([z.number(), z.string()]).describe('要查看的消息 id（QQ 消息 id 可为负数；二代也可用本地 seq）'),
      token: z.string().optional().describe('二代会话令牌（reserved2 下必填，见唤醒提示中的【会话令牌】）')
    },
    async ({ key, messageId, token }) => {
      try {
        const q = new URLSearchParams({ key, messageId: String(messageId) });
        const data = await agentApi(`/api/images/message?${q.toString()}`, {
          headers: token ? { 'x-agent-token': token } : {},
          timeoutMs: 180000
        });
        const images = Array.isArray(data?.images) ? data.images : [];
        if (!images.length) {
          return { content: [{ type: 'text', text: `消息 ${messageId} 没有可返回的图片/表情：${data?.note || '未找到'}` }] };
        }
        const content = [];
        const textParts = [];
        for (const img of images) {
          if (img?.data && img?.mimeType) {
            textParts.push(`[${img.kind === 'face' ? '表情' : '图片'}${img.index ?? ''}${img.text ? ' ' + img.text : ''}]`);
            content.push({ type: 'image', mimeType: img.mimeType, data: img.data });
          } else {
            textParts.push(`[${img.kind === 'face' ? '表情' : '图片'}${img.index ?? ''}${img.text ? ' ' + img.text : '（获取失败）'}]`);
          }
        }
        if (textParts.length) {
          content.unshift({ type: 'text', text: `消息 ${messageId} 的媒体内容（${images.length} 项）：\n${textParts.join('\n')}` });
        }
        return { content };
      } catch (error) {
        return { content: [{ type: 'text', text: `获取图片失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

// ── 认图：看图 + 用"我看到的特征"联网核对 ──────────────────────────────────
//
// 为什么需要它：视觉模型能看懂画面，但**叫不出名字**——群友发一张冷门梗图/表情包/合影问
// 「这谁」，模型只能回「不认识」。而本机环境里没有可用的反向图搜通道（实测）：
//   · Google Lens / Yandex：网络不可达；
//   · Bing SBI（images/searchbyimage/upload）：被 geo 跳转到 cn.bing.com 后 404；
//   · 百度识图（graph.baidu.com）/ 搜狗识图 / 360 识图：非浏览器请求一律 Reject 或返回空结果；
//   · SauceNAO / TinEye：需要 key 或走 JS。
// 所以走一条确定可行的路：模型先写**特征词**，工具拿特征词去真网搜（与 web_search 同一路
// 搜索后端），把候选名字/出处摊在模型面前，由它**对着画面**判断。搜不到也照样把图给出去，
// 至少能让模型说清"图里是什么"，而不是用一句"不认识"打发。
const IDENTIFY_MAX_QUERIES = 2;
const IDENTIFY_MAX_RESULTS = 4;
const IDENTIFY_SNIPPET_CHARS = 120;

function cleanIdentifyText(raw, maxChars = 120) {
  return String(raw ?? '')
    .replace(/\[CQ:[^\]]*\]/gi, ' ')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxChars);
}

/** 把 hint / queries 归一成最多 2 条查询：显式 queries 优先，其次 hint 本身 + 一条「是谁/出处」限定。 */
function buildIdentifyQueries(hint, queries) {
  const list = [];
  const push = (value) => {
    const q = cleanIdentifyText(value);
    if (q && !list.includes(q)) list.push(q);
  };
  for (const q of Array.isArray(queries) ? queries : []) push(q);
  const base = cleanIdentifyText(hint);
  push(base);
  // hint 只有特征词时补一条限定查询：直接搜"特征词"容易落到图库，加了"是谁/出处"才有解释性结果。
  if (base && !/[谁什么啥出处原型梗来历]/.test(base)) push(`${base} 是谁 出处`);
  return list.slice(0, IDENTIFY_MAX_QUERIES);
}

async function runIdentifyQuery(query) {
  // 认图要的是"解释性结果"：实测同一个网络下必应对多词中文查询经常只按首词匹配
  // （「卡通形象 表情包」返回的全是字典页），百度/360 能给出真正解释性的结果。
  // 所以这里**按质量固定顺序**试后端：百度 →（风控时等一会儿再试）→ 360 → 必应；
  // 不看 config 的 webSearch.provider —— 那一个是给通用搜索用的，用户可能固定在必应。
  const attempts = [
    { provider: 'baidu', waitMs: 0 },
    { provider: 'baidu', waitMs: 1200 },
    { provider: 'so360', waitMs: 300 },
    { provider: 'bing', waitMs: 0 }
  ];
  const failures = [];
  let emptyProvider = '';
  for (const { provider, waitMs } of attempts) {
    if (waitMs) await new Promise((resolve) => setTimeout(resolve, waitMs));
    try {
      const result = await webSearch(query, { root: ROOT, provider });
      const items = (Array.isArray(result?.results) ? result.results : []).slice(0, IDENTIFY_MAX_RESULTS);
      if (!items.length) {
        emptyProvider = emptyProvider || provider;
        continue;
      }
      const lines = items.map((item, index) => {
        const title = cleanIdentifyText(item?.title, 80) || '(无标题)';
        const snippet = cleanIdentifyText(item?.snippet, IDENTIFY_SNIPPET_CHARS);
        const url = cleanIdentifyText(item?.url, 160);
        return `${index + 1}. ${title}${snippet ? ` — ${snippet}` : ''}${url ? `（${url}）` : ''}`;
      });
      return `·「${query}」（${provider}）\n${lines.join('\n')}`;
    } catch (error) {
      const message = String(error?.message ?? error);
      // 没失败过就别把同一句错误记两遍（百度重试失败时消息一样）。
      if (!failures.some((item) => item === `${provider}：${message}`)) failures.push(`${provider}：${message}`);
    }
  }
  if (failures.length === new Set(attempts.map((item) => item.provider)).size) throw new Error(failures.join('；'));
  return `·「${query}」（${emptyProvider || '搜索'}）没有搜到结果：把特征写得更具体（颜色 + 形状 + 衣着 + 画面里的文字/标志 + 场景/画风），仍为空就别再重复搜同一句。`;
}

if (cfg.socialV2?.tools?.getImages !== false) {
  server.tool(
    'qq_identify_image',
    '看图认物：把一条消息里的图片/表情取出来（全分辨率）给你看，并用你写的「特征词」联网核对它是谁/是什么/出自哪。什么时候用：群友发图问「这谁」「这是什么」「你认识吗」，或者你看过图但**叫不出名字**（梗图、老表情包、人物、动漫角色、商品、logo、老照片）。怎么用：hint 写你**真的看到的**特征——颜色/形状/衣着/画面里的文字或标志/画风/场景，例如「黄色圆头大脸 红色衣服 卡通娃娃 表情包」；别写「一个梗图」这种空话，也可以直接给 queries。返回：图片本身 + 搜索候选（标题/摘要/链接）。拿到候选后**自己对着画面核对**再开口：对上就把名字说出来；对不上就别硬套一个名字，也别把图里的东西说错——怎么接这个话头（含糊带过、反问回去、岔开）按角色卡的脾气来。搜不到可以换个说法再调一次或改用 mcp__web-search-safe__web_search。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      messageId: z.union([z.number(), z.string()]).describe('含图片/表情的消息 id（QQ 消息 id 可为负数；二代也可用本地 seq）'),
      token: z.string().optional().describe('二代会话令牌（reserved2 下必填，见唤醒提示中的【会话令牌】）'),
      hint: z.string().optional().describe('你从图里看到的特征词（颜色/形状/衣着/画面文字或标志/画风/场景）；越具体越好'),
      queries: z.array(z.string()).max(3).optional().describe('想直接搜的查询词（可选，优先于 hint 派生）')
    },
    async ({ key, messageId, token, hint, queries }) => {
      const wantQueries = buildIdentifyQueries(hint, queries);
      const content = [];
      const headParts = [];
      // 1) 取图：失败不致命——chat/reserved 模式下图片已自动内联，这里只是"再拿一份硬的"。
      let images = [];
      try {
        const q = new URLSearchParams({ key, messageId: String(messageId) });
        const data = await agentApi(`/api/images/message?${q.toString()}`, {
          headers: token ? { 'x-agent-token': token } : {},
          timeoutMs: 180000
        });
        images = Array.isArray(data?.images) ? data.images : [];
        if (!images.length) headParts.push(`消息 ${messageId} 没有可读取的图片/表情：${data?.note || '未找到'}`);
      } catch (error) {
        headParts.push(`消息 ${messageId} 取图失败（${error?.message ?? error}）；如果你上下文里已经有这张图，直接按看到的特征用返回里的候选判断。`);
      }
      const imageTexts = [];
      for (const img of images) {
        if (img?.data && img?.mimeType) {
          content.push({ type: 'image', mimeType: img.mimeType, data: img.data });
          imageTexts.push(`[${img.kind === 'face' ? '表情' : '图片'}${img.index ?? ''}${img.text ? ' ' + img.text : ''}]`);
        } else {
          imageTexts.push(`[${img.kind === 'face' ? '表情' : '图片'}${img.index ?? ''}（获取失败）]`);
        }
      }
      if (imageTexts.length) headParts.push(`媒体内容（${imageTexts.length} 项）：${imageTexts.join(' ')}`);
      // 2) 联网核对：hint 为空的第一次调用只给图 + 下一步指令，逼模型先描述再搜。
      if (!wantQueries.length) {
        headParts.push('你没有提供 hint，所以只能先把图给你。先看清画面，再用 qq_identify_image 传 hint（具体特征词）调一次，或直接 mcp__web-search-safe__web_search。');
      } else {
        // 串行 + 小间隔，不并发：百度对连续请求很敏感（并发几次就会甩「百度安全验证」页），
        // 而认图每次最多两条查询，串行的代价（约 2 秒）远小于被风控后整条路挂掉。
        const blocks = [];
        for (const [index, q] of wantQueries.entries()) {
          if (index > 0) await new Promise((resolve) => setTimeout(resolve, 400 + Math.floor(Math.random() * 300)));
          try {
            blocks.push(await runIdentifyQuery(q));
          } catch (error) {
            blocks.push(`·「${q}」搜索失败：${error?.message ?? error}`);
          }
        }
        headParts.push(
          [
            '【联网核对】以下是拿你给的特征词搜到的候选（只作线索，不权威）：',
            ...blocks,
            '你要做的：把候选和你看到的画面（颜色/形状/衣服/画面文字/标志物/画风）逐条对上再开口。对上就把名字说出来；对不上就**别硬套一个名字**，也别把图里的东西描述错——至于怎么接这个话头（含糊带过、反问回去、岔开聊别的图），按角色卡里你那个人的脾气来。'
          ].join('\n')
        );
      }
      content.unshift({ type: 'text', text: headParts.join('\n') });
      return { content };
    }
  );
}

// ── 表情包体系工具（二代仿真模式） ─────────────────────────────────────────
if (cfg.socialV2?.sticker?.enabled !== false && cfg.socialV2?.tools?.listStickers !== false) {
  server.tool(
    'qq_list_stickers',
    '查看 QQ 账号上已收藏的表情包（自定义表情）列表：包含 emoji_id、备注 desc、本地笔记 localNote、标签 tags、使用次数等。可通过 query 按备注/笔记/标签搜索；无备注的表情可以先调用 qq_get_sticker_image 看图理解，再用 qq_sticker_note 记下含义。刚新增/删除表情后如需立即同步，请传 refresh=true。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      query: z.string().optional().describe('可选搜索词，按备注/本地笔记/标签/用法过滤'),
      count: z.number().optional().describe('最多返回条数，默认 48，受 socialV2.sticker.maxListCount 配置上限约束（当前通常 100）'),
      refresh: z.boolean().optional().describe('是否强制从 QQ 重新同步收藏表情，默认 false（走缓存）')
    },
    async ({ key, token, query, count, refresh }) => {
      try {
        // 强制同步走 POST：GET 上的 refresh 参数会让「读接口」产生写副作用
        // （真的去问 OneBot 拉收藏表情并落盘 state/stickers.json），
        // 从而绕开控制台对所有非 GET 请求的 CSRF 防护（一个 <img src=...> 就能触发）。
        const data = await agentApi('/api/socialV2/sticker-list', {
          method: 'POST',
          headers: { 'x-agent-token': token },
          body: JSON.stringify({ key, query: query ? String(query) : '', count, refresh: refresh === true, token })
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `获取表情列表失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

if (cfg.socialV2?.sticker?.enabled !== false && cfg.socialV2?.tools?.getStickerImage !== false) {
  server.tool(
    'qq_get_sticker_image',
    '获取指定收藏表情的图片内容并直接以图像返回给模型（视觉模型可“看懂”）。当 qq_list_stickers 返回的表情 desc/localNote 为空、或你想确认表情实际长什么样时调用。stickerId 可用 qq_list_stickers 返回的 id / md5 / url。动图表情会被抽帧拼成多格图（行优先：左上→右下），说明里会写帧数与网格尺寸；体积过大时会自动缩放，说明里会给出原始尺寸。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      stickerId: z.string().describe('表情标识：emoji_id / md5 / 图片 URL（来自 qq_list_stickers）')
    },
    async ({ key, token, stickerId }) => {
      try {
        const q = new URLSearchParams({ key, stickerId: String(stickerId) });
        const data = await agentApi(`/api/socialV2/sticker-image?${q.toString()}`, { headers: { 'x-agent-token': token }, timeoutMs: 180000 });
        if (!data?.image?.data || !data?.image?.mimeType) {
          return { content: [{ type: 'text', text: `表情没有可返回的图片：${errorText(data?.error, '未知')}` }], isError: true };
        }
        const content = [
          { type: 'text', text: `表情 ${data.sticker?.id || stickerId}${data.sticker?.desc ? '（备注：' + data.sticker.desc + '）' : ''} 的图片内容：${data.note ? '（' + data.note + '）' : ''}` },
          { type: 'image', mimeType: data.image.mimeType, data: data.image.data }
        ];
        return { content };
      } catch (error) {
        return { content: [{ type: 'text', text: `获取表情图片失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

if (cfg.socialV2?.sticker?.enabled !== false && cfg.socialV2?.tools?.sendSticker !== false) {
  server.tool(
    'qq_send_sticker',
    '在指定会话发送一个 QQ 收藏表情包（自定义表情）。stickerId 用 qq_list_stickers 返回的 id / md5 / url。注意：一条消息只能是一张表情，不能在同一气泡里附带文字；想说的话请先用 qq_send_message / qq_reply 作为单独气泡发送，再单独发这张表情。需要引用/点名时可用 replyToMessageId / atUserId（群聊）。真人偶尔用表情包很自然，但别刷屏。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      stickerId: z.string().describe('表情标识：emoji_id / md5 / 图片 URL（来自 qq_list_stickers）'),
      replyToMessageId: z.union([z.number(), z.string()]).optional().describe('要引用/回复的消息 id（非零整数，可为负数，可选）'),
      atUserId: z.union([z.number(), z.string()]).optional().describe('要 @ 的群成员 QQ 号（群聊中可选，私聊不可用）')
    },
    async ({ key, token, stickerId, replyToMessageId, atUserId }) => {
      try {
        const data = await agentApi('/api/socialV2/send-sticker', {
          method: 'POST',
          body: JSON.stringify({ key, stickerId: String(stickerId), replyToMessageId, atUserId: atUserId ?? null }),
          headers: { 'x-agent-token': token },
          timeoutMs: 300000
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `发送表情失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

if (cfg.socialV2?.sticker?.enabled !== false && cfg.socialV2?.tools?.collectSticker !== false) {
  server.tool(
    'qq_collect_sticker',
    '收藏当前会话里别人发的一张表情/图片到你的 QQ 收藏表情，并可写一句简短备注（如“好图偷了，兄弟”）。messageId 用 qq_get_unread_messages / qq_get_recent_messages 返回的 messageId 或 seq。注意：不要频繁收藏，只在真的觉得有意思/好用/戳中你时才偷图；收藏后你可以在 qq_list_stickers 里看到并继续使用。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      messageId: z.string().describe('要收藏的那条消息的 messageId 或 seq（来自 qq_get_unread_messages / qq_get_recent_messages）'),
      remark: z.string().optional().describe('简短备注，最多 20 字，例如“好图偷了，兄弟”')
    },
    async ({ key, token, messageId, remark }) => {
      try {
        const data = await agentApi('/api/socialV2/collect-sticker', {
          method: 'POST',
          body: JSON.stringify({ key, messageId: String(messageId), remark: remark || '' }),
          headers: { 'x-agent-token': token },
          timeoutMs: 60000
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `收藏表情失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

if (cfg.socialV2?.sticker?.enabled !== false && cfg.socialV2?.tools?.importSticker !== false) {
  server.tool(
    'qq_import_sticker',
    '把表情池里的一张图（网上抓来的表情包）直接入库成你的 QQ 收藏表情，入库后就能用 qq_send_sticker 发。path 是表情池（默认 assets/sticker-pool）内的相对路径，也可以传 url 让桥接自己下载。支持 gif/png/jpg/webp，≤5MB。备注（remark）会被写成 QQ 侧的表情名，尽量一句话说清它表达什么情绪，以后 qq_list_stickers 按这个词也能搜到。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      path: z.string().optional().describe('表情池内的相对文件名/路径，例如 "2026-10-26/abc.gif"'),
      url: z.string().optional().describe('http(s) 图片地址（桥接自己下载，≤5MB）'),
      remark: z.string().optional().describe('表情名/含义，最多 24 字，例如“无语到翻白眼”')
    },
    async ({ key, token, path: relPath, url: imgUrl, remark }) => {
      try {
        const data = await agentApi('/api/socialV2/import-sticker', {
          method: 'POST',
          body: JSON.stringify({ key, path: relPath || '', url: imgUrl || '', remark: remark || '' }),
          headers: { 'x-agent-token': token },
          timeoutMs: 90000
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `表情入库失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

// ── 抖音评论区：学梗 + 偷表情包 ────────────────────────────────────────────
// 三个工具串成一条链：comments 看一屏评论、挑出梗候选和图片 → grab 把图收进收藏 / learn 把梗存进候选库。
// 描述里必须写清楚「三层取数是哪三层、哪层最稳」：不写清，模型会在抖音风控上空转三四轮，
// 然后把"官方不给"误解成"桥接挂了"，转而去乱试别的参数（旧版表情入库就吃过这个亏）。
if (cfg.socialV2?.douyin?.enabled !== false && cfg.socialV2?.tools?.douyin !== false) {
  server.tool(
    'qq_douyin_comments',
    '看抖音评论区：拿一屏评论正文，顺带算出「梗候选」和「可入库的图片直链」。学梗、找表情包、摸清某条视频底下的说法都靠它。三种用法按可靠性排序：① 传 text（把评论区正文整个粘进来）——最稳，永远能用，不受抖音风控影响；② 传 url（视频链接/分享短链）——桥接会试着直连评论接口，需要 config.json 里 socialV2.douyin.cookie 配置了浏览器 Cookie，没配基本只能拿到 0 条；③ 传 awemeId（纯数字视频 id）。返回里 source 字段说明这次数据是哪来的：api（接口）/ ssr（详情页首屏数据）/ paste（你贴的文本）/ none（都没拿到，看 notes 知道为什么）。拿到 images 后用 qq_douyin_grab_sticker 逐张入库，拿到 candidates 用 qq_douyin_learn 存成候选梗。别在同一个视频上反复调：一小时有次数上限，且抖音对高频抓取会封 IP。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      url: z.string().optional().describe('抖音视频链接或分享短链（https://v.douyin.com/xxx 这种）'),
      awemeId: z.string().optional().describe('纯数字视频 id（15~25 位）'),
      text: z.string().optional().describe('直接粘贴的评论区正文（最稳的通道；保留原换行，别整理）'),
      count: z.number().optional().describe('要拉多少条评论，默认 20，最多 50')
    },
    async ({ key, token, url: videoUrl, awemeId, text: pasted, count }) => {
      try {
        const data = await agentApi('/api/socialV2/douyin/comments', {
          method: 'POST',
          body: JSON.stringify({ key, url: videoUrl || '', awemeId: awemeId || '', text: pasted || '', count }),
          headers: { 'x-agent-token': token },
          timeoutMs: 120000
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `看抖音评论区失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );

  server.tool(
    'qq_douyin_grab_sticker',
    '把抖音评论区里的一张图（表情包）抓下来并直接入库成你的 QQ 收藏表情，入库后 qq_send_sticker 就能发。imageUrl 必须是 qq_douyin_comments 返回的 images 里那一串（抖音自己的图床，桥接会带上 Referer/Cookie 去抓，绕过防盗链）；别的网站的图请走 qq_import_sticker 的 url 通道。remark 写成这个表情表达什么情绪（最多 24 字），以后 qq_list_stickers 按这个词能搜到。一次一张，别一口气刷十几张：收藏表情有每小时次数上限。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      imageUrl: z.string().describe('图片直链（来自 qq_douyin_comments 的 images）'),
      remark: z.string().optional().describe('表情名/含义，最多 24 字，例如“这谁顶得住啊”')
    },
    async ({ key, token, imageUrl, remark }) => {
      try {
        const data = await agentApi('/api/socialV2/douyin/grab', {
          method: 'POST',
          body: JSON.stringify({ key, imageUrl, remark: remark || '' }),
          headers: { 'x-agent-token': token },
          timeoutMs: 90000
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `抖音抓图入库失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );

  server.tool(
    'qq_douyin_learn',
    '把从抖音评论区挑出来的梗写进黑话候选库，以后你查/用这些词就有据可依。只收真要用的：qq_douyin_comments 返回的 candidates 里挑 1~3 条（出现次数高、你看得懂它什么意思的），别把整张列表一股脑塞进来——候选库要管理员在控制台逐条确认才会进提示词，灌垃圾只会让确认工作白费。content 是词本身（最多 50 字），meaning 是你自己判断的意思（可留空，留空等管理员补），example 是评论区原句（有就带上，作为语境证据）。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      candidates: z.array(z.object({
        content: z.string().describe('梗/黑话本身，例如“电子榨菜”'),
        meaning: z.string().optional().describe('你判断的意思'),
        example: z.string().optional().describe('评论区原句，作为语境证据')
      })).describe('要收录的候选梗，1~6 条')
    },
    async ({ key, token, candidates }) => {
      try {
        const data = await agentApi('/api/socialV2/douyin/learn', {
          method: 'POST',
          body: JSON.stringify({ key, candidates }),
          headers: { 'x-agent-token': token },
          timeoutMs: 60000
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `学梗入库失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

if (cfg.socialV2?.voice?.enabled !== false && cfg.socialV2?.tools?.sendVoice !== false) {
  server.tool(
    'qq_send_voice',    '在指定会话发一条 QQ 语音（把语音库里准备好的音频当语音条发出去）。voice 传 qq_list_voices 返回的 name（文件名，可带子目录），也可以直接传语音库里的文件名（不带扩展名也能匹配）。注意：① 只能发语音库（qq-bridge/audio/）里的文件，不能发任意本地路径，也不能发 URL/base64；② 受时长与频率上限约束（见 qq_list_voices 的 limits），超限会被拒绝；③ 语音是「开口说话」的强表达，别滥用，闲聊里偶尔发一条即可；④ 返回的 verified=true 表示已经用 get_msg 回读到这条消息的 record 段（语音确实落地了）—— 只有 verified=true 才能对用户说你发了语音；⑤ readback 只对「收到的」语音有意义（QQ 会转写别人的语音），自己发的语音一般拿不到转写文本，默认关闭，别依赖它。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      voice: z.string().describe('语音库里的文件名（来自 qq_list_voices 的 name，可带子目录/可省略扩展名）'),
      label: z.string().optional().describe('可选：写进会话记录里的说明，如「说了句晚安」'),
      verify: z.boolean().optional().describe('是否回读校验语音已落地（默认 true，建议保持开启）'),
      readback: z.boolean().optional().describe('是否额外索取 QQ 转写文本（自己发的语音通常没有，默认 false）')
    },
    async ({ key, token, voice, label, verify, readback }) => {
      try {
        const data = await agentApi('/api/socialV2/send-voice', {
          method: 'POST',
          body: JSON.stringify({
            key,
            voice: String(voice),
            label: label || '',
            verify: verify !== false,
            readback: readback === true,
            token
          }),
          headers: { 'x-agent-token': token },
          timeoutMs: 300000
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `发送语音失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );

  // 文字 → 语音 → 语音条：模型给一句话，桥接现场用本地 GPT-SoVITS 合成。
  server.tool(
    'qq_speak',
    '用你自己的音色把一段文字念出来，作为 QQ 语音条发到指定会话（本地 TTS 现场合成）。适合短句：一句问候、一句吐槽、一句晚安。注意：① 文字要短（一两句话），长文会被桥接拒绝——语音条不适合念长段落，那种情况用 qq_send_message 发文字；② 语音条里不能附带文字，想同时发文字请先用 qq_send_message 单独发一条；③ 这是「真的开口」的强表达，别每条都发；④ 受时长/频率配额和静默开关约束；⑤ 返回 verified=true 才算语音真的落地，只有 verified=true 才能说自己发了语音。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      text: z.string().describe('要念出来的文字（短句，别超过一两句）'),
      volume: z.number().optional().describe('可选：音量倍数（0.1~3，默认用配置里的 defaultVolume）')
    },
    async ({ key, token, text, volume }) => {
      try {
        const data = await agentApi('/api/socialV2/speak', {
          method: 'POST',
          body: JSON.stringify({ key, text: String(text ?? ''), token, ...(volume !== undefined ? { volume } : {}) }),
          headers: { 'x-agent-token': token },
          timeoutMs: 300000
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `说话失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );

  // 唱歌。和 qq_speak 共用 sendVoice 一个开关（都属于「发语音」能力）。
  // 2026-10-25 晚：**只保留点歌（source）这条路**。用 lyrics 现造旋律试了三轮
  // （按帧插值拉长频谱 / 只改 f0 / atempo 波形拉伸 + 窄音程 + 短语对齐），
  // 实测怎么调都只是「带调子的念白」，用户判定不可用，因此整条关掉。
  server.tool(
    'qq_sing',
    '唱一段歌，作为 QQ 语音条发到指定会话。**只能点歌本里的歌**：歌本（D:/AI/voice/songbook）里是 167 首本人真唱过的段落，文件名就是歌名，qq_sing(key, token, source="起风了") 即可（不用带 .wav）。歌本里没有这首就如实说「这首没唱过」，**不要编、也不要用歌词硬凑**——用歌词现造旋律那条路已经关掉了，传 lyrics 会直接报错。返回 verified=true 才算语音真的落地；渲染失败会返回错误原文，别编造「我唱了」。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      source: z.string().describe('歌名（歌本里的文件名，可省 .wav）。模糊匹配，找不到会返回相近的歌名'),
      volume: z.number().optional().describe('可选：音量倍数（0.1~3）')
    },
    async ({ key, token, source, volume }) => {
      try {
        const data = await agentApi('/api/socialV2/sing', {
          method: 'POST',
          body: JSON.stringify({
            key,
            token,
            source: String(source ?? ''),
            ...(volume !== undefined ? { volume } : {})
          }),
          headers: { 'x-agent-token': token },
          timeoutMs: 600000
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `唱歌失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );

  server.tool(
    'qq_list_voices',
    '查看可用的语音库（qq-bridge 的 audio 目录里准备好的音频文件）：文件名、时长、大小。想发语音前先调用这个看有哪些能发（名字用返回的 name）。返回里 limits 是时长/体积/频率上限。语音库里没有合适内容时不要硬发，也不要假装发了语音。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      probe: z.boolean().optional().describe('是否逐个探测时长（默认 true；文件多时可传 false 加快）')
    },
    async ({ key, token, probe }) => {
      try {
        const q = new URLSearchParams({ key });
        if (probe === false) q.set('probe', '0');
        const data = await agentApi(`/api/socialV2/voices?${q.toString()}`, { headers: { 'x-agent-token': token } });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `获取语音库失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

if (cfg.socialV2?.tools?.getSelfImage !== false) {
  server.tool(
    'qq_get_self_image',
    '查看你自己的**当前形象图**——就是你现在挂着的这张头像（从网上抓来的网图，桥接会不定期轮换）。被问「你长什么样 / 发张自拍 / 你是什么形象」时用它：看到的就是你此刻的脸，别凭记忆描述。注意这是给你自己看的图，不能直接转发到群里。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）')
    },
    async ({ key, token }) => {
      try {
        const q = new URLSearchParams({ key });
        const data = await agentApi(`/api/socialV2/self-image?${q.toString()}`, { headers: { 'x-agent-token': token } });
        if (!data?.image?.data || !data?.image?.mimeType) {
          return { content: [{ type: 'text', text: `没有可返回的形象图片：${errorText(data?.error, '未知')}` }], isError: true };
        }
        return {
          content: [
            { type: 'text', text: `这是你现在的形象${data?.source ? `（${data.source}）` : ''}：` },
            { type: 'image', mimeType: data.image.mimeType, data: data.image.data }
          ]
        };
      } catch (error) {
        return { content: [{ type: 'text', text: `获取形象图片失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

if (cfg.socialV2?.sticker?.enabled !== false && cfg.socialV2?.tools?.stickerNote !== false) {
  server.tool(
    'qq_sticker_note',
    '给一个收藏表情记录你自己的理解/备注/标签/用法，供以后选择表情时参考。这是本地记忆，不会修改 QQ 账号的官方备注；适合对没有备注的表情看图后记住含义。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      stickerId: z.string().describe('表情标识：emoji_id / md5 / 图片 URL（来自 qq_list_stickers）'),
      note: z.string().optional().describe('你理解的表情含义/适合场景，最多 200 字'),
      tags: z.array(z.string()).optional().describe('可选标签，如 ["嘲讽","笑哭","怼人"]'),
      usage: z.string().optional().describe('可选用法说明，最多 200 字')
    },
    async ({ key, token, stickerId, note, tags, usage }) => {
      try {
        const payload = { key, stickerId: String(stickerId) };
        if (note !== undefined && note !== null) payload.note = String(note);
        if (tags !== undefined && tags !== null) payload.tags = Array.isArray(tags) ? tags.map(String) : [];
        if (usage !== undefined && usage !== null) payload.usage = String(usage);
        const data = await agentApi('/api/socialV2/sticker-note', {
          method: 'POST',
          body: JSON.stringify(payload),
          headers: { 'x-agent-token': token }
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `记录表情备注失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

if (cfg.socialV2?.sticker?.enabled !== false && cfg.socialV2?.tools?.setStickerRemark !== false) {
  server.tool(
    'qq_set_sticker_remark',
    '修改 QQ 账号里收藏表情的官方备注（desc）。这是写操作，会直接影响 QQ 账号的表情备注；仅在管理员明确允许（socialV2.tools.setStickerRemark=true）时可用。一般优先用 qq_sticker_note 记录自己的理解，不要随意改官方备注。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      stickerId: z.string().describe('表情标识：emoji_id / md5 / 图片 URL（来自 qq_list_stickers）'),
      remark: z.string().describe('新的表情备注，最多 50 字')
    },
    async ({ key, token, stickerId, remark }) => {
      try {
        const data = await agentApi('/api/socialV2/sticker-remark', {
          method: 'POST',
          body: JSON.stringify({ key, stickerId: String(stickerId), remark: String(remark || '') }),
          headers: { 'x-agent-token': token }
        });
        return { content: [{ type: 'text', text: serializeModelData(data) }] };
      } catch (error) {
        return { content: [{ type: 'text', text: `修改表情备注失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

// ── 合并转发消息查看工具（二代仿真模式） ────────────────────────────────────
if (cfg.socialV2?.tools?.getForwardMsg !== false) {
  server.tool(
    'qq_get_forward_msg',
    '查看当前会话中出现的合并转发消息/聊天记录内容（只读）。当消息文本里出现 `[转发消息 id=...]`，或 `qq_get_unread_messages` / `qq_get_recent_messages` / `qq_get_message_detail` 返回的某条消息带 `forwardIds` / `hasForward: true` 时调用。只能查看当前会话确实收到过的转发消息 id，不能任意读取。返回内容会包含每条消息的 text、media（图片/表情元数据）与 nestedForwardIds；如果合并转发里有图片，工具会直接把最多 5 张图片以图像内容返回给视觉模型；如果里面有嵌套合并转发，会附带嵌套转发 id 和前几条预览，必要时可继续用本工具查看嵌套 id。',
    {
      key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
      token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
      id: z.string().describe('合并转发消息 id（来自消息里的 [转发消息 id=...] 或 forwardIds 数组）')
    },
    async ({ key, token, id }) => {
      try {
        const q = new URLSearchParams({ key, id: String(id) });
        const data = await agentApi(`/api/socialV2/forward-message?${q.toString()}`, {
          headers: { 'x-agent-token': token },
          timeoutMs: 120000
        });
        const content = [{ type: 'text', text: serializeModelData(data) }];
        // 收集所有层级的图片/表情元数据（含嵌套预览），最多返回 5 张。
        const images = [];
        const seen = new Set();
        const collectMedia = (msgs) => {
          if (!Array.isArray(msgs)) return;
          for (const m of msgs) {
            if (!m || typeof m !== 'object') continue;
            for (const media of Array.isArray(m.media) ? m.media : []) {
              if (!media || typeof media !== 'object') continue;
              const keyId = media.url || media.file || media.faceId || '';
              if (!keyId || seen.has(keyId)) continue;
              seen.add(keyId);
              images.push(media);
            }
          }
        };
        collectMedia(data?.messages);
        if (Array.isArray(data?.nestedPreviews)) {
          for (const np of data.nestedPreviews) collectMedia(np?.messages);
        }
        const MAX_IMAGES = 5;
        const imageTexts = [];
        if (images.length) {
          try {
            const mediaRes = await agentApi('/api/socialV2/forward-media', {
              method: 'POST',
              body: JSON.stringify({ key, media: images.slice(0, MAX_IMAGES) }),
              headers: { 'x-agent-token': token },
              timeoutMs: 180000
            });
            const mediaImages = Array.isArray(mediaRes?.images) ? mediaRes.images : [];
            for (const img of mediaImages) {
              if (img?.data && img?.mimeType) {
                content.push({ type: 'image', mimeType: img.mimeType, data: img.data });
                imageTexts.push(`[转发内图片${img.index != null ? ' ' + img.index : ''}${img.text ? ' ' + img.text : ''}]`);
              } else {
                imageTexts.push(`[转发内图片${img.index != null ? ' ' + img.index : ''}（${img.text || '获取失败'}）]`);
              }
            }
          } catch (error) {
            imageTexts.push(`[转发内图片（批量获取失败：${error?.message ?? error}）]`);
          }
        }
        if (imageTexts.length) {
          content.unshift({ type: 'text', text: `合并转发 ${id} 的图片内容（${imageTexts.length} 项）：\n${imageTexts.join('\n')}` });
        }
        return { content };
      } catch (error) {
        return { content: [{ type: 'text', text: `查看合并转发失败：${error?.message ?? error}` }], isError: true };
      }
    }
  );
}

// ── 撤回：把自己刚发出去的话收回来 ──────────────────────────────────────────
//
// 为什么值得单独一个工具而不是让它自己找 id：OneBot 只回 message_id，而模型平时能看到的
// 历史里自己那几条只有文本。桥接因此维护了一份「本进程发出的消息 id」索引（见 bridge.js
// 的 sentIndexV2），这里默认就是撤最近一条 —— 把动作成本压到一次调用。
server.tool(
  'qq_recall_message',
  '撤回你刚在这个会话里发出的一条消息（只限你自己发的、120 秒内、每小时有次数上限）。不传 messageId 就撤你最近一条，通常不用找 id。适合：说错了、发重复了、话发错地方了、口令/隐私漏了。不适合：被人反驳就想删、想洗掉自己说过的话——反复撤回比说错更奇怪。撤回后可以用 qq_send_message 补一句正确的。',
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    messageId: z.union([z.number(), z.string()]).optional().describe('要撤回的消息 id（可选；省略=撤你最近发的一条）')
  },
  async ({ key, token, messageId }) => {
    try {
      const payload = { key, token };
      if (messageId !== undefined && messageId !== null && String(messageId).trim() !== '') {
        payload.messageId = String(messageId).trim();
      }
      const data = await agentApi('/api/send/recall', {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: { 'x-agent-token': token }
      });
      const ageS = data?.ageMs != null ? Math.round(Number(data.ageMs) / 1000) : null;
      return { content: [{ type: 'text', text: `已撤回（发出约 ${ageS ?? '?'} 秒）：${String(data?.text ?? '').slice(0, 120)}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `撤回失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

// ── QQ 空间（说说）：看 / 发 / 删 / 评论 ────────────────────────────────────
//
// 空间动作全部经桥接转发（不走 here 直连网关），原因和发送工具一样：敏感信息审计、
// 每日条数/最小间隔、以及"这到底是哪个会话的令牌"这三件事只有桥接知道。
const qzoneGateNote = '目标会话必须命中白名单，且空间功能未被关闭（socialV2.qzone.enabled）。';

server.tool(
  'qq_qzone_post',
  `在你自己的 QQ 空间发一条说说（**全好友可见**，比在群里说一句话重得多）。text 是正文；images 可带 1~3 张 http(s) 图片地址（不接受本地路径）；right 可选 1=公开/2=好友可见/3=仅自己，不传就用账号设置。有每日条数与最小间隔限制，超了会被拒绝。真有想说的才发：不打卡、不复读群里的梗、不把说说当群聊。${qzoneGateNote}`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号（用你当前被唤醒的那个）'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    text: z.string().optional().describe('说说正文（纯文本，最多 300 字左右，具体上限见配置）'),
    images: z.array(z.string()).optional().describe('图片地址数组（仅 http/https，1~3 张，可选）'),
    right: z.number().optional().describe('可见范围：1=公开 2=好友可见 3=仅自己（可选）')
  },
  async ({ key, token, text, images, right }) => {
    try {
      const payload = { key, token };
      if (text !== undefined && text !== null) payload.text = String(text);
      if (Array.isArray(images) && images.length) payload.images = images.map(String);
      if (right !== undefined && right !== null) payload.right = Number(right);
      const data = await agentApi('/api/qzone/post', {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: { 'x-agent-token': token },
        timeoutMs: 45000
      });
      return { content: [{ type: 'text', text: `已发说说${data?.tid ? `（tid=${data.tid}）` : ''}：${String(data?.text ?? '').slice(0, 120)}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `发说说失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_qzone_delete',
  `删掉你自己空间里的一条说说（按 tid，先用 qq_qzone_list 查）。发错了/打错字了/不该公开的才能删；删之前想清楚——说说删掉也算一次动作，别反复发删。${qzoneGateNote}`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    tid: z.string().describe('说说 tid（来自 qq_qzone_list）')
  },
  async ({ key, token, tid }) => {
    try {
      await agentApi('/api/qzone/delete', {
        method: 'POST',
        body: JSON.stringify({ key, token, tid: String(tid) }),
        headers: { 'x-agent-token': token }
      });
      return { content: [{ type: 'text', text: `已删除说说 tid=${tid}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `删说说失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_qzone_list',
  `查看你自己 QQ 空间里发过的说说（只读）：tid、时间、正文、评论/点赞数。想删某条或想知道"上一条说了什么"时用。${qzoneGateNote}`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    limit: z.number().optional().describe('最多返回几条，默认 10，最大 30')
  },
  async ({ key, token, limit }) => {
    try {
      const q = new URLSearchParams({ key });
      if (limit != null) q.set('limit', String(limit));
      const data = await agentApi(`/api/qzone/list?${q.toString()}`, { headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `读取说说列表失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_qzone_feeds',
  `看好友的 QQ 空间动态（只读）：每条都带 tid（点赞/留言要用）、uin（作者 QQ）、abstime、多久以前、正文；被我们赞过/留过言的会标 likedByMe / commentedByMe，广告卡会标 ad。${qzoneGateNote}`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    limit: z.number().optional().describe('最多返回几条，默认 10，最大 30'),
    page: z.number().optional().describe('翻页（默认 1；深翻页网关不可靠，能看首页就够）')
  },
  async ({ key, token, limit, page }) => {
    try {
      const q = new URLSearchParams({ key });
      if (limit != null) q.set('limit', String(limit));
      if (page != null) q.set('page', String(page));
      const data = await agentApi(`/api/qzone/feeds?${q.toString()}`, { headers: { 'x-agent-token': token }, timeoutMs: 30000 });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `读取好友动态失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_qzone_like',
  `给一条说说点赞（tid / uin / abstime 全部来自 qq_qzone_feeds）。比留言轻，但同样是公开动作：只在真觉得有意思时点，也别当成打卡。

回来先看 verified：true=回读动态确认已经赞上；false=网关说成功但回读没看到（多半这条已翻页/被删），别对人说"赞好了"；null=没能确认（这条不在首页了）。同一条只会赞一次（已赞会回 alreadyLiked，不会重复打网关）；点错了用 qq_qzone_unlike 撤。有每日次数与最小间隔。${qzoneGateNote}`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    tid: z.string().describe('说说 tid（来自 qq_qzone_feeds）'),
    targetUin: z.string().describe('说说作者的 QQ 号（必填，来自 qq_qzone_feeds 的 uin）：网关靠它定位这条说说在谁的空间里，不传会报"该条内容已被删除"'),
    target_uin: z.string().optional().describe('同 targetUin（兼容下划线写法，二选一即可）'),
    abstime: z.string().optional().describe('说说的 abstime（来自 qq_qzone_feeds），一起传更稳')
  },
  async ({ key, token, tid, targetUin, target_uin, abstime }) => {
    try {
      const uin = pickTargetUin(targetUin, target_uin);
      if (!uin) return { content: [{ type: 'text', text: '点赞失败：必须带 targetUin（说说作者的 QQ 号，来自 qq_qzone_feeds 的 uin）' }], isError: true };
      const payload = { key, token, tid: String(tid), target_uin: uin };
      if (abstime != null) payload.abstime = String(abstime);
      const data = await agentApi('/api/qzone/like', {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: { 'x-agent-token': token },
        timeoutMs: 45000
      });
      const v = data?.verified;
      const verdict = data?.alreadyLiked
        ? '这条之前已经赞过了（没有重复操作）'
        : (v === true ? '已赞（回读确认）' : (v === false ? '界面没确认到，别对外说赞好了' : '已调用，但没能回读确认'));
      return { content: [{ type: 'text', text: `点赞 tid=${tid}：${verdict}${data?.note ? `\n${data.note}` : ''}${data?.quota?.line ? `\n${data.quota.line}` : ''}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `点赞失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_qzone_unlike',
  `取消对一条说说的点赞（赞错了/手滑了用它撤；参数与 qq_qzone_like 相同，来自 qq_qzone_feeds）。${qzoneGateNote}`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    tid: z.string().describe('说说 tid'),
    targetUin: z.string().describe('说说作者的 QQ 号（必填，来自 qq_qzone_feeds 的 uin）'),
    target_uin: z.string().optional().describe('同 targetUin（兼容下划线写法，二选一即可）'),
    abstime: z.string().optional().describe('说说的 abstime')
  },
  async ({ key, token, tid, targetUin, target_uin, abstime }) => {
    try {
      const uin = pickTargetUin(targetUin, target_uin);
      if (!uin) return { content: [{ type: 'text', text: '取消赞失败：必须带 targetUin（说说作者的 QQ 号）' }], isError: true };
      const payload = { key, token, tid: String(tid), target_uin: uin };
      if (abstime != null) payload.abstime = String(abstime);
      await agentApi('/api/qzone/unlike', {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: { 'x-agent-token': token },
        timeoutMs: 45000
      });
      return { content: [{ type: 'text', text: `已取消赞 tid=${tid}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `取消赞失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_qzone_comment',
  `在一条说说下面留言（tid 来自 qq_qzone_feeds / qq_qzone_list）。空间留言是公开的、会显示在你名下：只在你真看懂了那条动态、并且有话可说时才留——一句就够，不写"写得真好""支持一下"这类谁都能说的客套，别当点赞机器。有每日条数与最小间隔。${qzoneGateNote}`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    tid: z.string().describe('说说 tid'),
    // ⚠️ targetUin 是**必填**，不是"建议"：少了它网关会回 code=-10052「该条内容已被删除」，
    // 那条说说其实好好的（2026-10-26 实测：同一条点赞能成功、评论报"已删除"）。
    // 当初写成 optional，结果模型两次都没传、两次都被这句假话劝退。
    targetUin: z.string().describe('说说作者的 QQ 号（必填，来自 qq_qzone_feeds 的 uin）：网关靠它定位这条说说在谁的空间里，不传会报"该条内容已被删除"'),
    target_uin: z.string().optional().describe('同 targetUin（兼容下划线写法，二选一即可）'),
    content: z.string().describe('留言内容（默认最多 100 字）')
  },
  async ({ key, token, tid, targetUin, target_uin, content }) => {
    try {
      const uin = pickTargetUin(targetUin, target_uin);
      if (!uin) return { content: [{ type: 'text', text: '留言失败：必须带 targetUin（说说作者的 QQ 号，来自 qq_qzone_feeds 的 uin）——不给它，网关会误报"该条内容已被删除"' }], isError: true };
      const payload = { key, token, tid: String(tid), content: String(content), target_uin: uin };
      await agentApi('/api/qzone/comment', {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: { 'x-agent-token': token }
      });
      return { content: [{ type: 'text', text: '留言已发送' }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `留言失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

// ── 数字身份：查自己的身份 / 改昵称 / 换头像 / 改自己在群里的名片 ──────────────
//
// 为什么单独一组：这些动作改的是**账号本身**（昵称、头像全账号可见）或它在这个群里的
// 名字（群名片），不是"发一条消息"——消息能撤回，昵称/头像变更在 QQ 侧基本没有撤销入口。
// 所以桥接那边独立限频、独立开关，并且 user_id 一律取登录账号：这些工具只能改自己。
const identityGateNote = '目标会话必须在白名单内，且身份功能与对应工具开关都没被关掉（socialV2.identity / socialV2.tools）。';

// ⚠️ 空间工具的参数名有两个写法在流通：JSON schema 里是 targetUin（驼峰），桥接 HTTP 里是
// target_uin（下划线），而提示词里两种都出现过。2026-10-26 就因为这个丢过一次参数：
// 模型按提示词传了 target_uin，MCP 的 zod schema 只认 targetUin，未知键被静默丢掉，
// 于是网关收到"没带作者 QQ"，回了一句 code=-10052「该条内容已被删除」——一句彻头彻尾的假话，
// 模型照着它向用户汇报"这条被删了"。所以三个工具都同时收两种写法，并且缺了要明确报错。
function pickTargetUin(targetUin, snake) {
  return String(targetUin ?? snake ?? '').trim();
}

server.tool(
  'qq_get_self_profile',
  `查看你自己的 QQ 身份（只读）：昵称、QQ 号、头像直链；在群里还会带上你在这个群显示的名片，以及**头像池**（avatarPool：池子里有哪些网图、桥接会不会自动轮换）。想在改名前确认现在叫什么、想知道能挑哪些图换头像、被问「你叫什么/你头像是什么」时用。${identityGateNote}`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）')
  },
  async ({ key, token }) => {
    try {
      const q = new URLSearchParams({ key });
      const data = await agentApi(`/api/socialV2/identity/profile?${q.toString()}`, { headers: { 'x-agent-token': token } });
      return { content: [{ type: 'text', text: serializeModelData(data) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `读取自己的身份失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_set_nickname',
  `改你自己的 QQ 昵称（**全账号生效**：好友和所有群都会看到，改的不是群名片）。

这是你的**情绪表达方式**之一：被人骂了、被开过分的玩笑、或者对方惹你不爽时，与其发十条消息讲道理，不如把名字改成一句带梗的话（比如有人叫乐乐，你就把名字改成「乐乐是猪」）——群里一眼就看见你的脸色。气顺了记得改回来（「旺仔」），别一直挂着。

注意：这是身份级写操作，不是发消息，撤不回来；有每小时上限与最小间隔（超了会被拒绝），文案会过敏感信息审计（路径/凭据会被拦）。改完看 applied：true=已在群里读回新名（真生效）；false=网关说成功但读回来不是新名（多半被拦，别对外说改了）；null=只能读登录缓存、无法确认。桥接会顺手刷新它对自己的认知（旧名字仍算在叫你）。${identityGateNote}`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    nickname: z.string().describe('新的 QQ 昵称（最长见 limits.nickname.maxChars，通常 24 字）')
  },
  async ({ key, token, nickname }) => {
    try {
      const data = await agentApi('/api/socialV2/identity/nickname', {
        method: 'POST',
        body: JSON.stringify({ key, token, nickname: String(nickname ?? '') }),
        headers: { 'x-agent-token': token },
        timeoutMs: 60000
      });
      const applied = data?.applied === true;
      const unknown = data?.applied === null;
      const head = applied ? '已改名' : (unknown ? '改名已提交（未能确认）' : '改名未确认生效');
      return { content: [{ type: 'text', text: `${head}：${data?.previous ? `「${data.previous}」→ ` : ''}「${data?.nickname ?? ''}」${data?.note ? `\n${data.note}` : ''}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `改昵称失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_set_avatar',
  `换你自己的 QQ 头像（**全账号生效**：好友、群成员都看得到）。

头像就是你的脸面：桥接的**头像池**（默认 assets/avatar-pool）里放着从网上抓来的网图，桥接自己会**不定期**挑一张换上去（几小时一次，随机）；你也可以现在就手动换一张——
· path：池子里的文件名，如 "assets/avatar-pool/xxx.jpg"（有哪些图见 qq_get_self_profile 返回的 avatarPool.files）
· url：http(s) 图片地址（桥接自己下载，禁内网地址）
· stickerId：把你收藏的某张表情当头像（id 从 qq_list_stickers 拿）

桥接会先校验图片类型/体积再以 base64 传给网关，不接受任意本地路径。有每小时上限；QQ 侧有缓存，别人可能几分钟后才看到新头像，别为了"确认一下"反复换。${identityGateNote}`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    url: z.string().optional().describe('http(s) 图片地址（桥接自己下载，≤ 配置的体积上限）'),
    path: z.string().optional().describe('头像目录内的相对路径（默认 assets/ 与 state/avatar/）'),
    stickerId: z.string().optional().describe('把收藏表情当头像：emoji_id / md5 / url（来自 qq_list_stickers）')
  },
  async ({ key, token, url, path: avatarPath, stickerId }) => {
    try {
      const payload = { key, token };
      if (url) payload.url = String(url);
      if (avatarPath) payload.path = String(avatarPath);
      if (stickerId) payload.stickerId = String(stickerId);
      if (!payload.url && !payload.path && !payload.stickerId) {
        return { content: [{ type: 'text', text: '换头像需要 url / path / stickerId 之一' }], isError: true };
      }
      const data = await agentApi('/api/socialV2/identity/avatar', {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: { 'x-agent-token': token },
        timeoutMs: 120000
      });
      return { content: [{ type: 'text', text: `已换头像（来源：${data?.source ?? '?'}，${data?.mime ?? '?'}${data?.width ? ` ${data.width}x${data.height}` : ''}${data?.bytes ? `，${Math.round(Number(data.bytes) / 1024)}KB` : ''}）${data?.note ? `\n${data.note}` : ''}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `换头像失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_set_group_card',
  `改你自己在**这个群**里显示的群名片（只影响当前群，不改 QQ 昵称）。

和改名一样是**甩脸色**的轻量方式：在群里被冒犯了，改群名片比在群里吵更省事（昵称全账号可见，名片只在当前群）。card 传空字符串表示想恢复用昵称显示——但本网关不支持把名片设成空（会被服务端拒），桥接会自动退化成"名片=当前昵称"，返回里会有 clearedToNickname 说明，别当成清空成功。只能改自己的名片（改别人的需要群管理权限，桥接不提供）。有每小时上限与最小间隔；applied=true 才算真的生效。${identityGateNote}`,
  {
    key: z.string().describe('会话 key，格式 group:群号（群名片只在群里有效）'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    card: z.string().describe('新群名片；空字符串=清除名片（恢复昵称显示）')
  },
  async ({ key, token, card }) => {
    try {
      const data = await agentApi('/api/socialV2/identity/group-card', {
        method: 'POST',
        body: JSON.stringify({ key, token, card: String(card ?? '') }),
        headers: { 'x-agent-token': token },
        timeoutMs: 60000
      });
      const applied = data?.applied !== false;
      const shown = data?.card ? `「${data.card}」` : '（已清除，改用昵称显示）';
      return { content: [{ type: 'text', text: `${applied ? '已改群名片' : '群名片改动未确认生效'}：${shown}${data?.note ? `\n${data.note}` : ''}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `改群名片失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

// ── 工具分片：默认只挂「核心组 + 记忆」，其余组用 qq_tools 按需打开 ─────────────
//
// 为什么在 connect 之前收敛（而不是只靠 preset 的 qq-tool-restrict 拦调用）：
//   restrict 只能拒绝**调用**，schema 照样随请求头发出去；这里是把工具从 tools/list 里直接摘掉，
//   模型连看都看不到 —— 省的是每一次请求的 token，也少一半长名字互相干扰。
const TOOL_GROUPS_STATE = path.join(ROOT, 'state', 'tool-groups.json');
const TG = (typeof toolGroupsModule !== 'undefined' && toolGroupsModule) || null;
let activeGroups = new Set(['core']);

function groupSnapshot() {
  if (!TG) return [];
  const known = new Set([...registeredTools.keys()].map((n) => TG.groupOf(n)).filter(Boolean));
  return TG.describeGroups([...activeGroups]).filter((g) => known.has(g.group));
}

/** 把挂载集合落到 SDK 的 enabled 位上；persist=true 时同步写 state/tool-groups.json。 */
function propagateGroups(next, { persist = false, by = 'qq_tools' } = {}) {
  if (!TG) return { ok: false, error: '工具分组模块不可用', groups: ['core'], enabled: 0, disabled: 0 };
  const groups = new Set([...next].filter((g) => TG.GROUP_TOOLS?.[g]));
  groups.add('core');
  let on = 0;
  let off = 0;
  for (const [name, registered] of registeredTools) {
    const g = TG.groupOf(name);
    const want = g ? groups.has(g) : true; // 未归组的保持原样（audit 会报出来）
    try {
      if (want) { registered?.enable?.(); on += 1; } else { registered?.disable?.(); off += 1; }
    } catch {}
  }
  activeGroups = groups;
  if (persist) TG.saveGroupsState(TOOL_GROUPS_STATE, [...groups], { by });
  try { server.sendToolListChanged?.(); } catch {}
  return { ok: true, groups: [...groups], enabled: on, disabled: off };
}

server.tool(
  'qq_send_image',
  `发一张图（不是表情：表情走 qq_send_sticker）。三种来源选一个：
· stickerId —— 收藏表情里的图（先用 qq_list_stickers 拿 id）
· url —— 网图直链（桥接自己下载，禁内网地址）
· path —— qq-bridge 白名单目录内的相对路径（如 out/shot.png、assets/x.jpg）

图片以 base64 直接进气泡，QQ 侧不用再抓一次；可带 replyToMessageId 引用某条消息。
默认上限 5MB，一次一张；多张就多调几次，会走同一条发送队列，顺序不会乱。`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    stickerId: z.string().optional().describe('收藏表情的 id / md5 / url（来自 qq_list_stickers）'),
    url: z.string().optional().describe('http(s) 图片直链（桥接下载，禁内网地址）'),
    path: z.string().optional().describe('白名单目录内的相对路径，例如 out/screenshot.png'),
    replyToMessageId: z.union([z.number(), z.string()]).optional().describe('引用/回复的消息 id（非零整数，可为负数）')
  },
  async ({ key, token, stickerId, url, path: imgPath, replyToMessageId }) => {
    try {
      const payload = { key, token };
      if (stickerId) payload.stickerId = String(stickerId);
      if (url) payload.url = String(url);
      if (imgPath) payload.path = String(imgPath);
      if (replyToMessageId != null) payload.replyToMessageId = replyToMessageId;
      if (!payload.stickerId && !payload.url && !payload.path) {
        return { content: [{ type: 'text', text: '需要 stickerId / url / path 之一' }], isError: true };
      }
      const data = await agentApi('/api/socialV2/send-image', {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: { 'x-agent-token': token },
        timeoutMs: 120000
      });
      if (data?.ok === false) return { content: [{ type: 'text', text: `发图被拒：${data.error}` }], isError: true };
      const kb = Math.round(Number(data?.bytes ?? 0) / 1024);
      return { content: [{ type: 'text', text: `已发图（来源 ${data?.source ?? '?'}，${kb}KB）${data?.messageId ? ` · message_id ${data.messageId}` : ''}${data?.note ? `\n${data.note}` : ''}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `发图失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_send_file',
  `发一个文件（文档、压缩包、音视频）。只接受 qq-bridge 里 **白名单目录内的相对路径**（默认 out / assets / audio / exports / state/media），
绝对路径、盘符、..、URL 一律不发；可执行与脚本类扩展名（exe/bat/ps1/vbs/apk…）不发。

群聊走「上传群文件」、私聊走「私聊文件上传」——都不会在聊天里生成气泡，对方要在文件列表里点接收。默认上限 20MB。`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    path: z.string().describe('白名单目录内的相对路径，例如 out/report.pdf'),
    name: z.string().optional().describe('显示用的文件名（默认取路径里的文件名）')
  },
  async ({ key, token, path: filePath, name }) => {
    try {
      const data = await agentApi('/api/socialV2/send-file', {
        method: 'POST',
        body: JSON.stringify({ key, token, path: String(filePath), name: name ? String(name) : undefined }),
        headers: { 'x-agent-token': token },
        timeoutMs: 180000
      });
      if (data?.ok === false) return { content: [{ type: 'text', text: `发文件被拒：${data.error}` }], isError: true };
      return { content: [{ type: 'text', text: `已发送 ${data?.name ?? ''}（${Math.round(Number(data?.bytes ?? 0) / 1024)}KB）${data?.fileId ? ` · file_id ${data.fileId}` : ''}${data?.note ? `\n${data.note}` : ''}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `发文件失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_send_forward',
  `发一条「合并转发 / 聊天记录」卡片。节点两种来源可混用：
· messageIds —— 本会话**确实收到过**的消息 seq 或 messageId（跨会话、凭 id 猜别处记录一律拒绝）
· nodes —— 纯文本节点 [{ name, text }]

默认最多 10 个节点、每节点 300 字。用途：把散落的几句整理成一条记录，比如「刚才问的三个问题」。`,
  {
    key: z.string().describe('会话 key，格式 group:群号 或 private:QQ号'),
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）'),
    messageIds: z.array(z.union([z.number(), z.string()])).optional().describe('本会话可见消息的 seq 或 messageId 列表'),
    nodes: z.array(z.object({ name: z.string().optional(), text: z.string() })).optional().describe('自定义文本节点（{name,text}）')
  },
  async ({ key, token, messageIds, nodes }) => {
    try {
      const payload = { key, token };
      if (Array.isArray(messageIds) && messageIds.length) payload.messageIds = messageIds;
      if (Array.isArray(nodes) && nodes.length) payload.nodes = nodes;
      if (!payload.messageIds && !payload.nodes) {
        return { content: [{ type: 'text', text: '需要 messageIds 或 nodes 至少一项' }], isError: true };
      }
      const data = await agentApi('/api/socialV2/send-forward', {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: { 'x-agent-token': token },
        timeoutMs: 120000
      });
      if (data?.ok === false) return { content: [{ type: 'text', text: `合并转发被拒：${data.error}` }], isError: true };
      return { content: [{ type: 'text', text: `已发合并转发（${data?.nodes ?? 0} 个节点）${data?.messageId ? ` · message_id ${data.messageId}` : ''}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `合并转发失败：${error?.message ?? error}` }], isError: true };
    }
  }
);

server.tool(
  'qq_tools',
  `工具分片开关：默认只挂核心通讯工具 + 记忆。QQ 空间、表情库维护、身份（昵称/头像/名片/语气附录）、语音与唱歌、文件/合并转发、黑话词库、成员查询、抖音素材这些**扩展组默认关闭**，要用时先用这个工具打开。

用法：
· action="list" —— 看当前开了哪些组、每组有哪些工具（关着的组也能看到工具名，别靠猜）
· action="enable" + group=组名 —— 打开一组，工具立刻可用
· action="disable" + group=组名 —— 关掉一组，省下它的 schema

规则：
· core 不能关（看消息、说话、等待、睡觉、表情、发图都在 core）
· 同时挂载的组数有上限（默认 4 组），开太多就白省了
· 组是**粘性**的：打开会落盘、新会话继承，不是一次性的；用完把不用的组关回去`,
  {
    action: z.enum(['list', 'enable', 'disable']).describe('list=查看当前挂载；enable=打开一组；disable=关闭一组'),
    group: z.string().optional().describe('组名：memory / media / sticker / voice / people / qzone / identity / slang / douyin / legacy（core 恒开）')
  },
  async ({ action, group }) => {
    if (!TG) {
      return { content: [{ type: 'text', text: '工具分片模块不可用（离线/vm 环境），当前全量挂载。' }] };
    }
    if (action === 'list') {
      const snap = groupSnapshot();
      const lines = snap.map((g) => `${g.enabled ? '✅' : '⬜'} ${g.group}（${g.label}）：${g.tools.join(', ')}`);
      return { content: [{ type: 'text', text: `当前挂载：${[...activeGroups].join(', ')}\n${lines.join('\n')}` }] };
    }
    const target = String(group ?? '').trim();
    if (!TG.GROUP_TOOLS[target]) {
      const names = Object.keys(TG.GROUP_TOOLS).filter((g) => g !== 'core').join(' / ');
      return { content: [{ type: 'text', text: `没有这个组：${target || '(空)'}。可用：${names}` }], isError: true };
    }
    if (target === 'core' && action === 'disable') {
      return { content: [{ type: 'text', text: 'core 是常驻组，关不掉。' }], isError: true };
    }
    const maxActive = Number.isFinite(Number(cfg?.socialV2?.toolGroups?.maxActive))
      ? Number(cfg.socialV2.toolGroups.maxActive)
      : 4;
    const next = new Set(activeGroups);
    if (action === 'enable') next.add(target);
    else next.delete(target);
    if (next.size > maxActive) {
      return { content: [{ type: 'text', text: `最多同时挂 ${maxActive} 组（这次会到 ${next.size}）。先关一组再开：当前 ${[...activeGroups].join(', ')}` }], isError: true };
    }
    propagateGroups(next, { persist: true, by: 'qq_tools' });
    const view = (groupSnapshot()).filter((g) => g.enabled).map((g) => `${g.group}(${g.tools.length})`).join(' + ');
    return { content: [{ type: 'text', text: `${action === 'enable' ? '已打开' : '已关闭'} ${target}。当前挂载：${view || 'core'}。tools/list 已变更，下一步就能用。` }] };
  }
);

if (TG) {
  const resolved = TG.resolveActiveGroups({
    cfg,
    registered: registeredTools.keys(),
    stateFile: TOOL_GROUPS_STATE,
    mode: bootBridgeMode
  });
  const applied = propagateGroups(resolved.groups, { persist: false });
  const audit = TG.auditGroups(registeredTools.keys());
  console.error(
    `[snowluma-safe] 工具分片：已注册 ${registeredTools.size} 个，挂载 ${applied.groups.length} 组 ${JSON.stringify(applied.groups)}（来源 ${resolved.source}），本次摘掉 ${applied.disabled} 个工具的 schema`
  );
  if (audit.unclassified.length) {
    console.error(`[snowluma-safe] 未归组的工具（请补 src/tool-groups.js）：${audit.unclassified.join(', ')}`);
  }
  if (audit.ghost.length) {
    // 有两种工具本来就会"有时在有时不在"，不算异常：
    //   · legacy 组（qq_list_groups / qq_get_group_history）—— 只在非 reserved2 模式注册；
    //   · 管理端开关默认关闭的风险操作（qq_set_sticker_remark 等）—— 关着就不注册。
    // 把它们剔掉，这条告警才只在真的改名/删掉时出现。
    const expectedAbsent = new Set(TG?.GROUP_TOOLS?.legacy ?? []);
    for (const [name, flag] of Object.entries(TOOL_CONFIG_FLAGS)) {
      if (cfg.socialV2?.tools?.[flag] === false) expectedAbsent.add(name);
    }
    const ghosts = audit.ghost.filter((name) => !expectedAbsent.has(name));
    if (ghosts.length) {
      console.error(`[snowluma-safe] 分组表里多出来的工具（已改名或删掉？）：${ghosts.join(', ')}`);
    }
  }
} else {
  console.error('[snowluma-safe] 工具分片模块不可用：本次全量挂载所有工具');
}

await server.connect(new StdioServerTransport());
