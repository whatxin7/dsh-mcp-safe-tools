// 联网搜索（MCP `web_search` 的实现）。
//
// 设计目标：**优先复用 DSH 原本的联网搜索能力**，而不是自己抓 Bing 的搜索结果页。
//
// DSH 的 `web_search` 工具背后是 `@deepseek-ai/dsh-web-search-deepseek`：
// 向 DeepSeek 的 Anthropic 兼容 Messages 端点发一次带 `web_search_20250305`
// 服务端工具的请求，从 `web_search_tool_result` 里取结构化结果。本模块照同一
// 端点/模型/工具参数实现一份最小客户端，于是 QQ 里的 AI 和 DSH 里的 AI 拿到的是
// **同一路搜索结果**；搜索词只发给 DeepSeek（也就是本来就在处理这段对话的同一家），
// 不再把群聊里提炼出来的词发给 Bing。
//
// 凭据解析顺序与 DSH 一致：
//   1. config.json 的 `webSearch.apiKey`（不推荐，明文）
//   2. 环境变量 `DEEPSEEK_API_KEY`（可用 `webSearch.apiKeyEnv` 改）
//   3. DSH 的 `$DSH_HOME/.credentials.yaml` → `refs.<ref>`（DSH 的 Models 页写入的 key）
// 都没有时：回退 Bing（`cn.bing.com` 的 RSS，失败再退回 HTML），保证"永远有一个能用的搜索"。
//
// 安全边界：
// - API key 只发往**校验过**的 HTTPS 端点：必须是 https、必须解析到公网地址
//   （防止把 key 发到 localhost/内网），且禁止跟随重定向（`redirect: error`）。
// - key 永远不写日志、不进错误信息、不进返回结果。
// - 响应体有大小上限；请求有总超时；查询词在 MCP 层已清洗。
// - Bing 走 safe-fetch（SSRF 防护 + 多地址故障切换）。
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import { URL } from 'node:url';
import YAML from 'js-yaml';
import { resolveSafeAddresses, safeFetch } from './safe-fetch.js';

const DEFAULT_BASE_URL = 'https://api.deepseek.com/anthropic/v1';
const DEFAULT_MODEL = 'deepseek-v4-flash';
const DEFAULT_API_VERSION = '2023-06-01';
const DEFAULT_API_KEY_ENV = 'DEEPSEEK_API_KEY';
const DEFAULT_TIMEOUT_MS = 35000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_MAX_ENTRIES = 64;
// 抓搜索引擎的网页结果是有配额的：实测百度连续 6~8 次就甩「百度安全验证」页，360 差不多
// （连 10 次左右开始回验证页），冷却一阵才恢复。所以这里做两件事：
//   ① 请求之间至少隔 MIN_REQUEST_GAP_MS，别让自己写成"爬虫"；
//   ② 一旦某家被判风控，就把它拉黑一段时间（进程内），后续查询直接跳过、交给下一家，
//      而不是每轮都再去撞一次（撞一次就多一次风控计数）。
const MIN_REQUEST_GAP_MS = 1500;
const PROVIDER_COOLDOWN_MS = 10 * 60 * 1000;
const providerCooldownUntil = new Map();
let lastScrapeRequestAt = 0;

function providerCoolingDown(provider) {
  const until = providerCooldownUntil.get(provider) ?? 0;
  return until > Date.now() ? Math.ceil((until - Date.now()) / 60000) : 0;
}

function assertProviderReady(provider) {
  const left = providerCoolingDown(provider);
  if (left > 0) {
    throw Object.assign(new Error(`${provider} 刚被风控，冷却中（约 ${left} 分钟）`), { code: 'COOLDOWN' });
  }
}

function noteProviderOutcome(provider, error) {
  if (!error) {
    providerCooldownUntil.delete(provider);
    return;
  }
  // 因为我们自己在跳过（冷却中）而失败，不是新证据 —— 别把冷却时间一次次往后推。
  if (error?.code === 'COOLDOWN') return;
  const text = String(error?.message ?? error);
  if (/安全验证|验证页|captcha|人机|风控|Reject/i.test(text)) {
    providerCooldownUntil.set(provider, Date.now() + PROVIDER_COOLDOWN_MS);
  }
}

/** 让所有抓取型后端排队通过（间隔 + 冷却检查）。 */
async function politeFetchGate(provider) {
  assertProviderReady(provider);
  const wait = MIN_REQUEST_GAP_MS - (Date.now() - lastScrapeRequestAt);
  if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
  lastScrapeRequestAt = Date.now();
}

// Anthropic 兼容响应里文本块/结果块都可能有；这里只要结构化结果。
const SEARCH_TOOL_TYPE = 'web_search_20250305';

const defaultConfig = Object.freeze({
  provider: 'auto',
  apiKey: '',
  apiKeyEnv: DEFAULT_API_KEY_ENV,
  baseURL: '',
  model: DEFAULT_MODEL,
  maxUses: 5,
  maxTokens: 4096,
  maxResults: 8,
  timeoutMs: DEFAULT_TIMEOUT_MS
});

function num(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

/** 读取 config.json 里的 webSearch 段（不存在就用默认值）。 */
export function loadSearchConfig(root) {
  let file = {};
  try {
    const text = fs.readFileSync(path.join(root, 'config.json'), 'utf8');
    file = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch {}
  const raw = file?.webSearch && typeof file.webSearch === 'object' && !Array.isArray(file.webSearch) ? file.webSearch : {};
  const provider = ['deepseek', 'bing', 'baidu', 'so360'].includes(raw.provider) ? raw.provider : 'auto';
  return {
    ...defaultConfig,
    provider,
    apiKey: typeof raw.apiKey === 'string' ? raw.apiKey.trim() : '',
    apiKeyEnv: typeof raw.apiKeyEnv === 'string' && raw.apiKeyEnv.trim() ? raw.apiKeyEnv.trim() : DEFAULT_API_KEY_ENV,
    baseURL: typeof raw.baseURL === 'string' ? raw.baseURL.trim().replace(/\/+$/, '') : '',
    model: typeof raw.model === 'string' && raw.model.trim() ? raw.model.trim() : DEFAULT_MODEL,
    maxUses: num(raw.maxUses, defaultConfig.maxUses, 1, 5),
    maxTokens: num(raw.maxTokens, defaultConfig.maxTokens, 256, 8192),
    maxResults: num(raw.maxResults, defaultConfig.maxResults, 1, 20),
    timeoutMs: num(raw.timeoutMs, defaultConfig.timeoutMs, 5000, 120000)
  };
}

/** DSH home：与 dsh-client 的判定保持一致（`DSH_HOME` 优先）。 */
export function resolveDshHome() {
  return process.env.DSH_HOME || path.join(os.homedir(), '.dsh');
}

/**
 * 从 DSH 的凭据文件里取 key。
 * 结构：`refs: { <名称>: <明文值> }`（实测；不是记录 id）。只看指定 ref，绝不遍历其它凭据。
 */
export function readDshCredential(ref) {
  const name = String(ref ?? '').trim();
  if (!name) return '';
  try {
    const doc = YAML.load(fs.readFileSync(path.join(resolveDshHome(), '.credentials.yaml'), 'utf8'));
    const value = doc?.refs?.[name];
    return typeof value === 'string' ? value.trim() : '';
  } catch {
    return '';
  }
}

/** 解析搜索用的 DeepSeek key；返回 { key, source } —— key 只在这里出现，不落日志。 */
export function resolveSearchApiKey(config) {
  const literal = String(config?.apiKey ?? '').trim();
  if (literal) return { key: literal, source: 'config' };
  const envName = String(config?.apiKeyEnv || DEFAULT_API_KEY_ENV);
  const fromEnv = String(process.env[envName] ?? '').trim();
  if (fromEnv) return { key: fromEnv, source: 'env' };
  const fromDsh = readDshCredential(envName);
  if (fromDsh) return { key: fromDsh, source: 'dsh-credentials' };
  return { key: '', source: 'none' };
}

function normalizeSearchUrl(raw) {
  const s = String(raw ?? '').trim();
  if (!/^https?:\/\//i.test(s)) return '';
  // DeepSeek 的结果 URL 会带 `#1` 这类"第几条"的锚点（不是页面真实片段），去掉更干净；
  // 但真实的 `#section` 也可能有意义，所以只去纯数字锚点。
  const cleaned = s.replace(/#\d+$/, '');
  try {
    const url = new URL(cleaned);
    if (!['http:', 'https:'].includes(url.protocol)) return '';
    if (url.username || url.password) return '';
    return url.toString();
  } catch {
    return '';
  }
}

/** 把 Anthropic Messages 响应映射成统一结果（参照 dsh-web-search-deepseek 的实现）。 */
export function mapDeepSeekResponse(response, maxResults = 8) {
  const blocks = Array.isArray(response?.content) ? response.content : [];
  const resultBlocks = blocks.filter((block) => block?.type === 'web_search_tool_result');
  if (!resultBlocks.length) {
    throw Object.assign(new Error('DeepSeek 没有返回 web_search_tool_result（可能未触发联网搜索）'), { code: 'NO_RESULT_BLOCK' });
  }
  const snippets = new Map();
  for (const block of blocks) {
    if (block?.type !== 'text') continue;
    for (const cite of block.citations ?? []) {
      const url = normalizeSearchUrl(cite?.url);
      if (!url || snippets.has(url)) continue;
      const text = String(cite?.cited_text ?? '').trim();
      if (text) snippets.set(url, text);
    }
  }
  const seen = new Set();
  const results = [];
  for (const block of resultBlocks) {
    for (const item of block?.content ?? []) {
      if (item?.type !== 'web_search_result') continue;
      const url = normalizeSearchUrl(item.url);
      if (!url || seen.has(url)) continue;
      seen.add(url);
      const title = String(item.title ?? '').trim().slice(0, 200);
      const snippet = String(snippets.get(url) ?? '').trim().slice(0, 500);
      results.push({
        title,
        url,
        ...(snippet ? { snippet } : {}),
        ...(item.page_age ? { publishedAt: String(item.page_age).slice(0, 40) } : {})
      });
      if (results.length >= maxResults) return results;
    }
  }
  return results;
}

/** 校验搜索端点：https + 公网地址。返回 { url, addresses }。 */
async function validateSearchEndpoint(baseURL) {
  let url;
  try {
    url = new URL(String(baseURL ?? '').trim());
  } catch {
    throw new Error('webSearch.baseURL 无效');
  }
  if (url.protocol !== 'https:') throw new Error('webSearch.baseURL 必须是 https（API key 只能发给加密端点）');
  if (url.username || url.password) throw new Error('webSearch.baseURL 不能包含凭据');
  const addresses = await resolveSafeAddresses(url.hostname);
  return { url, addresses };
}

/**
 * 向搜索端点 POST JSON（单个已校验地址）。
 * 不复用 safeFetch（它只做 GET）：这里需要 POST、禁止重定向，并把 key 只交给校验过的地址。
 * 网络层失败（连接/超时/中断）由 postJson() 换地址重试；HTTP 状态是结果，不在这里重试。
 */
function postJsonOnce(url, address, { headers, body, timeoutMs, maxBytes = MAX_RESPONSE_BYTES }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let req;
    let response;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value);
    };
    const timer = setTimeout(() => {
      const error = new Error(`联网搜索请求超时（${Math.round(timeoutMs / 1000)}s）`);
      finish(error);
      req?.destroy(error);
      response?.destroy();
    }, timeoutMs);
    try {
      req = https.request({
        hostname: address,
        port: url.port || 443,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          ...headers,
          host: url.host,
          'content-length': Buffer.byteLength(body)
        },
        // 证书校验用真实域名（SNI/Host 与站点一致），连接目标才是固定 IP。
        servername: url.hostname,
        rejectUnauthorized: true,
        timeout: timeoutMs
      }, (res) => {
        response = res;
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400) {
          finish(new Error(`联网搜索端点返回重定向（HTTP ${status}），已拒绝跟随`));
          res.destroy();
          return;
        }
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          if (settled) return;
          size += chunk.length;
          if (size > maxBytes) {
            finish(new Error('联网搜索响应体过大，已中止'));
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on('error', (error) => finish(error));
        res.on('aborted', () => finish(new Error('联网搜索响应中断')));
        res.on('close', () => { if (!res.complete) finish(new Error('联网搜索响应中断')); });
        res.on('end', () => {
          if (settled) return;
          const text = Buffer.concat(chunks).toString('utf8');
          finish(null, { status, text });
        });
      });
      req.on('timeout', () => {
        const error = new Error(`联网搜索请求超时（${Math.round(timeoutMs / 1000)}s）`);
        finish(error);
        req.destroy(error);
        response?.destroy();
      });
      req.on('error', (error) => finish(error));
      req.end(body);
    } catch (error) {
      finish(error);
      req?.destroy();
    }
  });
}

/** 依次尝试前两个已校验地址（同一失败形态：DNS 先给 IPv6、本机没有 IPv6 出口）。 */
async function postJson(url, addresses, options) {
  const list = (Array.isArray(addresses) ? addresses : [addresses]).filter(Boolean);
  if (!list.length) throw new Error('没有任何可用地址');
  const deadline = Date.now() + options.timeoutMs;
  const attempts = Math.min(list.length, 2);
  let lastError = null;
  for (let i = 0; i < attempts; i += 1) {
    const remaining = deadline - Date.now();
    if (remaining <= 500) break;
    const budget = attempts === 1 ? options.timeoutMs : Math.min(remaining, Math.ceil(options.timeoutMs / 2));
    try {
      return await postJsonOnce(url, list[i], { ...options, timeoutMs: budget });
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error('联网搜索请求失败');
}

/** DeepSeek 原生联网搜索。失败时抛出带稳定 code 的错误，由调用方决定是否回退。 */
export async function deepseekSearch(query, config = defaultConfig) {
  const { key } = resolveSearchApiKey(config);
  if (!key) {
    throw Object.assign(new Error('没有可用的 DeepSeek API key'), { code: 'NO_KEY' });
  }
  const baseURL = config.baseURL || process.env.DEEPSEEK_SEARCH_BASE_URL || DEFAULT_BASE_URL;
  const { url, addresses } = await validateSearchEndpoint(baseURL);
  const endpoint = new URL(`${url.toString().replace(/\/+$/, '')}/messages`);
  const body = JSON.stringify({
    model: config.model || DEFAULT_MODEL,
    max_tokens: config.maxTokens || defaultConfig.maxTokens,
    messages: [{
      role: 'user',
      content: [{ type: 'text', text: `Perform a web search for the query: ${query}` }]
    }],
    tools: [{
      type: SEARCH_TOOL_TYPE,
      name: 'web_search',
      max_uses: config.maxUses || defaultConfig.maxUses
    }]
  });
  const response = await postJson(endpoint, addresses, {
    headers: {
      'x-api-key': key,
      authorization: `Bearer ${key}`,
      'anthropic-version': DEFAULT_API_VERSION,
      'content-type': 'application/json',
      accept: 'application/json',
      'user-agent': 'qq-bridge-web-search/0.2.0'
    },
    body,
    timeoutMs: config.timeoutMs || DEFAULT_TIMEOUT_MS
  });
  if (response.status < 200 || response.status >= 300) {
    // 只回显 HTTP 状态与主体里的简短错误，绝不拼接请求头（里面是 key）。
    let detail = '';
    try {
      const parsed = JSON.parse(response.text);
      const message = typeof parsed?.error === 'string' ? parsed.error : parsed?.error?.message ?? parsed?.message;
      if (typeof message === 'string') detail = message.slice(0, 200);
    } catch {}
    throw Object.assign(
      new Error(`DeepSeek 搜索接口 HTTP ${response.status}${detail ? `：${detail}` : ''}`),
      { code: 'HTTP_ERROR', status: response.status }
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(response.text);
  } catch {
    throw Object.assign(new Error('DeepSeek 搜索接口返回了无法解析的响应'), { code: 'BAD_BODY' });
  }
  return mapDeepSeekResponse(parsed, config.maxResults || defaultConfig.maxResults);
}

function decodeEntities(text) {
  return String(text ?? '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => {
      const code = Number.parseInt(hex, 16);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    })
    .replace(/&#(\d+);/g, (_, dec) => {
      const code = Number(dec);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    })
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function pickTag(block, tag) {
  const match = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i').exec(block);
  return match ? decodeEntities(match[1]) : '';
}

/** 百度结果页解析。
 *
 * 为什么要有百度这一路：实测同一个网络下，必应对**多词中文查询**几乎只按第一个词匹配
 * （"卡通形象 表情包" 返回的全是字典页；"某游戏 某角色 介绍" 只回官网），
 * 而百度同样的查询能命中山寨科普、百科词条这类真正解释性
 * 的结果。认图/认梗这类场景只能靠解释性结果，所以中文查询优先走这里。
 *
 * 结构（2026-10 实测）：正文条目是 `<div class="result c-container ..." mu="<真实 URL>">`，
 * 标题在块内第一个 `<h3>` 里，摘要是标题之后的文本。类名带 hash 后缀，只能用前缀锚定。
 */
export function parseBaiduHtml(html, maxResults = 8) {
  const text = String(html ?? '');
  const results = [];
  const seen = new Set();
  const starts = [];
  const re = /<div[^>]*class="result[^"]*c-container[^"]*"[^>]*>/g;
  let match;
  while ((match = re.exec(text)) !== null) starts.push(match.index);
  if (!starts.length) return results;
  for (let i = 0; i < starts.length; i += 1) {
    const block = text.slice(starts[i], i + 1 < starts.length ? starts[i + 1] : Math.min(text.length, starts[i] + 20000));
    // mu= 是百度给的**真实落地页**（href 是 baidu.com/link?url=... 的跳转壳，不能直接用）。
    const url = normalizeSearchUrl(decodeEntities((block.match(/\smu="([^"]+)"/i) || [])[1] || ''));
    if (!url || seen.has(url)) continue;
    // 首条常常是百度自家的"图片/视频"竖版卡片（指向 image.baidu.com，标题带"百度图片"），
    // 对"这东西是什么"没有任何解释力，只占名额。
    if (/^https?:\/\/image\.baidu\.com\//i.test(url)) continue;
    const titleHtml = (block.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i) || [])[1] || '';
    const title = decodeEntities(titleHtml).slice(0, 200);
    if (!title) continue;
    let afterTitle = block.slice(Math.max(0, block.indexOf(titleHtml) + titleHtml.length));
    // 百度会把卡片数据塞进 <script> / 注释 / 内联 JSON 里（decodeEntities 一过就成了满屏
    // `"summarySpan":12` 这种垃圾）。先剁掉这些，再取纯文本，摘要才有可读性。
    afterTitle = afterTitle
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<!--[\s\S]*?-->/g, ' ');
    const rawSnippet = decodeEntities(afterTitle)
      .replace(/^[\s\-–—|·:,，。]+/, '')
      .replace(/\{[\s\S]*$/, '')
      .slice(0, 400);
    // 残留的 JSON 片段（`"summarySpan":12`）不如不给：宁可只有标题。
    const snippet = rawSnippet && !/^["'][\w-]+["']\s*:/.test(rawSnippet) ? rawSnippet : '';
    seen.add(url);
    results.push({ title, url, ...(snippet ? { snippet } : {}) });
    if (results.length >= maxResults) break;
  }
  return results;
}

/** 百度网页搜索（HTML 抓取；中文/梗/人物类查询比必应的 RSS 准得多）。 */
export async function baiduSearch(query, config = defaultConfig) {
  const maxResults = config.maxResults || defaultConfig.maxResults;
  await politeFetchGate('baidu');
  const url = new URL('https://www.baidu.com/s');
  url.searchParams.set('wd', query);
  url.searchParams.set('ie', 'utf-8');
  url.searchParams.set('rn', String(Math.min(20, Math.max(10, maxResults))));
  const res = await safeFetch(url.toString(), 2 * 1024 * 1024);
  if (res.statusCode < 200 || res.statusCode >= 300) throw new Error(`百度搜索 HTTP ${res.statusCode}`);
  const results = parseBaiduHtml(res.body, maxResults);
  // 百度命中反爬/风控时会返回一个没有正文条目的壳页：当成"没搜到"而不是"搜到 0 条"，
  // 让上层能明确区分（webSearch 的 note 会提示换词或换后端）。
  if (!results.length && /百度安全验证|网络不给力/.test(String(res.body))) {
    throw new Error('百度返回了安全验证页（被风控），请稍后重试或换后端');
  }
  return results;
}

/** 360 搜索（so.com）结果页解析。
 *
 * 为什么还要这一路：百度对连续请求很敏感（连搜几次就甩「百度安全验证」页），而必应在这台
 * 机器上对**多词中文**查询会被截成第一个词（"卡通形象 表情包" 只回字典页）。360 实测两种
 * 毛病都没有，结果也和查询词对得上，所以当成百度的下一顺位。
 *
 * 结构（2026-10 实测）：条目以 `class="res-list` 开头，标题在块内第一个 `<h3>`，
 * 真实落地页在 `data-mdurl="..."`（块内 href 常是 360 自己的包装页）。
 */
export function parseSo360Html(html, maxResults = 8) {
  const text = String(html ?? '');
  const results = [];
  const seen = new Set();
  for (const block of text.split('class="res-list').slice(1)) {
    const url = normalizeSearchUrl(decodeEntities((block.match(/data-mdurl="([^"]+)"/i) || [])[1] || ''));
    if (!url || seen.has(url)) continue;
    // 360 自家的图片/视频竖版卡片（image.so.com、so.com/i?）对"这是什么"没有解释力。
    if (/^https?:\/\/(?:image|pic|video|img)\d*\.(?:so|360)\.com\//i.test(url)) continue;
    if (/^https?:\/\/www\.so\.com\/i\?/i.test(url)) continue;
    const titleHtml = (block.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i) || [])[1] || '';
    const title = decodeEntities(titleHtml).slice(0, 200);
    if (!title) continue;
    const afterTitle = block.slice(Math.max(0, block.indexOf(titleHtml) + titleHtml.length))
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<!--[\s\S]*?-->/g, ' ');
    const snippet = decodeEntities(afterTitle)
      // 块边界可能把标签切一半：先剁掉尾部未闭合的标签，再把残留的 `<` 变成空格，
      // 而不是像 split('<') 那样把后面整段正文一起丢掉。
      .replace(/<[^>]*$/g, '')
      .replace(/</g, ' ')
      // 360 会在摘要尾巴上挂自家站名和"反馈/其他"这类按钮文字。
      .replace(/^[\s\-–—|·:,，。]+/, '')
      .replace(/\s*(?:反馈|其他)\s*$/g, '')
      .trim()
      .slice(0, 400);
    seen.add(url);
    results.push({ title, url, ...(snippet ? { snippet } : {}) });
    if (results.length >= maxResults) break;
  }
  return results;
}

/** 360 搜索（HTML 抓取；百度被风控时的下一顺位）。 */
export async function so360Search(query, config = defaultConfig) {
  const maxResults = config.maxResults || defaultConfig.maxResults;
  await politeFetchGate('so360');
  const url = new URL('https://www.so.com/s');
  url.searchParams.set('q', query);
  url.searchParams.set('ie', 'utf-8');
  const res = await safeFetch(url.toString(), 2 * 1024 * 1024);
  if (res.statusCode < 200 || res.statusCode >= 300) throw new Error(`360 搜索 HTTP ${res.statusCode}`);
  const results = parseSo360Html(res.body, maxResults);
  if (!results.length && /验证|captcha|人机/.test(String(res.body).slice(0, 4000))) {
    throw new Error('360 返回了验证页，请稍后重试或换后端');
  }
  return results;
}

/** Bing 的 RSS 结果（比 HTML 页面稳定：没有 JS、结构固定）。 */
export function parseBingRss(xml, maxResults = 8) {
  const results = [];
  const seen = new Set();
  for (const match of String(xml ?? '').matchAll(/<item>([\s\S]*?)<\/item>/gi)) {
    const block = match[1];
    const url = normalizeSearchUrl(pickTag(block, 'link'));
    if (!url || seen.has(url)) continue;
    const title = pickTag(block, 'title').slice(0, 200);
    const snippet = pickTag(block, 'description').slice(0, 500);
    seen.add(url);
    results.push({ title: title || url, url, ...(snippet ? { snippet } : {}) });
    if (results.length >= maxResults) break;
  }
  return results;
}

/** Bing 的 HTML 结果页（RSS 不可用时的兜底，保持旧实现的解析口径）。 */
export function parseBingHtml(html, maxResults = 8) {
  const results = [];
  const seen = new Set();
  const blocks = String(html ?? '').split('<li class="b_algo"').slice(1);
  for (const block of blocks) {
    const hrefMatch = block.match(/<a[^>]+href="(https?:\/\/[^"]+)"/i);
    if (!hrefMatch) continue;
    const url = normalizeSearchUrl(decodeEntities(hrefMatch[1]));
    if (!url || seen.has(url)) continue;
    const titleMatch = block.match(/<h2[^>]*>([\s\S]*?)<\/h2>/i);
    const title = titleMatch ? decodeEntities(titleMatch[1]).slice(0, 200) : '';
    const snippetMatch = block.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
    const snippet = snippetMatch ? decodeEntities(snippetMatch[1]).slice(0, 500) : '';
    seen.add(url);
    results.push({ title: title || url, url, ...(snippet ? { snippet } : {}) });
    if (results.length >= maxResults) break;
  }
  return results;
}

/** Bing 搜索（RSS 优先，HTML 兜底）。 */
export async function bingSearch(query, config = defaultConfig) {
  const maxResults = config.maxResults || defaultConfig.maxResults;
  await politeFetchGate('bing');
  const rss = new URL('https://cn.bing.com/search');
  rss.searchParams.set('q', query);
  rss.searchParams.set('format', 'rss');
  rss.searchParams.set('count', String(Math.min(20, maxResults)));
  rss.searchParams.set('setlang', 'zh-hans');
  rss.searchParams.set('cc', 'CN');
  try {
    const res = await safeFetch(rss.toString(), 512000);
    if (res.statusCode >= 200 && res.statusCode < 300) {
      const results = parseBingRss(res.body, maxResults);
      if (results.length) return results;
    }
  } catch {}
  const html = new URL('https://cn.bing.com/search');
  html.searchParams.set('q', query);
  html.searchParams.set('count', String(Math.min(20, maxResults)));
  html.searchParams.set('setlang', 'zh-hans');
  html.searchParams.set('cc', 'CN');
  const res = await safeFetch(html.toString(), 512000);
  if (res.statusCode < 200 || res.statusCode >= 300) throw new Error(`Bing 搜索 HTTP ${res.statusCode}`);
  return parseBingHtml(res.body, maxResults);
}

const cache = new Map(); // `${provider}|${query}` -> { at, value }

export function clearSearchCache() {
  cache.clear();
}

/**
 * 统一入口：按配置选择 provider；`auto` 先试 DeepSeek（与 DSH 同源），失败回退 Bing。
 * @returns {{query:string, provider:'deepseek'|'baidu'|'so360'|'bing', results:object[], fallbackFrom?:string, note?:string}}
 */
export async function webSearch(query, options = {}) {
  const q = String(query ?? '').trim();
  if (!q) throw new Error('查询词为空');
  const config = { ...loadSearchConfig(options.root ?? process.cwd()), ...(options.config ?? {}) };
  const wanted = options.provider ?? config.provider;
  const cacheKey = `${wanted}|${q}|${config.maxResults}`;
  const cached = cache.get(cacheKey);
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.value;

  const attemptDeepSeek = async () => {
    const results = await deepseekSearch(q, config);
    return { query: q, provider: 'deepseek', results };
  };
  const attemptBing = async () => {
    try {
      const results = await bingSearch(q, config);
      return { query: q, provider: 'bing', results };
    } catch (error) {
      noteProviderOutcome('bing', error);
      throw error;
    }
  };
  const attemptBaidu = async () => {
    try {
      const results = await baiduSearch(q, config);
      return { query: q, provider: 'baidu', results };
    } catch (error) {
      noteProviderOutcome('baidu', error);
      throw error;
    }
  };
  const attemptSo360 = async () => {
    try {
      const results = await so360Search(q, config);
      return { query: q, provider: 'so360', results };
    } catch (error) {
      noteProviderOutcome('so360', error);
      throw error;
    }
  };

  let value;
  if (wanted === 'deepseek') {
    value = await attemptDeepSeek();
  } else if (wanted === 'bing') {
    value = await attemptBing();
  } else if (wanted === 'baidu') {
    value = await attemptBaidu();
  } else if (wanted === 'so360') {
    value = await attemptSo360();
  } else {
    // auto：DeepSeek（与 DSH 同源）→ 百度（解释性结果最全）→ 360（百度被风控时的下一顺位）
    // → 必应（最后兜底；注意它对多词中文查询会退化成只匹配第一个词）。
    const chain = [
      { label: 'DeepSeek', run: attemptDeepSeek },
      { label: '百度', run: attemptBaidu },
      { label: '360', run: attemptSo360 },
      { label: '必应', run: attemptBing }
    ];
    const reasons = [];
    for (const [index, step] of chain.entries()) {
      try {
        const out = await step.run();
        const empty = !(Array.isArray(out?.results) && out.results.length);
        // 最后一个后端就算空也直接返回（带上空结果说明），不再往下兜。
        if (empty && index < chain.length - 1) {
          reasons.push(`${step.label}没有结果`);
          continue;
        }
        value = index === 0 ? out : { ...out, fallbackFrom: 'deepseek', note: `${reasons.join('；')}，已回退${step.label}` };
        break;
      } catch (error) {
        const why = error?.code === 'NO_KEY' ? '未配置搜索凭据' : (error?.message ?? error);
        reasons.push(`${step.label}不可用：${why}`);
      }
    }
    // 每一路的原因都要带出来：只报最后一句的话，排查时最需要的信息（前面为什么不行为）就丢了。
    if (!value) throw new Error(reasons.join('；'));
  }
  // 空结果必须显式说明：以前直接返回 `results: []`，模型分不清「真没搜到」和
  // 「搜索接口静默失效」，会一直换关键词重试（issue #17）。现在给出可操作的下一步。
  // ⚠️ 这段必须在 `cache.set` **之前**：note 走的是「新建对象」而不是原地改，
  // 而缓存里存的是**引用**。反过来写（先缓存、后加 note）时，5 分钟内的重复查询会命中
  // 那个没有 note 的旧对象 —— 恰好是模型最容易开始重试的场景（同一句 query 连着问）。
  if (Array.isArray(value.results) && value.results.length === 0) {
    value = { ...value, note: [value.note, '没有搜到结果（可换个说法/加限定词；仍为空就不要再重复搜索）'].filter(Boolean).join('；') };
  }
  cache.set(cacheKey, { at: Date.now(), value });
  if (cache.size > CACHE_MAX_ENTRIES) {
    for (const key of [...cache.keys()].slice(0, cache.size - CACHE_MAX_ENTRIES)) cache.delete(key);
  }
  return value;
}
