# dsh-mcp-safe-tools

> **一句话**：给 agent 联网和发消息的"手"装上护栏 —— 只读搜索/抓取、内网地址一律拦在 DNS 之后、出站前脱敏、媒体只从白名单目录发。
>
> 从 `qq-bridge` 抽出的独立项目，对应成本统计里 **「能力扩展（视觉 / 搜索 / 语感）」** 这条线。

---

## 里面有什么

三个 stdio MCP server + 四组可单独引用的工具模块：

| 入口 | 暴露的工具 | 干什么 |
|---|---|---|
| `src/mcp-web-search-safe.js` | `web_search`、`web_fetch` | 只读联网：搜索优先走与 DSH 同一条 DeepSeek 联网搜索，失败回退百度 → 360 → Bing；抓取只允许 http/https |
| `src/mcp-host-server.js` | `snowluma_status` | 只读探活：网关在不在线、登录的是哪个号。**故意没有启停进程的能力** |
| `src/mcp-snowluma-safe.js` | QQ 相关工具（按工具组开关） | 消息/表情/语音/空间等，默认只挂 core + memory 两组 |
| `src/safe-fetch.js` | — | SSRF 防护核心：DNS 全解析检查、逐跳重定向校验、限量读取 |
| `src/web-search.js` | — | 四个后端 + 缓存 + 请求间隔，纯函数解析可直接测 |
| `src/tool-groups.js` | — | 工具分组与开关状态（省 context 的手段） |
| `src/md-to-plain.js` / `sensitive.js` / `media-out.js` | — | Markdown 降级、出站脱敏正则、媒体白名单 |

## 安装

```bash
git clone https://github.com/whatxin7/dsh-mcp-safe-tools.git
cd dsh-mcp-safe-tools
npm install
npm test                  # 9 个用例，含两个真实 stdio MCP 握手
cp config.example.json config.json   # 按需改 snowluma / webSearch
```

### 装法与别的仓库不同

它不是「装完就有命令」的 CLI，而是被 MCP 客户端（DSH / Claude Desktop / Cursor / Cline）**当子进程启动**的 server：

```bash
# 只想验证它能起来（stdio 握手成功后 Ctrl+C 退出即可）
npx github:whatxin7/dsh-mcp-safe-tools
```

配置里必须写**本机绝对路径**（`command: node`，`args: ["/绝对路径/src/mcp-web-search-safe.js"]`），因为客户端不会去猜你在哪个目录 clone 的。

Node ≥ 20。测试里的 MCP 用例会真的 `spawn` 两个 server，走 `initialize` → `tools/list`，断言工具清单 —— 不是"看代码猜它能跑"。

## 接到 DSH / 任意 MCP 客户端

```json
{
  "mcpServers": {
    "web-search-safe": {
      "command": "node",
      "args": ["D:/Work/dsh-mcp-safe-tools/src/mcp-web-search-safe.js"]
    },
    "snowluma-host": {
      "command": "node",
      "args": ["D:/Work/dsh-mcp-safe-tools/src/mcp-host-server.js"]
    }
  }
}
```

`config.json` 放在仓库根目录（和 `src/` 同级），server 启动时读它；读不到就用默认值起步。

## SSRF 防护都防了什么

`web_fetch` 是整条链路上最像"后门"的东西：模型能构造任意 URL。所以校验必须发生在**连接之前**，而且必须校验**DNS 解析结果**，不是字符串。

```
输入 URL
  ├─ 协议不是 http/https → 拒绝
  ├─ URL 里带 username/password → 拒绝（防 http://user:pass@内网/）
  ├─ DNS 解析全部 A/AAAA 记录
  │    └─ 任一条是内网/环回/链路本地/CGNAT/保留段 → 拒绝（防 DNS rebinding）
  ├─ 选一个地址建连（保留原 Host/SNI，禁止重新解析）
  ├─ 30x 重定向 → 手动跟随，每一跳重新走上面全套校验
  └─ 响应体按字节流限量读取（防超大响应拖死进程）
```

`isPrivateIp()` 覆盖：`10/8`、`172.16/12`、`192.168/16`、`127/8`、`0/8`、`169.254/16`、`100.64/10`、`198.18/15`、`192.0.0/24`、`224+`，以及 IPv6 的 `::1`、`fc00::/7`、`fe80::/10`、`ff00::/8`、`2001:db8::/32`、`::ffff:` 映射、NAT64 `64:ff9b::/96`。

调用方补的请求头只能追加非 `Host` / `Content-Length` 字段 —— 否则"带 Referer 抓图"就成了改 Host 的 SSRF 跳板。

## 工具分组（省 context）

工具全挂着最省事，代价是每轮都付 schema 的 token。所以按组挂：

```
core    看消息、说话、等待、睡觉、表情、发图
memory  轻量记忆
voice / sticker / people / qzone / identity / slang / douyin / media   按需打开
```

`resolveActiveGroups()` 决定这一轮挂哪几组，`auditGroups(registered)` 检查"注册了但没归组"的工具 —— 这类漏网的会在切组时神秘消失。

## 出站脱敏与媒体白名单

- `SENSITIVE_RE`：本地路径（`C:\...`、`\\host\share`、`/home/`、`/Users/`、`/etc/`…）与 `token=xxx` / `password: xxx` 形态，用于往群聊/日志输出前拦一道。
- `resolveOutMedia()`：只发白名单目录（`out/`、`assets/`、`audio/`、`exports/`、`state/media/`）里的相对路径；`..`、盘符、UNC、URL 一律报错。
- `checkOutMedia()`：可执行/脚本类扩展名不发；图片有单独的体积上限。

## 作为库用

```js
import { safeFetch } from 'dsh-mcp-safe-tools/safe-fetch';
import { mdToPlain } from 'dsh-mcp-safe-tools/md';
import { resolveActiveGroups } from 'dsh-mcp-safe-tools/tool-groups';

const { text, finalUrl } = await safeFetch('https://example.com', 50000);
```

## 已知边界

- 搜索后端依赖外部服务；DeepSeek 那条要 `webSearch` 凭据（配置或 DSH 的 `.credentials.yaml`），没有就走回退链。
- 抓取只做 GET，不提交表单、不带 cookie 会话。
- 不做 JS 渲染：SPA 页面抓到的可能只有骨架（要渲染请用浏览器自动化）。
- `mcp-snowluma-safe.js` 的能力取决于网关支持的动作；网关不在线时工具会返回可操作的提示，而不是静默失败。

## 项目家族

| 项目 | 对应成本条目 |
|---|---|
| **dsh-mcp-safe-tools**（本仓库） | 能力扩展（视觉 / 搜索 / 语感） |
| [dsh-token-meter](https://github.com/whatxin7/dsh-token-meter) | 用量与成本核算 |
| [dsh-qq-access](https://github.com/whatxin7/dsh-qq-access) | 好友 / 白名单 / 权限 |
| [dsh-qq-voice](https://github.com/whatxin7/dsh-qq-voice) | 语音 / 唱歌 / 音色 |
| [dsh-qq-stickers](https://github.com/whatxin7/dsh-qq-stickers) | 表情包 / 斗图 |
| [dsh-session-link](https://github.com/whatxin7/dsh-session-link) | 联通会话 / 行为调优 |
| [dsh-persona-kit](https://github.com/whatxin7/dsh-persona-kit) | 人格 / 角色卡 |
| [qq-bridge](https://github.com/whatxin7/qq-bridge) | 桥接内核（旗舰仓库） |

## English

Three read-only MCP servers plus reusable guards: an SSRF-hardened `web_fetch` (DNS-result validation, per-hop redirect re-validation, byte-limited reads), a multi-backend web search with parsers, gateway health probing with no process control, and outbound redaction / media allow-listing. 9 tests, including a real stdio MCP handshake.

## License

MIT © whatxin7


