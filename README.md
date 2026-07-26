# @vafast/helmet

Vafast 安全响应头中间件：为响应附加 CSP、HSTS、X-Frame-Options、Permissions-Policy 等，不改业务逻辑。

## 安装

```bash
npm install @vafast/helmet
```

## 快速开始

```typescript
import { Server, defineRoute, defineRoutes, json, serve } from 'vafast'
import { vafastHelmet } from '@vafast/helmet'

const routes = defineRoutes([
  defineRoute({
    method: 'GET',
    path: '/',
    handler: () => json({ ok: true }),
  }),
])

const server = new Server(routes)
server.use(vafastHelmet())
serve({ fetch: server.fetch, port: 3000 })
```

`elysiaHelmet` 是 `vafastHelmet` 的兼容别名。另会始终设置 `X-Content-Type-Options: nosniff`。

**HSTS 仅在 `NODE_ENV === 'production'` 时写入**，避免本地 HTTP 被强制 HTTPS。

## 选项

### `SecurityConfig`

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `csp` | `CSPConfig` | 见下表 | Content-Security-Policy |
| `frameOptions` | `'DENY' \| 'SAMEORIGIN' \| 'ALLOW-FROM'` | `'DENY'` | `X-Frame-Options`（`ALLOW-FROM` 已过时） |
| `xssProtection` | `boolean` | `true` | 写 `X-XSS-Protection: 1; mode=block` |
| `dnsPrefetch` | `boolean` | `false` | `X-DNS-Prefetch-Control`：`on` / `off` |
| `referrerPolicy` | 标准枚举字符串 | `'strict-origin-when-cross-origin'` | `Referrer-Policy` |
| `permissionsPolicy` | `Record<string, string[]>` | 禁用 camera / microphone / geolocation / interest-cohort（空数组 = 禁用） | `Permissions-Policy` |
| `hsts` | `HSTSConfig` | `{ maxAge: 15552000, includeSubDomains: true, preload: true }` | **仅生产环境**写 `Strict-Transport-Security` |
| `corp` | `'same-origin' \| 'same-site' \| 'cross-origin'` | `'same-origin'` | `Cross-Origin-Resource-Policy` |
| `coop` | `'unsafe-none' \| 'same-origin-allow-popups' \| 'same-origin'` | `'same-origin'` | `Cross-Origin-Opener-Policy` |
| `reportTo` | `ReportToConfig[]` | — | `Report-To` |
| `customHeaders` | `Record<string, string>` | — | 额外自定义头 |

### 默认 CSP / `CSPConfig`

| 字段 | 默认 | 白话 |
|------|------|------|
| `defaultSrc` | `['self']` | 未单独声明的资源类型的兜底来源 |
| `scriptSrc` | `['self', 'unsafe-inline']` | 允许的脚本来源 |
| `styleSrc` | `['self', 'unsafe-inline']` | 允许的样式来源 |
| `imgSrc` | `['self', 'data:', 'blob:']` | 允许的图片来源 |
| `fontSrc` | `['self']` | 允许的字体来源 |
| `connectSrc` | `['self']` | `fetch` / XHR / WebSocket 等 |
| `frameSrc` | `['self']` | 允许嵌入的 frame 源 |
| `objectSrc` | `['none']` | `<object>` / `<embed>` |
| `baseUri` | `['self']` | 限制 `<base href>` |
| `reportUri` | — | CSP `report-uri` |
| `useNonce` | — | 为 script/style 注入 nonce，并写 `X-Nonce` |
| `reportOnly` | — | 使用 `Content-Security-Policy-Report-Only` |

### `HSTSConfig`

| 字段 | 默认 | 说明 |
|------|------|------|
| `maxAge` | `15552000` | 秒；`< 0` 初始化抛错 |
| `includeSubDomains` | `true` | 附加 `; includeSubDomains` |
| `preload` | `true` | 附加 `; preload` |

### `ReportToConfig`

| 字段 | 说明 |
|------|------|
| `group` | 端点组名 |
| `maxAge` | 缓存秒数（`< 0` 抛错） |
| `endpoints` | `{ url, priority?, weight? }[]`，至少一个 |
| `includeSubdomains` | 可选，是否含子域 |

### `permission` 常量

| 常量 | 值 |
|------|-----|
| `SELF` | `'self'` |
| `UNSAFE_INLINE` | `'unsafe-inline'` |
| `HTTPS` | `https:` |
| `DATA` | `data:` |
| `NONE` | `'none'` |
| `BLOB` | `blob:` |

```typescript
import { vafastHelmet, permission } from '@vafast/helmet'

server.use(
  vafastHelmet({
    csp: {
      scriptSrc: [permission.SELF],
      imgSrc: [permission.SELF, permission.DATA, 'https:'],
    },
  }),
)
```

## 文档

完整概念说明（CSP / HSTS / Nonce 白话）与注意事项见站点文档：[Helmet 中间件](https://vafast.huyooo.com/middleware/helmet.html)（仓库内 `vafast-doc/docs/middleware/helmet.md`）。
