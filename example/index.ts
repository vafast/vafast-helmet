import { Server, createRouteHandler } from "vafast";
import type { Route } from "vafast";
import { vafastHelmet } from "../src/index";

// 创建安全头中间件
const helmet = vafastHelmet({
  csp: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
  },
  frameOptions: "DENY",
  xssProtection: true,
  referrerPolicy: "strict-origin-when-cross-origin",
});

// 定义路由
const routes: Route[] = [
  {
    method: "GET",
    path: "/",
    handler: createRouteHandler(() => {
      return { message: "Hello World with Security Headers!" }
    }),
    middleware: [helmet],
  },
  {
    method: "GET",
    path: "/api/data",
    handler: createRouteHandler(() => {
      return { data: "Protected API endpoint" }
    }),
    middleware: [helmet],
  },
];

// 创建服务器
const server = new Server(routes);

// 导出 fetch 函数
export default {
  fetch: (req: Request) => server.fetch(req),
};
