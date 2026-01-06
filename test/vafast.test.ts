import { Server, createHandler, json } from 'vafast'
import { vafastHelmet } from '../src/index'
import { describe, expect, it } from 'vitest'

describe('Vafast Helmet', () => {
  it('should add security headers to responses', async () => {
    const helmet = vafastHelmet({
      csp: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
      },
      frameOptions: "DENY",
      xssProtection: true,
    })

    const app = new Server([
      {
        method: 'GET',
        path: '/',
        handler: createHandler(() => {
          return json({ message: 'Hello World with Security Headers!' })
        }),
        middleware: [helmet],
      },
    ])

    const res = await app.fetch(new Request('http://localhost/'))
    
    // 检查安全头部是否被添加
    expect(res.headers.get('X-Frame-Options')).toBe('DENY')
    expect(res.headers.get('X-XSS-Protection')).toBe('1; mode=block')
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
    expect(res.headers.get('Content-Security-Policy')).toContain("default-src 'self'")
    expect(res.headers.get('Content-Security-Policy')).toContain("script-src 'self' 'unsafe-inline'")
  })

  it('should handle custom headers', async () => {
    const helmet = vafastHelmet({
      customHeaders: {
        'X-Custom-Header': 'custom-value',
        'X-Another-Header': 'another-value',
      },
    })

    const app = new Server([
      {
        method: 'GET',
        path: '/',
        handler: createHandler(() => {
          return json({ message: 'Hello World!' })
        }),
        middleware: [helmet],
      },
    ])

    const res = await app.fetch(new Request('http://localhost/'))
    
    expect(res.headers.get('X-Custom-Header')).toBe('custom-value')
    expect(res.headers.get('X-Another-Header')).toBe('another-value')
  })

  it('should handle HSTS headers in production', async () => {
    // 模拟生产环境
    const originalEnv = process.env.NODE_ENV
    process.env.NODE_ENV = 'production'

    const helmet = vafastHelmet({
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
    })

    const app = new Server([
      {
        method: 'GET',
        path: '/',
        handler: createHandler(() => {
          return json({ message: 'Hello World!' })
        }),
        middleware: [helmet],
      },
    ])

    const res = await app.fetch(new Request('http://localhost/'))
    
    expect(res.headers.get('Strict-Transport-Security')).toBe('max-age=31536000; includeSubDomains; preload')

    // 恢复环境变量
    process.env.NODE_ENV = originalEnv
  })
})
