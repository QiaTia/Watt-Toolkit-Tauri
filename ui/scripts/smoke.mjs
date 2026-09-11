/**
 * UI 冒烟测试：通过 CDP 驱动系统 Edge（headless）加载各路由，
 * 收集控制台错误/页面异常，并输出截图。不依赖 Tauri IPC（浏览器环境下 IPC 调用
 * 会失败，属预期；只验证模板/组件渲染无崩溃）。
 *
 * 用法：node scripts/smoke.mjs <route...>
 */
import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';

const EDGE = 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const PORT = 9223;
const OUT_DIR = 'C:/Users/Tia/AppData/Local/Temp/ui-smoke';
const BASE = process.env.SMOKE_BASE ?? 'http://127.0.0.1:5173';

const routes = process.argv.slice(2).length
  ? process.argv.slice(2)
  : ['/', '/accelerator', '/settings', '/about'];

mkdirSync(OUT_DIR, { recursive: true });

const proc = spawn(EDGE, [
  '--headless=new',
  '--disable-gpu',
  '--no-first-run',
  '--no-default-browser-check',
  `--remote-debugging-port=${PORT}`,
  '--user-data-dir=C:/Users/Tia/AppData/Local/Temp/ui-smoke-prof',
  'about:blank',
], { stdio: 'ignore' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function cdp(wsUrl, msgId, method, params = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    const timer = setTimeout(() => { ws.close(); reject(new Error('cdp timeout: ' + method)); }, 20000);
    ws.onopen = () => ws.send(JSON.stringify({ id: msgId, method, params }));
    ws.onmessage = (ev) => {
      const data = JSON.parse(ev.data);
      if (data.id === msgId) {
        clearTimeout(timer);
        ws.close();
        if (data.error) reject(new Error(method + ': ' + JSON.stringify(data.error)));
        else resolve(data.result);
      }
    };
    ws.onerror = () => { clearTimeout(timer); reject(new Error('ws error')); };
  });
}

async function main() {
  // 等待调试端口就绪
  let version = null;
  for (let i = 0; i < 30; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/json/version`);
      version = await res.json();
      break;
    } catch { await sleep(500); }
  }
  if (!version) throw new Error('CDP 端口未就绪');
  console.log('Browser:', version.Browser);

  for (const route of routes) {
    const name = route === '/' ? 'home' : route.replaceAll('/', '_').replace(/^_/, '');
    const res = await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent(BASE + route)}`, { method: 'PUT' });
    const target = await res.json();
    const wsUrl = target.webSocketDebuggerUrl;

    const errors = [];
    let msgId = 0;
    const listener = (ev) => {
      const d = JSON.parse(ev.data);
      if (d.method === 'Runtime.exceptionThrown') {
        errors.push(d.params.exceptionDetails?.exception?.description ?? JSON.stringify(d.params).slice(0, 300));
      }
      if (d.method === 'Runtime.consoleAPICalled' && d.params.type === 'error') {
        errors.push(d.params.args?.map((a) => a.value ?? a.description ?? '').join(' ').slice(0, 300));
      }
    };

    const ws = new WebSocket(wsUrl);
    await new Promise((res2, rej2) => { ws.onopen = res2; ws.onerror = rej2; });
    ws.onmessage = listener;
    ws.send(JSON.stringify({ id: ++msgId, method: 'Runtime.enable' }));
    ws.send(JSON.stringify({ id: ++msgId, method: 'Page.enable' }));
    ws.send(JSON.stringify({ id: ++msgId, method: 'Emulation.setDeviceMetricsOverride', params: { width: 1280, height: 860, deviceScaleFactor: 1, mobile: false } }));
    ws.send(JSON.stringify({ id: ++msgId, method: 'Page.navigate', params: { url: BASE + route } }));

    await sleep(3500);

    // 页面内容探测
    const evalRes = await new Promise((resolve, reject) => {
      const id = ++msgId;
      ws.onmessage = (ev) => {
        const d = JSON.parse(ev.data);
        if (d.id === id) resolve(d.result?.result?.value ?? '');
        if (d.method === 'Runtime.exceptionThrown') errors.push(d.params.exceptionDetails?.exception?.description ?? 'exception');
        if (d.method === 'Runtime.consoleAPICalled' && d.params.type === 'error') {
          errors.push(d.params.args?.map((a) => a.value ?? a.description ?? '').join(' ').slice(0, 300));
        }
      };
      ws.send(JSON.stringify({ id, method: 'Runtime.evaluate', params: { expression: 'document.querySelector("#app")?.innerText.slice(0, 400) ?? "EMPTY"' } }));
      setTimeout(() => reject(new Error('evaluate timeout')), 8000);
    });

    const shotId = ++msgId;
    const shot = await new Promise((resolve) => {
      ws.onmessage = (ev) => {
        const d = JSON.parse(ev.data);
        if (d.id === shotId) resolve(d.result?.data ?? null);
      };
      ws.send(JSON.stringify({ id: shotId, method: 'Page.captureScreenshot', params: { format: 'png' } }));
      setTimeout(() => resolve(null), 8000);
    });

    ws.close();
    if (shot) writeFileSync(`${OUT_DIR}/${name}.png`, Buffer.from(shot, 'base64'));

    console.log(`\n=== ${route} ===`);
    console.log('innerText:', evalRes.replaceAll('\n', ' | ').slice(0, 300));
    const real = errors.filter((e) => e && !e.includes('__TAURI_INTERNALS__') && !e.includes('IPC'));
    console.log('errors(非 IPC):', real.length ? real.slice(0, 5) : '无');
    if (shot) console.log('screenshot:', `${OUT_DIR}/${name}.png`);
  }

  proc.kill();
  process.exit(0);
}

main().catch((e) => {
  console.error('SMOKE FAILED:', e.message);
  proc.kill();
  process.exit(1);
});
