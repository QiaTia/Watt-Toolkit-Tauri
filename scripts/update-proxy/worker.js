/**
 * Watt Toolkit 更新源镜像 Worker（规划书「方案 B：无服务重写」）
 *
 * 背景：latest.json 里的 platforms.*.url 是绝对地址，通用 GitHub 加速前缀只能代理
 * 这份 JSON，不会改写 JSON 内部的 URL，客户端下载安装包时仍会直连 github.com。
 * 本 Worker 取回上游 latest.json，把每个 url 的 `https://github.com/` 前缀换成
 * 加速前缀后原样返回；signature 字段绝不改动（minisign 只签安装包内容）。
 *
 * 部署：wrangler deploy（见同目录 wrangler.toml）
 * 客户端：设置 → 软件更新 → 更新源填 https://<worker 域名>/latest.json
 */

const DEFAULT_REPO = 'QiaTia/Watt-Toolkit-Tauri';
const DEFAULT_MIRROR_PREFIX = 'https://ghfast.top/';
const GITHUB_PREFIX = 'https://github.com/';

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      // 上游 Release 内容不会秒级变化，短缓存足以挡掉重复探测
      'cache-control': 'public, max-age=300',
      'access-control-allow-origin': '*',
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== '/latest.json' && url.pathname !== '/') {
      return json({ error: 'not found' }, 404);
    }

    const repo = env.REPO || DEFAULT_REPO;
    const mirror = env.MIRROR_PREFIX || DEFAULT_MIRROR_PREFIX;
    const upstream = `https://github.com/${repo}/releases/latest/download/latest.json`;

    let upstreamRes;
    try {
      upstreamRes = await fetch(upstream, {
        // 跟随 GitHub 的 302 到对象存储
        redirect: 'follow',
        headers: { accept: 'application/json' },
        cf: { cacheTtl: 300 },
      });
    } catch (e) {
      return json({ error: `upstream fetch failed: ${e}` }, 502);
    }

    if (!upstreamRes.ok) {
      // 仓库还没有正式 Release 时上游是 404：原样透出，客户端按「检查失败」处理
      return json({ error: `upstream status ${upstreamRes.status}` }, 502);
    }

    let manifest;
    try {
      manifest = await upstreamRes.json();
    } catch (e) {
      return json({ error: `invalid upstream json: ${e}` }, 502);
    }

    const platforms = manifest.platforms || {};
    for (const entry of Object.values(platforms)) {
      if (entry && typeof entry.url === 'string' && entry.url.startsWith(GITHUB_PREFIX)) {
        entry.url = mirror + entry.url;
      }
    }

    return json(manifest);
  },
};
