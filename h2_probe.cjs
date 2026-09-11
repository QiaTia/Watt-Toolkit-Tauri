// 临时诊断脚本：经正向代理 CONNECT 隧道，用 HTTP/2 访问目标（模拟浏览器 ALPN 协商）
// 用法: node h2_probe.js [host] [alpn]
const net = require('net');
const tls = require('tls');
const http2 = require('http2');

const PROXY_PORT = 26501;
const HOST = process.argv[2] || 'github.com';
const ALPN = (process.argv[3] || 'h2,http/1.1').split(',');

const sock = net.connect(PROXY_PORT, '127.0.0.1', () => {
  sock.write(`CONNECT ${HOST}:443 HTTP/1.1\r\nHost: ${HOST}:443\r\n\r\n`);
});

let buf = Buffer.alloc(0);
function onData(d) {
  buf = Buffer.concat([buf, d]);
  const idx = buf.indexOf('\r\n\r\n');
  if (idx === -1) return;
  sock.removeListener('data', onData);
  const head = buf.slice(0, idx).toString();
  console.log('[proxy]', head.split('\r\n')[0]);
  const rest = buf.slice(idx + 4);
  if (rest.length) sock.unshift(rest);

  const tlsSock = tls.connect(
    { socket: sock, servername: HOST, ALPNProtocols: ALPN, rejectUnauthorized: false },
    () => {
      const alpn = tlsSock.alpnProtocol;
      console.log('[tls] negotiated ALPN =', alpn || '(none)');

      if (alpn === 'h2') {
        const client = http2.connect(`https://${HOST}`, { createConnection: () => tlsSock });
        const req = client.request({ ':method': 'GET', ':path': '/' });
        let status = null, len = 0;
        req.on('response', (h) => { status = h[':status']; });
        req.on('data', (c) => { len += c.length; });
        req.on('end', () => {
          console.log(`[h2] :status = ${status}   body = ${len} bytes`);
          client.close();
        });
        req.on('error', (e) => console.log('[h2] err', e.message));
        req.end();
      } else {
        tlsSock.write(`GET / HTTP/1.1\r\nHost: ${HOST}\r\nConnection: close\r\n\r\n`);
        let all = '';
        tlsSock.on('data', (c) => { all += c.toString('latin1'); });
        tlsSock.on('end', () => {
          const first = all.split('\r\n')[0];
          console.log(`[h1] ${first}   body = ${all.length} bytes`);
        });
      }
    }
  );
  tlsSock.on('error', (e) => console.log('[tls] err', e.message));
}
sock.on('data', onData);
sock.on('error', (e) => console.log('[sock] err', e.message));
sock.setTimeout(25000, () => { console.log('[timeout]'); process.exit(1); });
