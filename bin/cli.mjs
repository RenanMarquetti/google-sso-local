#!/usr/bin/env node
// google-sso-local: answer Google ID-token verification from this machine, for one process only.
//
//   google-sso-local init                         create the local CA, TLS cert and signing key (once)
//   google-sso-local proxy [--port 8899] [--only-local]
//                                                 start the proxy (127.0.0.1 only); serves Google's real keys plus
//                                                 the local one, so real Google sign-ins keep working (--only-local: just ours)
//   google-sso-local env [--port 8899]            print the two env vars for the process that should trust it
//   google-sso-local mint --email E --aud CLIENT_ID [--name N] [--nonce X] [--sub S] [--ttl 3600] [--hd D]
//
// How it works: the backend verifies a Google ID token by downloading Google's public keys from
// www.googleapis.com. Started with HTTPS_PROXY pointing here and NODE_EXTRA_CA_CERTS trusting the local CA,
// that one process gets OUR keys for www.googleapis.com / oauth2.googleapis.com; every other host is tunnelled
// untouched. No backend code or config changes, and nothing outside that process trusts these tokens.
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';

const HOME = process.env.GOOGLE_SSO_LOCAL_HOME ?? path.join(os.homedir(), '.google-sso-local');
const INTERCEPT = new Set(['www.googleapis.com', 'oauth2.googleapis.com']);
const ISSUER = 'https://accounts.google.com';
const file = (name) => path.join(HOME, name);

const args = (argv) => {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i].startsWith('--')) {
      const next = argv[i + 1];
      const isFlag = next === undefined || next.startsWith('--');
      out[argv[i].slice(2)] = isFlag ? 'true' : next;
      i += isFlag ? 0 : 1;
    } else {
      out._.push(argv[i]);
    }
  }
  return out;
};

const openssl = (...a) => execFileSync('openssl', a, { stdio: ['ignore', 'ignore', 'pipe'] });

const init = () => {
  if (fs.existsSync(file('ca.crt'))) {
    console.log(`already initialised: ${HOME}`);
    return;
  }
  fs.mkdirSync(HOME, { recursive: true, mode: 0o700 });
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650', '-subj', '/CN=google-sso-local CA',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    '-keyout', file('ca.key'), '-out', file('ca.crt'));
  const ext = file('tls.ext');
  fs.writeFileSync(ext, `subjectAltName=${[...INTERCEPT].map((h) => `DNS:${h}`).join(',')}\nextendedKeyUsage=serverAuth\n`);
  openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=www.googleapis.com', '-keyout', file('tls.key'), '-out', file('tls.csr'));
  openssl('x509', '-req', '-in', file('tls.csr'), '-CA', file('ca.crt'), '-CAkey', file('ca.key'), '-CAcreateserial',
    '-days', '825', '-extfile', ext, '-out', file('tls.crt'));
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650', '-subj', '/CN=google-sso-local signing',
    '-keyout', file('sign.key'), '-out', file('sign.crt'));
  for (const f of fs.readdirSync(HOME)) fs.chmodSync(file(f), 0o600);
  console.log(`initialised ${HOME}\ntrust anchor for the target process: ${file('ca.crt')}`);
};

const signing = () => {
  const certPem = fs.readFileSync(file('sign.crt'), 'utf8');
  const key = crypto.createPrivateKey(fs.readFileSync(file('sign.key')));
  const kid = crypto.createHash('sha256').update(new crypto.X509Certificate(certPem).raw).digest('hex').slice(0, 40);
  return { certPem, key, kid };
};

const b64url = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

const mint = (o) => {
  if (!o.email || !o.aud) throw new Error('mint needs --email and --aud (the backend GOOGLE_CLIENT_ID)');
  const { key, kid } = signing();
  const now = Math.floor(Date.now() / 1000);
  const email = o.email.trim().toLowerCase();
  const payload = {
    iss: ISSUER,
    azp: o.aud,
    aud: o.aud,
    sub: o.sub ?? BigInt(`0x${crypto.createHash('sha256').update(email).digest('hex').slice(0, 15)}`).toString(),
    email,
    email_verified: true,
    name: o.name ?? email.split('@')[0],
    ...(o.nonce ? { nonce: o.nonce } : {}),
    ...(o.hd ? { hd: o.hd } : {}),
    iat: now,
    exp: now + Number(o.ttl ?? 3600),
    jti: crypto.randomUUID(),
    local_sso: true,
  };
  const head = `${b64url({ alg: 'RS256', kid, typ: 'JWT' })}.${b64url(payload)}`;
  return `${head}.${crypto.sign('RSA-SHA256', Buffer.from(head), key).toString('base64url')}`;
};

const verifyOwn = (token) => {
  const { certPem } = signing();
  const [h, p, s] = token.split('.');
  const ok = crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`), certPem, Buffer.from(s, 'base64url'));
  return ok ? JSON.parse(Buffer.from(p, 'base64url')) : null;
};

const UPSTREAM_TTL_MS = 5 * 60 * 1000;
const upstreamCache = new Map();

const getUpstream = (pathAndQuery) =>
  new Promise((resolve) => {
    const req = https.get({ host: 'www.googleapis.com', path: pathAndQuery, timeout: 5000 }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, json: JSON.parse(body) });
        } catch {
          resolve(null);
        }
      });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
  });

const upstreamCerts = async (pathname) => {
  const hit = upstreamCache.get(pathname);
  if (hit && Date.now() - hit.at < UPSTREAM_TTL_MS) return hit.json;
  const res = await getUpstream(pathname);
  if (res?.status !== 200) {
    console.error(`[google-sso-local] could not fetch Google's ${pathname}; serving only the local key`);
    return hit?.json ?? null;
  }
  upstreamCache.set(pathname, { at: Date.now(), json: res.json });
  return res.json;
};

let onlyLocal = false;

const googleApi = async (req, res) => {
  const { certPem, kid } = signing();
  const url = new URL(req.url, `https://${req.headers.host}`);
  const send = (code, body) => {
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'public, max-age=300' });
    res.end(JSON.stringify(body));
  };
  console.error(`[google-sso-local] ${req.method} https://${req.headers.host}${url.pathname}`);
  if (url.pathname === '/oauth2/v1/certs') {
    const upstream = onlyLocal ? null : await upstreamCerts(url.pathname);
    return send(200, { ...(upstream ?? {}), [kid]: certPem });
  }
  if (url.pathname === '/oauth2/v3/certs') {
    const jwk = new crypto.X509Certificate(certPem).publicKey.export({ format: 'jwk' });
    const upstream = onlyLocal ? null : await upstreamCerts(url.pathname);
    return send(200, { keys: [...(upstream?.keys ?? []), { ...jwk, kid, alg: 'RS256', use: 'sig' }] });
  }
  if (url.pathname === '/oauth2/v3/tokeninfo' || url.pathname === '/tokeninfo') {
    const claims = verifyOwn(url.searchParams.get('id_token') ?? '');
    if (claims) return send(200, { ...claims, alg: 'RS256', kid });
    if (onlyLocal) return send(400, { error: 'invalid_token' });
    const upstream = await getUpstream(`/oauth2/v3/tokeninfo${url.search}`);
    return send(upstream?.status ?? 502, upstream?.json ?? { error: 'upstream_unavailable' });
  }
  return send(404, { error: 'not served by google-sso-local', path: url.pathname });
};

const proxy = (o) => {
  const port = Number(o.port ?? 8899);
  onlyLocal = o['only-local'] === 'true';
  const tlsOpts = { key: fs.readFileSync(file('tls.key')), cert: fs.readFileSync(file('tls.crt')) };
  const inner = http.createServer(googleApi);
  const server = http.createServer((_req, res) => {
    res.writeHead(405, { 'content-type': 'text/plain' });
    res.end('google-sso-local only handles CONNECT (HTTPS) requests\n');
  });
  server.on('connect', (req, client, head) => {
    const [host, p] = req.url.split(':');
    if (INTERCEPT.has(host)) {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head?.length) client.unshift(head);
      const secure = new tls.TLSSocket(client, { isServer: true, ...tlsOpts });
      secure.on('error', () => client.destroy());
      inner.emit('connection', secure);
      return;
    }
    const upstream = net.connect(Number(p || 443), host, () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head?.length) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on('error', () => client.destroy());
    client.on('error', () => upstream.destroy());
  });
  server.listen(port, '127.0.0.1', () =>
    console.error(`[google-sso-local] proxy on http://127.0.0.1:${port} (intercepts ${[...INTERCEPT].join(', ')}; ${onlyLocal ? 'local key only' : "Google's keys + local key"})`),
  );
  return server;
};

const env = (o) => {
  const port = Number(o.port ?? 8899);
  console.log(`HTTPS_PROXY=http://127.0.0.1:${port} NODE_EXTRA_CA_CERTS=${file('ca.crt')}`);
};

const main = () => {
  const o = args(process.argv.slice(2));
  const cmd = o._[0];
  if (cmd === 'init') return init();
  if (cmd === 'proxy') return proxy(o);
  if (cmd === 'env') return env(o);
  if (cmd === 'mint') return console.log(mint(o));
  console.log(fs.readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 9).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'));
};

export { mint, proxy, init };

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('/cli.mjs')) main();
