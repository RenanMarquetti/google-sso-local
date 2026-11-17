// End-to-end check with the real google-auth-library (OAuth2Client.verifyIdToken), in child processes:
//  1. with HTTPS_PROXY + NODE_EXTRA_CA_CERTS -> the locally minted token is accepted (email, nonce, audience)
//  2. a tampered token is rejected even with the proxy
//  3. without the env vars (real Google) the same token is rejected
//  4. the proxy serves Google's real keys too (real Google sign-ins keep working), plus the local one
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, 'bin/cli.mjs');
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'google-sso-local-'));
const port = String(18000 + Math.floor(Math.random() * 1000));
const aud = '1234567890-test.apps.googleusercontent.com';
const baseEnv = { ...process.env, GOOGLE_SSO_LOCAL_HOME: home };
delete baseEnv.HTTPS_PROXY; delete baseEnv.https_proxy; delete baseEnv.NO_PROXY; delete baseEnv.no_proxy;

execFileSync(process.execPath, [cli, 'init'], { env: baseEnv, stdio: 'ignore' });
const proxy = spawn(process.execPath, [cli, 'proxy', '--port', port], { env: baseEnv, stdio: ['ignore', 'ignore', 'pipe'] });
let proxyLog = '';
proxy.stderr.on('data', (d) => { proxyLog += d; });
await new Promise((r) => setTimeout(r, 500));

const token = execFileSync(process.execPath, [cli, 'mint', '--email', 'Bot@Example.test', '--aud', aud, '--nonce', 'n-123', '--name', 'Test Bot'], { env: baseEnv }).toString().trim();
const verifier = `
import { OAuth2Client } from 'google-auth-library';
const t = await new OAuth2Client('${aud}').verifyIdToken({ idToken: process.argv[1], audience: '${aud}' });
const p = t.getPayload();
console.log(JSON.stringify({ email: p.email, nonce: p.nonce, verified: p.email_verified, iss: p.iss }));`;
const verify = (idToken, env) => {
  try {
    return { ok: true, out: JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', verifier, idToken], { env, cwd: root, stdio: ['ignore', 'pipe', 'pipe'], timeout: 20000 }).toString()) };
  } catch (e) {
    return { ok: false, err: (e.stderr?.toString() || e.message).split('\n').find((l) => /Error|error/.test(l)) };
  }
};
const viaProxy = { ...baseEnv, HTTPS_PROXY: `http://127.0.0.1:${port}`, NODE_EXTRA_CA_CERTS: path.join(home, 'ca.crt') };
const fails = [];
const a = verify(token, viaProxy);
if (!a.ok || a.out.email !== 'bot@example.test' || a.out.nonce !== 'n-123' || a.out.verified !== true) fails.push(`1 accepted via proxy: ${JSON.stringify(a)}`);
const [h, p, s] = token.split('.');
const forged = JSON.parse(Buffer.from(p, 'base64url'));
forged.email = 'someone-else@example.test';
const b = verify(`${h}.${Buffer.from(JSON.stringify(forged)).toString('base64url')}.${s}`, viaProxy);
if (b.ok) fails.push('2 tampered token was accepted');
const c = verify(token, baseEnv);
if (c.ok) fails.push('3 token accepted WITHOUT the proxy (should only work for the opted-in process)');
const certsScript = `
import { OAuth2Client } from 'google-auth-library';
const { certs } = await new OAuth2Client().getFederatedSignonCertsAsync();
console.log(JSON.stringify(Object.keys(certs)));`;
const kids = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', certsScript], { env: viaProxy, cwd: root, timeout: 20000 }).toString());
const localKid = JSON.parse(Buffer.from(h, 'base64url')).kid;
if (!kids.includes(localKid) || kids.length < 2) fails.push(`4 certs via proxy should hold Google's keys + the local one: ${JSON.stringify(kids)}`);
proxy.kill();
fs.rmSync(home, { recursive: true, force: true });
console.log(proxyLog.trim().split('\n').filter((l) => l.includes('GET')).slice(0, 2).join('\n'));
if (fails.length) {
  console.error(`FAIL\n${fails.join('\n')}`);
  process.exit(1);
}
console.log(`ok: certs via proxy = ${kids.length - 1} Google key(s) + local`);
console.log(`ok: accepted via proxy (${a.out.email}, nonce ${a.out.nonce}); tampered rejected (${b.err ?? 'error'}); without proxy rejected (${c.err ?? 'error'})`);
