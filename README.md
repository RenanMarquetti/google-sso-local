# google-sso-local

Log in with "Sign in with Google" against a backend **running on your machine**, with any e-mail, **without a Google
account and without changing the backend's code or config**.

The backend verifies Google ID tokens by downloading Google's public keys from `www.googleapis.com`. This tool runs a
small proxy on `127.0.0.1` that answers those key requests with **your** local key, and mints ID tokens signed by it.
Only the process you start with two environment variables trusts it:

```sh
HTTPS_PROXY=http://127.0.0.1:8899 NODE_EXTRA_CA_CERTS=~/.google-sso-local/ca.crt node your-backend.js
```

Every other host goes through the proxy as a blind tunnel (real TLS, untouched). Every other process on the machine,
and every deployed environment, keeps talking to the real Google and rejects these tokens (`No pem found for envelope`).

## Why not a "dev mode" flag in the backend?

A switch in code or config that changes where tokens are verified is a backdoor waiting to be enabled by mistake in
production. Here the backend is unchanged; the redirection lives in the environment of one local process, and only
someone who already controls that machine can set it.

## Usage

```sh
npx google-sso-local init                 # once: local CA, TLS cert for *.googleapis.com, signing key (~/.google-sso-local, mode 600)
npx google-sso-local proxy --port 8899    # keep running
npx google-sso-local env --port 8899      # prints the two variables for the backend process
npx google-sso-local mint --email bot@example.test --aud <backend GOOGLE_CLIENT_ID> --nonce <nonce from the login attempt>
```

The token has `iss=https://accounts.google.com`, `aud`/`azp`, `email_verified=true`, `name`, optional `nonce`/`hd`,
a unique `jti` (backends that block replays accept each token once), and `local_sso=true` so it is easy to spot in logs.

Served on the intercepted hosts: `/oauth2/v1/certs` (PEM, used by `google-auth-library`), `/oauth2/v3/certs` (JWKS),
`/oauth2/v3/tokeninfo`.

Other runtimes: Python `requests` honours `HTTPS_PROXY` and `REQUESTS_CA_BUNDLE`; Go honours `HTTPS_PROXY` and
`SSL_CERT_FILE`. Check that `NO_PROXY` does not include `googleapis.com`.

## What it does not do

- The browser side ("Sign in with Google" button / Google Identity Services) still talks to the real Google. Drive the
  backend's login API directly with the minted token (bots, tests), or stub the button in your test browser.
- The e-mail still has to be a user your local backend knows (or one it auto-registers).
- Not for shared or deployed environments. The CA key in `~/.google-sso-local` lets anyone holding it mint tokens for
  processes that trust it: keep it on your machine.

## Test

```sh
npm install && npm test   # real google-auth-library: accepted via proxy, tampered rejected, rejected without proxy
```

License: MIT.
