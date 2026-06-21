# dotenv-exposure-check

> Probe any **live URL** for the secret artifacts that get served by accident — `.env`, `.env.production`, the `.git/` directory, production source maps (`.js.map`), `.DS_Store`, and backup/database dumps — and **prove each hit by fetching the bytes** and showing the real credentials, remote URLs, and source paths inside. Other scanners read your repo; this checks what your *server* is actually handing to strangers.

> ⚡ **Run it in one line, no install, no token:**
> ```bash
> npx dotenv-exposure-check --url https://your-app.example.com
> ```

> 🤝 **Want it done for you?** [Fixed-scope audit — $99 / 24h](https://buy.stripe.com/3cIeVdgikfj47yx9LkcAo0m): I verify each exposure live, help you rotate the leaked credentials, and send a written remediation report.

[![npm](https://img.shields.io/npm/v/dotenv-exposure-check?color=red)](https://www.npmjs.com/package/dotenv-exposure-check) [![downloads](https://img.shields.io/npm/dw/dotenv-exposure-check)](https://www.npmjs.com/package/dotenv-exposure-check) ![license](https://img.shields.io/badge/license-MIT-green) ![node](https://img.shields.io/badge/node-%3E%3D18-blue) ![deps](https://img.shields.io/badge/dependencies-0-brightgreen)

```
$ npx dotenv-exposure-check --url https://app.example.com
2 critical, 1 high, 1 medium — 4 CONFIRMED by fetching the bytes
  CRITICAL  /.env            5 vars readable — secret keys: DATABASE_URL, STRIPE_SECRET_KEY, JWT_SECRET
  CRITICAL  /.git/config     repo cloneable — remote https://<credentials-redacted>@github.com/acme/app.git
  HIGH      /main.js.map     12 source files mapped (original source embedded)
  MEDIUM    /.DS_Store       directory listing leaked
```

## Why this exists

Serving a secret file is the single highest-yield mistake on the web, and it
happens constantly: researchers catalogued **12M+ exposed `.env` files** in the
wild, and Palo Alto Unit 42 documented an extortion campaign that **scanned 230M
targets and harvested 90,000+ secret variables** from misconfigured `.env`
endpoints. Source maps are just as bad — even Claude Code shipped a production
`.js.map` leak in 2026 — and a web-readable `.git/` folder lets anyone clone your
entire source, remote token included.

The hard part is *confirmation*. Most single-page apps return `200 OK` with
`index.html` for **every** path, so "got a 200 on `/.env`" means nothing.
`dotenv-exposure-check` fetches each candidate and **inspects the actual bytes**:
an `.env` hit must contain real `KEY=VALUE` assignments, a source map must be
valid sourcemap JSON, a `.DS_Store` must carry the `Bud1` magic, a backup must
have a real archive/dump signature. You triage facts, not 200s.

## What it checks

| Check | Severity | How it's confirmed |
|---|---|---|
| `.env` / `.env.production` / `.env.local` … served | critical | body parsed for `KEY=VALUE` lines; secret-looking keys (DB/API/JWT/Stripe/AWS) flagged |
| Exposed `.git/` directory (repo cloneable) | critical | `/.git/config` + `/.git/HEAD` validated as git stanzas; embedded remote credentials detected and redacted |
| Production source map (`.js.map`) exposed | high | parsed as sourcemap JSON (`version` + `mappings`); counts mapped sources, flags embedded original source |
| Backup / database dump downloadable | high | archive (`zip`/`gzip`) or SQL-dump signature in the bytes |
| `.DS_Store` directory listing | medium | `Bud1` binary magic at offset 4 |

SPA catch-all (`200` + `index.html` for everything) is explicitly rejected, so
the tool does not false-positive on modern frontends.

## Usage

```bash
# Probe a live site (tries the common filenames for each artifact)
npx dotenv-exposure-check --url https://app.example.com

# Restrict to specific candidate paths
npx dotenv-exposure-check --url https://app.example.com --paths .env,.env.production

# Write a shareable HTML report
npx dotenv-exposure-check --url https://app.example.com --html report.html

# Dry run: list what would be checked, send no requests
npx dotenv-exposure-check --url https://app.example.com --no-probe
```

Output is JSON on stdout (pipe it into CI) and a one-line summary on stderr.
Exit is non-zero only on usage errors — gate your pipeline on the JSON `summary`.

## Install (optional)

```bash
npm i -g dotenv-exposure-check
dotenv-exposure-check --url https://app.example.com
```

Zero dependencies. Read-only and keyless — every request goes straight from the
tool to the target you name; nothing is stored, modified, or sent anywhere else.
**Only scan systems you own or are authorized to test.**

## Sister tools

Same active-probe philosophy across the stack, all MIT:

[supabase-security](https://github.com/Perufitlife/supabase-security-skill) ·
[pocketbase-security](https://github.com/Perufitlife/pocketbase-security-skill) ·
[firebase-security](https://github.com/Perufitlife/firebase-security-skill) ·
[appwrite-security](https://github.com/Perufitlife/appwrite-security-skill) ·
[nhost-security](https://github.com/Perufitlife/nhost-security-skill) ·
[strapi-security](https://github.com/Perufitlife/strapi-security) ·
[directus-security](https://github.com/Perufitlife/directus-security) ·
[aws-s3-security](https://github.com/Perufitlife/aws-s3-security) ·
[stripe-webhook-security](https://github.com/Perufitlife/stripe-webhook-security) ·
[github-actions-security](https://github.com/Perufitlife/github-actions-security) ·
[web-exposure-mcp](https://github.com/Perufitlife/web-exposure-mcp)

## License

MIT © [Renzo Madueno](https://github.com/Perufitlife)
