#!/usr/bin/env node
// dotenv-exposure-check — pure Node.js, no deps.
//
// Probes a live URL for the secret artifacts that get served by accident, then
// CONFIRMS each hit by fetching the bytes and inspecting what's actually inside:
//
//   - .env / .env.production / .env.local / ...  → real KEY=VALUE secrets
//   - .git/config + .git/HEAD                    → cloneable repo + remote URL
//   - JavaScript source maps (.js.map)           → original source / paths leaked
//   - .DS_Store                                  → directory listing leaked
//   - backup & dump files (.bak, .sql, .zip ...) → server-side files downloadable
//
// A 200 alone is not enough — many SPAs return index.html for everything. So
// every candidate is content-verified: a hit only counts when the body really
// looks like the artifact (env assignments, git config stanza, sourcemap JSON,
// DS_Store magic, archive/dump signatures).
//
// Usage:
//   dotenv-exposure-check --url https://app.example.com
//   dotenv-exposure-check --url https://app.example.com --paths .env,.env.prod
//   dotenv-exposure-check --url https://app.example.com --html report.html
//   dotenv-exposure-check --url https://app.example.com --no-probe
//
// Keyless and read-only. Every request goes straight from this process to the
// target; nothing is stored, modified, or sent anywhere else.

import { writeFileSync } from "node:fs";

const VERSION = "0.1.0";
const UA = `dotenv-exposure-check/${VERSION}`;
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Cap how many bytes we pull per candidate so a giant dump doesn't blow memory.
const MAX_BYTES = 64 * 1024;

// ---- the artifact catalog ---------------------------------------------------
// Each artifact knows the paths to try, a severity, copy, a fix, and a
// `confirm(text, ct)` that returns evidence ONLY when the body is the real
// thing (so SPA catch-all index.html never produces a false positive).

const ARTIFACTS = [
  {
    id: "dotenv",
    severity: "critical",
    title: "Environment file (.env) served over HTTP",
    explain:
      "An .env file with KEY=VALUE secrets is reachable anonymously. Attackers mass-scan for exactly this; a single hit can hand over database passwords, API keys, and signing secrets. 12M+ exposed .env files have been catalogued in the wild.",
    fix: "Stop serving dotfiles: block `/\\.env` at the web server / CDN, move secrets to the platform's env-var store, and rotate every credential that was in the file.",
    paths: [
      ".env",
      ".env.production",
      ".env.prod",
      ".env.local",
      ".env.development",
      ".env.dev",
      ".env.staging",
      ".env.backup",
      ".env.bak",
      ".env.save",
      ".env.old",
    ],
    confirm: confirmDotenv,
  },
  {
    id: "git_config",
    severity: "critical",
    title: "Exposed .git directory (repo is cloneable)",
    explain:
      "The .git directory is web-readable. With /.git/config and /.git/HEAD an attacker can reconstruct your entire source tree — and the config often embeds the remote URL with an embedded token.",
    fix: "Deny access to `/\\.git` in the web server config (and confirm /.git/HEAD 404s). Never deploy the .git folder; build artifacts only.",
    paths: [".git/config", ".git/HEAD"],
    confirm: confirmGitConfig,
  },
  {
    id: "sourcemap",
    severity: "high",
    title: "Production source map (.js.map) exposed",
    explain:
      "A JavaScript source map is downloadable, reverse-mapping minified code back to original source — internal file paths, comments, sometimes hard-coded endpoints and keys. (Claude Code itself shipped a sourcemap leak in 2026.)",
    fix: "Disable source-map emission in production builds, or stop uploading *.js.map to the public origin. If maps are needed for error tracking, upload them privately to your monitoring vendor only.",
    paths: [
      "main.js.map",
      "app.js.map",
      "index.js.map",
      "bundle.js.map",
      "assets/index.js.map",
      "static/js/main.js.map",
      "_next/static/chunks/main.js.map",
    ],
    confirm: confirmSourceMap,
  },
  {
    id: "ds_store",
    severity: "medium",
    title: ".DS_Store leaks the directory listing",
    explain:
      "A macOS .DS_Store file is served. It enumerates every filename in the directory it sits in, handing attackers a free map of hidden files and backups to probe next.",
    fix: "Block `/\\.DS_Store`, delete it from the deploy, and add `.DS_Store` to .gitignore / your deploy ignore list.",
    paths: [".DS_Store"],
    confirm: confirmDsStore,
  },
  {
    id: "backup_dump",
    severity: "high",
    title: "Backup / database dump downloadable",
    explain:
      "A backup or dump artifact is reachable anonymously. These often contain a full copy of the application or database, including credentials and customer data.",
    fix: "Remove backups/dumps from the public web root and block the extensions (`\\.(sql|bak|zip|tar\\.gz|dump)$`) at the edge.",
    paths: [
      "backup.zip",
      "backup.sql",
      "backup.tar.gz",
      "db.sql",
      "dump.sql",
      "database.sql",
      "site.zip",
      "www.zip",
      "app.bak",
      "index.php.bak",
      "config.php.bak",
    ],
    confirm: confirmBackup,
  },
];

// ---- content confirmers -----------------------------------------------------

// Matches lines like  KEY=value  /  KEY="value"  /  export KEY=value
const ENV_LINE = /^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=\s*.+$/m;
const SECRETY_KEY =
  /(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|DATABASE_?URL|DB_PASS|AWS_|STRIPE_|JWT|SUPABASE|MONGODB_URI|REDIS_URL)/i;

function looksLikeHtml(text, ct) {
  if (ct && ct.includes("text/html")) return true;
  const head = text.slice(0, 512).toLowerCase();
  return head.includes("<!doctype html") || head.includes("<html");
}

function confirmDotenv(text, ct) {
  if (looksLikeHtml(text, ct)) return null;
  const lines = text.split(/\r?\n/);
  const assignments = lines.filter((l) => ENV_LINE.test(l));
  if (assignments.length === 0) return null;
  const keys = assignments
    .map((l) => l.replace(/^\s*export\s+/, "").split("=")[0].trim())
    .filter(Boolean);
  const secretKeys = keys.filter((k) => SECRETY_KEY.test(k));
  return {
    var_count: keys.length,
    sample_keys: keys.slice(0, 8),
    secret_keys: [...new Set(secretKeys)].slice(0, 8),
    has_secrets: secretKeys.length > 0,
  };
}

function confirmGitConfig(text, ct) {
  if (looksLikeHtml(text, ct)) return null;
  if (/^ref:\s+refs\//m.test(text)) return { kind: "HEAD", ref: text.trim().slice(0, 80) };
  if (/\[core\]/.test(text) || /\[remote /.test(text)) {
    const remote = (text.match(/url\s*=\s*(\S+)/) || [])[1] || null;
    return { kind: "config", remote_url: remote ? redactUrl(remote) : null };
  }
  return null;
}

function confirmSourceMap(text, ct) {
  if (looksLikeHtml(text, ct)) return null;
  let j;
  try {
    j = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof j !== "object" || j === null) return null;
  if (!("version" in j) || !("mappings" in j)) return null;
  const sources = Array.isArray(j.sources) ? j.sources : [];
  return {
    sourcemap_version: j.version,
    source_files: sources.length,
    sample_sources: sources.slice(0, 5),
    embeds_source: Array.isArray(j.sourcesContent) && j.sourcesContent.length > 0,
  };
}

function confirmDsStore(text, ct, rawBytes) {
  // .DS_Store starts with magic bytes 00 00 00 01 42 75 64 31 ("Bud1").
  const bytes = rawBytes || Buffer.from(text, "binary");
  if (bytes.length < 8) return null;
  const magic = bytes.subarray(0, 8);
  if (magic[4] === 0x42 && magic[5] === 0x75 && magic[6] === 0x64 && magic[7] === 0x31) {
    return { magic: "Bud1", bytes: bytes.length };
  }
  return null;
}

function confirmBackup(text, ct, rawBytes, url) {
  if (looksLikeHtml(text, ct)) return null;
  const bytes = rawBytes || Buffer.from(text, "binary");
  if (bytes.length < 4) return null;
  // Archive / dump signatures.
  const b = bytes;
  const sig = (...xs) => xs.every((v, i) => b[i] === v);
  if (sig(0x50, 0x4b, 0x03, 0x04)) return { format: "zip", bytes: b.length };
  if (sig(0x1f, 0x8b)) return { format: "gzip", bytes: b.length };
  // SQL dumps are text — look for telltale statements.
  const head = text.slice(0, 4096);
  if (/(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL dump|PostgreSQL database dump)/i.test(head)) {
    return { format: "sql", bytes: b.length };
  }
  // PHP backups.
  if (url && /\.php\.bak$/i.test(url) && /<\?php/.test(head)) {
    return { format: "php-source", bytes: b.length };
  }
  return null;
}

// ---- helpers ----------------------------------------------------------------

function redactUrl(u) {
  // Strip embedded credentials but flag that they were present.
  try {
    const m = u.match(/^([a-z]+:\/\/)([^@/]+)@(.*)$/i);
    if (m) return `${m[1]}<credentials-redacted>@${m[3]}`;
  } catch {
    /* ignore */
  }
  return u;
}

async function fetchArtifact(url) {
  try {
    const r = await fetch(url, {
      headers: { "User-Agent": UA, Accept: "*/*" },
      redirect: "manual",
    });
    // A redirect to a login/home page is not an exposed file.
    if (r.status >= 300 && r.status < 400) {
      return { ok: false, status: r.status, redirected: true };
    }
    const ct = r.headers.get("content-type") || "";
    const buf = Buffer.from(await r.arrayBuffer());
    const bytes = buf.subarray(0, MAX_BYTES);
    return {
      ok: r.ok,
      status: r.status,
      contentType: ct,
      bytes,
      text: bytes.toString("utf8"),
    };
  } catch (e) {
    return { ok: false, status: 0, error: e.message };
  }
}

// ---- main scan --------------------------------------------------------------

export async function scan({ url, paths = null, activeProbe = true } = {}) {
  if (!url) throw new Error("scan() requires { url }");
  const base = url.replace(/\/+$/, "");
  const findings = [];
  let probed = 0;
  let confirmed = 0;

  for (const art of ARTIFACTS) {
    // Allow restricting which paths to try (per-artifact still confirmed).
    const tryPaths = paths
      ? art.paths.filter((p) => paths.includes(p))
      : art.paths;
    if (tryPaths.length === 0) continue;

    let hit = null;
    for (const p of tryPaths) {
      if (!activeProbe) break;
      const full = `${base}/${p}`;
      const res = await fetchArtifact(full);
      probed++;
      if (res.status !== 200 || !res.bytes) continue;
      const evidence = art.confirm(res.text, res.contentType, res.bytes, full);
      if (evidence) {
        hit = { path: p, url: full, status: res.status, contentType: res.contentType, evidence };
        break; // one confirmed artifact of this class is enough
      }
    }

    if (hit) {
      confirmed++;
      findings.push({
        check: art.id,
        severity: art.severity,
        title: art.title,
        explain: art.explain,
        target: hit.url,
        confirmed: true,
        evidence: hit.evidence,
        fix: art.fix,
      });
    } else if (!activeProbe) {
      // In static mode, list what WOULD be checked.
      findings.push({
        check: art.id,
        severity: "info",
        title: `Would probe: ${art.title}`,
        explain: art.explain,
        target: `${base}/{${art.paths.join(",")}}`,
        confirmed: false,
        fix: art.fix,
      });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    target_url: base,
    scanned_by: `dotenv-exposure-check v${VERSION}`,
    active_probe: { enabled: activeProbe, probed, confirmed },
    summary,
    findings,
  };
}

// ---- CLI --------------------------------------------------------------------

function parseArgs(argv) {
  const a = argv.slice(2);
  const flag = (k) => {
    const i = a.indexOf(k);
    return i !== -1 ? a[i + 1] : null;
  };
  return {
    help: a.includes("--help") || a.includes("-h"),
    url: flag("--url") || process.env.TARGET_URL,
    paths: (flag("--paths") || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    activeProbe: !a.includes("--no-probe"),
    html: a.includes("--html") ? flag("--html") || "dotenv-exposure-report.html" : null,
  };
}

export async function run() {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.url) {
    console.error(`dotenv-exposure-check — probe a URL for served secret artifacts and confirm each hit.

Usage:
  dotenv-exposure-check --url https://app.example.com
  dotenv-exposure-check --url https://app.example.com --paths .env,.env.production
  dotenv-exposure-check --url https://app.example.com --html report.html
  dotenv-exposure-check --url https://app.example.com --no-probe

Flags:
  --url <url>       Target base URL (or TARGET_URL env)
  --paths a,b,c     Restrict to specific candidate paths
  --no-probe        List what would be checked without sending any request
  --html <file>     Write a shareable HTML report

Detects (and content-confirms): .env files, exposed .git directory,
production source maps (.js.map), .DS_Store directory listing,
backup / database dumps. Keyless and read-only.`);
    process.exit(opts.url ? 0 : 1);
  }

  const result = await scan({
    url: opts.url,
    paths: opts.paths.length ? opts.paths : null,
    activeProbe: opts.activeProbe,
  });

  if (opts.html) {
    const { renderHtml } = await import("./report.js");
    writeFileSync(opts.html, renderHtml(result));
    console.error(`HTML report written to ${opts.html}`);
  }

  console.log(JSON.stringify(result, null, 2));
  const s = result.summary;
  console.error(
    `\n${s.critical} critical, ${s.high} high, ${s.medium} medium` +
      (result.active_probe.enabled
        ? ` — ${result.active_probe.confirmed} CONFIRMED by fetching the bytes`
        : "")
  );
}

const isMain =
  process.argv[1] &&
  (import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` ||
    import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/")));
if (isMain) run().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
