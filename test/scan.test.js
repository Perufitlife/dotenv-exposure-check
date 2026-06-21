// Tests: drive scan() against a mocked fetch and assert that
//  (1) a leaky site has each artifact CONFIRMED by its real bytes,
//  (2) a clean / SPA-catch-all site produces zero false positives,
//  (3) the .DS_Store binary magic and zip signature are matched correctly.
import { scan } from "../scripts/scan.js";
import assert from "node:assert";

const SPA_HTML = "<!doctype html><html><head><title>App</title></head><body>spa</body></html>";

const REAL_ENV = `# production
NODE_ENV=production
DATABASE_URL=postgres://user:s3cr3t@db.internal:5432/app
STRIPE_SECRET_KEY=sk_live_51abcDEF
JWT_SECRET=supersecretvalue
PORT=3000
`;

const REAL_GIT_CONFIG = `[core]
\trepositoryformatversion = 0
[remote "origin"]
\turl = https://x-token:ghp_abc123@github.com/acme/app.git
`;

const REAL_SOURCEMAP = JSON.stringify({
  version: 3,
  sources: ["webpack://app/src/index.js", "webpack://app/src/config.js"],
  sourcesContent: ["const x=1", "export const API='https://api.acme.com'"],
  mappings: "AAAA,SAASA",
});

// .DS_Store: 4 bytes + "Bud1" magic.
const DS_STORE = Buffer.concat([Buffer.from([0, 0, 0, 1]), Buffer.from("Bud1"), Buffer.alloc(32)]);

// zip backup: PK\x03\x04 signature.
const ZIP_BACKUP = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(64)]);

function resp(status, body, ct) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => (k.toLowerCase() === "content-type" ? ct || "application/octet-stream" : null) },
    arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
  };
}

function leakyFetch(url) {
  const u = String(url);
  if (u.endsWith("/.env")) return resp(200, REAL_ENV, "text/plain");
  if (u.endsWith("/.git/config")) return resp(200, REAL_GIT_CONFIG, "text/plain");
  if (u.endsWith("/main.js.map")) return resp(200, REAL_SOURCEMAP, "application/json");
  if (u.endsWith("/.DS_Store")) return resp(200, DS_STORE, "application/octet-stream");
  if (u.endsWith("/backup.zip")) return resp(200, ZIP_BACKUP, "application/zip");
  // Everything else: SPA catch-all returns index.html with HTTP 200.
  return resp(200, SPA_HTML, "text/html");
}

function cleanFetch() {
  // Real 404s everywhere.
  return resp(404, "Not Found", "text/plain");
}

function spaFetch() {
  // The dangerous case: 200 + index.html for ALL paths. Must NOT false-positive.
  return resp(200, SPA_HTML, "text/html");
}

let pass = 0;

// 1) Leaky site — every artifact confirmed by its bytes.
globalThis.fetch = async (url) => leakyFetch(url);
let r = await scan({ url: "https://leaky.test" });
const got = (id) => r.findings.find((f) => f.check === id && f.confirmed);

assert.ok(got("dotenv"), "should confirm .env");
assert.ok(got("dotenv").evidence.has_secrets, "should flag secret keys in .env");
assert.ok(got("dotenv").evidence.secret_keys.includes("DATABASE_URL"), "DATABASE_URL is a secret key");
assert.ok(got("git_config"), "should confirm .git/config");
assert.ok(/credentials-redacted/.test(got("git_config").evidence.remote_url), "remote creds redacted");
assert.ok(got("sourcemap"), "should confirm sourcemap");
assert.strictEqual(got("sourcemap").evidence.source_files, 2, "two source files mapped");
assert.ok(got("ds_store"), "should confirm .DS_Store via Bud1 magic");
assert.ok(got("backup_dump"), "should confirm zip backup via PK signature");
assert.strictEqual(got("backup_dump").evidence.format, "zip", "format is zip");
assert.ok(r.active_probe.confirmed >= 5, "should confirm >=5 artifacts");
assert.ok(r.summary.critical >= 2, "env + git are critical");
console.log("PASS: leaky site — all 5 artifact classes confirmed by their real bytes");
pass++;

// 2) Clean site — nothing confirmed.
globalThis.fetch = async () => cleanFetch();
r = await scan({ url: "https://clean.test" });
assert.strictEqual(r.findings.length, 0, "clean site has no findings");
assert.strictEqual(r.active_probe.confirmed, 0, "clean site confirms nothing");
console.log("PASS: clean site (all 404) — zero findings");
pass++;

// 3) SPA catch-all (200 + HTML for everything) — zero false positives.
globalThis.fetch = async () => spaFetch();
r = await scan({ url: "https://spa.test" });
assert.strictEqual(r.active_probe.confirmed, 0, "SPA catch-all must not false-positive");
assert.strictEqual(r.findings.length, 0, "SPA index.html for every path is not an exposure");
console.log("PASS: SPA catch-all (200 index.html everywhere) — zero false positives");
pass++;

// 4) Static mode lists checks without probing.
r = await scan({ url: "https://x.test", activeProbe: false });
assert.strictEqual(r.active_probe.probed, 0, "no requests in --no-probe mode");
assert.ok(r.findings.length >= 5, "static mode lists every artifact class");
console.log("PASS: static mode (--no-probe) lists checks, sends no requests");
pass++;

console.log(`\n${pass}/4 tests passed`);
