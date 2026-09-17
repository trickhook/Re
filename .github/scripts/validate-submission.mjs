// Plugin Hub submission validator (Node, zero external dependencies).
//
// Reads a plugin-submission issue body, validates it end to end, and on success
// writes the plugin file + updated index.json into the working tree. It NEVER
// executes the submitted script; NocturneScript is only checked structurally
// here. The real guard is the on-device sandbox (see docs/PLUGIN-HUB.md).
//
// Inputs (env):
//   ISSUE_BODY   the raw issue body (untrusted; passed via env, never inlined)
//   REPO_DIR     repo root to read/write (default: process.cwd())
//   ISSUE_NUMBER for messages (optional)
//   GITHUB_OUTPUT if set, `ok/id/version/sha256/fingerprint/is_update/message`
//                 are appended for later workflow steps
//   RESULT_FILE  if set, a JSON {ok,message,...} is written there (used by tests)
//
// Exit code: 0 when the validator ran (whether it ACCEPTED or REJECTED the
// submission — branch on the `ok` output); non-zero only on an internal error.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonical, KEY_ORDER } from "./canonical.mjs";

const ID_RE = /^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$/;
const VERSION_RE = /^\d+\.\d+(\.\d+)?$/;
const SCRIPT_MAX = 64 * 1024; // bytes
const FILE_MAX = 128 * 1024; // bytes

class Reject extends Error {}

function extractJsonBlock(body) {
  if (typeof body !== "string" || body.trim() === "") {
    throw new Reject("The issue body is empty. Expected one fenced ```json block.");
  }
  // First ```json ... ``` fence. Tolerant of CRLF and a language tag with
  // trailing spaces. Non-greedy to the first closing fence.
  const m = body.match(/```[ \t]*json[ \t]*\r?\n([\s\S]*?)\r?\n?```/i);
  if (!m) {
    throw new Reject(
      "No ```json code block found in the issue. The submission must contain exactly one fenced json block with { \"plugin\", \"authorKey\", \"signature\" }.",
    );
  }
  return m[1];
}

function parseSubmission(text) {
  let obj;
  try {
    obj = JSON.parse(text);
  } catch (e) {
    throw new Reject("The json block is not valid JSON: " + e.message);
  }
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Reject("The json block must be a JSON object.");
  }
  for (const k of ["plugin", "authorKey", "signature"]) {
    if (!(k in obj)) throw new Reject("Submission is missing the `" + k + "` field.");
  }
  if (obj.plugin === null || typeof obj.plugin !== "object" || Array.isArray(obj.plugin)) {
    throw new Reject("`plugin` must be the .nocturneplugin JSON object.");
  }
  if (typeof obj.authorKey !== "string" || obj.authorKey.trim() === "") {
    throw new Reject("`authorKey` must be a non-empty base64 string (SPKI DER).");
  }
  if (typeof obj.signature !== "string" || obj.signature.trim() === "") {
    throw new Reject("`signature` must be a non-empty base64 string (DER ECDSA).");
  }
  return obj;
}

function validatePluginSchema(plugin) {
  const keys = Object.keys(plugin);
  const extra = keys.filter((k) => !KEY_ORDER.includes(k));
  if (extra.length) throw new Reject("`plugin` has unexpected field(s): " + extra.join(", ") + ". Allowed: " + KEY_ORDER.join(", ") + ".");
  for (const k of KEY_ORDER) {
    if (!(k in plugin)) throw new Reject("`plugin` is missing the `" + k + "` field.");
    if (typeof plugin[k] !== "string") throw new Reject("`plugin." + k + "` must be a string.");
  }
  if (!ID_RE.test(plugin.id)) {
    throw new Reject("`id` \"" + plugin.id + "\" is invalid. It must be lowercase letters, digits and hyphens, 3-40 chars, not starting/ending with a hyphen (^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$).");
  }
  if (!VERSION_RE.test(plugin.version)) {
    throw new Reject("`version` \"" + plugin.version + "\" is invalid. Use MAJOR.MINOR or MAJOR.MINOR.PATCH (digits and dots).");
  }
  if (plugin.name.trim() === "") throw new Reject("`name` must not be empty.");
  if (plugin.script.trim() === "") throw new Reject("`script` must not be empty.");
  const scriptBytes = Buffer.byteLength(plugin.script, "utf-8");
  if (scriptBytes > SCRIPT_MAX) {
    throw new Reject("`script` is " + scriptBytes + " bytes, over the " + SCRIPT_MAX + "-byte (64 KiB) cap.");
  }
}

// Structural NocturneScript sanity ONLY. Not a language check; the on-device
// sandbox is the real guard. Verifies: decodes as UTF-8, non-empty, and braces
// {} and parens () are balanced (ignoring ## line comments and "..." strings).
function structuralSanity(script) {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(script, "utf-8"));
  } catch {
    throw new Reject("`script` is not valid UTF-8.");
  }
  let brace = 0, paren = 0, inStr = false, esc = false, inComment = false;
  for (let i = 0; i < script.length; i++) {
    const c = script[i];
    if (inComment) {
      if (c === "\n") inComment = false;
      continue;
    }
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === "#" && script[i + 1] === "#") { inComment = true; i++; continue; }
    if (c === "{") brace++;
    else if (c === "}") { brace--; if (brace < 0) throw new Reject("Unbalanced braces in `script` (a '}' with no matching '{')."); }
    else if (c === "(") paren++;
    else if (c === ")") { paren--; if (paren < 0) throw new Reject("Unbalanced parentheses in `script` (a ')' with no matching '(')."); }
  }
  if (inStr) throw new Reject("Unterminated string literal in `script`.");
  if (brace !== 0) throw new Reject("Unbalanced braces in `script` (" + brace + " unclosed '{').");
  if (paren !== 0) throw new Reject("Unbalanced parentheses in `script` (" + paren + " unclosed '(').");
}

function verifyCrypto(plugin, authorKeyB64, signatureB64) {
  const canonBytes = canonical({
    id: plugin.id, name: plugin.name, version: plugin.version,
    author: plugin.author, description: plugin.description, script: plugin.script,
  });
  if (canonBytes.length > FILE_MAX) {
    throw new Reject("The plugin file is " + canonBytes.length + " bytes, over the " + FILE_MAX + "-byte (128 KiB) cap.");
  }
  const sha256 = crypto.createHash("sha256").update(canonBytes).digest("hex");

  let spki;
  try {
    spki = Buffer.from(authorKeyB64, "base64");
  } catch {
    throw new Reject("`authorKey` is not valid base64.");
  }
  let key;
  try {
    key = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
  } catch (e) {
    throw new Reject("`authorKey` is not a valid SPKI public key: " + e.message);
  }
  const kd = key.asymmetricKeyDetails || {};
  if (key.asymmetricKeyType !== "ec" || kd.namedCurve !== "prime256v1") {
    throw new Reject("`authorKey` must be an EC P-256 (prime256v1) key; got " + key.asymmetricKeyType + "/" + (kd.namedCurve || "?") + ".");
  }
  const sig = Buffer.from(signatureB64, "base64");
  let ok = false;
  try {
    ok = crypto.verify("sha256", canonBytes, { key, dsaEncoding: "der" }, sig);
  } catch (e) {
    throw new Reject("Signature could not be checked: " + e.message);
  }
  if (!ok) {
    throw new Reject("Signature does NOT verify against `authorKey` over the canonical plugin bytes. The plugin was not signed by this device key, or the bytes were altered in transit.");
  }
  const fingerprint = crypto.createHash("sha256").update(spki).digest("hex").slice(0, 16);
  return { canonBytes, sha256, fingerprint };
}

function cmpVersion(a, b) {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function loadIndex(repoDir) {
  const p = path.join(repoDir, "plugins/index.json");
  if (!fs.existsSync(p)) return { schema: 1, updated: null, plugins: [] };
  const idx = JSON.parse(fs.readFileSync(p, "utf-8"));
  if (!Array.isArray(idx.plugins)) idx.plugins = [];
  return idx;
}

// Anti-hijack: an id, once in the registry, is owned by the authorKey that first
// claimed it. A resubmission of that id must come from the SAME authorKey AND
// bump the version. A different key is rejected.
function checkOwnership(index, plugin, authorKeyB64) {
  const existing = index.plugins.find((e) => e.id === plugin.id);
  if (!existing) return { isUpdate: false };
  if (existing.authorKey !== authorKeyB64) {
    throw new Reject("The id \"" + plugin.id + "\" is already owned by a different device key (fingerprint " + existing.authorFingerprint + "). Ids belong to the first key that claims them; pick a different id.");
  }
  if (cmpVersion(plugin.version, existing.version) <= 0) {
    throw new Reject("Version " + plugin.version + " does not bump the registered version " + existing.version + " for id \"" + plugin.id + "\". Increase the version to publish an update.");
  }
  return { isUpdate: true };
}

function writeOutputs(fields) {
  const out = process.env.GITHUB_OUTPUT;
  if (!out) return;
  const lines = [];
  for (const [k, v] of Object.entries(fields)) {
    if (k === "message") {
      const d = "MSG_" + crypto.randomBytes(8).toString("hex");
      lines.push(`${k}<<${d}\n${v}\n${d}`);
    } else {
      lines.push(`${k}=${v}`);
    }
  }
  fs.appendFileSync(out, lines.join("\n") + "\n");
}

function finish(ok, message, extra = {}) {
  const result = { ok, message, ...extra };
  writeOutputs({ ok: String(ok), message, id: extra.id || "", version: extra.version || "", sha256: extra.sha256 || "", fingerprint: extra.fingerprint || "", is_update: String(extra.isUpdate || false) });
  if (process.env.RESULT_FILE) fs.writeFileSync(process.env.RESULT_FILE, JSON.stringify(result, null, 2));
  console.log((ok ? "ACCEPT: " : "REJECT: ") + message);
  process.exit(0);
}

function main() {
  const repoDir = process.env.REPO_DIR || process.cwd();
  let sub, plugin;
  try {
    const block = extractJsonBlock(process.env.ISSUE_BODY);
    sub = parseSubmission(block);
    plugin = sub.plugin;
    validatePluginSchema(plugin);
    structuralSanity(plugin.script);
    const { canonBytes, sha256, fingerprint } = verifyCrypto(plugin, sub.authorKey, sub.signature);
    const index = loadIndex(repoDir);
    const { isUpdate } = checkOwnership(index, plugin, sub.authorKey);

    // Passed. Write the plugin file + update the index in the working tree.
    const relPath = "plugins/community/" + plugin.id + ".nocturneplugin";
    const absPath = path.join(repoDir, relPath);
    fs.mkdirSync(path.dirname(absPath), { recursive: true });
    fs.writeFileSync(absPath, canonBytes);

    const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const entry = {
      id: plugin.id, name: plugin.name, version: plugin.version, author: plugin.author,
      authorKey: sub.authorKey, authorFingerprint: fingerprint, description: plugin.description,
      path: relPath, sha256, signature: sub.signature, submittedAt: now,
    };
    const i = index.plugins.findIndex((e) => e.id === plugin.id);
    if (i >= 0) index.plugins[i] = entry; else index.plugins.push(entry);
    index.plugins.sort((a, b) => a.id.localeCompare(b.id));
    index.schema = 1;
    index.updated = now;
    fs.writeFileSync(path.join(repoDir, "plugins/index.json"), JSON.stringify(index, null, 2) + "\n");

    finish(true,
      (isUpdate ? "Updated" : "Added") + " `" + plugin.id + "` v" + plugin.version +
      " (author fingerprint `" + fingerprint + "`, sha256 `" + sha256 + "`). Signature verified.",
      { id: plugin.id, version: plugin.version, sha256, fingerprint, isUpdate });
  } catch (e) {
    if (e instanceof Reject) finish(false, e.message, { id: plugin && plugin.id });
    // Internal error: surface it and fail the step.
    console.error("INTERNAL ERROR: " + (e && e.stack || e));
    if (process.env.RESULT_FILE) fs.writeFileSync(process.env.RESULT_FILE, JSON.stringify({ ok: false, internalError: String(e) }, null, 2));
    process.exit(2);
  }
}

main();
