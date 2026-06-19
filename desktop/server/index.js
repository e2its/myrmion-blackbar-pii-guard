#!/usr/bin/env node
/*
 * index.js — Presidio MCP server (Node, zero dependencies)
 * ========================================================
 * A stdio JSON-RPC 2.0 MCP server exposing three tools:
 *   presidio_analyze    -> detect PII entities in text
 *   presidio_anonymize  -> replace / redact / mask / hash / encrypt PII
 *   presidio_decrypt    -> reverse encrypt: restore <ENC:...> tokens with the key
 *
 * Why Node: Claude Desktop bundles a Node runtime, so a node-type .mcpb needs
 * no Python and no extra install. This file uses only Node built-ins
 * (readline, crypto, global fetch in Node 18+), so the bundle ships nothing in
 * node_modules.
 *
 * Detection is delegated to a local Presidio Analyzer HTTP service. The
 * replace/redact/mask/hash operators and the reversible encrypt/decrypt are all
 * applied locally (encrypt uses Node's built-in crypto, no anonymizer service),
 * so only the analyzer service is required.
 *
 * Configuration (env vars):
 *   PRESIDIO_ANALYZER_URL     default http://localhost:5002
 *   PRESIDIO_GUARD_OPERATOR   default replace
 *   PRESIDIO_GUARD_LANGUAGE   default en
 *   PRESIDIO_GUARD_THRESHOLD  default 0.5
 *   PRESIDIO_GUARD_ENTITIES   comma list, default all
 *   PRESIDIO_GUARD_TIMEOUT    seconds, default 8
 */

"use strict";

const readline = require("readline");
const crypto = require("crypto");

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "blackbar", version: "0.1.0" };

const CFG = {
  analyzerUrl: env("PRESIDIO_ANALYZER_URL", "http://localhost:5002"),
  operator: env("PRESIDIO_GUARD_OPERATOR", "replace"),
  language: env("PRESIDIO_GUARD_LANGUAGE", "en"),
  threshold: parseFloat(env("PRESIDIO_GUARD_THRESHOLD", "0.5")),
  entities: env("PRESIDIO_GUARD_ENTITIES", "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
  timeoutMs: parseFloat(env("PRESIDIO_GUARD_TIMEOUT", "8")) * 1000,
};

function env(name, def) {
  const v = process.env[name];
  return v === undefined || v === "" ? def : v;
}

const TOOLS = [
  {
    name: "presidio_analyze",
    description:
      "Detect personally identifiable information (PII) in text using Microsoft Presidio. Returns each entity's type, character span, confidence score, and matched text.",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", description: "Text to scan for PII." },
        language: { type: "string", description: "Language code (default en)." },
        entities: {
          type: "array",
          items: { type: "string" },
          description: "Optional list of entity types to detect; default is all.",
        },
      },
      required: ["text"],
    },
  },
  {
    name: "presidio_anonymize",
    description:
      "Return a copy of the text with PII removed using the chosen operator: replace (<EMAIL_ADDRESS>), redact (delete), mask (****1234), hash, or encrypt. Only encrypt is reversible: it emits self-contained <ENC:TYPE:...> tokens that presidio_decrypt turns back into the originals with the same key. The other operators are one-way.",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string" },
        operator: {
          type: "string",
          enum: ["replace", "redact", "mask", "hash", "encrypt"],
          description: "Anonymization operator (default replace).",
        },
        language: { type: "string" },
        entities: { type: "array", items: { type: "string" } },
        key: { type: "string", description: "Encryption key (required only for operator=encrypt)." },
      },
      required: ["text"],
    },
  },
  {
    name: "presidio_decrypt",
    description:
      "Reverse a previous encrypt: find every <ENC:TYPE:...> token in the text and restore the original value using the same key. Needs only the text and the key — no spans, no Presidio service. Tokens that fail to authenticate (wrong key or tampered) are left untouched.",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", description: "Text containing <ENC:...> tokens to restore." },
        key: { type: "string", description: "The same key used when the text was encrypted." },
      },
      required: ["text", "key"],
    },
  },
];

// --------------------------------------------------------------------------- //
// Detection
// --------------------------------------------------------------------------- //
async function analyze(text, language, entities) {
  if (!text || !text.trim()) return [];
  const payload = { text, language: language || CFG.language };
  const ents = entities && entities.length ? entities : CFG.entities;
  if (ents.length) payload.entities = ents;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CFG.timeoutMs);
  let results;
  try {
    const res = await fetch(CFG.analyzerUrl.replace(/\/+$/, "") + "/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`analyzer returned HTTP ${res.status}`);
    results = await res.json();
  } catch (err) {
    throw new PresidioUnavailable(
      `Presidio analyzer unreachable at ${CFG.analyzerUrl}: ${err.message}`
    );
  } finally {
    clearTimeout(timer);
  }
  return results
    .map((r) => ({
      entity_type: r.entity_type,
      start: r.start,
      end: r.end,
      score: r.score == null ? 1.0 : r.score,
    }))
    .filter((s) => s.score >= CFG.threshold);
}

// --------------------------------------------------------------------------- //
// Local operators
// --------------------------------------------------------------------------- //
function resolveOverlaps(spans) {
  const ordered = [...spans].sort(
    (a, b) => a.start - b.start || b.end - b.start - (a.end - a.start) || b.score - a.score
  );
  const kept = [];
  let lastEnd = -1;
  for (const s of ordered) {
    if (s.start >= lastEnd) {
      kept.push(s);
      lastEnd = s.end;
    }
  }
  return kept.sort((a, b) => b.start - a.start); // apply right-to-left
}

function replacement(original, entityType, operator) {
  switch (operator) {
    case "redact":
      return "";
    case "mask":
      return original.length <= 4
        ? "*".repeat(original.length)
        : "*".repeat(original.length - 4) + original.slice(-4);
    case "hash": {
      const digest = crypto.createHash("sha256").update(original).digest("hex").slice(0, 10);
      return `<${entityType}:${digest}>`;
    }
    default:
      return `<${entityType}>`;
  }
}

function applyOperator(text, spans, operator) {
  let out = text;
  for (const span of resolveOverlaps(spans)) {
    const original = out.slice(span.start, span.end);
    out = out.slice(0, span.start) + replacement(original, span.entity_type, operator) + out.slice(span.end);
  }
  return out;
}

// --------------------------------------------------------------------------- //
// Reversible encryption — self-describing <ENC:TYPE:payload> tokens.
//
// This mirrors plugins/blackbar/scripts/bb_crypto.py byte-for-byte, so a token
// produced in Claude Code decrypts here and vice-versa. Zero dependencies: only
// Node's built-in `crypto`. No Presidio Anonymizer service required.
//
//   payload bytes = MAGIC(1) | salt(16) | nonce(12) | ciphertext(N) | tag(16)
//   dk        = PBKDF2-HMAC-SHA256(key, salt, ITERATIONS, 64)
//   keystream = HMAC-SHA256(dk[:32], nonce || be32(i)) for i = 0,1,...
//   tag       = HMAC-SHA256(dk[32:], MAGIC || salt || nonce || ciphertext)[:16]
// --------------------------------------------------------------------------- //
const MAGIC = Buffer.from([0x01]);
const ITERATIONS = 200000;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const TOKEN_RE = /<ENC:([A-Z0-9_]+):([A-Za-z0-9_-]+)>/g;

const _deriveCache = new Map();
function derive(key, salt) {
  const ck = key + "|" + salt.toString("hex");
  let v = _deriveCache.get(ck);
  if (!v) {
    const dk = crypto.pbkdf2Sync(key, salt, ITERATIONS, 64, "sha256");
    v = { encKey: dk.subarray(0, 32), macKey: dk.subarray(32) };
    _deriveCache.set(ck, v);
  }
  return v;
}

function keystream(encKey, nonce, length) {
  const chunks = [];
  let got = 0;
  let counter = 0;
  while (got < length) {
    const ctr = Buffer.alloc(4);
    ctr.writeUInt32BE(counter >>> 0, 0);
    const block = crypto.createHmac("sha256", encKey).update(Buffer.concat([nonce, ctr])).digest();
    chunks.push(block);
    got += block.length;
    counter++;
  }
  return Buffer.concat(chunks).subarray(0, length);
}

function xorBuf(a, b) {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function encryptValue(plaintext, key, salt) {
  salt = salt || crypto.randomBytes(SALT_LEN);
  const nonce = crypto.randomBytes(NONCE_LEN);
  const { encKey, macKey } = derive(key, salt);
  const pt = Buffer.from(plaintext, "utf8");
  const ct = xorBuf(pt, keystream(encKey, nonce, pt.length));
  const tag = crypto
    .createHmac("sha256", macKey)
    .update(Buffer.concat([MAGIC, salt, nonce, ct]))
    .digest()
    .subarray(0, TAG_LEN);
  return Buffer.concat([MAGIC, salt, nonce, ct, tag]).toString("base64url");
}

function decryptValue(payload, key) {
  const raw = Buffer.from(payload, "base64url");
  if (raw.length < 1 + SALT_LEN + NONCE_LEN + TAG_LEN || raw[0] !== 0x01) {
    throw new Error("unrecognized token");
  }
  const salt = raw.subarray(1, 1 + SALT_LEN);
  const nonce = raw.subarray(1 + SALT_LEN, 1 + SALT_LEN + NONCE_LEN);
  const tag = raw.subarray(raw.length - TAG_LEN);
  const ct = raw.subarray(1 + SALT_LEN + NONCE_LEN, raw.length - TAG_LEN);
  const { encKey, macKey } = derive(key, salt);
  const expected = crypto
    .createHmac("sha256", macKey)
    .update(Buffer.concat([MAGIC, salt, nonce, ct]))
    .digest()
    .subarray(0, TAG_LEN);
  if (expected.length !== tag.length || !crypto.timingSafeEqual(expected, tag)) {
    throw new Error("authentication failed (wrong key or corrupted token)");
  }
  return xorBuf(ct, keystream(encKey, nonce, ct.length)).toString("utf8");
}

function encryptText(text, spans, key) {
  if (!key) return { error: "operator=encrypt requires a 'key'." };
  const salt = crypto.randomBytes(SALT_LEN);
  let out = text;
  for (const s of resolveOverlaps(spans)) {
    const original = out.slice(s.start, s.end);
    out = out.slice(0, s.start) + `<ENC:${s.entity_type}:${encryptValue(original, key, salt)}>` + out.slice(s.end);
  }
  return {
    text: out,
    entities_found: [...new Set(spans.map((s) => s.entity_type))].sort(),
    note: "reversible: call presidio_decrypt with the same key",
  };
}

function decryptText(text, key) {
  let count = 0;
  const out = text.replace(TOKEN_RE, (m, _type, payload) => {
    try {
      const value = decryptValue(payload, key);
      count++;
      return value;
    } catch {
      return m;
    }
  });
  return { text: out, restored: count };
}

// --------------------------------------------------------------------------- //
// Tool dispatch
// --------------------------------------------------------------------------- //
async function toolAnalyze(args) {
  const text = args.text || "";
  const spans = await analyze(text, args.language, args.entities);
  const entities = spans.map((s) => ({
    entity_type: s.entity_type,
    start: s.start,
    end: s.end,
    score: Math.round(s.score * 1000) / 1000,
    text: text.slice(s.start, s.end),
  }));
  return JSON.stringify({ count: entities.length, entities }, null, 2);
}

async function toolAnonymize(args) {
  const operator = args.operator || CFG.operator;
  const text = args.text || "";
  const spans = await analyze(text, args.language, args.entities);
  if (operator === "encrypt") {
    return JSON.stringify(encryptText(text, spans, args.key || ""), null, 2);
  }
  const redacted = applyOperator(text, spans, operator);
  return JSON.stringify(
    { text: redacted, entities_found: [...new Set(spans.map((s) => s.entity_type))].sort() },
    null,
    2
  );
}

function toolDecrypt(args) {
  const text = args.text || "";
  const key = args.key || "";
  if (!key) return JSON.stringify({ error: "presidio_decrypt requires a 'key'." }, null, 2);
  return JSON.stringify(decryptText(text, key), null, 2);
}

async function dispatchTool(name, args) {
  try {
    let text;
    if (name === "presidio_analyze") text = await toolAnalyze(args);
    else if (name === "presidio_anonymize") text = await toolAnonymize(args);
    else if (name === "presidio_decrypt") text = toolDecrypt(args);
    else return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
    return { content: [{ type: "text", text }] };
  } catch (err) {
    const msg = err instanceof PresidioUnavailable ? `Presidio unavailable: ${err.message}` : String(err);
    return { content: [{ type: "text", text: msg }], isError: true };
  }
}

// --------------------------------------------------------------------------- //
// JSON-RPC handling
// --------------------------------------------------------------------------- //
async function handle(msg) {
  const { method, id } = msg;
  if (method === "initialize") {
    const requested = (msg.params && msg.params.protocolVersion) || PROTOCOL_VERSION;
    return rpc(id, {
      protocolVersion: requested,
      capabilities: { tools: {} },
      serverInfo: SERVER_INFO,
    });
  }
  if (method === "tools/list") return rpc(id, { tools: TOOLS });
  if (method === "tools/call") {
    const p = msg.params || {};
    const result = await dispatchTool(p.name || "", p.arguments || {});
    return rpc(id, result);
  }
  if (method === "ping") return rpc(id, {});
  if (method && method.startsWith("notifications/")) return null;
  if (id !== undefined && id !== null) {
    return { jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } };
  }
  return null;
}

function rpc(id, result) {
  return { jsonrpc: "2.0", id, result };
}

class PresidioUnavailable extends Error {}

function main() {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on("line", async (line) => {
    line = line.trim();
    if (!line) return;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    const response = await handle(msg);
    if (response !== null) process.stdout.write(JSON.stringify(response) + "\n");
  });
}

// Run the server only when executed directly, so the crypto can be unit-tested.
if (require.main === module) main();

module.exports = { encryptValue, decryptValue, encryptText, decryptText };
