/* Blackbar PII firewall — front-end. All state is in memory only; the key never
   comes here (only a fingerprint). CSP is strict, so this file has no inline
   code and no external requests beyond same-origin /api/*. */
"use strict";

// --------------------------------------------------------------------------- //
// Constants / helpers
// --------------------------------------------------------------------------- //
const CSRF = document.querySelector('meta[name="blackbar-csrf"]').content;
const TOKEN_RE = /<ENC:[A-Z0-9_]+:[A-Za-z0-9_-]+>/g;
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
};
const esc = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const debounce = (fn, ms) => {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
};

async function api(method, path, body, opts = {}) {
  const headers = { "X-Blackbar-Token": CSRF };
  let payload;
  if (opts.raw) {
    headers["Content-Type"] = "application/octet-stream";
    if (opts.filename) headers["X-Blackbar-Filename"] = opts.filename;
    payload = body;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetch(path, { method, headers, body: payload });
  let data = null;
  try { data = await res.json(); } catch (_) {}
  if (!res.ok) {
    const err = new Error((data && (data.detail || data.error)) || res.statusText);
    err.code = data && data.error;
    err.hint = data && data.hint;
    err.status = res.status;
    throw err;
  }
  return data;
}

function toast(msg, isErr) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, isErr ? 4200 : 2200);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_) {
    try {
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch (_) { return false; }
  }
}

// code-point aware slice (Presidio offsets are Python code points)
function cpSlice(cps, start, end) { return cps.slice(start, end).join(""); }
// convert a UTF-16 index in `s` to a code-point index
function cpIndex(s, utf16) { return Array.from(s.slice(0, utf16)).length; }

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 24) return 99; // cheap early-out for very different lengths
  const dp = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    let prev = dp[0]; dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[n];
}

// --------------------------------------------------------------------------- //
// Global state (memory only)
// --------------------------------------------------------------------------- //
const FAMILY = {};        // entity_type -> family
const ENTITY_LABEL = {};  // entity_type -> label
let CATALOG = [];
let HEALTH = null;
let KEY_FP = null;
let PDF_OK = false;
let seenGuardrail = false;

const PREFS = loadPrefs();
let session = { turns: [] };
let current = null;       // current turn object
let seq = 0;

function loadPrefs() {
  try { return JSON.parse(localStorage.getItem("blackbar.prefs") || "{}"); }
  catch (_) { return {}; }
}
function savePrefs() {
  try { localStorage.setItem("blackbar.prefs", JSON.stringify(PREFS)); } catch (_) {}
}

function turnTimestamp() {
  const now = new Date();
  const p = (n) => String(n).padStart(2, "0");
  let tz = "";
  try {
    const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" }).formatToParts(now);
    tz = (parts.find((x) => x.type === "timeZoneName") || {}).value || "";
  } catch (_) {}
  const date = `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`;
  const time = `${p(now.getHours())}:${p(now.getMinutes())}`;
  return { label: `${date} · ${time}${tz ? " " + tz : ""}`, iso: now.toISOString() };
}

function newTurn() {
  seq += 1;
  const ts = turnTimestamp();
  return {
    id: seq, name: "Turn " + seq, createdLabel: ts.label, createdISO: ts.iso,
    input: "", detections: [], scannedText: null, langUsed: null,
    excluded: new Set(), manual: [], disabledTypes: new Set(),
    perEntity: {}, operator: PREFS.operator || "encrypt",
    selectedTypes: null, archived: false,
    anon: "", emittedTokens: [], reply: "", restored: "",
    integrity: null, keyFp: null, status: "empty",
  };
}

// --------------------------------------------------------------------------- //
// DOM refs
// --------------------------------------------------------------------------- //
const D = {};
["analyzer-dot","analyzer-label","key-dot","key-label","lang-select","turn-list",
 "turn-title","turn-meta","input","detect-summary","preview-details","preview",
 "legend","thresh","thresh-out","operator","op-warning","autocopy","btn-anon",
 "smart-pill-1","anon","btn-copy-anon","btn-copy-bt","selfcheck","guardrail",
 "btn-guardrail","btn-guardrail-x","reply","btn-decrypt","smart-pill-3","integrity",
 "restored","btn-copy-restored","privacy-text","dropzone","import-file"
].forEach((k) => { D[k] = $(k); });

// --------------------------------------------------------------------------- //
// Bootstrap
// --------------------------------------------------------------------------- //
async function boot() {
  applyTheme(PREFS.theme);
  try {
    const ents = await api("GET", "/api/entities");
    CATALOG = ents.entities;
    for (const e of CATALOG) { FAMILY[e.type] = e.family; ENTITY_LABEL[e.type] = e.label; }
  } catch (e) { toast("Cannot reach the app backend: " + e.message, true); }

  await refreshHealth();

  // language selector
  const langs = (HEALTH && HEALTH.analyzer && HEALTH.analyzer.languages) || ["en","es","fr","de","it","pt"];
  for (const l of langs) {
    const o = el("option", null, l);
    o.value = l; D["lang-select"].appendChild(o);
  }
  D["lang-select"].value = PREFS.language || "auto";
  if (PREFS.threshold != null) { D.thresh.value = PREFS.threshold; }
  D["thresh-out"].textContent = Number(D.thresh.value).toFixed(2);

  buildTypeCombo();
  session.turns.push(newTurn());
  selectTurn(session.turns[0]);
  wireEvents();
  // periodic analyzer re-check
  setInterval(refreshAnalyzerDot, 15000);
}

async function refreshHealth() {
  try {
    HEALTH = await api("GET", "/api/health");
    KEY_FP = HEALTH.key.fingerprint;
    PDF_OK = HEALTH.config.pdf_available;
    if (!PREFS.operator) { D.operator.value = HEALTH.config.default_operator || "encrypt"; }
    renderKeyChip(HEALTH.key);
    renderAnalyzer(HEALTH.analyzer);
  } catch (e) {
    renderAnalyzer({ reachable: false, error: e.message });
  }
}

async function refreshAnalyzerDot() {
  try { renderAnalyzer(await api("GET", "/api/analyzer/health")); }
  catch (_) { renderAnalyzer({ reachable: false }); }
}

function renderAnalyzer(a) {
  const dot = D["analyzer-dot"], label = D["analyzer-label"];
  if (a && a.reachable) {
    dot.className = "dot ok";
    label.textContent = "detector · " + (a.recognizers != null ? a.recognizers + " rules" : "on");
    D["analyzer-label"].parentElement.title = a.url + " · " + (a.latency_ms ?? "?") + "ms";
    D.btn_anon_down = false;
  } else {
    dot.className = "dot bad";
    label.textContent = "detector offline";
    D["analyzer-label"].parentElement.title =
      "Analyzer unreachable. Start it: plugins/blackbar/presidio-native/run.sh — Restore still works.";
    D.btn_anon_down = true;
  }
  updateAnonEnabled();
}

function renderKeyChip(k) {
  const dot = D["key-dot"], label = D["key-label"];
  if (k && k.present) {
    dot.className = "dot ok";
    label.textContent = "key " + (k.fingerprint || "") + " · " + (k.source || "");
    D["key-label"].parentElement.title = "Key active (" + k.source + "). Same key restores this session. Click to rotate.";
  } else {
    dot.className = "dot bad";
    label.textContent = "no key";
    D["key-label"].parentElement.title = "No key set — encrypt/decrypt disabled. Click to generate one.";
  }
  updateAnonEnabled();
}

function hasKey() { return HEALTH && HEALTH.key && HEALTH.key.present; }

function updateAnonEnabled() {
  const op = D.operator.value;
  const needKey = op === "encrypt";
  const blocked = (D.btn_anon_down && true) || (needKey && !hasKey());
  D["btn-anon"].disabled = !!blocked;
  D["btn-anon"].title = D.btn_anon_down ? "Detector offline — anonymize disabled"
    : (needKey && !hasKey()) ? "No key — click the key chip to generate one" : "Ctrl/Cmd+Enter";
}

// --------------------------------------------------------------------------- //
// Turn navigation
// --------------------------------------------------------------------------- //
function syncFromDOM() {
  if (!current) return;
  current.input = D.input.value;
  current.reply = D.reply.value;
}

function selectTurn(turn) {
  syncFromDOM();
  current = turn;
  D.input.value = turn.input;
  D.anon.value = turn.anon;
  D.reply.value = turn.reply;
  D.restored.value = turn.restored;
  D.operator.value = turn.operator;
  onOperatorChange();
  D["turn-title"].textContent = turn.name;
  D["btn-copy-anon"].disabled = !turn.anon;
  D["btn-copy-bt"].disabled = !turn.anon;
  D["btn-copy-restored"].disabled = !turn.restored;
  D.selfcheck.hidden = true;
  renderTurnMeta();
  renderTypeCombo();
  renderIntegrity(turn.integrity, turn);
  renderDetections();
  renderTurnList();
  updateSmartPills();
}

function renderTurnMeta() {
  const t = current;
  const bits = [];
  if (t.createdLabel) bits.push(t.createdLabel);
  bits.push(t.operator);
  if (t.langUsed) bits.push("lang " + t.langUsed);
  if (t.emittedTokens.length) bits.push(t.emittedTokens.length + " protected");
  if (t.keyFp && KEY_FP && t.keyFp !== KEY_FP) bits.push("⚠ key changed");
  D["turn-meta"].textContent = bits.join(" · ");
}

function turnListItem(t, isArchived) {
  const li = el("li", "turn-item" + (t === current ? " active" : "") + (isArchived ? " archived" : ""));
  const st = el("span", "ti-status");
  if (t.status === "restored") st.classList.add(t.integrity && t.integrity._warn ? "warn" : "done");
  else if (t.status === "anon" || t.status === "replied") st.classList.add("anon");
  li.appendChild(st);

  const main = el("div", "ti-main");
  main.appendChild(el("span", "ti-name", t.name));
  if (t.createdLabel) main.appendChild(el("span", "ti-time", t.createdLabel));
  li.appendChild(main);

  li.appendChild(el("span", "ti-badge", t.emittedTokens.length ? ("✓" + t.emittedTokens.length) : ""));

  const actions = el("span", "ti-actions");
  const arch = el("button", "ti-act", isArchived ? "⤒" : "⤓");
  arch.type = "button";
  arch.title = isArchived ? "Unarchive turn" : "Archive turn";
  arch.addEventListener("click", (ev) => { ev.stopPropagation(); t.archived = !t.archived; renderTurnList(); });
  const del = el("button", "ti-act ti-del", "✕");
  del.type = "button"; del.title = "Delete turn";
  del.addEventListener("click", (ev) => { ev.stopPropagation(); deleteTurn(t); });
  actions.appendChild(arch); actions.appendChild(del);
  li.appendChild(actions);

  li.addEventListener("click", () => selectTurn(t));
  return li;
}

function renderTurnList() {
  const list = D["turn-list"];
  list.innerHTML = "";
  const activeTurns = session.turns.filter((t) => !t.archived);
  const archived = session.turns.filter((t) => t.archived);
  // newest first
  for (const t of [...activeTurns].reverse()) list.appendChild(turnListItem(t, false));
  if (archived.length) {
    const hdr = el("li", "turn-archived-hdr");
    hdr.textContent = `${PREFS.showArchived ? "▾" : "▸"} Archived (${archived.length})`;
    hdr.addEventListener("click", () => { PREFS.showArchived = !PREFS.showArchived; savePrefs(); renderTurnList(); });
    list.appendChild(hdr);
    if (PREFS.showArchived) for (const t of [...archived].reverse()) list.appendChild(turnListItem(t, true));
  }
  const n = session.turns.length;
  D["privacy-text"].textContent = `Originals in memory only · ${n} turn${n === 1 ? "" : "s"} · 0 bytes to disk`;
}

function deleteTurn(t) {
  const hasContent = t.input || t.anon || t.reply || t.restored;
  if (hasContent && !confirm(`Delete ${t.name}? It will be removed from memory.`)) return;
  const idx = session.turns.indexOf(t);
  if (idx < 0) return;
  session.turns.splice(idx, 1);
  if (!session.turns.length) session.turns.push(newTurn());
  if (current === t) {
    const next = session.turns[Math.min(idx, session.turns.length - 1)] || session.turns[0];
    selectTurn(next);
  } else {
    renderTurnList();
  }
  toast("Turn deleted");
}

// --------------------------------------------------------------------------- //
// Scan + preview
// --------------------------------------------------------------------------- //
const scanDebounced = debounce(() => runScan(), 320);

function allTypes() { return CATALOG.map((e) => e.type); }
function enabledEntities() {
  // Always return an explicit list: passing entities=None makes Presidio drop
  // some NER hits (notably PERSON), so we send the full allow-list even for
  // "all". `selectedTypes` (the per-turn combo) narrows it; the legend's
  // disabledTypes removes individual types on top.
  const base = current.selectedTypes ? [...current.selectedTypes] : allTypes();
  return base.filter((t) => !current.disabledTypes.has(t));
}

// Per-turn "what to detect" combo: a dropdown of every entity type, grouped by
// family. Default = all (sent as an explicit list so PERSON is not dropped).
function buildTypeCombo() {
  const row = D["btn-anon"].closest(".step-actions");
  if (!row || $("type-combo") || !CATALOG.length) return;
  const wrap = el("div", "type-combo"); wrap.id = "type-combo";
  const btn = el("button", "btn btn-small"); btn.id = "type-combo-btn"; btn.type = "button";
  btn.textContent = "Detect: all ▾"; btn.title = "Choose which PII types to detect in this turn";
  const panel = el("div", "type-combo-panel"); panel.id = "type-combo-panel"; panel.hidden = true;

  const head = el("div", "tc-head");
  head.appendChild(el("span", null, "Detect in this turn"));
  const quick = el("span", "tc-quick");
  const bAll = el("button", null, "All"); bAll.type = "button";
  const bNone = el("button", null, "None"); bNone.type = "button";
  quick.appendChild(bAll); quick.append(" · "); quick.appendChild(bNone);
  head.appendChild(quick); panel.appendChild(head);

  const groups = {}; const order = [];
  for (const e of CATALOG) { if (!groups[e.family]) { groups[e.family] = []; order.push(e.family); } groups[e.family].push(e); }
  const gwrap = el("div", "tc-groups");
  for (const fam of order) {
    const g = el("div", "tc-group");
    const lbl = el("div", "tc-group-label");
    const sw = el("span", "swatch"); sw.style.background = "var(--ent-" + fam + ")"; lbl.appendChild(sw);
    lbl.append(fam); g.appendChild(lbl);
    for (const e of groups[fam]) {
      const lab = el("label", "tc-item");
      const cb = el("input"); cb.type = "checkbox"; cb.dataset.type = e.type; cb.checked = true;
      cb.addEventListener("change", onTypeToggle);
      lab.appendChild(cb); lab.append(" " + e.label);
      g.appendChild(lab);
    }
    gwrap.appendChild(g);
  }
  panel.appendChild(gwrap);
  wrap.appendChild(btn); wrap.appendChild(panel);
  row.insertBefore(wrap, row.firstChild);

  btn.addEventListener("click", (ev) => { ev.stopPropagation(); panel.hidden = !panel.hidden; });
  bAll.addEventListener("click", () => { current.selectedTypes = null; renderTypeCombo(); runScan(); });
  bNone.addEventListener("click", () => { current.selectedTypes = new Set(); renderTypeCombo(); runScan(); });
  document.addEventListener("click", (ev) => { if (!wrap.contains(ev.target)) panel.hidden = true; });
}

function onTypeToggle() {
  const boxes = [...document.querySelectorAll("#type-combo-panel input[type=checkbox]")];
  const checked = boxes.filter((b) => b.checked).map((b) => b.dataset.type);
  current.selectedTypes = (checked.length === boxes.length) ? null : new Set(checked);
  renderTypeCombo();
  runScan();
}

function renderTypeCombo() {
  if (!$("type-combo") || !current) return;
  const boxes = [...document.querySelectorAll("#type-combo-panel input[type=checkbox]")];
  const sel = current.selectedTypes;
  for (const b of boxes) b.checked = sel ? sel.has(b.dataset.type) : true;
  const n = sel ? sel.size : boxes.length;
  $("type-combo-btn").textContent =
    "Detect: " + (sel ? (n === 0 ? "none" : n + " type" + (n > 1 ? "s" : "")) : "all") + " ▾";
}

async function runScan() {
  if (!current) return;
  const text = D.input.value;
  current.input = text;
  if (!text.trim()) { current.detections = []; current.scannedText = ""; renderDetections(); updateSmartPills(); return; }
  if (D.btn_anon_down) { D["detect-summary"].textContent = "Detector offline — highlighting unavailable (Restore still works)."; return; }
  try {
    const body = { text, language: D["lang-select"].value, threshold: Number(D.thresh.value),
                   entities: enabledEntities() };
    const res = await api("POST", "/api/scan", body);
    current.detections = res.entities || [];
    current.scannedText = text;
    current.langUsed = res.language_used;
    renderDetections();
    updateSmartPills();
  } catch (e) {
    if (e.status === 503) D["detect-summary"].textContent = "Detector offline — Restore still works.";
    else D["detect-summary"].textContent = "scan error: " + e.message;
  }
}

function activeDetections() {
  // detections not excluded by occurrence; type filtering already applied server-side
  return current.detections.filter((d) => !current.excluded.has(d.start + ":" + d.end));
}

function renderDetections() {
  const t = current;
  const dets = t.detections;
  const active = activeDetections();
  const byType = {};
  for (const d of active) byType[d.entity_type] = (byType[d.entity_type] || 0) + 1;
  const nAll = dets.length, nActive = active.length + t.manual.length;

  if (!D.input.value.trim()) {
    D["detect-summary"].textContent = "";
    D["preview-details"].hidden = true;
    updateAnonCount(0);
    return;
  }
  const parts = [];
  parts.push(`<b>${nActive}</b> will be protected`);
  if (nAll !== active.length) parts.push(`${nAll - active.length} excluded`);
  if (t.manual.length) parts.push(`${t.manual.length} manual`);
  D["detect-summary"].innerHTML = nActive || nAll ? parts.join(" · ")
    : "No PII detected. Lower the confidence threshold or mark text manually.";

  // legend
  D.legend.innerHTML = "";
  const types = Object.keys(byType).sort();
  const disabledPresent = new Set();
  for (const d of dets) if (t.disabledTypes.has(d.entity_type)) disabledPresent.add(d.entity_type);
  for (const ty of [...new Set([...types, ...disabledPresent])].sort()) {
    const fam = FAMILY[ty] || "temporal";
    const off = t.disabledTypes.has(ty);
    const item = el("span", "legend-item fam-" + fam + (off ? " off" : ""));
    const sw = el("span", "swatch"); sw.style.background = "var(--ent-" + fam + ")";
    item.appendChild(sw);
    item.appendChild(el("span", null, ENTITY_LABEL[ty] || ty));
    item.appendChild(el("span", "cnt", " " + (byType[ty] || 0)));
    item.title = "Click to " + (off ? "include" : "exclude") + " all " + ty;
    item.addEventListener("click", (ev) => {
      if (ev.target.tagName === "SELECT") return;
      if (off) t.disabledTypes.delete(ty); else t.disabledTypes.add(ty);
      runScan();
    });
    // per-entity operator override
    const sel = el("select", "per-op");
    for (const [v, lbl] of [["", "op: default"], ["encrypt", "encrypt"], ["replace", "replace"],
                            ["redact", "redact"], ["mask", "mask"], ["hash", "hash"]]) {
      const o = el("option", null, lbl); o.value = v; sel.appendChild(o);
    }
    sel.value = t.perEntity[ty] || "";
    sel.title = "Operator override for " + ty;
    sel.addEventListener("click", (e) => e.stopPropagation());
    sel.addEventListener("change", () => {
      if (sel.value) t.perEntity[ty] = sel.value; else delete t.perEntity[ty];
    });
    item.appendChild(sel);
    D.legend.appendChild(item);
  }

  // preview (code-point aware)
  const text = D.input.value;
  const cps = Array.from(text);
  const marks = [...active.map((d) => ({ ...d, manual: false })),
                 ...t.manual.map((m) => ({ entity_type: m[2], start: m[0], end: m[1], manual: true })),
                 ...dets.filter((d) => current.excluded.has(d.start + ":" + d.end))
                        .map((d) => ({ ...d, excluded: true }))]
                .sort((a, b) => a.start - b.start || a.end - b.end);
  let html = "", pos = 0;
  for (const m of marks) {
    if (m.start < pos) continue; // skip overlaps in preview
    html += esc(cpSlice(cps, pos, m.start));
    const fam = FAMILY[m.entity_type] || "temporal";
    const cls = "ent fam-" + fam + (m.excluded ? " excluded" : "");
    const title = (ENTITY_LABEL[m.entity_type] || m.entity_type) +
      (m.score != null ? " · " + m.score : "") + (m.manual ? " · manual" : "") +
      " — click to " + (m.excluded ? "include" : "exclude");
    html += `<mark class="${cls}" data-s="${m.start}" data-e="${m.end}" title="${esc(title)}">` +
            esc(cpSlice(cps, m.start, m.end)) + "</mark>";
    pos = m.end;
  }
  html += esc(cpSlice(cps, pos, cps.length));
  D.preview.innerHTML = html;
  D.preview.querySelectorAll("mark.ent").forEach((mk) => {
    mk.addEventListener("click", () => {
      const key = mk.dataset.s + ":" + mk.dataset.e;
      if (current.excluded.has(key)) current.excluded.delete(key); else current.excluded.add(key);
      renderDetections();
    });
  });
  D["preview-details"].hidden = false;
  updateAnonCount(nActive);
}

function updateAnonCount(n) {
  D["btn-anon"].textContent = n ? `Anonymize ${n} ⏎` : "Anonymize ⏎";
}

// --------------------------------------------------------------------------- //
// Anonymize
// --------------------------------------------------------------------------- //
async function doAnonymize() {
  if (!current) return;
  syncFromDOM();
  const text = current.input;
  if (!text.trim()) { toast("Nothing to anonymize."); return; }
  const op = D.operator.value;
  // ensure a fresh scan of the exact text so exclusions/manual align server-side
  if (current.scannedText !== text) await runScan();
  const body = {
    text, operator: op,
    language: current.langUsed || D["lang-select"].value,
    threshold: Number(D.thresh.value),
    per_entity: current.perEntity,
  };
  body.entities = enabledEntities();
  const excl = [...current.excluded].map((k) => k.split(":").map(Number));
  if (excl.length) body.exclude_spans = excl;
  if (current.manual.length) body.include_spans = current.manual;
  D["btn-anon"].disabled = true;
  try {
    const res = await api("POST", "/api/anonymize", body);
    current.anon = res.text;
    current.emittedTokens = res.text.match(TOKEN_RE) || [];
    current.langUsed = res.language_used;
    current.operator = op;
    current.keyFp = res.reversible ? KEY_FP : null;
    current.status = "anon";
    D.anon.value = res.text;
    D["btn-copy-anon"].disabled = !res.text;
    D["btn-copy-bt"].disabled = !res.text;
    renderTurnMeta(); renderTurnList();
    // self-verify round trip
    if (res.reversible) {
      selfVerify(res.text, res.entities_found);
      maybeShowGuardrail();
    } else {
      D.selfcheck.hidden = false;
      D.selfcheck.className = "selfcheck bad";
      D.selfcheck.textContent = "⚠ one-way operator — this cannot be restored later.";
    }
    const found = res.entities_found.length ? res.entities_found.join(", ") : "none";
    toast(`Protected ${res.count} value(s): ${found}`);
    if (PREFS.autocopy !== false && D.autocopy.checked && res.text) {
      copyBackticks(res.text, true);
    }
  } catch (e) {
    if (e.code === "no_key") { toast("No key — generate one first.", true); flashKeyChip(); }
    else if (e.status === 503) { toast("Detector offline — cannot anonymize.", true); }
    else toast("Anonymize failed: " + e.message, true);
  } finally {
    updateAnonEnabled();
  }
}

async function selfVerify(anonText, found) {
  try {
    const res = await api("POST", "/api/decrypt", { text: anonText });
    const ok = res.restored === (anonText.match(TOKEN_RE) || []).length && res.restored > 0;
    D.selfcheck.hidden = false;
    D.selfcheck.className = "selfcheck " + (ok ? "ok" : "bad");
    D.selfcheck.textContent = ok
      ? `✓ reversible verified — ${res.restored} token(s) restore cleanly`
      : `⚠ self-check restored ${res.restored}/${(anonText.match(TOKEN_RE) || []).length}`;
  } catch (_) { D.selfcheck.hidden = true; }
}

function maybeShowGuardrail() {
  if (seenGuardrail || PREFS.guardrailDismissed) return;
  seenGuardrail = true;
  D.guardrail.hidden = false;
}

// --------------------------------------------------------------------------- //
// Decrypt / restore
// --------------------------------------------------------------------------- //
async function doDecrypt() {
  if (!current) return;
  syncFromDOM();
  const text = current.reply || D.reply.value;
  if (!text.trim()) { toast("Paste Claude's reply first."); return; }
  if (!hasKey()) { toast("No key — generate one first.", true); flashKeyChip(); return; }
  D["btn-decrypt"].disabled = true;
  try {
    const res = await api("POST", "/api/decrypt", { text });
    current.restored = res.text;
    current.integrity = { ...res.integrity, tokens_seen: res.tokens_seen, restored: res.restored,
                          _warn: res.restored < res.tokens_seen };
    current.status = "restored";
    D.restored.value = res.text;
    D["btn-copy-restored"].disabled = !res.text;
    renderIntegrity(current.integrity, current);
    renderTurnList();
  } catch (e) {
    toast("Restore failed: " + e.message, true);
  } finally {
    D["btn-decrypt"].disabled = false;
  }
}

function renderIntegrity(ig, turn) {
  const box = D.integrity;
  if (!ig) { box.hidden = true; return; }
  box.hidden = false;
  const seen = ig.tokens_seen, restored = ig.restored;
  // gather unrestored: strict tokens still present in restored text + malformed fragments
  const stillStrict = (turn.restored.match(TOKEN_RE) || []);
  const unrestored = [
    ...stillStrict.map((tk) => ({ token: tk, reason: "auth-failed" })),
    ...(ig.malformed || []).map((m) => ({ token: m.token, reason: m.reason, entity_type: m.entity_type })),
  ];

  let cls, head;
  if (seen === 0) { cls = "info"; head = "○ No tokens found — nothing to restore. Did you paste Claude's reply?"; }
  else if (ig.wrong_key_suspected) {
    cls = "bad";
    head = `✗ 0 / ${seen} restored — these look like your tokens but the key doesn't match.`;
  } else if (unrestored.length === 0) {
    cls = ig.repaired ? "info" : "ok";
    head = `✓ ${restored} / ${seen} tokens restored` + (ig.repaired ? ` (${ig.repaired} auto-repaired)` : "");
  } else {
    cls = "warn";
    head = `⚠ ${restored} restored · ${unrestored.length} could not be restored`;
  }
  box.className = "integrity " + cls;
  box.innerHTML = "";
  box.appendChild(el("div", "ig-head", head));

  if (ig.wrong_key_suspected) {
    const b = el("div", "ig-body");
    b.append("Did the key change since an earlier turn? ");
    const btn = el("button", "btn btn-small", "Open key");
    btn.addEventListener("click", flashKeyChip);
    b.appendChild(btn);
    box.appendChild(b);
  }

  if (unrestored.length) {
    const body = el("div", "ig-body");
    for (const f of unrestored) {
      const row = el("div", "ig-fail");
      const near = nearestEmitted(f.token, turn.emittedTokens);
      let msg = reasonText(f.reason);
      if (near && near.dist <= 6) msg += ` — looks like your ${entityOf(near.token)} token, altered by ${near.dist} char(s).`;
      row.appendChild(el("span", null, msg));
      const frag = el("span", "frag", f.token.length > 42 ? f.token.slice(0, 40) + "…" : f.token);
      row.appendChild(frag);
      if (near) {
        const btn = el("button", "btn btn-small", "⧉ Correct token");
        btn.title = "Copy the intact token so you can ask Claude to reproduce it verbatim";
        btn.addEventListener("click", async () => {
          (await copyText(near.token)) ? toast("Correct token copied") : toast("Copy failed", true);
        });
        row.appendChild(btn);
      }
      body.appendChild(row);
    }
    box.appendChild(body);
    const tip = el("div", "ig-body");
    tip.style.marginTop = "8px";
    tip.append("Tell Claude to keep the ");
    const c = el("code", null, "<ENC:…>"); tip.appendChild(c);
    tip.append(" tokens verbatim (in backticks) so they restore cleanly.");
    box.appendChild(tip);
  }
}

function reasonText(r) {
  return ({
    "auth-failed": "Token altered or wrong key",
    "interior-whitespace": "Token was line-wrapped",
    "no-closing-bracket": "Token was cut off (missing '>')",
    "bad-charset": "Token has stray characters",
    "truncated-payload": "Token is truncated",
  })[r] || "Token could not be restored";
}
function entityOf(token) {
  const m = /^<ENC:([A-Z0-9_]+):/.exec(token);
  return m ? (ENTITY_LABEL[m[1]] || m[1]) : "protected";
}
function nearestEmitted(token, emitted) {
  let best = null;
  for (const e of emitted || []) {
    const d = levenshtein(token, e);
    if (!best || d < best.dist) best = { token: e, dist: d };
  }
  return best;
}

// --------------------------------------------------------------------------- //
// Copy helpers
// --------------------------------------------------------------------------- //
function withBackticks(text) {
  return text.replace(TOKEN_RE, (m) => "`" + m + "`");
}
async function copyPlain(text) {
  (await copyText(text)) ? toast("Copied — paste into Claude Desktop") : toast("Copy failed", true);
}
async function copyBackticks(text, silent) {
  const ok = await copyText(withBackticks(text));
  if (!silent) ok ? toast("Copied with backticks — paste into Claude") : toast("Copy failed", true);
  else if (ok) toast("Copied — paste into Claude Desktop");
}

// --------------------------------------------------------------------------- //
// Smart-box pills
// --------------------------------------------------------------------------- //
function updateSmartPills() {
  const inTokens = (D.input.value.match(TOKEN_RE) || []).length;
  const p1 = D["smart-pill-1"];
  if (inTokens > 0) {
    p1.hidden = false;
    p1.innerHTML = `<span>This looks already anonymized (${inTokens} token${inTokens>1?"s":""}). Did you mean Restore?</span>`;
    const b = el("button", "btn btn-small", "Restore instead");
    b.addEventListener("click", () => {
      D.reply.value = D.input.value; current.reply = D.input.value;
      D.input.value = ""; current.input = "";
      updateSmartPills(); doDecrypt();
    });
    p1.appendChild(b);
  } else p1.hidden = true;

  const rep = D.reply.value;
  const repTokens = (rep.match(TOKEN_RE) || []).length;
  const p3 = D["smart-pill-3"];
  if (rep.trim() && repTokens === 0) {
    p3.hidden = false;
    p3.innerHTML = "<span>No <code>&lt;ENC:…&gt;</code> tokens found here — nothing to restore.</span>";
  } else p3.hidden = true;
}

// --------------------------------------------------------------------------- //
// Key management
// --------------------------------------------------------------------------- //
async function keyChipClick() {
  if (!hasKey()) {
    if (!confirm("Generate a new encryption key?\nIt is stored at ~/.config/blackbar/key (0600) and never shown here. Keep it safe — without it, encrypted values cannot be restored.")) return;
    try {
      const res = await api("POST", "/api/key/generate", {});
      toast("Key generated · " + res.fingerprint);
      await refreshHealth();
    } catch (e) {
      if (e.code === "key_exists") { await refreshHealth(); toast("A key already exists."); }
      else toast("Key generation failed: " + e.message, true);
    }
  } else {
    if (!confirm("Rotate the key?\nText encrypted with the CURRENT key will no longer decrypt. Back up ~/.config/blackbar/key first if you still need it.")) return;
    try {
      const res = await api("POST", "/api/key/rotate", { force: true });
      toast("Key rotated · " + res.fingerprint);
      await refreshHealth();
    } catch (e) { toast("Rotate failed: " + e.message, true); }
  }
}
function flashKeyChip() {
  const c = $("key-chip");
  c.style.outline = "2px solid var(--danger)";
  setTimeout(() => { c.style.outline = ""; }, 1600);
}

// --------------------------------------------------------------------------- //
// Audit dialog
// --------------------------------------------------------------------------- //
async function openAudit() {
  const dlg = $("audit-dialog"), body = $("audit-body");
  body.innerHTML = "Loading…";
  dlg.showModal();
  try {
    const s = await api("GET", "/api/audit/stats");
    body.innerHTML = "";
    if (!s.enabled) {
      body.appendChild(el("p", "muted",
        "The audit trail is off. Enable it by starting the app with BLACKBAR_AUDIT_ENABLED=1. " +
        "It records PII-safe metadata only (entity types, counts, salted fingerprints, redacted text) — never raw PII or tokens."));
      return;
    }
    for (const [k, v] of [["Records", s.records], ["Files", s.files],
                          ["Retention (days)", s.retention_days], ["Size (bytes)", s.bytes]]) {
      const row = el("div", "audit-stat");
      row.appendChild(el("span", null, k)); row.appendChild(el("b", null, String(v)));
      body.appendChild(row);
    }
    // latest day records
    const days = s.days || [];
    if (days.length) {
      const day = days[days.length - 1].replace("pii-audit-", "").replace(".jsonl", "");
      const rec = await api("GET", "/api/audit/records?day=" + encodeURIComponent(day) + "&limit=40");
      body.appendChild(el("h3", "muted", "Latest: " + day));
      for (const r of rec.records || []) {
        const line = `${r.ts || ""} ${r.event || ""} ${r.source || ""} ` +
          (r.n_entities != null ? "n=" + r.n_entities : (r.n_transformed != null ? "×" + r.n_transformed : "")) +
          (r.entities ? " [" + r.entities.map((e) => e.type).join(",") + "]" : "");
        body.appendChild(el("div", "audit-rec", line));
      }
    }
    const tools = el("div"); tools.style.marginTop = "12px";
    const prune = el("button", "btn btn-small", "Prune old");
    prune.addEventListener("click", async () => { await api("POST", "/api/audit/prune", {}); toast("Pruned"); openAudit(); });
    const purge = el("button", "btn btn-small btn-danger", "Purge all");
    purge.style.marginLeft = "8px";
    purge.addEventListener("click", async () => {
      if (confirm("Delete ALL audit files?")) { await api("POST", "/api/audit/purge", { confirm: true }); toast("Purged"); openAudit(); }
    });
    tools.appendChild(prune); tools.appendChild(purge);
    body.appendChild(tools);
  } catch (e) { body.innerHTML = ""; body.appendChild(el("p", "muted", "Audit error: " + e.message)); }
}

// --------------------------------------------------------------------------- //
// Export / import (tokens only)
// --------------------------------------------------------------------------- //
function exportTokens() {
  syncFromDOM();
  const data = {
    tool: "blackbar-web", version: HEALTH ? HEALTH.version : "?",
    key_fingerprint: KEY_FP,
    turns: session.turns.map((t) => ({
      name: t.name, operator: t.operator, language: t.langUsed,
      anonymized: t.anon, reply_tokenized: (t.reply.match(TOKEN_RE) || []).length ? t.reply : "",
      entities_found: [...new Set(t.emittedTokens.map((tk) => (/^<ENC:([A-Z0-9_]+):/.exec(tk) || [])[1]).filter(Boolean))],
      integrity: t.integrity ? { restored: t.integrity.restored, tokens_seen: t.integrity.tokens_seen } : null,
    })),
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "blackbar-session-tokens.json";
  a.click();
  URL.revokeObjectURL(a.href);
  toast("Exported tokens only (no real PII)");
}

function importTokens(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(reader.result);
      if (!data.turns) throw new Error("not a blackbar session file");
      session.turns = [];
      seq = 0;
      for (const t of data.turns) {
        const nt = newTurn();
        nt.name = t.name || nt.name;
        nt.operator = t.operator || "encrypt";
        nt.langUsed = t.language || null;
        nt.anon = t.anonymized || "";
        nt.emittedTokens = nt.anon.match(TOKEN_RE) || [];
        nt.reply = t.reply_tokenized || "";
        nt.status = nt.anon ? "anon" : "empty";
        session.turns.push(nt);
      }
      if (!session.turns.length) session.turns.push(newTurn());
      selectTurn(session.turns[0]);
      if (data.key_fingerprint && KEY_FP && data.key_fingerprint !== KEY_FP)
        toast("Imported — note: this session used a different key (" + data.key_fingerprint + ")", true);
      else toast("Session imported (tokens only)");
    } catch (e) { toast("Import failed: " + e.message, true); }
  };
  reader.readAsText(file);
}

// --------------------------------------------------------------------------- //
// Document extraction (drag/drop + picker)
// --------------------------------------------------------------------------- //
async function extractFile(file) {
  if (file.size > 25 * 1024 * 1024) { toast("File too large (25 MiB max).", true); return; }
  const ext = (file.name.split(".").pop() || "").toLowerCase();
  if (ext === "pdf" && !PDF_OK) { toast("PDF support not installed: pip install -r web/requirements-docs.txt", true); return; }
  toast("Extracting " + file.name + "…");
  try {
    const buf = await file.arrayBuffer();
    const res = await api("POST", "/api/extract", buf, { raw: true, filename: file.name });
    if (!res.text.trim()) { toast((res.warnings && res.warnings[0]) || "No text found in document.", true); return; }
    D.input.value = res.text;
    current.input = res.text;
    runScan();
    updateSmartPills();
    let msg = `Loaded ${res.chars} chars from ${res.kind}`;
    if (res.truncated) msg += " (truncated)";
    if (res.warnings && res.warnings.length) msg += " · " + res.warnings[0];
    toast(msg);
  } catch (e) {
    if (e.code === "pdf_optional") toast("PDF support not installed: " + e.hint, true);
    else toast("Extract failed: " + e.message, true);
  }
}

// --------------------------------------------------------------------------- //
// Theme + panic
// --------------------------------------------------------------------------- //
function applyTheme(theme) {
  if (theme === "light" || theme === "dark") document.documentElement.setAttribute("data-theme", theme);
  else document.documentElement.removeAttribute("data-theme");
}
function toggleTheme() {
  const cur = document.documentElement.getAttribute("data-theme");
  const dark = cur ? cur === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  PREFS.theme = next; savePrefs(); applyTheme(next);
}
async function panic() {
  session = { turns: [newTurn()] };
  current = null;
  ["input","anon","reply","restored"].forEach((k) => { D[k].value = ""; });
  selectTurn(session.turns[0]);
  await copyText("").catch(() => {});
  toast("Wiped — nothing left in memory");
}

// --------------------------------------------------------------------------- //
// Events
// --------------------------------------------------------------------------- //
function onOperatorChange() {
  const op = D.operator.value;
  D["op-warning"].hidden = op === "encrypt";
  if (current) current.operator = op;
  PREFS.operator = op; savePrefs();
  updateAnonEnabled();
}

function wireEvents() {
  D.input.addEventListener("input", () => { current.input = D.input.value; current.scannedText = null; scanDebounced(); updateSmartPills(); });
  D.reply.addEventListener("input", () => { current.reply = D.reply.value; updateSmartPills(); });
  D.thresh.addEventListener("input", () => { D["thresh-out"].textContent = Number(D.thresh.value).toFixed(2); PREFS.threshold = Number(D.thresh.value); savePrefs(); scanDebounced(); });
  D.operator.addEventListener("change", onOperatorChange);
  D["lang-select"].addEventListener("change", () => { PREFS.language = D["lang-select"].value; savePrefs(); runScan(); });
  D["btn-anon"].addEventListener("click", doAnonymize);
  D["btn-decrypt"].addEventListener("click", doDecrypt);
  D["btn-copy-anon"].addEventListener("click", () => copyPlain(current.anon));
  D["btn-copy-bt"].addEventListener("click", () => copyBackticks(current.anon));
  D["btn-copy-restored"].addEventListener("click", async () =>
    (await copyText(current.restored)) ? toast("Copied restored text (contains real PII)") : toast("Copy failed", true));
  D.autocopy.addEventListener("change", () => { PREFS.autocopy = D.autocopy.checked; savePrefs(); });
  D["btn-guardrail"].addEventListener("click", async () => {
    const prompt = "The bracketed <ENC:…> tokens are protected placeholders for private data. " +
      "Reproduce any you reference exactly, character-for-character, inside backticks. " +
      "Never rewrite, translate, summarize, or split them.";
    (await copyText(prompt)) ? toast("Guardrail prompt copied") : toast("Copy failed", true);
  });
  D["btn-guardrail-x"].addEventListener("click", () => { D.guardrail.hidden = true; PREFS.guardrailDismissed = true; savePrefs(); });
  $("key-chip").addEventListener("click", keyChipClick);
  $("analyzer-chip").addEventListener("click", refreshAnalyzerDot);
  $("btn-new-turn").addEventListener("click", () => { const t = newTurn(); session.turns.push(t); selectTurn(t); D.input.focus(); });
  $("btn-theme").addEventListener("click", toggleTheme);
  $("btn-help").addEventListener("click", () => $("help-dialog").showModal());
  $("btn-audit").addEventListener("click", openAudit);
  $("btn-panic").addEventListener("click", panic);
  $("btn-export").addEventListener("click", exportTokens);
  $("btn-import").addEventListener("click", () => D["import-file"].click());
  D["import-file"].addEventListener("change", (e) => { if (e.target.files[0]) importTokens(e.target.files[0]); e.target.value = ""; });

  // drag & drop
  const dz = D.dropzone;
  ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); if (ev === "drop" || e.target === dz) dz.classList.remove("dragging"); }));
  dz.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) extractFile(f); });

  // keyboard
  let lastEsc = 0;
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      if (document.activeElement === D.reply) doDecrypt(); else doAnonymize();
    } else if ((e.metaKey || e.ctrlKey) && (e.key === "n" || e.key === "N")) {
      e.preventDefault(); const t = newTurn(); session.turns.push(t); selectTurn(t); D.input.focus();
    } else if (e.key === "Escape") {
      const now = Date.now();
      if (now - lastEsc < 600) panic();
      lastEsc = now;
    } else if (e.key === "?" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) {
      $("help-dialog").showModal();
    }
  });
}

boot();
