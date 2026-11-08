"use strict";

const $ = (id) => document.getElementById(id);
let lastResponse = null;

const STATUS_BADGES = [
  "VERIFIED",
  "VERIFIED_DERIVED",
  "INCOMPLETE",
  "CONFLICT",
  "NOT_AVAILABLE",
  "ERROR",
];

const HTML_ESCAPES = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function escapeHtml(value) {
  return String(value === null || value === undefined ? "" : value).replace(
    /[&<>"']/g,
    (ch) => HTML_ESCAPES[ch]
  );
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function num(value, fallback) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function statusClass(status) {
  return STATUS_BADGES.includes(status) ? status : "NOT_AVAILABLE";
}

function textList(items, cls) {
  const list = el("ul", cls);
  for (const item of items) list.appendChild(el("li", null, item));
  return list;
}

async function loadParsers() {
  try {
    const res = await fetch("/api/parsers");
    const data = await res.json();
    const table = $("parser-table");
    table.replaceChildren();
    const head = el("tr");
    ["Engine", "Status", "Detail"].forEach((h) => head.appendChild(el("th", null, h)));
    table.appendChild(head);
    for (const p of data.parsers) {
      const row = el("tr");
      row.appendChild(el("td", null, `${p.name} (${p.engine})`));
      row.appendChild(el("td", null, p.available ? "AVAILABLE" : "UNAVAILABLE"));
      row.appendChild(el("td", null, p.message || ""));
      table.appendChild(row);
    }
    $("parsers").classList.remove("hidden");
    if (!data.strict_three_engine_ready) {
      setStatus(
        `${data.available_count}/3 engines available — strict 3/3 verification is limited.`,
        "error"
      );
    }
  } catch (e) {
    /* non-fatal */
  }
}

function setStatus(text, kind) {
  const s = $("status");
  s.textContent = text;
  s.className = "status" + (kind ? " " + kind : "");
}

function describeFile(file) {
  if (!file) return "";
  const kb = (file.size / 1024).toFixed(1);
  return `${file.name} — ${kb} KB`;
}

async function analyze() {
  const fileInput = $("file");
  const file = fileInput.files[0];
  if (!file) {
    setStatus("Choose a .pka or .pkt file first.", "error");
    return;
  }
  const questions = $("questions").value.trim();
  if (!questions) {
    setStatus("Paste at least one question.", "error");
    return;
  }

  const form = new FormData();
  form.append("file", file);
  form.append("questions", questions);
  form.append("use_ai", $("useai").checked ? "true" : "false");

  $("analyze").disabled = true;
  setStatus("Analyzing… parsing once, then evaluating all questions.", "busy");
  const started = performance.now();

  try {
    const res = await fetch("/api/analyze", { method: "POST", body: form });
    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try {
        const err = await res.json();
        detail = err.detail || detail;
      } catch (_) {}
      throw new Error(detail);
    }
    const data = await res.json();
    lastResponse = data;
    const secs = ((performance.now() - started) / 1000).toFixed(1);
    render(data);
    setStatus(`Done in ${secs}s — ${data.results.length} question(s).`, "");
  } catch (err) {
    setStatus(`Failed: ${err.message}`, "error");
  } finally {
    $("analyze").disabled = false;
  }
}

function render(data) {
  renderMeta(data);
  renderResultsHeader(data);
  const root = $("results");
  root.replaceChildren();
  const meta = {
    snapshot_id: data.snapshot_id || "—",
    snapshot_ambiguous: Boolean(data.snapshot_ambiguous),
  };
  for (const r of data.results) {
    root.appendChild(renderResult(r, meta));
  }
  $("toolbar").classList.remove("hidden");
  loadParsers();
}

function renderResultsHeader(data) {
  const header = $("results-header");
  const summary = $("results-summary");
  const caveat = $("decoder-caveat");
  const results = data.results || [];
  const total = results.length;
  const counts = {};
  for (const r of results) {
    counts[r.status] = (counts[r.status] || 0) + 1;
  }
  const parts = STATUS_BADGES.filter((s) => counts[s]).map(
    (s) => `${counts[s]} ${s.toLowerCase().replace(/_/g, " ")}`
  );
  summary.textContent =
    `${total} question${total === 1 ? "" : "s"}` + (parts.length ? " — " + parts.join(", ") : "");
  const shared =
    results.some((r) => (r.consensus || {}).crypto_shared === true) ||
    (data.network_summary || {}).crypto_shared === true;
  caveat.classList.toggle("hidden", !(shared && total > 0));
  header.classList.remove("hidden");
}

function renderMeta(data) {
  const box = $("meta");
  const pre = $("meta-body");
  const lines = [];
  lines.push(`File:      ${data.file_name}`);
  lines.push(`SHA-256:   ${data.file_sha256}`);
  lines.push(`Bytes:     ${data.file_bytes}`);
  lines.push(`Snapshot:  ${data.snapshot_id}${data.snapshot_ambiguous ? "  (AMBIGUOUS — see notes)" : ""}`);
  lines.push(`Policy:    ${data.consensus_policy}`);
  lines.push(`AI used:   ${data.ai_used ? "yes" : "no"}`);
  for (const n of data.snapshot_notes || []) lines.push(`Snapshot note: ${n}`);
  lines.push("");
  lines.push("Engines:");
  for (const p of data.parsers) {
    lines.push(
      `  ${p.engine.padEnd(9)} ${p.state.padEnd(12)} devices=${p.device_count} links=${p.link_count} ` +
        `${p.duration_ms}ms  ${p.message}`
    );
  }
  lines.push("");
  lines.push("Network model:");
  for (const [k, v] of Object.entries(data.network_summary || {})) {
    if (k === "conflicts") continue;
    lines.push(`  ${k}: ${JSON.stringify(v)}`);
  }
  const conflicts = (data.network_summary || {}).conflicts || [];
  if (conflicts.length) {
    lines.push("");
    lines.push("Field conflicts:");
    for (const c of conflicts) lines.push(`  ! ${c}`);
  }
  if ((data.warnings || []).length) {
    lines.push("");
    lines.push("Warnings:");
    for (const w of data.warnings) lines.push(`  - ${w}`);
  }
  pre.textContent = lines.join("\n");
  box.classList.remove("hidden");
}

function renderResult(r, meta) {
  const status = statusClass(r.status);
  const box = el("div", `result ${status}`);
  const cons = r.consensus || {};

  const head = el("div", "result-head");
  head.appendChild(el("span", "qnum", `Q${r.question_number}`));
  head.appendChild(el("span", `badge ${status}`, status));

  const agree = num(cons.agree, 0);
  const required = num(cons.required, 3);
  const available = num(cons.available, agree);
  head.appendChild(el("span", "meta-line families", `${agree}/${required} families`));
  if (available !== agree) {
    head.appendChild(el("span", "meta-line families", `${available} available`));
  }
  head.appendChild(
    el(
      "span",
      "meta-line snapshot",
      `snapshot ${meta.snapshot_id}${meta.snapshot_ambiguous ? " (ambiguous)" : ""}`
    )
  );
  box.appendChild(head);

  box.appendChild(el("div", "qtext", r.original_question));

  if (r.answer !== null && r.answer !== undefined && r.answer !== "") {
    const answer = el("div", "answer");
    if (r.selected_options && r.selected_options.length) {
      answer.appendChild(el("span", "letter", `${r.selected_options.join(", ")}` + " — "));
    }
    answer.appendChild(document.createTextNode(r.answer));
    box.appendChild(answer);
  }

  if (r.explanation) box.appendChild(el("div", "explain", r.explanation));

  const conflicts = r.conflicts || [];
  const missing = r.missing_evidence || [];
  if (conflicts.length || missing.length) {
    const issues = el("section", "issues");
    if (conflicts.length) {
      issues.appendChild(el("h3", "issues-title conflict", "Conflicts"));
      issues.appendChild(textList(conflicts, "issue-list conflict-list"));
    }
    if (missing.length) {
      issues.appendChild(el("h3", "issues-title missing", "Missing evidence"));
      issues.appendChild(textList(missing, "issue-list missing-list"));
    }
    box.appendChild(issues);
  }

  if (r.manual_check) box.appendChild(el("div", "hint", `Manual check: ${r.manual_check}`));

  const evidence = Array.isArray(r.evidence) ? r.evidence : [];
  if (evidence.length) box.appendChild(renderEvidence(evidence));

  return box;
}

function renderEvidence(evidence) {
  const details = el("details", "evidence");
  details.appendChild(el("summary", null, `Evidence (${evidence.length})`));
  const body = el("div", "evidence-body");
  evidence.forEach((item) => body.appendChild(renderEvidenceItem(item)));
  details.appendChild(body);
  return details;
}

function renderEvidenceItem(e) {
  const item = el("div", "evidence-item");

  const head = el("div", "ev-head");
  if (e.device) head.appendChild(el("span", "ev-device", e.device));
  if (e.interface) head.appendChild(el("span", "ev-iface", e.interface));
  if (!e.device && !e.interface) head.appendChild(el("span", "ev-device", "network"));
  head.appendChild(el("span", "ev-field", e.field));
  item.appendChild(head);

  const valueRow = el("div", "ev-value");
  valueRow.appendChild(el("span", "ev-label", "value"));
  valueRow.appendChild(el("code", "ev-value-text", e.value));
  item.appendChild(valueRow);

  const sources = Array.isArray(e.sources) ? e.sources : [];
  if (sources.length) {
    const row = el("div", "ev-row");
    row.appendChild(el("span", "ev-label", "sources"));
    const chips = el("span", "ev-chips");
    for (const s of sources) chips.appendChild(el("span", "chip", s));
    row.appendChild(chips);
    item.appendChild(row);
  }

  const paths = Array.isArray(e.extraction_paths) ? e.extraction_paths : [];
  if (paths.length) {
    const row = el("div", "ev-row");
    row.appendChild(el("span", "ev-label", paths.length > 1 ? "extraction paths" : "extraction path"));
    const list = el("ul", "ev-paths");
    for (const p of paths) {
      const raw = String(p);
      const split = raw.indexOf(":");
      const family = split > 0 ? raw.slice(0, split) : raw;
      const step = split > 0 ? raw.slice(split + 1) : "";
      const entry = el("li");
      entry.appendChild(el("span", "family", family));
      if (step) entry.appendChild(el("span", "path", step));
      list.appendChild(entry);
    }
    row.appendChild(list);
    item.appendChild(row);
  }

  const raw = e.raw_evidence === null || e.raw_evidence === undefined ? "" : String(e.raw_evidence);
  if (raw) {
    const lines = raw.split(/\r?\n/).filter((line) => line.trim() !== "");
    let structural = lines.filter((line) => /TYPE\/@model|DEVICE\/ENGINE\/TYPE/.test(line));
    if (!structural.length && e.field === "hardware_model") {
      structural = ["DEVICE/ENGINE/TYPE/@model"];
    }
    if (structural.length) {
      const row = el("div", "ev-row structural");
      row.appendChild(el("span", "ev-label", "structural source"));
      const code = el("div", "structural-path");
      for (const line of structural) code.appendChild(el("code", null, line));
      row.appendChild(code);
      item.appendChild(row);
    }
    const pre = el("pre", "ev-raw");
    pre.textContent = raw;
    item.appendChild(pre);
  }

  return item;
}

/* ---------- exports ---------- */

function asPlainText(data) {
  const out = [];
  out.push("TRIDENT analysis");
  out.push(`File: ${data.file_name}`);
  out.push(`SHA-256: ${data.file_sha256}`);
  out.push(`Snapshot: ${data.snapshot_id}${data.snapshot_ambiguous ? " (ambiguous)" : ""}`);
  out.push("");
  for (const r of data.results) {
    out.push(`Q${r.question_number}. ${r.original_question.replace(/\s+/g, " ").trim()}`);
    out.push(`Status: ${r.status}`);
    if (r.selected_options && r.selected_options.length)
      out.push(`Selected: ${r.selected_options.join(", ")}`);
    if (r.answer) out.push(`Answer: ${r.answer}`);
    out.push(
      `Agreement: ${r.consensus.agree}/${r.consensus.available} (required ${r.consensus.required})`
    );
    if (r.explanation) out.push(`Explanation: ${r.explanation}`);
    for (const c of r.conflicts || []) out.push(`Conflict: ${c}`);
    for (const m of r.missing_evidence || []) out.push(`Missing: ${m}`);
    if (r.manual_check) out.push(`Manual check: ${r.manual_check}`);
    out.push("");
  }
  return out.join("\n");
}

function answersOnly(data) {
  return data.results
    .map((r) => {
      const sel = (r.selected_options || []).join("");
      const body = sel || r.answer || r.status;
      return `Q${r.question_number}: ${body} [${r.status}]`;
    })
    .join("\n");
}

function download(name, mime, text) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

$("analyze").addEventListener("click", analyze);

$("file").addEventListener("change", () => {
  $("fileinfo").textContent = describeFile($("file").files[0]);
});

$("copy").addEventListener("click", async () => {
  if (!lastResponse) return;
  try {
    await navigator.clipboard.writeText(answersOnly(lastResponse));
    setStatus("Answers copied to clipboard.", "");
  } catch (_) {
    setStatus("Clipboard unavailable; use Export text instead.", "error");
  }
});

$("export-json").addEventListener("click", () => {
  if (!lastResponse) return;
  download(`trident-${lastResponse.file_sha256.slice(0, 8)}.json`, "application/json",
    JSON.stringify(lastResponse, null, 2));
});

$("export-text").addEventListener("click", () => {
  if (!lastResponse) return;
  download(`trident-${lastResponse.file_sha256.slice(0, 8)}.txt`, "text/plain", asPlainText(lastResponse));
});

loadParsers();

// ---------------------------------------------------------------------------
// Phase 3: simulator availability
// ---------------------------------------------------------------------------
// Shown before anything runs, so the user knows whether Double-Check can do
// operational work. Nothing here launches Packet Tracer; it only reads status.

async function loadSimulatorStatus() {
  const target = document.getElementById("sim-status-text");
  if (!target) return;
  try {
    const response = await fetch("/api/phase3/simulator/status");
    if (!response.ok) throw new Error(`status ${response.status}`);
    const data = await response.json();
    if (data.available) {
      target.textContent =
        "Operational simulation is available. Smart Investigation and Double-Check can run live diagnostics.";
      target.className = "ok";
    } else {
      target.textContent =
        `Operational simulation unavailable: ${data.reason}. Static analysis works normally.`;
      target.className = "muted";
    }
  } catch (error) {
    target.textContent = "Operational simulation status could not be read.";
    target.className = "muted";
  }
}

loadSimulatorStatus();
