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
    // Streamed analysis: answers appear as they resolve, and stage events show
    // real phases. Falls back to the buffered endpoint if streaming is
    // unavailable in this browser or proxy.
    const streamed = await analyzeStreamed(form, started);
    if (!streamed) {
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
    }
  } catch (err) {
    setStatus(`Failed: ${err.message}`, "error");
  } finally {
    $("analyze").disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Streamed analysis
// ---------------------------------------------------------------------------
// Renders each answer as it arrives. Returns false when streaming is not
// usable, so the caller can fall back to the single-response endpoint.

async function analyzeStreamed(form, started) {
  let res;
  try {
    res = await fetch("/api/analyze/stream", { method: "POST", body: form });
  } catch (_) {
    // Network-level failure: let the caller fall back to the buffered endpoint.
    return false;
  }
  if (!res.ok || !res.body) return false;

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const collected = [];
  let complete = false;

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const frame = buffer.slice(0, boundary).trim();
        buffer = buffer.slice(boundary + 2);
        if (frame.startsWith("data: ")) {
          let event;
          try {
            event = JSON.parse(frame.slice(6));
          } catch (_) {
            boundary = buffer.indexOf("\n\n");
            continue;
          }
          if (event.kind === "COMPLETE") complete = true;
          handleStreamEvent(event, collected, started);
        }
        boundary = buffer.indexOf("\n\n");
      }
    }
  } catch (_) {
    // The stream broke mid-flight (aborted, proxy reset, connection dropped).
    // If nothing was delivered, fall back to the buffered endpoint; if answers
    // already rendered, keep them and report the interruption honestly rather
    // than clearing correct results.
    if (collected.length === 0) return false;
    setStatus(
      `Stream interrupted after ${collected.length} answer(s). Reload to retry.`,
      "error"
    );
    return true;
  }

  // A stream that ends without a COMPLETE frame did not finish cleanly.
  if (!complete && collected.length === 0) return false;
  return true;
}

function handleStreamEvent(event, collected, started) {
  if (event.kind === "STAGE") {
    setStatus(`Analyzing… ${event.stage}`, "busy");
    return;
  }
  if (event.kind === "ANSWER") {
    collected.push(event.answer);
    appendStreamedAnswer(event.answer);
    return;
  }
  if (event.kind === "COMPLETE") {
    const secs = ((performance.now() - started) / 1000).toFixed(1);
    setStatus(
      `Done in ${secs}s — ${collected.length} question(s): ${formatCounts(event.payload.status_counts)}.`,
      ""
    );
    return;
  }
  if (event.kind === "ERROR") {
    setStatus(`Failed: ${event.detail || "stream error"}`, "error");
  }
}

function formatCounts(counts) {
  if (!counts) return "no results";
  return Object.entries(counts)
    .map(([status, n]) => `${n} ${status.toLowerCase()}`)
    .join(", ");
}

// Renders one answer into the results list without clearing what is already
// shown, so the user sees earlier answers while later ones are still resolving.
function appendStreamedAnswer(answer) {
  // Use the same renderer as the buffered path. Two renderers produced two
  // different DOM shapes for the same concept (a <div> here, an <article>
  // there), which meant any selector that worked for one path silently matched
  // nothing in the other. One renderer is the fix.
  const root = $("results");
  if (!root) return;
  const meta = { snapshot_id: "—", snapshot_ambiguous: false };
  const node = renderResult(answer, meta);
  node.classList.add("streamed");
  root.appendChild(node);
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
  const p3 = data.phase3 || {};
  if (p3.available) {
    lines.push("");
    lines.push("Static diagnosis (Phase 3):");
    const findings = p3.findings || [];
    if (!findings.length) {
      lines.push("  no defects detected in the configuration");
    } else {
      for (const f of findings) {
        const where = [f.device, f.interface].filter(Boolean).join(" ");
        lines.push(`  ${String(f.kind).padEnd(24)} ${where}  (${f.confidence})`);
      }
    }
    const unresolved = p3.unresolved_questions || [];
    if (unresolved.length) {
      lines.push(
        `  unresolved questions: ${unresolved.length} of which ` +
          `${p3.escalatable || 0} are operationally testable`
      );
    }
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

// ---------------------------------------------------------------------------
// Analyze Mode
// ---------------------------------------------------------------------------
// One button, no questions. Renders a device-by-device report: overview first,
// then each device as its section is built, then network-wide findings and what
// was not checked.

async function runAnalyzeNetwork() {
  const input = document.querySelector('input[type=file]');
  const file = input?.files?.[0];
  if (!file) {
    setStatus("Choose a .pka or .pkt file first.", "error");
    return;
  }
  const mode = $("analyze-mode")?.value || "quick";
  const exportFormat = $("analyze-export")?.value || "json";
  const button = $("analyze-network");

  if (button) button.disabled = true;
  setStatus("Analyzing network…", "busy");
  const started = performance.now();

  const form = new FormData();
  form.append("file", file);
  form.append("mode", mode);
  form.append("export", exportFormat);

  try {
    // JSON goes through the streaming endpoint so device sections appear as they
    // are built. Exports need the finished document, so they use the plain one.
    if (exportFormat === "json") {
      const streamed = await streamNetworkReport(form, started);
      if (streamed) return;
    }
    const res = await fetch("/api/network/analyze", { method: "POST", body: form });
    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try {
        const err = await res.json();
        detail = err.detail || detail;
      } catch (_) {}
      throw new Error(detail);
    }

    if (exportFormat !== "json") {
      // An export is a file, not a rendered report.
      const text = await res.text();
      const secs = ((performance.now() - started) / 1000).toFixed(1);
      renderExport(text, file.name, exportFormat);
      setStatus(`Report exported in ${secs}s.`, "");
      return;
    }

    const report = await res.json();
    renderNetworkReport(report);
    const secs = ((performance.now() - started) / 1000).toFixed(1);
    const count = (report.sections || []).length;
    setStatus(`Analyzed ${count} device(s) in ${secs}s.`, "");
    // Keep the report around so the export buttons can reuse it.
    window.__lastNetworkReport = report;
  } catch (err) {
    setStatus(`Failed: ${err.message}`, "error");
  } finally {
    if (button) button.disabled = false;
  }
}

async function streamNetworkReport(form, started) {
  let res;
  try {
    res = await fetch("/api/network/analyze/stream", { method: "POST", body: form });
  } catch (_) {
    return false;
  }
  if (!res.ok || !res.body) return false;

  const wrap = $("network-report");
  wrap.classList.remove("hidden");
  const overview = $("network-overview");
  const sections = $("device-sections");
  const findings = $("network-findings");
  const coverage = $("network-coverage");
  overview.replaceChildren();
  sections.replaceChildren();
  findings.replaceChildren();
  coverage.replaceChildren();

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let count = 0;
  let complete = false;
  let sessionId = null;
  let lastSeq = 0;
  let seen = new Set();

  const handle = (event) => {
    if (event.kind === "SESSION") {
      sessionId = event.payload?.session_id || null;
      return;
    }
    if (event.kind === "STAGE") {
      setStatus("Analyzing network…", "busy");
      return;
    }
    if (event.kind === "OVERVIEW") {
      renderOverview(event.payload, overview);
      return;
    }
    if (event.kind === "SECTION") {
      const name = event.payload?.name;
      // A replayed event must not create a second card for the same device.
      if (name && seen.has(name)) return;
      if (name) seen.add(name);
      sections.appendChild(renderDeviceSection(event.payload));
      count += 1;
      setStatus(`Analyzing network… ${count} device(s)`, "busy");
      return;
    }
    if (event.kind === "FINDINGS") {
      renderNetworkFindings(event.payload.network_findings || [], findings);
      return;
    }
    if (event.kind === "COVERAGE") {
      renderCoverage(event.payload, coverage);
      return;
    }
    if (event.kind === "COMPLETE") {
      complete = true;
      const secs = ((performance.now() - started) / 1000).toFixed(1);
      setStatus(`Analyzed ${count} device(s) in ${secs}s.`, "");
      return;
    }
    if (event.kind === "ERROR") {
      setStatus(`Failed: ${event.detail || "analyze error"}`, "error");
    }
  };

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const frame = buffer.slice(0, boundary).trim();
        buffer = buffer.slice(boundary + 2);
        if (frame.startsWith("id: ")) {
          const idLine = frame.slice(0, frame.indexOf("\n"));
          const parsed = parseInt(idLine.slice(4), 10);
          if (!Number.isNaN(parsed)) lastSeq = parsed;
        }
        const dataLine = frame.split("\n").find((line) => line.startsWith("data: "));
        if (dataLine) {
          try {
            handle(JSON.parse(dataLine.slice(6)));
          } catch (_) {}
        }
        boundary = buffer.indexOf("\n\n");
      }
    }
  } catch (_) {
    // The stream broke. Try to resume from the last event actually seen rather
    // than restarting: a finished report must not be lost to a dropped socket.
    if (sessionId) {
      const resumed = await resumeNetworkReport(sessionId, lastSeq, {
        sections,
        overview,
        findings,
        coverage,
        seen,
        onSection: () => {
          count += 1;
          setStatus(`Analyzing network… ${count} device(s)`, "busy");
        },
        handle,
      });
      if (resumed) {
        const secs = ((performance.now() - started) / 1000).toFixed(1);
        setStatus(`Analyzed ${count} device(s) in ${secs}s (resumed).`, "");
        return true;
      }
    }
    if (count === 0) return false;
    setStatus(`Stream interrupted after ${count} device(s). Reload to retry.`, "error");
    return true;
  }
  return complete || count > 0;
}

async function resumeNetworkReport(sessionId, lastSeq, ctx) {
  let res;
  try {
    res = await fetch(
      `/api/network/analyze/replay/${sessionId}?last_event_id=${lastSeq}`
    );
  } catch (_) {
    return false;
  }
  if (!res.ok) return false;
  const payload = await res.json();
  if (payload.expired) {
    setStatus(
      `Session expired; ${ctx.seen.size} device(s) already shown. Reload to restart.`,
      "error"
    );
    return true;
  }
  for (const event of payload.events || []) {
    ctx.handle({ kind: event.kind, payload: event.payload });
  }
  return true;
}

function renderOverview(ov, target) {
  target.replaceChildren();
  target.appendChild(el("h2", null, "Network overview"));
  const grid = el("div", "overview-grid");
  const stats = [
    ["Devices", ov.device_count ?? 0],
    ["Physical links", ov.link_count ?? 0],
    ["Interfaces", ov.interface_count ?? 0],
    ["VLANs", ov.vlan_count ?? 0],
    ["Routing protocols", (ov.routing_protocols || []).join(", ") || "none detected"],
    ["Findings", formatSeverity(ov.findings_by_severity)],
    ["Unsupported checks", ov.unsupported_checks ?? 0],
  ];
  for (const [label, value] of stats) {
    const cell = el("div", "overview-stat");
    cell.appendChild(el("span", "stat-label", label));
    cell.appendChild(el("span", "stat-value", String(value)));
    grid.appendChild(cell);
  }
  target.appendChild(grid);
  const types = ov.devices_by_type || {};
  const typeLine = Object.entries(types)
    .map(([kind, n]) => `${n} ${kind.toLowerCase()}`)
    .join(", ");
  if (typeLine) target.appendChild(el("p", "muted", `By type: ${typeLine}`));

  // Deep Analyze runtime status. Present only when that mode ran; the wording
  // states what actually happened rather than implying more was tested.
  if (ov.runtime_available === true) {
    target.appendChild(
      el(
        "p",
        "ok",
        `Deep Analyze ran operational experiments in Packet Tracer ` +
          `${ov.runtime_version || "(version unknown)"}. ` +
          (ov.source_intact === false ? "WARNING: source file changed." : "Source file unchanged.")
      )
    );
  } else if (ov.runtime_available === false) {
    target.appendChild(
      el("p", "muted", `Deep Analyze could not run experiments: ${ov.runtime_reason || "no simulator available"}.`)
    );
  }
}

function renderNetworkFindings(list, target) {
  target.replaceChildren();
  target.appendChild(el("h2", null, "Network-wide issues"));
  if (!list.length) {
    target.appendChild(
      el("p", "muted", "No network-wide problem detected by the checks that were run.")
    );
    return;
  }
  for (const finding of list) target.appendChild(renderFinding(finding));
}

function renderCoverage(payload, target) {
  target.replaceChildren();
  target.appendChild(el("h2", null, "What was not checked"));
  const unsupported = payload.unsupported_checks || [];
  if (!unsupported.length) {
    target.appendChild(el("p", "muted", "Nothing outstanding."));
  } else {
    const ul = el("ul", "unsupported-list");
    for (const item of unsupported) ul.appendChild(el("li", null, item));
    target.appendChild(ul);
  }
  target.appendChild(
    el(
      "p",
      "muted",
      "A report with no findings means no check fired. It is not proof that the network is correct."
    )
  );
}

function renderNetworkReport(report) {
  const wrap = $("network-report");
  if (!wrap) return;
  wrap.classList.remove("hidden");

  // Overview
  const overview = $("network-overview");
  overview.replaceChildren();
  overview.appendChild(el("h2", null, "Network overview"));
  const ov = report.overview || {};
  const grid = el("div", "overview-grid");
  const stats = [
    ["Devices", ov.device_count ?? 0],
    ["Physical links", ov.link_count ?? 0],
    ["Interfaces", ov.interface_count ?? 0],
    ["VLANs", ov.vlan_count ?? 0],
    ["Routing protocols", (ov.routing_protocols || []).join(", ") || "none detected"],
    ["Findings", formatSeverity(ov.findings_by_severity)],
    ["Unsupported checks", ov.unsupported_checks ?? 0],
  ];
  for (const [label, value] of stats) {
    const cell = el("div", "overview-stat");
    cell.appendChild(el("span", "stat-label", label));
    cell.appendChild(el("span", "stat-value", String(value)));
    grid.appendChild(cell);
  }
  overview.appendChild(grid);
  const types = ov.devices_by_type || {};
  const typeLine = Object.entries(types)
    .map(([kind, n]) => `${n} ${kind.toLowerCase()}`)
    .join(", ");
  if (typeLine) overview.appendChild(el("p", "muted", `By type: ${typeLine}`));

  // Device sections, one card each
  const sections = $("device-sections");
  sections.replaceChildren();
  for (const section of report.sections || []) {
    sections.appendChild(renderDeviceSection(section));
  }

  // Network-wide findings
  const findings = $("network-findings");
  findings.replaceChildren();
  findings.appendChild(el("h2", null, "Network-wide issues"));
  const list = report.network_findings || [];
  if (!list.length) {
    findings.appendChild(
      el("p", "muted", "No network-wide problem detected by the checks that were run.")
    );
  } else {
    for (const finding of list) findings.appendChild(renderFinding(finding));
  }

  // Coverage / what was not checked
  const coverage = $("network-coverage");
  coverage.replaceChildren();
  coverage.appendChild(el("h2", null, "What was not checked"));
  const unsupported = report.unsupported_checks || [];
  if (!unsupported.length) {
    coverage.appendChild(el("p", "muted", "Nothing outstanding."));
  } else {
    const ul = el("ul", "unsupported-list");
    for (const item of unsupported) ul.appendChild(el("li", null, item));
    coverage.appendChild(ul);
  }
  coverage.appendChild(
    el(
      "p",
      "muted",
      "A report with no findings means no check fired. It is not proof that the network is correct."
    )
  );
}

function formatSeverity(counts) {
  if (!counts || !Object.keys(counts).length) return "none";
  return Object.entries(counts)
    .map(([severity, n]) => `${n} ${severity.toLowerCase()}`)
    .join(", ");
}

function renderDeviceSection(section) {
  const card = el("section", "card device-section");
  card.appendChild(el("h2", null, section.heading));
  if (section.model) card.appendChild(el("p", "muted", `Model: ${section.model}`));

  if (section.basics?.length) {
    card.appendChild(el("h3", null, "Basic Information"));
    const table = el("table", "basics-table");
    for (const row of section.basics) {
      const tr = el("tr");
      tr.appendChild(el("th", null, row.label));
      tr.appendChild(el("td", null, row.value));
      table.appendChild(tr);
    }
    card.appendChild(table);
  }

  if (section.questions?.length) {
    const details = el("details", "questions");
    details.appendChild(el("summary", null, `Common Cisco Questions (${section.questions.length})`));
    for (const item of section.questions) {
      const wrap = el("div", "question");
      wrap.appendChild(el("div", "question-text", item.question));
      if (item.answer === null || item.answer === undefined) {
        wrap.appendChild(el("div", "answer unavailable", `${item.status}: ${item.limitation}`));
      } else {
        wrap.appendChild(el("div", "answer", item.answer));
        wrap.appendChild(el("span", `badge status-${item.status.toLowerCase()}`, item.status));
      }
      details.appendChild(wrap);
    }
    card.appendChild(details);
  }

  card.appendChild(el("h3", null, "Potential Problems"));
  if (!section.findings?.length) {
    card.appendChild(el("p", "muted", "No problem detected by the checks that were run."));
  } else {
    for (const finding of section.findings) card.appendChild(renderFinding(finding));
  }
  return card;
}

function renderFinding(finding) {
  const box = el("div", `finding severity-${String(finding.severity).toLowerCase()}`);
  const head = el("div", "finding-head");
  head.appendChild(el("span", `badge severity-${String(finding.severity).toLowerCase()}`, finding.severity));
  const where = [finding.device, finding.interface].filter(Boolean).join(" ");
  if (where) head.appendChild(el("span", "finding-where", where));
  head.appendChild(el("span", `badge status-${String(finding.status).toLowerCase()}`, finding.status));
  box.appendChild(head);
  box.appendChild(el("p", "finding-desc", finding.description));
  if (finding.why_it_matters) {
    box.appendChild(el("p", "muted", `Why it matters: ${finding.why_it_matters}`));
  }
  if (finding.evidence) {
    const details = el("details", "evidence");
    details.appendChild(el("summary", null, "Evidence"));
    details.appendChild(el("pre", "evidence-body", finding.evidence));
    box.appendChild(details);
  }
  if (finding.next_commands?.length) {
    box.appendChild(el("p", "muted", `Check with: ${finding.next_commands.join(", ")}`));
  }
  if (finding.remediation) {
    box.appendChild(el("p", "muted", `Suggested fix: ${finding.remediation}`));
  }
  return box;
}

function renderExport(text, fileName, format) {
  const wrap = $("network-report");
  wrap.classList.remove("hidden");
  $("network-overview").replaceChildren();
  $("device-sections").replaceChildren();
  $("network-findings").replaceChildren();

  const coverage = $("network-coverage");
  coverage.replaceChildren();
  coverage.appendChild(el("h2", null, `Exported report (${format})`));
  coverage.appendChild(el("pre", "export-body", text));

  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = el("a", "download-link", `Download ${fileName}.${format === "markdown" ? "md" : "txt"}`);
  link.href = url;
  link.download = `${fileName}.${format === "markdown" ? "md" : "txt"}`;
  coverage.appendChild(link);
}

const analyzeNetworkButton = $("analyze-network");
if (analyzeNetworkButton) {
  analyzeNetworkButton.addEventListener("click", runAnalyzeNetwork);
}
