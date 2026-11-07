"use strict";

const $ = (id) => document.getElementById(id);
let lastResponse = null;

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function loadParsers() {
  try {
    const res = await fetch("/api/parsers");
    const data = await res.json();
    const table = $("parser-table");
    table.innerHTML = "";
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
  const root = $("results");
  root.innerHTML = "";
  for (const r of data.results) {
    root.appendChild(renderResult(r));
  }
  $("toolbar").classList.remove("hidden");
  loadParsers();
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

function renderResult(r) {
  const box = el("div", `result ${r.status}`);

  const head = el("div", "result-head");
  head.appendChild(el("span", "qnum", `Q${r.question_number}`));
  head.appendChild(el("span", `badge ${r.status}`, r.status));
  const cons = r.consensus || {};
  head.appendChild(
    el(
      "span",
      "meta-line",
      `agreement ${cons.agree ?? 0}/${cons.available ?? 0} (required ${cons.required ?? 3})` +
        (cons.crypto_shared ? " · shared container decode" : "")
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

  for (const c of r.conflicts || []) box.appendChild(el("div", "conflict", `Conflict: ${c}`));
  for (const m of r.missing_evidence || [])
    box.appendChild(el("div", "hint", `Missing: ${m}`));
  if (r.manual_check) box.appendChild(el("div", "hint", `Manual check: ${r.manual_check}`));

  if ((r.evidence || []).length) {
    const details = el("details");
    details.appendChild(el("summary", null, `Evidence (${r.evidence.length})`));
    const pre = el("pre");
    pre.textContent = r.evidence
      .map((e) => {
        const where = [e.device, e.interface].filter(Boolean).join(" ");
        const src = (e.sources || []).join(", ");
        const paths = (e.extraction_paths || []).join(", ");
        let line = `${where ? where + " · " : ""}${e.field} = ${e.value}\n  sources: ${src}\n  via: ${paths}`;
        if (e.raw_evidence) line += `\n  raw: ${e.raw_evidence}`;
        return line;
      })
      .join("\n\n");
    details.appendChild(pre);
    box.appendChild(details);
  }

  return box;
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
