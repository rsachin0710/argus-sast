// Argus web UI script.
//
// Security rule for this file: scanned code, finding text and anything that
// came from an LLM is UNTRUSTED. It is only ever inserted with textContent /
// createElement, never with innerHTML. State-changing requests carry the
// CSRF token from <meta name="argus-csrf">.
"use strict";

const CSRF = document.querySelector('meta[name="argus-csrf"]')?.content || "";

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json", "X-Argus-CSRF": CSRF },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* non-JSON */ }
  if (!res.ok) throw new Error((data && (data.detail || data.error)) || `Request failed (${res.status})`);
  return data;
}

// Tiny DOM builder: el("p", {class: "x"}, "text", child...) — strings become text nodes.
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return n;
}

function setupTabs(root) {
  const tabs = root.querySelectorAll('[role="tab"]');
  tabs.forEach((t) => t.addEventListener("click", () => {
    tabs.forEach((x) => x.setAttribute("aria-selected", String(x === t)));
    root.querySelectorAll("[data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== t.dataset.tab; });
  }));
  return () => root.querySelector('[role="tab"][aria-selected="true"]')?.dataset.tab;
}

function showMsg(node, text, kind) {
  node.hidden = false;
  node.className = "notice" + (kind ? " " + kind : "");
  node.textContent = text;
}

const SEV = ["info", "low", "medium", "high", "critical"];
const STATUS_LABEL = { confirmed: "confirmed", needs_context: "needs your input", unverified: "unverified",
  rejected: "rejected", suppressed: "suppressed" };

// ------------------------------------------------------------------ dashboard
function pageDashboard() {
  document.querySelectorAll("time[data-utc]").forEach((t) => {
    const d = new Date(t.dataset.utc);
    if (!isNaN(d)) t.textContent = d.toLocaleString();
  });
}

// ------------------------------------------------------------------ new scan
function pageNewScan() {
  const form = document.getElementById("scan-form");
  const currentTab = setupTabs(form);
  const ai = document.getElementById("ai");
  const aiFields = document.getElementById("ai-fields");
  const provider = document.getElementById("provider");
  const model = document.getElementById("model");
  const defaults = JSON.parse(model.dataset.defaults || "{}");
  const errBox = document.getElementById("form-error");
  ai.addEventListener("change", () => { aiFields.hidden = !ai.checked; });
  provider.addEventListener("change", () => { model.value = defaults[provider.value] || ""; });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errBox.hidden = true;
    const btn = form.querySelector('button[type="submit"]');
    const tab = currentTab();
    const body = {
      ai: ai.checked,
      provider: provider.value,
      model: model.value.trim(),
      votes: form.votes.value,
      mode: form.mode.value,
      trace: document.getElementById("trace").checked,
      owasp_edition: form.owasp_edition.value,
      min_severity: form.min_severity.value,
      categories: [...form.querySelectorAll('input[name="categories"]:checked')].map((c) => c.value),
      languages: [...form.querySelectorAll('input[name="languages"]:checked')].map((c) => c.value),
      rule_paths: form.rule_paths.value,
    };
    if (tab === "path") { body.target = form.target.value.trim(); body.ref = form.ref.value.trim(); }
    if (tab === "pr") body.github_pr = form.github_pr.value.trim();
    if (tab === "upload") {
      const file = document.getElementById("upload").files[0];
      if (!file) return showMsg(errBox, "Choose a file to upload.", "error");
      if (file.size > 2_000_000) return showMsg(errBox, "That file is over 2 MB. Scan its folder instead.", "error");
      body.upload = { name: file.name, content: await file.text() };
    }
    if (!body.languages.length) return showMsg(errBox, "Pick at least one language.", "error");
    btn.disabled = true;
    btn.textContent = "Starting scan";
    try {
      const res = await api("POST", "/api/scans", body);
      window.location.href = `/runs/${encodeURIComponent(res.run_id)}`;
    } catch (err) {
      showMsg(errBox, err.message, "error");
      btn.disabled = false;
      btn.textContent = "Start scan";
    }
  });
}

// ------------------------------------------------------------------ run page
function pageRun() {
  const live = document.getElementById("live");
  if (live) return pollRun(live.dataset.run);
  const dataNode = document.getElementById("run-data");
  if (!dataNode || !document.getElementById("flist")) return;
  const run = JSON.parse(dataNode.textContent);
  const owaspNames = JSON.parse(document.getElementById("owasp-names").textContent);
  const ui = { run, owaspNames, selected: null };
  const fStatus = document.getElementById("f-status");
  const fSev = document.getElementById("f-sev");
  const fQ = document.getElementById("f-q");
  [fStatus, fSev, fQ].forEach((x) => x.addEventListener("input", () => renderList(ui)));
  const fromHash = decodeURIComponent(location.hash.slice(1));
  if (fromHash && run.findings.some((f) => f.id === fromHash)) {
    const f = run.findings.find((x) => x.id === fromHash);
    if (!["confirmed", "needs_context", "unverified"].includes(f.status)) fStatus.value = "all";
    ui.selected = fromHash;
  }
  renderList(ui);
  setupFixDialog(ui);
}

function pollRun(runId) {
  const bar = document.getElementById("bar");
  const phase = document.getElementById("phase");
  document.getElementById("cancel").addEventListener("click", async (e) => {
    e.target.disabled = true;
    try { await api("POST", `/api/runs/${encodeURIComponent(runId)}/cancel`); } catch (_) { /* ignore */ }
  });
  const tick = async () => {
    try {
      const s = await (await fetch(`/api/runs/${encodeURIComponent(runId)}/status`)).json();
      bar.style.width = `${Math.round((s.progress || 0) * 100)}%`;
      phase.textContent = s.phase ? s.phase.charAt(0).toUpperCase() + s.phase.slice(1) : "Working";
      if (s.status && s.status !== "running" && s.status !== "queued") return window.location.reload();
    } catch (_) { /* server busy: retry */ }
    setTimeout(tick, 1200);
  };
  tick();
}

function filtered(ui) {
  const st = document.getElementById("f-status").value;
  const sev = document.getElementById("f-sev").value;
  const q = document.getElementById("f-q").value.trim().toLowerCase();
  return ui.run.findings.filter((f) => {
    if (st === "active" && !["confirmed", "needs_context", "unverified"].includes(f.status)) return false;
    if (st !== "active" && st !== "all" && f.status !== st) return false;
    if (sev && SEV.indexOf(f.severity) < SEV.indexOf(sev)) return false;
    if (q && !`${f.title} ${f.file} ${f.cwe} ${f.id} ${f.cwe_name}`.toLowerCase().includes(q)) return false;
    return true;
  });
}

function renderList(ui) {
  const list = document.getElementById("flist");
  const items = filtered(ui);
  list.replaceChildren();
  if (!items.some((f) => f.id === ui.selected)) ui.selected = items[0]?.id || null;
  for (const f of items) {
    const btn = el("button", { type: "button", role: "option", "aria-selected": String(f.id === ui.selected),
      onclick: () => { ui.selected = f.id; history.replaceState(null, "", `#${f.id}`); renderList(ui); } },
      el("span", { class: "row1" }, el("span", { class: `sev sev-${f.severity}` }, f.severity),
        el("span", { class: `status status-${f.status}` }, STATUS_LABEL[f.status] || f.status)),
      el("span", { class: "t" }, f.title),
      el("span", { class: "loc" }, `${f.file}:${f.start_line}  ${f.cwe || ""}`));
    list.append(el("li", {}, btn));
  }
  document.getElementById("fcount").textContent =
    `${items.length} of ${ui.run.findings.length} findings shown`;
  renderDetail(ui, ui.run.findings.find((f) => f.id === ui.selected));
}

function codeViewer(f) {
  const ctx = f.code_context;
  const box = el("div", { class: "code", role: "region", "aria-label": `Code around line ${f.start_line}` });
  if (!ctx) {
    box.append(el("div", { class: "ln hit" }, el("span", { class: "flow" }), el("span", { class: "gut" }, f.start_line),
      el("span", { class: "src" }, f.snippet)));
    return box;
  }
  const marks = new Map();
  f.data_flow.forEach((s, i) => { if (s.file === f.file && !marks.has(s.line)) marks.set(s.line, { n: i + 1, sink: s.role === "sink" }); });
  ctx.lines.forEach((line, i) => {
    const n = ctx.start_line + i;
    const hit = n >= f.start_line && n <= f.end_line;
    const m = marks.get(n);
    box.append(el("div", { class: `ln${hit ? " hit" : ""}` },
      el("span", { class: "flow" }, m ? el("i", { class: m.sink ? "sink" : "", title: `Data flow step ${m.n}` }, m.n) : ""),
      el("span", { class: "gut" }, n),
      el("span", { class: "src" }, line || " ")));
  });
  requestAnimationFrame(() => {
    const first = box.querySelector(".hit");
    if (first) box.scrollTop = Math.max(0, first.offsetTop - box.clientHeight / 3);
  });
  return box;
}

function diffView(text) {
  const box = el("div", { class: "diff", role: "region", "aria-label": "Suggested change" });
  for (const line of text.replace(/\n$/, "").split("\n")) {
    const cls = line.startsWith("+++") || line.startsWith("---") || line.startsWith("@@") ? "h"
      : line.startsWith("+") ? "a" : line.startsWith("-") ? "d" : "";
    box.append(el("span", { class: cls }, line || " "));
  }
  return box;
}

function para(title, text) {
  if (!text) return null;
  return [el("h3", {}, title), el("div", { class: "prose" }, el("p", {}, text))];
}

function renderDetail(ui, f) {
  const d = document.getElementById("detail");
  d.replaceChildren();
  if (!f) { d.append(el("p", { class: "muted" }, "No findings match these filters.")); return; }
  const run = ui.run;
  const cat = f.owasp[run.owasp_edition];
  const other = run.owasp_edition === "2025" ? "2021" : "2025";
  const factors = f.severity_factors
    ? `${f.severity_factors.impact.replace(/_/g, " ")}, ${f.severity_factors.attacker_position.replace(/_/g, " ")}, ${f.severity_factors.exploitability} to exploit`
    : null;

  d.append(
    el("div", { class: "run-meta" },
      el("span", { class: `sev sev-${f.severity}` }, f.severity),
      el("span", { class: `status status-${f.status}` }, STATUS_LABEL[f.status] || f.status),
      el("span", { class: "mono" }, f.id)),
    el("h2", {}, f.title),
    el("dl", { class: "facts" },
      el("dt", {}, "Location"), el("dd", { class: "mono" }, `${f.file}:${f.start_line}${f.end_line !== f.start_line ? "-" + f.end_line : ""}${f.function ? "  in " + f.function : ""}`),
      el("dt", {}, "Weakness"), el("dd", {}, f.references[0] ? el("a", { href: f.references[0], target: "_blank", rel: "noopener noreferrer" }, `${f.cwe} ${f.cwe_name}`) : `${f.cwe || ""} ${f.cwe_name}`),
      el("dt", {}, "OWASP"), el("dd", {}, cat ? `${cat}:${run.owasp_edition} ${ui.owaspNames[cat] || ""}` : "Not in the OWASP Top 10", f.owasp[other] ? `  (${other}: ${f.owasp[other]})` : ""),
      el("dt", {}, "Detected by"), el("dd", {}, f.detector === "ai+rule" ? "AI agents and a pattern rule" : f.detector === "ai" ? "AI agents" : "Pattern rule", f.rule_id ? ` (${f.rule_id})` : ""),
      el("dt", {}, "Confidence"), el("dd", {}, `${Math.round(f.confidence * 100)}%`, f.votes ? `, found in ${f.votes} votes` : ""),
      factors ? [el("dt", {}, "Severity basis"), el("dd", {}, factors)] : null,
      f.suppressed_reason ? [el("dt", {}, "Suppressed"), el("dd", {}, f.suppressed_reason)] : null),
    codeViewer(f),
  );

  if (f.data_flow.length) {
    d.append(el("h3", {}, "How data reaches this line"),
      el("ol", { class: "flowlist" }, f.data_flow.map((s, i) => el("li", {},
        el("i", { class: s.role === "sink" ? "sink" : "" }, i + 1),
        el("span", {}, el("b", {}, s.role), " ", el("code", {}, `${s.file}:${s.line}`), s.note ? ` ${s.note}` : "")))));
  }
  d.append(...(para(f.status === "rejected" ? "Why the verifier rejected it" : "Why this is flagged", f.explanation) || []));
  d.append(...(para("How it could be exploited", f.exploit_scenario) || []));
  d.append(...(para("Impact", f.impact) || []));

  if (f.status === "needs_context") {
    const ta = el("textarea", { id: "answer", placeholder: "Answer in a sentence or two." });
    const msg = el("span", { "aria-live": "polite" });
    const btn = el("button", { class: "btn primary", type: "button", onclick: async () => {
      if (!ta.value.trim()) { msg.textContent = "Write an answer first."; return; }
      btn.disabled = true; msg.textContent = "Re-checking with your answer";
      try {
        const updated = await api("POST", `/api/runs/${encodeURIComponent(run.id)}/findings/${encodeURIComponent(f.id)}/answer`, { answer: ta.value });
        Object.assign(f, updated);
        renderList(ui);
      } catch (err) { msg.textContent = err.message; btn.disabled = false; }
    } }, "Send answer and re-check");
    d.append(el("section", { class: "ask" }, el("h3", {}, "Argus needs your input"),
      el("p", {}, el("b", {}, f.context_question || "")),
      el("label", { for: "answer", class: "sr-only" }, "Your answer"), ta,
      el("div", { class: "actions" }, btn, msg)));
  }
  if (f.context_answer) d.append(...para("Your answer", f.context_answer));

  const r = f.remediation;
  if (r.summary || r.patch || r.fixed_code) {
    d.append(el("h3", {}, "Secure fix"));
    if (r.summary) d.append(el("div", { class: "prose" }, el("p", {}, r.summary)));
    if (r.applied) d.append(el("div", { class: "notice ok" }, `Applied ${new Date(r.applied_at).toLocaleString()}.`));
    if (r.patch) {
      d.append(diffView(r.patch));
      const acts = el("div", { class: "actions" });
      if (!r.applied && r.patch_valid && run.target_root) {
        acts.append(el("button", { class: "btn primary", type: "button", onclick: () => openFix(ui, f) }, "Review and apply fix"));
      }
      acts.append(el("a", { class: "btn", href: `/api/runs/${encodeURIComponent(run.id)}/patches/${encodeURIComponent(f.id)}` }, "Download patch"));
      if (!run.target_root) acts.append(el("span", { class: "muted" }, "This scan used a temporary copy; apply the patch in your own checkout."));
      d.append(acts);
      if (r.validation_note) d.append(el("p", { class: "hint" }, r.validation_note));
    } else if (r.fixed_code) {
      d.append(el("p", { class: "hint" }, `Not applied automatically: ${r.validation_note}`),
        el("pre", { class: "code" }, el("code", {}, r.fixed_code)));
    }
  }
  if (f.references.length > 1) {
    d.append(el("h3", {}, "References"), el("ul", {}, f.references.map((u) =>
      el("li", {}, /^https?:\/\//.test(u) ? el("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, u) : u))));
  }
}

function setupFixDialog(ui) {
  const dlg = document.getElementById("fix-dialog");
  const input = document.getElementById("fix-confirm");
  const apply = document.getElementById("fix-apply");
  input.addEventListener("input", () => { apply.disabled = input.value.trim().toUpperCase() !== (ui.fixing?.id || ""); });
  document.getElementById("fix-cancel").addEventListener("click", () => dlg.close());
  apply.addEventListener("click", async () => {
    const f = ui.fixing;
    const errBox = document.getElementById("fix-error");
    apply.disabled = true;
    try {
      await api("POST", `/api/runs/${encodeURIComponent(ui.run.id)}/findings/${encodeURIComponent(f.id)}/fix`, { confirm: input.value.trim() });
      f.remediation.applied = true;
      f.remediation.applied_at = new Date().toISOString();
      dlg.close();
      renderList(ui);
    } catch (err) { showMsg(errBox, err.message, "error"); apply.disabled = false; }
  });
}

async function openFix(ui, f) {
  const dlg = document.getElementById("fix-dialog");
  const errBox = document.getElementById("fix-error");
  errBox.hidden = true;
  ui.fixing = f;
  document.getElementById("fix-id").textContent = f.id;
  document.getElementById("fix-confirm").value = "";
  document.getElementById("fix-apply").disabled = true;
  const diffBox = document.getElementById("fix-diff");
  diffBox.replaceChildren(document.createTextNode("Preparing the change"));
  dlg.showModal();
  try {
    const p = await api("GET", `/api/runs/${encodeURIComponent(ui.run.id)}/findings/${encodeURIComponent(f.id)}/fix-preview`);
    document.getElementById("fix-file").textContent = p.file + (p.how === "relocated" ? "  (file changed since the scan; lines were relocated)" : "");
    diffBox.replaceWith(Object.assign(diffView(p.diff), { id: "fix-diff" }));
  } catch (err) {
    showMsg(errBox, err.message, "error");
    diffBox.replaceChildren();
  }
}

// ------------------------------------------------------------------ context
function pageContext() {
  document.querySelectorAll(".ask-card").forEach((card) => {
    const btn = card.querySelector(".send-answer");
    const out = card.querySelector(".result");
    btn.addEventListener("click", async () => {
      const answer = card.querySelector(".answer").value.trim();
      if (!answer) { out.textContent = "Write an answer first."; return; }
      btn.disabled = true; out.textContent = "Re-checking with your answer";
      try {
        const f = await api("POST", `/api/runs/${encodeURIComponent(card.dataset.run)}/findings/${encodeURIComponent(card.dataset.id)}/answer`, { answer });
        out.textContent = f.status === "needs_context"
          ? `Still unclear: ${f.context_question}`
          : `Re-checked: now ${STATUS_LABEL[f.status] || f.status} (${f.severity}).`;
        if (f.status === "needs_context") btn.disabled = false;
      } catch (err) { out.textContent = err.message; btn.disabled = false; }
    });
  });
}

// ------------------------------------------------------------------ rules
function pageRules() {
  const editor = document.getElementById("rule-editor");
  const currentTab = setupTabs(editor);
  const form = document.getElementById("rule-form");
  const msg = document.getElementById("rule-msg");
  const type = document.getElementById("r-type");
  const syncType = () => form.querySelectorAll("[data-show]").forEach((n) => {
    n.hidden = !n.dataset.show.split(" ").includes(type.value);
  });
  type.addEventListener("change", syncType);
  syncType();
  document.getElementById("new-rule-btn").addEventListener("click", () => { editor.hidden = false; editor.scrollIntoView({ behavior: "smooth" }); });
  document.getElementById("rule-close").addEventListener("click", () => { editor.hidden = true; });

  const collect = () => {
    const data = {};
    for (const n of form.querySelectorAll("input[name], select[name], textarea[name]")) {
      if (n.closest("[hidden]") || n.type === "checkbox") continue;
      data[n.name] = n.value.trim();
    }
    data.languages = [...form.querySelectorAll('input[name="languages"]:checked')].map((c) => c.value);
    return data;
  };
  const toYaml = (rule) => JSON.stringify({ version: 1, rules: [Object.fromEntries(Object.entries(rule).map(([k, v]) =>
    [k, ["patterns", "pattern-not", "exclude"].includes(k) ? v.split("\n").map((x) => x.trim()).filter(Boolean) : v])
    .filter(([, v]) => v !== "" && !(Array.isArray(v) && !v.length)))] });

  document.getElementById("rule-validate").addEventListener("click", async () => {
    const text = currentTab() === "yaml" ? document.getElementById("r-yaml").value : toYaml(collect());
    try {
      const res = await api("POST", "/api/rules/validate", { yaml: text });
      showMsg(msg, res.ok ? `Valid: ${res.rules.map((r) => r.id).join(", ")}` : res.errors.join("\n"), res.ok ? "ok" : "error");
    } catch (err) { showMsg(msg, err.message, "error"); }
  });
  document.getElementById("rule-save").addEventListener("click", async () => {
    const body = currentTab() === "yaml"
      ? { yaml: document.getElementById("r-yaml").value, filename: document.getElementById("r-filename").value.trim() }
      : { rule: collect() };
    try {
      const res = await api("POST", "/api/rules", body);
      showMsg(msg, `Saved to ${res.saved}. It will be used by every scan.`, "ok");
      setTimeout(() => window.location.reload(), 900);
    } catch (err) { showMsg(msg, err.message, "error"); }
  });

  document.querySelectorAll(".rule-toggle").forEach((cb) => cb.addEventListener("change", async () => {
    try { await api("POST", `/api/rules/${encodeURIComponent(cb.dataset.id)}/toggle`, { enabled: cb.checked }); }
    catch (err) { cb.checked = !cb.checked; alert(err.message); }
  }));
  document.querySelectorAll(".rule-delete").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm(`Delete the custom rule ${b.dataset.id}? Its file will be removed from your rules folder.`)) return;
    try { await api("POST", `/api/rules/${encodeURIComponent(b.dataset.id)}/delete`); b.closest("tr").remove(); }
    catch (err) { alert(err.message); }
  }));
  const q = document.getElementById("rq");
  const origin = document.getElementById("rorigin");
  const filter = () => document.querySelectorAll("#rules-table tbody tr").forEach((tr) => {
    tr.hidden = (q.value && !tr.dataset.text.includes(q.value.toLowerCase())) || (origin.value && tr.dataset.origin !== origin.value);
  });
  q.addEventListener("input", filter);
  origin.addEventListener("change", filter);
}

// ------------------------------------------------------------------ settings
function pageSettings() {
  const form = document.getElementById("settings-form");
  const msg = document.getElementById("settings-msg");
  const provider = document.getElementById("s-provider");
  const model = document.getElementById("s-model");
  const defaults = JSON.parse(model.dataset.defaults || "{}");
  const keyState = document.getElementById("key-state");
  const states = JSON.parse(keyState.dataset.states || "{}");
  const keyField = document.getElementById("key-field");
  const sync = () => {
    keyField.hidden = provider.value === "ollama";
    keyState.textContent = `Current key: ${states[provider.value] || "not set"}.`;
  };
  provider.addEventListener("change", () => { model.value = defaults[provider.value] || ""; document.getElementById("s-base").value = ""; sync(); });
  sync();

  document.getElementById("list-models").addEventListener("click", async (e) => {
    e.target.disabled = true;
    try {
      const res = await api("GET", `/api/models?provider=${encodeURIComponent(provider.value)}`);
      const dl = document.getElementById("model-list");
      dl.replaceChildren(...res.models.map((m) => el("option", { value: m })));
      showMsg(msg, `${res.models.length} models available. Start typing in the Model field to pick one.`, "ok");
    } catch (err) { showMsg(msg, err.message, "error"); }
    e.target.disabled = false;
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const out = {};
    for (const n of form.querySelectorAll("[data-key]")) {
      const [sec, key] = n.dataset.key.split(".");
      out[sec] = out[sec] || {};
      let v = n.type === "checkbox" ? n.checked : n.value;
      if (n.type === "number") v = Number(v);
      if (n.dataset.list) v = v.split("\n").map((x) => x.trim()).filter(Boolean);
      if (key === "base_url" && !v) v = null;
      out[sec][key] = v;
    }
    out.output = { formats: [...form.querySelectorAll('input[name="formats"]')].filter((c) => c.checked).map((c) => c.value) };
    try {
      const key = document.getElementById("s-key").value.trim();
      if (key && provider.value !== "ollama") {
        await api("POST", "/api/settings/key", { provider: provider.value, key });
        document.getElementById("s-key").value = "";
        states[provider.value] = "set";
        sync();
      }
      const res = await api("POST", "/api/settings", { settings: out });
      showMsg(msg, res.restart_needed ? "Saved. Restart argus serve to use the new port." : "Saved.", "ok");
    } catch (err) { showMsg(msg, err.message, "error"); }
  });
}

const PAGES = { dashboard: pageDashboard, new_scan: pageNewScan, run: pageRun, context: pageContext, rules: pageRules, settings: pageSettings };
document.addEventListener("DOMContentLoaded", () => { (PAGES[document.body.dataset.page] || (() => {}))(); });
