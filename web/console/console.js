/* ASIP analyst console.
 *
 * Nine screens over the JSON API. Deliberately dependency-free: every screen
 * here reads an endpoint a React client would read identically, so replacing
 * this file changes nothing below the API.
 *
 * Two rules carried from the directives into every render below:
 *
 *   D-68 — three distinct empty states. "No activity in this window" (measured
 *   and empty), "source not updated" (unknown), and "not ready yet" mean
 *   different things, and showing the first when the truth is the second leads
 *   the analyst to a wrong conclusion. `emptyState()` refuses to be generic.
 *
 *   V-4 — the one rule running has no measured precision, so every finding it
 *   produces is labelled as a shadow observation wherever it appears. It is
 *   never presented as a verdict.
 */

const api = async (path, options) => {
  const response = await fetch(path, options);
  if (!response.ok) throw new Error(`${path} → ${response.status}`);
  return response.headers.get("content-type")?.includes("json")
    ? response.json()
    : response.text();
};

const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) node.setAttribute(k, v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
};

/* D-65: times are UTC ISO 8601, and only ever UTC here.
 *
 * Trimmed to whole seconds. The API sends microseconds, which is right for the
 * record and wrong for a column an analyst scans: six trailing digits that
 * differ on every row defeat the comparison the column exists to support.
 * Nothing is lost — the stored value keeps full precision, and the evidence
 * timestamps that matter are the TSA's, not ours. */
const ts = (value) => {
  if (!value) return "—";
  return String(value).replace("T", " ").replace(/\.\d+Z$/, "Z");
};
const shortHash = (value) => (value ? String(value).slice(0, 12) : "—");

/* D-68. Three states, and the caller must say which one applies. A generic
   "nothing here" would let "we lost the source" render as "nothing happened". */
const emptyState = (kind, headline, why) =>
  el("div", { class: `empty empty-${kind}` },
    el("div", { class: "headline" }, headline),
    el("div", { class: "why" }, why));

/* D-57 — the provenance strip. Every assertion carries one. It never hides. */
const provenance = ({ hash, time, verified, source, extra }) =>
  el("div", { class: "provenance-strip" },
    el("span", { class: "hash" }, `◆ ${shortHash(hash)}`),
    el("span", { class: "timestamp" }, ts(time)),
    el("span", { class: verified ? "verified" : "pending" },
      verified ? "TSA ✓" : "TSA pending"),
    source ? el("span", {}, source) : null,
    extra ? el("span", {}, extra) : null);

const table = (columns, rows, renderRow) => {
  const body = el("tbody", {}, rows.map((row, i) => renderRow(row, i)));
  return el("table", {},
    el("thead", {}, el("tr", {}, columns.map((c) => el("th", {}, c)))),
    body);
};

const shadowBadge = () =>
  el("span", { class: "shadow-badge", title:
    "This rule has no measured precision, so it runs in shadow mode (V-4). " +
    "Its output is an observation, not a verdict." }, "SHADOW");

// ── screens ────────────────────────────────────────────────────────────────

const screens = {};

screens.dashboard = {
  title: "Dashboard",
  note: "Pipeline state at a glance. Source health is shown here, not buried, so an empty screen is never mistaken for a quiet day.",
  async render(root) {
    const d = await api("/api/dashboard");
    root.append(el("div", { class: "tiles" },
      tile("Sources", d.sources.total, `${d.sources.enabled} enabled`),
      tile("Evidence bundles", d.bundles.total, `${d.bundles.last_24h} in last 24h`),
      tile("Content items", d.content.content, `${d.content.accounts} accounts`),
      tile("Findings", d.findings.total, `${d.findings.shadow} shadow`),
      tile("STIX exports", d.exports, "bundles written")));

    root.append(el("h2", {}, "Source health"));
    if (!d.source_health.length) {
      root.append(emptyState("notready", "No sources configured yet",
        "Seed a source, then run the pipeline. Nothing has been collected because nothing has been asked for."));
    } else {
      root.append(table(["Source", "Last success", "Consecutive failures", "Last failure"],
        d.source_health, (s) => el("tr", { "data-row": "1" },
          el("td", {}, s.name),
          el("td", { class: "timestamp" }, ts(s.last_success_at)),
          el("td", { class: "num" }, s.consecutive_failures),
          el("td", {}, s.last_failure_reason || "—"))));
    }

    root.append(el("h2", {}, "Recent fetches"));
    if (!d.recent_jobs.length) {
      root.append(emptyState("measured", "No fetches recorded",
        "The scheduler has not run. Press “Run pipeline” to collect once."));
    } else {
      root.append(jobsTable(d.recent_jobs));
    }
  },
};

const tile = (label, value, sub) =>
  el("div", { class: "tile" },
    el("div", { class: "k" }, label),
    el("div", { class: "v" }, value ?? 0),
    el("div", { class: "sub" }, sub || ""));

const jobsTable = (jobs) =>
  table(["Started", "Source", "Status", "Bytes", "Trace", "Detail"], jobs, (j) =>
    el("tr", { "data-row": "1" },
      el("td", { class: "timestamp" }, ts(j.started_at)),
      el("td", {}, j.source_name),
      el("td", {}, el("span", { class: `status status-${j.status}` }, j.status)),
      el("td", { class: "num" }, j.bytes_fetched),
      el("td", { class: "hash" }, j.trace_id),
      el("td", {}, j.failure_reason || (j.capture_id ? shortHash(j.capture_id) : "—"))));

screens.sources = {
  title: "Sources",
  note: "What is monitored, how often, and when each was last read successfully.",
  async render(root) {
    const rows = await api("/api/sources");
    if (!rows.length) {
      root.append(emptyState("notready", "No sources configured",
        "Run `make seed-dev` to register the canary source."));
      return;
    }
    root.append(table(
      ["Name", "URL", "Platform", "Every", "Enabled", "Canary", "Last success", "Failures"],
      rows, (s) => el("tr", { "data-row": "1" },
        el("td", {}, s.name),
        el("td", {}, el("a", { href: s.url, target: "_blank", rel: "noreferrer" }, s.url)),
        el("td", {}, s.platform),
        el("td", { class: "num" }, `${s.interval_seconds}s`),
        el("td", {}, s.enabled ? "yes" : "no"),
        el("td", {}, s.is_canary ? "yes" : "—"),
        el("td", { class: "timestamp" }, ts(s.last_success_at)),
        el("td", { class: "num" }, s.consecutive_failures))));
  },
};

screens.captures = {
  title: "Captures",
  note: "Every fetch attempt, successful or not. A failed capture is a record too — “we looked and it was gone” is evidence.",
  async render(root) {
    const rows = await api("/api/captures");
    if (!rows.length) {
      root.append(emptyState("measured", "No capture attempts recorded",
        "Nothing has been fetched yet. This is measured emptiness, not a lost source."));
      return;
    }
    root.append(jobsTable(rows));

    root.append(el("h2", {}, "Reprocessing (D-13)"));
    root.append(el("p", { class: "screen-note" },
      "A capture is fetched once and may be parsed many times. Bumping the extractor " +
      "and re-running it over stored captures costs CPU and contacts no source — " +
      "refetching instead is the error D-13 exists to prevent, and it costs real money."));

    const backlog = await api("/api/reprocess/backlog");
    root.append(el("p", { class: "screen-note" },
      `Current extractor: v${backlog.current_extractor_version}. ` +
      `${backlog.captures.length} capture(s) hold content from an older version.`));

    root.append(el("div", { class: "verdict-actions" },
      el("button", { onclick: async () => {
        const status = document.getElementById("reprocess-status");
        status.textContent = "reprocessing…";
        try {
          const r = await api("/api/reprocess", { method: "POST" });
          status.textContent = r.summary;
        } catch (error) { status.textContent = `failed: ${error.message}`; }
      } }, "Reprocess stored captures"),
      el("span", { id: "reprocess-status", class: "run-status" }, "")));
  },
};

screens.bundles = {
  title: "Evidence Bundles",
  note: "Each bundle is a WARC carrying its own manifest, chain entry and timestamp — verifiable without ASIP.",
  async render(root) {
    const rows = await api("/api/bundles");
    if (!rows.length) {
      root.append(emptyState("measured", "No evidence bundles sealed",
        "Bundles appear once a capture succeeds."));
      return;
    }
    root.append(table(["Chain", "Captured", "Source", "Manifest sha256", "Entry hash", "TSA", ""],
      rows, (b) => el("tr", { "data-row": "1" },
        el("td", { class: "num" }, b.chain_index),
        el("td", { class: "timestamp" }, ts(b.captured_at)),
        el("td", {}, b.source_url),
        el("td", { class: "hash" }, shortHash(b.manifest_sha256)),
        el("td", { class: "hash" }, shortHash(b.entry_hash)),
        el("td", {}, el("span", { class: `status status-${b.has_timestamp ? "ok" : "stale"}` },
          b.has_timestamp ? "verified" : "pending")),
        el("td", {}, el("button", { class: "link",
          onclick: () => go("evidence", { id: b.bundle_id }) }, "open")))));
  },
};

screens.evidence = {
  title: "Evidence Viewer",
  note: "One bundle, re-verified on open. Every check is reported separately — an analyst has to say which check failed, not quote a score.",
  async render(root, params) {
    if (!params.id) {
      root.append(emptyState("notready", "No bundle selected",
        "Choose a bundle from the Evidence Bundles screen."));
      return;
    }
    const b = await api(`/api/bundles/${params.id}`);
    const v = b.verification;

    root.append(el("dl", { class: "detail-grid" },
      dt("Bundle"), dd(b.bundle_id, "hash"),
      dt("Capture"), dd(b.capture_id, "hash"),
      dt("Trace"), dd(b.trace_id, "hash"),
      dt("Source"), dd(b.source_url),
      dt("Captured at"), dd(ts(b.captured_at), "timestamp"),
      dt("Manifest sha256"), dd(b.manifest_sha256, "hash"),
      dt("Chain index"), dd(b.chain_index, "hash"),
      dt("Chain entry"), dd(b.entry_hash, "hash"),
      dt("Previous entry"), dd(b.prev_hash, "hash"),
      dt("Chain algorithm"), dd(b.algorithm, "hash")));

    root.append(el("h2", {}, "Verification"));
    root.append(table(["Check", "Result"], [
      ["Manifest covers artifacts", v.manifest_ok],
      ["Hash chain intact", v.chain_ok],
      ["External timestamp", v.tsa_ok],
    ], ([name, ok]) => el("tr", { "data-row": "1" },
      el("td", {}, name),
      el("td", {}, el("span", { class: `status status-${ok ? "ok" : "stale"}` },
        ok ? "pass" : "not confirmed")))));

    if (v.problems.length) {
      root.append(el("h2", {}, "Problems"));
      root.append(el("ul", {}, v.problems.map((p) => el("li", {}, p))));
    }
    root.append(el("p", { class: "screen-note" },
      `Outcome: ${v.outcome}. “incomplete” means the content is intact but no external ` +
      `timestamp has been confirmed — neither verified nor broken.`));

    root.append(el("h2", {}, "Manifest (the bytes that were hashed)"));
    root.append(el("pre", { class: "doc" }, JSON.stringify(b.manifest, null, 2)));

    root.append(provenance({
      hash: b.manifest_sha256, time: b.captured_at,
      verified: (b.timestamps || []).length > 0, source: b.source_url,
      extra: `chain ${b.chain_index}`,
    }));
  },
};

screens.content = {
  title: "Extracted Content",
  note: "What the extractor recovered from each capture. The original text is preserved; the authoritative timestamp is derived.",
  async render(root) {
    const rows = await api("/api/content");
    if (!rows.length) {
      root.append(emptyState("measured", "Nothing extracted yet",
        "Content appears after a capture is parsed."));
      return;
    }
    root.append(table(
      ["Posted (authoritative)", "Precision", "Account", "Text", "Script", "Last seen", "Extractor"],
      rows, (c) => el("tr", { "data-row": "1" },
        el("td", { class: "timestamp" }, ts(c.posted_at_authoritative)),
        el("td", { class: "hash" }, c.timestamp_precision),
        el("td", {}, c.handle),
        el("td", {}, c.text),
        el("td", { class: "hash" }, c.script || "—"),
        el("td", { class: "timestamp" }, ts(c.last_seen)),
        el("td", { class: "num" }, `v${c.extractor_version}`))));
  },
};

screens.findings = {
  title: "Findings",
  note: "Clusters, never individuals. The unit of analysis is the group's behaviour — there is no object in this system that can hold a verdict about a person.",
  async render(root, params) {
    if (params.id) return findingDetail(root, params.id);
    const rows = await api("/api/findings");
    if (!rows.length) {
      root.append(emptyState("measured", "No findings in this window",
        "The rule ran and did not fire. That is a measurement, not an absence of data."));
      return;
    }
    root.append(table(["Detected", "Rule", "Window", "Items", "Accounts", "Status", ""],
      rows, (f) => el("tr", { "data-row": "1" },
        el("td", { class: "timestamp" }, ts(f.detected_at)),
        el("td", {}, f.rule_name),
        el("td", { class: "timestamp" }, `${ts(f.window_start)} → ${ts(f.window_end)}`),
        el("td", { class: "num" }, f.item_count),
        el("td", { class: "num" }, f.account_count),
        el("td", {}, f.shadow ? shadowBadge() : el("span", { class: "status status-ok" }, "measured"),
          f.verdict ? el("div", { class: `verdict verdict-${f.verdict.verdict}` },
            f.verdict.verdict.replace(/_/g, " ")) : null),
        el("td", {}, el("button", { class: "link",
          onclick: () => go("findings", { id: f.finding_id }) }, "open")))));
  },
};

//: The result of the last verdict posted, so the detail screen can report what
//: the verdict did after it re-renders. Cleared when a different finding opens.
let lastExport = null;

async function findingDetail(root, id) {
  if (lastExport && lastExport.finding_id !== id) lastExport = null;
  const f = await api(`/api/findings/${id}`);
  root.append(el("dl", { class: "detail-grid" },
    dt("Finding"), dd(f.finding_id, "hash"),
    dt("Rule"), dd(f.rule_name),
    dt("Trace"), dd(f.trace_id, "hash"),
    dt("Window"), dd(`${ts(f.window_start)} → ${ts(f.window_end)}`, "timestamp"),
    dt("Items"), dd(f.item_count),
    dt("Accounts in cluster"), dd(f.account_count),
    dt("Status"), dd(f.shadow ? "shadow — not a verdict" : "measured")));

  if (f.shadow) {
    root.append(el("p", { class: "screen-note" },
      "This rule has no measured precision, so it cannot be enabled (V-4) and its " +
      "output is an observation rather than a conclusion. Precision is measured " +
      "against hand-labelled data before any rule leaves shadow mode."));
  }

  root.append(el("h2", {}, "Signals"));
  root.append(el("table", { class: "signal-table" },
    el("thead", {}, el("tr", {}, ["Signal", "Observed", "Threshold", "Fired", "Meaning"]
      .map((c) => el("th", {}, c)))),
    el("tbody", {}, (f.signals || []).map((s) => el("tr", {},
      el("td", {}, s.name),
      el("td", { class: "signal-value" }, s.observed),
      el("td", { class: "signal-value" }, s.threshold),
      el("td", { class: s.passed ? "pass" : "fail" }, s.passed ? "yes" : "no"),
      el("td", {}, s.description))))));

  root.append(el("h2", {}, "Cluster membership"));
  root.append(el("p", { class: "screen-note" },
    "Which accounts acted together. This describes the group; it attaches nothing to any member."));
  root.append(table(["Account", "Items"], f.cluster || [], (c) =>
    el("tr", {}, el("td", { class: "hash" }, c.account_id), el("td", { class: "num" }, c.item_count))));

  root.append(el("h2", {}, "Evidence"));
  root.append(el("ul", {}, (f.evidence_refs || []).map((ref) =>
    el("li", {}, el("button", { class: "link", onclick: () => go("evidence", { id: ref }) },
      el("span", { class: "hash" }, ref))))));

  // D-112 — the question asked when a finding is disputed: which bytes is this
  // built on? One query, so the answer cannot disagree with itself.
  root.append(el("h2", {}, "Provenance"));
  const trace = await api(`/api/findings/${id}/trace`).catch(() => null);
  if (!trace) {
    root.append(el("p", { class: "screen-note held" }, "No trace available."));
  } else if (!trace.traceable) {
    root.append(el("p", { class: "screen-note held" }, trace.summary));
  } else {
    root.append(el("p", { class: "screen-note ok" }, trace.summary));
    root.append(el("dl", { class: "detail-grid" },
      dt("Capture"), dd(trace.capture_id, "hash"),
      dt("Captured"), dd(ts(trace.captured_at), "timestamp"),
      dt("Bundle"), dd(trace.bundle_id, "hash"),
      dt("Manifest"), dd(trace.manifest_sha256, "hash"),
      dt("Chain index"), dd(trace.chain_index),
      dt("Timestamped"), dd(trace.has_timestamp ? "yes — RFC 3161 token stored" : "not yet"),
      dt("Trace continuous"), dd(trace.trace_is_continuous
        ? `yes — ${trace.finding_trace_id} from fetch to finding`
        : `no — finding ${trace.finding_trace_id}, capture ${trace.bundle_trace_id}`),
      dt("Items still pointing here"), dd(
        `${trace.items_still_pointing_here} (first extracted from this capture: ${trace.items_from_this_capture})`)));
    root.append(el("p", { class: "screen-note" },
      "\"Items still pointing here\" falls to zero once the same items are seen " +
      "again in a later capture — the content moves forward while this finding " +
      "keeps pointing at the bytes it was actually built on. That is the intent: " +
      "the evidence a finding rests on does not change when the page does."));
  }

  root.append(el("h2", {}, "Verdict"));
  root.append(el("p", { class: "screen-note" },
    "Recording likely or confirmed coordination is what exports this finding as STIX. " +
    "M-06: nothing leaves the system on a rule's say-so — a rule with no measured " +
    "precision produces observations, and an observation sent to a recipient as an " +
    "assessment cannot be recalled."));

  // Survives the re-render below, which is the whole point: an analyst needs to
  // see what their verdict did, and re-rendering the screen would otherwise
  // discard the answer the moment it arrived.
  if (lastExport && lastExport.finding_id === id) {
    root.append(el("p", { class: lastExport.exported ? "screen-note ok" : "screen-note held" },
      lastExport.exported
        ? `Exported — ${lastExport.object_count} STIX objects, sha256 ${String(lastExport.bundle_sha256).slice(0, 16)}…`
        : `Not exported — ${lastExport.reason}`));
  }

  root.append(el("div", { class: "verdict-actions" },
    ["confirmed_coordination", "likely_coordination", "insufficient_evidence", "no_coordination"]
      .map((v) => el("button", { onclick: async () => {
        const res = await api(`/api/findings/${id}/verdict`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ verdict: v, analyst: "console" }),
        });
        // What the verdict did, not only that it was recorded. "Held in Tier 1"
        // is a result, not a failure — an analyst who is not told will conclude
        // the export is broken and go looking for a bug that does not exist.
        lastExport = { ...res, finding_id: id };
        go("findings", { id });
      } }, el("span", { class: `verdict verdict-${v}` }, v.replace(/_/g, " "))))));

  if ((f.verdict_history || []).length) {
    root.append(table(["Decided", "Verdict", "Analyst"], f.verdict_history, (v) =>
      el("tr", {}, el("td", { class: "timestamp" }, ts(v.decided_at)),
        el("td", {}, el("span", { class: `verdict verdict-${v.verdict}` }, v.verdict.replace(/_/g, " "))),
        el("td", {}, v.analyst))));
  }

  root.append(provenance({
    hash: f.finding_id, time: f.detected_at, verified: false,
    source: f.rule_name, extra: `${f.item_count} items / ${f.account_count} accounts`,
  }));
}

screens.timeline = {
  title: "Timeline",
  note: "Captures, bundles, findings and exports on one axis, so the pipeline reads as a sequence rather than four tables.",
  async render(root) {
    const rows = await api("/api/timeline");
    if (!rows.length) {
      root.append(emptyState("measured", "Nothing has happened yet",
        "The timeline fills as the pipeline runs."));
      return;
    }
    root.append(table(["When", "Stage", "Trace", "What", "Detail"], rows, (r) =>
      el("tr", { "data-row": "1" },
        el("td", { class: "timestamp" }, ts(r.at)),
        el("td", {}, el("span", { class: "hash" }, r.kind)),
        el("td", { class: "hash" }, r.trace_id),
        el("td", {}, r.label),
        el("td", { class: "hash" }, shortHash(r.detail)))));
  },
};

screens.scheduler = {
  title: "Scheduler",
  note: "The unattended run. Every tick is recorded, including the ones that found nothing due — that is how an idle system is told apart from a stopped one (D-68, D-87).",
  async render(root) {
    const data = await api("/api/scheduler/runs");
    const health = data.health || {};

    root.append(el("p", {
      class: health.status === "ok" ? "screen-note ok"
        : health.status === "unverified" ? "screen-note" : "screen-note held",
    }, health.detail || ""));

    if (!data.runs.length) {
      root.append(emptyState("unknown", "The scheduler has never run",
        "Nothing is being collected on a schedule. Start it with: make run-scheduler ASIP_DB_URL=…"));
      return;
    }

    root.append(table(
      ["Started", "Outcome", "Took", "Due", "Captures", "Items", "Findings", "Held", "Detail"],
      data.runs,
      (r) => el("tr", { "data-row": "1" },
        el("td", { class: "timestamp" }, ts(r.started_at)),
        el("td", {}, el("span", { class: `run run-${r.outcome}` }, r.outcome)),
        el("td", { class: "num" }, r.duration_seconds === null ? "—" : `${Number(r.duration_seconds).toFixed(1)}s`),
        el("td", { class: "num" }, r.sources_due),
        el("td", { class: "num" }, r.captures),
        el("td", { class: "num" }, r.items),
        el("td", { class: "num" }, r.findings),
        el("td", { class: "num" }, r.held_for_review),
        el("td", {}, r.detail))));

    root.append(el("p", { class: "screen-note" },
      "\"Held\" counts findings that stayed in Tier 1. A schedule does not bypass " +
      "M-06: export follows an analyst's verdict, never a rule firing. An " +
      "unattended run reaches detection and stops there by design."));
  },
};

screens.graph = {
  title: "Graph View",
  note: "Co-participation: accounts that appeared in the same finding. An edge says two accounts were in one window — a property of the cluster, not a claim about either account.",
  async render(root) {
    const g = await api("/api/graph");
    if (!g.nodes.length) {
      root.append(emptyState("measured", "No clusters to draw",
        "The graph fills once a finding groups accounts together."));
      return;
    }
    root.append(el("p", { class: "screen-note" },
      `${g.nodes.length} accounts, ${g.edges.length} co-participation edges, ${g.clusters} cluster(s).`));

    // Circular layout, drawn as inline SVG. Cytoscape (D-70) lands with the
    // React console; this exists so the shape of the data is visible now.
    const size = 420, cx = size / 2, cy = size / 2, r = 150;
    const positions = new Map(g.nodes.map((n, i) => {
      const angle = (2 * Math.PI * i) / g.nodes.length - Math.PI / 2;
      return [n.id, { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) }];
    }));
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("class", "graph");
    svg.setAttribute("viewBox", `0 0 ${size} ${size}`);

    for (const e of g.edges) {
      const a = positions.get(e.source), b = positions.get(e.target);
      if (!a || !b) continue;
      const line = document.createElementNS(svgNS, "line");
      line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
      line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
      svg.append(line);
    }
    for (const n of g.nodes) {
      const p = positions.get(n.id);
      const circle = document.createElementNS(svgNS, "circle");
      circle.setAttribute("cx", p.x); circle.setAttribute("cy", p.y); circle.setAttribute("r", 7);
      const text = document.createElementNS(svgNS, "text");
      text.setAttribute("x", p.x + 11); text.setAttribute("y", p.y + 4);
      text.textContent = n.label;
      svg.append(circle, text);
    }
    root.append(svg);
  },
};

screens.health = {
  title: "System Health",
  note: "What is working, and — more usefully — what is not. Silent degradation is the primary failure mode of this class of system, so known gaps are listed as gaps rather than omitted.",
  async render(root) {
    const h = await api("/api/health");
    root.append(table(["Component", "Status", "Detail"], h.checks, (c) =>
      el("tr", { "data-row": "1" },
        el("td", {}, c.name),
        el("td", {}, el("span", { class: `status status-${c.status}` }, c.status)),
        el("td", {}, c.detail))));
    root.append(el("h2", {}, "Detection rules"));
    const rules = await api("/api/rules");
    root.append(table(["Rule", "Shadow", "Enabled", "Measured precision"], rules, (r) =>
      el("tr", {}, el("td", {}, r.name),
        el("td", {}, r.shadow_mode ? "yes" : "no"),
        el("td", {}, r.enabled ? "yes" : "no"),
        el("td", { class: "num" }, r.measured_precision ?? "not measured"))));
    root.append(el("p", { class: "screen-note" },
      "A rule with no measured precision cannot be enabled — the database refuses it (V-4)."));

    root.append(el("h2", {}, "Chain anchoring"));
    root.append(el("p", { class: "screen-note" },
      "A hash chain proves nobody edited one record. It does not stop someone with " +
      "database access rebuilding the chain from genesis — every link consistent, the " +
      "whole history replaced. An anchor is an external timestamp over the chain head; " +
      "once one exists, history before it cannot be rewritten undetectably."));

    const anchorBar = el("div", { class: "verdict-actions" },
      el("button", { onclick: async () => {
        const status = document.getElementById("anchor-status");
        status.textContent = "anchoring…";
        try {
          const r = await api("/api/chain/anchor", { method: "POST" });
          status.textContent = `${r.status}: ${r.detail}`;
          go("health");
        } catch (error) { status.textContent = `failed: ${error.message}`; }
      } }, "Anchor chain head now"),
      el("span", { id: "anchor-status", class: "run-status" }, ""));
    root.append(anchorBar);

    const anchors = await api("/api/chain/anchors");
    if (!anchors.length) {
      root.append(emptyState("notready", "The chain has never been anchored",
        "Everything written so far is rewritable without detection. This is a real gap, " +
        "not a cosmetic one — anchor the head to close it."));
    } else {
      root.append(table(["Anchored at", "Chain index", "Entry hash", "Authority", "Token"],
        anchors, (a) => el("tr", { "data-row": "1" },
          el("td", { class: "timestamp" }, ts(a.anchored_at)),
          el("td", { class: "num" }, a.chain_index),
          el("td", { class: "hash" }, shortHash(a.entry_hash)),
          el("td", {}, a.authority_url),
          el("td", { class: "num" }, `${a.token_bytes} B`))));
    }
  },
};

screens.exports = {
  title: "STIX Exports",
  note: "Findings serialised as STIX 2.1, so they can be exchanged with organisations that have never heard of ASIP.",
  async render(root) {
    const rows = await api("/api/exports");
    if (!rows.length) {
      root.append(emptyState("measured", "Nothing exported yet",
        "Exports are written when a finding is produced."));
      return;
    }
    root.append(table(["Created", "Finding", "Objects", "Bundle sha256", ""], rows, (e) =>
      el("tr", { "data-row": "1" },
        el("td", { class: "timestamp" }, ts(e.created_at)),
        el("td", { class: "hash" }, shortHash(e.finding_id)),
        el("td", { class: "num" }, e.object_count),
        el("td", { class: "hash" }, shortHash(e.bundle_sha256)),
        el("td", {}, el("button", { class: "link", onclick: async () => {
          const body = await api(`/api/exports/${e.export_id}/bundle`);
          const box = document.getElementById("stix-preview");
          box.textContent = JSON.stringify(JSON.parse(body), null, 2);
        } }, "view")))));
    root.append(el("h2", {}, "Bundle"));
    root.append(el("pre", { class: "doc", id: "stix-preview" }, "Select an export to view its STIX bundle."));
  },
};

const dt = (text) => el("dt", {}, text);
const dd = (text, cls) => el("dd", { class: cls || "" }, text ?? "—");

// ── routing and keyboard ───────────────────────────────────────────────────

const ORDER = ["dashboard", "sources", "scheduler", "captures", "bundles", "evidence",
               "content", "findings", "timeline", "graph", "exports", "health"];

let current = "dashboard";
let cursor = -1;

function go(name, params = {}) {
  current = name;
  const query = new URLSearchParams({ screen: name, ...params });
  history.replaceState(null, "", `#${query}`);
  render();
}

async function render() {
  const root = document.getElementById("screen");
  const params = Object.fromEntries(new URLSearchParams(location.hash.slice(1)));
  const screen = screens[current] || screens.dashboard;
  root.replaceChildren(
    el("h1", {}, screen.title),
    el("p", { class: "screen-note" }, screen.note));
  cursor = -1;
  try {
    await screen.render(root, params);
  } catch (error) {
    root.append(emptyState("unknown", "This screen could not load",
      `${error.message}. The API may be unreachable or the database may not be migrated. ` +
      `This is an unknown state, not an empty one — do not read it as "no data".`));
  }
  drawNav();
}

function drawNav() {
  const nav = document.getElementById("nav");
  nav.replaceChildren(...ORDER.map((name, i) =>
    el("button", {
      "aria-current": String(name === current),
      onclick: () => go(name),
    }, el("span", { class: "idx" }, i + 1), screens[name].title)));
}

async function runPipeline() {
  const button = document.getElementById("run-pipeline");
  const status = document.getElementById("run-status");
  button.disabled = true;
  status.textContent = "running…";
  try {
    const result = await api("/api/pipeline/run", { method: "POST" });
    status.textContent = `${result.trace_id} · ${result.stages.length} stages`;
    const root = document.getElementById("screen");
    const panel = el("div", { class: "stages" },
      result.stages.map((s) => el("div", { class: `stage ${s.status}` },
        el("span", { class: "name" }, s.stage),
        el("span", { class: `status status-${s.status}` }, s.status),
        el("span", {}, s.detail))));
    root.prepend(el("h2", {}, "Last pipeline run"), panel);
  } catch (error) {
    status.textContent = `failed: ${error.message}`;
  } finally {
    button.disabled = false;
  }
}

/* D-67: the analyst should not have to touch the mouse. */
let pendingG = false;
document.addEventListener("keydown", (event) => {
  if (event.target.matches("input, textarea")) return;
  if (event.key === "g") { pendingG = true; return; }
  if (pendingG && /^[1-9]$/.test(event.key)) {
    pendingG = false;
    const name = ORDER[Number(event.key) - 1];
    if (name) go(name);
    return;
  }
  pendingG = false;
  if (event.key === "r") runPipeline();
  if (event.key === "j" || event.key === "k") {
    const rows = [...document.querySelectorAll("tbody tr[data-row]")];
    if (!rows.length) return;
    rows[cursor]?.classList.remove("cursor");
    cursor = Math.max(0, Math.min(rows.length - 1, cursor + (event.key === "j" ? 1 : -1)));
    rows[cursor].classList.add("cursor");
    rows[cursor].scrollIntoView({ block: "nearest" });
  }
  if (event.key === "Enter" && cursor >= 0) {
    document.querySelectorAll("tbody tr[data-row]")[cursor]
      ?.querySelector("button.link")?.click();
  }
});

document.getElementById("run-pipeline").addEventListener("click", runPipeline);

const initial = Object.fromEntries(new URLSearchParams(location.hash.slice(1)));
current = screens[initial.screen] ? initial.screen : "dashboard";
render();
