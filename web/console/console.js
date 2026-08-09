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

/* Thrown for a 403 so a screen can show *why* it was denied rather than a
   generic failure. A denial carries the audit entry that recorded it, which is
   what a support conversation should start from. */
class Denied extends Error {
  constructor(detail, entry) { super(detail); this.entry = entry; }
}

const api = async (path, options) => {
  const response = await fetch(path, { credentials: "same-origin", ...options });

  if (response.status === 401) {
    // The session went away — expired, revoked, or the user was disabled. Not
    // an error to display: it means the login screen, and losing the current
    // screen is the correct outcome rather than a half-rendered one.
    showLogin();
    throw new Error("not authenticated");
  }
  if (response.status === 403) {
    const body = await response.json().catch(() => ({}));
    throw new Denied(body.detail || "not permitted", body.audit_entry);
  }
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

/* What each support level means on screen. Symbol plus label, never colour
   alone (D-62) — and the wording is about consequence, not implementation.
   Nobody adding a page cares that there is no extractor; they care whether
   this will ever tell them anything. */
const SUPPORT_LABEL = {
  extracts: "◆ fully read",
  capture_only: "· evidence only",
  blocked: "✕ cannot reach",
  unknown: "? unrecognised",
};

screens.sources = {
  title: "Sources",
  note: "What is monitored, how often, and when each was last read successfully. Adding a page here is what starts collection.",
  async render(root) {
    const data = await api("/api/sources");
    const rows = data.sources || [];

    // Adding a source is an administrative act (MANAGE_PROJECTS), and it is
    // the tenant_admin's, not the analyst's — a source's project decides who
    // can see its findings, so adding one is a permissions change wearing a
    // different hat (D-49).
    //
    // Hidden rather than shown-and-refused: an analyst who fills in a form and
    // is then told no has been wasted, and the audit log gains a denial that
    // records our interface being wrong rather than them being. The API still
    // enforces it — this only stops the pointless attempt.
    if (canManageSources()) {
      root.append(bulkForm(data.platforms || []));
      root.append(sourceForm(data.platforms || []));
    } else {
      root.append(el("p", { class: "screen-note" },
        "Adding or pausing a source is a tenant administrator's action. You are signed in " +
        "as " + (me ? me.roles.join(" · ") : "an analyst") + "."));
    }

    root.append(el("h2", {}, "Monitored"));
    if (!rows.length) {
      root.append(emptyState("notready", "No sources configured",
        "Nothing is being collected. Add one above, or run `make seed-dev` for the canary."));
      return;
    }

    root.append(table(
      ["Name", "URL", "Platform", "Reads", "Baseline", "Every", "Enabled", "Last success", "Fails"],
      rows, (s) => el("tr", { "data-row": "1" },
        el("td", {}, s.name),
        el("td", {}, el("a", { href: s.url, target: "_blank", rel: "noreferrer" }, s.url)),
        el("td", {}, s.platform),
        el("td", {}, el("span", { class: `support support-${s.support}`, title: s.support_note },
          SUPPORT_LABEL[s.support] || s.support)),
        el("td", {}, baselineCell(s)),
        el("td", { class: "num" }, `${s.interval_seconds}s`),
        el("td", {}, canManageSources()
          ? el("button", {
              class: "link",
              onclick: async () => {
                await api(`/api/sources/${s.source_id}/enabled`, {
                  method: "POST", headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ enabled: !s.enabled }),
                });
                go("sources");
              },
            }, s.enabled ? "on — pause" : "off — resume")
          : (s.enabled ? "on" : "off")),
        el("td", { class: "timestamp" }, ts(s.last_success_at)),
        el("td", { class: "num" }, s.consecutive_failures))));

    // Anything that will never produce a finding says so here too, not only in
    // a tooltip. A source quietly collecting nothing is how an empty Findings
    // screen gets misread as "no coordinated activity" (D-68).
    const mute = rows.filter((s) => s.support !== "extracts");
    if (mute.length) {
      root.append(el("p", { class: "screen-note held" },
        `${mute.length} of ${rows.length} source(s) will not produce findings. ` +
        `They are captured and sealed as evidence, and nothing is extracted from them. ` +
        `An empty Findings screen for these means "not read", not "nothing happening".`));
    }

    // The single most misreadable state in the product's first month.
    const young = rows.filter(
      (s) => s.support === "extracts" && (s.observed_days ?? 0) < BASELINE_DAYS);
    if (young.length) {
      const most = Math.max(...young.map((s) => s.observed_days ?? 0));
      root.append(el("p", { class: "screen-note held" },
        `${young.length} source(s) are still building a baseline — the longest has ` +
        `${most} of ${BASELINE_DAYS} days. Until a source is ready, D-80 holds every rule ` +
        `against it, so an empty Findings screen right now means "not enough history yet", ` +
        `not "nothing is happening". This is the one wait that no amount of engineering ` +
        `shortens.`));
    }
  },
};

/* D-31 / D-80. Roughly thirty days of history before a rule may fire against a
   source, so the first month's honest answer is "watching, cannot tell you yet"
   — and that has to be legible. A month of empty Findings screens read as "no
   coordinated activity" is the D-68 failure at its most expensive: sustained,
   confident, and wrong. */
const BASELINE_DAYS = 30;

/* A courtesy, never the enforcement. The API checks for itself and a console
   bug that showed the form would still get a 403. */
const canManageSources = () => Boolean(me?.permissions?.includes("manage_projects"));

function baselineCell(source) {
  const days = source.observed_days ?? 0;
  if (!source.observing_since) {
    return el("span", { class: "support support-unknown" }, "not started");
  }
  if (days >= BASELINE_DAYS) {
    return el("span", { class: "support support-extracts", title: `${days} days observed` },
      "◆ baseline ready");
  }
  return el("span", {
    class: "support support-capture_only",
    title: "A rule cannot fire against this source until its baseline is ready (D-80).",
  }, `· day ${days} of ${BASELINE_DAYS}`);
}

function bulkForm(platforms) {
  const box = el("textarea", {
    id: "bulk-list", rows: "6",
    placeholder: "one per line — channel name, @name, or t.me link\n\ncivilgeorgia\n@some_channel\nhttps://t.me/another",
  });
  const select = el("select", { id: "bulk-platform" },
    ...platforms.filter((p) => p.support === "extracts")
      .map((p) => el("option", { value: p.key }, p.label)));
  const result = el("p", { class: "screen-note" });

  const submit = async (event) => {
    event.preventDefault();
    result.className = "screen-note";
    result.textContent = "adding…";
    try {
      const r = await api("/api/sources/bulk", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sources: box.value, platform: select.value, interval_seconds: 3600 }),
      });
      result.className = r.rejected.length ? "screen-note held" : "screen-note ok";
      result.textContent =
        `${r.added.length} added. ${r.clock}` +
        (r.rejected.length
          ? `  Rejected ${r.rejected.length}: ` +
            r.rejected.map((x) => `${x.input} (${x.reason})`).join("; ")
          : "");
      box.value = "";
      setTimeout(() => go("sources"), 2500);
    } catch (error) {
      result.className = "screen-note held";
      result.textContent = error.message;
    }
  };

  return el("div", {},
    el("h2", {}, "Start watching a list"),
    el("p", { class: "screen-note" },
      "Paste the channels you want monitored. Collection has a thirty-day lead time and " +
      "nothing else does — every day not collecting is a day added to the earliest " +
      "possible answer, so start with the ones you are sure about and add more later. " +
      "Re-pasting the same list is safe: it will not restart anyone's clock."),
    el("form", { class: "source-form bulk", onsubmit: submit },
      el("label", { for: "bulk-platform" }, "Platform"), select,
      el("label", { for: "bulk-list" }, "Channels"), box,
      el("button", { type: "submit" }, "Start watching")),
    result);
}

function sourceForm(platforms) {
  const name = el("input", { type: "text", id: "src-name", placeholder: "Ministry press page" });
  const url = el("input", { type: "url", id: "src-url", placeholder: "https://…" });
  const interval = el("input", { type: "number", id: "src-interval", value: "3600", min: "60" });
  const select = el("select", { id: "src-platform" },
    ...platforms.map((p) => el("option", { value: p.key }, p.label)));

  const explain = el("p", { class: "screen-note" });
  const result = el("p", { class: "screen-note" });

  // The explanation updates as the platform changes, BEFORE anything is
  // submitted. Telling someone after they added a Facebook page that it cannot
  // be read is worse than not telling them: they have already formed the
  // expectation this screen exists to set.
  const describe = () => {
    const chosen = platforms.find((p) => p.key === select.value);
    if (!chosen) return;
    explain.textContent = chosen.note;
    explain.className = chosen.support === "extracts" ? "screen-note ok" : "screen-note held";
  };
  select.addEventListener("change", describe);

  const submit = async (event) => {
    event.preventDefault();
    result.textContent = "";
    try {
      const response = await api("/api/sources", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.value,
          url: url.value,
          platform: select.value,
          interval_seconds: Number(interval.value),
        }),
      });
      result.className = response.warning ? "screen-note held" : "screen-note ok";
      result.textContent = response.warning
        ? `Added — but ${response.warning}`
        : "Added. It will be collected on the next scheduler tick.";
      name.value = "";
      url.value = "";
      setTimeout(() => go("sources"), 1200);
    } catch (error) {
      result.className = "screen-note held";
      result.textContent = error.message;
    }
  };

  const form = el("form", { class: "source-form", onsubmit: submit },
    el("label", { for: "src-name" }, "Name"), name,
    el("label", { for: "src-url" }, "URL"), url,
    el("label", { for: "src-platform" }, "Platform"), select,
    el("label", { for: "src-interval" }, "Check every (seconds)"), interval,
    el("button", { type: "submit" }, "Add source"));

  const wrap = el("div", {},
    el("h2", {}, "Add a source"),
    form, explain, result);
  describe();
  return wrap;
}

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

/* ── authentication ─────────────────────────────────────────────────────────
   The console is a shell over the API and holds no data of its own, so it does
   not decide what anyone may see — the API denies and this renders the denial.
   `whoami` is used only to label the header and hide screens that would 403
   anyway. Hiding a screen is a courtesy; the enforcement is server-side. */

let me = null;

function showLogin(message) {
  document.getElementById("nav").replaceChildren();
  const root = document.getElementById("screen");
  const error = el("p", { class: "screen-note held" }, message || "");

  const email = el("input", { type: "email", id: "login-email", autocomplete: "username",
                              placeholder: "analyst@asip.local" });
  const password = el("input", { type: "password", id: "login-password",
                                 autocomplete: "current-password" });

  const submit = async (event) => {
    event.preventDefault();
    error.textContent = "";
    const response = await fetch("/api/auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email.value, password: password.value }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      // One message for every failure, matching the API. Telling the user
      // which half was wrong tells an attacker the same thing.
      error.textContent = body.detail || "Sign in failed.";
      return;
    }
    me = null;
    await start();
  };

  root.replaceChildren(
    el("h1", {}, "Sign in"),
    el("p", { class: "screen-note" },
      "The console shows one tenant's data and only the projects you are assigned to. " +
      "Every screen you open is recorded in the audit log, including the ones you are " +
      "refused (D-52)."),
    el("form", { class: "login", onsubmit: submit },
      el("label", { for: "login-email" }, "Email"), email,
      el("label", { for: "login-password" }, "Password"), password,
      el("button", { type: "submit" }, "Sign in")),
    error);
}

screens.audit = {
  title: "Audit Log",
  note: "Who did what, and who was refused. Append-only and hash-chained — the database grants no UPDATE or DELETE on this table, to anyone (D-51).",
  async render(root) {
    const data = await api("/api/audit");

    root.append(el("p", {
      class: data.chain_intact ? "screen-note ok" : "screen-note held",
    }, data.chain_intact
      ? `Chain verified over ${data.entries.length} entries — no entry has been altered, removed or reordered.`
      : `CHAIN BROKEN: ${data.problems.join("; ")}`));

    if (!data.entries.length) {
      root.append(emptyState("measured", "Nothing recorded yet",
        "The log fills as people read and act. An empty audit log on a system in use is itself a finding."));
      return;
    }

    root.append(table(["When", "#", "Actor", "Action", "Resource", "Outcome", "Why"],
      data.entries, (e) => el("tr", { "data-row": "1" },
        el("td", { class: "timestamp" }, ts(e.occurred_at)),
        el("td", { class: "num" }, e.chain_index),
        el("td", { class: "hash" }, shortHash(e.actor_id)),
        el("td", {}, e.action.replace(/_/g, " ")),
        el("td", { class: "hash" }, `${e.resource_type}/${shortHash(e.resource_id)}`),
        el("td", {}, el("span", { class: `run run-${e.outcome === "allowed" ? "ok" : "failed"}` },
          e.outcome)),
        el("td", {}, e.reason))));
  },
};

const ORDER = ["dashboard", "sources", "scheduler", "captures", "bundles", "evidence",
               "content", "findings", "timeline", "graph", "exports", "audit", "health"];

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
    if (error instanceof Denied) {
      // A denial is not a broken screen. Saying so plainly, with the audit
      // entry that recorded it, is the difference between "this tool is
      // broken" and "you are not assigned to this project" (D-49, D-68).
      root.append(emptyState("unknown", "You do not have access to this",
        `${error.message}` +
        (error.entry ? ` — recorded in the audit log as ${error.entry}.` : "")));
    } else if (error.message !== "not authenticated") {
      root.append(emptyState("unknown", "This screen could not load",
        `${error.message}. The API may be unreachable or the database may not be migrated. ` +
        `This is an unknown state, not an empty one — do not read it as "no data".`));
    }
  }
  drawNav();
}

let hiddenScreens = [];

function drawNav(hidden) {
  if (hidden !== undefined) hiddenScreens = hidden;
  const nav = document.getElementById("nav");
  const visible = ORDER.filter((name) => !hiddenScreens.includes(name));
  nav.replaceChildren(...visible.map((name, i) =>
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
    // The visible list, not ORDER — otherwise the numbers on screen and the
    // numbers the keyboard uses drift apart as soon as a screen is hidden.
    const name = ORDER.filter((s) => !hiddenScreens.includes(s))[Number(event.key) - 1];
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

/* Who am I, and therefore what is worth showing.

   The identity strip is not decoration: an analyst who cannot see which tenant
   and which project they are looking at can misread one client's data as
   another's, and the console gives no other clue (D-68). */
function drawIdentity() {
  const bar = document.getElementById("identity") || (() => {
    const node = el("div", { id: "identity", class: "identity" });
    document.getElementById("nav").after(node);
    return node;
  })();

  if (!me) { bar.replaceChildren(); return; }
  bar.replaceChildren(
    el("span", { class: "hash" }, `tenant ${shortHash(me.tenant_id)}`),
    el("span", {}, me.roles.join(" · ")),
    el("span", { class: "hash" },
      me.projects.length === 1
        ? `project ${shortHash(me.projects[0])}`
        : `${me.projects.length} projects`),
    el("button", { class: "link", onclick: async () => {
      await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
      me = null;
      showLogin("Signed out.");
    } }, "sign out"));
}

async function start() {
  try {
    me = await api("/api/auth/me");
  } catch {
    // api() already routed a 401 to the login screen. Anything else means the
    // API is unreachable, and the login form is still the honest next step.
    if (!me) return;
  }

  // Screens the current roles cannot use are hidden rather than shown-and-403.
  // A courtesy only: the API is what enforces this, and a console bug that
  // showed one would still be refused.
  const hidden = me.permissions.includes("read_audit") ? [] : ["audit"];
  drawNav(hidden);
  drawIdentity();

  const initial = Object.fromEntries(new URLSearchParams(location.hash.slice(1)));
  current = screens[initial.screen] ? initial.screen : "dashboard";
  render();
}

start();
