// RemoteConfig dashboard: dependency-free single page app.
// Everything from devices (names, events, messages) is attacker-influenced, so the DOM
// is built with text nodes only (see h()); never assign device data to innerHTML.
"use strict";

const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } },
};

const state = {
  token: store.get("rc.session") || "",   // a dashboard session token (never the password)
  project: store.get("rc.project") || "",
  me: null,          // {id, username, display_name, is_admin}
  projects: [],      // [{id, name, role}]: only the projects this user can see
  view: "devices",   // devices | device | config | members | users | audit
  deviceId: null,
  scope: "global",
  notice: null,      // {kind, text}
  timer: null,
};

// What the signed-in user may do in the current project. The server enforces every one of
// these; the page only hides what would be refused, so nobody is offered a button that errors.
const RANK = { viewer: 1, operator: 2, admin: 3 };
const myRole = () => state.projects.find((p) => p.id === state.project)?.role || "";
const can = (min) => (RANK[myRole()] || 0) >= RANK[min];
const isServerAdmin = () => !!state.me?.is_admin;

// ------------------------------------------------------------------ helpers

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v; // via the CSSOM: a style="" attribute is blocked by the page's CSP
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "aria-current") el.setAttribute(k, v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

async function api(method, path, body) {
  const res = await fetch("/v1/admin" + path, {
    method,
    headers: { Authorization: "Bearer " + state.token, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) { signOut(); throw new ApiError(401, "Signed out"); }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data.error || res.statusText);
  return data;
}

function ago(ts) {
  const t = ts ? new Date(ts).getTime() : 0;
  if (!t || t < 86400000 * 366) return "never";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 5) return "just now";
  if (s < 90) return s + "s ago";
  if (s < 5400) return Math.round(s / 60) + "m ago";
  if (s < 129600) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
}

function bytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}

function dur(s) {
  s = Math.round(Number(s) || 0);
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s";
  if (s < 86400) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
  return Math.floor(s / 86400) + "d " + Math.floor((s % 86400) / 3600) + "h";
}

const reachClass = { online: "ok", stale: "warn", offline: "bad" };
const appClass = { running: "ok", loading: "warn", idle: "", error: "bad", stopped: "bad" };

function badge(text, cls) { return h("span", { class: "badge " + (cls || "") }, text); }
const reachBadge = (d) => badge(d.reachability, reachClass[d.reachability]);
const appBadge = (d) => badge("app: " + (d.app_state || "no data"), appClass[d.app_state] ?? "");
// Signed config: "strict" agents only act on what the server signed; "legacy" ones still accept
// unsigned content (an attacker on the network could change their config); "rejecting" ones
// refused something recently, which is worth a look.
const sigBadge = (d) => d.signature_state === "rejecting" ? badge("rejecting bad signatures", "bad")
  : d.signature_state === "legacy" ? badge("accepts unsigned config", "warn") : null;

function sigRow(d) {
  const t = d.trust;
  if (!t) return ["Signatures", "not reported yet"];
  if (t.state === "legacy") return ["Signatures", h("span", null, "Unsigned config is accepted. Reinstall with the server key to enforce signing.")];
  const bits = [`enforced, ${t.keys_trusted} trusted key${t.keys_trusted === 1 ? "" : "s"}`];
  if (t.key_id) bits.push("config verified with " + t.key_id);
  if (t.pinned) bits.push("key pinned at install");
  return ["Signatures", h("div", null, bits.join(" · "),
    t.rejected ? h("div", { class: "lvl-error small" }, `${t.rejected} refused: ${t.last_rejected}`) : null)];
}

const budgetBadge = (d) => d.budget_state === "soft" ? badge("data budget low", "warn")
  : d.budget_state === "exhausted" ? badge("data budget used up", "bad") : null;

// ------------------------------------------------------------------ screenshots
// Images need the admin token, which an <img src> cannot send, so they are fetched as
// blobs and shown through object URLs (no token ever appears in a URL). A small cache
// keeps the 5-second auto refresh from re-downloading anything.

const imgCache = new Map(); // artifact id -> object URL, oldest first
const IMG_CACHE_MAX = 80;

async function imageUrl(id) {
  if (imgCache.has(id)) return imgCache.get(id);
  const res = await fetch(`/v1/admin/projects/${state.project}/artifacts/${id}`, { headers: { Authorization: "Bearer " + state.token } });
  if (!res.ok) throw new ApiError(res.status, "image unavailable");
  const url = URL.createObjectURL(await res.blob());
  imgCache.set(id, url);
  while (imgCache.size > IMG_CACHE_MAX) {
    const [oldId, oldUrl] = imgCache.entries().next().value;
    imgCache.delete(oldId);
    URL.revokeObjectURL(oldUrl);
  }
  return url;
}

const lazyImages = new IntersectionObserver((entries) => {
  for (const e of entries) {
    if (!e.isIntersecting) continue;
    lazyImages.unobserve(e.target);
    imageUrl(e.target.dataset.id).then((u) => { e.target.src = u; }, () => e.target.classList.add("broken"));
  }
}, { rootMargin: "300px" });

function shotImg(id, cls, alt) {
  const img = h("img", { class: cls, alt, draggable: "false" });
  if (imgCache.has(id)) img.src = imgCache.get(id); // cached: present at first paint, so the refresh sees no change
  else { img.dataset.id = id; lazyImages.observe(img); }
  return img;
}

// One capture produces one artifact per display; they share meta.group.
function groupShots(arts) {
  const groups = new Map();
  for (const a of arts) {
    const key = a.meta?.group || a.id;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(a);
  }
  return [...groups.values()].map((g) => g.sort((a, b) => (a.meta?.display ?? 0) - (b.meta?.display ?? 0)));
}

function reasonText(r) {
  if (!r || r === "schedule") return "scheduled";
  if (r === "command") return "on request";
  return r.startsWith("event:") ? "after " + r.slice(6).replace("app.", "app ") : r;
}

function openLightbox(groups, start, refresh) {
  let gi = start, di = 0;
  const stage = h("div", { class: "stage" });
  const info = h("div", { class: "muted small" });
  const tabs = h("div", { class: "row" });
  const dlg = h("dialog", { class: "lightbox" });

  const show = () => {
    const g = groups[gi], a = g[di];
    stage.replaceChildren(shotImg(a.id, "big", "Screenshot"));
    info.textContent = `${ago(a.captured_at)} · ${new Date(a.captured_at).toLocaleString()} · ${a.meta?.width}×${a.meta?.height} (native ${a.meta?.orig_width}×${a.meta?.orig_height}) · ${bytes(a.size)} · ${reasonText(a.meta?.reason)}`
      + (a.meta?.black ? " · BLACK: screen locked/asleep or an exclusive-fullscreen app" : "");
    tabs.replaceChildren(...g.map((s, i) => h("button", { class: "btn small" + (i === di ? " primary" : ""), onclick: () => { di = i; show(); } }, "Display " + ((s.meta?.display ?? i) + 1))));
    prev.disabled = gi >= groups.length - 1;
    next.disabled = gi <= 0;
  };
  const go = (d) => { const n = gi + d; if (n >= 0 && n < groups.length) { gi = n; di = 0; show(); } };
  const prev = h("button", { class: "btn small", onclick: () => go(1) }, "‹ Older");
  const next = h("button", { class: "btn small", onclick: () => go(-1) }, "Newer ›");
  const del = h("button", { class: "btn small danger", onclick: async () => {
    const a = groups[gi][di];
    if (!confirm("Delete this screenshot?")) return;
    try { await api("DELETE", `/projects/${state.project}/artifacts/${a.id}`); } catch (e) { return alert(e.message); }
    dlg.close();
    refresh();
  } }, "Delete");
  dlg.append(stage, h("div", { class: "row between mt" }, h("div", { class: "row" }, prev, next, tabs), h("div", { class: "row" }, can("operator") ? del : null, h("button", { class: "btn small", onclick: () => dlg.close() }, "Close"))), info);
  dlg.addEventListener("keydown", (e) => { if (e.key === "ArrowLeft") go(1); if (e.key === "ArrowRight") go(-1); });
  dlg.addEventListener("close", () => dlg.remove());
  document.body.append(dlg);
  show();
  dlg.showModal();
}

function screenshotPolicyText(p) {
  if (!p || !p.enabled) return "Scheduled capture is off. “Capture now” still works.";
  const every = p.interval_s ? (p.interval_s % 60 === 0 ? p.interval_s / 60 + " min" : p.interval_s + " s") : "5 min";
  return `Every ${every} · ${p.max_width || 1280}px wide · JPEG q${p.quality || 60}` + (p.on_event ? " · also when the app hangs or crashes" : "")
    + (p.upload_unchanged ? "" : " · unchanged screens are skipped");
}

function budgetRow(d) {
  const used = (d.bytes_in || 0) + (d.bytes_out || 0);
  if (!d.budget_mb) return ["Data this cycle", `${bytes(used)} (no budget set)`];
  const pct = Math.min(100, Math.round(used * 100 / (d.budget_mb * 1048576)));
  const cls = d.budget_state === "exhausted" ? "bad" : d.budget_state === "soft" ? "warn" : "ok";
  return ["Data this cycle", h("div", null, `${bytes(used)} of ${d.budget_mb} MB (${pct}%)`,
    h("div", { class: "bar " + cls, role: "progressbar", "aria-valuenow": pct, "aria-valuemin": 0, "aria-valuemax": 100 }, h("i", { style: `width:${pct}%` })))];
}

function setNotice(kind, text) { state.notice = text ? { kind, text } : null; }
function noticeEl() { return state.notice ? h("div", { class: "msg " + state.notice.kind + " mt" }, state.notice.text) : null; }

function signOut(serverSide = false) {
  if (serverSide === true && state.token) { // end the session on the server too, so a copied token is dead
    fetch("/v1/auth/logout", { method: "POST", headers: { Authorization: "Bearer " + state.token } }).catch(() => {});
  }
  store.del("rc.session");
  state.token = "";
  state.me = null;
  state.projects = [];
  state.view = "devices";
  stopTimer();
  render();
}

function stopTimer() { clearInterval(state.timer); state.timer = null; }
function startTimer(fn, ms) { stopTimer(); state.timer = setInterval(fn, ms); }

// ------------------------------------------------------------------ chrome

function go(view, extra = {}) {
  Object.assign(state, { view, notice: null }, extra);
  render();
}

function chrome(content) {
  const sel = h("select", {
    "aria-label": "Project",
    onchange: (e) => { state.project = e.target.value; store.set("rc.project", state.project); go("devices"); },
  }, state.projects.map((p) => h("option", { value: p.id, selected: p.id === state.project }, p.name)));

  const tab = (id, label) => h("button", {
    class: "tab", "aria-current": (state.view === id || (id === "devices" && state.view === "device")) ? "page" : null,
    onclick: () => go(id),
  }, label);

  const role = myRole();
  const inProject = state.projects.length > 0;
  return h("div", null,
    h("header", { class: "topbar" },
      h("div", { class: "brand" }, h("i"), "RemoteConfig"),
      inProject ? sel : null,
      inProject && role ? h("span", { class: "rolepill", title: "Your role in this project" }, role) : null,
      h("nav", { class: "tabs" },
        inProject ? [tab("devices", "Devices"), tab("config", "Config"), tab("library", "Library")] : null,
        can("admin") ? [tab("members", "Members"), tab("audit", "Audit")] : null,
        isServerAdmin() ? tab("users", "Users") : null),
      h("div", { class: "spacer" }),
      isServerAdmin() ? h("button", { class: "btn small", onclick: newProjectDialog }, "New project") : null,
      can("admin") ? h("button", { class: "btn small", onclick: enrollDialog }, "Add device") : null,
      h("button", { class: "btn small", onclick: accountDialog, "aria-haspopup": "dialog" }, state.me?.display_name || state.me?.username || "Account")),
    h("main", { class: "page" }, content));
}

// ------------------------------------------------------------------ devices

async function viewDevices() {
  const devices = await api("GET", `/projects/${state.project}/devices`);
  const count = (f) => devices.filter(f).length;
  const stat = (n, label) => h("div", { class: "card stat" }, h("b", null, n), h("span", { class: "muted" }, label));

  const summary = h("div", { class: "summary" },
    stat(devices.length, "devices"),
    stat(count((d) => d.reachability === "online"), "online"),
    stat(count((d) => d.app_state === "error" || d.app_state === "stopped"), "app problems"),
    stat(count((d) => !d.in_sync), "config out of sync"),
    stat(count((d) => d.budget_state === "soft" || d.budget_state === "exhausted"), "data budget alerts"),
    stat(count((d) => d.signature_state === "legacy" || d.signature_state === "rejecting"), "signature problems"));

  const cards = devices.map((d) => h("button", { class: "card devcard", onclick: () => go("device", { deviceId: d.id }) },
    h("div", { class: "row between" }, h("h2", null, d.name), reachBadge(d)),
    h("div", { class: "row mt" }, appBadge(d), budgetBadge(d), sigBadge(d),
      d.in_sync ? null : badge("config r" + d.reported_revision + " → r" + d.desired_revision, "warn")),
    h("div", { class: "row small muted mt" },
      h("span", null, "seen " + ago(d.last_seen_at)),
      d.restarts ? h("span", null, "· " + d.restarts + " restart" + (d.restarts === 1 ? "" : "s")) : null),
    d.tags?.length ? h("div", { class: "row mt" }, d.tags.map((t) => h("span", { class: "tag" }, t))) : null));

  return h("div", null, summary,
    devices.length ? h("div", { class: "grid" }, cards)
      : h("div", { class: "card empty" }, can("admin")
        ? ["No devices yet. Use ", h("b", null, "Add device"), " to get an enrollment token."]
        : "No devices yet. A project admin can add one."));
}

function kv(rows) {
  return h("dl", { class: "kv" }, rows.filter(Boolean).flatMap(([k, v]) => [h("dt", null, k), h("dd", null, v ?? "—")]));
}

async function viewDevice() {
  const base = `/projects/${state.project}/devices/${state.deviceId}`;
  const [d, arts] = await Promise.all([api("GET", base + "/detail"), api("GET", base + "/artifacts?kind=screenshot&limit=60")]);
  const groups = groupShots(arts);
  const app = d.app || {};
  const sys = d.system || {};

  const command = async (type, label) => {
    try {
      await api("POST", base + "/commands", { type });
      setNotice("ok", `${label} queued. It reaches the device at its next check-in.`);
    } catch (e) { setNotice("bad", e.message); }
    render();
  };

  const rename = async () => {
    const name = prompt("Device name", d.name);
    if (name) { await api("PATCH", base, { name }); render(); }
  };
  const editTags = async () => {
    const v = prompt("Tags (comma separated). Tags select which config layers apply.", (d.tags || []).join(", "));
    if (v !== null) {
      await api("PATCH", base, { tags: v.split(",").map((t) => t.trim()).filter(Boolean) });
      render();
    }
  };
  const remove = async () => {
    if (!confirm(`Remove ${d.name}? Its history is deleted. The agent will need to re-enroll.`)) return;
    await api("DELETE", base);
    go("devices");
  };

  const metrics = { ...(app.metrics || {}), ...d.metrics };
  const eventItem = (e) => h("li", null,
    h("span", { class: "ts", title: e.ts }, ago(e.ts)),
    h("span", { class: e.level === "error" ? "lvl-error" : e.level === "warn" ? "lvl-warn" : "" },
      h("b", null, e.type), e.message ? " — " + e.message : ""));
  const cmdItem = (c) => h("li", null,
    h("span", { class: "ts" }, ago(c.expires_at && new Date(new Date(c.expires_at).getTime() - 3600e3))),
    h("span", null, h("b", null, c.type), " ", badge(c.status, c.status === "succeeded" ? "ok" : c.status === "failed" ? "bad" : c.status === "expired" ? "" : "warn"),
      c.params?.result ? h("span", { class: "muted small" }, " " + c.params.result) : null));

  return h("div", null,
    h("div", { class: "row between" },
      h("div", { class: "row" },
        h("button", { class: "btn small", onclick: () => go("devices") }, "← Devices"),
        h("h2", null, d.name), reachBadge(d), appBadge(d), budgetBadge(d), sigBadge(d)),
      h("div", { class: "row" },
        can("operator") ? [
          h("button", { class: "btn small", onclick: rename }, "Rename"),
          h("button", { class: "btn small", onclick: editTags }, "Tags"),
          h("button", { class: "btn small", onclick: () => command("checkin_now", "Check-in") }, "Check in now"),
          h("button", { class: "btn small primary", onclick: () => confirm(`Restart the app on ${d.name}?`) && command("restart_app", "Restart") }, "Restart app"),
        ] : h("span", { class: "muted small" }, "Read-only access"),
        can("admin") ? h("button", { class: "btn small danger", onclick: remove }, "Remove") : null)),
    noticeEl(),
    h("div", { class: "cols mt" },
      h("section", { class: "card" }, h("h3", null, "App"),
        kv([["State", app.state ? app.state + (app.message ? " — " + app.message : "") : "no data"],
          ["Build", app.build], ["Uptime", app.uptime_s != null ? dur(app.uptime_s) : null],
          ["FPS", app.fps || null], ["Restarts", String(d.restarts)],
          ["Config", `reported r${d.reported_revision}, desired r${d.desired_revision}` + (d.in_sync ? " ✓" : " (out of sync)")]])),
      h("section", { class: "card" }, h("h3", null, "Device"),
        kv([["Last seen", ago(d.last_seen_at)], ["Host", `${d.hostname} (${d.os}/${d.arch})`],
          ["Agent", d.agent_version], sigRow(d), ["Agent uptime", sys.uptime_s != null ? dur(sys.uptime_s) : null],
          budgetRow(d), ["Traffic", `${bytes(d.bytes_out)} up / ${bytes(d.bytes_in)} down`],
          ["Tags", d.tags?.length ? d.tags.join(", ") : "none"], ["Enrolled", ago(d.enrolled_at)], ["ID", h("code", null, d.id)]])),
      Object.keys(metrics).length ? h("section", { class: "card" }, h("h3", null, "Metrics"),
        kv(Object.entries(metrics).map(([k, v]) => [k, String(v)]))) : null),
    h("div", { class: "cols mt" },
      h("section", { class: "card" }, h("h3", null, `Recent events (${d.events.length})`),
        d.events.length ? h("ul", { class: "list" }, d.events.slice(0, 30).map(eventItem)) : h("span", { class: "muted" }, "None yet")),
      h("section", { class: "card" }, h("h3", null, "Commands"),
        d.commands.length ? h("ul", { class: "list" }, d.commands.slice(0, 15).map(cmdItem)) : h("span", { class: "muted" }, "None"))),
    h("section", { class: "card mt" },
      h("div", { class: "row between" },
        h("div", null, h("h3", null, `Screenshots (${arts.length})`), h("div", { class: "muted small" }, screenshotPolicyText(d.effective.screenshots))),
        can("operator") ? h("button", { class: "btn small", onclick: () => command("capture_screenshot", "Screenshot") }, "Capture now") : null),
      groups.length
        ? h("div", { class: "gallery mt" }, groups.map((g, i) => {
          const a = g[0];
          return h("button", { class: "tile", onclick: () => openLightbox(groups, i, render), "aria-label": `Screenshot from ${ago(a.captured_at)}` },
            shotImg(a.id, "shot", "Screenshot"),
            h("div", { class: "cap" }, h("b", null, ago(a.captured_at)),
              h("span", { class: "muted" }, " · " + reasonText(a.meta?.reason) + (g.length > 1 ? ` · ${g.length} displays` : "") + (a.meta?.black ? " · black" : ""))));
        }))
        : h("p", { class: "muted mt" }, "No screenshots yet.")),
    h("section", { class: "card mt" },
      h("div", { class: "row between" }, h("h3", null, `Effective config — revision ${d.effective.revision}, reload mode ${d.effective.reload_mode}`),
        h("button", { class: "btn small", onclick: () => go("config", { scope: "device:" + d.id }) }, can("operator") ? "Edit device override" : "View device override")),
      h("pre", null, JSON.stringify({ data: d.effective.data, supervisor: d.effective.supervisor }, null, 2))));
}

// ------------------------------------------------------------------ config

const SAMPLE = { data: {}, reload_mode: "watch" };

async function viewConfig() {
  const docs = await api("GET", `/projects/${state.project}/config`);
  const scopes = Object.keys(docs).sort((a, b) => (a === "global" ? -1 : b === "global" ? 1 : a.localeCompare(b)));
  if (!scopes.includes(state.scope)) scopes.push(state.scope);
  const doc = docs[state.scope] || SAMPLE;

  const editable = can("operator");
  const area = h("textarea", { class: "code", spellcheck: "false", "aria-label": "Config document JSON", readonly: !editable }, JSON.stringify(doc, null, 2));
  const status = h("div");
  const say = (kind, text) => status.replaceChildren(h("div", { class: "msg " + kind + " mt" }, text));

  const save = async () => {
    let parsed;
    try { parsed = JSON.parse(area.value); } catch (e) { return say("bad", "Not valid JSON: " + e.message); }
    if (!parsed || typeof parsed.data !== "object" || Array.isArray(parsed.data)) return say("bad", 'Top level must be an object with a "data" object.');
    try {
      await api("PUT", `/projects/${state.project}/config/${encodeURIComponent(state.scope)}`, parsed);
      say("ok", "Saved. Devices pick it up at their next check-in (or immediately if long-polling).");
    } catch (e) { say("bad", e.message); }
  };
  const del = async () => {
    if (!confirm(`Delete the ${state.scope} config layer?`)) return;
    try { await api("DELETE", `/projects/${state.project}/config/${encodeURIComponent(state.scope)}`); } catch (e) { return say("bad", e.message); }
    go("config", { scope: "global" });
  };
  const addScope = () => {
    const v = prompt('New layer: "tag:<name>" or "device:<id>"', "tag:");
    if (v && /^(tag|device):.+/.test(v.trim())) go("config", { scope: v.trim() });
  };

  const help = {
    global: "Applies to every device in the project.",
  }[state.scope] || (state.scope.startsWith("tag:") ? "Applies to devices carrying this tag, over global." : "Applies to this one device, over everything else.");

  return h("div", { class: "split" },
    h("aside", { class: "card" }, h("h3", null, "Layers"),
      h("div", { class: "scopes" }, scopes.map((s) => h("button", {
        class: "scope", "aria-current": String(s === state.scope), onclick: () => go("config", { scope: s }),
      }, s, docs[s] ? "" : " (new)"))),
      editable ? h("button", { class: "btn small mt", onclick: addScope }, "+ Add layer") : null),
    h("section", { class: "card" },
      h("h2", null, state.scope), h("p", { class: "muted small" }, help + " Layers merge in order: global → tag → device; objects merge deeply, other values replace."),
      !editable ? h("div", { class: "msg mt" }, "You have read-only access to this project. Secret values in the supervisor environment are hidden.") : null,
      !can("admin") && editable ? h("div", { class: "msg mt" }, "The supervisor section decides which program runs on the machines, so changing it needs the project admin role. Everything else you can edit.") : null,
      area,
      editable ? h("div", { class: "row mt" },
        h("button", { class: "btn primary", onclick: save }, "Save"),
        h("button", { class: "btn", onclick: () => { area.value = JSON.stringify(doc, null, 2); status.replaceChildren(); } }, "Revert"),
        docs[state.scope] ? h("button", { class: "btn danger", onclick: del }, "Delete layer") : null) : null,
      h("p", { class: "muted small mt" }, 'Keys: "data" (your app\'s settings), "reload_mode" (none | watch | trigger | restart), "supervisor" (exe, args, workdir, env, heartbeat_timeout_s, max_restarts, scheduled_restart "HH:MM", mode "monitor", quit_timeout_s, stop_app_on_agent_exit), '
        + '"screenshots" (enabled, interval_s ≥ 10, max_width, quality, on_event, upload_unchanged, unchanged_every_s), "budget" (monthly_mb, reset_day 1-28, soft_pct). '
        + 'Screenshots and budget merge field by field across layers.'),
      status));
}

// ------------------------------------------------------------------ enrollment

function enrollDialog() {
  const tags = h("input", { type: "text", placeholder: "e.g. lobby, ground-floor (optional)", "aria-label": "Tags" });
  const out = h("div");
  const dlg = h("dialog", null,
    h("h2", null, "Add a device"),
    h("p", { class: "muted small" }, "Creates a one-time token (valid 72 hours). Tags are applied to the device on enrollment."),
    tags, out,
    h("div", { class: "row mt" },
      h("button", { class: "btn primary", onclick: async (e) => {
        try {
          const r = await api("POST", `/projects/${state.project}/enrollment-tokens`,
            { tags: tags.value.split(",").map((t) => t.trim()).filter(Boolean) });
          // -server-key pins the server's signing key, so the agent only ever acts on config and
          // commands this server signed. Without it the agent has to take the key on trust.
          const cmd = `agent.exe install -server ${location.origin} -enroll-token ${r.token} -server-key ${r.server_key}`;
          out.replaceChildren(h("p", { class: "small mt" }, "Run on the new machine, as the account the app runs under:"),
            h("textarea", { class: "code copy", readonly: true, rows: 4, onfocus: (ev) => ev.target.select() }, cmd),
            h("p", { class: "muted small mt" }, `The server key (${r.key_id}) is pinned so the agent refuses anything this server did not sign.`
              + (location.protocol === "https:" ? "" : " This page is not served over HTTPS: copy the command from a trusted connection.")));
          e.target.disabled = true;
        } catch (err) { out.replaceChildren(h("div", { class: "msg bad mt" }, err.message)); }
      } }, "Create token"),
      h("button", { class: "btn", onclick: () => dlg.close() }, "Close")));
  dlg.addEventListener("close", () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
}

// ------------------------------------------------------------------ projects

function newProjectDialog() {
  const name = h("input", { type: "text", placeholder: "e.g. Lobby screens", "aria-label": "Project name", autocomplete: "off", maxlength: 80 });
  const out = h("div");
  const create = async () => {
    try {
      const p = await api("POST", "/projects", { name: name.value });
      state.project = p.id;
      store.set("rc.project", p.id);
      dlg.close();
      go("devices");
    } catch (e) { out.replaceChildren(h("div", { class: "msg bad mt" }, e.message)); }
  };
  name.addEventListener("keydown", (e) => { if (e.key === "Enter") create(); });
  const dlg = h("dialog", null, h("h2", null, "New project"),
    h("p", { class: "muted small" }, "A project is a group of devices that share config. Server administrators can see and manage every project; add other people from the project's Members tab."),
    name, out,
    h("div", { class: "row mt" }, h("button", { class: "btn primary", onclick: create }, "Create"), h("button", { class: "btn", onclick: () => dlg.close() }, "Cancel")));
  dlg.addEventListener("close", () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  name.focus();
}

// ------------------------------------------------------------------ members (project admins)

const ROLE_HELP = {
  viewer: "sees everything, changes nothing",
  operator: "restarts apps, takes screenshots, renames and tags devices, edits config (but not the supervisor section)",
  admin: "everything in the project, including members, enrolment and the supervisor section",
};

async function viewMembers() {
  const base = `/projects/${state.project}/members`;
  const members = await api("GET", base);
  const act = async (fn) => { try { await fn(); setNotice(null); } catch (e) { setNotice("bad", e.message); } render(); };

  const roleSelect = (m) => h("select", { "aria-label": `Role of ${m.username}`, onchange: (e) => act(() => api("PUT", `${base}/${encodeURIComponent(m.username)}`, { role: e.target.value })) },
    Object.keys(RANK).map((r) => h("option", { value: r, selected: r === m.role }, r)));

  const username = h("input", { type: "text", placeholder: "username", "aria-label": "Username to add", autocomplete: "off", spellcheck: "false" });
  const newRole = h("select", { "aria-label": "Role for the new member" }, Object.keys(RANK).map((r) => h("option", { value: r, selected: r === "operator" }, r)));

  const proj = state.projects.find((p) => p.id === state.project);
  const rename = h("input", { type: "text", value: proj?.name || "", "aria-label": "Project name", maxlength: 80, autocomplete: "off" });
  const doRename = () => rename.value.trim() && rename.value.trim() !== proj?.name && act(() => api("PATCH", `/projects/${encodeURIComponent(state.project)}`, { name: rename.value }));
  rename.addEventListener("keydown", (e) => { if (e.key === "Enter") doRename(); });

  return h("div", null,
    noticeEl(),
    h("section", { class: "card mt" },
      h("h3", null, "Project"),
      h("div", { class: "row" }, rename, h("button", { class: "btn primary", onclick: doRename }, "Rename")),
      h("p", { class: "muted small mt" }, `The id "${state.project}" stays the same, so enrolled devices and links keep working.`)),
    h("section", { class: "card mt" },
      h("h3", null, `Members of ${state.projects.find((p) => p.id === state.project)?.name || state.project}`),
      members.length ? h("table", { class: "table" },
        h("thead", null, h("tr", null, ["User", "Role", ""].map((c) => h("th", null, c)))),
        h("tbody", null, members.map((m) => h("tr", null,
          h("td", null, h("b", null, m.display_name || m.username), m.display_name && m.display_name !== m.username ? h("span", { class: "muted" }, "  " + m.username) : null,
            m.disabled ? h("span", { class: "muted" }, "  (disabled)") : null),
          h("td", null, roleSelect(m)),
          h("td", { class: "right" }, h("button", { class: "btn small danger", onclick: () => confirm(`Remove ${m.username} from this project?`) && act(() => api("DELETE", `${base}/${encodeURIComponent(m.username)}`)) }, "Remove")))))) :
        h("p", { class: "muted" }, "No one has been added yet. Server administrators can always see every project."),
      h("div", { class: "row mt2" }, username, newRole,
        h("button", { class: "btn primary", onclick: () => username.value.trim() && act(() => api("PUT", `${base}/${encodeURIComponent(username.value.trim().toLowerCase())}`, { role: newRole.value })) }, "Add member")),
      h("p", { class: "muted small mt" }, "Add someone who already has an account; a server administrator creates accounts (Users tab)."),
      h("dl", { class: "kv mt" }, Object.entries(ROLE_HELP).flatMap(([r, t]) => [h("dt", null, r), h("dd", null, t)]))));
}

// ------------------------------------------------------------------ users (server admins)

async function viewUsers() {
  const users = await api("GET", "/users");
  const act = async (fn) => { try { await fn(); setNotice(null); } catch (e) { setNotice("bad", e.message); } render(); };
  const patch = (u, body) => act(() => api("PATCH", `/users/${encodeURIComponent(u.username)}`, body));

  const resetPassword = (u) => {
    const pw = prompt(`New password for ${u.username} (at least 10 characters). They are signed out everywhere.`);
    if (pw) patch(u, { password: pw });
  };

  const keys = await api("GET", "/signing");
  const rotate = () => confirm("Rotate the signing key?\n\nAgents that trust the current key follow the new one automatically, and the old private key is erased.") && act(() => api("POST", "/signing/rotate"));
  const cur = keys.keys.find((k) => k.kid === keys.current);

  return h("div", null, noticeEl(),
    h("section", { class: "card mt" }, h("h3", null, "Signing key"),
      h("p", { class: "muted small" }, "Config and commands are signed with this key, and agents refuse anything else. Pin the public key on agents with -server-key (the Add device dialog does it for you)."),
      kv([["Key id", h("code", null, keys.current)], ["Public key", h("code", { class: "small" }, cur?.public || "")],
        ["Keys in chain", String(keys.keys.length)]]),
      h("div", { class: "row mt" }, h("button", { class: "btn small", onclick: rotate }, "Rotate key"))),
    h("section", { class: "card mt" },
      h("div", { class: "row between" }, h("h3", null, `Accounts (${users.length})`),
        h("button", { class: "btn small primary", onclick: newUserDialog }, "New user")),
      h("table", { class: "table" },
        h("thead", null, h("tr", null, ["User", "Projects", "Last sign-in", ""].map((c) => h("th", null, c)))),
        h("tbody", null, users.map((u) => h("tr", null,
          h("td", null, h("b", null, u.display_name || u.username), u.display_name && u.display_name !== u.username ? h("span", { class: "muted" }, "  " + u.username) : null,
            h("div", { class: "row small mt" },
              u.is_admin ? badge("server admin", "ok") : null, u.disabled ? badge("disabled", "bad") : null, !u.has_password ? badge("token only", "") : null,
              u.id === state.me?.id ? badge("you", "") : null)),
          h("td", { class: "small" }, Object.entries(u.projects || {}).map(([p, r]) => h("div", null, `${p}: ${r}`)).concat(u.is_admin ? [h("div", { class: "muted" }, "all projects")] : [])),
          h("td", { class: "small muted" }, u.last_login && new Date(u.last_login).getFullYear() > 2000 ? ago(u.last_login) : "never"),
          h("td", { class: "right" }, h("div", { class: "row" },
            h("button", { class: "btn small", onclick: () => resetPassword(u) }, "Reset password"),
            h("button", { class: "btn small", onclick: () => patch(u, { is_admin: !u.is_admin }) }, u.is_admin ? "Remove admin" : "Make admin"),
            h("button", { class: "btn small", onclick: () => patch(u, { disabled: !u.disabled }) }, u.disabled ? "Enable" : "Disable"),
            u.id === state.me?.id ? null : h("button", { class: "btn small danger", onclick: () => confirm(`Delete ${u.username}? Their tokens stop working.`) && act(() => api("DELETE", `/users/${encodeURIComponent(u.username)}`)) }, "Delete")))))))));
}

function newUserDialog() {
  const f = (label, attrs) => h("label", { class: "field" }, h("span", null, label), h("input", { type: "text", ...attrs }));
  const username = f("Username", { autocomplete: "off", spellcheck: "false" });
  const display = f("Name (optional)", { autocomplete: "off" });
  const password = f("Initial password (at least 10 characters)", { type: "password", autocomplete: "new-password" });
  const isAdmin = h("input", { type: "checkbox" });
  const out = h("div");
  const dlg = h("dialog", null, h("h2", null, "New user"),
    username, display, password,
    h("label", { class: "row mt" }, isAdmin, h("span", null, "Server administrator (manages accounts and sees every project)")),
    out,
    h("div", { class: "row mt" },
      h("button", { class: "btn primary", onclick: async () => {
        try {
          await api("POST", "/users", { username: username.querySelector("input").value, display_name: display.querySelector("input").value, password: password.querySelector("input").value, is_admin: isAdmin.checked });
          dlg.close(); render();
        } catch (e) { out.replaceChildren(h("div", { class: "msg bad mt" }, e.message)); }
      } }, "Create"),
      h("button", { class: "btn", onclick: () => dlg.close() }, "Cancel")),
    h("p", { class: "muted small mt" }, "Add them to projects from each project's Members tab."));
  dlg.addEventListener("close", () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
}

// ------------------------------------------------------------------ audit (project admins)

async function viewAudit() {
  const entries = await api("GET", `/audit?project=${encodeURIComponent(state.project)}&limit=300`);
  return h("section", { class: "card mt" }, h("h3", null, `Audit log: ${state.project}`),
    entries.length ? h("table", { class: "table" },
      h("thead", null, h("tr", null, ["When", "Who", "What", "Target", "Detail"].map((c) => h("th", null, c)))),
      h("tbody", null, entries.map((e) => h("tr", null,
        h("td", { class: "small muted", title: e.time }, ago(e.time)), h("td", null, e.username || "—"), h("td", null, h("code", null, e.action)),
        h("td", { class: "small" }, e.target || ""), h("td", { class: "small muted" }, e.detail || ""))))) : h("p", { class: "muted" }, "Nothing recorded yet."),
    h("p", { class: "muted small mt" }, "Config values are never written to the log, only which parts changed."));
}

// ------------------------------------------------------------------ library: scripts and releases

const INTERPRETERS = ["powershell", "cmd", "bash", "sh", "python"];

// Sending a script or a build runs code on the devices, so every send goes through here: pick
// the devices, see the consequence, and get a per-device answer.
async function deployDialog(title, blurb, type, params, osHint) {
  const devices = await api("GET", `/projects/${state.project}/devices`);
  const picks = devices.map((d) => ({
    d,
    box: h("input", { type: "checkbox", checked: !osHint || d.os === osHint, "aria-label": `Send to ${d.name}` }),
    canary: h("input", { type: "checkbox", "aria-label": `${d.name} goes first (canary)` }),
  }));
  const staged = h("input", { type: "checkbox", checked: true, "aria-label": "Send in stages" });
  const soakS = h("input", { type: "number", value: type === "apply_release" ? 120 : 30, min: 0, max: 86400, "aria-label": "Seconds to wait" });
  const batch = h("input", { type: "number", value: 0, min: 0, "aria-label": "Devices per wave" });
  const out = h("div");
  const dlg = h("dialog", null,
    h("h2", null, title), h("p", { class: "muted small" }, blurb),
    devices.length ? h("table", { class: "table" },
      h("thead", null, h("tr", null, ["Send", "Canary", "Device"].map((c) => h("th", null, c)))),
      h("tbody", null, picks.map(({ d, box, canary }) => h("tr", null, h("td", null, box), h("td", null, canary),
        h("td", null, `${d.name} `, h("span", { class: "muted small" }, `${d.os} · ${d.reachability}`)))))) : h("p", { class: "muted" }, "No devices yet."),
    h("label", { class: "row mt" }, staged, h("span", null, "Send in stages: canary devices first, the rest only if they succeed and stay healthy")),
    h("div", { class: "row mt" },
      h("label", { class: "field" }, h("span", null, "Wait after the canary succeeds (seconds)"), soakS),
      h("label", { class: "field" }, h("span", null, "Devices per wave afterwards (0 = all)"), batch)),
    h("p", { class: "muted small" }, "With no canary ticked, the first ticked device is the canary. If a canary fails or reports an error, nothing more is sent."),
    out,
    h("div", { class: "row mt" },
      h("button", { class: "btn primary", onclick: async (ev) => {
        const chosen = picks.filter((p) => p.box.checked);
        if (!chosen.length) { out.replaceChildren(h("div", { class: "msg bad mt" }, "Tick at least one device.")); return; }
        ev.target.disabled = true;
        if (staged.checked) {
          const first = chosen.filter((p) => p.canary.checked);
          const ordered = [...first, ...chosen.filter((p) => !p.canary.checked)];
          try {
            await api("POST", `/projects/${state.project}/rollouts`, {
              type, params, devices: ordered.map((p) => p.d.id), canary: Math.max(1, first.length),
              soak_s: Number(soakS.value), batch: Number(batch.value),
            });
            out.replaceChildren(h("div", { class: "msg ok mt" }, `Rollout started: ${ordered[0].d.name} first. Follow it on the Library page.`));
          } catch (e) { out.replaceChildren(h("div", { class: "msg bad mt" }, e.message)); ev.target.disabled = false; }
          return;
        }
        const lines = [];
        for (const { d } of chosen) {
          try {
            await api("POST", `/projects/${state.project}/devices/${d.id}/commands`, { type, params });
            lines.push(h("li", null, "✓ ", d.name, " queued"));
          } catch (e) { lines.push(h("li", { class: "lvl-error" }, "✗ ", d.name, ": ", e.message)); }
        }
        out.replaceChildren(h("ul", { class: "list mt" }, lines), h("p", { class: "muted small" }, "Each device picks it up at its next check-in and reports the outcome under Commands."));
      } }, "Send"),
      h("button", { class: "btn", onclick: () => dlg.close() }, "Close")));
  dlg.addEventListener("close", () => { dlg.remove(); render(); });
  document.body.append(dlg);
  dlg.showModal();
}
function scriptDialog() {
  const name = h("input", { type: "text", placeholder: "e.g. clear-cache", "aria-label": "Script name", spellcheck: "false" });
  const interp = h("select", { "aria-label": "Interpreter" }, INTERPRETERS.map((i) => h("option", { value: i }, i)));
  const timeout = h("input", { type: "number", value: 120, min: 1, max: 3600, "aria-label": "Time limit in seconds" });
  const desc = h("input", { type: "text", placeholder: "what it does (optional)", "aria-label": "Description" });
  const body = h("textarea", { class: "code", rows: 12, spellcheck: "false", "aria-label": "Script", placeholder: "Script text" });
  const out = h("div");
  const dlg = h("dialog", null,
    h("h2", null, "Add a script"),
    h("p", { class: "muted small" }, "Scripts are versioned and never edited: saving the same name again makes the next version. A device runs exactly the version you send, checked by its hash."),
    h("label", { class: "field" }, h("span", null, "Name"), name),
    h("label", { class: "field" }, h("span", null, "Interpreter"), interp),
    h("label", { class: "field" }, h("span", null, "Time limit (seconds)"), timeout),
    h("label", { class: "field" }, h("span", null, "Description"), desc),
    h("label", { class: "field" }, h("span", null, "Script"), body), out,
    h("div", { class: "row mt" },
      h("button", { class: "btn primary", onclick: async () => {
        try {
          await api("POST", `/projects/${state.project}/scripts`, { name: name.value.trim(), interpreter: interp.value, content: body.value, description: desc.value.trim(), timeout_s: Number(timeout.value) });
          dlg.close();
        } catch (e) { out.replaceChildren(h("div", { class: "msg bad mt" }, e.message)); }
      } }, "Save"),
      h("button", { class: "btn", onclick: () => dlg.close() }, "Cancel")));
  dlg.addEventListener("close", () => { dlg.remove(); render(); });
  document.body.append(dlg);
  dlg.showModal();
}

function releaseDialog() {
  const kind = h("select", { "aria-label": "Kind" }, [h("option", { value: "app" }, "app (a .zip of the build folder)"), h("option", { value: "agent" }, "agent (the agent executable)")]);
  const name = h("input", { type: "text", placeholder: "e.g. kiosk", "aria-label": "Release name", spellcheck: "false" });
  const version = h("input", { type: "text", placeholder: "e.g. 1.4.2", "aria-label": "Version", spellcheck: "false" });
  const os = h("select", { "aria-label": "Operating system" }, ["windows", "linux", "darwin"].map((o) => h("option", { value: o }, o)));
  const arch = h("select", { "aria-label": "Architecture" }, ["any", "amd64", "arm64"].map((o) => h("option", { value: o }, o)));
  const notes = h("input", { type: "text", placeholder: "release notes (optional)", "aria-label": "Notes" });
  const file = h("input", { type: "file", "aria-label": "Build file" });
  const out = h("div");
  const dlg = h("dialog", null,
    h("h2", null, "Upload a release"),
    h("p", { class: "muted small" }, "Releases never change once uploaded. An agent release must use the version the agent prints for `agent version`, and a specific architecture. App builds are unpacked beside each other and the supervisor's ${release} placeholder points at the one in use."),
    h("label", { class: "field" }, h("span", null, "Kind"), kind),
    h("label", { class: "field" }, h("span", null, "Name"), name),
    h("label", { class: "field" }, h("span", null, "Version"), version),
    h("label", { class: "field" }, h("span", null, "Operating system"), os),
    h("label", { class: "field" }, h("span", null, "Architecture"), arch),
    h("label", { class: "field" }, h("span", null, "Notes"), notes),
    h("label", { class: "field" }, h("span", null, "File"), file), out,
    h("div", { class: "row mt" },
      h("button", { class: "btn primary", onclick: async (ev) => {
        if (!file.files[0]) { out.replaceChildren(h("div", { class: "msg bad mt" }, "Choose the build file first.")); return; }
        ev.target.disabled = true;
        out.replaceChildren(h("div", { class: "msg mt" }, `Uploading ${bytes(file.files[0].size)}…`));
        const q = new URLSearchParams({ kind: kind.value, name: name.value.trim(), version: version.value.trim(), os: os.value, arch: arch.value, notes: notes.value.trim() });
        try {
          const res = await fetch(`/v1/admin/projects/${encodeURIComponent(state.project)}/releases?` + q, { method: "POST", headers: { Authorization: "Bearer " + state.token }, body: file.files[0] });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data.error || res.statusText);
          dlg.close();
        } catch (e) { out.replaceChildren(h("div", { class: "msg bad mt" }, e.message)); ev.target.disabled = false; }
      } }, "Upload"),
      h("button", { class: "btn", onclick: () => dlg.close() }, "Cancel")));
  dlg.addEventListener("close", () => { dlg.remove(); render(); });
  document.body.append(dlg);
  dlg.showModal();
}

async function viewLibrary() {
  const base = `/projects/${state.project}`;
  const [scripts, releases, rollouts] = await Promise.all([api("GET", base + "/scripts"), api("GET", base + "/releases"), api("GET", base + "/rollouts")]);
  const admin = can("admin");
  const act = async (fn) => { try { await fn(); setNotice(null); } catch (e) { setNotice("bad", e.message); } render(); };
  const runDialog = (s) => {
    const args = prompt(`Arguments for ${s.name} v${s.version} (optional, one per line)`, "");
    if (args === null) return;
    deployDialog(`Run ${s.name} v${s.version}`, `Runs on the devices you tick, with the ${s.interpreter} interpreter and a ${s.timeout_s}s limit. Output comes back under Commands.`,
      "run_script", { script: s.id, args: args.split("\n").filter(Boolean) });
  };
  const sendRelease = (r) => deployDialog(`Install ${r.name} ${r.version}`,
    r.kind === "agent"
      ? "Replaces the agent program after a test run of the new one, then restarts the agent. The app keeps running. Try one device first."
      : "Downloads the build (counts against the device's data budget), unpacks it, restarts the app on it, and goes back to the previous build if the app does not stay up. Try one device first.",
    "apply_release", { release_id: r.id }, r.os);

  const active = rollouts.filter((r) => ["canary", "soaking", "rolling"].includes(r.state));
  const stateText = { canary: "canary running", soaking: "canary succeeded, waiting", rolling: "rolling out", done: "done", halted: "halted" };
  const rolloutCard = (r) => h("div", { class: "card mt" },
    h("div", { class: "row between" },
      h("div", null, h("b", null, r.type === "apply_release" ? "Release" : "Script"), " ", badge(stateText[r.state] || r.state, r.state === "done" ? "ok" : r.state === "halted" ? "bad" : "warn"),
        h("span", { class: "muted small" }, ` ${ago(r.created_at)}${r.created_by ? " by " + r.created_by : ""}`)),
      admin && active.includes(r) ? h("button", { class: "btn small danger", onclick: () => confirm("Stop sending to the remaining devices?") && act(() => api("POST", `${base}/rollouts/${r.id}/halt`)) }, "Halt") : null),
    r.reason ? h("div", { class: "msg bad mt" }, r.reason) : null,
    h("ul", { class: "list mt" }, (r.devices || []).map((d) => h("li", null,
      h("span", { class: "ts" }, d.stage),
      h("span", null, h("b", null, d.name), " ", badge(d.status, d.status === "succeeded" ? "ok" : d.status === "failed" || d.status === "expired" ? "bad" : d.status === "waiting" ? "" : "warn"),
        d.result ? h("span", { class: "muted small" }, " " + d.result) : null)))));

  return h("div", null,
    noticeEl(),
    rollouts.length ? h("section", { class: "mt" }, h("h3", null, `Rollouts (${rollouts.length})`), rollouts.slice(0, 5).map(rolloutCard)) : null,
    h("section", { class: "card mt" },
      h("div", { class: "row between" }, h("h3", null, `Scripts (${scripts.length})`),
        admin ? h("button", { class: "btn small primary", onclick: scriptDialog }, "Add script") : null),
      scripts.length ? h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Name", "Version", "Runs with", "Hash", "Added", ""].map((c) => h("th", null, c)))),
        h("tbody", null, scripts.map((s) => h("tr", null,
          h("td", null, h("b", null, s.name), s.description ? h("div", { class: "muted small" }, s.description) : null),
          h("td", null, "v" + s.version), h("td", null, `${s.interpreter}, ${s.timeout_s}s`),
          h("td", null, h("code", { title: s.sha256 }, s.sha256.slice(0, 12))),
          h("td", { class: "small muted" }, `${s.created_by || "—"} · ${ago(s.created_at)}`),
          h("td", { class: "row" }, admin ? [
            h("button", { class: "btn small", onclick: () => runDialog(s) }, "Run…"),
            h("button", { class: "btn small danger", onclick: () => confirm(`Delete ${s.name} v${s.version}?`) && act(() => api("DELETE", `${base}/scripts/${s.id}`)) }, "Delete"),
          ] : null))))) : h("p", { class: "muted" }, "No scripts yet."),
      h("p", { class: "muted small mt" }, "Only project admins can add or run scripts. Devices that do not verify signatures refuse to run them.")),
    h("section", { class: "card mt" },
      h("div", { class: "row between" }, h("h3", null, `Releases (${releases.length})`),
        admin ? h("button", { class: "btn small primary", onclick: releaseDialog }, "Upload release") : null),
      releases.length ? h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Kind", "Name", "Version", "Platform", "Size", "Hash", "Added", ""].map((c) => h("th", null, c)))),
        h("tbody", null, releases.map((r) => h("tr", null,
          h("td", null, r.kind), h("td", null, h("b", null, r.name), r.notes ? h("div", { class: "muted small" }, r.notes) : null),
          h("td", null, r.version), h("td", null, `${r.os}/${r.arch}`), h("td", null, bytes(r.size)),
          h("td", null, h("code", { title: r.sha256 }, r.sha256.slice(0, 12))),
          h("td", { class: "small muted" }, `${r.created_by || "—"} · ${ago(r.created_at)}`),
          h("td", { class: "row" }, admin ? [
            h("button", { class: "btn small", onclick: () => sendRelease(r) }, "Install…"),
            h("button", { class: "btn small danger", onclick: () => confirm(`Delete ${r.name} ${r.version}?`) && act(() => api("DELETE", `${base}/releases/${r.id}`)) }, "Delete"),
          ] : null))))) : h("p", { class: "muted" }, "No releases yet."),
      h("p", { class: "muted small mt" }, "Downloads resume if the link drops and stop when a device's data budget is used up. Each device checks the file against the hash the server signed before it unpacks or runs anything.")));
}

// ------------------------------------------------------------------ account menu

function accountDialog() {
  const out = h("div");
  const say = (kind, text) => out.replaceChildren(h("div", { class: "msg " + kind + " mt" }, text));
  const field = (label, type, ac) => h("label", { class: "field" }, h("span", null, label), h("input", { type, autocomplete: ac }));
  const cur = field("Current password", "password", "current-password");
  const next = field("New password (at least 10 characters)", "password", "new-password");
  const tokens = h("div");
  const newTokenName = h("input", { type: "text", placeholder: "what it is for, e.g. build script", "aria-label": "Token name" });

  const loadTokens = async () => {
    try {
      const list = await api("GET", "/me/tokens");
      tokens.replaceChildren(list.length ? h("ul", { class: "list" }, list.map((t) => h("li", null,
        h("span", null, h("b", null, t.name), h("span", { class: "muted small" }, `  created ${ago(t.created_at)}, last used ${ago(t.last_used)}` + (t.expires_at ? `, expires ${new Date(t.expires_at).toLocaleDateString()}` : ", never expires"))),
        h("button", { class: "btn small danger", onclick: async () => { await api("DELETE", `/me/tokens/${t.id}`); loadTokens(); } }, "Revoke"))))
        : h("p", { class: "muted small" }, "None."));
    } catch (e) { tokens.replaceChildren(h("span", { class: "muted" }, e.message)); }
  };

  const dlg = h("dialog", null,
    h("h2", null, state.me?.display_name || state.me?.username),
    h("p", { class: "muted small" }, `Signed in as ${state.me?.username}` + (isServerAdmin() ? " (server administrator)" : "")),
    h("h3", { class: "mt2" }, "Change password"), cur, next,
    h("div", { class: "row mt" }, h("button", { class: "btn", onclick: async () => {
      try {
        await api("POST", "/me/password", { current: cur.querySelector("input").value, new: next.querySelector("input").value });
        cur.querySelector("input").value = next.querySelector("input").value = "";
        say("ok", "Password changed. Your other sessions were signed out.");
      } catch (e) { say("bad", e.message); }
    } }, "Change password")),
    h("h3", { class: "mt2" }, "Personal access tokens"),
    h("p", { class: "muted small" }, "For scripts and automation. A token can do what you can do. It is shown once and can be revoked here."),
    tokens,
    h("div", { class: "row mt" }, newTokenName, h("button", { class: "btn", onclick: async () => {
      try {
        const t = await api("POST", "/me/tokens", { name: newTokenName.value || "token", ttl_days: 90 });
        newTokenName.value = "";
        out.replaceChildren(h("div", { class: "msg ok mt" }, "Copy this token now; it will not be shown again (valid for 90 days):"),
          h("textarea", { class: "code copy", readonly: true, rows: 2, onfocus: (e) => e.target.select() }, t.token));
        loadTokens();
      } catch (e) { say("bad", e.message); }
    } }, "Create token")),
    out,
    h("div", { class: "row between mt2" },
      h("button", { class: "btn danger", onclick: () => { dlg.close(); signOut(true); } }, "Sign out"),
      h("button", { class: "btn", onclick: () => dlg.close() }, "Close")));
  dlg.addEventListener("close", () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  loadTokens();
}

// ------------------------------------------------------------------ login + render

function viewLogin() {
  const user = h("input", { type: "text", autocomplete: "username", "aria-label": "Username", placeholder: "Username", autocapitalize: "none", spellcheck: "false" });
  const pass = h("input", { type: "password", autocomplete: "current-password", "aria-label": "Password", placeholder: "Password" });
  const msg = h("div");
  const button = h("button", { class: "btn primary" }, "Sign in");
  const submit = async () => {
    if (!user.value || !pass.value) return;
    button.disabled = true;
    try {
      const res = await fetch("/v1/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: user.value, password: pass.value }) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const wait = res.status === 429 ? ` Try again in ${Math.ceil((Number(res.headers.get("Retry-After")) || 900) / 60)} min.` : "";
        throw new Error((data.error || "Sign-in failed") + wait);
      }
      store.set("rc.session", data.token);
      state.token = data.token;
      render();
    } catch (e) {
      msg.replaceChildren(h("div", { class: "msg bad" }, e.message));
      pass.value = "";
      button.disabled = false;
      pass.focus();
    }
  };
  for (const input of [user, pass]) input.addEventListener("keydown", (e) => e.key === "Enter" && submit());
  button.addEventListener("click", submit);
  return h("div", { class: "card login" },
    h("div", { class: "brand" }, h("i"), "RemoteConfig"),
    h("p", { class: "muted" }, "Sign in with your account."), user, pass, button, msg);
}

let rendering = false;
async function render() {
  const root = document.getElementById("app");
  if (!state.token) { root.replaceChildren(viewLogin()); return; }
  if (rendering) return;
  rendering = true;
  try {
    const me = await api("GET", "/me");
    state.me = me.user;
    state.projects = me.projects;
    if (!state.projects.some((p) => p.id === state.project)) state.project = state.projects[0]?.id || "";
    // a page this account may no longer (or never) use falls back to the devices list
    const allowed = { devices: true, device: true, config: true, library: true, members: can("admin"), audit: can("admin"), users: isServerAdmin() };
    if (!allowed[state.view] || (!state.project && state.view !== "users")) state.view = state.project ? "devices" : (isServerAdmin() ? "users" : "devices");
    if (!state.project && state.view !== "users") {
      root.replaceChildren(chrome(h("div", { class: "card empty" }, isServerAdmin()
        ? [h("p", null, "No projects yet. A project holds a group of devices and their config."),
          h("button", { class: "btn primary", onclick: newProjectDialog }, "Create the first project")]
        : "You are not a member of any project yet. Ask an administrator to add you.")));
      return;
    }
    const view = { devices: viewDevices, device: viewDevice, config: viewConfig, library: viewLibrary, members: viewMembers, users: viewUsers, audit: viewAudit }[state.view];
    const content = await view();
    const next = chrome(content);
    // Background refreshes that change nothing must not touch the DOM: swapping nodes
    // under the pointer can swallow a click, and resets focus/hover.
    if (!(root.firstElementChild && root.firstElementChild.outerHTML === next.outerHTML)) {
      const keepScroll = window.scrollY;
      root.replaceChildren(next);
      window.scrollTo(0, keepScroll);
    }
    if (state.view === "devices" || state.view === "device" || state.view === "library") startTimer(() => { if (!document.hidden && !document.querySelector("dialog[open]")) render(); }, 5000);
    else stopTimer();
  } catch (e) {
    if (e.status !== 401) root.replaceChildren(chrome(h("div", { class: "msg bad" }, "Error: " + e.message)));
  } finally { rendering = false; }
}

render();
