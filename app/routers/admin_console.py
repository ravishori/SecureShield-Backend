"""A small operator console served by the API itself (no build step, no third-party scripts).

The page contains no secret. The operator types the admin token into the page; it is kept only in JS memory
(never in storage or the URL) and sent as ``X-Admin-Token`` to the same-origin admin API. All server data is
inserted with ``textContent`` (never as HTML), and a strict CSP forbids everything except this page's own
inline script/style.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/admin", tags=["admin"])

CSP = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>SecureShield admin</title>
<style>
body{font:14px system-ui,sans-serif;margin:0;background:#0b1020;color:#e6ecff}
header{padding:12px 16px;background:#121a33;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
main{padding:16px;max-width:1100px;margin:auto}
input,button{font:inherit;padding:6px 10px;border-radius:6px;border:1px solid #33406b;background:#0f1630;color:inherit}
button{cursor:pointer;background:#1b6cff;border-color:#1b6cff}button.warn{background:#c0392b;border-color:#c0392b}
table{border-collapse:collapse;width:100%;margin:8px 0 24px}th,td{border-bottom:1px solid #223055;padding:6px 8px;text-align:left}
.cards{display:flex;gap:12px;flex-wrap:wrap}.card{background:#121a33;border-radius:10px;padding:10px 16px;min-width:130px}
.card b{display:block;font-size:22px}#msg{color:#ffb4a8;margin-left:8px}
</style></head><body>
<header><strong>SecureShield admin</strong>
<input id="tok" type="password" placeholder="Admin token" autocomplete="off">
<button id="go">Load</button><span id="msg"></span></header>
<main>
<div class="cards" id="stats"></div>
<h3>Users</h3>
<div><input id="q" placeholder="Search e-mail / phone / name"> <button id="search">Search</button></div>
<table id="users"><thead><tr><th>E-mail</th><th>Phone</th><th>Name</th><th>Active</th><th></th></tr></thead><tbody></tbody></table>
<h3>Audit log</h3>
<table id="audit"><thead><tr><th>When (UTC)</th><th>Action</th><th>User</th><th>From</th></tr></thead><tbody></tbody></table>
</main>
<script>
"use strict";
let token = "";
const $ = (id) => document.getElementById(id);
function cell(tr, text) { const td = document.createElement("td"); td.textContent = text == null ? "" : String(text); tr.appendChild(td); return td; }
async function api(path, opts) {
  const r = await fetch("/api/v1/admin" + path, Object.assign({headers: {"X-Admin-Token": token, "Content-Type": "application/json"}}, opts || {}));
  if (!r.ok) throw new Error(r.status === 401 ? "Invalid admin token" : "Request failed (" + r.status + ")");
  return r.json();
}
async function loadAll() {
  $("msg").textContent = "";
  try {
    const s = await api("/stats"); const box = $("stats"); box.replaceChildren();
    for (const [k, v] of Object.entries(s)) { const d = document.createElement("div"); d.className = "card"; const b = document.createElement("b"); b.textContent = v; d.append(b, k.replaceAll("_", " ")); box.appendChild(d); }
    await loadUsers(); await loadAudit();
  } catch (e) { $("msg").textContent = e.message; }
}
async function loadUsers() {
  const u = await api("/users?limit=50&q=" + encodeURIComponent($("q").value.trim()));
  const body = $("users").tBodies[0]; body.replaceChildren();
  for (const x of u.items) {
    const tr = document.createElement("tr"); cell(tr, x.email); cell(tr, x.phone); cell(tr, x.full_name); cell(tr, x.is_active ? "yes" : "no");
    const td = document.createElement("td"); const b = document.createElement("button");
    b.textContent = x.is_active ? "Disable" : "Enable"; if (x.is_active) b.className = "warn";
    b.onclick = async () => { if (!confirm((x.is_active ? "Disable " : "Enable ") + (x.email || x.phone || "this user") + "?")) return;
      try { await api("/users/" + x.id + "/status", {method: "PATCH", body: JSON.stringify({is_active: !x.is_active})}); await loadAll(); } catch (e) { $("msg").textContent = e.message; } };
    td.appendChild(b); tr.appendChild(td); body.appendChild(tr);
  }
}
async function loadAudit() {
  const a = await api("/audit?limit=50"); const body = $("audit").tBodies[0]; body.replaceChildren();
  for (const x of a.items) { const tr = document.createElement("tr"); cell(tr, x.created_at); cell(tr, x.action); cell(tr, x.target_user_id); cell(tr, x.client_ip); body.appendChild(tr); }
}
$("go").onclick = () => { token = $("tok").value; $("tok").value = ""; loadAll(); };
$("search").onclick = () => loadUsers().catch((e) => { $("msg").textContent = e.message; });
</script></body></html>
"""


@router.get("/console", response_class=HTMLResponse, include_in_schema=False)
async def console() -> HTMLResponse:
    return HTMLResponse(
        PAGE,
        headers={
            "Content-Security-Policy": CSP,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )
