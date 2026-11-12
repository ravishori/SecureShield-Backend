"""A small operator console served by the API itself (no build step, no third-party scripts).

The page contains no secret. The operator signs in with e-mail, password and a TOTP (or one-time recovery) code; first
sign-in walks through the password change and MFA enrolment. The short-lived access token is kept only in JS memory
(never in storage or the URL) and sent as ``Authorization: Bearer`` to the same-origin admin API. A "legacy token"
field remains while ``ADMIN_LEGACY_TOKEN_ENABLED`` is true. All server data is inserted with ``textContent`` (never as
HTML), and a strict CSP forbids everything except this page's own inline script/style.
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
.card b{display:block;font-size:22px}#msg{color:#ffb4a8;margin-left:8px}.panel{background:#121a33;border-radius:10px;padding:12px 16px;margin:12px 0}
.panel input{display:block;margin:6px 0;min-width:280px}code{word-break:break-all}.hidden{display:none}
</style></head><body>
<header><strong>SecureShield admin</strong>
<span id="who"></span>
<span id="loginbar">
<input id="em" type="email" placeholder="E-mail" autocomplete="username">
<input id="pw" type="password" placeholder="Password" autocomplete="current-password">
<input id="code" placeholder="6-digit code or recovery code" autocomplete="one-time-code" inputmode="numeric">
<button id="signin">Sign in</button>
<input id="tok" type="password" placeholder="Legacy admin token" autocomplete="off">
<button id="go">Use token</button>
</span>
<button id="signout" class="hidden">Sign out</button><span id="msg"></span></header>
<main>
<div id="setup" class="panel hidden">
<h3>Finish account setup</h3>
<div id="pwstep" class="hidden"><b>1. Choose a new password</b> (12+ characters)
<input id="curpw" type="password" placeholder="Current (temporary) password" autocomplete="current-password">
<input id="newpw" type="password" placeholder="New password" autocomplete="new-password">
<button id="chpw">Change password</button></div>
<div id="mfastep" class="hidden"><b>2. Enrol an authenticator app</b>
<button id="mfastart">Show setup key</button>
<div id="mfainfo" class="hidden"><p>Add this key (time-based, 6 digits) to your authenticator app, then enter the code it shows:</p>
<code id="mfasecret"></code><p><code id="mfauri"></code></p>
<input id="mfacode" placeholder="6-digit code" inputmode="numeric" autocomplete="off"><button id="mfaconfirm">Confirm</button></div></div>
<div id="recovery" class="hidden"><b>Recovery codes - shown once. Store them safely; each works one time.</b>
<pre id="recoverylist"></pre><button id="recoverydone">I have saved them</button></div>
</div>
<div id="app" class="hidden">
<div class="cards" id="stats"></div>
<h3>Users</h3>
<div><input id="q" placeholder="Search e-mail / phone / name"> <button id="search">Search</button></div>
<table id="users"><thead><tr><th>E-mail</th><th>Phone</th><th>Name</th><th>Active</th><th></th></tr></thead><tbody></tbody></table>
<h3>Audit log</h3>
<table id="audit"><thead><tr><th>When (UTC)</th><th>Action</th><th>By</th><th>User</th><th>From</th></tr></thead><tbody></tbody></table>
<div id="admins" class="hidden"><h3>Admin accounts</h3>
<table id="adminlist"><thead><tr><th>E-mail</th><th>Role</th><th>Active</th><th>MFA</th><th>Locked</th></tr></thead><tbody></tbody></table></div>
</div>
</main>
<script>
"use strict";
let token = "", legacy = "", role = "", pendingRecovery = null;
const $ = (id) => document.getElementById(id);
const show = (id, on) => $(id).classList.toggle("hidden", !on);
const say = (m) => { $("msg").textContent = m || ""; };
function cell(tr, text) { const td = document.createElement("td"); td.textContent = text == null ? "" : String(text); tr.appendChild(td); return td; }
async function api(path, opts) {
  const headers = {"Content-Type": "application/json"};
  if (token) headers["Authorization"] = "Bearer " + token; else if (legacy) headers["X-Admin-Token"] = legacy;
  const r = await fetch("/api/v1/admin" + path, Object.assign({headers: headers}, opts || {}));
  let data = null; try { data = await r.json(); } catch (e) { data = null; }
  if (!r.ok) { const d = data && data.detail; throw new Error(typeof d === "string" ? d : (r.status === 401 ? "Not signed in" : "Request failed (" + r.status + ")")); }
  return data;
}
const post = (path, body) => api(path, {method: "POST", body: JSON.stringify(body || {})});
function applyToken(res) { token = res.access_token; role = res.role || role; }
function route(res) {
  const need = res.setup_required || [];
  show("loginbar", false); show("signout", true); say("");
  if (need.length) {
    show("setup", true); show("app", false); show("pwstep", need.includes("password")); show("mfastep", need.includes("mfa"));
  } else if (pendingRecovery) {
    show("setup", true); show("pwstep", false); show("mfastep", false);
  } else { show("setup", false); show("app", true); loadAll(); }
}
async function signIn() {
  say("");
  const code = $("code").value.trim();
  const body = {email: $("em").value.trim(), password: $("pw").value};
  if (/^[0-9 ]{6,8}$/.test(code)) body.totp_code = code; else if (code) body.recovery_code = code;
  try {
    const res = await post("/auth/login", body);
    $("pw").value = ""; $("code").value = ""; $("who").textContent = body.email;
    applyToken(res); route(res);
  } catch (e) { say(e.message); }
}
async function loadAll() {
  say("");
  try {
    const s = await api("/stats"); const box = $("stats"); box.replaceChildren();
    for (const [k, v] of Object.entries(s)) { const d = document.createElement("div"); d.className = "card"; const b = document.createElement("b"); b.textContent = v; d.append(b, k.replaceAll("_", " ")); box.appendChild(d); }
    await loadUsers(); await loadAudit();
    if (role === "superadmin") await loadAdmins(); else show("admins", false);
  } catch (e) { say(e.message); }
}
async function loadUsers() {
  const u = await api("/users?limit=50&q=" + encodeURIComponent($("q").value.trim()));
  const body = $("users").tBodies[0]; body.replaceChildren();
  for (const x of u.items) {
    const tr = document.createElement("tr"); cell(tr, x.email); cell(tr, x.phone); cell(tr, x.full_name); cell(tr, x.is_active ? "yes" : "no");
    const td = document.createElement("td"); const b = document.createElement("button");
    b.textContent = x.is_active ? "Disable" : "Enable"; if (x.is_active) b.className = "warn";
    b.onclick = async () => { if (!confirm((x.is_active ? "Disable " : "Enable ") + (x.email || x.phone || "this user") + "?")) return;
      try { await api("/users/" + x.id + "/status", {method: "PATCH", body: JSON.stringify({is_active: !x.is_active})}); await loadAll(); } catch (e) { say(e.message); } };
    td.appendChild(b); tr.appendChild(td); body.appendChild(tr);
  }
}
async function loadAudit() {
  const a = await api("/audit?limit=50"); const body = $("audit").tBodies[0]; body.replaceChildren();
  for (const x of a.items) { const tr = document.createElement("tr"); cell(tr, x.created_at); cell(tr, x.action); cell(tr, x.actor); cell(tr, x.target_user_id); cell(tr, x.client_ip); body.appendChild(tr); }
}
async function loadAdmins() {
  const a = await api("/auth/accounts"); const body = $("adminlist").tBodies[0]; body.replaceChildren(); show("admins", true);
  for (const x of a.items) { const tr = document.createElement("tr"); cell(tr, x.email); cell(tr, x.role); cell(tr, x.is_active ? "yes" : "no"); cell(tr, x.mfa_enabled ? "yes" : "no"); cell(tr, x.locked ? "yes" : ""); body.appendChild(tr); }
}
$("signin").onclick = signIn;
$("go").onclick = () => { legacy = $("tok").value; $("tok").value = ""; token = ""; role = "admin"; $("who").textContent = "legacy token"; show("loginbar", false); show("signout", true); show("app", true); loadAll(); };
$("signout").onclick = async () => { try { if (token) await post("/auth/logout"); } catch (e) {} token = ""; legacy = ""; role = ""; pendingRecovery = null;
  show("app", false); show("setup", false); show("signout", false); show("loginbar", true); $("who").textContent = ""; say("Signed out"); };
$("chpw").onclick = async () => { try { const res = await post("/auth/password/change", {current_password: $("curpw").value, new_password: $("newpw").value});
  $("curpw").value = ""; $("newpw").value = ""; if (res.access_token) applyToken(res); route(res); } catch (e) { say(e.message); } };
$("mfastart").onclick = async () => { try { const r = await post("/auth/mfa/enroll/start"); $("mfasecret").textContent = r.secret; $("mfauri").textContent = r.otpauth_uri; show("mfainfo", true); } catch (e) { say(e.message); } };
$("mfaconfirm").onclick = async () => { try { const res = await post("/auth/mfa/enroll/confirm", {code: $("mfacode").value.trim()}); $("mfacode").value = "";
  $("mfasecret").textContent = ""; $("mfauri").textContent = ""; show("mfainfo", false);
  if (res.access_token) applyToken(res);
  pendingRecovery = res.recovery_codes || []; $("recoverylist").textContent = pendingRecovery.join("\\n"); show("recovery", true); show("mfastep", false); show("pwstep", (res.setup_required || []).includes("password"));
  if ((res.setup_required || []).length) say("Now change your password."); } catch (e) { say(e.message); } };
$("recoverydone").onclick = () => { pendingRecovery = null; $("recoverylist").textContent = ""; show("recovery", false); show("setup", false); show("app", true); loadAll(); };
$("search").onclick = () => loadUsers().catch((e) => { say(e.message); });
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
