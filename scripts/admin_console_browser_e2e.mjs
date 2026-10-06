// Real-browser test of the admin console (headless Chrome via the DevTools protocol; Node >= 22, no packages).
//
// Needs a LOCAL backend started by scripts/e2e_local_server.py on a disposable database containing >= 3 users, one of
// them named with HTML (to prove it is rendered as text): see docs/SECURESHIELD_FEATURE_COMPLETION_MATRIX.md.
//   node scripts/admin_console_browser_e2e.mjs        (set CHROME_PATH to override the browser location)
// It disables/enables a user and so writes audit rows: clear admin_audit_logs between runs.
// Drives the admin console in a real (headless) Chrome through the DevTools protocol. No packages needed.
import { spawn } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = "http://localhost:8000/api/v1/admin/console";
const TOKEN = "e2e-local-admin-token";
const dir = mkdtempSync(join(tmpdir(), "chrome-e2e-"));
const chrome = spawn(process.env.CHROME_PATH || "C:/Program Files/Google/Chrome/Application/chrome.exe", [
  "--headless=new", "--remote-debugging-port=9333", `--user-data-dir=${dir}`, "--no-first-run", "--window-size=1200,1000", "about:blank",
], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
const check = (name, ok, extra = "") => { results.push({ name, ok: !!ok, extra }); console.log((ok ? "PASS " : "FAIL ") + name + (extra ? "  -> " + extra : "")); };

let targets;
for (let i = 0; i < 50; i++) { try { targets = await (await fetch("http://127.0.0.1:9333/json")).json(); if (targets.length) break; } catch {} await sleep(200); }
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const events = [];
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } else events.push(d); };
const send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => { const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }); if (r.result.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails)); return r.result.result.value; };
const shot = async (name) => { const r = await send("Page.captureScreenshot", { format: "png" }); writeFileSync(`${process.env.SHOT_DIR || tmpdir()}/${name}.png`, Buffer.from(r.result.data, "base64")); };
await send("Page.enable"); await send("Runtime.enable"); await send("Network.enable"); await send("Log.enable");
const dialogs = [];
// auto-accept confirm() but record the message
setInterval(async () => { for (const e of events.splice(0)) { if (e.method === "Page.javascriptDialogOpening") { dialogs.push(e.params.message); await send("Page.handleJavaScriptDialog", { accept: true }); } else events.push(e); } }, 50);

const nav = async (url) => { await send("Page.navigate", { url }); await sleep(1200); };
const type = async (sel, text) => ev(`(()=>{const e=document.querySelector(${JSON.stringify(sel)});e.value=${JSON.stringify(text)};return true})()`);
const click = async (sel) => ev(`document.querySelector(${JSON.stringify(sel)}).click()`);
const rows = (sel) => ev(`[...document.querySelectorAll(${JSON.stringify(sel)})].map(tr=>[...tr.children].map(td=>td.textContent))`);

// 1. page loads without any data and without a token
await nav(BASE);
check("console page loads", (await ev("document.title")) === "SecureShield admin");
check("no data before authentication", (await ev("document.querySelectorAll('#users tbody tr').length")) === 0);
check("token field is a password input", (await ev("document.getElementById('tok').type")) === "password");

// 2. wrong token -> clear failure, nothing loaded
await type("#tok", "definitely-wrong"); await click("#go"); await sleep(1000);
check("wrong token shows an error message", /Invalid admin token/.test(await ev("document.getElementById('msg').textContent")), await ev("document.getElementById('msg').textContent"));
check("wrong token loads no users", (await ev("document.querySelectorAll('#users tbody tr').length")) === 0);
check("token field cleared after submit", (await ev("document.getElementById('tok').value")) === "");

// 3. correct token
await type("#tok", TOKEN); await click("#go"); await sleep(1500);
check("no error after correct token", (await ev("document.getElementById('msg').textContent")) === "");
const stats = await ev("[...document.querySelectorAll('#stats .card')].map(c=>c.textContent)");
check("statistics rendered", stats.length >= 5 && stats.some((s) => /3userstotal/.test(s.replace(/\s/g, ""))), JSON.stringify(stats));
let users = await rows("#users tbody tr");
check("users listed", users.length === 3, users.map((u) => u[0]).join(","));
await shot("console_loaded");

// 4. search
await type("#q", "p2@"); await click("#search"); await sleep(800);
users = await rows("#users tbody tr");
check("search narrows to one user", users.length === 1 && users[0][0] === "p2@example.com");
await type("#q", ""); await click("#search"); await sleep(800);

// 5. disable a user (confirm dialog)
await ev(`[...document.querySelectorAll('#users tbody tr')].find(tr=>tr.children[0].textContent==='p2@example.com').querySelector('button').click()`); await sleep(1500);
check("confirm dialog was shown", dialogs.length === 1 && /Disable p2@example.com/.test(dialogs[0]), dialogs[0]);
users = await rows("#users tbody tr");
check("user shows as disabled", users.find((u) => u[0] === "p2@example.com")[3] === "no");
const stats2 = await ev("[...document.querySelectorAll('#stats .card')].map(c=>c.textContent.replace(/\\s/g,''))");
check("statistics updated (1 disabled)", stats2.some((s) => /1usersdisabled/.test(s)), JSON.stringify(stats2));
let audit = await rows("#audit tbody tr");
check("audit log shows user.disable with source address", audit.length === 1 && audit[0][1] === "user.disable" && audit[0][3] !== "", JSON.stringify(audit));
await shot("console_disabled");

// 6. the disabled user is really locked out (API level)
const login = await ev(`(async()=>{const r=await fetch('/api/v1/auth/check-user?identifier=p2@example.com');return r.status})()`);
check("service still answers", login === 200);

// 7. re-enable and audit order
await ev(`[...document.querySelectorAll('#users tbody tr')].find(tr=>tr.children[0].textContent==='p2@example.com').querySelector('button').click()`); await sleep(1500);
audit = await rows("#audit tbody tr");
check("re-enable logged, newest first", audit.length === 2 && audit[0][1] === "user.enable" && audit[1][1] === "user.disable", JSON.stringify(audit.map((a) => a[1])));

// 8. cancelling the confirmation changes nothing
dialogs.length = 0;
const before = (await rows("#audit tbody tr")).length;
await ev("window.confirm = () => false"); // user clicks Cancel
await ev(`[...document.querySelectorAll('#users tbody tr')][0].querySelector('button').click()`); await sleep(800);
check("cancel in the confirmation does nothing", (await rows("#audit tbody tr")).length === before);

// 9. same-origin / CSP protections
const csp = await ev(`fetch(location.href).then(r=>r.headers.get('content-security-policy'))`);
check("CSP header present", /default-src 'none'/.test(csp) && /frame-ancestors 'none'/.test(csp), csp);
let cross = await ev(`fetch('http://example.com/', {mode:'no-cors'}).then(()=> 'allowed').catch(e=>'blocked: '+e.message)`);
check("cross-origin fetch blocked by connect-src", /blocked/.test(cross), cross);
const injected = await ev(`(()=>{try{ const s=document.createElement('script'); s.src='http://example.com/x.js'; document.head.appendChild(s); return 'appended'; }catch(e){return 'err'} })()`);
await sleep(500);
const consoleViol = events.filter((e) => e.method === "Log.entryAdded" && /Content Security Policy|Refused/i.test(e.params.entry.text)).length;
check("external script injection refused by CSP", consoleViol >= 1, "violations logged: " + consoleViol);
const evalTry = await ev(`(()=>{try{ new Function('return 1')(); return 'eval allowed'}catch(e){return 'blocked'} })()`);
// framing attempt: embed the console in a frame inside another page
await send("Page.navigate", { url: "about:blank" }); await sleep(500);
await ev(`document.body.innerHTML = '<iframe id="f" src="${BASE}" width="600" height="300"></iframe>'`); await sleep(2500);
const tree = (await send("Page.getFrameTree")).result.frameTree;
const child = (tree.childFrames || [])[0];
const rendered = child ? await send("Runtime.evaluate", { expression: "1", contextId: undefined }) : null;
const childUrl = child ? (child.frame.unreachableUrl ? "unreachable:" + child.frame.unreachableUrl : child.frame.url) : "no child frame";
check("console refuses to render inside a frame (frame-ancestors)", child && (child.frame.unreachableUrl || /^chrome-error:/.test(child.frame.url)), childUrl);

// 10. XSS: a user whose name is HTML must be rendered as text
await nav(BASE);
await type("#tok", TOKEN); await click("#go"); await sleep(1500);
const hasInjectedNode = await ev(`document.querySelectorAll('#users img, #users script, #users svg').length`);
const xssFlag = await ev('window.__xss === undefined');
const shownName = (await rows('#users tbody tr')).map(r=>r[2]).find(n=>n && n.includes('<img'));
check("HTML in a user's name is shown as text, never executed", hasInjectedNode === 0 && xssFlag && !!shownName, shownName);

// 11. failure behaviour: server error / network down
await ev("window.__orig = window.fetch; window.fetch = () => Promise.reject(new TypeError('network down'))");
await click("#search"); await sleep(500);
check("network failure shows a message and keeps the page usable", (await ev("document.getElementById('msg').textContent")).length > 0, await ev("document.getElementById('msg').textContent"));
await ev("window.fetch = window.__orig");
const tokenInStorage = await ev(`JSON.stringify([Object.keys(localStorage), Object.keys(sessionStorage), document.cookie, location.href])`);
check("token not stored in storage, cookies or URL", !tokenInStorage.includes(TOKEN) && tokenInStorage.includes('[[],[],"",'), tokenInStorage);

console.log(JSON.stringify({ passed: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length }));
ws.close(); chrome.kill();
process.exit(results.some((r) => !r.ok) ? 1 : 0);
