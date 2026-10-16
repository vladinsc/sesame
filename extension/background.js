// Service worker: keeps the catalog, matches tabs to tools, drives logins, and writes the returned session
// artifacts (cookies, web storage) into the browser. It never holds any tool password.
import { BROKER, CATALOG_REFRESH_MS } from "./config.js";
import { accessToken, loadTokens } from "./auth.js";

let catalog = []; // [{ id, name, url, login, accounts:[{label}] }]
const lastLogin = new Map(); // tabId-or-toolId -> timestamp, to avoid login loops

async function refreshCatalog() {
  try {
    const token = await accessToken();
    const r = await fetch(`${BROKER}/v1/catalog`, { headers: { Authorization: `Bearer ${token}` } });
    if (r.ok) catalog = (await r.json()).tools || [];
  } catch (_) {
    /* not signed in yet */
  }
}

// matchTool returns the catalog tool whose url is a prefix of tabUrl (longest match wins).
function matchTool(tabUrl) {
  let best = null;
  for (const t of catalog) {
    if (sameOriginPrefix(t.url, tabUrl) && (!best || t.url.length > best.url.length)) best = t;
  }
  return best;
}
function sameOriginPrefix(toolUrl, tabUrl) {
  try {
    const a = new URL(toolUrl), b = new URL(tabUrl);
    if (a.protocol !== b.protocol || a.host !== b.host) return false;
    const base = a.pathname.replace(/\/$/, "");
    return b.pathname === base || b.pathname.startsWith(base + "/") || base === "";
  } catch {
    return false;
  }
}

// onLogin is triggered by the content script when it detects a tool's logged-out page.
async function login(tool, accountLabel, tab) {
  const key = `${tab.id}:${tool.id}`;
  if (Date.now() - (lastLogin.get(key) || 0) < 60000) return { skipped: true };
  lastLogin.set(key, Date.now());

  const token = await accessToken();
  const r = await fetch(`${BROKER}/v1/login`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      tool: tool.id,
      account: accountLabel || (tool.accounts[0] && tool.accounts[0].label) || "",
      user_agent: navigator.userAgent,
      language: navigator.language,
    }),
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    return { error: e.error || `login ${r.status}` };
  }
  const { artifacts, landing } = await r.json();
  await applyArtifacts(artifacts);
  if (tab && tab.id) {
    const dest = landing && landing.startsWith("/") ? new URL(landing, tool.url).toString() : tool.url;
    await chrome.tabs.update(tab.id, { url: dest });
  }
  return { ok: true };
}

// applyArtifacts writes cookies and (via a content script) web-storage entries, per origin.
async function applyArtifacts(artifacts) {
  const storageByOrigin = new Map();
  for (const a of artifacts || []) {
    if (a.type === "cookie") {
      await setCookie(a);
    } else if (a.type === "localStorage" || a.type === "sessionStorage") {
      if (!storageByOrigin.has(a.origin)) storageByOrigin.set(a.origin, []);
      storageByOrigin.get(a.origin).push(a);
    }
  }
  // web storage is set by injecting a one-shot function into a tab on that origin (omitted in the local demo,
  // which only uses cookies).
}

async function setCookie(a) {
  const url = a.origin + (a.path || "/");
  const details = {
    url,
    name: a.name,
    value: a.value,
    path: a.path || "/",
    httpOnly: !!a.httpOnly,
    secure: !!a.secure || a.origin.startsWith("https"),
  };
  if (a.sameSite) details.sameSite = ({ lax: "lax", strict: "strict", none: "no_restriction" })[a.sameSite];
  if (a.maxAge && a.maxAge > 0) details.expirationDate = Math.floor(Date.now() / 1000) + a.maxAge;
  await chrome.cookies.set(details);
}

// Messages from the popup and content script.
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    switch (msg.type) {
      case "catalog":
        await refreshCatalog();
        reply({ catalog, signedIn: !!(await loadTokens()) });
        break;
      case "login":
        reply(await login(msg.tool, msg.account, sender.tab || msg.tab));
        break;
      case "match":
        reply({ tool: matchTool(msg.url) });
        break;
      default:
        reply({ error: "unknown message" });
    }
  })();
  return true; // async reply
});

chrome.alarms?.create("catalog", { periodInMinutes: CATALOG_REFRESH_MS / 60000 });
chrome.alarms?.onAlarm.addListener((a) => a.name === "catalog" && refreshCatalog());
refreshCatalog();
