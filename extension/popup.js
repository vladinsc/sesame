import { signIn, signOut, loadTokens } from "./auth.js";

const bodyEl = document.getElementById("body");
const whoEl = document.getElementById("who");
const authEl = document.getElementById("auth");
const countEl = document.getElementById("count");

async function render() {
  const signedIn = !!(await loadTokens());
  authEl.textContent = signedIn ? "Sign out" : "Sign in";
  if (!signedIn) {
    whoEl.textContent = "";
    bodyEl.innerHTML = `<div class="msg">Sign in to see your tools.</div>`;
    countEl.textContent = "";
    return;
  }
  const { catalog } = await chrome.runtime.sendMessage({ type: "catalog" });
  countEl.textContent = `${catalog.length} tool${catalog.length === 1 ? "" : "s"}`;
  if (!catalog.length) {
    bodyEl.innerHTML = `<div class="empty">No tools available for your groups.</div>`;
    return;
  }
  const ul = document.createElement("ul");
  for (const tool of catalog) {
    for (const acct of tool.accounts.length ? tool.accounts : [{ label: "" }]) {
      const li = document.createElement("li");
      const left = document.createElement("div");
      left.innerHTML = `<div class="name">${esc(tool.name)}</div><div class="acct">${esc(acct.label || "default")}</div>`;
      const btn = document.createElement("button");
      btn.textContent = "Open";
      btn.onclick = () => open(tool, acct.label, btn);
      li.append(left, btn);
      ul.append(li);
    }
  }
  bodyEl.replaceChildren(ul);
}

async function open(tool, account, btn) {
  btn.disabled = true;
  btn.textContent = "Opening…";
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const r = await chrome.runtime.sendMessage({ type: "login", tool, account, tab });
  if (r && r.ok) {
    await chrome.tabs.update(tab.id, { url: tool.url });
    window.close();
  } else {
    btn.disabled = false;
    btn.textContent = "Retry";
    if (r && r.error) {
      const note = document.createElement("div");
      note.className = "msg";
      note.textContent = r.error;
      bodyEl.prepend(note);
    }
  }
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

authEl.onclick = async () => {
  if (await loadTokens()) {
    await signOut();
  } else {
    try {
      await signIn();
    } catch (e) {
      bodyEl.innerHTML = `<div class="msg">Sign-in failed: ${esc(e.message)}</div>`;
      return;
    }
  }
  render();
};

render();
