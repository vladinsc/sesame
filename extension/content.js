// Content script: on a catalog tool's page, ask the background whether this URL is a known tool and, if the page
// looks like a logged-out login page, trigger a login. Minimal and defensive: it never reads page content for
// secrets and accepts no messages from the page.
(async () => {
  const resp = await chrome.runtime.sendMessage({ type: "match", url: location.href });
  const tool = resp && resp.tool;
  if (!tool) return;

  // Heuristic for "logged out": a password field or a /login path. Real connectors declare this precisely via
  // LoginMeta.logged_out; the background could pass it down. Here we keep it simple.
  const looksLoggedOut =
    /\/login(\/|$)/.test(location.pathname) || !!document.querySelector('input[type="password"]');
  if (!looksLoggedOut) return;

  const r = await chrome.runtime.sendMessage({ type: "login", tool });
  if (r && r.error) console.info("[sesame] login:", r.error);
})();
