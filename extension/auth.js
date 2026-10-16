// OIDC Authorization Code + PKCE sign-in via chrome.identity.launchWebAuthFlow. The refresh token stays in the
// extension's storage; only short-lived access tokens are sent to the broker. The extension never sees any tool
// password — it only receives session artifacts from the broker.
import { BROKER } from "./config.js";

const TOKEN_KEY = "sesame_tokens";

async function sha256(buf) {
  const d = await crypto.subtle.digest("SHA-256", buf);
  return b64url(new Uint8Array(d));
}
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randomString(n = 48) {
  return b64url(crypto.getRandomValues(new Uint8Array(n)));
}

export async function brokerAuthConfig() {
  const r = await fetch(`${BROKER}/v1/auth/config`);
  if (!r.ok) throw new Error(`auth config: ${r.status}`);
  return r.json(); // { issuer, client_id, scopes }
}

async function discovery(issuer) {
  const r = await fetch(`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`);
  if (!r.ok) throw new Error(`discovery: ${r.status}`);
  return r.json();
}

export async function signIn() {
  const { issuer, client_id, scopes } = await brokerAuthConfig();
  const meta = await discovery(issuer);
  const redirectUri = chrome.identity.getRedirectURL("oauth2");
  const verifier = randomString();
  const challenge = await sha256(new TextEncoder().encode(verifier));
  const state = randomString(16);

  const authUrl = new URL(meta.authorization_endpoint);
  authUrl.search = new URLSearchParams({
    response_type: "code",
    client_id,
    redirect_uri: redirectUri,
    scope: (scopes || ["openid", "profile", "email"]).join(" "),
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
  }).toString();

  const redirect = await chrome.identity.launchWebAuthFlow({ url: authUrl.toString(), interactive: true });
  const params = new URL(redirect).searchParams;
  if (params.get("state") !== state) throw new Error("state mismatch");
  const code = params.get("code");
  if (!code) throw new Error(params.get("error") || "no code");

  const tokens = await exchange(meta.token_endpoint, {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id,
    code_verifier: verifier,
  });
  await store(tokens);
  return tokens;
}

async function exchange(tokenEndpoint, body) {
  const r = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  });
  if (!r.ok) throw new Error(`token: ${r.status}`);
  const t = await r.json();
  t.obtained_at = Date.now();
  t.token_endpoint = tokenEndpoint;
  return t;
}

async function store(tokens) {
  await chrome.storage.local.set({ [TOKEN_KEY]: tokens });
}
export async function loadTokens() {
  const v = await chrome.storage.local.get(TOKEN_KEY);
  return v[TOKEN_KEY] || null;
}
export async function signOut() {
  await chrome.storage.local.remove(TOKEN_KEY);
}

// accessToken returns a valid access token, refreshing silently if needed.
export async function accessToken() {
  let t = await loadTokens();
  if (!t) throw new Error("not signed in");
  const expiresAt = t.obtained_at + (t.expires_in || 300) * 1000 - 30000;
  if (Date.now() < expiresAt) return t.access_token;
  if (!t.refresh_token) throw new Error("session expired");
  const { client_id } = await brokerAuthConfig();
  const refreshed = await exchange(t.token_endpoint, {
    grant_type: "refresh_token",
    refresh_token: t.refresh_token,
    client_id,
  });
  if (!refreshed.refresh_token) refreshed.refresh_token = t.refresh_token;
  await store(refreshed);
  return refreshed.access_token;
}
