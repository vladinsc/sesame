// sesame extension configuration. Set BROKER to your broker's base URL. The OIDC client details are fetched
// from the broker at runtime (GET /v1/auth/config), so the extension is identity-provider agnostic.
export const BROKER = "http://127.0.0.1:8080";
export const CATALOG_REFRESH_MS = 5 * 60 * 1000;
