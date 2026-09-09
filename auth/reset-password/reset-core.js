// reset-core.js — pure logic for the password-reset fallback page.
//
// No DOM, no globals, no config baked in: every function takes what it needs
// as an argument, so it is all unit-testable with a mocked `fetch`. reset.js
// wires this to the page and supplies the public Supabase URL + anon key.
//
// Security rules enforced here:
//   * the recovery credential is read ONLY from a URL fragment string;
//   * a query string that carries any recovery material is rejected outright;
//   * failures are returned as short opaque `kind` codes, never as server
//     response bodies — reset.js turns a kind into a fixed user-facing string;
//   * nothing here logs, stores, or echoes the token_hash or the session.

export const MIN_PASSWORD_LENGTH = 8;

// Keys that must never appear in the query string of a reset link.
const RECOVERY_QUERY_KEYS = ["token_hash", "access_token", "refresh_token"];

/**
 * Parse `token_hash` + `type=recovery` from a URL fragment string.
 * Accepts the raw `location.hash` (with or without the leading "#").
 * Returns { tokenHash } or null. Unrelated fragment params are ignored, but a
 * DUPLICATED `token_hash` or `type` is rejected outright: a link that carries
 * two of either is malformed / suspicious, and refusing removes any ambiguity
 * about which value would win.
 */
export function parseRecoveryFragment(hash) {
  if (typeof hash !== "string") return null;
  const body = hash.charAt(0) === "#" ? hash.slice(1) : hash;
  if (!body) return null;

  let params;
  try {
    params = new URLSearchParams(body);
  } catch {
    return null;
  }
  if (params.getAll("token_hash").length > 1 || params.getAll("type").length > 1) {
    return null;
  }
  if (params.get("type") !== "recovery") return null;
  const tokenHash = params.get("token_hash");
  return tokenHash ? { tokenHash } : null;
}

/**
 * True if a query string ("?a=b" or "a=b") carries anything recovery-related.
 * Such a link is refused: query values reach the origin server and its logs.
 */
export function queryHasRecoveryMaterial(search) {
  if (typeof search !== "string" || search === "" || search === "?") return false;
  const body = search.charAt(0) === "?" ? search.slice(1) : search;
  let params;
  try {
    params = new URLSearchParams(body);
  } catch {
    return false;
  }
  if (params.get("type") === "recovery") return true;
  return RECOVERY_QUERY_KEYS.some((k) => params.has(k));
}

/**
 * Strip the fragment AND the query from the address bar before any network
 * call, so the credential is never left visible or re-readable. `history` and
 * `pathname` are injected so this is testable without a browser.
 */
export function stripAddressBar(history, pathname) {
  if (history && typeof history.replaceState === "function") {
    history.replaceState(null, "", pathname || "/");
  }
}

/**
 * The full "on load" sequence, DOM-free: strip the address bar first, then
 * reject a query-string leak, then require a well-formed recovery fragment.
 * Returns { ok: true, tokenHash } or { ok: false, kind }.
 */
export function beginRecovery({ hash, search, history, pathname }) {
  // Always strip first — regardless of what we find below.
  stripAddressBar(history, pathname);

  if (queryHasRecoveryMaterial(search)) {
    return { ok: false, kind: "query-leak" };
  }
  const parsed = parseRecoveryFragment(hash);
  if (!parsed) {
    return { ok: false, kind: "missing" };
  }
  return { ok: true, tokenHash: parsed.tokenHash };
}

/** Validate the new password pair. Returns { ok: true } or { ok: false, message }. */
export function validateNewPassword(password, confirmation) {
  if (typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
    return { ok: false, message: `Password needs at least ${MIN_PASSWORD_LENGTH} characters.` };
  }
  if (password !== confirmation) {
    return { ok: false, message: "The two passwords do not match." };
  }
  return { ok: true };
}

// Fixed, safe user-facing text per failure kind. No server text ever reaches
// the user; these strings are the whole vocabulary of what can be shown.
const MESSAGES = {
  missing: "This reset link is missing or malformed. Open the RealFlow app and use “Forgot password?” to get a new one.",
  malformed: "This reset link is missing or malformed. Open the RealFlow app and use “Forgot password?” to get a new one.",
  "query-leak": "This reset link isn’t in a form we can safely use. Request a new one from the RealFlow app.",
  expired: "This reset link has expired. Request a new one from the RealFlow app.",
  used: "This reset link has already been used. Request a new one from the RealFlow app.",
  "verify-failed": "We couldn’t verify this reset link. Request a new one from the RealFlow app.",
  "update-failed": "We couldn’t update your password. Request a new reset link from the RealFlow app and try again.",
  network: "We couldn’t reach the server. Check your connection and try again.",
};

export function messageForFailure(kind) {
  return MESSAGES[kind] || MESSAGES["verify-failed"];
}

// --- Supabase Auth REST calls -------------------------------------------------
// GoTrue endpoints, called directly with fetch. No supabase-js, so nothing is
// ever written to localStorage / sessionStorage / cookies.

/**
 * Classify a non-2xx verify response into a safe kind WITHOUT surfacing the
 * body. We peek at a small set of known error codes only to choose between
 * "expired" and "used"; anything else is a generic "verify-failed".
 */
function classifyVerifyFailure(status, body) {
  const code = String(
    (body && (body.error_code || body.code || body.error)) || "",
  ).toLowerCase();
  const msg = String((body && (body.msg || body.message || body.error_description)) || "").toLowerCase();
  const blob = code + " " + msg;
  if (blob.includes("expired")) return "expired";
  if (blob.includes("used") || blob.includes("already") || blob.includes("consumed")) return "used";
  if (status >= 400 && status < 500) return "expired"; // otp_* failures are 4xx and mean "no longer usable"
  return "verify-failed";
}

/**
 * POST /auth/v1/verify with { type: "recovery", token_hash }.
 * Returns { ok: true, accessToken } or { ok: false, kind }.
 * The token_hash goes in the JSON body only — never in the URL.
 */
export async function verifyRecovery({ baseUrl, apiKey, tokenHash, fetchImpl }) {
  const doFetch = fetchImpl || fetch;
  let res;
  try {
    res = await doFetch(`${baseUrl}/auth/v1/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        apikey: apiKey,
        Accept: "application/json",
      },
      body: JSON.stringify({ type: "recovery", token_hash: tokenHash }),
    });
  } catch {
    return { ok: false, kind: "network" };
  }

  let body = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }

  if (!res.ok) {
    return { ok: false, kind: classifyVerifyFailure(res.status, body) };
  }
  const accessToken = body && typeof body.access_token === "string" ? body.access_token : "";
  if (!accessToken) {
    return { ok: false, kind: "verify-failed" };
  }
  return { ok: true, accessToken };
}

/**
 * PUT /auth/v1/user with { password }, authorised by the recovery session's
 * access token. Returns { ok: true } or { ok: false, kind }.
 */
export async function updatePassword({ baseUrl, apiKey, accessToken, password, fetchImpl }) {
  const doFetch = fetchImpl || fetch;
  let res;
  try {
    res = await doFetch(`${baseUrl}/auth/v1/user`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        apikey: apiKey,
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
      body: JSON.stringify({ password }),
    });
  } catch {
    return { ok: false, kind: "network" };
  }
  if (!res.ok) {
    return { ok: false, kind: "update-failed" };
  }
  return { ok: true };
}
