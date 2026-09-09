// reset.js — page wiring for the RealFlow password-reset fallback.
//
// Runs when a recovery universal link (…/auth/reset-password#token_hash=…&type=recovery)
// opens in the browser instead of the app. It:
//   1. reads token_hash from the URL FRAGMENT only,
//   2. clears the fragment + query from the address bar immediately,
//   3. exchanges token_hash for a short-lived session (POST /auth/v1/verify),
//   4. shows a new-password form and updates the password (PUT /auth/v1/user),
//   5. wipes the token and session from memory afterwards.
//
// The token_hash and the session are NEVER logged, shown, or written to
// localStorage / sessionStorage / cookies. This file uses no storage APIs and
// no console output.

// Absolute, origin-rooted specifier: resolves to
// https://realflow.kiravin.com/auth/reset-password/reset-core.js regardless of
// whether this page was reached at /auth/reset-password or /auth/reset-password/.
import {
  beginRecovery,
  validateNewPassword,
  messageForFailure,
  verifyRecovery,
  updatePassword,
} from "/auth/reset-password/reset-core.js";

// --- Public configuration ---------------------------------------------------
// Both values are PUBLIC by design and already ship inside the RealFlow app
// bundle. Neither is a service-role key or any other secret. The anon key only
// permits what an unauthenticated visitor may do; the actual authority to set a
// password comes from the one-time recovery token in the link.
const CONFIG = {
  baseUrl: "https://amkjommxiricicbdgdgj.supabase.co",
  apiKey:
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFta2pvbW14aXJpY2ljYmRnZGdqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQwNDM1NzksImV4cCI6MjA5OTYxOTU3OX0." +
    "WgvK7DQWjinzn-hycOomKvVxmZC6qjTFa8DH9GRjYmw",
};

const statusEl = document.getElementById("status");
const formEl = document.getElementById("pwform");
const pwEl = document.getElementById("pw");
const pw2El = document.getElementById("pw2");
const formErrorEl = document.getElementById("formError");
const submitEl = document.getElementById("submit");

// Held only in memory, cleared as soon as it is spent or a step fails.
const held = { tokenHash: "", accessToken: "" };

function showStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = "status" + (cls ? " " + cls : "");
}

function showFormError(text) {
  formErrorEl.textContent = text;
  formErrorEl.hidden = !text;
}

function wipe() {
  held.tokenHash = "";
  held.accessToken = "";
  if (pwEl) pwEl.value = "";
  if (pw2El) pw2El.value = "";
}

async function start() {
  // Step 1 + 2: parse the fragment and strip the address bar (both happen
  // inside beginRecovery, before any network call).
  const begun = beginRecovery({
    hash: window.location.hash,
    search: window.location.search,
    history: window.history,
    pathname: window.location.pathname,
  });
  if (!begun.ok) {
    showStatus(messageForFailure(begun.kind), "is-error");
    return;
  }
  held.tokenHash = begun.tokenHash;

  // Step 3: exchange token_hash for a session.
  showStatus("Verifying your reset link…");
  const verified = await verifyRecovery({
    baseUrl: CONFIG.baseUrl,
    apiKey: CONFIG.apiKey,
    tokenHash: held.tokenHash,
    fetchImpl: window.fetch.bind(window),
  });
  held.tokenHash = ""; // no longer needed, spent or not
  if (!verified.ok) {
    showStatus(messageForFailure(verified.kind), "is-error");
    return;
  }
  held.accessToken = verified.accessToken;

  // Step 4: reveal the form.
  showStatus("Choose a new password for your RealFlow account.");
  formEl.hidden = false;
  pwEl.focus();
}

formEl.addEventListener("submit", async (event) => {
  event.preventDefault();
  showFormError("");

  const check = validateNewPassword(pwEl.value, pw2El.value);
  if (!check.ok) {
    showFormError(check.message);
    return;
  }
  if (!held.accessToken) {
    showFormError("");
    showStatus(messageForFailure("verify-failed"), "is-error");
    formEl.hidden = true;
    return;
  }

  submitEl.disabled = true;
  submitEl.textContent = "Updating…";

  let newPassword = pwEl.value;
  const done = await updatePassword({
    baseUrl: CONFIG.baseUrl,
    apiKey: CONFIG.apiKey,
    accessToken: held.accessToken,
    password: newPassword,
    fetchImpl: window.fetch.bind(window),
  });
  newPassword = "";

  if (done.ok) {
    wipe();
    formEl.hidden = true;
    showStatus(
      "Your password has been updated. Open the RealFlow app and sign in with your new password.",
      "is-done",
    );
    return;
  }

  // Failure: the recovery session is spent / unusable — drop it and send the
  // user back to request a fresh link rather than letting them retry blind.
  wipe();
  formEl.hidden = true;
  showStatus(messageForFailure(done.kind), "is-error");
});

window.addEventListener("pagehide", wipe);

start().catch(() => {
  wipe();
  showStatus(messageForFailure("verify-failed"), "is-error");
});
