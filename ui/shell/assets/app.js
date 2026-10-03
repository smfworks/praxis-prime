const banner = document.querySelector("#banner");
const login = document.querySelector("#login");
const security = document.querySelector("#security");
const providers = document.querySelector("#providers");
const totpForm = document.querySelector("#totp-form");
const identities = document.querySelector("#identities");
const linkProvider = document.querySelector("#link-provider");
const who = document.querySelector("#who");

let csrf = "";
let mfaToken = "";
let providerRows = [];

function showBanner(text) {
  banner.textContent = text;
  banner.hidden = !text;
}

function clearNode(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

async function request(path, options) {
  const headers = { Accept: "application/json" };
  if (options && options.body) {
    headers["Content-Type"] = "application/json";
  }
  if (csrf && options && options.csrf) {
    headers["x-csrf-token"] = csrf;
  }
  const response = await fetch(path, {
    method: options && options.method ? options.method : "GET",
    headers,
    body: options && options.body ? JSON.stringify(options.body) : undefined,
    credentials: "same-origin",
  });
  const payload = await response.json();
  return { status: response.status, payload };
}

function messageOf(payload, fallback) {
  const error = payload && payload.error;
  if (error && typeof error.message === "string" && error.message) {
    return error.message;
  }
  return fallback;
}

function showLogin() {
  login.hidden = false;
  security.hidden = true;
}

function showSecurity(account) {
  login.hidden = true;
  totpForm.hidden = true;
  security.hidden = false;
  const name = account && account.username ? account.username : "this account";
  who.textContent = "Signed in as " + name + ".";
}

async function loadProviders() {
  const { payload } = await request("/v1/auth/oidc/providers");
  providerRows = Array.isArray(payload.providers) ? payload.providers : [];
  clearNode(providers);
  clearNode(linkProvider);
  providerRows.forEach(function (item) {
    if (!item || typeof item.id !== "string" || typeof item.displayName !== "string") {
      return;
    }
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary";
    button.textContent = "Sign in with " + item.displayName;
    button.addEventListener("click", function () {
      startOidc(item.id);
    });
    providers.appendChild(button);
    const option = document.createElement("option");
    option.value = item.id;
    option.textContent = item.displayName;
    linkProvider.appendChild(option);
  });
  document.querySelector("#link-button").disabled = providerRows.length === 0;
}

async function loadIdentities() {
  const { status, payload } = await request("/v1/auth/oidc/identities");
  clearNode(identities);
  if (status !== 200 || !Array.isArray(payload.identities)) {
    return;
  }
  if (payload.identities.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No linked identities.";
    identities.appendChild(item);
    return;
  }
  payload.identities.forEach(function (row) {
    const item = document.createElement("li");
    const label = document.createElement("span");
    const name = row.displayName || row.issuer || "Identity";
    label.textContent = name;
    item.appendChild(label);
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary";
    button.textContent = "Unlink";
    button.addEventListener("click", function () {
      unlink(row.issuer, row.subject);
    });
    item.appendChild(button);
    identities.appendChild(item);
  });
}

async function refreshSession() {
  const { status, payload } = await request("/v1/auth/session");
  if (status !== 200) {
    csrf = "";
    showLogin();
    return false;
  }
  csrf = typeof payload.csrfToken === "string" ? payload.csrfToken : "";
  showSecurity(payload.account);
  await loadIdentities();
  return true;
}

async function startOidc(provider) {
  showBanner("");
  const { status, payload } = await request("/v1/auth/oidc/login", {
    method: "POST",
    body: { provider: provider },
  });
  if (status !== 200 || typeof payload.authorizationUrl !== "string") {
    showBanner(messageOf(payload, "Sign-in could not be completed."));
    return;
  }
  window.location.assign(payload.authorizationUrl);
}

async function stepUp() {
  const password = document.querySelector("#link-password").value;
  const code = document.querySelector("#link-code").value;
  const { status, payload } = await request("/v1/auth/step-up", {
    method: "POST",
    csrf: true,
    body: { password: password, code: code },
  });
  if (status !== 200 || typeof payload.stepUpToken !== "string") {
    showBanner(messageOf(payload, "The change could not be completed."));
    return "";
  }
  return payload.stepUpToken;
}

async function unlink(issuer, subject) {
  const token = await stepUp();
  if (!token) {
    return;
  }
  const { status, payload } = await request("/v1/auth/oidc/unlink", {
    method: "POST",
    csrf: true,
    body: { issuer: issuer, subject: subject, stepUpToken: token },
  });
  if (status !== 200) {
    showBanner(messageOf(payload, "The change could not be completed."));
    return;
  }
  showBanner("Identity unlinked.");
  await loadIdentities();
}

document.querySelector("#password-form").addEventListener("submit", async function (event) {
  event.preventDefault();
  showBanner("");
  const { status, payload } = await request("/v1/auth/login", {
    method: "POST",
    body: {
      username: document.querySelector("#username").value,
      password: document.querySelector("#password").value,
    },
  });
  if (status !== 200) {
    showBanner(messageOf(payload, "Sign-in could not be completed."));
    return;
  }
  if (payload.mfaRequired) {
    mfaToken = typeof payload.mfaToken === "string" ? payload.mfaToken : "";
    totpForm.hidden = false;
    return;
  }
  csrf = typeof payload.csrfToken === "string" ? payload.csrfToken : "";
  showSecurity(payload.account);
  await loadIdentities();
});

totpForm.addEventListener("submit", async function (event) {
  event.preventDefault();
  const { status, payload } = await request("/v1/auth/login/totp", {
    method: "POST",
    body: { mfaToken: mfaToken, code: document.querySelector("#totp").value },
  });
  if (status !== 200) {
    showBanner(messageOf(payload, "Sign-in could not be completed."));
    return;
  }
  mfaToken = "";
  csrf = typeof payload.csrfToken === "string" ? payload.csrfToken : "";
  showSecurity(payload.account);
  await loadIdentities();
});

document.querySelector("#link-form").addEventListener("submit", async function (event) {
  event.preventDefault();
  const provider = linkProvider.value;
  if (!provider) {
    showBanner("The change could not be completed.");
    return;
  }
  const token = await stepUp();
  if (!token) {
    return;
  }
  const { status, payload } = await request("/v1/auth/oidc/link", {
    method: "POST",
    csrf: true,
    body: { provider: provider, stepUpToken: token },
  });
  if (status !== 200 || typeof payload.authorizationUrl !== "string") {
    showBanner(messageOf(payload, "The change could not be completed."));
    return;
  }
  window.location.assign(payload.authorizationUrl);
});

document.querySelector("#logout").addEventListener("click", async function () {
  await request("/v1/auth/logout", { method: "POST", csrf: true, body: {} });
  csrf = "";
  showBanner("");
  showLogin();
});

const flag = new URLSearchParams(window.location.search).get("oidc");
if (flag) {
  const next = window.location.pathname;
  window.history.replaceState({}, "", next);
}
loadProviders().then(refreshSession).then(function (signedIn) {
  if (flag === "mfa") {
    totpForm.hidden = false;
    showBanner("Enter the code from your authenticator.");
    return;
  }
  if (flag === "error") {
    showBanner(signedIn ? "The change could not be completed." : "Sign-in could not be completed.");
    return;
  }
  if (flag === "linked") {
    showBanner("Identity linked.");
    return;
  }
  if (flag === "ok") {
    showBanner("Signed in.");
  }
});
