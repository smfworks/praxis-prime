import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";

import { ApiError, api, currentProfile, rowsOf, selectProfile, setCsrf, textOf } from "./api";
import { ChatView, DirectoryView, FactorsView, ListView, Approvals } from "./views";
import { asPublicKey, credentialJson, requestOptions } from "./webauthn";

type Account = { username: string; role: string };

const NAV = [
  ["chat", "Chat"],
  ["approvals", "Approvals"],
  ["memory", "Memory"],
  ["skills", "Skills"],
  ["routines", "Routines"],
  ["security", "Security"],
] as const;

function useRoute(): string {
  const [route, setRoute] = useState(() => routeFromHash());
  useEffect(() => {
    const onHash = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  return route;
}

function routeFromHash(): string {
  const raw = location.hash.replace(/^#\/?/, "");
  return raw.split("/")[0] || "chat";
}

export function App() {
  const route = useRoute();
  const client = useQueryClient();
  const session = useQuery({
    queryKey: ["session"],
    queryFn: loadSession,
  });
  const account = session.data ?? null;

  if (session.isLoading) {
    return (
      <p className="p-6" role="status">
        Loading…
      </p>
    );
  }
  if (!account) {
    return (
      <Login
        onSignedIn={() => {
          void client.invalidateQueries({ queryKey: ["session"] });
          if (!location.hash) location.hash = "#/chat";
        }}
      />
    );
  }
  return <Shell account={account} route={route} />;
}

async function loadSession(): Promise<Account | null> {
  try {
    const body = await api("GET", "/v1/auth/session");
    setCsrf(textOf(body.csrfToken));
    const account = body.account;
    if (!account || typeof account !== "object") return null;
    const row = account as Record<string, unknown>;
    return { username: textOf(row.username), role: textOf(row.role) };
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 403)) return null;
    throw error;
  }
}

function Shell({ account, route }: { account: Account; route: string }) {
  const client = useQueryClient();
  const [profile, setProfile] = useState(currentProfile);
  const [notice, setNotice] = useState("");
  const profiles = useQuery({
    queryKey: ["profiles"],
    queryFn: async () => rowsOf(await api("GET", "/v1/profiles"), "profiles"),
  });
  useEffect(() => {
    const flag = new URLSearchParams(window.location.search).get("oidc");
    if (flag === "ok") setNotice("Signed in.");
    else if (flag === "linked") setNotice("Identity linked.");
    if (flag) {
      const url = new URL(window.location.href);
      url.searchParams.delete("oidc");
      window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
      if (!location.hash) location.hash = "#/chat";
    }
  }, []);
  useEffect(() => {
    const names = (profiles.data ?? []).map((item) => textOf(item.id)).filter(Boolean);
    if (!names.length) return;
    if (profile && names.includes(profile)) return;
    const next = names.includes("default") ? "default" : names[0];
    selectProfile(next);
    setProfile(next);
  }, [profiles.data, profile]);

  async function signOut() {
    await api("POST", "/v1/auth/logout");
    setCsrf("");
    await client.invalidateQueries({ queryKey: ["session"] });
  }

  const admin = account.role === "owner" || account.role === "admin";
  return (
    <div className="min-h-screen bg-canvas text-ink">
      <a className="skip" href="#main">
        Skip to content
      </a>
      <header className="border-b border-line bg-card">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-4 px-4 py-3">
          <p className="text-lg font-semibold">Praxis Prime</p>
          <nav className="flex flex-wrap gap-3" aria-label="Primary">
            {NAV.map(([id, label]) => (
              <a key={id} href={`#/${id}`} aria-current={route === id ? "page" : undefined}>
                {label}
              </a>
            ))}
            {admin ? (
              <a href="#/directory" aria-current={route === "directory" ? "page" : undefined}>
                Directory
              </a>
            ) : null}
          </nav>
          <label className="ml-auto flex items-center gap-2 text-sm">
            Profile
            <select
              value={profile}
              onChange={(event) => {
                selectProfile(event.target.value);
                setProfile(event.target.value);
              }}
            >
              {(profiles.data ?? []).map((item) => {
                const id = textOf(item.id);
                return (
                  <option key={id} value={id}>
                    {id}
                  </option>
                );
              })}
            </select>
          </label>
          <button type="button" className="btn-quiet" onClick={() => void signOut()}>
            Sign out
          </button>
        </div>
      </header>
      <main id="main" className="mx-auto max-w-5xl px-4 py-6">
        <p className="mb-4 text-sm text-muted">
          Signed in as {account.username}. <span className="text-muted">({account.role})</span>
        </p>
        {notice ? (
          <p className="mb-4" role="status">
            {notice}
          </p>
        ) : null}
        {profile ? (
          <>
            {route === "approvals" ? <Approvals profile={profile} /> : null}
            {route === "chat" ? <ChatView profile={profile} /> : null}
            {route === "memory" ? (
              <ListView title="Memory" path="/v1/memory" field="entries" profile={profile} />
            ) : null}
            {route === "skills" ? (
              <ListView title="Skills" path="/v1/skills" field="skills" profile={profile} />
            ) : null}
            {route === "routines" ? (
              <ListView title="Routines" path="/v1/routines" field="routines" profile={profile} />
            ) : null}
          </>
        ) : (
          <p role="status">Choose a profile.</p>
        )}
        {route === "security" ? <FactorsView /> : null}
        {route === "directory" && admin ? <DirectoryView /> : null}
      </main>
    </div>
  );
}

function oidcNeedsCode(): boolean {
  return new URLSearchParams(window.location.search).get("oidc") === "mfa";
}

function Login({ onSignedIn }: { onSignedIn: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  // OIDC leaves the second-factor token in the pp_mfa cookie. The code form
  // must show even though mfaToken stays empty; the server reads the cookie.
  const [codeStep, setCodeStep] = useState(oidcNeedsCode);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<{ id: string; displayName: string }[]>([]);

  useEffect(() => {
    const flag = new URLSearchParams(window.location.search).get("oidc");
    if (flag === "ok") setNotice("Signed in.");
    else if (flag === "linked") setNotice("Identity linked.");
    else if (flag === "mfa") {
      setNotice("Enter your authenticator code to finish sign-in.");
      setCodeStep(true);
    } else if (flag === "error") setError("Sign-in could not be completed.");
    if (flag) {
      const url = new URL(window.location.href);
      url.searchParams.delete("oidc");
      window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
    }
    void api("GET", "/v1/auth/oidc/providers")
      .then((body) => {
        const rows = rowsOf(body, "providers")
          .map((item) => ({
            id: textOf(item.id),
            displayName: textOf(item.displayName),
          }))
          .filter((item) => item.id && item.displayName);
        setProviders(rows);
      })
      .catch(() => setProviders([]));
  }, []);

  async function startOidc(provider: string) {
    setBusy(true);
    setError("");
    try {
      const body = await api("POST", "/v1/auth/oidc/login", { provider });
      const url = textOf(body.authorizationUrl);
      if (!url) throw new Error("Sign-in could not be completed.");
      window.location.assign(url);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Sign-in could not be completed.");
      setBusy(false);
    }
  }

  async function submitPassword(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = await api("POST", "/v1/auth/login", { username, password });
      if (body.mfaRequired === true) {
        setMfaToken(textOf(body.mfaToken));
        return;
      }
      setCsrf(textOf(body.csrfToken));
      onSignedIn();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "sign-in failed");
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = await api("POST", "/v1/auth/login/totp", { mfaToken, code });
      setCsrf(textOf(body.csrfToken));
      onSignedIn();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "code was rejected");
    } finally {
      setBusy(false);
    }
  }

  async function usePasskey() {
    setBusy(true);
    setError("");
    try {
      const started = await api("POST", "/v1/auth/passkey/options", { username });
      const credential = await navigator.credentials.get({
        publicKey: requestOptions(started.options),
      });
      if (!credential) throw new Error("passkey was not used");
      const body = await api("POST", "/v1/auth/passkey/verify", {
        credential: credentialJson(asPublicKey(credential)),
      });
      setCsrf(textOf(body.csrfToken));
      onSignedIn();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "passkey was rejected");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto max-w-md px-4 py-12">
      <h1 className="mb-2 text-2xl font-semibold">Praxis Prime</h1>
      <p className="mb-6 text-muted">Sign in on this machine. The app does not call out.</p>
      {codeStep || mfaToken ? (
        <form className="grid gap-3" onSubmit={(event) => void submitCode(event)}>
          <label className="grid gap-1">
            Authenticator code
            <input
              className="field"
              value={code}
              inputMode="numeric"
              autoComplete="one-time-code"
              onChange={(event) => setCode(event.target.value)}
              required
            />
          </label>
          <button className="btn" type="submit" disabled={busy}>
            Verify code
          </button>
        </form>
      ) : (
        <form className="grid gap-3" onSubmit={(event) => void submitPassword(event)}>
          <label className="grid gap-1">
            Username
            <input
              className="field"
              value={username}
              autoComplete="username"
              onChange={(event) => setUsername(event.target.value)}
              required
            />
          </label>
          <label className="grid gap-1">
            Password
            <input
              className="field"
              type="password"
              value={password}
              autoComplete="current-password"
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </label>
          <button className="btn" type="submit" disabled={busy}>
            Sign in
          </button>
          <button className="btn-quiet" type="button" disabled={busy} onClick={() => void usePasskey()}>
            Use a passkey
          </button>
          {providers.map((item) => (
            <button
              key={item.id}
              className="btn-quiet"
              type="button"
              disabled={busy}
              onClick={() => void startOidc(item.id)}
            >
              Sign in with {item.displayName}
            </button>
          ))}
        </form>
      )}
      {notice ? (
        <p className="mt-4" role="status">
          {notice}
        </p>
      ) : null}
      {error ? (
        <p className="mt-4 text-danger" role="alert">
          {error}
        </p>
      ) : null}
    </main>
  );
}
