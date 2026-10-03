import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type FormEvent } from "react";

import { api, rowsOf, textOf } from "./api";
import { streamChat } from "./chat";
import { asPublicKey, creationOptions, credentialJson } from "./webauthn";

type Line = { role: "you" | "agent" | "error"; text: string };

export function ChatView({ profile }: { profile: string }) {
  const [lines, setLines] = useState<Line[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const sessionId = useRef("");
  const stopStream = useRef<(() => void) | null>(null);
  const generation = useRef(0);

  useEffect(() => {
    generation.current += 1;
    sessionId.current = "";
    setLines([]);
    setDraft("");
    setBusy(false);
    stopStream.current?.();
    stopStream.current = null;
    return () => {
      stopStream.current?.();
      stopStream.current = null;
    };
  }, [profile]);

  function send(event: FormEvent) {
    event.preventDefault();
    const text = draft.trim();
    if (!text || busy || !profile) return;
    const ticket = generation.current;
    setDraft("");
    setBusy(true);
    setLines((current) => [...current, { role: "you", text }, { role: "agent", text: "" }]);
    stopStream.current?.();
    stopStream.current = streamChat(
      text,
      profile,
      sessionId.current,
      (delta) => {
        if (generation.current !== ticket) return;
        setLines((current) => {
          const next = current.slice();
          const last = next[next.length - 1];
          if (last && last.role === "agent") {
            next[next.length - 1] = { role: "agent", text: last.text + delta };
          }
          return next;
        });
      },
      (result) => {
        if (generation.current !== ticket) return;
        if (result.sessionId) sessionId.current = result.sessionId;
        if (result.error) {
          setLines((current) => [...current, { role: "error", text: result.error }]);
        }
        setBusy(false);
      },
    );
  }

  return (
    <section className="grid gap-4">
      <h1 className="text-xl font-semibold">Chat</h1>
      <div className="min-h-48 rounded-md border border-line bg-card p-3" role="log" aria-live="polite" aria-relevant="additions" aria-busy={busy}>
        {lines.length === 0 ? <p className="text-muted">No messages yet.</p> : null}
        {lines.map((line, index) => (
          <p key={`${line.role}-${index}`} className={line.role === "error" ? "text-danger" : "mb-2 whitespace-pre-wrap"}>
            <span className="font-semibold">{line.role === "you" ? "You" : line.role === "agent" ? "Agent" : "Error"}: </span>
            {line.text}
          </p>
        ))}
        {busy ? <p role="status">Waiting for the agent…</p> : null}
      </div>
      <form className="grid gap-2" onSubmit={send}>
        <label className="grid gap-1" htmlFor="message">
          Message
        </label>
        <textarea
          id="message"
          className="field min-h-24"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
        />
        <button className="btn w-fit" type="submit" disabled={busy}>
          Send
        </button>
      </form>
      <Approvals profile={profile} />
    </section>
  );
}

export function Approvals({ profile }: { profile: string }) {
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ["approvals", profile],
    queryFn: async () => rowsOf(await api("GET", "/v1/approvals"), "approvals"),
    refetchInterval: 1000,
    enabled: profile.length > 0,
  });
  const [error, setError] = useState("");

  async function decide(id: string, decision: string) {
    setError("");
    try {
      await api("POST", `/v1/approvals/${encodeURIComponent(id)}`, { decision, id });
      await client.invalidateQueries({ queryKey: ["approvals"] });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "could not decide");
    }
  }

  const rows = query.data ?? [];
  return (
    <section className="grid gap-3" aria-label="Pending approvals">
      <h2 className="text-lg font-semibold">Approvals</h2>
      {query.isError ? (
        <p className="text-danger" role="alert">
          {query.error instanceof Error ? query.error.message : "could not load approvals"}
        </p>
      ) : null}
      {error ? (
        <p className="text-danger" role="alert">
          {error}
        </p>
      ) : null}
      {rows.length === 0 ? <p className="text-muted">No pending approvals.</p> : null}
      {rows.map((item) => {
        const id = textOf(item.id);
        const tool = textOf(item.tool) || "action";
        return (
          <article key={id} className="grid gap-2 rounded-md border border-line bg-card p-3" aria-label={`Approval for ${tool}`}>
            <h3 className="font-semibold">{tool}</h3>
            <p>{textOf(item.risk)}</p>
            <p>{textOf(item.summary) || textOf(item.reason)}</p>
            <div className="flex flex-wrap gap-2">
              <button className="btn" type="button" onClick={() => void decide(id, "allow_once")}>
                Approve once
              </button>
              <button className="btn-quiet" type="button" onClick={() => void decide(id, "allow_session")}>
                Approve for this session
              </button>
              <button className="btn-danger" type="button" onClick={() => void decide(id, "deny")}>
                Deny
              </button>
            </div>
          </article>
        );
      })}
    </section>
  );
}

export function ListView({
  title,
  path,
  field,
  profile,
}: {
  title: string;
  path: string;
  field: string;
  profile: string;
}) {
  const query = useQuery({
    queryKey: [field, profile],
    queryFn: async () => rowsOf(await api("GET", path), field),
    enabled: profile.length > 0,
  });
  return (
    <section className="grid gap-3">
      <h1 className="text-xl font-semibold">{title}</h1>
      {query.isError ? (
        <p className="text-danger" role="alert">
          {query.error instanceof Error ? query.error.message : "could not load"}
        </p>
      ) : null}
      {query.data && query.data.length === 0 ? <p className="text-muted">Nothing stored for this profile.</p> : null}
      <ul className="grid gap-2">
        {(query.data ?? []).map((item, index) => (
          <li key={textOf(item.id) || textOf(item.name) || String(index)} className="rounded-md border border-line bg-card p-3">
            <p className="font-semibold">{textOf(item.name) || textOf(item.content) || textOf(item.id)}</p>
            <p className="text-sm text-muted">{textOf(item.description) || textOf(item.trigger) || textOf(item.tier)}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function DirectoryView() {
  const query = useQuery({
    queryKey: ["directory"],
    queryFn: () => api("GET", "/v1/admin/directory"),
  });
  const accounts = query.data ? rowsOf(query.data, "accounts") : [];
  const memberships = query.data ? rowsOf(query.data, "memberships") : [];
  return (
    <section className="grid gap-4">
      <h1 className="text-xl font-semibold">Directory</h1>
      <p className="text-muted">Read only. Create accounts with the praxis-prime command.</p>
      {query.isError ? (
        <p className="text-danger" role="alert">
          {query.error instanceof Error ? query.error.message : "could not load the directory"}
        </p>
      ) : null}
      <table className="w-full border-collapse text-left">
        <caption className="sr-only">Accounts</caption>
        <thead>
          <tr>
            <th className="border-b border-line py-2">Username</th>
            <th className="border-b border-line py-2">Role</th>
            <th className="border-b border-line py-2">Status</th>
          </tr>
        </thead>
        <tbody>
          {accounts.map((account) => (
            <tr key={textOf(account.id)}>
              <td className="py-2">{textOf(account.username)}</td>
              <td>{textOf(account.role)}</td>
              <td>{textOf(account.status)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2 className="font-semibold">Memberships</h2>
      <ul>
        {memberships.map((item) => (
          <li key={`${textOf(item.accountId)}-${textOf(item.profileId)}`}>
            {textOf(item.accountId)} · {textOf(item.profileId)} · {textOf(item.role)}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function FactorsView() {
  const client = useQueryClient();
  const factors = useQuery({
    queryKey: ["factors"],
    queryFn: () => api("GET", "/v1/auth/factors"),
  });
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [enrollment, setEnrollment] = useState<Record<string, unknown> | null>(null);
  const totp = factors.data?.totp === true;
  const passkeys = factors.data ? rowsOf(factors.data, "passkeys") : [];

  async function stepUp(password: string, code: string): Promise<string> {
    const body = await api("POST", "/v1/auth/step-up", { password, code });
    const token = textOf(body.stepUpToken);
    if (!token) throw new Error("step-up did not return a token");
    return token;
  }

  async function enroll(password: string, code: string) {
    setError("");
    const token = await stepUp(password, code);
    const body = await api("POST", "/v1/auth/totp/enroll", { stepUpToken: token });
    setEnrollment(body);
    setNotice("Confirm the code from your authenticator. Recovery codes are shown once.");
    await client.invalidateQueries({ queryKey: ["factors"] });
  }

  async function confirm(code: string) {
    setError("");
    await api("POST", "/v1/auth/totp/confirm", { code });
    setEnrollment(null);
    setNotice("Authenticator enrolled.");
    await client.invalidateQueries({ queryKey: ["factors"] });
  }

  async function disable(password: string, code: string) {
    setError("");
    const token = await stepUp(password, code);
    await api("POST", "/v1/auth/totp/disable", { stepUpToken: token });
    setNotice("Authenticator removed.");
    await client.invalidateQueries({ queryKey: ["factors"] });
  }

  async function removePasskey(id: string, password: string, code: string) {
    setError("");
    const token = await stepUp(password, code);
    await api("POST", "/v1/auth/passkey/remove", { credentialId: id, stepUpToken: token });
    setNotice("Passkey removed.");
    await client.invalidateQueries({ queryKey: ["factors"] });
  }

  async function addPasskey(name: string, password: string, code: string) {
    setError("");
    const token = await stepUp(password, code);
    const started = await api("POST", "/v1/auth/passkey/register/options", { stepUpToken: token });
    const credential = await navigator.credentials.create({
      publicKey: creationOptions(started.options),
    });
    if (!credential) throw new Error("passkey was not created");
    await api("POST", "/v1/auth/passkey/register/verify", {
      credential: credentialJson(asPublicKey(credential)),
      name,
    });
    setNotice("Passkey enrolled.");
    await client.invalidateQueries({ queryKey: ["factors"] });
  }

  return (
    <section className="grid gap-4">
      <h1 className="text-xl font-semibold">Security</h1>
      <p className="text-muted">Changing a passkey or authenticator asks for a fresh step-up.</p>
      {factors.isError ? (
        <p className="text-danger" role="alert">
          {factors.error instanceof Error ? factors.error.message : "could not load factors"}
        </p>
      ) : null}
      {error ? (
        <p className="text-danger" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? <p role="status">{notice}</p> : null}
      <h2 className="font-semibold">Authenticator</h2>
      <p>{totp ? "Enrolled." : "Not enrolled."}</p>
      {enrollment ? (
        <div className="grid gap-2 rounded-md border border-line bg-card p-3">
          <p>
            Secret: <span className="font-mono">{textOf(enrollment.secret)}</span>
          </p>
          <p className="break-all text-sm">{textOf(enrollment.otpauthUri)}</p>
          <ul>
            {(Array.isArray(enrollment.recoveryCodes) ? enrollment.recoveryCodes : []).map((code) => (
              <li key={String(code)} className="font-mono">
                {String(code)}
              </li>
            ))}
          </ul>
          <ConfirmForm label="Confirm authenticator" onSubmit={(code) => confirm(code).catch(show(setError))} />
        </div>
      ) : null}
      {totp ? (
        <StepUpForm
          legend="Remove authenticator"
          totp
          submitLabel="Remove authenticator"
          onSubmit={(password, code) => disable(password, code).catch(show(setError))}
        />
      ) : (
        <StepUpForm
          legend="Enroll authenticator"
          totp={false}
          submitLabel="Start enrollment"
          onSubmit={(password, code) => enroll(password, code).catch(show(setError))}
        />
      )}
      <h2 className="font-semibold">Passkeys</h2>
      <ul className="grid gap-2">
        {passkeys.length === 0 ? <li className="text-muted">No passkeys.</li> : null}
        {passkeys.map((item) => {
          const id = textOf(item.id);
          const name = textOf(item.name) || "passkey";
          return (
            <li key={id} className="rounded-md border border-line bg-card p-3">
              <p>{name}</p>
              <StepUpForm
                legend={`Remove ${name}`}
                totp={totp}
                submitLabel={`Remove passkey ${name}`}
                onSubmit={(password, code) => removePasskey(id, password, code).catch(show(setError))}
              />
            </li>
          );
        })}
      </ul>
      <PasskeyForm totp={totp} onSubmit={(name, password, code) => addPasskey(name, password, code).catch(show(setError))} />
    </section>
  );
}

function show(setError: (value: string) => void) {
  return (caught: unknown) => {
    setError(caught instanceof Error ? caught.message : "request failed");
  };
}

function StepUpForm({
  legend,
  totp,
  submitLabel,
  onSubmit,
}: {
  legend: string;
  totp: boolean;
  submitLabel: string;
  onSubmit: (password: string, code: string) => void;
}) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  return (
    <form
      className="grid gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(password, code);
        setPassword("");
        setCode("");
      }}
    >
      <fieldset className="grid gap-2">
        <legend>{legend}</legend>
        <label className="grid gap-1">
          Password
          <input className="field" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required />
        </label>
        {totp ? (
          <label className="grid gap-1">
            Authenticator code
            <input className="field" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value)} required />
          </label>
        ) : null}
        <button className="btn w-fit" type="submit">
          {submitLabel}
        </button>
      </fieldset>
    </form>
  );
}

function ConfirmForm({ label, onSubmit }: { label: string; onSubmit: (code: string) => void }) {
  const [code, setCode] = useState("");
  return (
    <form
      className="grid gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(code);
      }}
    >
      <label className="grid gap-1">
        {label}
        <input className="field" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value)} required />
      </label>
      <button className="btn w-fit" type="submit">
        Confirm code
      </button>
    </form>
  );
}

function PasskeyForm({
  totp,
  onSubmit,
}: {
  totp: boolean;
  onSubmit: (name: string, password: string, code: string) => void;
}) {
  const [name, setName] = useState("this browser");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  return (
    <form
      className="grid gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(name, password, code);
        setPassword("");
        setCode("");
      }}
    >
      <fieldset className="grid gap-2">
        <legend>Add a passkey</legend>
        <label className="grid gap-1">
          Passkey name
          <input className="field" value={name} onChange={(event) => setName(event.target.value)} required />
        </label>
        <label className="grid gap-1">
          Password
          <input className="field" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required />
        </label>
        {totp ? (
          <label className="grid gap-1">
            Authenticator code
            <input className="field" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value)} required />
          </label>
        ) : null}
        <button className="btn w-fit" type="submit">
          Enroll passkey
        </button>
      </fieldset>
    </form>
  );
}
