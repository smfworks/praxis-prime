import { useQuery } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";

import { api, clearSetupToken, rowsOf, setCsrf, textOf } from "./api";
import { asPublicKey, credentialJson, requestOptions } from "./webauthn";

const CLOUD_WARNING = "Requires a BAA/DPA with the provider; PHI will leave this machine";

type Step = "welcome" | "owner" | "factors" | "lane" | "models" | "dials" | "extras" | "done";

export type MissingItem = { id: string; step: string };

const LANES = [
  ["local", "On this computer"],
  ["lan", "On my network"],
  ["cloud", "Cloud provider"],
  ["skip", "Skip for now"],
] as const;

export function missingItems(body: Record<string, unknown> | undefined): MissingItem[] {
  if (!body) return [];
  return rowsOf(body, "missing")
    .map((item) => ({ id: textOf(item.id), step: textOf(item.step) || "provider" }))
    .filter((item) => item.id);
}

function initialStep(mode: "first" | "admin"): Step {
  if (mode === "first") return "welcome";
  const part = window.location.hash.replace(/^#\/?/, "").split("/")[1] || "";
  if (part === "owner") return "owner";
  if (part === "dials") return "dials";
  if (part === "test" || part === "provider") return "lane";
  return "lane";
}

export function SetupWizard({
  mode,
  onFinished,
}: {
  mode: "first" | "admin";
  onFinished: () => void;
}) {
  const status = useQuery({
    queryKey: ["setup-detail", mode],
    queryFn: () => api("GET", "/v1/onboarding/status"),
  });
  const [step, setStep] = useState<Step>(() => initialStep(mode));
  const [lane, setLane] = useState("");
  const [provider, setProvider] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [utility, setUtility] = useState("");
  const [vision, setVision] = useState("");
  const [judge, setJudge] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [dials, setDials] = useState<Record<string, string>>({});
  const [dialsReady, setDialsReady] = useState(false);
  const [servers, setServers] = useState<string[]>([]);
  const [looked, setLooked] = useState(false);
  const [ready, setReady] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [pair, setPair] = useState("");
  const [replace, setReplace] = useState(false);
  const [accountPassword, setAccountPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [passkeyToken, setPasskeyToken] = useState("");

  const warning = textOf(status.data?.cloudWarning);
  const missing = missingItems(status.data);
  const configured = textOf(status.data?.provider) !== "";

  useEffect(() => {
    if (dialsReady || !status.data) return;
    const raw = status.data.dials;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return;
    const next: Record<string, string> = {};
    for (const [key, value] of Object.entries(raw)) {
      if (value === "off" || value === "monitor" || value === "enforce") next[key] = value;
    }
    setDials(next);
    setDialsReady(true);
  }, [status.data, dialsReady]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "setup failed");
    } finally {
      setBusy(false);
    }
  }

  async function createOwner(event: FormEvent) {
    event.preventDefault();
    await run(async () => {
      const body = await api("POST", "/v1/onboarding/owner", {
        username,
        password,
        displayName: username,
      });
      clearSetupToken();
      setCsrf(textOf(body.csrfToken));
      if (body.restartRequired === true) {
        setNotice("Restart the daemon before the new profile can chat.");
      }
      setPassword("");
      setStep("factors");
    });
  }

  async function look() {
    await run(async () => {
      const body = await api("POST", "/v1/onboarding/detect", {});
      const rows = rowsOf(body, "servers");
      setServers(
        rows.map((item) => {
          const id = textOf(item.provider);
          const base = textOf(item.baseUrl);
          return base ? `${id} at ${base}` : id;
        }),
      );
      setLooked(true);
    });
  }

  async function confirmChange(): Promise<Record<string, unknown>> {
    if (!configured) return {};
    if (!replace) throw new Error("Confirm replacement before saving a new provider.");
    if (passkeyToken) return { replace: true, stepUpToken: passkeyToken };
    const body = await api("POST", "/v1/auth/step-up", {
      password: accountPassword,
      code: totpCode,
    });
    const token = textOf(body.stepUpToken);
    if (!token) throw new Error("step-up did not return a token");
    return { replace: true, stepUpToken: token };
  }

  async function usePasskey() {
    await run(async () => {
      const started = await api("POST", "/v1/auth/step-up/passkey/options", {});
      const credential = await navigator.credentials.get({
        publicKey: requestOptions(started.options),
      });
      if (!credential) throw new Error("passkey was not used");
      const body = await api("POST", "/v1/auth/step-up/passkey/verify", {
        credential: credentialJson(asPublicKey(credential)),
      });
      const token = textOf(body.stepUpToken);
      if (!token) throw new Error("step-up did not return a token");
      setPasskeyToken(token);
      setNotice("Passkey confirmed.");
    });
  }

  async function saveProvider(event: FormEvent) {
    event.preventDefault();
    await run(async () => {
      const extra = await confirmChange();
      if (lane === "skip") {
        const body = await api("POST", "/v1/onboarding/save", { lane: "skip", ...extra });
        setReady(body.inferenceReady === true);
        if (body.restartRequired === true) {
          setNotice("Restart the daemon before this change can take effect.");
        }
        setStep("done");
        return;
      }
      const body = await api("POST", "/v1/onboarding/save", {
        lane,
        provider,
        model,
        baseUrl,
        apiKey,
        utilityModel: utility,
        visionModel: vision,
        judgeModel: judge,
        ...extra,
      });
      setApiKey("");
      setAccountPassword("");
      setTotpCode("");
      setReady(body.inferenceReady === true);
      const warnings = body.warnings;
      if (body.restartRequired === true) {
        setNotice("Restart the daemon before chat uses this provider.");
      } else if (Array.isArray(warnings) && warnings.length) {
        setNotice(warnings.map((item) => String(item)).join(" "));
      }
      setStep("dials");
    });
  }

  async function saveDials() {
    await run(async () => {
      await api("POST", "/v1/onboarding/dials", { positions: dials });
      setStep("extras");
    });
  }

  async function addOidc(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await run(async () => {
      await api("POST", "/v1/onboarding/oidc", {
        providerId: String(form.get("providerId") || ""),
        displayName: String(form.get("displayName") || ""),
        issuer: String(form.get("issuer") || ""),
        clientId: String(form.get("clientId") || ""),
        clientSecret: String(form.get("clientSecret") || ""),
        preset: String(form.get("preset") || ""),
      });
      setNotice("OIDC provider added. The secret was stored and is not shown again.");
    });
  }

  async function pairTelegram() {
    await run(async () => {
      const body = await api("POST", "/v1/onboarding/telegram", {});
      setPair(textOf(body.command));
    });
  }

  return (
    <div className="mx-auto max-w-xl px-4 py-10">
      {step === "welcome" ? (
        <section className="grid gap-4">
          <h1 className="text-2xl font-semibold">Welcome</h1>
          <p>
            The daemon listens on 127.0.0.1 only. A cloud provider sends prompts off this machine.
            A model on this computer keeps them here. Nothing is selected until you choose it.
          </p>
          {missing.length ? (
            <p>
              Missing: {missing.map((item) => item.id).join(", ")}.
            </p>
          ) : null}
          <button className="btn w-fit" type="button" onClick={() => setStep("owner")}>
            Continue
          </button>
        </section>
      ) : null}

      {step === "owner" ? (
        <form className="grid gap-3" onSubmit={(event) => void createOwner(event)}>
          <h1 className="text-2xl font-semibold">Create the owner</h1>
          <p className="text-muted">This account administers the daemon. The password stays on this machine.</p>
          <label className="grid gap-1">
            Username
            <input className="field" value={username} autoComplete="username" onChange={(event) => setUsername(event.target.value)} required />
          </label>
          <label className="grid gap-1">
            Password
            <input className="field" type="password" value={password} autoComplete="new-password" onChange={(event) => setPassword(event.target.value)} required />
          </label>
          <button className="btn w-fit" type="submit" disabled={busy}>
            Create owner
          </button>
        </form>
      ) : null}

      {step === "factors" ? (
        <section className="grid gap-3">
          <h1 className="text-2xl font-semibold">Second factor</h1>
          <p>Add a passkey or an authenticator from Security after setup. You can skip that for now.</p>
          <button className="btn w-fit" type="button" onClick={() => setStep("lane")}>
            Skip enrollment
          </button>
        </section>
      ) : null}

      {step === "lane" ? (
        <section className="grid gap-3">
          <h1 className="text-2xl font-semibold">Choose a provider</h1>
          <p>Nothing is preselected. Detection only offers servers it found.</p>
          <button className="btn-quiet w-fit" type="button" disabled={busy} onClick={() => void look()}>
            Look for local servers
          </button>
          {looked && servers.length === 0 ? (
            <pre className="rounded-md border border-line bg-card p-3 text-sm">{`ollama serve\nllama-server --port 8080\nvllm serve`}</pre>
          ) : null}
          {servers.length ? (
            <ul className="list-disc pl-5">
              {servers.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          ) : null}
          <fieldset className="grid gap-2">
            <legend className="sr-only">Provider lane</legend>
            {LANES.map(([id, label]) => (
              <label key={id} className="flex items-center gap-2">
                <input type="radio" name="lane" value={id} checked={lane === id} onChange={() => setLane(id)} />
                {label}
              </label>
            ))}
          </fieldset>
          {lane === "cloud" && warning ? <p role="status">{warning}</p> : null}
          <button className="btn w-fit" type="button" disabled={!lane} onClick={() => setStep("models")}>
            Continue
          </button>
        </section>
      ) : null}

      {step === "models" ? (
        <form className="grid gap-3" onSubmit={(event) => void saveProvider(event)}>
          <h1 className="text-2xl font-semibold">Models</h1>
          {lane === "cloud" && warning ? <p role="status">{CLOUD_WARNING}</p> : null}
          {lane === "skip" ? <p>Chat stays up and shows a persistent inference banner.</p> : null}
          {lane !== "skip" ? (
            <>
              <label className="grid gap-1">
                Provider id
                <input className="field" value={provider} onChange={(event) => setProvider(event.target.value)} placeholder="for example ollama or llamacpp" required />
              </label>
              <label className="grid gap-1">
                Base URL
                <input className="field" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="127.0.0.1:8080" />
              </label>
              <label className="grid gap-1">
                Primary model
                <input className="field" value={model} onChange={(event) => setModel(event.target.value)} required />
              </label>
              <label className="grid gap-1">
                Utility model
                <input className="field" value={utility} onChange={(event) => setUtility(event.target.value)} />
              </label>
              <label className="grid gap-1">
                Vision model
                <input className="field" value={vision} onChange={(event) => setVision(event.target.value)} />
              </label>
              <label className="grid gap-1">
                Decision Engine judge
                <input className="field" value={judge} onChange={(event) => setJudge(event.target.value)} />
              </label>
              <label className="grid gap-1">
                API key
                <input className="field" type="password" value={apiKey} autoComplete="off" onChange={(event) => setApiKey(event.target.value)} />
              </label>
            </>
          ) : null}
          {configured ? (
            <>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={replace}
                  onChange={(event) => setReplace(event.target.checked)}
                />
                Replace the current provider
              </label>
              <fieldset className="grid gap-2">
                <legend>Confirm this change</legend>
                <label className="grid gap-1">
                  Account password
                  <input
                    className="field"
                    type="password"
                    autoComplete="current-password"
                    value={accountPassword}
                    onChange={(event) => setAccountPassword(event.target.value)}
                  />
                </label>
                <label className="grid gap-1">
                  Authenticator code
                  <input
                    className="field"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    value={totpCode}
                    onChange={(event) => setTotpCode(event.target.value)}
                  />
                  <span className="text-muted">Leave blank if you do not use one.</span>
                </label>
                <button className="btn-quiet w-fit" type="button" disabled={busy} onClick={() => void usePasskey()}>
                  Use a passkey
                </button>
              </fieldset>
            </>
          ) : null}
          <button className="btn w-fit" type="submit" disabled={busy}>
            Test and save
          </button>
        </form>
      ) : null}

      {step === "dials" ? (
        <section className="pp-dial grid gap-3">
          <h1 className="text-2xl font-semibold">Compliance dials</h1>
          {ready ? <p role="status">Inference ready</p> : null}
          <p>Every dial stays off unless you change it. Existing positions are kept.</p>
          {Object.entries(dials).map(([id, position]) => (
            <label key={id} className="pp-dial-row flex items-center justify-between gap-3">
              {id}
              <select
                className="pp-dial-control field w-auto"
                value={position}
                onChange={(event) => setDials({ ...dials, [id]: event.target.value })}
              >
                <option value="off">off</option>
                <option value="monitor">monitor</option>
                <option value="enforce">enforce</option>
              </select>
            </label>
          ))}
          <button className="btn w-fit" type="button" disabled={busy} onClick={() => void saveDials()}>
            Save dials
          </button>
          <button className="btn-quiet w-fit" type="button" onClick={() => setStep("extras")}>
            Continue
          </button>
        </section>
      ) : null}

      {step === "extras" ? (
        <section className="grid gap-4">
          <h1 className="text-2xl font-semibold">Optional extras</h1>
          <form className="grid gap-3" onSubmit={(event) => void addOidc(event)}>
            <h2 className="text-lg font-semibold">OIDC provider</h2>
            <label className="grid gap-1">
              Provider id
              <input className="field" name="providerId" />
            </label>
            <label className="grid gap-1">
              Display name
              <input className="field" name="displayName" />
            </label>
            <label className="grid gap-1">
              Issuer
              <input className="field" name="issuer" autoComplete="off" />
            </label>
            <label className="grid gap-1">
              Client id
              <input className="field" name="clientId" />
            </label>
            <label className="grid gap-1">
              Client secret
              <input className="field" name="clientSecret" type="password" autoComplete="off" />
            </label>
            <label className="grid gap-1">
              Preset
              <input className="field" name="preset" placeholder="google, entra, authentik, or keycloak" />
            </label>
            <button className="btn-quiet w-fit" type="submit" disabled={busy}>
              Add OIDC provider
            </button>
          </form>
          <div className="grid gap-2">
            <h2 className="text-lg font-semibold">Telegram approvals</h2>
            <button className="btn-quiet w-fit" type="button" disabled={busy} onClick={() => void pairTelegram()}>
              Issue a pairing code
            </button>
            {pair ? <p role="status">{pair}</p> : null}
          </div>
          <button className="btn w-fit" type="button" onClick={() => setStep("done")}>
            Continue
          </button>
        </section>
      ) : null}

      {step === "done" ? (
        <section className="grid gap-3">
          <h1 className="text-2xl font-semibold">Done</h1>
          <p role="status">{ready ? "Inference ready" : "Inference is not configured"}</p>
          <a
            href="#/chat"
            onClick={(event) => {
              event.preventDefault();
              onFinished();
            }}
          >
            Continue to the app
          </a>
        </section>
      ) : null}

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
    </div>
  );
}

export function SetupNeeded({ items }: { items: MissingItem[] }) {
  return (
    <section className="mb-6 rounded-md border border-line bg-card p-4">
      <h1 className="text-xl font-semibold">Setup needed</h1>
      <ul className="mt-2 list-disc pl-5">
        {items.map((item) => (
          <li key={item.id}>
            <a href={`#/setup/${item.step}`}>{item.id}</a>
          </li>
        ))}
      </ul>
      <a className="mt-3 inline-block" href="#/chat">
        Continue to the app
      </a>
    </section>
  );
}
