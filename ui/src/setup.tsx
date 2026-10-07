import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState, type FormEvent } from "react";

import { api, clearSetupToken, rowsOf, setCsrf, textOf } from "./api";
import { asPublicKey, credentialJson, requestOptions } from "./webauthn";
import { validateBase } from "./setup/baseUrl";
import { ConnectStep } from "./setup/ConnectStep";
import { ConfirmChange, ModelStep } from "./setup/ModelStep";
import { ProviderPicker } from "./setup/ProviderPicker";
import type { Catalog, ProviderInfo } from "./setup/types";

export const CLOUD_WARNING = "Requires a BAA/DPA with the provider; PHI will leave this machine";

type Step =
  | "welcome"
  | "owner"
  | "factors"
  | "provider"
  | "connect"
  | "model"
  | "dials"
  | "extras"
  | "done";

const STEPS: Step[] = [
  "welcome",
  "owner",
  "factors",
  "provider",
  "connect",
  "model",
  "dials",
  "extras",
  "done",
];

export type MissingItem = { id: string; step: string };

const EMPTY_CATALOG: Catalog = {
  providers: [],
  servers: [],
  envKeys: [],
  hardware: [],
  allowProviders: [],
  cloudWarning: "",
};

export function missingItems(body: Record<string, unknown> | undefined): MissingItem[] {
  if (!body) return [];
  return rowsOf(body, "missing")
    .map((item) => ({ id: textOf(item.id), step: textOf(item.step) || "provider" }))
    .filter((item) => item.id);
}

function isStep(value: string): value is Step {
  return (STEPS as string[]).includes(value);
}

function stepFromHash(hash: string, mode: "first" | "admin"): Step | null {
  if (!hash || hash === "#" || hash === "#/") return mode === "first" ? "welcome" : "provider";
  if (hash.startsWith("#/chat") || hash.startsWith("#setup=")) return null;
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  if (parts[0] !== "setup") return null;
  const name = parts[1] || "";
  if (!name) return mode === "first" ? "welcome" : "provider";
  if (name === "test") return "provider";
  if (name === "connect") return "connect";
  if (isStep(name)) return name;
  return null;
}

function providerFromHash(hash: string): string {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  if (parts[1] === "connect") return parts[2] || "";
  return "";
}

function hashFor(step: Step, providerId: string): string {
  if (step === "welcome") return "#/setup";
  if (step === "connect") return `#/setup/connect/${providerId}`;
  return `#/setup/${step}`;
}

function initialStep(mode: "first" | "admin"): Step {
  const parsed = stepFromHash(window.location.hash, mode);
  if (parsed) return parsed;
  return mode === "first" ? "welcome" : "provider";
}

function readCatalog(body: Record<string, unknown>): Catalog {
  const detection = body.detection;
  const policy = body.policy;
  const detect = detection && typeof detection === "object" ? (detection as Record<string, unknown>) : {};
  const rules = policy && typeof policy === "object" ? (policy as Record<string, unknown>) : {};
  return {
    providers: rowsOf(body, "providers").map(readProvider),
    servers: rowsOf(detect, "servers").map((item) => ({
      provider: textOf(item.provider),
      baseUrl: textOf(item.baseUrl),
      models: stringsOf(item.models),
    })),
    envKeys: stringsOf(detect.envKeys),
    hardware: Array.isArray(detect.hardware) ? detect.hardware : [],
    allowProviders: stringsOf(rules.allowProviders),
    cloudWarning: textOf(rules.cloudWarning),
  };
}

function readProvider(item: Record<string, unknown>): ProviderInfo {
  const modelList = item.modelList;
  const models = modelList && typeof modelList === "object" ? (modelList as Record<string, unknown>) : {};
  const defaults = item.defaultModels;
  const primary =
    defaults && typeof defaults === "object" ? textOf((defaults as Record<string, unknown>).primary) : "";
  const port = typeof item.port === "number" ? item.port : null;
  return {
    id: textOf(item.id),
    adapter: textOf(item.adapter),
    displayName: textOf(item.displayName),
    aliases: stringsOf(item.aliases),
    section: textOf(item.section) === "cloud" ? "cloud" : "local",
    description: textOf(item.description),
    authMethods: rowsOf(item, "authMethods").map((method) => ({
      id: textOf(method.id),
      label: textOf(method.label),
      note: textOf(method.note),
      secretName: textOf(method.secretName),
      envNames: stringsOf(method.envNames),
      available: method.available !== false,
    })),
    defaultBaseUrl: textOf(item.defaultBaseUrl),
    baseUrlEditable: item.baseUrlEditable === true,
    port,
    curated: stringsOf(models.curated),
    defaultPrimary: primary,
    keyUrl: textOf(item.keyUrl),
  };
}

function stringsOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function envNameFor(entry: ProviderInfo | undefined, keys: string[]): string {
  if (!entry) return "";
  for (const method of entry.authMethods) {
    if (method.id !== "api_key") continue;
    for (const name of method.envNames) {
      if (keys.includes(name)) return name;
    }
  }
  return "";
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
  const [catalog, setCatalog] = useState<Catalog>(EMPTY_CATALOG);
  const [scan, setScan] = useState(0);
  const [providerId, setProviderId] = useState(() => providerFromHash(window.location.hash));
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [probed, setProbed] = useState<string[] | null>(null);
  const [probeNetwork, setProbeNetwork] = useState(false);
  const [probeHttps, setProbeHttps] = useState(false);
  const [typed, setTyped] = useState(false);
  const [utility, setUtility] = useState("");
  const [vision, setVision] = useState("");
  const [judge, setJudge] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [auth, setAuth] = useState("");
  const [keySource, setKeySource] = useState<"env" | "paste">("paste");
  const [tls, setTls] = useState("");
  const [username, setUsername] = useState("");
  const [ownerName, setOwnerName] = useState("");
  const [password, setPassword] = useState("");
  const [dials, setDials] = useState<Record<string, string>>({});
  const [dialsReady, setDialsReady] = useState(false);
  const [ready, setReady] = useState(false);
  const [savedSpec, setSavedSpec] = useState("");
  const [reviewSaved, setReviewSaved] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [pair, setPair] = useState("");
  const [replace, setReplace] = useState(false);
  const [accountPassword, setAccountPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [passkeyToken, setPasskeyToken] = useState("");
  // Refs let the hash listener see the current provider and catalog without
  // re-binding, so every provider change goes through resetForProvider.
  const providerRef = useRef(providerId);
  const catalogRef = useRef(catalog);
  catalogRef.current = catalog;

  const warning = textOf(status.data?.cloudWarning);
  const missing = missingItems(status.data);
  const configured = textOf(status.data?.provider) !== "";
  const entry = catalog.providers.find((item) => item.id === providerId);
  const showCloud = Boolean(warning || catalog.cloudWarning);
  const knownOwner = ownerName || (mode === "admin" ? "the owner" : "");

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

  useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const body = await api("POST", "/v1/onboarding/providers", {});
        if (live) setCatalog(readCatalog(body));
      } catch (caught) {
        if (live) setError(caught instanceof Error ? caught.message : "setup failed");
      }
    })();
    return () => {
      live = false;
    };
  }, [scan]);

  useEffect(() => {
    function onHash() {
      if (window.location.hash.startsWith("#/chat")) return;
      const next = stepFromHash(window.location.hash, mode);
      if (!next) return;
      const id = providerFromHash(window.location.hash);
      setStep((prev) => {
        if (prev === "connect" && next === "provider") setApiKey("");
        if (prev === "dials" && next === "model" && savedSpec) setReviewSaved(true);
        if (next === "provider" || next === "connect") setReviewSaved(false);
        return next;
      });
      if (id && id !== providerRef.current) resetForProvider(id);
    }
    window.addEventListener("hashchange", onHash);
    window.addEventListener("popstate", onHash);
    return () => {
      window.removeEventListener("hashchange", onHash);
      window.removeEventListener("popstate", onHash);
    };
  }, [mode, savedSpec]);

  useEffect(() => {
    if (step !== "model" || !entry) return;
    if (entry.section === "cloud") {
      setProbed(entry.curated);
      if (entry.defaultPrimary) {
        setModel((current) => current || entry.defaultPrimary);
      }
      return;
    }
    if (probed) return;
    if (!baseUrl.trim()) return;
    let live = true;
    void (async () => {
      try {
        const body = await api("POST", "/v1/onboarding/probe", {
          provider: entry.id,
          baseUrl,
        });
        if (!live) return;
        const names = stringsOf(body.models);
        setProbed(names);
        setProbeNetwork(body.network === true);
        setProbeHttps(body.https === true);
        if (names.length === 1) setModel((current) => current || names[0]);
      } catch {
        if (live) setProbed([]);
      }
    })();
    return () => {
      live = false;
    };
  }, [step, entry, baseUrl, probed]);

  function go(next: Step, id = providerId) {
    setStep((prev) => {
      if (prev === "connect" && next === "provider") setApiKey("");
      if (prev === "dials" && next === "model" && savedSpec) setReviewSaved(true);
      if (next === "provider" || next === "connect") setReviewSaved(false);
      return next;
    });
    const hash = hashFor(next, id);
    if (window.location.hash !== hash) window.location.hash = hash;
  }

  function back() {
    window.history.back();
  }

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
      setOwnerName(username);
      setPassword("");
      go("factors");
    });
  }

  /**
   * Clear everything tied to the previous provider: key, base URL, TLS pin,
   * models, and the probed list. A picker click and a hash or history change
   * both come through here, so one provider's key never reaches another.
   */
  function resetForProvider(id: string) {
    const next = catalogRef.current.providers.find((item) => item.id === id);
    providerRef.current = id;
    setProviderId(id);
    setBaseUrl(next?.defaultBaseUrl ?? "");
    setApiKey("");
    setAuth("");
    setModel("");
    setUtility("");
    setVision("");
    setJudge("");
    setProbed(null);
    setTyped(false);
    setTls("");
    setProbeNetwork(false);
    setProbeHttps(false);
    setKeySource(envNameFor(next, catalogRef.current.envKeys) ? "env" : "paste");
    setReviewSaved(false);
  }

  function chooseProvider(id: string) {
    resetForProvider(id);
    go("connect", id);
  }

  async function checkConnection() {
    if (!entry) return;
    const problem = entry.baseUrlEditable ? validateBase(baseUrl) : "";
    if (problem) {
      setError(problem);
      return;
    }
    await run(async () => {
      const body = await api("POST", "/v1/onboarding/probe", {
        provider: entry.id,
        baseUrl,
        tlsFingerprint: tls,
      });
      const names = stringsOf(body.models);
      setProbed(names);
      setProbeNetwork(body.network === true);
      setProbeHttps(body.https === true);
      if (body.ok === false) {
        setNotice(textOf(body.error) || "The server did not return a model list.");
        return;
      }
      setNotice(names.length ? "Connected." : "Connected. The server returned no models.");
      if (names.length === 1) setModel(names[0]);
    });
  }

  function continueConnect() {
    if (!entry) return;
    if (entry.id === "xai" && auth !== "api_key") {
      setError("Subscription sign-in is coming in a later release.");
      return;
    }
    if (entry.baseUrlEditable) {
      const problem = validateBase(baseUrl);
      if (problem) {
        setError(problem);
        return;
      }
    }
    setError("");
    go("model");
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

  async function skipProvider() {
    await run(async () => {
      const extra = await confirmChange();
      const body = await api("POST", "/v1/onboarding/save", { lane: "skip", ...extra });
      setReady(body.inferenceReady === true);
      setSavedSpec("");
      if (body.restartRequired === true) {
        setNotice("Restart the daemon before this change can take effect.");
      }
      go("dials");
    });
  }

  async function saveProvider(event: FormEvent) {
    event.preventDefault();
    if (!entry) return;
    await run(async () => {
      const extra = await confirmChange();
      const authMethod = entry.section === "cloud" ? "api_key" : "none";
      const body = await api("POST", "/v1/onboarding/save", {
        provider: entry.id,
        model,
        baseUrl,
        apiKey: keySource === "env" ? "" : apiKey,
        authMethod,
        tlsFingerprint: tls,
        ...(utility ? { utilityModel: utility } : {}),
        ...(vision ? { visionModel: vision } : {}),
        ...(judge ? { judgeModel: judge } : {}),
        ...extra,
      });
      setApiKey("");
      setAccountPassword("");
      setTotpCode("");
      setReady(body.inferenceReady === true);
      setSavedSpec(textOf(body.spec) || `${entry.adapter}:${model}`);
      const warnings = body.warnings;
      if (body.restartRequired === true) {
        setNotice("Restart the daemon before chat uses this provider.");
      } else if (Array.isArray(warnings) && warnings.length) {
        setNotice(warnings.map((item) => String(item)).join(" "));
      }
      go("dials");
    });
  }

  async function saveDials() {
    await run(async () => {
      await api("POST", "/v1/onboarding/dials", { positions: dials });
      go("extras");
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

  const models = probed ?? (entry?.section === "cloud" ? entry.curated : []);
  const root = mode === "first" ? "welcome" : "provider";

  return (
    <div className="mx-auto max-w-xl px-4 py-10">
      <button
        className="btn-quiet mb-4"
        type="button"
        onClick={back}
        disabled={step === root && (step !== "welcome" || !knownOwner)}
      >
        ← Back
      </button>

      {step === "welcome" && knownOwner ? (
        <section className="grid gap-4">
          <h1 className="text-2xl font-semibold">Welcome</h1>
          <p>Owner created: {knownOwner}</p>
          <button className="btn w-fit" type="button" onClick={() => go("factors")}>
            Continue
          </button>
        </section>
      ) : null}

      {step === "welcome" && !knownOwner ? (
        <section className="grid gap-4">
          <h1 className="text-2xl font-semibold">Welcome</h1>
          <p>
            The daemon listens on 127.0.0.1 only. A cloud provider sends prompts off this machine.
            A model on this computer keeps them here. Nothing is selected until you choose it.
          </p>
          {missing.length ? <p>Missing: {missing.map((item) => item.id).join(", ")}.</p> : null}
          <button className="btn w-fit" type="button" onClick={() => go("owner")}>
            Continue
          </button>
        </section>
      ) : null}

      {step === "owner" ? (
        knownOwner ? (
          <section className="grid gap-3">
            <h1 className="text-2xl font-semibold">Create the owner</h1>
            <p>Owner created: {knownOwner}</p>
            <button className="btn w-fit" type="button" onClick={() => go("factors")}>
              Continue
            </button>
          </section>
        ) : (
          <form className="grid gap-3" onSubmit={(event) => void createOwner(event)}>
            <h1 className="text-2xl font-semibold">Create the owner</h1>
            <p className="text-muted">This account administers the daemon. The password stays on this machine.</p>
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
                autoComplete="new-password"
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </label>
            <button className="btn w-fit" type="submit" disabled={busy}>
              Create owner
            </button>
          </form>
        )
      ) : null}

      {step === "factors" ? (
        <section className="grid gap-3">
          <h1 className="text-2xl font-semibold">Second factor</h1>
          <p>Add a passkey or an authenticator from Security after setup. You can skip that for now.</p>
          <button className="btn w-fit" type="button" onClick={() => go("provider")}>
            Skip enrollment
          </button>
        </section>
      ) : null}

      {step === "provider" ? (
        <div className="grid gap-3">
          <ProviderPicker
            catalog={catalog}
            cloudWarning={showCloud ? CLOUD_WARNING : ""}
            busy={busy}
            onChoose={chooseProvider}
            onSkip={() => void skipProvider()}
            onScan={() => setScan((count) => count + 1)}
          />
          {configured ? (
            <ConfirmChange
              replace={replace}
              accountPassword={accountPassword}
              totpCode={totpCode}
              busy={busy}
              onReplace={setReplace}
              onAccountPassword={setAccountPassword}
              onTotpCode={setTotpCode}
              onPasskey={() => void usePasskey()}
            />
          ) : null}
        </div>
      ) : null}

      {step === "connect" && entry ? (
        <ConnectStep
          entry={entry}
          baseUrl={baseUrl}
          apiKey={apiKey}
          auth={auth}
          tls={tls}
          envName={envNameFor(entry, catalog.envKeys)}
          keySource={keySource}
          network={probeNetwork}
          https={probeHttps}
          onBaseUrl={setBaseUrl}
          onApiKey={setApiKey}
          onAuth={setAuth}
          onTls={setTls}
          onKeySource={setKeySource}
          onCheck={() => void checkConnection()}
          onContinue={continueConnect}
          busy={busy}
        />
      ) : null}

      {step === "model" && reviewSaved && savedSpec ? (
        <section className="grid gap-3">
          <h1 className="text-2xl font-semibold">Model</h1>
          <p>Provider saved: {savedSpec}</p>
          <button className="btn-quiet w-fit" type="button" onClick={() => go("provider")}>
            Change
          </button>
        </section>
      ) : null}

      {step === "model" && !(reviewSaved && savedSpec) ? (
        <ModelStep
          models={models}
          curated={entry?.section === "cloud" && (entry?.curated.length ?? 0) > 0}
          model={model}
          utility={utility}
          vision={vision}
          judge={judge}
          typed={typed}
          configured={configured}
          replace={replace}
          accountPassword={accountPassword}
          totpCode={totpCode}
          busy={busy}
          onModel={setModel}
          onUtility={setUtility}
          onVision={setVision}
          onJudge={setJudge}
          onTyped={setTyped}
          onReplace={setReplace}
          onAccountPassword={setAccountPassword}
          onTotpCode={setTotpCode}
          onPasskey={() => void usePasskey()}
          onSubmit={(event) => void saveProvider(event)}
        />
      ) : null}

      {step === "dials" ? (
        <section className="pp-dial grid gap-3">
          <h1 className="text-2xl font-semibold">Compliance dials</h1>
          <p role="status">{ready ? "Inference ready" : "Inference not configured"}</p>
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
          <button className="btn-quiet w-fit" type="button" onClick={() => go("extras")}>
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
          <button className="btn w-fit" type="button" onClick={() => go("done")}>
            Continue
          </button>
        </section>
      ) : null}

      {step === "done" ? (
        <section className="grid gap-3">
          <h1 className="text-2xl font-semibold">Done</h1>
          <p role="status">{ready ? "Inference ready" : "Inference not configured"}</p>
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
