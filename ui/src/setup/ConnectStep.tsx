import { hostOf, isLoopbackHost, schemeOf } from "./baseUrl";
import type { ProviderInfo } from "./types";

const XAI_BILLING =
  "A SuperGrok or X Premium subscription does not include API credits. API-key usage is billed separately by xAI, even if you also subscribe.";

export function ConnectStep({
  entry,
  baseUrl,
  apiKey,
  auth,
  tls,
  envName,
  keySource,
  network,
  https,
  cloudWarning,
  onBaseUrl,
  onApiKey,
  onAuth,
  onTls,
  onKeySource,
  onCheck,
  onContinue,
  busy,
}: {
  entry: ProviderInfo;
  baseUrl: string;
  apiKey: string;
  auth: string;
  tls: string;
  envName: string;
  keySource: "env" | "paste";
  network: boolean;
  https: boolean;
  cloudWarning: string;
  onBaseUrl: (value: string) => void;
  onApiKey: (value: string) => void;
  onAuth: (value: string) => void;
  onTls: (value: string) => void;
  onKeySource: (value: "env" | "paste") => void;
  onCheck: () => void;
  onContinue: () => void;
  busy: boolean;
}) {
  const host = hostOf(baseUrl);
  const remote = network || (host !== "" && !isLoopbackHost(host));
  const secure = https || schemeOf(baseUrl) === "https";
  const showPin = secure && remote;
  return (
    <section className="grid gap-3">
      <h1 className="text-2xl font-semibold">Connect</h1>
      <p>{entry.description}</p>
      {cloudWarning ? <span className="mt-1 block text-sm">{cloudWarning}</span> : null}
      {entry.id === "xai" ? (
        <div className="grid gap-2">
          <button type="button" className="rounded-md border border-line p-3 text-left" disabled>
            Sign in with Grok (SuperGrok / X Premium subscription)
            <span className="ml-2 text-sm">Coming soon</span>
          </button>
          <button
            type="button"
            className="rounded-md border border-line p-3 text-left"
            aria-pressed={auth === "api_key"}
            onClick={() => onAuth("api_key")}
          >
            API key — Billed to your xAI API account in console.x.ai, pay as you go
          </button>
          <p>{XAI_BILLING}</p>
        </div>
      ) : null}
      {entry.baseUrlEditable ? (
        <label className="grid gap-1">
          Base URL
          <input className="field" value={baseUrl} onChange={(event) => onBaseUrl(event.target.value)} />
        </label>
      ) : null}
      {remote ? <p>This server is on your network</p> : null}
      {showPin ? (
        <label className="grid gap-1">
          TLS fingerprint
          <input className="field" value={tls} onChange={(event) => onTls(event.target.value)} />
        </label>
      ) : null}
      {entry.section === "local" ? (
        <fieldset className="grid gap-2">
          <legend>This server needs a key</legend>
          <KeyField apiKey={apiKey} onApiKey={onApiKey} />
        </fieldset>
      ) : null}
      {entry.section === "cloud" && (entry.id !== "xai" || auth === "api_key") ? (
        <CloudKey
          entry={entry}
          apiKey={apiKey}
          envName={envName}
          keySource={keySource}
          onApiKey={onApiKey}
          onKeySource={onKeySource}
        />
      ) : null}
      {entry.section === "local" || entry.baseUrlEditable ? (
        <button className="btn-quiet w-fit" type="button" disabled={busy} onClick={onCheck}>
          Check connection
        </button>
      ) : null}
      <button className="btn w-fit" type="button" disabled={busy} onClick={onContinue}>
        Continue
      </button>
    </section>
  );
}

function CloudKey({
  entry,
  apiKey,
  envName,
  keySource,
  onApiKey,
  onKeySource,
}: {
  entry: ProviderInfo;
  apiKey: string;
  envName: string;
  keySource: "env" | "paste";
  onApiKey: (value: string) => void;
  onKeySource: (value: "env" | "paste") => void;
}) {
  return (
    <div className="grid gap-2">
      {envName ? (
        <fieldset className="grid gap-2">
          <legend>API key source</legend>
          <label className="flex items-center gap-2">
            <input
              type="radio"
              name="key-source"
              checked={keySource === "env"}
              onChange={() => onKeySource("env")}
            />
            Use the key in {envName}
          </label>
          <label className="flex items-center gap-2">
            <input
              type="radio"
              name="key-source"
              checked={keySource === "paste"}
              onChange={() => onKeySource("paste")}
            />
            Paste a different key
          </label>
        </fieldset>
      ) : null}
      {!envName || keySource === "paste" ? <KeyField apiKey={apiKey} onApiKey={onApiKey} /> : null}
      {entry.keyUrl ? (
        <a href={entry.keyUrl} rel="noreferrer">
          Get an API key
        </a>
      ) : null}
    </div>
  );
}

function KeyField({ apiKey, onApiKey }: { apiKey: string; onApiKey: (value: string) => void }) {
  return (
    <label className="grid gap-1">
      API key
      <input
        className="field"
        type="password"
        autoComplete="off"
        value={apiKey}
        onChange={(event) => onApiKey(event.target.value)}
      />
    </label>
  );
}
