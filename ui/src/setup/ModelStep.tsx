import type { FormEvent } from "react";

export function ModelStep({
  models,
  curated,
  cloudWarning,
  model,
  utility,
  vision,
  judge,
  typed,
  configured,
  replace,
  accountPassword,
  totpCode,
  busy,
  onModel,
  onUtility,
  onVision,
  onJudge,
  onTyped,
  onReplace,
  onAccountPassword,
  onTotpCode,
  onPasskey,
  onSubmit,
}: {
  models: string[];
  curated: boolean;
  cloudWarning: string;
  model: string;
  utility: string;
  vision: string;
  judge: string;
  typed: boolean;
  configured: boolean;
  replace: boolean;
  accountPassword: string;
  totpCode: string;
  busy: boolean;
  onModel: (value: string) => void;
  onUtility: (value: string) => void;
  onVision: (value: string) => void;
  onJudge: (value: string) => void;
  onTyped: (value: boolean) => void;
  onReplace: (value: boolean) => void;
  onAccountPassword: (value: string) => void;
  onTotpCode: (value: string) => void;
  onPasskey: () => void;
  onSubmit: (event: FormEvent) => void;
}) {
  const showList = models.length > 0 && !typed;
  return (
    <form className="grid gap-3" onSubmit={onSubmit}>
      <h1 className="text-2xl font-semibold">Model</h1>
      {cloudWarning ? <span className="mt-1 block text-sm">{cloudWarning}</span> : null}
      {curated ? <p>Suggested models</p> : null}
      {models.length === 0 ? (
        <p>The server did not return a model list. Type a model id.</p>
      ) : null}
      {showList ? (
        <div className="grid gap-2">
          {models.map((id) => (
            <button key={id} type="button" className="btn-quiet w-fit" onClick={() => onModel(id)}>
              {id}
            </button>
          ))}
        </div>
      ) : null}
      <button className="btn-quiet w-fit" type="button" onClick={() => onTyped(true)}>
        Type a model id instead
      </button>
      <label className="grid gap-1">
        Primary model
        <input className="field" value={model} onChange={(event) => onModel(event.target.value)} required />
      </label>
      <details>
        <summary>Advanced (optional)</summary>
        <div className="mt-2 grid gap-2">
          <Role label="Utility" value={utility} empty="Same as primary" onChange={onUtility} />
          <Role label="Vision" value={vision} empty="Same as primary" onChange={onVision} />
          <Role label="Decision Engine judge" value={judge} empty="None (rules only)" onChange={onJudge} />
        </div>
      </details>
      {configured ? (
        <ConfirmChange
          replace={replace}
          accountPassword={accountPassword}
          totpCode={totpCode}
          busy={busy}
          onReplace={onReplace}
          onAccountPassword={onAccountPassword}
          onTotpCode={onTotpCode}
          onPasskey={onPasskey}
        />
      ) : null}
      <button className="btn w-fit" type="submit" disabled={busy}>
        Test and save
      </button>
    </form>
  );
}

function Role({
  label,
  value,
  empty,
  onChange,
}: {
  label: string;
  value: string;
  empty: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="grid gap-1">
      {label}
      <select className="field" value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">{empty}</option>
      </select>
    </label>
  );
}

export function ConfirmChange({
  replace,
  accountPassword,
  totpCode,
  busy,
  onReplace,
  onAccountPassword,
  onTotpCode,
  onPasskey,
}: {
  replace: boolean;
  accountPassword: string;
  totpCode: string;
  busy: boolean;
  onReplace: (value: boolean) => void;
  onAccountPassword: (value: string) => void;
  onTotpCode: (value: string) => void;
  onPasskey: () => void;
}) {
  return (
    <>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={replace} onChange={(event) => onReplace(event.target.checked)} />
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
            onChange={(event) => onAccountPassword(event.target.value)}
          />
        </label>
        <label className="grid gap-1">
          Authenticator code
          <input
            className="field"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={totpCode}
            onChange={(event) => onTotpCode(event.target.value)}
          />
          <span className="text-muted">Leave blank if you do not use one.</span>
        </label>
        <button className="btn-quiet w-fit" type="button" disabled={busy} onClick={onPasskey}>
          Use a passkey
        </button>
      </fieldset>
    </>
  );
}
