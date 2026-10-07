import { useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";

import { NO_GPU_NOTE, NO_MATCH, type Catalog, type ProviderInfo } from "./types";

export function ProviderPicker({
  catalog,
  cloudWarning,
  busy,
  onChoose,
  onSkip,
  onScan,
}: {
  catalog: Catalog;
  cloudWarning: string;
  busy: boolean;
  onChoose: (id: string) => void;
  onSkip: () => void;
  onScan: () => void;
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(-1);
  const searchRef = useRef<HTMLInputElement>(null);
  const visible = catalog.providers.filter((entry) => matches(entry, query));
  const local = visible.filter((entry) => entry.section === "local");
  const cloud = visible.filter((entry) => entry.section === "cloud");

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target;
      const typing = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement;
      if (event.key === "/" && !typing) {
        event.preventDefault();
        searchRef.current?.focus();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  function onListKey(event: ReactKeyboardEvent) {
    if (event.key === "Escape") {
      setQuery("");
      return;
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      setActive((index) => {
        if (!visible.length) return -1;
        const next = event.key === "ArrowDown" ? index + 1 : index - 1;
        return Math.max(0, Math.min(visible.length - 1, next));
      });
    }
    if (event.key === "Enter" && active >= 0) {
      const entry = visible[active];
      if (entry && !blocked(entry, catalog.allowProviders)) onChoose(entry.id);
    }
  }

  return (
    <section className="grid gap-3">
      <h1 className="text-2xl font-semibold">Choose where Praxis thinks</h1>
      <label className="grid gap-1">
        Search
        <input
          ref={searchRef}
          className="field"
          aria-label="Search providers"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setActive(-1);
          }}
          onKeyDown={(event) => {
            if (event.key === "Escape") setQuery("");
          }}
        />
      </label>
      <button className="btn-quiet w-fit" type="button" disabled={busy} onClick={onScan}>
        Scan again
      </button>
      {visible.length === 0 ? <p>{NO_MATCH}</p> : null}
      <div
        role="listbox"
        aria-label="Providers"
        tabIndex={0}
        className="grid gap-4"
        onKeyDown={onListKey}
      >
        {local.length ? (
          <section role="group" aria-label="Local">
            <h2 className="text-lg font-semibold">Local</h2>
            {catalog.hardware.length === 0 ? <p>{NO_GPU_NOTE}</p> : null}
            <div className="mt-2 grid gap-2">
              {local.map((entry) => (
                <ProviderRow
                  key={entry.id}
                  entry={entry}
                  catalog={catalog}
                  cloudWarning=""
                  active={visible[active]?.id === entry.id}
                  onChoose={onChoose}
                />
              ))}
            </div>
          </section>
        ) : null}
        {cloud.length ? (
          <section role="group" aria-label="Cloud">
            <h2 className="text-lg font-semibold">Cloud</h2>
            <div className="mt-2 grid gap-2">
              {cloud.map((entry) => (
                <ProviderRow
                  key={entry.id}
                  entry={entry}
                  catalog={catalog}
                  cloudWarning={cloudWarning}
                  active={visible[active]?.id === entry.id}
                  onChoose={onChoose}
                />
              ))}
            </div>
          </section>
        ) : null}
      </div>
      <button className="btn-quiet w-fit" type="button" disabled={busy} onClick={onSkip}>
        Skip for now
      </button>
    </section>
  );
}

function ProviderRow({
  entry,
  catalog,
  cloudWarning,
  active,
  onChoose,
}: {
  entry: ProviderInfo;
  catalog: Catalog;
  cloudWarning: string;
  active: boolean;
  onChoose: (id: string) => void;
}) {
  const denied = blocked(entry, catalog.allowProviders);
  const server = catalog.servers.find((item) => item.provider === entry.id);
  const badge = envBadge(entry, catalog.envKeys);
  return (
    <button
      type="button"
      role="option"
      id={`provider-${entry.id}`}
      aria-label={entry.displayName}
      aria-selected={false}
      aria-disabled={denied}
      disabled={denied}
      className={`rounded-md border border-line bg-card p-3 text-left ${active ? "ring-2 ring-focus" : ""}`}
      onClick={() => onChoose(entry.id)}
    >
      <span className="font-medium">{entry.displayName}</span>
      <span className="mt-1 block text-sm text-muted">{entry.description}</span>
      {server ? (
        <span className="mt-1 flex items-center gap-2 text-sm">
          <span className="inline-block h-2 w-2 rounded-full bg-ok" aria-hidden="true" />
          Running here · {server.models.length} models
        </span>
      ) : null}
      {!server && entry.port ? (
        <span className="mt-1 block text-sm text-muted">Not detected (port {entry.port})</span>
      ) : null}
      {badge ? <span className="mt-1 block text-sm">key found in {badge}</span> : null}
      {denied ? (
        <span className="mt-1 block text-sm">Blocked by the admin provider allowlist</span>
      ) : null}
      {cloudWarning ? <span className="mt-1 block text-sm">{cloudWarning}</span> : null}
    </button>
  );
}

function matches(entry: ProviderInfo, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  const haystack = [entry.id, entry.displayName, ...entry.aliases].join(" ").toLowerCase();
  return haystack.includes(needle);
}

function blocked(entry: ProviderInfo, allow: string[]): boolean {
  if (!allow.length) return false;
  return !allow.includes(entry.id) && !allow.includes(entry.adapter);
}

function envBadge(entry: ProviderInfo, present: string[]): string {
  for (const method of entry.authMethods) {
    if (method.id !== "api_key") continue;
    for (const name of method.envNames) {
      if (present.includes(name)) return name;
    }
  }
  return "";
}
