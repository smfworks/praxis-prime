import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { ApiError, api, apiUpload, rowsOf, textOf } from "./api";

type ThemeRow = {
  id: string;
  name: string;
  description: string;
  contrast: string;
  builtin: boolean;
};

const MODES = [
  ["system", "System"],
  ["light", "Light"],
  ["dark", "Dark"],
] as const;

export function Appearance({ admin, profile }: { admin: boolean; profile: string }) {
  const client = useQueryClient();
  const catalog = useQuery({
    queryKey: ["themes", profile],
    queryFn: () => api("GET", "/v1/themes"),
  });
  const [themeId, setThemeId] = useState("");
  const [mode, setMode] = useState("system");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [preview, setPreview] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);

  const body = catalog.data;
  const themes: ThemeRow[] = rowsOf(body ?? {}, "themes").map((item) => ({
    id: textOf(item.id),
    name: textOf(item.name) || textOf(item.id),
    description: textOf(item.description),
    contrast: textOf(item.contrast),
    builtin: item.builtin === true,
  }));
  const active = (body?.active ?? {}) as Record<string, unknown>;
  const lock = (body?.lock ?? {}) as Record<string, unknown>;
  const locked = active.locked === true;
  const currentId = textOf(active.id) || "smf.praxis";
  const currentMode = textOf(active.mode) || "system";
  const shownId = themeId || currentId;
  const shownMode = mode || currentMode;
  const chosen = themes.find((item) => item.id === shownId);
  const canChange = Boolean(profile) && (admin || !locked);

  async function refresh() {
    await client.invalidateQueries({ queryKey: ["themes"] });
    await client.invalidateQueries({ queryKey: ["theme-active"] });
  }

  async function save(nextId: string, nextMode: string) {
    setError("");
    setNotice("");
    if (!profile) {
      setError("Choose a profile before setting a theme.");
      return;
    }
    setBusy(true);
    try {
      await api("POST", "/v1/themes/select", { id: nextId, mode: nextMode, profile });
      setThemeId(nextId);
      setMode(nextMode);
      setNotice("Theme updated.");
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "could not set the theme");
    } finally {
      setBusy(false);
    }
  }

  async function onPreview(file: File) {
    setError("");
    setNotice("");
    setPreview(null);
    setBusy(true);
    try {
      const report = await apiUpload("/v1/themes/preview", file, "application/zip");
      setPreview(report);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "that package was rejected");
    } finally {
      setBusy(false);
    }
  }

  async function onInstall(event: FormEvent) {
    event.preventDefault();
    const digest = textOf(preview?.packageHash);
    if (!digest) return;
    setBusy(true);
    setError("");
    try {
      await api("POST", "/v1/themes/install", { packageHash: digest });
      setNotice(`Installed ${textOf(preview?.name) || "theme"}.`);
      setPreview(null);
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "could not install");
    } finally {
      setBusy(false);
    }
  }

  async function onRemove() {
    if (!chosen || chosen.builtin) return;
    setBusy(true);
    setError("");
    try {
      await api("POST", "/v1/themes/remove", { id: chosen.id });
      setNotice(`Removed ${chosen.name}.`);
      setThemeId("");
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "could not remove");
    } finally {
      setBusy(false);
    }
  }

  async function onLock(next: boolean) {
    setBusy(true);
    setError("");
    try {
      await api("POST", "/v1/themes/lock", next ? { id: shownId, mode: shownMode } : { id: "", mode: "" });
      setNotice(next ? "Theme locked for every profile." : "Theme unlocked.");
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "could not change the lock");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="grid max-w-xl gap-4" aria-labelledby="appearance-heading">
      <h1 id="appearance-heading" className="text-lg font-semibold">
        Appearance
      </h1>
      <p className="text-sm text-muted">
        Themes change colours, type, and ornaments. They do not add controls or load anything off this machine.
      </p>
      {locked ? (
        <p role="status">An admin locked the theme{textOf(lock.id) ? `: ${textOf(lock.id)}` : ""}.</p>
      ) : null}
      {catalog.isError ? (
        <p className="text-danger" role="alert">
          {catalog.error instanceof Error ? catalog.error.message : "could not load themes"}
        </p>
      ) : null}
      {error ? (
        <p className="text-danger" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? <p role="status">{notice}</p> : null}
      <div className="grid gap-1 text-sm">
        <label htmlFor="pp-theme-choice">Theme</label>
        <select
          id="pp-theme-choice"
          value={shownId}
          disabled={!canChange || busy}
          onChange={(event) => {
            const next = event.target.value;
            setThemeId(next);
            void save(next, shownMode || currentMode);
          }}
        >
          {themes.map((item) => (
            <option key={item.id} value={item.id}>
              {item.name} ({item.contrast}
              {item.builtin ? ", built-in" : ""})
            </option>
          ))}
        </select>
      </div>
      {chosen?.description ? <p className="text-sm text-muted">{chosen.description}</p> : null}
      <div className="grid gap-1 text-sm">
        <label htmlFor="pp-theme-mode">Mode</label>
        <select
          id="pp-theme-mode"
          value={shownMode || currentMode}
          disabled={!canChange || busy}
          onChange={(event) => {
            const next = event.target.value;
            setMode(next);
            void save(shownId, next);
          }}
        >
          {MODES.map(([id, label]) => (
            <option key={id} value={id}>
              {label}
            </option>
          ))}
        </select>
      </div>
      {admin ? (
        <div className="grid gap-3 border-t border-line pt-4">
          <h2 className="font-semibold">Install theme…</h2>
          <div className="grid gap-1 text-sm">
            <label htmlFor="pp-theme-file">Theme package (.zip)</label>
            <input
              id="pp-theme-file"
              type="file"
              accept=".zip,application/zip"
              disabled={busy}
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) void onPreview(file);
              }}
            />
          </div>
          {preview ? (
            <form className="grid gap-2" onSubmit={(event) => void onInstall(event)}>
              <p>
                {textOf(preview.name)} {textOf(preview.version)} · contrast {textOf(preview.contrast)}
              </p>
              <p className="break-all text-sm text-muted">Package hash {textOf(preview.packageHash)}</p>
              <button className="btn w-fit" type="submit" disabled={busy}>
                Install
              </button>
            </form>
          ) : null}
          <div className="flex flex-wrap gap-2">
            {chosen && !chosen.builtin ? (
              <button className="btn-quiet" type="button" disabled={busy} onClick={() => void onRemove()}>
                Remove {chosen.name}
              </button>
            ) : null}
            {locked ? (
              <button className="btn-quiet" type="button" disabled={busy} onClick={() => void onLock(false)}>
                Unlock theme
              </button>
            ) : (
              <button className="btn-quiet" type="button" disabled={busy || !shownId} onClick={() => void onLock(true)}>
                Lock for every profile
              </button>
            )}
          </div>
        </div>
      ) : null}
    </section>
  );
}
