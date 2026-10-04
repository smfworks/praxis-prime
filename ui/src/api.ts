const PROFILE_KEY = "praxis-prime-profile";

let csrf = "";
let setupToken = "";

export function setSetupToken(token: string): void {
  setupToken = token;
}

export function clearSetupToken(): void {
  setupToken = "";
}

/** Read `#setup=<token>` once, then drop it so it never stays in the address bar. */
export function takeSetupFragment(): void {
  const hash = window.location.hash;
  if (!hash.startsWith("#setup=")) return;
  const token = decodeURIComponent(hash.slice("#setup=".length)).trim();
  if (token) setupToken = token;
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
}

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function setCsrf(token: string): void {
  csrf = token;
}

export function currentProfile(): string {
  return sessionStorage.getItem(PROFILE_KEY) || "";
}

export function selectProfile(profile: string): void {
  if (profile) sessionStorage.setItem(PROFILE_KEY, profile);
  else sessionStorage.removeItem(PROFILE_KEY);
}

const CATALOG_ROUTES = ["/v1/memory", "/v1/skills", "/v1/routines", "/v1/approvals"];

function catalogRoute(path: string): boolean {
  const bare = path.split("?")[0].replace(/\/$/, "");
  return CATALOG_ROUTES.some((route) => bare === route || bare.startsWith(`${route}/`));
}

function readJson(text: string): Record<string, unknown> {
  if (!text.trim()) return {};
  try {
    const loaded: unknown = JSON.parse(text);
    if (loaded && typeof loaded === "object" && !Array.isArray(loaded)) {
      return loaded as Record<string, unknown>;
    }
  } catch {
    return {};
  }
  return {};
}

export async function api(
  method: string,
  path: string,
  body?: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (setupToken) headers["x-praxis-setup-token"] = setupToken;
  const profile = currentProfile();
  if (catalogRoute(path) && !profile) {
    throw new ApiError(403, "forbidden", "a profile is required");
  }
  if (profile) headers["x-praxis-profile"] = profile;
  const init: RequestInit = { method, headers, credentials: "same-origin" };
  if (method !== "GET" && method !== "HEAD") {
    headers["Content-Type"] = "application/json";
    headers["x-csrf-token"] = csrf;
    init.body = JSON.stringify(body ?? {});
  }
  const response = await fetch(path, init);
  const parsed = readJson(await response.text());
  if (!response.ok) {
    const error = parsed.error;
    const code =
      error && typeof error === "object" && "code" in error
        ? String((error as { code?: unknown }).code || "error")
        : "error";
    const message =
      error && typeof error === "object" && "message" in error
        ? String((error as { message?: unknown }).message || response.statusText)
        : response.statusText;
    throw new ApiError(response.status, code, message);
  }
  return parsed;
}

/** Upload a theme zip. The body is the file, not JSON. */
export async function apiUpload(
  path: string,
  body: Blob,
  contentType: string,
): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": contentType,
    "x-csrf-token": csrf,
  };
  if (setupToken) headers["x-praxis-setup-token"] = setupToken;
  const profile = currentProfile();
  if (profile) headers["x-praxis-profile"] = profile;
  const response = await fetch(path, { method: "POST", headers, body, credentials: "same-origin" });
  const parsed = readJson(await response.text());
  if (!response.ok) {
    const error = parsed.error;
    const code =
      error && typeof error === "object" && "code" in error
        ? String((error as { code?: unknown }).code || "error")
        : "error";
    const message =
      error && typeof error === "object" && "message" in error
        ? String((error as { message?: unknown }).message || response.statusText)
        : response.statusText;
    throw new ApiError(response.status, code, message);
  }
  return parsed;
}

export function textOf(value: unknown): string {
  return typeof value === "string" ? value : "";
}

export function rowsOf(body: Record<string, unknown>, key: string): Record<string, unknown>[] {
  const rows = body[key];
  if (!Array.isArray(rows)) return [];
  return rows.filter((item): item is Record<string, unknown> => !!item && typeof item === "object");
}
