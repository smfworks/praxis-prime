const PROFILE_KEY = "praxis-prime-profile";

let csrf = "";

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

export async function api(
  method: string,
  path: string,
  body?: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const profile = currentProfile();
  if (profile) headers["x-praxis-profile"] = profile;
  const init: RequestInit = { method, headers, credentials: "same-origin" };
  if (method !== "GET" && method !== "HEAD") {
    headers["Content-Type"] = "application/json";
    headers["x-csrf-token"] = csrf;
    init.body = JSON.stringify(body ?? {});
  }
  const response = await fetch(path, init);
  const text = await response.text();
  let parsed: Record<string, unknown> = {};
  if (text) {
    const loaded: unknown = JSON.parse(text);
    if (loaded && typeof loaded === "object") parsed = loaded as Record<string, unknown>;
  }
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
