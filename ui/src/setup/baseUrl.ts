/** Client checks for a server base. The daemon normalizes the value on save. */

const MARK = "://";

export function validateBase(input: string): string {
  const text = input.trim();
  if (!text) return "Enter a host and port, or a base URL.";
  let rest = text;
  const split = text.indexOf(MARK);
  if (split !== -1) {
    const scheme = text.slice(0, split).toLowerCase();
    rest = text.slice(split + MARK.length);
    if (scheme !== "http" && scheme !== "https") return "Only http and https URLs are allowed.";
  }
  if (rest.includes("?") || rest.includes("#")) {
    return "The URL cannot include a query or a fragment.";
  }
  const slash = rest.indexOf("/");
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  if (!authority || authority.includes("@")) {
    if (authority.includes("@")) return "Credentials in the URL are not allowed.";
    return "The URL needs a host.";
  }
  const host = hostOf(text);
  if (!host) return "The URL needs a host.";
  const port = portOf(authority);
  if (port === "bad") return "The port must be between 1 and 65535.";
  return "";
}

export function hostOf(input: string): string {
  let rest = input.trim();
  const split = rest.indexOf(MARK);
  if (split !== -1) rest = rest.slice(split + MARK.length);
  rest = rest.split("/")[0]?.split("?")[0]?.split("#")[0] ?? "";
  if (!rest || rest.includes("@")) return "";
  if (rest.startsWith("[")) {
    const end = rest.indexOf("]");
    return end === -1 ? "" : rest.slice(1, end);
  }
  return rest.split(":")[0] ?? "";
}

export function schemeOf(input: string): string {
  const split = input.trim().indexOf(MARK);
  if (split === -1) return "";
  return input.trim().slice(0, split).toLowerCase();
}

export function isLoopbackHost(host: string): boolean {
  const text = host.trim().toLowerCase();
  return text === "localhost" || text === "::1" || text.startsWith("127.");
}

function portOf(authority: string): string {
  let port = "";
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end === -1) return "bad";
    const after = authority.slice(end + 1);
    if (!after) return "";
    if (!after.startsWith(":")) return "bad";
    port = after.slice(1);
  } else if (authority.includes(":")) {
    const parts = authority.split(":");
    if (parts.length !== 2) return "bad";
    port = parts[1] ?? "";
  }
  if (!port) return "";
  if (!/^\d{1,5}$/.test(port)) return "bad";
  const number = Number(port);
  if (number < 1 || number > 65535) return "bad";
  return port;
}
