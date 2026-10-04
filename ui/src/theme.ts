import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";

import { api, textOf } from "./api";

const THEME_CSS = /^\/themes\/[a-z0-9.-]+\/[0-9a-f]{64}\.css$/;

/** Point the document at one compiled theme stylesheet. No inline style. */
export function applyTheme(body: Record<string, unknown>): void {
  const mode = textOf(body.mode);
  const css = textOf(body.css);
  const root = document.documentElement;
  if (mode === "light" || mode === "dark" || mode === "system") {
    root.dataset.mode = mode;
  }
  const existing = document.getElementById("pp-theme");
  const link = existing instanceof HTMLLinkElement ? existing : null;
  const href = acceptedThemeCss(css);
  if (!href) {
    link?.remove();
    return;
  }
  const node = link ?? document.createElement("link");
  if (link === null) {
    node.id = "pp-theme";
    node.rel = "stylesheet";
    document.head.append(node);
  }
  if (node.href !== href) node.href = href;
}

/** Same-origin package stylesheet. A path that normalizes away is refused. */
function acceptedThemeCss(css: string): string {
  if (!THEME_CSS.test(css)) return "";
  let next: URL;
  try {
    next = new URL(css, window.location.origin);
  } catch {
    return "";
  }
  if (next.origin !== window.location.origin || next.pathname !== css) return "";
  return next.href;
}

/** Poll while System (Omarchy) is selected so a rewritten palette swaps the link. */
function omarchyPoll(data: Record<string, unknown> | undefined): number | false {
  if (!data) return false;
  if (textOf(data.id) === "omarchy.live" || textOf(data.requested) === "omarchy") return 2000;
  return false;
}

/** Load the active theme for the signed-in profile, or the public default. */
export function ThemeBridge({ profile }: { profile: string }) {
  const active = useQuery({
    queryKey: ["theme-active", profile],
    queryFn: () =>
      api(
        "GET",
        profile ? `/v1/themes/active?profile=${encodeURIComponent(profile)}` : "/v1/themes/active",
      ),
    refetchInterval: (query) => omarchyPoll(query.state.data),
  });
  useEffect(() => {
    if (active.data) applyTheme(active.data);
  }, [active.data]);
  return null;
}
