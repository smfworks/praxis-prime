import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";

import { api, textOf } from "./api";

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
  if (!css) {
    link?.remove();
    return;
  }
  const node = link ?? document.createElement("link");
  if (link === null) {
    node.id = "pp-theme";
    node.rel = "stylesheet";
    document.head.append(node);
  }
  const next = new URL(css, window.location.origin).href;
  if (node.href !== next) node.href = next;
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
  });
  useEffect(() => {
    if (active.data) applyTheme(active.data);
  }, [active.data]);
  return null;
}
