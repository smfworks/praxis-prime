import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api";
import { CLOUD_WARNING, SetupWizard } from "../setup";
import { NO_GPU_NOTE } from "./types";

const { api } = vi.hoisted(() => ({ api: vi.fn() }));

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return { ...actual, api };
});

const GLM = ["zai-org/GLM-4.6", "glm-4.5-air"];

function method(
  id: string,
  label: string,
  extra: { available?: boolean; envNames?: string[]; note?: string } = {},
) {
  return {
    id,
    label,
    note: extra.note ?? "",
    secretName: "",
    envNames: extra.envNames ?? [],
    available: extra.available !== false,
  };
}

function provider(partial: Record<string, unknown>) {
  return {
    adapter: "openai-compatible",
    aliases: [],
    description: "",
    authMethods: [method("none", "No key"), method("api_key", "API key")],
    defaultBaseUrl: "",
    baseUrlEditable: true,
    port: null,
    modelList: { curated: [] },
    defaultModels: {},
    keyUrl: "",
    ...partial,
  };
}

const CATALOG = {
  providers: [
    provider({
      id: "ollama",
      adapter: "ollama",
      displayName: "Ollama",
      section: "local",
      description: "Local Ollama",
      port: 11434,
      baseUrlEditable: true,
    }),
    provider({
      id: "network",
      displayName: "Network server (OpenAI-compatible)",
      aliases: ["network", "lan", "remote", "sglang", "vllm", "glm", "openai-compatible"],
      section: "local",
      description: "Another machine on your network: vLLM, SGLang, llama.cpp, Ollama…",
    }),
    provider({
      id: "xai",
      adapter: "xai",
      displayName: "xAI (Grok)",
      aliases: ["grok", "x.ai"],
      section: "cloud",
      description: "Grok models",
      baseUrlEditable: false,
      authMethods: [
        method("oauth", "Sign in with Grok (SuperGrok / X Premium subscription)", {
          available: false,
          note: "Coming soon",
        }),
        method("api_key", "API key", { envNames: ["XAI_API_KEY"] }),
      ],
      modelList: { curated: ["grok-4.7"] },
      defaultModels: { primary: "grok-4.7" },
    }),
  ],
  detection: {
    servers: [{ provider: "ollama", baseUrl: "", models: ["local-llama"] }],
    envKeys: [],
    hardware: [],
  },
  policy: { allowProviders: [], cloudWarning: "" },
};

function flagOnCatalog(regulatedEnforce = false) {
  return {
    ...CATALOG,
    providers: CATALOG.providers.map((item) => {
      if (item.id !== "xai") return item;
      return {
        ...item,
        authMethods: item.authMethods.map((method) =>
          method.id === "oauth" ? { ...method, available: true, note: "" } : method,
        ),
      };
    }),
    policy: {
      allowProviders: [],
      cloudWarning: "",
      subscriptionOauthEnabled: true,
      regulatedEnforce,
    },
  };
}

const DEVICE = {
  flowId: "flow-1",
  userCode: "WDJB-MJHT",
  verificationUri: "https://accounts.x.ai/device",
  verificationUriComplete: "https://accounts.x.ai/device?user_code=WDJB-MJHT",
  expiresAt: 1_800_000_000,
  interval: 0,
};

function renderWizard() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <SetupWizard mode="admin" onFinished={() => undefined} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  window.location.hash = "#/setup";
  api.mockImplementation(async (methodName: string, path: string, body?: Record<string, unknown>) => {
    if (path === "/v1/onboarding/status") {
      return { provider: "", dials: {}, missing: [] };
    }
    if (path === "/v1/onboarding/providers") return CATALOG;
    if (path === "/v1/onboarding/probe") {
      const base = String(body?.baseUrl ?? "");
      if (base.includes("bad")) throw new Error("probe failed");
      return { ok: true, models: GLM, network: true, https: false, loopback: false };
    }
    if (path === "/v1/onboarding/save") return { inferenceReady: false, spec: "" };
    return {};
  });
});

describe("provider picker", () => {
  it("lists Local and Cloud and does not preselect the one detected server", async () => {
    renderWizard();
    const local = await screen.findByRole("group", { name: "Local" });
    expect(screen.getByRole("group", { name: "Cloud" })).toBeInTheDocument();
    expect(local).toHaveTextContent(NO_GPU_NOTE);
    expect(local).toHaveTextContent("Running here · 1 models");
    const options = screen.getAllByRole("option");
    expect(options.length).toBeGreaterThan(1);
    for (const option of options) {
      expect(option).toHaveAttribute("aria-selected", "false");
    }
    expect(screen.queryByRole("radio", { checked: true })).not.toBeInTheDocument();
  });

  it("filters by name and by alias", async () => {
    const user = userEvent.setup();
    renderWizard();
    const search = await screen.findByRole("textbox", { name: "Search providers" });
    await user.type(search, "grok");
    expect(screen.getByRole("option", { name: "xAI (Grok)" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Ollama" })).not.toBeInTheDocument();
    await user.clear(search);
    await user.type(search, "x.ai");
    expect(screen.getByRole("option", { name: "xAI (Grok)" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Ollama" })).not.toBeInTheDocument();
  });

  it("finds the network server by glm, sglang, and network", async () => {
    const user = userEvent.setup();
    renderWizard();
    const search = await screen.findByRole("textbox", { name: "Search providers" });
    const local = () => screen.getByRole("group", { name: "Local" });
    for (const query of ["glm", "sglang", "network"]) {
      await user.clear(search);
      await user.type(search, query);
      expect(
        within(local()).getByRole("option", { name: "Network server (OpenAI-compatible)" }),
      ).toBeInTheDocument();
      expect(screen.queryByRole("option", { name: "Ollama" })).not.toBeInTheDocument();
    }
  });

  it("keeps xAI sign-in disabled and offers an API key", async () => {
    const user = userEvent.setup();
    renderWizard();
    await user.click(await screen.findByRole("option", { name: "xAI (Grok)" }));
    const signIn = screen.getByRole("button", {
      name: /Sign in with Grok \(SuperGrok \/ X Premium subscription\)/,
    });
    expect(signIn).toBeDisabled();
    expect(signIn).toHaveTextContent("Coming soon");
    await user.click(screen.getByRole("button", { name: /API key — Billed/ }));
    expect(
      screen.getByText(/billed separately by xAI, even if you also subscribe/),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("API key")).toBeInTheDocument();
  });

  it("clears the API key when Back leaves Connect", async () => {
    const user = userEvent.setup();
    renderWizard();
    await user.click(
      await screen.findByRole("option", { name: "Network server (OpenAI-compatible)" }),
    );
    await user.type(screen.getByLabelText("API key"), "sk-unit");
    await user.click(screen.getByRole("button", { name: /Back/ }));
    expect(
      await screen.findByRole("heading", { name: "Choose where Praxis thinks" }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("option", { name: "Network server (OpenAI-compatible)" }));
    expect(screen.getByLabelText("API key")).toHaveValue("");
  });

  it("skips to inference not configured", async () => {
    const user = userEvent.setup();
    renderWizard();
    await user.click(await screen.findByRole("button", { name: "Skip for now" }));
    expect(await screen.findByText("Inference not configured")).toBeInTheDocument();
    expect(api).toHaveBeenCalledWith(
      "POST",
      "/v1/onboarding/save",
      expect.objectContaining({ lane: "skip" }),
    );
  });

  it("shows a validation error and then the mocked model list", async () => {
    const user = userEvent.setup();
    renderWizard();
    await user.click(
      await screen.findByRole("option", { name: "Network server (OpenAI-compatible)" }),
    );
    const base = screen.getByLabelText("Base URL");
    await user.type(base, "ftp://x");
    await user.click(screen.getByRole("button", { name: "Check connection" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Only http and https URLs are allowed.",
    );
    await user.clear(base);
    await user.type(base, "192.168.1.50:8000");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("button", { name: "zai-org/GLM-4.6" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "glm-4.5-air" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Type a model id instead" })).toBeInTheDocument();
    expect(screen.getByLabelText("Primary model")).toBeInTheDocument();
  });

  it("resets provider state when the hash or history moves between providers", async () => {
    const user = userEvent.setup();
    renderWizard();
    await user.click(
      await screen.findByRole("option", { name: "Network server (OpenAI-compatible)" }),
    );
    await user.type(screen.getByLabelText("API key"), "sk-provider-a");
    await user.type(screen.getByLabelText("Base URL"), "192.168.1.50:8000");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(await screen.findByRole("button", { name: "zai-org/GLM-4.6" }));

    function navigate(hash: string) {
      act(() => {
        window.location.hash = hash;
        window.dispatchEvent(new HashChangeEvent("hashchange"));
      });
    }

    navigate("#/setup/connect/ollama");
    expect(await screen.findByLabelText("API key")).toHaveValue("");
    expect(screen.getByLabelText("Base URL")).not.toHaveValue("192.168.1.50:8000");
    expect(screen.queryByDisplayValue("sk-provider-a")).not.toBeInTheDocument();

    navigate("#/setup/model");
    expect(await screen.findByLabelText("Primary model")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "zai-org/GLM-4.6" })).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue("zai-org/GLM-4.6")).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue("192.168.1.50:8000")).not.toBeInTheDocument();
    expect(api).not.toHaveBeenCalledWith(
      "POST",
      "/v1/onboarding/probe",
      expect.objectContaining({ provider: "ollama", baseUrl: "192.168.1.50:8000" }),
    );
  });

  it("warns when a network server probes a public host and stays quiet for a LAN host", async () => {
    api.mockImplementation(async (methodName: string, path: string, body?: Record<string, unknown>) => {
      if (path === "/v1/onboarding/status") return { provider: "", dials: {}, missing: [] };
      if (path === "/v1/onboarding/providers") return CATALOG;
      if (path === "/v1/onboarding/probe") {
        const base = String(body?.baseUrl ?? "");
        if (base.includes("203.0.113")) {
          return {
            ok: false,
            error: "down",
            models: [],
            network: true,
            https: false,
            loopback: false,
            locality: "cloud",
          };
        }
        return {
          ok: true,
          models: GLM,
          network: true,
          https: false,
          loopback: false,
          locality: "lan",
        };
      }
      return {};
    });
    const user = userEvent.setup();
    renderWizard();
    await user.click(
      await screen.findByRole("option", { name: "Network server (OpenAI-compatible)" }),
    );
    const base = screen.getByLabelText("Base URL");
    await user.type(base, "http://192.168.1.50:8000");
    await user.click(screen.getByRole("button", { name: "Check connection" }));
    expect(await screen.findByText("Connected.")).toBeInTheDocument();
    expect(screen.queryByText(CLOUD_WARNING)).not.toBeInTheDocument();

    await user.clear(base);
    await user.type(base, "http://203.0.113.10:8000");
    expect(screen.queryByText(CLOUD_WARNING)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check connection" }));
    expect(await screen.findByText(CLOUD_WARNING)).toBeInTheDocument();
    expect(screen.getByText(/down/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("heading", { name: "Model" })).toBeInTheDocument();
    expect(screen.getByText(CLOUD_WARNING)).toBeInTheDocument();
  });

  it("flag-on catalog enables the button and Continue does not show coming in a later release", async () => {
    api.mockImplementation(async (_method: string, path: string) => {
      if (path === "/v1/onboarding/status") return { provider: "", dials: {}, missing: [] };
      if (path === "/v1/onboarding/providers") return flagOnCatalog();
      if (path === "/v1/onboarding/oauth/start") return { ...DEVICE, interval: 30 };
      if (path === "/v1/onboarding/oauth/poll") return { status: "pending" };
      if (path === "/v1/onboarding/oauth/cancel") return { ok: true };
      return {};
    });
    const user = userEvent.setup();
    renderWizard();
    await user.click(await screen.findByRole("option", { name: "xAI (Grok)" }));
    const signIn = screen.getByRole("button", { name: /Sign in with Grok/ });
    expect(signIn).toBeEnabled();
    expect(signIn).not.toHaveTextContent("Coming soon");
    await user.click(signIn);
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.queryByText(/coming in a later release/i)).not.toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Sign in with Grok" })).toBeInTheDocument();
  });

  it("flag-off catalog never calls oauth/start", async () => {
    const user = userEvent.setup();
    renderWizard();
    await user.click(await screen.findByRole("option", { name: "xAI (Grok)" }));
    expect(screen.getByRole("button", { name: /Sign in with Grok/ })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText(/coming in a later release/i)).toBeInTheDocument();
    expect(api).not.toHaveBeenCalledWith("POST", "/v1/onboarding/oauth/start", expect.anything());
  });

  it("keeps sign-in disabled and shows the enforce sentence when a regulated dial is at enforce", async () => {
    api.mockImplementation(async (_method: string, path: string) => {
      if (path === "/v1/onboarding/status") return { provider: "", dials: {}, missing: [] };
      if (path === "/v1/onboarding/providers") return flagOnCatalog(true);
      return {};
    });
    const user = userEvent.setup();
    renderWizard();
    await user.click(await screen.findByRole("option", { name: "xAI (Grok)" }));
    expect(screen.getByRole("button", { name: /Sign in with Grok/ })).toBeDisabled();
    expect(screen.getByText(/can't be covered by a BAA\/DPA/)).toBeInTheDocument();
    expect(api).not.toHaveBeenCalledWith("POST", "/v1/onboarding/oauth/start", expect.anything());
  });

  it("save posts authMethod oauth and does not post an API key", async () => {
    api.mockImplementation(async (_method: string, path: string) => {
      if (path === "/v1/onboarding/status") return { provider: "", dials: {}, missing: [] };
      if (path === "/v1/onboarding/providers") return flagOnCatalog();
      if (path === "/v1/onboarding/oauth/start") return DEVICE;
      if (path === "/v1/onboarding/oauth/poll") {
        return { status: "approved", account: { name: "Ada", email: "ada@x.ai" } };
      }
      if (path === "/v1/onboarding/oauth/cancel") return { ok: true };
      if (path === "/v1/onboarding/save") return { inferenceReady: true, spec: "xai:grok-4.7" };
      return {};
    });
    const user = userEvent.setup();
    renderWizard();
    await user.click(await screen.findByRole("option", { name: "xAI (Grok)" }));
    await user.click(screen.getByRole("button", { name: /Sign in with Grok/ }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText("Signed in as ada@x.ai")).toBeInTheDocument();
    expect(screen.getByText("Ada")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByLabelText("Primary model")).toHaveValue("grok-4.7");
    await user.click(screen.getByRole("button", { name: "Test and save" }));
    await waitFor(() => {
      expect(api).toHaveBeenCalledWith(
        "POST",
        "/v1/onboarding/save",
        expect.objectContaining({ authMethod: "oauth", provider: "xai", model: "grok-4.7" }),
      );
    });
    const save = api.mock.calls.find((call) => call[1] === "/v1/onboarding/save");
    expect(save?.[2]).not.toHaveProperty("apiKey");
  });

  it("a 409 replace uses the existing step-up path and retries start once with stepUpToken", async () => {
    const starts: Record<string, unknown>[] = [];
    api.mockImplementation(async (_method: string, path: string, body?: Record<string, unknown>) => {
      if (path === "/v1/onboarding/status") return { provider: "", dials: {}, missing: [] };
      if (path === "/v1/onboarding/providers") return flagOnCatalog();
      if (path === "/v1/onboarding/oauth/start") {
        starts.push(body ?? {});
        if (!body?.stepUpToken) throw new ApiError(409, "replace", "needs a step-up");
        return { ...DEVICE, interval: 30 };
      }
      if (path === "/v1/auth/step-up") return { stepUpToken: "step-up-1" };
      if (path === "/v1/onboarding/oauth/poll") return { status: "pending" };
      if (path === "/v1/onboarding/oauth/cancel") return { ok: true };
      return {};
    });
    const user = userEvent.setup();
    renderWizard();
    await user.click(await screen.findByRole("option", { name: "xAI (Grok)" }));
    await user.click(screen.getByRole("button", { name: /Sign in with Grok/ }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByLabelText("Account password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Use a passkey" })).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Replace the current provider" }));
    await user.type(screen.getByLabelText("Account password"), "correct horse");
    await user.click(screen.getByRole("button", { name: "Confirm this change" }));
    await waitFor(() => expect(starts).toHaveLength(2));
    expect(starts[0]).toEqual({ provider: "xai", flow: "device" });
    expect(starts[1]).toEqual({ provider: "xai", flow: "device", stepUpToken: "step-up-1" });
    expect(starts[1]).not.toHaveProperty("replace");
    expect(api).toHaveBeenCalledWith(
      "POST",
      "/v1/auth/step-up",
      expect.objectContaining({ password: "correct horse" }),
    );
  });
});
