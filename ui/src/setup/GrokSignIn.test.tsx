import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api";
import { GrokSignIn } from "./GrokSignIn";

const { api } = vi.hoisted(() => ({ api: vi.fn() }));

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return { ...actual, api };
});

const FLOW = {
  flowId: "flow-1",
  userCode: "WDJB-MJHT",
  verificationUri: "https://accounts.x.ai/device",
  verificationUriComplete: "https://accounts.x.ai/device?user_code=WDJB-MJHT",
  expiresAt: 1_800_000_000,
  interval: 5,
};

function startBody(extra: Record<string, unknown> = {}) {
  return { ...FLOW, ...extra };
}

function renderSignIn(stepUpToken = "") {
  const onNeedStepUp = vi.fn();
  const onBack = vi.fn();
  const view = render(
    <GrokSignIn
      stepUpToken={stepUpToken}
      onNeedStepUp={onNeedStepUp}
      onApproved={() => undefined}
      onContinue={() => undefined}
      onBack={onBack}
      onUseApiKey={() => undefined}
      onFlow={() => undefined}
    />,
  );
  return { ...view, onNeedStepUp, onBack };
}

beforeEach(() => {
  api.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("GrokSignIn", () => {
  it("renders the user code and the verification URL, has no token field, and Back calls cancel", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    api.mockImplementation(async (_method: string, path: string) => {
      if (path.endsWith("/oauth/start")) return startBody();
      if (path.endsWith("/oauth/poll")) return { status: "pending" };
      if (path.endsWith("/oauth/cancel")) return { ok: true };
      return {};
    });
    const { onBack } = renderSignIn();
    expect(await screen.findByText(/WDJB-MJHT/)).toBeInTheDocument();
    expect(screen.getByText(/https:\/\/accounts\.x\.ai\/device/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy code" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy link" })).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /token/i })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/access token|refresh token|device code|client id/i)).not.toBeInTheDocument();
    const link = screen.getByRole("link", { name: "Open sign-in page" });
    expect(link).toHaveAttribute("href", FLOW.verificationUriComplete);
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    fireEvent.click(screen.getByRole("button", { name: "← Back" }));
    await waitFor(() => {
      expect(api).toHaveBeenCalledWith("POST", "/v1/onboarding/oauth/cancel", { flowId: "flow-1" });
    });
    expect(onBack).toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
    log.mockRestore();
  });

  it("does not set an href when the verification URL is not https on x.ai", async () => {
    api.mockImplementation(async (_method: string, path: string) => {
      if (path.endsWith("/oauth/start")) {
        return startBody({ verificationUriComplete: "http://evil.example/device" });
      }
      if (path.endsWith("/oauth/poll")) return { status: "pending" };
      return { ok: true };
    });
    renderSignIn();
    expect(await screen.findByText(/WDJB-MJHT/)).toBeInTheDocument();
    expect(screen.getByText("Open sign-in page").closest("a")).toBeNull();
    expect(screen.queryByRole("link", { name: "Open sign-in page" })).not.toBeInTheDocument();
  });

  it("waiting copy follows status pending and slow_down is not a failure", async () => {
    vi.useFakeTimers();
    const polls: string[] = [];
    api.mockImplementation(async (_method: string, path: string) => {
      if (path.endsWith("/oauth/start")) return startBody({ interval: 5 });
      if (path.endsWith("/oauth/poll")) {
        polls.push("poll");
        return { status: polls.length === 1 ? "pending" : "slow_down" };
      }
      return { ok: true };
    });
    renderSignIn();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getByText(/Waiting for you to approve/)).toBeInTheDocument();
    expect(api).not.toHaveBeenCalledWith("POST", "/v1/onboarding/oauth/poll", expect.anything());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(api).toHaveBeenCalledWith("POST", "/v1/onboarding/oauth/poll", { flowId: "flow-1" });
    expect(screen.getByText(/Waiting for you to approve/)).toBeInTheDocument();
    expect(screen.queryByText("Couldn't reach auth.x.ai.")).not.toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(screen.getByText(/Waiting for you to approve/)).toBeInTheDocument();
    expect(screen.queryByText(/cancelled on the xAI page|code expired|Couldn't reach/)).not.toBeInTheDocument();
  });

  it("does not treat a success field named replace as a second grant", async () => {
    api.mockImplementation(async (_method: string, path: string) => {
      if (path.endsWith("/oauth/start")) return startBody({ replace: true });
      if (path.endsWith("/oauth/poll")) return { status: "pending" };
      return { ok: true };
    });
    const { onNeedStepUp } = renderSignIn();
    expect(await screen.findByText(/WDJB-MJHT/)).toBeInTheDocument();
    expect(onNeedStepUp).not.toHaveBeenCalled();
  });

  it("retries start once with stepUpToken after a 409 replace", async () => {
    const starts: Record<string, unknown>[] = [];
    api.mockImplementation(async (_method: string, path: string, body?: Record<string, unknown>) => {
      if (path.endsWith("/oauth/start")) {
        starts.push(body ?? {});
        if (!body?.stepUpToken) throw new ApiError(409, "replace", "needs a step-up");
        return startBody();
      }
      if (path.endsWith("/oauth/poll")) return { status: "pending" };
      return { ok: true };
    });
    const props = {
      onNeedStepUp: vi.fn(),
      onApproved: () => undefined,
      onContinue: () => undefined,
      onBack: () => undefined,
      onUseApiKey: () => undefined,
      onFlow: () => undefined,
    };
    const view = render(<GrokSignIn stepUpToken="" {...props} />);
    await waitFor(() => expect(props.onNeedStepUp).toHaveBeenCalled());
    expect(starts).toEqual([{ provider: "xai", flow: "device" }]);
    view.rerender(<GrokSignIn stepUpToken="step-up-1" {...props} />);
    await waitFor(() => expect(starts).toHaveLength(2));
    expect(starts[1]).toEqual({ provider: "xai", flow: "device", stepUpToken: "step-up-1" });
    expect(starts[1]).not.toHaveProperty("replace");
    expect(starts).toHaveLength(2);
  });
});
