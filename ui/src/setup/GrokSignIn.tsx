import { useEffect, useRef, useState } from "react";

import { ApiError, api, textOf } from "../api";

const WAITING = "Waiting for you to approve…";
const DENIED = "Sign-in was cancelled on the xAI page.";
const EXPIRED = "The code expired before it was approved.";
const INELIGIBLE =
  "xAI signed you in but says this account can't use Grok here (no eligible subscription, or no usage left).";
const FAILED = "Couldn't reach auth.x.ai.";

export type SignedInAccount = { name: string; email: string };

type Phase = "starting" | "step-up" | "pending" | "approved" | "denied" | "expired" | "ineligible" | "failed";

type FlowView = {
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresAt: number;
  interval: number;
};

export function pinnedSignInUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) return false;
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  return host === "x.ai" || host.endsWith(".x.ai");
}

function clock(expiresAt: number, now: number): string {
  const left = Math.max(0, expiresAt - now);
  const minutes = Math.floor(left / 60);
  const seconds = left % 60;
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

async function copyText(value: string): Promise<void> {
  if (!value || !navigator.clipboard) return;
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    // The code and the URL stay on the screen either way.
  }
}

export function GrokSignIn({
  stepUpToken,
  onNeedStepUp,
  onApproved,
  onContinue,
  onBack,
  onUseApiKey,
  onFlow,
}: {
  stepUpToken: string;
  onNeedStepUp: (message: string) => void;
  onApproved: (account: SignedInAccount) => void;
  onContinue: () => void;
  onBack: () => void;
  onUseApiKey: () => void;
  onFlow: (flowId: string) => void;
}) {
  const [phase, setPhase] = useState<Phase>("starting");
  const [flow, setFlow] = useState<FlowView | null>(null);
  const [account, setAccount] = useState<SignedInAccount | null>(null);
  const [detail, setDetail] = useState("");
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  const generation = useRef(0);
  const flowId = useRef("");
  const timers = useRef<number[]>([]);
  const waiters = useRef<Array<() => void>>([]);
  const beginRef = useRef<(token: string) => Promise<void>>(async () => undefined);

  function stopTimers() {
    for (const timer of timers.current) window.clearTimeout(timer);
    timers.current = [];
    const pending = waiters.current;
    waiters.current = [];
    for (const resolve of pending) resolve();
  }

  function delay(ms: number): Promise<void> {
    return new Promise((resolve) => {
      waiters.current.push(resolve);
      const timer = window.setTimeout(resolve, ms);
      timers.current.push(timer);
    });
  }

  async function cancelId(id: string): Promise<void> {
    if (!id) return;
    try {
      await api("POST", "/v1/onboarding/oauth/cancel", { flowId: id });
    } catch {
      // A cancel that fails still leaves. It does not retry start.
    }
  }

  async function cancelCurrent(): Promise<void> {
    const id = flowId.current;
    flowId.current = "";
    onFlow("");
    stopTimers();
    generation.current += 1;
    await cancelId(id);
  }

  async function begin(token: string): Promise<void> {
    stopTimers();
    const gen = ++generation.current;
    setPhase("starting");
    setDetail("");
    setAccount(null);
    const body: Record<string, unknown> = { provider: "xai", flow: "device" };
    if (token) body.stepUpToken = token;
    let started: Record<string, unknown>;
    try {
      started = await api("POST", "/v1/onboarding/oauth/start", body);
    } catch (caught) {
      if (gen !== generation.current) return;
      // A second grant is a 409 replace. It is not a success field.
      if (!token && caught instanceof ApiError && caught.status === 409 && caught.code === "replace") {
        setPhase("step-up");
        onNeedStepUp(caught.message);
        return;
      }
      setPhase("failed");
      setDetail(caught instanceof Error ? caught.message : FAILED);
      return;
    }
    if (gen !== generation.current) return;
    const id = textOf(started.flowId);
    const next: FlowView = {
      userCode: textOf(started.userCode),
      verificationUri: textOf(started.verificationUri),
      verificationUriComplete: textOf(started.verificationUriComplete),
      expiresAt: typeof started.expiresAt === "number" ? started.expiresAt : 0,
      interval: typeof started.interval === "number" ? started.interval : 5,
    };
    flowId.current = id;
    onFlow(id);
    setFlow(next);
    setPhase("pending");
    void watch(id, next.interval, gen);
  }

  beginRef.current = begin;

  async function watch(id: string, interval: number, gen: number): Promise<void> {
    let wait = Math.max(0, interval);
    while (gen === generation.current) {
      await delay(wait * 1000);
      if (gen !== generation.current) return;
      let body: Record<string, unknown>;
      try {
        body = await api("POST", "/v1/onboarding/oauth/poll", { flowId: id });
      } catch {
        if (gen !== generation.current) return;
        setPhase("failed");
        setDetail(FAILED);
        return;
      }
      if (gen !== generation.current) return;
      const status = textOf(body.status);
      if (typeof body.interval === "number") wait = Math.max(0, body.interval);
      if (status === "pending" || status === "slow_down") {
        setPhase("pending");
        continue;
      }
      if (status === "approved") {
        const raw = body.account;
        const record = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
        const signedIn = { name: textOf(record.name), email: textOf(record.email) };
        setAccount(signedIn);
        setPhase("approved");
        onApproved(signedIn);
        return;
      }
      if (status === "denied" || status === "expired" || status === "ineligible") {
        setPhase(status);
        return;
      }
      setPhase("failed");
      setDetail(FAILED);
      return;
    }
  }

  useEffect(() => {
    void beginRef.current("");
    return () => {
      const id = flowId.current;
      flowId.current = "";
      generation.current += 1;
      stopTimers();
      if (id) void cancelId(id);
    };
  }, []);

  useEffect(() => {
    if (!stepUpToken) return;
    void beginRef.current(stepUpToken);
  }, [stepUpToken]);

  useEffect(() => {
    if (phase !== "pending") return;
    setNow(Math.floor(Date.now() / 1000));
    const timer = window.setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [phase, flow?.expiresAt]);

  async function leave(after: () => void) {
    await cancelCurrent();
    after();
  }

  async function restart() {
    await cancelCurrent();
    await beginRef.current("");
  }

  const openHref =
    flow && pinnedSignInUrl(flow.verificationUriComplete) ? flow.verificationUriComplete : "";

  return (
    <section className="grid gap-3">
      <h1 className="text-2xl font-semibold">Sign in with Grok</h1>
      {phase === "pending" && flow ? (
        <div className="grid gap-2">
          <p>
            Open this page on any device: {flow.verificationUri}{" "}
            {openHref ? (
              <a href={openHref} target="_blank" rel="noopener noreferrer">
                Open sign-in page
              </a>
            ) : (
              <span>Open sign-in page</span>
            )}{" "}
            <button type="button" className="btn-quiet" onClick={() => void copyText(flow.verificationUri)}>
              Copy link
            </button>
          </p>
          <p>
            Enter this code: {flow.userCode}{" "}
            <button type="button" className="btn-quiet" onClick={() => void copyText(flow.userCode)}>
              Copy code
            </button>
          </p>
          <p>The link above already has the code filled in.</p>
          <p>
            {WAITING} <span aria-hidden="true">◌</span> Code expires in {clock(flow.expiresAt, now)}
          </p>
          <button type="button" className="btn-quiet w-fit" onClick={() => void leave(onBack)}>
            Cancel
          </button>
          <button type="button" className="btn-quiet w-fit" onClick={() => void restart()}>
            Get a new code
          </button>
        </div>
      ) : null}
      {phase === "approved" && account ? (
        <div className="grid gap-2">
          <p>Signed in as {account.email}</p>
          <p>{account.name}</p>
          <button type="button" className="btn w-fit" onClick={onContinue}>
            Continue
          </button>
        </div>
      ) : null}
      {phase === "denied" ? (
        <div className="grid gap-2">
          <p>{DENIED}</p>
          <button type="button" className="btn w-fit" onClick={() => void restart()}>
            Try again
          </button>
        </div>
      ) : null}
      {phase === "expired" ? (
        <div className="grid gap-2">
          <p>{EXPIRED}</p>
          <button type="button" className="btn w-fit" onClick={() => void restart()}>
            Get a new code
          </button>
        </div>
      ) : null}
      {phase === "ineligible" ? (
        <div className="grid gap-2">
          <p>{INELIGIBLE}</p>
          <button type="button" className="btn w-fit" onClick={() => void leave(onUseApiKey)}>
            Use an API key instead
          </button>
        </div>
      ) : null}
      {phase === "failed" ? (
        <div className="grid gap-2">
          <p>{detail || FAILED}</p>
          <button type="button" className="btn w-fit" onClick={() => void restart()}>
            Try again
          </button>
        </div>
      ) : null}
      <button type="button" className="btn-quiet w-fit" onClick={() => void leave(onBack)}>
        ← Back
      </button>
    </section>
  );
}
