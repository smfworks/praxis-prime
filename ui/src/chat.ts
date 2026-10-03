import { api, textOf } from "./api";

export type ChatResult = {
  text: string;
  error: string;
  sessionId: string;
};

function messageOf(frame: Record<string, unknown>): string {
  const payload = frame.payload;
  if (payload && typeof payload === "object") {
    const message = (payload as Record<string, unknown>).message;
    if (typeof message === "string" && message) return message;
    const error = (payload as Record<string, unknown>).error;
    if (typeof error === "string" && error) return error;
  }
  return "chat failed";
}

export function streamChat(
  text: string,
  profile: string,
  sessionId: string,
  onText: (delta: string) => void,
  onDone: (result: ChatResult) => void,
): () => void {
  if (!profile) {
    onDone({ text: "", error: "a profile is required", sessionId: "" });
    return () => {};
  }
  const socket: { ws?: WebSocket } = {};
  let settled = false;
  const finish = (result: ChatResult) => {
    if (settled) return;
    settled = true;
    onDone(result);
    socket.ws?.close();
  };
  void (async () => {
    const ticketBody = await api("POST", "/v1/auth/ws-ticket", {});
    const ticket = textOf(ticketBody.ticket);
    if (!ticket) throw new Error("no websocket ticket");
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${location.host}/ws?ticket=${encodeURIComponent(ticket)}`);
    socket.ws = ws;
    const frameId = crypto.randomUUID().replaceAll("-", "");
    let hello = false;
    ws.addEventListener("open", () => {
      ws.send(
        JSON.stringify({
          type: "connect",
          id: `c${frameId}`,
          payload: {
            role: "operator",
            client: "web",
            version: "0",
            capabilities: ["chat", "approvals"],
          },
        }),
      );
    });
    ws.addEventListener("message", (event) => {
      let frame: Record<string, unknown>;
      try {
        const loaded: unknown = JSON.parse(String(event.data));
        if (!loaded || typeof loaded !== "object") return;
        frame = loaded as Record<string, unknown>;
      } catch {
        return;
      }
      if (!hello) {
        if (frame.type === "hello" && frame.ok === true) {
          hello = true;
          const payload: Record<string, unknown> = { text, profile };
          if (sessionId) payload.sessionId = sessionId;
          ws.send(
            JSON.stringify({
              type: "chat.send",
              id: frameId,
              idempotencyKey: crypto.randomUUID().replaceAll("-", ""),
              payload,
            }),
          );
        } else if (frame.type === "error") {
          finish({ text: "", error: messageOf(frame), sessionId });
        }
        return;
      }
      if (frame.id !== frameId) return;
      if (frame.type === "event") {
        const payload = frame.payload;
        if (payload && typeof payload === "object") {
          const body = payload as Record<string, unknown>;
          if (body.kind === "text" && typeof body.text === "string") onText(body.text);
        }
        return;
      }
      if (frame.type === "result" || frame.type === "error") {
        const payload =
          frame.payload && typeof frame.payload === "object"
            ? (frame.payload as Record<string, unknown>)
            : {};
        finish({
          text: textOf(payload.text),
          error: frame.type === "error" ? messageOf(frame) : textOf(payload.error),
          sessionId: textOf(payload.sessionId) || sessionId,
        });
      }
    });
    ws.addEventListener("error", () => {
      finish({ text: "", error: "websocket failed", sessionId });
    });
    ws.addEventListener("close", () => {
      finish({ text: "", error: "connection closed", sessionId });
    });
  })().catch((error: unknown) => {
    finish({
      text: "",
      error: error instanceof Error ? error.message : "chat failed",
      sessionId,
    });
  });
  return () => {
    settled = true;
    socket.ws?.close();
  };
}
