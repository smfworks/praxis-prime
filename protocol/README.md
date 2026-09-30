# Protocol schemas

`gateway.schema.json` is the frame every client sends on the loopback gateway (WebSocket, and the same payloads on HTTP for health, status, and approvals). The listen address is `127.0.0.1` only.

`decide.schema.json` is the request and response for `POST /v1/decide` and the `/v1/systemone` alias. Both need the gateway bearer token. The handler is local. It does not call a hosted decision service.

The gateway itself is ARCHITECTURE §4. The Decision Engine is ARCHITECTURE §7.
